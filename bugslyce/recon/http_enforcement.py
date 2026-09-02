"""Central policy-aware execution boundary for internal Python HTTP traffic."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import ipaddress
import math
import re
import socket
import ssl
import threading
from time import monotonic as system_monotonic
from time import sleep as system_sleep
from typing import Callable, Iterator, Protocol
import unicodedata
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    READINESS_FUTURE_ENFORCEMENT,
    EngagementPolicy,
    IdentificationHeader,
    assess_engagement_policy,
    policy_from_dict,
    validate_identification_header_name,
    validate_identification_headers,
    validate_identification_value,
)
from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.programme_scope import (
    DESTINATION_HOSTNAME,
    DESTINATION_HTTP_URL,
    DESTINATION_IPV4,
    OUTCOME_ALLOWED,
    OUTCOME_BLOCKED,
    CanonicalHostnameDestination,
    CanonicalHTTPURLDestination,
    ProgrammeScopePolicy,
    ScopeDecision,
    build_programme_scope_policy,
    build_programme_scope_rule,
    canonicalise_ipv4,
    canonicalise_resolved_ipv4_peer,
    evaluate_resolved_ipv4_peer,
    evaluate_raw_scope_destination,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.recon.user_agent import built_in_user_agent


REDIRECT_SAME_ORIGIN = "same_origin_only"
DEFAULT_MAXIMUM_REDIRECT_HOPS = 5
MAXIMUM_REDIRECT_HOPS = 10
MAXIMUM_RETRY_AFTER_CHARS = 128
MAXIMUM_SLEEP_CHUNK_SECONDS = 60
MAXIMUM_TERMINAL_POLL_SECONDS = Decimal("0.1")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HTTP_FIELD_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PEER_BOUND_TRANSPORT_REQUIRED = (
    "Programme-scoped internal HTTP requires a peer-bound transport."
)

Monotonic = Callable[[], float]
Sleeper = Callable[[float], None]
InterruptibleWaiter = Callable[[float, threading.Event], bool]
IPv4Resolver = Callable[[str, int], tuple[str, ...]]
SocketFactory = Callable[[int, int, int], socket.socket]


@dataclass(frozen=True)
class HTTPEnforcementConfiguration:
    """Immutable policy-derived internal HTTP enforcement configuration."""

    maximum_request_starts_per_second: Decimal
    maximum_concurrent_requests: int
    user_agent: str = field(repr=False)
    identification_headers: tuple[IdentificationHeader, ...] = field(
        repr=False
    )
    approved_origins: tuple[HttpOrigin, ...]
    redirect_policy: str = REDIRECT_SAME_ORIGIN
    maximum_redirect_hops: int = DEFAULT_MAXIMUM_REDIRECT_HOPS
    user_agent_source: str = "programme_or_builtin"

    def __post_init__(self) -> None:
        rate = self.maximum_request_starts_per_second
        if (
            isinstance(rate, bool)
            or not isinstance(rate, Decimal)
            or not rate.is_finite()
            or rate <= 0
        ):
            raise ValueError("Runtime HTTP rate must be a positive finite Decimal.")
        concurrency = self.maximum_concurrent_requests
        if (
            isinstance(concurrency, bool)
            or not isinstance(concurrency, int)
            or concurrency <= 0
        ):
            raise ValueError("Runtime HTTP concurrency must be a positive integer.")
        validate_identification_value(self.user_agent, label="Effective User-Agent")
        _require_transport_encodable(
            self.user_agent,
            label="Effective User-Agent",
        )
        validated_headers = validate_identification_headers(
            self.identification_headers
        )
        if validated_headers != self.identification_headers:
            raise ValueError("Runtime identification headers are not canonical.")
        for header in self.identification_headers:
            _require_transport_encodable(
                header.value,
                label="Identification header value",
            )
        if (
            not isinstance(self.approved_origins, tuple)
            or any(not isinstance(origin, HttpOrigin) for origin in self.approved_origins)
            or tuple(sorted(set(self.approved_origins))) != self.approved_origins
        ):
            raise ValueError("Runtime approved HTTP origins are not canonical.")
        if self.redirect_policy != REDIRECT_SAME_ORIGIN:
            raise ValueError("Runtime HTTP redirect policy is unsupported.")
        if (
            isinstance(self.maximum_redirect_hops, bool)
            or not isinstance(self.maximum_redirect_hops, int)
            or not 0 <= self.maximum_redirect_hops <= MAXIMUM_REDIRECT_HOPS
        ):
            raise ValueError("Runtime HTTP redirect hop limit is invalid.")

    @property
    def redacted_metadata(self) -> tuple[tuple[str, str], ...]:
        """Return display-safe runtime configuration metadata."""

        return (
            (
                "maximum_request_starts_per_second",
                str(self.maximum_request_starts_per_second),
            ),
            ("maximum_concurrent_requests", str(self.maximum_concurrent_requests)),
            ("user_agent", "configured"),
            (
                "identification_headers",
                ", ".join(header.name for header in self.identification_headers)
                or "none",
            ),
            ("redirect_policy", self.redirect_policy),
            ("maximum_redirect_hops", str(self.maximum_redirect_hops)),
        )


@dataclass(frozen=True)
class HTTPTransportRequest:
    """One fully prepared internal HTTP exchange passed to the transport."""

    url: str
    method: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    timeout_seconds: int
    maximum_response_bytes: int
    selected_ipv4: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class HTTPTransportResponse:
    """One response returned by an injected single-exchange transport."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class HTTPRedirectHop:
    """One accepted and separately executed redirect transition."""

    status_code: int
    source_url: str
    destination_url: str


@dataclass(frozen=True)
class HTTPRedirectRefusal:
    """One received redirect response whose destination was not transmitted."""

    status_code: int
    source_url: str
    destination_url: str
    reason: str


@dataclass(frozen=True)
class InternalHTTPResponse:
    """Structured response from the central internal execution boundary."""

    requested_url: str
    final_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_seconds: float
    redirects: tuple[HTTPRedirectHop, ...]
    refused_redirect: HTTPRedirectRefusal | None = None


class HTTPTransport(Protocol):
    """Injectable one-exchange transport contract."""

    def __call__(self, request: HTTPTransportRequest) -> HTTPTransportResponse: ...


class InternalHTTPExecutionError(RuntimeError):
    """Base class for redacted internal HTTP execution failures."""


class HTTPExecutorClosed(InternalHTTPExecutionError):
    """Raised when an executor has been cancelled or closed."""

    def __init__(self) -> None:
        super().__init__("Internal HTTP execution is closed.")


class HTTPRedirectRefused(InternalHTTPExecutionError):
    """Raised before transmission when a redirect is not policy-permitted."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Internal HTTP redirect refused: {reason}.")


class HTTPProgrammeScopeRefused(InternalHTTPExecutionError):
    """Raised before transmission when a logical URL or resolved peer is refused."""

    def __init__(self, stage: str, decision: ScopeDecision) -> None:
        if stage not in {"initial", "redirect", "resolved_peer"}:
            raise ValueError("Programme scope refusal stage is invalid.")
        if not isinstance(decision, ScopeDecision) or decision.outcome == OUTCOME_ALLOWED:
            raise ValueError("Programme scope refusal requires a refused decision.")
        self.stage = stage
        self.reason_code = decision.reason_code
        self.operator_safe_explanation = decision.operator_safe_explanation
        super().__init__(
            "Internal HTTP programme scope refused "
            f"at {stage}: {self.reason_code}. {self.operator_safe_explanation}"
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(stage={self.stage!r}, "
            f"reason_code={self.reason_code!r}, "
            "operator_safe_explanation="
            f"{self.operator_safe_explanation!r})"
        )


class HTTPRateRejected(InternalHTTPExecutionError):
    """Typed stage-stop signal for an HTTP 429 response."""

    def __init__(self, retry_after: str) -> None:
        self.status_code = 429
        self.retry_after = retry_after
        super().__init__(
            "The target returned HTTP 429; internal HTTP collection stopped. "
            f"Retry-After: {retry_after}."
        )


class HTTPTransportFailure(InternalHTTPExecutionError):
    """Typed redacted transport failure for collector evidence."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(f"Internal HTTP transport failed: {category}.")


class SteadyRequestStartLimiter:
    """Thread-safe monotonic limiter with no token accumulation or bursts."""

    def __init__(
        self,
        requests_per_second: Decimal,
        *,
        monotonic: Monotonic = system_monotonic,
        sleep: Sleeper = system_sleep,
        interruptible_wait: InterruptibleWaiter | None = None,
    ) -> None:
        if (
            not isinstance(requests_per_second, Decimal)
            or not requests_per_second.is_finite()
            or requests_per_second <= 0
        ):
            raise ValueError("Request-start rate must be a positive finite Decimal.")
        self._interval = Decimal(1) / requests_per_second
        self._monotonic = monotonic
        self._sleep = sleep
        self._interruptible_wait = interruptible_wait
        self._lock = threading.Lock()
        self._next_start: Decimal | None = None

    def wait(
        self,
        *,
        interrupt_event: threading.Event | None = None,
        interrupt_check: Callable[[], None] | None = None,
    ) -> Decimal:
        """Wait until and reserve the next evenly spaced request-start slot."""

        while True:
            if interrupt_check is not None:
                interrupt_check()
            with self._lock:
                now = _monotonic_decimal(self._monotonic)
                if self._next_start is None or now >= self._next_start:
                    self._next_start = now + self._interval
                    return now
                delay = self._next_start - now
            chunk = min(delay, Decimal(MAXIMUM_SLEEP_CHUNK_SECONDS))
            if interrupt_event is not None and self._interruptible_wait is None:
                # Injected sleepers cannot be woken by an Event. Poll at a small,
                # bounded interval while retaining deterministic fake-clock support.
                chunk = min(chunk, MAXIMUM_TERMINAL_POLL_SECONDS)
            sleep_seconds = _conservative_sleep_seconds(chunk)
            interrupted = False
            if interrupt_event is not None and self._interruptible_wait is not None:
                interrupted = self._interruptible_wait(sleep_seconds, interrupt_event)
            else:
                self._sleep(sleep_seconds)
            if interrupted and interrupt_check is not None:
                interrupt_check()
            if interrupt_check is not None:
                interrupt_check()

    def defer_next_start(self) -> Decimal:
        """Conservatively require one full interval after an opaque HTTP tool."""

        with self._lock:
            now = _monotonic_decimal(self._monotonic)
            barrier = now + self._interval
            if self._next_start is None or self._next_start < barrier:
                self._next_start = barrier
            return self._next_start


class _SharedHTTPEnforcementState:
    """Mutable policy enforcement shared by exact-origin executor handles."""

    def __init__(
        self,
        configuration: HTTPEnforcementConfiguration | None,
        *,
        monotonic: Monotonic,
        sleep: Sleeper,
    ) -> None:
        self.maximum_request_starts_per_second = (
            configuration.maximum_request_starts_per_second
            if configuration is not None
            else None
        )
        self.maximum_concurrent_requests = (
            configuration.maximum_concurrent_requests
            if configuration is not None
            else 0
        )
        self.limiter = (
            SteadyRequestStartLimiter(
                configuration.maximum_request_starts_per_second,
                monotonic=monotonic,
                sleep=sleep,
                interruptible_wait=(
                    _wait_for_terminal_event if sleep is system_sleep else None
                ),
            )
            if configuration is not None
            else None
        )
        self.concurrency = (
            threading.BoundedSemaphore(configuration.maximum_concurrent_requests)
            if configuration is not None
            else None
        )
        self.concurrency_gate = threading.Lock()
        self.exclusive_tool_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.total_request_attempts = 0
        self.last_request_start: Decimal | None = None
        self.rate_rejection: HTTPRateRejected | None = None
        self.terminal_event = threading.Event()
        self._handle_wake_events: set[threading.Event] = set()

    def register_handle(self, wake_event: threading.Event) -> None:
        with self.state_lock:
            self._handle_wake_events.add(wake_event)
            terminal = self.rate_rejection is not None
        if terminal:
            wake_event.set()

    def unregister_handle(self, wake_event: threading.Event) -> None:
        with self.state_lock:
            self._handle_wake_events.discard(wake_event)

    def record_rate_rejection(
        self,
        rejection: HTTPRateRejected,
    ) -> HTTPRateRejected:
        with self.state_lock:
            if self.rate_rejection is None:
                self.rate_rejection = rejection
            else:
                rejection = self.rate_rejection
            wake_events = tuple(self._handle_wake_events)
        self.terminal_event.set()
        for event in wake_events:
            event.set()
        return rejection


class InternalHTTPExecutor:
    """Shared mutable runtime enforcing identity, pacing and concurrency."""

    def __init__(
        self,
        configuration: HTTPEnforcementConfiguration | None,
        *,
        programme_scope_policy: ProgrammeScopePolicy | None = None,
        transport: HTTPTransport | None = None,
        ipv4_resolver: IPv4Resolver | None = None,
        monotonic: Monotonic = system_monotonic,
        sleep: Sleeper = system_sleep,
        _shared_enforcement_state: _SharedHTTPEnforcementState | None = None,
    ) -> None:
        if configuration is not None and not isinstance(
            configuration, HTTPEnforcementConfiguration
        ):
            raise ValueError("Internal HTTP enforcement configuration is invalid.")
        if programme_scope_policy is not None and configuration is None:
            raise ValueError(
                "Programme-scoped internal HTTP requires enforcement configuration."
            )
        if programme_scope_policy is not None:
            canonical_programme_scope_policy = _canonical_programme_scope_policy(
                programme_scope_policy
            )
        else:
            canonical_programme_scope_policy = None
        if ipv4_resolver is not None and not callable(ipv4_resolver):
            raise ValueError("Internal HTTP IPv4 resolver is invalid.")
        if (
            canonical_programme_scope_policy is not None
            and transport is not None
            and not isinstance(transport, PeerBoundHTTPTransport)
        ):
            raise ValueError(_PEER_BOUND_TRANSPORT_REQUIRED)
        self.configuration = configuration
        self._programme_scope_policy = canonical_programme_scope_policy
        self._ipv4_resolver = ipv4_resolver or _system_ipv4_resolver
        if transport is not None:
            self.transport = transport
        elif canonical_programme_scope_policy is not None:
            self.transport = PeerBoundHTTPTransport()
        else:
            self.transport = UrllibHTTPTransport(
                direct_only=configuration is not None
            )
        self._monotonic = monotonic
        if _shared_enforcement_state is None:
            shared_state = _SharedHTTPEnforcementState(
                configuration,
                monotonic=monotonic,
                sleep=sleep,
            )
        else:
            if not isinstance(_shared_enforcement_state, _SharedHTTPEnforcementState):
                raise ValueError("Shared internal HTTP enforcement state is invalid.")
            if configuration is None or (
                _shared_enforcement_state.maximum_request_starts_per_second
                != configuration.maximum_request_starts_per_second
                or _shared_enforcement_state.maximum_concurrent_requests
                != configuration.maximum_concurrent_requests
            ):
                raise ValueError("Shared internal HTTP enforcement policy is inconsistent.")
            shared_state = _shared_enforcement_state
        self._shared_enforcement_state = shared_state
        self._limiter = shared_state.limiter
        self._concurrency = shared_state.concurrency
        self._concurrency_limit = shared_state.maximum_concurrent_requests
        self._concurrency_gate = shared_state.concurrency_gate
        self._exclusive_tool_lock = shared_state.exclusive_tool_lock
        self._state_lock = shared_state.state_lock
        self._handle_state_lock = threading.Lock()
        self._closed = False
        self._terminal_event = threading.Event()
        shared_state.register_handle(self._terminal_event)

    @property
    def total_request_attempts(self) -> int:
        with self._state_lock:
            return self._shared_enforcement_state.total_request_attempts

    @property
    def last_request_start(self) -> Decimal | None:
        with self._state_lock:
            return self._shared_enforcement_state.last_request_start

    def close(self) -> None:
        with self._handle_state_lock:
            if self._closed:
                return
            self._closed = True
        self._terminal_event.set()
        self._shared_enforcement_state.unregister_handle(self._terminal_event)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout_seconds: int = 10,
        maximum_response_bytes: int = 1_000_000,
        allow_query_strings: bool = False,
        additional_headers: tuple[tuple[str, str], ...] = (),
    ) -> InternalHTTPResponse:
        """Execute one request and any permitted redirect hops."""

        return self._request(
            url,
            method=method,
            timeout_seconds=timeout_seconds,
            maximum_response_bytes=maximum_response_bytes,
            allow_query_strings=allow_query_strings,
            additional_headers=additional_headers,
            retain_refused_redirect=False,
        )

    def request_retaining_refused_redirect(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout_seconds: int = 10,
        maximum_response_bytes: int = 1_000_000,
        allow_query_strings: bool = False,
        additional_headers: tuple[tuple[str, str], ...] = (),
    ) -> InternalHTTPResponse:
        """Return a received exchange when only its cross-origin hop is refused."""

        return self._request(
            url,
            method=method,
            timeout_seconds=timeout_seconds,
            maximum_response_bytes=maximum_response_bytes,
            allow_query_strings=allow_query_strings,
            additional_headers=additional_headers,
            retain_refused_redirect=True,
        )

    def _request(
        self,
        url: str,
        *,
        method: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
        allow_query_strings: bool,
        additional_headers: tuple[tuple[str, str], ...],
        retain_refused_redirect: bool,
    ) -> InternalHTTPResponse:
        """Execute one bounded request under the selected redirect disposition."""

        method = _validate_request_shape(
            url,
            method,
            timeout_seconds,
            maximum_response_bytes,
            allow_query_strings,
        )
        logical_decision = self._require_programme_scope(url, stage="initial")
        self._require_approved_initial_origin(url)
        selected_ipv4 = self._select_programme_scope_peer(logical_decision)
        headers = self._effective_headers(additional_headers)
        requested_url = url
        current_url = url
        visited = {current_url}
        redirects: list[HTTPRedirectHop] = []
        started = _monotonic_decimal(self._monotonic)

        while True:
            response = self._execute_exchange(
                HTTPTransportRequest(
                    url=current_url,
                    method=method,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                    maximum_response_bytes=maximum_response_bytes,
                    selected_ipv4=selected_ipv4,
                )
            )
            if (
                response.status_code not in _REDIRECT_STATUSES
                or self.configuration is None
            ):
                return InternalHTTPResponse(
                    requested_url=requested_url,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers=response.headers,
                    body=response.body,
                    elapsed_seconds=max(
                        0.0,
                        float(_monotonic_decimal(self._monotonic) - started),
                    ),
                    redirects=tuple(redirects),
                )

            location = _redirect_location(response.headers)
            try:
                destination = self._redirect_destination(
                    current_url,
                    location,
                    allow_query_strings=allow_query_strings,
                )
            except HTTPRedirectRefused as exc:
                if not retain_refused_redirect or exc.reason != "origin_not_approved":
                    raise
                destination = _resolve_redirect_location(current_url, location)
                return InternalHTTPResponse(
                    requested_url=requested_url,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers=response.headers,
                    body=response.body,
                    elapsed_seconds=max(
                        0.0,
                        float(_monotonic_decimal(self._monotonic) - started),
                    ),
                    redirects=tuple(redirects),
                    refused_redirect=HTTPRedirectRefusal(
                        status_code=response.status_code,
                        source_url=current_url,
                        destination_url=destination,
                        reason=exc.reason,
                    ),
                )
            if destination in visited:
                raise HTTPRedirectRefused("redirect_loop")
            if len(redirects) >= self.configuration.maximum_redirect_hops:
                raise HTTPRedirectRefused("redirect_hop_limit")
            redirect_decision = self._require_programme_scope(
                destination,
                stage="redirect",
            )
            redirect_ipv4 = self._select_programme_scope_peer(
                redirect_decision,
            )
            redirects.append(
                HTTPRedirectHop(
                    status_code=response.status_code,
                    source_url=current_url,
                    destination_url=destination,
                )
            )
            visited.add(destination)
            current_url = destination
            selected_ipv4 = redirect_ipv4

    @contextmanager
    def external_request_permit(self) -> Iterator[Decimal]:
        """Reserve one paced opaque HTTP exchange and its completion barrier."""

        if self.configuration is None:
            raise ValueError(
                "External HTTP permits require policy-derived enforcement configuration."
            )
        with self._request_permit() as start:
            try:
                yield start
            finally:
                # A strict external process has one opaque exchange. Its target-visible
                # arrival can lag the permit, so reserve the next interval from process
                # completion before releasing the shared concurrency permit.
                if self._limiter is not None:
                    self._limiter.defer_next_start()

    @contextmanager
    def exclusive_external_http_tool(self) -> Iterator[Decimal]:
        """Reserve the HTTP runtime exclusively for one internally paced tool."""

        if self.configuration is None or self._concurrency is None:
            raise ValueError(
                "External HTTP tools require policy-derived enforcement configuration."
            )
        acquired = 0
        with self._exclusive_tool_lock:
            with self._concurrency_gate:
                try:
                    for _index in range(self._concurrency_limit):
                        self._concurrency.acquire()
                        acquired += 1
                except BaseException:
                    for _index in range(acquired):
                        self._concurrency.release()
                    raise
            try:
                start = self._paced_request_start()
                yield start
            finally:
                if self._limiter is not None:
                    self._limiter.defer_next_start()
                for _index in range(acquired):
                    self._concurrency.release()

    def record_external_rate_rejection(
        self,
        response_headers: tuple[tuple[str, str], ...],
    ) -> HTTPRateRejected:
        """Set the shared terminal HTTP 429 state from an external exchange."""

        rejection = HTTPRateRejected(_safe_retry_after(response_headers))
        return self._shared_enforcement_state.record_rate_rejection(rejection)

    def _execute_exchange(
        self,
        request: HTTPTransportRequest,
    ) -> HTTPTransportResponse:
        if self._programme_scope_policy is not None and not isinstance(
            self.transport,
            PeerBoundHTTPTransport,
        ):
            raise ValueError(_PEER_BOUND_TRANSPORT_REQUIRED)
        with self._request_permit():
            transport_invoked = False
            try:
                transport_invoked = True
                raw_response = self.transport(request)
            except TimeoutError:
                if self.configuration is None:
                    raise
                raise HTTPTransportFailure("timeout") from None
            except OSError:
                if self.configuration is None:
                    raise
                raise HTTPTransportFailure("transport_error") from None
            else:
                response = _validate_transport_response(raw_response)
                if self.configuration is not None and response.status_code == 429:
                    rejection = HTTPRateRejected(_safe_retry_after(response.headers))
                    raise self._shared_enforcement_state.record_rate_rejection(
                        rejection
                    )
                return response
            finally:
                # An internal exchange can reach the target after its permit is
                # committed. Reserve the next interval from exchange completion
                # before the shared concurrency permit is released.
                if transport_invoked and self._limiter is not None:
                    self._limiter.defer_next_start()

    @contextmanager
    def _request_permit(self) -> Iterator[Decimal]:
        self._check_available()
        acquired = False
        if self._concurrency is not None:
            with self._concurrency_gate:
                self._concurrency.acquire()
                acquired = True
        try:
            start = self._paced_request_start()
            yield start
        finally:
            if acquired and self._concurrency is not None:
                self._concurrency.release()

    def _paced_request_start(self) -> Decimal:
        self._check_available()
        start = (
            self._limiter.wait(
                interrupt_event=self._terminal_event,
                interrupt_check=self._check_available,
            )
            if self._limiter is not None
            else _monotonic_decimal(self._monotonic)
        )
        self._commit_request_attempt(start)
        return start

    def _check_available(self) -> None:
        with self._handle_state_lock:
            if self._closed:
                raise HTTPExecutorClosed()
        with self._state_lock:
            self._raise_if_aggregate_unavailable_locked()

    def _commit_request_attempt(self, start: Decimal) -> None:
        """Atomically check terminal state and commit one transport exchange."""

        with self._handle_state_lock:
            if self._closed:
                raise HTTPExecutorClosed()
            with self._state_lock:
                self._raise_if_aggregate_unavailable_locked()
                self._shared_enforcement_state.total_request_attempts += 1
                self._shared_enforcement_state.last_request_start = start

    def _raise_if_aggregate_unavailable_locked(self) -> None:
        rejection = self._shared_enforcement_state.rate_rejection
        if rejection is not None:
            raise HTTPRateRejected(rejection.retry_after)

    def _effective_headers(
        self,
        additional_headers: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        if self.configuration is None:
            user_agent = built_in_user_agent()
            identification_headers: tuple[IdentificationHeader, ...] = ()
        else:
            user_agent = self.configuration.user_agent
            identification_headers = self.configuration.identification_headers
        headers: list[tuple[str, str]] = [("User-Agent", user_agent)]
        headers.extend((header.name, header.value) for header in identification_headers)
        seen = {name.casefold() for name, _value in headers}
        for item in additional_headers:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("Additional HTTP headers must be name/value pairs.")
            name, value = item
            if not isinstance(name, str) or not _HTTP_FIELD_NAME.fullmatch(name):
                raise ValueError("Additional HTTP header name is invalid.")
            try:
                validate_identification_header_name(name)
            except ValueError:
                raise ValueError("Additional HTTP header name is not permitted.") from None
            folded = name.casefold()
            if folded in seen:
                raise ValueError(
                    "Additional HTTP header collides with the effective identity."
                )
            seen.add(folded)
            validated_value = validate_identification_value(
                value,
                label="Additional HTTP header value",
            )
            _require_transport_encodable(
                validated_value,
                label="Additional HTTP header value",
            )
            headers.append((name, validated_value))
        return tuple(headers)

    def _require_approved_initial_origin(self, url: str) -> None:
        if self.configuration is None:
            return
        origin = http_origin_from_url(url)
        if origin not in self.configuration.approved_origins:
            raise ValueError("Internal HTTP request origin is not approved.")

    def _require_programme_scope(
        self,
        url: str,
        *,
        stage: str,
    ) -> ScopeDecision | None:
        """Return the canonical logical URL decision after enforcing scope."""

        if self._programme_scope_policy is None:
            return None
        decision = evaluate_raw_scope_destination(
            self._programme_scope_policy,
            DESTINATION_HTTP_URL,
            url,
        )
        if decision.outcome != OUTCOME_ALLOWED:
            raise HTTPProgrammeScopeRefused(stage, decision)
        return decision

    def _select_programme_scope_peer(
        self,
        logical_decision: ScopeDecision | None,
    ) -> str | None:
        if self._programme_scope_policy is None:
            return None
        return select_programme_scope_ipv4_peer(
            self._programme_scope_policy,
            logical_decision,
            self._ipv4_resolver,
        )

    def _redirect_destination(
        self,
        current_url: str,
        location: str,
        *,
        allow_query_strings: bool,
    ) -> str:
        if self.configuration is None:
            raise HTTPRedirectRefused("redirect_policy_unavailable")
        return resolve_policy_redirect(
            current_url,
            location,
            approved_origins=self.configuration.approved_origins,
            allow_query_strings=allow_query_strings,
        )


def select_programme_scope_ipv4_peer(
    policy: ProgrammeScopePolicy,
    logical_decision: ScopeDecision | None,
    ipv4_resolver: IPv4Resolver,
    *,
    resolver_port: int | None = None,
) -> str:
    """Select the one peer authorised by the accepted complete-set semantics."""

    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("A canonical programme scope policy is required.")
    if logical_decision is None or logical_decision.outcome != OUTCOME_ALLOWED:
        raise ValueError("Canonical logical programme scope decision is required.")
    if not callable(ipv4_resolver):
        raise ValueError("Internal HTTP IPv4 resolver is invalid.")
    destination = logical_decision.canonical_destination
    if isinstance(destination, CanonicalHTTPURLDestination):
        if destination.origin.host_kind == DESTINATION_IPV4:
            return destination.origin.host
        if destination.origin.host_kind != DESTINATION_HOSTNAME:
            raise HTTPTransportFailure("invalid_resolver_result")
        hostname = destination.origin.host
        port = destination.origin.effective_port
    elif isinstance(destination, CanonicalHostnameDestination):
        if (
            isinstance(resolver_port, bool)
            or not isinstance(resolver_port, int)
            or not 0 <= resolver_port <= 65535
        ):
            raise ValueError("Canonical hostname peer selection requires a resolver port.")
        hostname = destination.hostname
        port = resolver_port
    else:
        raise ValueError("Canonical logical hostname or HTTP destination is required.")

    try:
        raw_candidates = ipv4_resolver(hostname, port)
    except HTTPTransportFailure:
        raise
    except (OSError, ValueError, TypeError):
        raise HTTPTransportFailure("dns_error") from None
    candidates = _canonical_ipv4_candidates(raw_candidates)
    decisions: list[tuple[str, ScopeDecision]] = []
    for candidate in candidates:
        resolved_peer = canonicalise_resolved_ipv4_peer(destination, candidate)
        decisions.append(
            (
                candidate,
                evaluate_resolved_ipv4_peer(
                    policy,
                    logical_decision,
                    resolved_peer,
                ),
            )
        )

    blocked = [item for item in decisions if item[1].outcome == OUTCOME_BLOCKED]
    non_allowed = [item for item in decisions if item[1].outcome != OUTCOME_ALLOWED]
    refused = blocked or non_allowed
    if refused:
        _candidate, decision = min(
            refused,
            key=lambda item: int(ipaddress.IPv4Address(item[0])),
        )
        raise HTTPProgrammeScopeRefused("resolved_peer", decision)
    return candidates[0]


def _canonical_programme_scope_policy(
    policy: ProgrammeScopePolicy,
) -> ProgrammeScopePolicy:
    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("A canonical programme scope policy is required.")
    if policy.engagement_context != BUG_BOUNTY_CONTEXT:
        raise ValueError("Programme scope policy context must be bug_bounty.")
    try:
        canonical_rules = tuple(
            build_programme_scope_rule(
                rule_id=rule.rule_id,
                action=rule.action,
                kind=rule.kind,
                value=rule.canonical_value,
                scheme=rule.scheme,
                port=rule.port,
                private_note=rule.private_note,
                private_source_wording=rule.private_source_wording,
            )
            for rule in policy.rules
        )
        canonical = build_programme_scope_policy(
            canonical_rules,
            schema_version=policy.schema_version,
            engagement_context=policy.engagement_context,
            updated_at=policy.updated_at,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Programme scope policy is not canonical.") from None
    if canonical != policy:
        raise ValueError("Programme scope policy is not canonical.")
    return canonical


def _system_ipv4_resolver(hostname: str, port: int) -> tuple[str, ...]:
    """Resolve TCP peers and retain only strict canonical IPv4 addresses."""

    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        raise HTTPTransportFailure("dns_error") from None
    if not isinstance(records, list):
        raise HTTPTransportFailure("invalid_resolver_result")

    candidates: list[str] = []
    for record in records:
        if not isinstance(record, tuple) or len(record) != 5:
            raise HTTPTransportFailure("invalid_resolver_result")
        family, socket_type, protocol, canonical_name, socket_address = record
        if (
            socket_type != socket.SOCK_STREAM
            or protocol != socket.IPPROTO_TCP
            or not isinstance(canonical_name, str)
            or not isinstance(socket_address, tuple)
        ):
            raise HTTPTransportFailure("invalid_resolver_result")
        if family == socket.AF_INET:
            if (
                len(socket_address) != 2
                or not isinstance(socket_address[0], str)
                or socket_address[1] != port
            ):
                raise HTTPTransportFailure("invalid_resolver_result")
            try:
                candidates.append(canonicalise_ipv4(socket_address[0]))
            except ValueError:
                raise HTTPTransportFailure("invalid_resolver_result") from None
        elif family == socket.AF_INET6:
            if (
                len(socket_address) != 4
                or not isinstance(socket_address[0], str)
                or socket_address[1] != port
                or not all(isinstance(value, int) for value in socket_address[2:])
            ):
                raise HTTPTransportFailure("invalid_resolver_result")
            try:
                ipaddress.IPv6Address(socket_address[0])
            except ValueError:
                raise HTTPTransportFailure("invalid_resolver_result") from None
        else:
            raise HTTPTransportFailure("invalid_resolver_result")
    return tuple(candidates)


def _canonical_ipv4_candidates(result: object) -> tuple[str, ...]:
    if not isinstance(result, tuple):
        raise HTTPTransportFailure("invalid_resolver_result")
    candidates: set[str] = set()
    for item in result:
        if not isinstance(item, str):
            raise HTTPTransportFailure("invalid_resolver_result")
        try:
            candidate = canonicalise_ipv4(item)
        except ValueError:
            raise HTTPTransportFailure("invalid_resolver_result") from None
        candidates.add(candidate)
    if not candidates:
        raise HTTPTransportFailure("no_usable_ipv4")
    return tuple(sorted(candidates, key=lambda value: int(ipaddress.IPv4Address(value))))


def _connect_selected_ipv4(
    selected_ipv4: str,
    port: int,
    timeout_seconds: int,
    *,
    socket_factory: SocketFactory = socket.socket,
) -> socket.socket:
    """Connect once to one approved IPv4 and verify the resulting TCP peer."""

    try:
        canonical_peer = canonicalise_ipv4(selected_ipv4)
    except ValueError:
        raise HTTPTransportFailure("invalid_resolver_result") from None
    connected_socket = None
    try:
        connected_socket = socket_factory(
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        connected_socket.settimeout(timeout_seconds)
        connected_socket.connect((canonical_peer, port))
        peer_name = connected_socket.getpeername()
        if (
            not isinstance(peer_name, tuple)
            or len(peer_name) < 2
            or not isinstance(peer_name[0], str)
        ):
            raise HTTPTransportFailure("peer_mismatch")
        try:
            actual_peer = canonicalise_ipv4(peer_name[0])
        except ValueError:
            raise HTTPTransportFailure("peer_mismatch") from None
        if actual_peer != canonical_peer:
            raise HTTPTransportFailure("peer_mismatch")
        return connected_socket
    except TimeoutError:
        if connected_socket is not None:
            connected_socket.close()
        raise
    except HTTPTransportFailure:
        if connected_socket is not None:
            connected_socket.close()
        raise
    except OSError:
        if connected_socket is not None:
            connected_socket.close()
        raise HTTPTransportFailure("connect_error") from None
    except BaseException:
        if connected_socket is not None:
            connected_socket.close()
        raise


class PeerBoundHTTPTransport:
    """Single-exchange HTTP/1.1 transport bound to one pre-approved IPv4 peer."""

    def __init__(
        self,
        *,
        socket_factory: SocketFactory = socket.socket,
        http_connection_factory: Callable[..., HTTPConnection] = HTTPConnection,
        https_connection_factory: Callable[..., HTTPSConnection] = HTTPSConnection,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    ) -> None:
        self._socket_factory = socket_factory
        self._http_connection_factory = http_connection_factory
        self._https_connection_factory = https_connection_factory
        self._ssl_context_factory = ssl_context_factory

    def __call__(self, request: HTTPTransportRequest) -> HTTPTransportResponse:
        if request.selected_ipv4 is None:
            raise HTTPTransportFailure("invalid_resolver_result")
        parsed = urlparse(request.url)
        logical_host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or logical_host is None:
            raise HTTPTransportFailure("transport_error")
        try:
            port = parsed.port
        except ValueError:
            raise HTTPTransportFailure("transport_error") from None
        effective_port = port or (80 if parsed.scheme.lower() == "http" else 443)
        target = parsed.path or "/"
        if "?" in request.url:
            target = f"{target}?{parsed.query}"

        headers = dict(request.headers)
        if not any(name.casefold() == "host" for name in headers):
            default_port = 80 if parsed.scheme.lower() == "http" else 443
            headers["Host"] = (
                logical_host
                if effective_port == default_port
                else f"{logical_host}:{effective_port}"
            )
        if not any(name.casefold() == "connection" for name in headers):
            headers["Connection"] = "close"

        context = None
        if parsed.scheme.lower() == "https":
            try:
                context = self._ssl_context_factory()
                if (
                    context.verify_mode != ssl.CERT_REQUIRED
                    or context.check_hostname is not True
                ):
                    raise HTTPTransportFailure("tls_error")
                context.set_alpn_protocols(["http/1.1"])
                if context.post_handshake_auth is not None:
                    context.post_handshake_auth = True
            except HTTPTransportFailure:
                raise
            except (OSError, ssl.SSLError):
                raise HTTPTransportFailure("tls_error") from None
            connection = self._https_connection_factory(
                logical_host,
                effective_port,
                timeout=request.timeout_seconds,
                context=context,
            )
        else:
            connection = self._http_connection_factory(
                logical_host,
                effective_port,
                timeout=request.timeout_seconds,
            )

        def create_peer_connection(
            _address,
            timeout=request.timeout_seconds,
            _source_address=None,
        ):
            return _connect_selected_ipv4(
                request.selected_ipv4,
                effective_port,
                timeout,
                socket_factory=self._socket_factory,
            )

        connection._create_connection = create_peer_connection
        response = None
        try:
            connection.request(request.method, target, headers=headers)
            response = connection.getresponse()
            body = response.read(request.maximum_response_bytes + 1)
            response_headers = tuple(
                (str(name), str(value)) for name, value in response.headers.items()
            )
            status = response.status
        except TimeoutError:
            raise
        except HTTPTransportFailure:
            raise
        except ssl.SSLError:
            raise HTTPTransportFailure("tls_error") from None
        except (HTTPException, OSError):
            raise HTTPTransportFailure("transport_error") from None
        finally:
            if response is not None:
                response.close()
            connection.close()
        return HTTPTransportResponse(
            status_code=status,
            headers=response_headers,
            body=body,
        )


class UrllibHTTPTransport:
    """Standard-library single-exchange transport with redirects disabled."""

    def __init__(self, *, direct_only: bool = False) -> None:
        self._opener = (
            build_opener(ProxyHandler({}), _NoRedirectHandler)
            if direct_only
            else None
        )

    def __call__(self, request: HTTPTransportRequest) -> HTTPTransportResponse:
        urllib_request = Request(
            request.url,
            headers=dict(request.headers),
            method=request.method,
        )
        opener = (
            self._opener
            if self._opener is not None
            else build_opener(_NoRedirectHandler)
        )
        try:
            response = opener.open(urllib_request, timeout=request.timeout_seconds)
        except HTTPError as error:
            response = error
        try:
            body = response.read(request.maximum_response_bytes + 1)
            headers = tuple(
                (str(name), str(value)) for name, value in response.headers.items()
            )
            status = _response_status(response)
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()
        return HTTPTransportResponse(status_code=status, headers=headers, body=body)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from following redirects outside the central executor."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def build_http_enforcement_configuration(
    policy: EngagementPolicy,
    *,
    approved_origins: tuple[str, ...],
) -> HTTPEnforcementConfiguration:
    """Derive immutable runtime enforcement only from a complete private policy."""

    if not isinstance(policy, EngagementPolicy):
        raise ValueError("A canonical bug bounty engagement policy is required.")
    canonical = policy_from_dict(policy.to_dict())
    assessment = assess_engagement_policy(canonical)
    if assessment.readiness_state != READINESS_FUTURE_ENFORCEMENT:
        raise ValueError(
            "Engagement policy is incomplete and cannot configure internal HTTP enforcement."
        )
    if canonical.automated_reconnaissance != AUTOMATION_PERMITTED:
        raise ValueError(
            "Automated reconnaissance is not confirmed for internal HTTP enforcement."
        )
    origins: list[HttpOrigin] = []
    for value in approved_origins:
        origin = http_origin_from_url(value)
        if origin is None:
            raise ValueError("Approved HTTP origin is invalid.")
        origins.append(origin)
    canonical_origins = tuple(sorted(set(origins)))
    if not canonical_origins:
        raise ValueError("At least one approved HTTP origin is required.")
    return HTTPEnforcementConfiguration(
        maximum_request_starts_per_second=Decimal(
            canonical.maximum_http_requests_per_second
        ),
        maximum_concurrent_requests=canonical.maximum_http_concurrency,
        user_agent=canonical.custom_user_agent or built_in_user_agent(),
        identification_headers=canonical.identification_headers,
        approved_origins=canonical_origins,
        user_agent_source=(
            "programme_custom" if canonical.custom_user_agent else "bugslyce_builtin"
        ),
    )


def build_internal_http_executor_view(
    source_executor: InternalHTTPExecutor,
    *,
    approved_origins: tuple[str, ...],
) -> InternalHTTPExecutor:
    """Derive an exact-origin handle sharing one aggregate HTTP policy runtime."""

    if not isinstance(source_executor, InternalHTTPExecutor):
        raise ValueError("Internal HTTP executor view source is invalid.")
    source_configuration = source_executor.configuration
    if source_configuration is None:
        raise ValueError("Internal HTTP executor view source is not configured.")
    with source_executor._handle_state_lock:
        if source_executor._closed:
            raise HTTPExecutorClosed()
    if (
        source_executor._programme_scope_policy is not None
        and not isinstance(source_executor.transport, PeerBoundHTTPTransport)
    ):
        raise ValueError(_PEER_BOUND_TRANSPORT_REQUIRED)
    if not isinstance(approved_origins, tuple):
        raise ValueError("Internal HTTP executor view origins are invalid.")
    origins: list[HttpOrigin] = []
    for value in approved_origins:
        origin = http_origin_from_url(value)
        if origin is None:
            raise ValueError("Internal HTTP executor view origin is invalid.")
        origins.append(origin)
    canonical_origins = tuple(sorted(set(origins)))
    if not canonical_origins:
        raise ValueError("Internal HTTP executor view requires an approved origin.")

    configuration = HTTPEnforcementConfiguration(
        maximum_request_starts_per_second=(
            source_configuration.maximum_request_starts_per_second
        ),
        maximum_concurrent_requests=(
            source_configuration.maximum_concurrent_requests
        ),
        user_agent=source_configuration.user_agent,
        identification_headers=source_configuration.identification_headers,
        approved_origins=canonical_origins,
        redirect_policy=source_configuration.redirect_policy,
        maximum_redirect_hops=source_configuration.maximum_redirect_hops,
        user_agent_source=source_configuration.user_agent_source,
    )
    return InternalHTTPExecutor(
        configuration,
        programme_scope_policy=source_executor._programme_scope_policy,
        ipv4_resolver=source_executor._ipv4_resolver,
        monotonic=source_executor._monotonic,
        _shared_enforcement_state=source_executor._shared_enforcement_state,
    )


def internal_http_executors_share_enforcement_state(
    source_executor: object,
    candidate_executor: object,
) -> bool:
    """Return whether two handles share the same aggregate HTTP enforcement state."""

    return (
        isinstance(source_executor, InternalHTTPExecutor)
        and isinstance(candidate_executor, InternalHTTPExecutor)
        and source_executor._shared_enforcement_state
        is candidate_executor._shared_enforcement_state
    )


def _monotonic_decimal(monotonic: Monotonic) -> Decimal:
    value = monotonic()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("Monotonic clock returned an invalid value.")
    parsed = Decimal(str(value))
    if not parsed.is_finite():
        raise RuntimeError("Monotonic clock returned an invalid value.")
    return parsed


def _wait_for_terminal_event(seconds: float, event: threading.Event) -> bool:
    """Sleep until a terminal event or the next pacing deadline, whichever is first."""

    return event.wait(seconds)


def _conservative_sleep_seconds(delay: Decimal) -> float:
    """Return a finite positive float wait that never shortens a Decimal delay."""

    sleep_seconds = float(delay)
    if not math.isfinite(sleep_seconds):
        raise RuntimeError("Request-start limiter produced an invalid delay.")
    if sleep_seconds <= 0:
        return math.nextafter(0.0, 1.0)
    if Decimal.from_float(sleep_seconds) < delay:
        return math.nextafter(sleep_seconds, math.inf)
    return sleep_seconds


def _require_transport_encodable(value: str, *, label: str) -> None:
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError(
            f"{label} cannot be represented by the internal HTTP transport."
        ) from None


def _validate_request_shape(
    url: str,
    method: str,
    timeout_seconds: int,
    maximum_response_bytes: int,
    allow_query_strings: bool,
) -> str:
    if not isinstance(url, str):
        raise ValueError("Internal HTTP request URL is invalid.")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("unsupported_scheme")
    if not parsed.hostname:
        raise ValueError("missing_hostname")
    if parsed.username or parsed.password:
        raise ValueError("url_userinfo_not_allowed")
    if parsed.fragment:
        raise ValueError("url_fragment_not_allowed")
    if not isinstance(allow_query_strings, bool):
        raise ValueError("Internal HTTP query-string policy is invalid.")
    if parsed.query and not allow_query_strings:
        raise ValueError("query_string_not_allowed")
    normalised_method = method.upper().strip() if isinstance(method, str) else ""
    if normalised_method not in {"GET", "HEAD"}:
        raise ValueError("method_not_allowed")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ValueError("Internal HTTP timeout is invalid.")
    if (
        isinstance(maximum_response_bytes, bool)
        or not isinstance(maximum_response_bytes, int)
        or maximum_response_bytes <= 0
    ):
        raise ValueError("Internal HTTP response bound is invalid.")
    return normalised_method


def _validate_transport_response(response: object) -> HTTPTransportResponse:
    if not isinstance(response, HTTPTransportResponse):
        raise ValueError("Internal HTTP transport returned an invalid response.")
    if (
        isinstance(response.status_code, bool)
        or not isinstance(response.status_code, int)
        or not 100 <= response.status_code <= 599
    ):
        raise ValueError("Internal HTTP transport returned an invalid status.")
    if not isinstance(response.body, bytes):
        raise ValueError("Internal HTTP transport returned an invalid body.")
    for item in response.headers:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(value, str) for value in item)
        ):
            raise ValueError("Internal HTTP transport returned invalid headers.")
    return response


def _redirect_location(headers: tuple[tuple[str, str], ...]) -> str:
    values = [value for name, value in headers if name.casefold() == "location"]
    if len(values) != 1:
        raise HTTPRedirectRefused("malformed_location")
    return values[0]


def _resolve_redirect_location(current_url: str, location: str) -> str:
    if (
        not isinstance(location, str)
        or not location
        or location != location.strip()
        or _contains_unsafe_target_text(location)
    ):
        raise HTTPRedirectRefused("malformed_location")
    try:
        destination = urljoin(current_url, location)
        parsed = urlparse(destination)
        _ = parsed.port
    except (TypeError, ValueError):
        raise HTTPRedirectRefused("malformed_location") from None
    if parsed.fragment or parsed.username or parsed.password:
        raise HTTPRedirectRefused("unsupported_redirect")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HTTPRedirectRefused("unsupported_redirect")
    return destination


def resolve_policy_redirect(
    current_url: str,
    location: str,
    *,
    approved_origins: tuple[HttpOrigin, ...],
    allow_query_strings: bool = False,
) -> str:
    """Resolve one redirect using the same strict policy for every HTTP transport."""

    destination = _resolve_redirect_location(current_url, location)
    if urlparse(destination).query and not allow_query_strings:
        raise HTTPRedirectRefused("redirect_query_not_allowed")
    current_origin = http_origin_from_url(current_url)
    destination_origin = http_origin_from_url(destination)
    if current_origin is None or destination_origin is None:
        raise HTTPRedirectRefused("unsupported_redirect")
    if current_origin == destination_origin:
        return destination
    if current_origin.scheme == "https" and destination_origin.scheme == "http":
        raise HTTPRedirectRefused("https_downgrade")
    approved = set(approved_origins)
    if (
        current_origin.scheme == "http"
        and destination_origin.scheme == "https"
        and current_origin.hostname == destination_origin.hostname
    ):
        if current_origin in approved and destination_origin in approved:
            return destination
        raise HTTPRedirectRefused("http_upgrade_not_approved")
    raise HTTPRedirectRefused("origin_not_approved")


def _safe_retry_after(headers: tuple[tuple[str, str], ...]) -> str:
    values = [value for name, value in headers if name.casefold() == "retry-after"]
    if not values:
        return "not provided"
    value = values[0]
    if _contains_unsafe_target_text(value):
        return "present but unsafe value omitted"
    if len(value) > MAXIMUM_RETRY_AFTER_CHARS:
        return value[: MAXIMUM_RETRY_AFTER_CHARS - 3] + "..."
    return value or "empty"


def _contains_unsafe_target_text(value: str) -> bool:
    """Reject controls and directional formatting from target-controlled text."""

    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or character in {"\u2028", "\u2029"}
        for character in value
    )


def _response_status(response: object) -> int:
    status = getattr(response, "status", None)
    if status is not None:
        return int(status)
    code = getattr(response, "code", None)
    if code is not None:
        return int(code)
    getcode = getattr(response, "getcode")
    return int(getcode())
