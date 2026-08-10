"""Focused tests for R0B1 internal HTTP enforcement."""

from __future__ import annotations

from decimal import Decimal
import math
import os
from pathlib import Path
import re
import socket
import ssl
import threading
from urllib.request import ProxyHandler

import pytest

import bugslyce.recon.http_enforcement as http_enforcement_module
import bugslyce.cli as cli_module
from bugslyce import __version__
from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IDENTIFICATION_NONE,
    IDENTIFICATION_UNKNOWN,
    IdentificationHeader,
    build_bug_bounty_policy,
)
from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopePolicy,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.project_session import (
    initialize_project,
    save_project_engagement_policy,
)
from bugslyce.recon.deep_http_fetcher import urllib_deep_http_fetcher
from bugslyce.recon.http_enforcement import (
    HTTPEnforcementConfiguration,
    HTTPExecutorClosed,
    HTTPRateRejected,
    HTTPRedirectRefused,
    HTTPTransportResponse,
    HTTPTransportFailure,
    InternalHTTPExecutor,
    SteadyRequestStartLimiter,
    UrllibHTTPTransport,
    _resolve_redirect_location,
    _safe_retry_after,
    build_http_enforcement_configuration,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.user_agent import (
    R0B2_POLICY_AWARE_EXTERNAL_BOUNDARIES,
    R0B3_BLOCKED_LEGACY_LIVE_RUNNERS,
    built_in_user_agent,
)


HEADER_SENTINEL = "private-researcher-identity-9173"
USER_AGENT_SENTINEL = "PrivateProgrammeAgent/9173"
ORDINARY_PUBLIC_IPV4 = "8.8.8.8"


@pytest.fixture(autouse=True)
def _prevent_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        _hostname,
        port,
        family,
        socket_type,
        protocol,
    ):
        assert family == socket.AF_UNSPEC
        assert socket_type == socket.SOCK_STREAM
        assert protocol == socket.IPPROTO_TCP
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ORDINARY_PUBLIC_IPV4, port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


class _FakeTime:
    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleeps: list[Decimal] = []
        self._lock = threading.Lock()

    def monotonic(self) -> float:
        with self._lock:
            return float(self.now)

    def sleep(self, seconds: float) -> None:
        duration = Decimal(str(seconds))
        with self._lock:
            self.sleeps.append(duration)
            self.now += duration


class _RecordingTransport:
    def __init__(
        self,
        responses: list[HTTPTransportResponse] | None = None,
        *,
        clock: _FakeTime | None = None,
        error: Exception | None = None,
    ) -> None:
        self.responses = list(responses or [_response()])
        self.clock = clock
        self.error = error
        self.requests = []
        self.starts: list[Decimal] = []

    def __call__(self, request):
        self.requests.append(request)
        if self.clock is not None:
            self.starts.append(self.clock.now)
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


class _RecordingPeerBoundTransport(
    _RecordingTransport,
    http_enforcement_module.PeerBoundHTTPTransport,
):
    """Deterministic scoped fake retaining the peer-bound transport capability."""


class _PeerSocket:
    def __init__(
        self,
        peer: str,
        events: list[tuple[object, ...]],
        *,
        connect_error: BaseException | None = None,
    ) -> None:
        self.peer = peer
        self.events = events
        self.connect_error = connect_error
        self.closed = False

    def settimeout(self, timeout: int) -> None:
        self.events.append(("timeout", timeout))

    def connect(self, address: tuple[str, int]) -> None:
        self.events.append(("connect", address))
        if self.connect_error is not None:
            raise self.connect_error

    def getpeername(self) -> tuple[str, int]:
        self.events.append(("getpeername",))
        return self.peer, 443

    def close(self) -> None:
        self.closed = True
        self.events.append(("socket_close",))


class _HTTPClientResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def __init__(self) -> None:
        self.closed = False
        self.read_limits: list[int] = []

    def read(self, limit: int) -> bytes:
        self.read_limits.append(limit)
        return b"peer-bound"

    def close(self) -> None:
        self.closed = True


class _HTTPClientConnection:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        events: list[tuple[object, ...]],
        response: _HTTPClientResponse,
        context=None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.events = events
        self.response = response
        self.context = context
        self._create_connection = None
        self.closed = False

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        assert self._create_connection is not None
        raw_socket = self._create_connection(
            (self.host, self.port),
            self.timeout,
            None,
        )
        if self.context is not None:
            raw_socket = self.context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        self.events.append(("request", method, target, headers, raw_socket))

    def getresponse(self) -> _HTTPClientResponse:
        self.events.append(("getresponse",))
        return self.response

    def close(self) -> None:
        self.closed = True
        self.events.append(("connection_close",))


class _VerifiedSSLContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True
    post_handshake_auth = False

    def __init__(self, events: list[tuple[object, ...]]) -> None:
        self.events = events

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.events.append(("alpn", tuple(protocols)))

    def wrap_socket(self, raw_socket, *, server_hostname: str):
        self.events.append(("tls", server_hostname, raw_socket))
        return ("tls-socket", raw_socket)


class _FakeUrllibResponse:
    def __init__(self, *, body: bytes = b"direct-response") -> None:
        self.status = 200
        self.headers = {"Content-Type": "text/plain"}
        self.body = body
        self.closed = False

    def read(self, maximum_bytes: int) -> bytes:
        return self.body[:maximum_bytes]

    def close(self) -> None:
        self.closed = True


class _RecordingOpener:
    def __init__(self, *, error: BaseException | None = None) -> None:
        self.error = error
        self.requests = []
        self.timeouts: list[int] = []

    def open(self, request, *, timeout: int):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return _FakeUrllibResponse()


class _DelayedRecordingTransport:
    """Record deterministic target-visible arrivals for internal exchanges."""

    def __init__(
        self,
        clock: _FakeTime,
        delays: tuple[Decimal, ...],
        responses: list[HTTPTransportResponse] | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.clock = clock
        self.delays = iter(delays)
        self.responses = list(responses or [_response()])
        self.error = error
        self.requests = []
        self.starts: list[Decimal] = []
        self.arrivals: list[Decimal] = []

    def __call__(self, request):
        self.requests.append(request)
        self.starts.append(self.clock.now)
        self.clock.now += next(self.delays)
        self.arrivals.append(self.clock.now)
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


class _BlockingTransport:
    def __init__(self, expected_active: int) -> None:
        self.expected_active = expected_active
        self.entered = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.active = 0
        self.maximum_active = 0

    def __call__(self, _request):
        with self.lock:
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            if self.active >= self.expected_active:
                self.entered.set()
        if not self.release.wait(timeout=2):
            raise AssertionError("test transport was not released")
        with self.lock:
            self.active -= 1
        return _response()


class _BlockingRateRejectionTransport:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.calls = 0

    def __call__(self, _request):
        with self.lock:
            self.calls += 1
            call_number = self.calls
        if call_number != 1:
            raise AssertionError("queued request reached transport after HTTP 429")
        self.entered.set()
        if not self.release.wait(timeout=2):
            raise AssertionError("test transport was not released")
        return _response(429, (("Retry-After", "2"),))


class _GateTime:
    """A fake clock whose next limiter sleep waits for test coordination."""

    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleeper_entered = threading.Event()
        self.release_sleeper = threading.Event()
        self.sleeps: list[Decimal] = []
        self._lock = threading.Lock()

    def monotonic(self) -> float:
        with self._lock:
            return float(self.now)

    def sleep(self, seconds: float) -> None:
        delay = Decimal(str(seconds))
        with self._lock:
            self.sleeps.append(delay)
        self.sleeper_entered.set()
        if not self.release_sleeper.wait(timeout=2):
            raise AssertionError("test limiter sleeper was not released")
        with self._lock:
            self.now += delay


class _FirstExchangeGateTransport:
    """Keep the first exchange in flight while a second request is paced."""

    def __init__(self, first_response: HTTPTransportResponse) -> None:
        self.first_response = first_response
        self.first_entered = threading.Event()
        self.release_first = threading.Event()
        self.requests = []
        self._lock = threading.Lock()

    def __call__(self, request):
        with self._lock:
            self.requests.append(request)
            request_number = len(self.requests)
        if request_number == 1:
            self.first_entered.set()
            if not self.release_first.wait(timeout=2):
                raise AssertionError("test first exchange was not released")
            return self.first_response
        return _response()


class _StopAfterFirstSleep(Exception):
    """Terminate a deliberately enormous deterministic limiter wait."""


class _FiniteChunkProbe:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        assert math.isfinite(seconds)
        assert seconds > 0
        raise _StopAfterFirstSleep()


class _EarlyReturnClock:
    """Return early from sleeps to prove limiter clock rechecks remain safe."""

    def __init__(self) -> None:
        self.now = Decimal("0")
        self.calls: list[Decimal] = []

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        delay = Decimal(str(seconds))
        self.calls.append(delay)
        self.now += delay / Decimal(2) if len(self.calls) == 1 else delay


class _SecondSleepObserved(Exception):
    """Prove a terminal state did not interrupt a queued limiter wait."""


class _ExtremeWaitGateTime:
    """Release one extreme-rate sleep and fail if a second wait is attempted."""

    def __init__(self) -> None:
        self.now = Decimal("0")
        self.first_sleep_entered = threading.Event()
        self.release_first_sleep = threading.Event()
        self.second_sleep_entered = threading.Event()
        self.sleeps: list[Decimal] = []
        self._lock = threading.Lock()

    def monotonic(self) -> float:
        with self._lock:
            return float(self.now)

    def sleep(self, seconds: float) -> None:
        delay = Decimal(str(seconds))
        with self._lock:
            self.sleeps.append(delay)
            sleep_number = len(self.sleeps)
        if sleep_number == 1:
            self.first_sleep_entered.set()
            if not self.release_first_sleep.wait(timeout=2):
                raise AssertionError("test extreme wait was not released")
            with self._lock:
                self.now += delay
            return
        self.second_sleep_entered.set()
        raise _SecondSleepObserved()


class _FiniteAdvancingClock:
    """Capture sleeper arguments while advancing a deterministic monotonic clock."""

    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        assert math.isfinite(seconds)
        assert seconds > 0
        self.now += Decimal(str(seconds))


def test_policy_configuration_derives_exact_private_identity_without_repr_leak() -> None:
    policy = _complete_policy()

    configuration = build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test",),
    )

    assert configuration.maximum_request_starts_per_second == Decimal("2")
    assert configuration.maximum_concurrent_requests == 1
    assert configuration.user_agent == USER_AGENT_SENTINEL
    assert configuration.identification_headers == (
        IdentificationHeader("X-Researcher-ID", HEADER_SENTINEL),
    )
    assert HEADER_SENTINEL not in repr(configuration)
    assert USER_AGENT_SENTINEL not in repr(configuration)


@pytest.mark.parametrize(
    ("rules", "url", "allow_query_strings", "allowed", "reason_code"),
    (
        ((("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
         "https://example.test/path", False, True, None),
        ((("wild", ACTION_INCLUDE, RULE_WILDCARD_SUBDOMAIN, "*.example.test"),),
         "https://deep.api.example.test/path", False, True, None),
        ((("wild", ACTION_INCLUDE, RULE_WILDCARD_SUBDOMAIN, "*.example.test"),),
         "https://example.test/path", False, False, "no_matching_inclusion"),
        ((("url", ACTION_INCLUDE, RULE_EXACT_HTTP_URL,
           "https://example.test/exact?order=1&order=2"),),
         "https://example.test/exact?order=1&order=2", True, True, None),
        ((("url", ACTION_INCLUDE, RULE_EXACT_HTTP_URL,
           "https://example.test/exact?order=1&order=2"),),
         "https://example.test/exact?order=2&order=1", True, False,
         "no_matching_inclusion"),
        ((("path", ACTION_INCLUDE, RULE_HTTP_PATH_PREFIX,
           "https://example.test/api"),),
         "https://example.test/api/items?view=short", True, True, None),
        ((("ip", ACTION_INCLUDE, RULE_EXACT_IPV4, "192.0.2.10"),),
         "https://192.0.2.10/path", False, True, None),
        ((("cidr", ACTION_INCLUDE, RULE_IPV4_CIDR, "192.0.2.0/24"),),
         "https://192.0.2.200/path", False, True, None),
        ((("cidr", ACTION_INCLUDE, RULE_IPV4_CIDR, "192.0.2.0/24"),),
         "https://example.test/path", False, False, "no_matching_inclusion"),
        ((
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("private", ACTION_EXCLUDE, RULE_HTTP_PATH_PREFIX,
             "https://example.test/private"),
         ), "https://example.test/private/item", False, False,
         "explicit_exclusion"),
        ((
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("exact", ACTION_INCLUDE, RULE_EXACT_HTTP_URL,
             "https://example.test/private/item"),
            ("private", ACTION_EXCLUDE, RULE_HTTP_PATH_PREFIX,
             "https://example.test/private"),
         ), "https://example.test/private/item", False, False,
         "explicit_exclusion"),
        ((("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
         "https://other.test/path", False, False, "no_matching_inclusion"),
        ((("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
         "https://example.test/%2f", False, False, "invalid_destination"),
    ),
)
def test_programme_scope_controls_initial_logical_url_before_transport(
    rules: tuple[tuple[str, str, str, str], ...],
    url: str,
    allow_query_strings: bool,
    allowed: bool,
    reason_code: str | None,
) -> None:
    clock = _FakeTime()
    transport = _RecordingPeerBoundTransport(clock=clock)
    policy = _programme_scope_policy(rules)
    approved_origins = (
        "https://192.0.2.10",
        "https://192.0.2.200",
        "https://deep.api.example.test",
        "https://example.test",
    )
    executor = InternalHTTPExecutor(
        _configuration(approved_origins=approved_origins),
        programme_scope_policy=policy,
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    if allowed:
        executor.request(url, allow_query_strings=allow_query_strings)
        assert len(transport.requests) == 1
        assert executor.total_request_attempts == 1
        assert executor.last_request_start == Decimal("0")
    else:
        with pytest.raises(
            http_enforcement_module.HTTPProgrammeScopeRefused
        ) as exc_info:
            executor.request(url, allow_query_strings=allow_query_strings)
        assert exc_info.value.stage == "initial"
        assert exc_info.value.reason_code == reason_code
        assert transport.requests == []
        assert executor.total_request_attempts == 0
        assert executor.last_request_start is None
        assert executor._limiter is not None
        assert executor._limiter._next_start is None
        assert clock.sleeps == []


def test_initial_scope_refusal_precedes_origin_identity_and_permit_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_note = "PRIVATE-NOTE-SENTINEL-3491"
    private_source = "PRIVATE-SOURCE-WORDING-SENTINEL-3491"
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "allowed.test"),),
        private_note=private_note,
        private_source_wording=private_source,
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: (_ for _ in ()).throw(
            AssertionError("logical refusal must precede resolution")
        ),
    )

    def unexpected_headers(_additional_headers):
        raise AssertionError("identity headers must not be prepared after scope refusal")

    monkeypatch.setattr(executor, "_effective_headers", unexpected_headers)
    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://other.test/not-authorised")

    refusal = exc_info.value
    assert refusal.stage == "initial"
    assert refusal.reason_code == "no_matching_inclusion"
    assert refusal.operator_safe_explanation == (
        "Destination has no matching programme scope inclusion."
    )
    assert str(refusal) == (
        "Internal HTTP programme scope refused at initial: "
        "no_matching_inclusion. Destination has no matching programme scope inclusion."
    )
    assert private_note not in str(refusal)
    assert private_note not in repr(refusal)
    assert private_source not in str(refusal)
    assert private_source not in repr(refusal)
    assert HEADER_SENTINEL not in str(refusal)
    assert HEADER_SENTINEL not in repr(refusal)
    assert transport.requests == []
    assert executor.total_request_attempts == 0


def test_programme_scope_refusal_is_distinct_from_redirect_and_transport_failures() -> None:
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=_RecordingPeerBoundTransport(),
    )

    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://other.test/")

    assert not isinstance(exc_info.value, HTTPRedirectRefused)
    assert not isinstance(exc_info.value, HTTPTransportFailure)
    assert repr(exc_info.value) == (
        "HTTPProgrammeScopeRefused(stage='initial', "
        "reason_code='no_matching_inclusion', "
        "operator_safe_explanation='Destination has no matching programme scope "
        "inclusion.')"
    )


def test_non_bug_bounty_programme_scope_policy_is_rejected_at_construction() -> None:
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    object.__setattr__(policy, "engagement_context", "ctf")

    with pytest.raises(ValueError, match="bug_bounty"):
        InternalHTTPExecutor(
            _configuration(),
            programme_scope_policy=policy,
            transport=_RecordingTransport(),
        )


def test_executor_stores_a_canonical_immutable_programme_scope_copy() -> None:
    private_note = "PRIVATE-NOTE-SENTINEL-8821"
    private_source = "PRIVATE-SOURCE-WORDING-SENTINEL-8821"
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
        private_note=private_note,
        private_source_wording=private_source,
    )

    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=_RecordingPeerBoundTransport(),
    )

    assert executor._programme_scope_policy == policy
    assert executor._programme_scope_policy is not policy
    assert private_note not in repr(executor)
    assert private_source not in repr(executor)
    with pytest.raises(ValueError, match="canonical programme scope policy"):
        InternalHTTPExecutor(
            _configuration(),
            programme_scope_policy=object(),  # type: ignore[arg-type]
            transport=_RecordingTransport(),
        )


def test_executor_rejects_a_noncanonical_programme_scope_rule() -> None:
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    object.__setattr__(policy.rules[0], "canonical_value", "Example.TEST")

    with pytest.raises(ValueError, match="not canonical"):
        InternalHTTPExecutor(
            _configuration(),
            programme_scope_policy=policy,
            transport=_RecordingTransport(),
        )


def test_programme_scope_requires_http_enforcement_configuration() -> None:
    private_note = "PRIVATE-NOTE-SENTINEL-5591"
    private_source = "PRIVATE-SOURCE-WORDING-SENTINEL-5591"
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
        private_note=private_note,
        private_source_wording=private_source,
    )
    transport = _RecordingTransport()

    with pytest.raises(ValueError) as exc_info:
        InternalHTTPExecutor(
            None,
            programme_scope_policy=policy,
            transport=transport,
        )

    assert str(exc_info.value) == (
        "Programme-scoped internal HTTP requires enforcement configuration."
    )
    assert private_note not in str(exc_info.value)
    assert private_note not in repr(exc_info.value)
    assert private_source not in str(exc_info.value)
    assert private_source not in repr(exc_info.value)
    assert transport.requests == []


def test_unscoped_executor_retains_existing_compatibility_behaviour() -> None:
    transport = _RecordingTransport()
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    executor.request("https://example.test/unscoped")

    assert [request.url for request in transport.requests] == [
        "https://example.test/unscoped"
    ]
    assert executor.total_request_attempts == 1


def test_allowed_scope_does_not_weaken_approved_origin_containment() -> None:
    policy = _programme_scope_policy(
        (("allowed", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "other.test"),)
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
    )

    with pytest.raises(ValueError, match="origin is not approved"):
        executor.request("https://other.test/path")

    assert transport.requests == []
    assert executor.total_request_attempts == 0


def test_allowed_relative_redirect_is_independently_scope_evaluated_and_sent() -> None:
    policy = _programme_scope_policy(
        (("path", ACTION_INCLUDE, RULE_HTTP_PATH_PREFIX,
          "https://example.test/allowed"),)
    )
    transport = _RecordingPeerBoundTransport(
        [
            _response(302, (("Location", "next"),)),
            _response(200, body=b"final"),
        ]
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
    )

    response = executor.request("https://example.test/allowed/start")

    assert [request.url for request in transport.requests] == [
        "https://example.test/allowed/start",
        "https://example.test/allowed/next",
    ]
    assert executor.total_request_attempts == 2
    assert response.redirects == (
        http_enforcement_module.HTTPRedirectHop(
            status_code=302,
            source_url="https://example.test/allowed/start",
            destination_url="https://example.test/allowed/next",
        ),
    )


@pytest.mark.parametrize(
    ("rules", "location", "reason_code"),
    (
        ((("start", ACTION_INCLUDE, RULE_EXACT_HTTP_URL,
           "https://example.test/start"),),
         "/next", "no_matching_inclusion"),
        ((
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("blocked", ACTION_EXCLUDE, RULE_HTTP_PATH_PREFIX,
             "https://example.test/private"),
         ), "/private/next", "explicit_exclusion"),
    ),
)
def test_denied_redirect_is_not_sent_counted_or_recorded(
    monkeypatch: pytest.MonkeyPatch,
    rules: tuple[tuple[str, str, str, str], ...],
    location: str,
    reason_code: str,
) -> None:
    policy = _programme_scope_policy(rules)
    transport = _RecordingPeerBoundTransport(
        [_response(302, (("Location", location),))]
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
    )

    def unexpected_redirect_hop(**_values):
        raise AssertionError("refused redirect must not be recorded as accepted")

    monkeypatch.setattr(
        http_enforcement_module,
        "HTTPRedirectHop",
        unexpected_redirect_hop,
    )
    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/start")

    assert exc_info.value.stage == "redirect"
    assert exc_info.value.reason_code == reason_code
    assert [request.url for request in transport.requests] == [
        "https://example.test/start"
    ]
    assert executor.total_request_attempts == 1


@pytest.mark.parametrize(
    ("location", "approved_origins", "reason"),
    (
        (
            "https://other.test/path",
            ("https://example.test", "https://other.test"),
            "origin_not_approved",
        ),
        (
            "http://example.test/path",
            ("http://example.test", "https://example.test"),
            "https_downgrade",
        ),
        (
            "https://example.test:8443/path",
            ("https://example.test", "https://example.test:8443"),
            "origin_not_approved",
        ),
    ),
)
def test_scope_inclusion_does_not_weaken_existing_redirect_mechanics(
    location: str,
    approved_origins: tuple[str, ...],
    reason: str,
) -> None:
    policy = _programme_scope_policy(
        (
            ("example", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("other", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "other.test"),
        )
    )
    transport = _RecordingPeerBoundTransport(
        [_response(302, (("Location", location),))]
    )
    executor = InternalHTTPExecutor(
        _configuration(approved_origins=approved_origins),
        programme_scope_policy=policy,
        transport=transport,
    )

    with pytest.raises(HTTPRedirectRefused, match=reason):
        executor.request("https://example.test/start")

    assert len(transport.requests) == 1
    assert executor.total_request_attempts == 1


def test_scoped_http_to_https_upgrade_retains_existing_origin_requirements() -> None:
    policy = _programme_scope_policy(
        (("example", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    transport = _RecordingPeerBoundTransport(
        [
            _response(301, (("Location", "https://example.test/secure"),)),
            _response(),
        ]
    )
    executor = InternalHTTPExecutor(
        _configuration(
            approved_origins=("http://example.test", "https://example.test")
        ),
        programme_scope_policy=policy,
        transport=transport,
    )

    executor.request("http://example.test/start")

    assert [request.url for request in transport.requests] == [
        "http://example.test/start",
        "https://example.test/secure",
    ]
    assert executor.total_request_attempts == 2


def test_programme_scoped_executor_selects_lowest_allowed_resolved_ipv4() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    transport = _RecordingPeerBoundTransport()
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        return ("192.0.2.20", "192.0.2.3", "192.0.2.20")

    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=resolver,
    )

    executor.request("https://example.test/path")

    assert resolver_calls == [("example.test", 443)]
    assert len(transport.requests) == 1
    assert transport.requests[0].selected_ipv4 == "192.0.2.3"
    assert executor.total_request_attempts == 1


def test_any_excluded_resolved_ipv4_rejects_complete_set_before_permit() -> None:
    policy = _programme_scope_policy(
        (
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("excluded", ACTION_EXCLUDE, RULE_EXACT_IPV4, "192.0.2.20"),
        ),
        private_note="PRIVATE-PEER-NOTE-7319",
        private_source_wording="PRIVATE-PEER-SOURCE-7319",
    )
    clock = _FakeTime()
    transport = _RecordingPeerBoundTransport(clock=clock)
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3", "192.0.2.20"),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/path")

    assert exc_info.value.stage == "resolved_peer"
    assert exc_info.value.reason_code == "resolved_ip_excluded"
    assert transport.requests == []
    assert executor.total_request_attempts == 0
    assert executor.last_request_start is None
    assert executor._limiter is not None
    assert executor._limiter._next_start is None
    assert clock.sleeps == []
    assert "PRIVATE-PEER-NOTE-7319" not in str(exc_info.value)
    assert "PRIVATE-PEER-SOURCE-7319" not in repr(exc_info.value)
    assert HEADER_SENTINEL not in repr(exc_info.value)
    assert "192.0.2.3" not in str(exc_info.value)
    assert "192.0.2.20" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("resolver_result", "category"),
    (
        ([], "invalid_resolver_result"),
        (("192.0.2.1", 7), "invalid_resolver_result"),
        (("192.000.2.1",), "invalid_resolver_result"),
        ((), "no_usable_ipv4"),
    ),
)
def test_programme_scoped_executor_rejects_invalid_or_empty_resolver_results(
    resolver_result,
    category: str,
) -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: resolver_result,
    )

    with pytest.raises(HTTPTransportFailure, match=category):
        executor.request("https://example.test/")

    assert transport.requests == []
    assert executor.total_request_attempts == 0


def test_ipv4_literal_scope_skips_resolution_and_binds_literal_peer() -> None:
    policy = _programme_scope_policy(
        (("network", ACTION_INCLUDE, RULE_IPV4_CIDR, "192.0.2.0/24"),)
    )
    transport = _RecordingPeerBoundTransport()

    def unexpected_resolver(_host: str, _port: int) -> tuple[str, ...]:
        raise AssertionError("IPv4 literal must not be resolved")

    executor = InternalHTTPExecutor(
        _configuration(approved_origins=("https://192.0.2.10",)),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=unexpected_resolver,
    )

    executor.request("https://192.0.2.10/path")

    assert transport.requests[0].selected_ipv4 == "192.0.2.10"


def test_redirect_resolves_and_evaluates_each_logical_destination_fresh() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("redirect-peer", ACTION_EXCLUDE, RULE_EXACT_IPV4, "192.0.2.8"),
        )
    )
    responses = [_response(302, (("Location", "/next"),))]
    transport = _RecordingPeerBoundTransport(responses)
    resolved = iter((("192.0.2.7",), ("192.0.2.8",)))
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        return next(resolved)

    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=resolver,
    )

    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/start")

    assert exc_info.value.stage == "resolved_peer"
    assert resolver_calls == [("example.test", 443), ("example.test", 443)]
    assert [request.url for request in transport.requests] == [
        "https://example.test/start"
    ]
    assert executor.total_request_attempts == 1


def test_system_ipv4_resolver_filters_well_formed_ipv6_and_alias_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "ignored-v6-alias.example",
            ("2001:db8::1", 443, 0, 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "ignored-v4-alias.example",
            ("192.0.2.20", 443),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.3", 443),
        ),
    ]
    calls = []

    def fake_getaddrinfo(*args):
        calls.append(args)
        return records

    monkeypatch.setattr(http_enforcement_module.socket, "getaddrinfo", fake_getaddrinfo)

    assert http_enforcement_module._system_ipv4_resolver("example.test", 443) == (
        "192.0.2.20",
        "192.0.2.3",
    )
    assert calls == [
        (
            "example.test",
            443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    ]


def test_peer_bound_http_transport_connects_to_selected_peer_with_logical_host() -> None:
    events: list[tuple[object, ...]] = []
    peer_socket = _PeerSocket("192.0.2.3", events)
    response = _HTTPClientResponse()
    connections: list[_HTTPClientConnection] = []

    def socket_factory(family: int, socktype: int, protocol: int):
        events.append(("socket", family, socktype, protocol))
        return peer_socket

    def connection_factory(host: str, port: int, *, timeout: int):
        connection = _HTTPClientConnection(
            host,
            port,
            timeout=timeout,
            events=events,
            response=response,
        )
        connections.append(connection)
        return connection

    transport = http_enforcement_module.PeerBoundHTTPTransport(
        socket_factory=socket_factory,
        http_connection_factory=connection_factory,
    )
    request = http_enforcement_module.HTTPTransportRequest(
        url="http://example.test:8080/path?a=1",
        method="GET",
        headers=(("User-Agent", "test-agent"),),
        timeout_seconds=7,
        maximum_response_bytes=50,
        selected_ipv4="192.0.2.3",
    )

    result = transport(request)

    assert result.status_code == 200
    assert result.headers == (("Content-Type", "text/plain"),)
    assert result.body == b"peer-bound"
    assert [(connection.host, connection.port) for connection in connections] == [
        ("example.test", 8080)
    ]
    assert ("socket", socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) in events
    assert ("timeout", 7) in events
    assert ("connect", ("192.0.2.3", 8080)) in events
    request_event = next(event for event in events if event[0] == "request")
    assert request_event[1:3] == ("GET", "/path?a=1")
    assert request_event[3]["Host"] == "example.test:8080"
    assert request_event[3]["Connection"] == "close"
    assert response.read_limits == [51]
    assert "192.0.2.3" not in repr(request)


def test_peer_bound_https_transport_uses_logical_sni_and_verified_context() -> None:
    events: list[tuple[object, ...]] = []
    peer_socket = _PeerSocket("192.0.2.3", events)
    response = _HTTPClientResponse()
    context = _VerifiedSSLContext(events)

    def socket_factory(_family: int, _socktype: int, _protocol: int):
        return peer_socket

    def connection_factory(
        host: str,
        port: int,
        *,
        timeout: int,
        context: _VerifiedSSLContext,
    ):
        return _HTTPClientConnection(
            host,
            port,
            timeout=timeout,
            events=events,
            response=response,
            context=context,
        )

    transport = http_enforcement_module.PeerBoundHTTPTransport(
        socket_factory=socket_factory,
        https_connection_factory=connection_factory,
        ssl_context_factory=lambda: context,
    )
    request = http_enforcement_module.HTTPTransportRequest(
        url="https://example.test/",
        method="HEAD",
        headers=(),
        timeout_seconds=5,
        maximum_response_bytes=10,
        selected_ipv4="192.0.2.3",
    )

    transport(request)

    peer_check_index = events.index(("getpeername",))
    tls_event = next(event for event in events if event[0] == "tls")
    tls_index = events.index(tls_event)
    request_index = next(index for index, event in enumerate(events) if event[0] == "request")
    assert peer_check_index < tls_index < request_index
    assert tls_event[1] == "example.test"
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert ("alpn", ("http/1.1",)) in events
    https_request = next(event for event in events if event[0] == "request")
    assert https_request[1:3] == ("HEAD", "/")


def test_peer_bound_connector_closes_mismatched_peer_before_http_bytes() -> None:
    events: list[tuple[object, ...]] = []
    peer_socket = _PeerSocket("192.0.2.99", events)

    with pytest.raises(HTTPTransportFailure, match="peer_mismatch"):
        http_enforcement_module._connect_selected_ipv4(
            "192.0.2.3",
            443,
            5,
            socket_factory=lambda _family, _socktype, _protocol: peer_socket,
        )

    assert peer_socket.closed is True
    assert not any(event[0] in {"tls", "request"} for event in events)


def test_resolved_peer_block_takes_precedence_over_lower_unknown_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _programme_scope_policy(
        (
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("blocked", ACTION_EXCLUDE, RULE_EXACT_IPV4, "192.0.2.20"),
        )
    )
    original_evaluator = http_enforcement_module.evaluate_resolved_ipv4_peer
    unknown = http_enforcement_module.evaluate_raw_scope_destination(
        policy,
        http_enforcement_module.DESTINATION_IPV4,
        "192.0.2.3",
    )

    def evaluator(policy_arg, logical_decision, resolved_peer):
        if resolved_peer.peer.address == "192.0.2.3":
            return unknown
        return original_evaluator(policy_arg, logical_decision, resolved_peer)

    monkeypatch.setattr(
        http_enforcement_module,
        "evaluate_resolved_ipv4_peer",
        evaluator,
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: ("192.0.2.20", "192.0.2.3"),
    )

    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/")

    assert exc_info.value.reason_code == "resolved_ip_excluded"
    assert transport.requests == []
    assert executor.total_request_attempts == 0


def test_numerically_lowest_blocked_peer_controls_deterministic_refusal() -> None:
    policy = _programme_scope_policy(
        (
            ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),
            ("lower-peer", ACTION_EXCLUDE, RULE_EXACT_IPV4, "192.0.2.3"),
            ("higher-peer", ACTION_EXCLUDE, RULE_EXACT_IPV4, "192.0.2.20"),
        )
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=_RecordingPeerBoundTransport(),
        ipv4_resolver=lambda _host, _port: ("192.0.2.20", "192.0.2.3"),
    )

    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/")

    assert exc_info.value.operator_safe_explanation == (
        "Resolved IPv4 peer is blocked by explicit programme scope rule lower-peer."
    )


def test_unknown_resolved_peer_rejects_complete_set_before_identity_or_permit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    unknown = http_enforcement_module.evaluate_raw_scope_destination(
        policy,
        http_enforcement_module.DESTINATION_IPV4,
        "192.0.2.3",
    )
    monkeypatch.setattr(
        http_enforcement_module,
        "evaluate_resolved_ipv4_peer",
        lambda _policy, _logical, _peer: unknown,
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )

    def unexpected_headers(_additional_headers):
        raise AssertionError("identity must not be prepared for a refused peer")

    monkeypatch.setattr(executor, "_effective_headers", unexpected_headers)
    with pytest.raises(http_enforcement_module.HTTPProgrammeScopeRefused) as exc_info:
        executor.request("https://example.test/")

    assert exc_info.value.stage == "resolved_peer"
    assert exc_info.value.reason_code == "no_matching_inclusion"
    assert transport.requests == []
    assert executor.total_request_attempts == 0


def test_resolver_failure_precedes_identity_permit_and_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    transport = _RecordingPeerBoundTransport()

    def failing_resolver(_host: str, _port: int) -> tuple[str, ...]:
        raise socket.gaierror("PRIVATE-RESOLVER-DETAIL-1192")

    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=failing_resolver,
    )
    monkeypatch.setattr(
        executor,
        "_effective_headers",
        lambda _headers: (_ for _ in ()).throw(
            AssertionError("identity must not be prepared after DNS failure")
        ),
    )

    with pytest.raises(HTTPTransportFailure) as exc_info:
        executor.request("https://example.test/")

    assert exc_info.value.category == "dns_error"
    assert "PRIVATE-RESOLVER-DETAIL-1192" not in str(exc_info.value)
    assert transport.requests == []
    assert executor.total_request_attempts == 0


@pytest.mark.parametrize(
    "records",
    (
        [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 80))],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1",))],
        [(9999, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))],
        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("not-ipv6", 443, 0, 0))],
        ["not-a-getaddrinfo-record"],
    ),
)
def test_system_ipv4_resolver_rejects_malformed_records(
    monkeypatch: pytest.MonkeyPatch,
    records,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: records)

    with pytest.raises(HTTPTransportFailure, match="invalid_resolver_result"):
        http_enforcement_module._system_ipv4_resolver("example.test", 443)


def test_system_ipv4_resolver_maps_gaierror_without_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args):
        raise socket.gaierror("PRIVATE-DNS-DETAIL-4412")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    with pytest.raises(HTTPTransportFailure) as exc_info:
        http_enforcement_module._system_ipv4_resolver("example.test", 443)

    assert exc_info.value.category == "dns_error"
    assert "PRIVATE-DNS-DETAIL-4412" not in str(exc_info.value)


def test_ipv6_only_system_resolution_becomes_no_usable_ipv4() -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    transport = _RecordingPeerBoundTransport()
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: (),
    )

    with pytest.raises(HTTPTransportFailure, match="no_usable_ipv4"):
        executor.request("https://example.test/")

    assert transport.requests == []


def test_selected_peer_connect_failure_has_no_fallback_and_counts_one_attempt() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    events: list[tuple[object, ...]] = []
    sockets: list[_PeerSocket] = []
    response = _HTTPClientResponse()

    def socket_factory(_family: int, _socket_type: int, _protocol: int):
        peer_socket = _PeerSocket(
            "192.0.2.3",
            events,
            connect_error=OSError("PRIVATE-CONNECT-DETAIL-9172"),
        )
        sockets.append(peer_socket)
        return peer_socket

    def connection_factory(host: str, port: int, *, timeout: int):
        return _HTTPClientConnection(
            host,
            port,
            timeout=timeout,
            events=events,
            response=response,
        )

    transport = http_enforcement_module.PeerBoundHTTPTransport(
        socket_factory=socket_factory,
        http_connection_factory=connection_factory,
    )
    executor = InternalHTTPExecutor(
        _configuration(approved_origins=("http://example.test",)),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: ("192.0.2.20", "192.0.2.3"),
    )

    with pytest.raises(HTTPTransportFailure) as exc_info:
        executor.request("http://example.test/")

    assert exc_info.value.category == "connect_error"
    assert "PRIVATE-CONNECT-DETAIL-9172" not in str(exc_info.value)
    assert len(sockets) == 1
    assert ("connect", ("192.0.2.3", 80)) in events
    assert not any(event == ("connect", ("192.0.2.20", 80)) for event in events)
    assert executor.total_request_attempts == 1


def test_peer_bound_https_transport_maps_tls_failure_without_http_request() -> None:
    events: list[tuple[object, ...]] = []
    peer_socket = _PeerSocket("192.0.2.3", events)
    response = _HTTPClientResponse()

    class FailingContext(_VerifiedSSLContext):
        def wrap_socket(self, raw_socket, *, server_hostname: str):
            self.events.append(("tls", server_hostname, raw_socket))
            raise ssl.SSLError("PRIVATE-TLS-DETAIL-3281")

    context = FailingContext(events)

    def connection_factory(host: str, port: int, *, timeout: int, context):
        return _HTTPClientConnection(
            host,
            port,
            timeout=timeout,
            events=events,
            response=response,
            context=context,
        )

    transport = http_enforcement_module.PeerBoundHTTPTransport(
        socket_factory=lambda _family, _type, _protocol: peer_socket,
        https_connection_factory=connection_factory,
        ssl_context_factory=lambda: context,
    )
    request = http_enforcement_module.HTTPTransportRequest(
        url="https://example.test/",
        method="GET",
        headers=(),
        timeout_seconds=5,
        maximum_response_bytes=10,
        selected_ipv4="192.0.2.3",
    )

    with pytest.raises(HTTPTransportFailure) as exc_info:
        transport(request)

    assert exc_info.value.category == "tls_error"
    assert "PRIVATE-TLS-DETAIL-3281" not in str(exc_info.value)
    assert not any(event[0] == "request" for event in events)


def test_https_ipv4_literal_is_used_as_certificate_identity() -> None:
    events: list[tuple[object, ...]] = []
    peer_socket = _PeerSocket("192.0.2.10", events)
    response = _HTTPClientResponse()
    context = _VerifiedSSLContext(events)

    def connection_factory(host: str, port: int, *, timeout: int, context):
        return _HTTPClientConnection(
            host,
            port,
            timeout=timeout,
            events=events,
            response=response,
            context=context,
        )

    transport = http_enforcement_module.PeerBoundHTTPTransport(
        socket_factory=lambda _family, _type, _protocol: peer_socket,
        https_connection_factory=connection_factory,
        ssl_context_factory=lambda: context,
    )
    transport(
        http_enforcement_module.HTTPTransportRequest(
            url="https://192.0.2.10/",
            method="GET",
            headers=(),
            timeout_seconds=5,
            maximum_response_bytes=10,
            selected_ipv4="192.0.2.10",
        )
    )

    tls_event = next(event for event in events if event[0] == "tls")
    assert tls_event[1] == "192.0.2.10"


def test_default_transport_selection_is_isolated_by_programme_scope() -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )

    scoped = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )
    configured_unscoped = InternalHTTPExecutor(_configuration())
    compatibility = InternalHTTPExecutor(None)

    assert isinstance(
        scoped.transport,
        http_enforcement_module.PeerBoundHTTPTransport,
    )
    assert isinstance(configured_unscoped.transport, UrllibHTTPTransport)
    assert isinstance(compatibility.transport, UrllibHTTPTransport)


def test_scoped_executor_rejects_explicit_urllib_transport_at_construction() -> None:
    private_note = "PRIVATE-TRANSPORT-NOTE-7741"
    private_source = "PRIVATE-TRANSPORT-SOURCE-7741"
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
        private_note=private_note,
        private_source_wording=private_source,
    )
    opener = _RecordingOpener()
    transport = UrllibHTTPTransport(direct_only=True)
    transport._opener = opener

    with pytest.raises(ValueError) as exc_info:
        InternalHTTPExecutor(
            _configuration(),
            programme_scope_policy=policy,
            transport=transport,
            ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
        )

    assert str(exc_info.value) == (
        "Programme-scoped internal HTTP requires a peer-bound transport."
    )
    assert opener.requests == []
    assert private_note not in str(exc_info.value)
    assert private_source not in repr(exc_info.value)
    assert HEADER_SENTINEL not in str(exc_info.value)


def test_scoped_executor_rejects_explicit_ordinary_recording_transport() -> None:
    policy = _programme_scope_policy(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )

    with pytest.raises(ValueError, match="peer-bound transport"):
        InternalHTTPExecutor(
            _configuration(),
            programme_scope_policy=policy,
            transport=_RecordingTransport(),
            ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
        )


def test_scoped_executor_accepts_explicit_peer_bound_transports() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    explicit = http_enforcement_module.PeerBoundHTTPTransport()
    test_subclass = _RecordingPeerBoundTransport()

    explicit_executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=explicit,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )
    fake_executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        transport=test_subclass,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )

    assert explicit_executor.transport is explicit
    fake_executor.request("https://example.test/path")
    assert [request.url for request in test_subclass.requests] == [
        "https://example.test/path"
    ]


def test_scoped_exchange_rejects_postconstruction_urllib_replacement() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )
    opener = _RecordingOpener()
    replacement = UrllibHTTPTransport(direct_only=True)
    replacement._opener = opener
    executor.transport = replacement

    with pytest.raises(ValueError, match="peer-bound transport"):
        executor.request("https://example.test/path")

    assert opener.requests == []
    assert executor.total_request_attempts == 0
    assert executor.last_request_start is None
    assert executor._limiter is not None
    assert executor._limiter._next_start is None


def test_scoped_exchange_rejects_postconstruction_recording_replacement() -> None:
    private_note = "PRIVATE-REPLACEMENT-NOTE-4418"
    private_source = "PRIVATE-REPLACEMENT-SOURCE-4418"
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),),
        private_note=private_note,
        private_source_wording=private_source,
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        programme_scope_policy=policy,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
    )
    replacement = _RecordingTransport()
    executor.transport = replacement

    with pytest.raises(ValueError) as exc_info:
        executor.request("https://example.test/path")

    assert str(exc_info.value) == (
        "Programme-scoped internal HTTP requires a peer-bound transport."
    )
    assert replacement.requests == []
    assert executor.total_request_attempts == 0
    assert executor.last_request_start is None
    assert executor._limiter is not None
    assert executor._limiter._next_start is None
    assert HEADER_SENTINEL not in str(exc_info.value)
    assert private_note not in str(exc_info.value)
    assert private_source not in repr(exc_info.value)


def test_programme_scoped_requests_retain_pacing_and_identity_headers() -> None:
    policy = _programme_scope_policy_with_fixture_peer(
        (("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "example.test"),)
    )
    clock = _FakeTime()
    transport = _RecordingPeerBoundTransport(
        [_response(), _response()],
        clock=clock,
    )
    executor = InternalHTTPExecutor(
        _configuration(rate="2"),
        programme_scope_policy=policy,
        transport=transport,
        ipv4_resolver=lambda _host, _port: ("192.0.2.3",),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    executor.request("https://example.test/one")
    executor.request("https://example.test/two")

    assert transport.starts == [Decimal("0"), Decimal("0.5")]
    assert executor.total_request_attempts == 2
    assert all(request.selected_ipv4 == "192.0.2.3" for request in transport.requests)
    assert all(
        ("X-Researcher-ID", HEADER_SENTINEL) in request.headers
        for request in transport.requests
    )


def test_multiple_policy_identification_headers_reach_every_exchange_in_order() -> None:
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", HEADER_SENTINEL),
            IdentificationHeader("X-Programme-Handle", "configured-handle"),
        ),
        custom_user_agent=USER_AGENT_SENTINEL,
        updated_at="2026-07-28T10:00:00Z",
    )
    configuration = build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test",),
    )
    transport = _RecordingTransport()
    executor = InternalHTTPExecutor(configuration, transport=transport)

    executor.request("https://example.test/")

    assert transport.requests[0].headers == (
        ("User-Agent", USER_AGENT_SENTINEL),
        ("X-Researcher-ID", HEADER_SENTINEL),
        ("X-Programme-Handle", "configured-handle"),
    )


def test_policy_configuration_uses_versioned_identity_when_custom_agent_is_absent() -> None:
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        identification_requirement=IDENTIFICATION_NONE,
        updated_at="2026-07-28T10:00:00Z",
    )

    configuration = build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test",),
    )

    assert configuration.user_agent == built_in_user_agent()
    assert configuration.user_agent == f"BugSlyce/{__version__} authorised-recon"
    assert "BugSlyce/0.3" not in configuration.user_agent


def test_strict_default_transport_constructs_one_proxy_free_opener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _RecordingOpener()
    handler_calls: list[tuple[object, ...]] = []

    def fake_build_opener(*handlers: object) -> _RecordingOpener:
        handler_calls.append(handlers)
        return opener

    monkeypatch.setattr(http_enforcement_module, "build_opener", fake_build_opener)

    executor = InternalHTTPExecutor(_configuration())

    assert isinstance(executor.transport, UrllibHTTPTransport)
    assert len(handler_calls) == 1
    proxy_handlers = [
        handler for handler in handler_calls[0] if isinstance(handler, ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}


def test_strict_transport_is_direct_only_across_environment_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_names = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )
    for name in proxy_names:
        monkeypatch.setenv(name, f"http://before-{name.casefold()}.invalid:8080")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    environment_before_construction = dict(os.environ)
    opener = _RecordingOpener()
    handler_calls: list[tuple[object, ...]] = []

    def fake_build_opener(*handlers: object) -> _RecordingOpener:
        handler_calls.append(handlers)
        return opener

    monkeypatch.setattr(http_enforcement_module, "build_opener", fake_build_opener)
    clock = _FakeTime()
    executor = InternalHTTPExecutor(
        _configuration(
            approved_origins=("http://example.test", "https://example.test")
        ),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert dict(os.environ) == environment_before_construction
    for name in proxy_names:
        monkeypatch.setenv(name, f"http://after-{name.casefold()}.invalid:9090")
    monkeypatch.setenv("NO_PROXY", "unexpected.example")
    monkeypatch.setenv("no_proxy", "*")
    environment_before_requests = dict(os.environ)

    executor.request("http://example.test/plain")
    executor.request("https://example.test/secure")

    assert dict(os.environ) == environment_before_requests
    assert len(handler_calls) == 1
    proxy_handlers = [
        handler for handler in handler_calls[0] if isinstance(handler, ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert [request.full_url for request in opener.requests] == [
        "http://example.test/plain",
        "https://example.test/secure",
    ]
    for request in opener.requests:
        headers = {
            name.casefold(): value for name, value in request.header_items()
        }
        assert headers["x-researcher-id"] == HEADER_SENTINEL
        assert headers["user-agent"] == USER_AGENT_SENTINEL
    assert executor.total_request_attempts == 2


def test_strict_direct_failure_does_not_retry_through_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://implicit-proxy.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://implicit-proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://implicit-proxy.invalid:8080")
    monkeypatch.setenv("NO_PROXY", "")
    opener = _RecordingOpener(error=OSError("direct connection failed"))
    handler_calls: list[tuple[object, ...]] = []

    def fake_build_opener(*handlers: object) -> _RecordingOpener:
        handler_calls.append(handlers)
        return opener

    monkeypatch.setattr(http_enforcement_module, "build_opener", fake_build_opener)
    executor = InternalHTTPExecutor(_configuration())

    with pytest.raises(HTTPTransportFailure, match="transport_error"):
        executor.request("https://example.test/fail")

    assert len(handler_calls) == 1
    assert len(opener.requests) == 1
    assert executor.total_request_attempts == 1


def test_injected_transport_does_not_construct_an_urllib_opener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_build_opener(*_handlers: object):
        raise AssertionError("injected transport must bypass urllib construction")

    monkeypatch.setattr(
        http_enforcement_module,
        "build_opener",
        unexpected_build_opener,
    )
    transport = _RecordingTransport()
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    executor.request("https://example.test/injected")

    assert len(transport.requests) == 1


def test_non_strict_compatibility_transport_retains_existing_opener_behaviour(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _RecordingOpener()
    handler_calls: list[tuple[object, ...]] = []

    def fake_build_opener(*handlers: object) -> _RecordingOpener:
        handler_calls.append(handlers)
        return opener

    monkeypatch.setattr(http_enforcement_module, "build_opener", fake_build_opener)
    executor = InternalHTTPExecutor(None)

    assert handler_calls == []
    executor.request("https://example.test/compatibility")

    assert len(handler_calls) == 1
    assert not any(isinstance(handler, ProxyHandler) for handler in handler_calls[0])
    assert len(opener.requests) == 1


@pytest.mark.parametrize(
    "policy",
    (
        build_bug_bounty_policy(updated_at="2026-07-28T10:00:00Z"),
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            identification_requirement=IDENTIFICATION_UNKNOWN,
            updated_at="2026-07-28T10:00:00Z",
        ),
    ),
)
def test_incomplete_policy_cannot_create_runtime_enforcement(policy) -> None:
    with pytest.raises(ValueError, match="incomplete"):
        build_http_enforcement_configuration(
            policy,
            approved_origins=("https://example.test",),
        )


def test_runtime_identity_refuses_unencodable_values_without_echoing_them() -> None:
    private_value = "researcher-identity-\u2603"
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", private_value),
        ),
        custom_user_agent=USER_AGENT_SENTINEL,
        updated_at="2026-07-28T10:00:00Z",
    )

    with pytest.raises(ValueError, match="internal HTTP transport") as exc_info:
        build_http_enforcement_configuration(
            policy,
            approved_origins=("https://example.test",),
        )

    assert private_value not in str(exc_info.value)


def test_direct_bug_bounty_internal_stage_remains_blocked_before_fetcher_construction(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "project"
    scope_file = tmp_path / "scope.md"
    scope_file.write_text(
        "# Scope\n\n## In Scope\n\n- example.test\n",
        encoding="utf-8",
    )
    _project, project_file = initialize_project(
        "http-policy-test",
        "example.test",
        scope_file,
        output_dir,
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(project_file, _complete_policy())
    with pytest.raises(ValueError, match="direct or modular"):
        cli_module._deep_http_fetcher_for_input(
            output_dir,
            "bug_bounty",
            ("https://example.test",),
        )



@pytest.mark.parametrize(
    "command",
    ("deep-metadata-collect", "deep-source-route-collect"),
)
def test_bug_bounty_modular_collection_commands_refuse_before_live_fetcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    command: str,
) -> None:
    output_dir = tmp_path / "project"
    scope_file = tmp_path / "scope.md"
    scope_file.write_text(
        "# Scope\n\n## In Scope\n\n- example.test\n",
        encoding="utf-8",
    )
    _project, project_file = initialize_project(
        "http-policy-cli-test",
        "example.test",
        scope_file,
        output_dir,
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(project_file, _complete_policy())
    (output_dir / "urls.txt").write_text("https://example.test/\n", encoding="utf-8")
    (output_dir / "httpx.jsonl").write_text(
        '{"url":"https://example.test/","host":"example.test","status_code":200}\n',
        encoding="utf-8",
    )
    collection_calls: list[object] = []

    def fail_if_collected(*args, **kwargs):
        collection_calls.append((args, kwargs))
        raise AssertionError("bug bounty collection must not reach a live collector")

    if command == "deep-metadata-collect":
        monkeypatch.setattr(cli_module, "collect_deep_metadata_from_plan", fail_if_collected)
    else:
        monkeypatch.setattr(
            cli_module,
            "collect_deep_source_routes_from_plan",
            fail_if_collected,
        )

    exit_code = cli_module.main(
        ["recon", command, "--input-dir", str(output_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "direct or modular entry point" in captured.err
    assert "policy-aware Standard or Deep project pipeline" in captured.err
    assert collection_calls == []


@pytest.mark.parametrize(
    "engagement_context",
    ("ctf_lab", "internal_authorised", "unknown"),
)
def test_non_bug_bounty_internal_stage_preserves_existing_fetcher_path(
    tmp_path: Path,
    engagement_context: str,
) -> None:
    assert (
        cli_module._deep_http_fetcher_for_input(
            tmp_path / "not-read",
            engagement_context,
            ("https://example.test",),
        )
        is urllib_deep_http_fetcher
    )


def test_steady_limiter_has_no_initial_burst_or_idle_token_accumulation() -> None:
    clock = _FakeTime()
    transport = _RecordingTransport([_response(), _response(), _response()], clock=clock)
    executor = InternalHTTPExecutor(
        _configuration(rate="2"),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    executor.request("https://example.test/one")
    executor.request("https://example.test/two")
    clock.now = Decimal("20")
    executor.request("https://example.test/three")

    assert transport.starts == [Decimal("0"), Decimal("0.5"), Decimal("20")]
    assert executor.total_request_attempts == 3


def test_decimal_rate_spacing_is_stable_across_stage_calls() -> None:
    clock = _FakeTime()
    transport = _RecordingTransport([_response(), _response(), _response()], clock=clock)
    executor = InternalHTTPExecutor(
        _configuration(rate="2.5"),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    executor.request("https://example.test/metadata")
    executor.request("https://example.test/source")
    executor.request("https://example.test/follow-up")

    assert transport.starts == [Decimal("0"), Decimal("0.4"), Decimal("0.8")]


def test_extremely_low_rate_uses_a_finite_sleep_chunk() -> None:
    probe = _FiniteChunkProbe()
    limiter = SteadyRequestStartLimiter(
        Decimal("1e-1000"),
        monotonic=lambda: 0.0,
        sleep=probe,
    )

    assert limiter.wait() == Decimal("0")
    with pytest.raises(_StopAfterFirstSleep):
        limiter.wait()

    assert len(probe.calls) == 1


def test_extremely_high_rate_uses_a_conservative_positive_sleep() -> None:
    clock = _FiniteAdvancingClock()
    limiter = SteadyRequestStartLimiter(
        Decimal("1e1000"),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert limiter.wait() == Decimal("0")
    second_start = limiter.wait()

    assert len(clock.sleeps) == 1
    assert Decimal(str(clock.sleeps[0])) >= Decimal("1e-1000")
    assert second_start >= Decimal("1e-1000")


def test_limiter_rechecks_monotonic_time_after_an_early_sleeper_return() -> None:
    clock = _EarlyReturnClock()
    limiter = SteadyRequestStartLimiter(
        Decimal("2"),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert limiter.wait() == Decimal("0")
    assert limiter.wait() == Decimal("0.5")
    assert clock.calls == [Decimal("0.5"), Decimal("0.25")]


def test_concurrent_callers_still_receive_distinct_aggregate_start_slots() -> None:
    clock = _FakeTime()
    transport = _RecordingTransport(
        [_response(), _response(), _response()],
        clock=clock,
    )
    executor = InternalHTTPExecutor(
        _configuration(rate="2", concurrency=3),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    threads = [
        threading.Thread(
            target=executor.request,
            args=(f"https://example.test/{index}",),
        )
        for index in range(3)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(transport.starts) == [Decimal("0"), Decimal("0.5"), Decimal("1.0")]


@pytest.mark.parametrize("concurrency", (1, 2))
def test_configured_concurrency_is_an_independent_in_flight_limit(
    concurrency: int,
) -> None:
    transport = _BlockingTransport(expected_active=concurrency)
    executor = InternalHTTPExecutor(
        _configuration(rate="100000", concurrency=concurrency),
        transport=transport,
    )
    threads = [
        threading.Thread(
            target=executor.request,
            args=(f"https://example.test/{index}",),
        )
        for index in range(2)
    ]

    threads[0].start()
    assert transport.entered.wait(timeout=1) if concurrency == 1 else True
    threads[1].start()
    if concurrency == 2:
        assert transport.entered.wait(timeout=1)
    else:
        with transport.lock:
            assert transport.active == 1
    transport.release.set()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert transport.maximum_active == concurrency


@pytest.mark.parametrize(
    ("rate", "concurrency"),
    ((Decimal("0"), 1), (Decimal("NaN"), 1), (Decimal("2"), 0), (Decimal("2"), True)),
)
def test_invalid_runtime_configuration_is_refused(
    rate: Decimal,
    concurrency: int,
) -> None:
    with pytest.raises(ValueError):
        HTTPEnforcementConfiguration(
            maximum_request_starts_per_second=rate,
            maximum_concurrent_requests=concurrency,
            user_agent="BugSlyce/test",
            identification_headers=(),
            approved_origins=(),
        )


def test_identity_is_applied_and_functional_header_collisions_are_refused() -> None:
    transport = _RecordingTransport()
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    executor.request(
        "https://example.test/",
        additional_headers=(("Accept", "text/plain"),),
    )

    assert transport.requests[0].headers == (
        ("User-Agent", USER_AGENT_SENTINEL),
        ("X-Researcher-ID", HEADER_SENTINEL),
        ("Accept", "text/plain"),
    )
    with pytest.raises(ValueError, match="collides") as exc_info:
        executor.request(
            "https://example.test/",
            additional_headers=(("x-researcher-id", "replacement"),),
        )
    assert HEADER_SENTINEL not in str(exc_info.value)
    assert HEADER_SENTINEL not in repr(transport.requests[0])
    assert USER_AGENT_SENTINEL not in repr(transport.requests[0])


def test_internal_completion_barrier_preserves_target_observable_spacing() -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(
        clock,
        (Decimal("0.4"), Decimal("0")),
        [_response(), _response()],
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    executor.request("https://example.test/one")
    executor.request("https://example.test/two")

    assert transport.starts == [Decimal("0"), Decimal("0.9")]
    assert transport.arrivals == [Decimal("0.4"), Decimal("0.9")]
    assert transport.arrivals[1] - transport.arrivals[0] == Decimal("0.5")
    assert max(
        sum(start <= arrival < start + Decimal(1) for arrival in transport.arrivals)
        for start in transport.arrivals
    ) == 2
    assert executor.total_request_attempts == 2
    assert executor.last_request_start == Decimal("0.9")


@pytest.mark.parametrize(
    ("response", "error", "raises"),
    (
        (HTTPTransportResponse(200, (), b"ok"), None, None),
        (HTTPTransportResponse(404, (), b"ok"), None, None),
        (None, TimeoutError("timeout"), HTTPTransportFailure),
        (None, OSError("transport error"), HTTPTransportFailure),
        (None, RuntimeError("transport failure"), RuntimeError),
        (None, KeyboardInterrupt(), KeyboardInterrupt),
        (None, SystemExit(7), SystemExit),
    ),
    ids=(
        "success",
        "non_2xx",
        "timeout",
        "os_error",
        "exception",
        "keyboard_interrupt",
        "system_exit",
    ),
)
def test_invoked_internal_exchange_installs_completion_barrier_for_all_outcomes(
    response: HTTPTransportResponse | None,
    error: BaseException | None,
    raises: type[BaseException] | None,
) -> None:
    clock = _FakeTime()
    first_transport = _DelayedRecordingTransport(
        clock,
        (Decimal("0.4"),),
        [response] if response is not None else None,
        error=error,
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=first_transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    if raises is None:
        executor.request("https://example.test/first")
    else:
        with pytest.raises(raises):
            executor.request("https://example.test/first")

    succeeding = _DelayedRecordingTransport(clock, (Decimal("0"),), [_response()])
    executor.transport = succeeding
    executor.request("https://example.test/after")

    assert first_transport.arrivals == [Decimal("0.4")]
    assert succeeding.starts == [Decimal("0.9")]
    assert executor.total_request_attempts == 2


def test_redirect_exchange_installs_a_completion_barrier_before_follow_up() -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(
        clock,
        (Decimal("0.4"), Decimal("0"), Decimal("0")),
        [
            _response(302, (("Location", "/next"),)),
            _response(),
            _response(),
        ],
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    executor.request("https://example.test/start")
    executor.request("https://example.test/after")

    assert transport.starts == [Decimal("0"), Decimal("0.9"), Decimal("1.4")]
    assert executor.total_request_attempts == 3


def test_429_installs_completion_barrier_before_entering_terminal_state() -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(
        clock,
        (Decimal("0.4"),),
        [_response(429, (("Retry-After", "2"),))],
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    with pytest.raises(HTTPRateRejected):
        executor.request("https://example.test/limited")
    with pytest.raises(HTTPRateRejected):
        executor.request("https://example.test/not-sent")

    assert executor._limiter is not None
    assert executor._limiter._next_start == Decimal("0.9")
    assert executor.total_request_attempts == 1
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "url",
    ("ftp://example.test/unsupported", "https://other.test/out-of-scope"),
)
def test_pre_transport_rejection_installs_no_completion_barrier(url: str) -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(clock, (Decimal("0"),), [_response()])
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    with pytest.raises(ValueError):
        executor.request(url)
    executor.request("https://example.test/allowed")

    assert transport.starts == [Decimal("0")]
    assert executor.total_request_attempts == 1


def test_closed_executor_rejection_installs_no_completion_barrier() -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(clock, (Decimal("0"),), [_response()])
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    executor.close()

    with pytest.raises(HTTPExecutorClosed):
        executor.request("https://example.test/closed")

    assert executor._limiter is not None
    assert executor._limiter._next_start is None
    assert executor.total_request_attempts == 0
    assert transport.requests == []


def test_internal_completion_barrier_precedes_concurrency_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeTime()
    transport = _DelayedRecordingTransport(clock, (Decimal("0"),), [_response()])
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert executor._limiter is not None
    assert executor._concurrency is not None
    original_defer = executor._limiter.defer_next_start
    barrier_entered = threading.Event()
    release_barrier = threading.Event()

    def defer_next_start() -> Decimal:
        barrier_entered.set()
        if not release_barrier.wait(timeout=2):
            raise AssertionError("test completion barrier was not released")
        return original_defer()

    monkeypatch.setattr(executor._limiter, "defer_next_start", defer_next_start)
    worker = threading.Thread(
        target=executor.request,
        args=("https://example.test/first",),
    )
    worker.start()
    assert barrier_entered.wait(timeout=1)

    assert not executor._concurrency.acquire(blocking=False)
    release_barrier.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert executor.total_request_attempts == 1


def test_same_origin_redirect_is_followed_as_a_separately_paced_attempt() -> None:
    clock = _FakeTime()
    transport = _RecordingTransport(
        [
            _response(302, (("Location", "/next"),)),
            _response(200, body=b"final"),
        ],
        clock=clock,
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    response = executor.request("https://example.test/start")

    assert [request.url for request in transport.requests] == [
        "https://example.test/start",
        "https://example.test/next",
    ]
    assert transport.starts == [Decimal("0"), Decimal("0.5")]
    assert response.final_url == "https://example.test/next"
    assert len(response.redirects) == 1
    assert all(
        request.headers[1] == ("X-Researcher-ID", HEADER_SENTINEL)
        for request in transport.requests
    )


def test_same_origin_absolute_redirect_is_followed() -> None:
    transport = _RecordingTransport(
        [
            _response(
                302,
                (("Location", "https://example.test/absolute"),),
            ),
            _response(),
        ]
    )
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    response = executor.request("https://example.test/start")

    assert response.final_url == "https://example.test/absolute"
    assert len(transport.requests) == 2


def test_redirect_cannot_broaden_the_existing_query_string_policy() -> None:
    transport = _RecordingTransport(
        [_response(302, (("Location", "/next?token=value"),))]
    )
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    with pytest.raises(HTTPRedirectRefused, match="redirect_query_not_allowed"):
        executor.request("https://example.test/start")

    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "location",
    ("", " https://example.test/path", "http://", "https://user:pass@example.test/"),
)
def test_malformed_redirect_locations_are_refused(location: str) -> None:
    transport = _RecordingTransport([_response(302, (("Location", location),))])
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    with pytest.raises(HTTPRedirectRefused):
        executor.request("https://example.test/start")

    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    ("location", "reason"),
    (
        ("https://other.test/path", "origin_not_approved"),
        ("http://example.test/path", "https_downgrade"),
        ("https://example.test:8443/path", "origin_not_approved"),
        ("ftp://example.test/path", "unsupported_redirect"),
    ),
)
def test_unsafe_redirect_is_refused_before_identity_can_be_transmitted(
    location: str,
    reason: str,
) -> None:
    transport = _RecordingTransport([_response(302, (("Location", location),))])
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    with pytest.raises(HTTPRedirectRefused, match=reason):
        executor.request("https://example.test/start")

    assert len(transport.requests) == 1


def test_http_upgrade_requires_both_origins_to_be_approved() -> None:
    transport = _RecordingTransport(
        [_response(301, (("Location", "https://example.test/secure"),)), _response()]
    )
    executor = InternalHTTPExecutor(
        _configuration(
            approved_origins=("http://example.test", "https://example.test")
        ),
        transport=transport,
    )

    executor.request("http://example.test/start")

    assert len(transport.requests) == 2


def test_redirect_loop_and_hop_cap_are_refused() -> None:
    loop_transport = _RecordingTransport(
        [
            _response(302, (("Location", "/two"),)),
            _response(302, (("Location", "/one"),)),
        ]
    )
    loop_executor = InternalHTTPExecutor(_configuration(), transport=loop_transport)
    with pytest.raises(HTTPRedirectRefused, match="redirect_loop"):
        loop_executor.request("https://example.test/one")

    hop_transport = _RecordingTransport(
        [
            _response(302, (("Location", "/two"),)),
            _response(302, (("Location", "/three"),)),
        ]
    )
    hop_executor = InternalHTTPExecutor(
        _configuration(maximum_redirect_hops=1), transport=hop_transport
    )
    with pytest.raises(HTTPRedirectRefused, match="redirect_hop_limit"):
        hop_executor.request("https://example.test/one")


def test_429_stops_executor_without_sleeping_retry_after() -> None:
    clock = _FakeTime()
    transport = _RecordingTransport(
        [_response(429, (("Retry-After", "999999999999999999999999"),))],
        clock=clock,
    )
    executor = InternalHTTPExecutor(
        _configuration(),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    with pytest.raises(HTTPRateRejected) as exc_info:
        executor.request("https://example.test/limited")
    with pytest.raises(HTTPRateRejected):
        executor.request("https://example.test/not-sent")

    assert exc_info.value.status_code == 429
    assert len(exc_info.value.retry_after) <= 128
    assert clock.sleeps == []
    assert len(transport.requests) == 1


def test_non_bug_bounty_executor_preserves_existing_429_and_transport_errors() -> None:
    rate_response = _RecordingTransport([_response(429)])
    executor = InternalHTTPExecutor(None, transport=rate_response)
    assert executor.request("https://example.test/limited").status_code == 429

    failing = _RecordingTransport(error=TimeoutError("timeout"))
    executor = InternalHTTPExecutor(None, transport=failing)
    with pytest.raises(TimeoutError):
        executor.request("https://example.test/timeout")


def test_429_stop_state_is_set_before_a_queued_caller_can_start() -> None:
    transport = _BlockingRateRejectionTransport()
    executor = InternalHTTPExecutor(
        _configuration(rate="100000", concurrency=1),
        transport=transport,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - test captures both typed stops
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.entered.wait(timeout=1)
    second.start()
    transport.release.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert transport.calls == 1
    assert len(errors) == 2
    assert all(isinstance(error, HTTPRateRejected) for error in errors)


def test_429_while_second_caller_waits_for_rate_slot_cannot_reach_transport() -> None:
    clock = _GateTime()
    transport = _FirstExchangeGateTransport(_response(429))
    executor = InternalHTTPExecutor(
        _configuration(rate="2", concurrency=2),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - asserts typed terminal states
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.first_entered.wait(timeout=1)
    second.start()
    assert clock.sleeper_entered.wait(timeout=1)
    transport.release_first.set()
    first.join(timeout=2)
    clock.release_sleeper.set()
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert len(transport.requests) == 1
    assert executor.total_request_attempts == 1
    assert len(errors) == 2
    assert all(isinstance(error, HTTPRateRejected) for error in errors)


def test_close_while_second_caller_waits_for_rate_slot_cannot_reach_transport() -> None:
    clock = _GateTime()
    transport = _FirstExchangeGateTransport(_response())
    executor = InternalHTTPExecutor(
        _configuration(rate="2", concurrency=2),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - asserts typed terminal states
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.first_entered.wait(timeout=1)
    second.start()
    assert clock.sleeper_entered.wait(timeout=1)
    executor.close()
    transport.release_first.set()
    first.join(timeout=2)
    clock.release_sleeper.set()
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert len(transport.requests) == 1
    assert executor.total_request_attempts == 1
    assert len(errors) == 1
    assert isinstance(errors[0], HTTPExecutorClosed)


def test_close_interrupts_an_extreme_rate_limiter_wait() -> None:
    clock = _ExtremeWaitGateTime()
    transport = _FirstExchangeGateTransport(_response())
    executor = InternalHTTPExecutor(
        _configuration(rate="1e-1000", concurrency=2),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - asserts typed terminal states
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.first_entered.wait(timeout=1)
    second.start()
    assert clock.first_sleep_entered.wait(timeout=1)
    executor.close()
    transport.release_first.set()
    first.join(timeout=2)
    clock.release_first_sleep.set()
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not clock.second_sleep_entered.is_set()
    assert len(transport.requests) == 1
    assert executor.total_request_attempts == 1
    assert len(errors) == 1
    assert isinstance(errors[0], HTTPExecutorClosed)


def test_429_interrupts_an_extreme_rate_limiter_wait() -> None:
    clock = _ExtremeWaitGateTime()
    transport = _FirstExchangeGateTransport(_response(429))
    executor = InternalHTTPExecutor(
        _configuration(rate="1e-1000", concurrency=2),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - asserts typed terminal states
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.first_entered.wait(timeout=1)
    second.start()
    assert clock.first_sleep_entered.wait(timeout=1)
    transport.release_first.set()
    first.join(timeout=2)
    clock.release_first_sleep.set()
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not clock.second_sleep_entered.is_set()
    assert len(transport.requests) == 1
    assert executor.total_request_attempts == 1
    assert len(errors) == 2
    assert all(isinstance(error, HTTPRateRejected) for error in errors)


def test_unsafe_retry_after_value_is_omitted_from_rate_rejection() -> None:
    transport = _RecordingTransport(
        [_response(429, (("Retry-After", "private\u2028control"),))]
    )
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    with pytest.raises(HTTPRateRejected) as exc_info:
        executor.request("https://example.test/limited")

    assert exc_info.value.retry_after == "present but unsafe value omitted"
    assert "private" not in str(exc_info.value)


@pytest.mark.parametrize("unsafe", ("\u202e", "\u2066", "\ud800", "\u2028", "\u2029"))
def test_target_controlled_unicode_controls_are_redacted_or_refused(unsafe: str) -> None:
    retry_after = f"private{unsafe}value"

    assert _safe_retry_after((("Retry-After", retry_after),)) == (
        "present but unsafe value omitted"
    )
    with pytest.raises(HTTPRedirectRefused, match="malformed_location") as exc_info:
        _resolve_redirect_location("https://example.test/start", f"/safe{unsafe}path")

    assert retry_after not in str(exc_info.value)


def test_printable_unicode_redirect_path_remains_available_to_the_validator() -> None:
    assert _resolve_redirect_location(
        "https://example.test/start",
        "/caf\u00e9",
    ) == "https://example.test/caf\u00e9"


def test_concurrency_slot_is_released_after_transport_failure() -> None:
    failing = _RecordingTransport(error=TimeoutError("timeout"))
    executor = InternalHTTPExecutor(_configuration(), transport=failing)
    with pytest.raises(HTTPTransportFailure, match="timeout"):
        executor.request("https://example.test/fail")

    succeeding = _RecordingTransport()
    executor.transport = succeeding
    executor.request("https://example.test/recovered")
    assert len(succeeding.requests) == 1


def test_concurrency_slot_is_released_after_transport_response_validation_failure() -> None:
    class InvalidThenValidTransport:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, _request):
            self.calls += 1
            return object() if self.calls == 1 else _response()

    transport = InvalidThenValidTransport()
    executor = InternalHTTPExecutor(_configuration(), transport=transport)

    with pytest.raises(ValueError, match="invalid response"):
        executor.request("https://example.test/invalid")
    assert executor.request("https://example.test/recovered").status_code == 200


def test_concurrency_slot_is_released_after_redirect_refusal_and_http_error() -> None:
    redirect_transport = _RecordingTransport(
        [_response(302, (("Location", "https://other.test/"),))]
    )
    executor = InternalHTTPExecutor(_configuration(), transport=redirect_transport)
    with pytest.raises(HTTPRedirectRefused):
        executor.request("https://example.test/redirect")

    succeeding = _RecordingTransport([_response(503), _response()])
    executor.transport = succeeding
    assert executor.request("https://example.test/unavailable").status_code == 503
    assert executor.request("https://example.test/recovered").status_code == 200


def test_executor_close_refuses_future_requests_without_transport() -> None:
    transport = _RecordingTransport()
    executor = InternalHTTPExecutor(_configuration(), transport=transport)
    executor.close()

    with pytest.raises(HTTPExecutorClosed):
        executor.request("https://example.test/")

    assert transport.requests == []


def test_closing_executor_refuses_a_queued_request_without_deadlock() -> None:
    transport = _BlockingTransport(expected_active=1)
    executor = InternalHTTPExecutor(
        _configuration(rate="100000", concurrency=1),
        transport=transport,
    )
    errors: list[Exception] = []

    def request(path: str) -> None:
        try:
            executor.request(f"https://example.test/{path}")
        except Exception as exc:  # noqa: BLE001 - verifies the typed cancellation
            errors.append(exc)

    first = threading.Thread(target=request, args=("first",))
    second = threading.Thread(target=request, args=("second",))
    first.start()
    assert transport.entered.wait(timeout=1)
    second.start()
    executor.close()
    transport.release.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], HTTPExecutorClosed)


def test_internal_http_source_audit_has_one_transport_boundary_and_no_stale_agent() -> None:
    root = Path(__file__).resolve().parents[1]
    package = root / "bugslyce"
    transport_path = package / "recon" / "http_enforcement.py"
    transport_source = transport_path.read_text(encoding="utf-8")
    assert "time.time" not in transport_source
    direct_patterns = (
        r"from urllib\.request import",
        r"import urllib\.request",
        r"\burlopen\(",
        r"\bbuild_opener\(",
        r"\brequests\.(?:get|post|put|delete|request)\(",
        r"\b(?:HTTPConnection|HTTPSConnection)\(",
    )

    for path in package.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "BugSlyce/0.3" not in source
        if path == transport_path:
            continue
        for pattern in direct_patterns:
            assert re.search(pattern, source) is None, (path, pattern)

    assert R0B3_BLOCKED_LEGACY_LIVE_RUNNERS == (
        "bugslyce.recon.runner.LiveCurlHeaderRunner",
        "bugslyce.recon.runner.LiveHTTPMetadataRunner",
        "bugslyce.recon.runner.LivePathFollowupRunner",
        "bugslyce.recon.runner.LiveContentFollowupRunner",
        "bugslyce.recon.runner.LiveBodyFetchRunner",
        "bugslyce.recon.runner.LiveContentDiscoveryRunner",
        "bugslyce.recon.runner.LiveNmapDiscoveryRunner",
        "bugslyce.recon.runner.LiveNmapServiceRunner",
    )
    assert R0B2_POLICY_AWARE_EXTERNAL_BOUNDARIES == (
        "bugslyce.recon.external_enforcement.build_bug_bounty_curl_plan",
        "bugslyce.recon.external_enforcement.build_bug_bounty_gobuster_plan",
        "bugslyce.recon.external_enforcement.build_bug_bounty_nmap_plan",
    )


def _configuration(
    *,
    rate: str = "2",
    concurrency: int = 1,
    approved_origins: tuple[str, ...] = ("https://example.test",),
    maximum_redirect_hops: int = 5,
) -> HTTPEnforcementConfiguration:
    return HTTPEnforcementConfiguration(
        maximum_request_starts_per_second=Decimal(rate),
        maximum_concurrent_requests=concurrency,
        user_agent=USER_AGENT_SENTINEL,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", HEADER_SENTINEL),
        ),
        approved_origins=tuple(
            origin
            for value in approved_origins
            if (origin := http_origin_from_url(value)) is not None
        ),
        maximum_redirect_hops=maximum_redirect_hops,
    )



def _programme_scope_policy_with_fixture_peer(
    rules: tuple[tuple[str, str, str, str], ...],
    *,
    private_note: str | None = None,
    private_source_wording: str | None = None,
) -> ProgrammeScopePolicy:
    return _programme_scope_policy(
        (
            *rules,
            (
                "fixture-peer-network",
                ACTION_INCLUDE,
                RULE_IPV4_CIDR,
                "192.0.2.0/24",
            ),
        ),
        private_note=private_note,
        private_source_wording=private_source_wording,
    )


def _programme_scope_policy(
    rules: tuple[tuple[str, str, str, str], ...],
    *,
    private_note: str | None = None,
    private_source_wording: str | None = None,
) -> ProgrammeScopePolicy:
    return build_programme_scope_policy(
        [
            build_programme_scope_rule(
                rule_id=rule_id,
                action=action,
                kind=kind,
                value=value,
                private_note=private_note,
                private_source_wording=private_source_wording,
            )
            for rule_id, action, kind, value in rules
        ],
        updated_at="2026-07-30T10:00:00Z",
    )


def _complete_policy():
    return build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="2",
        maximum_http_concurrency=1,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", HEADER_SENTINEL),
        ),
        custom_user_agent=USER_AGENT_SENTINEL,
        updated_at="2026-07-28T10:00:00Z",
    )


def _response(
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    *,
    body: bytes = b"ok",
) -> HTTPTransportResponse:
    return HTTPTransportResponse(status_code=status, headers=headers, body=body)
