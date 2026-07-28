"""Focused tests for R0B1 internal HTTP enforcement."""

from __future__ import annotations

from decimal import Decimal
import math
from pathlib import Path
import re
import threading

import pytest

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
    with pytest.raises(ValueError, match="R0B3"):
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
    assert "R0B3" in captured.err
    assert "controlled capture acceptance" in captured.err
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
