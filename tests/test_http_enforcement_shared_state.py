"""RED contracts for aggregate HTTP enforcement across exact-origin views."""

from __future__ import annotations

from decimal import Decimal
import importlib
import threading

import pytest

from bugslyce.recon.http_enforcement import (
    HTTPExecutorClosed,
    HTTPProgrammeScopeRefused,
    HTTPRateRejected,
    HTTPTransportResponse,
    InternalHTTPExecutor,
    PeerBoundHTTPTransport,
    build_http_enforcement_configuration,
)
from test_native_content_discovery import _runtime


class _Clock:
    def __init__(self) -> None:
        self.now = Decimal("0")

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        self.now += Decimal(str(seconds))


class _RecordingTransport(PeerBoundHTTPTransport):
    def __init__(self, responder, *, clock: _Clock | None = None) -> None:
        self._responder = responder
        self._clock = clock
        self.requests = []
        self.starts: list[Decimal] = []

    def __call__(self, request):
        self.requests.append(request)
        if self._clock is not None:
            self.starts.append(self._clock.now)
        status, body = self._responder(request.url)
        return HTTPTransportResponse(status_code=status, headers=(), body=body)


class _AggregateBlockingTransport(PeerBoundHTTPTransport):
    def __init__(self, tracker) -> None:
        self._tracker = tracker

    def __call__(self, _request):
        with self._tracker["lock"]:
            self._tracker["active"] += 1
            self._tracker["maximum"] = max(
                self._tracker["maximum"], self._tracker["active"]
            )
            self._tracker["entered"].set()
            if self._tracker["active"] > 1:
                self._tracker["overlap"].set()
        if not self._tracker["release"].wait(timeout=2):
            raise AssertionError("test transport release was not signalled")
        with self._tracker["lock"]:
            self._tracker["active"] -= 1
        return HTTPTransportResponse(status_code=200, headers=(), body=b"ok")


def _shared_view(parent: InternalHTTPExecutor, origins: tuple[str, ...]):
    module = importlib.import_module("bugslyce.recon.http_enforcement")
    builder = getattr(module, "build_internal_http_executor_view")
    return builder(parent, approved_origins=origins)


def _contexts(tmp_path):
    runtime = _runtime(tmp_path / "runtime")
    clock = _Clock()
    strict_transport = _RecordingTransport(lambda _url: (200, b"strict"), clock=clock)
    configuration = build_http_enforcement_configuration(
        runtime.policy,
        approved_origins=("https://app.example.test",),
    )
    strict = InternalHTTPExecutor(
        configuration,
        programme_scope_policy=runtime.programme_scope_policy,
        transport=strict_transport,
        ipv4_resolver=runtime.ipv4_resolver,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    sibling = _shared_view(strict, ("https://api.example.test",))
    sibling_transport = _RecordingTransport(
        lambda _url: (200, b"sibling"), clock=clock
    )
    sibling.transport = sibling_transport
    return runtime, clock, strict, sibling, strict_transport, sibling_transport


def test_exact_origin_executor_views_share_one_deterministic_request_start_schedule(
    tmp_path,
) -> None:
    _runtime_value, clock, strict, sibling, strict_transport, sibling_transport = (
        _contexts(tmp_path)
    )
    try:
        strict.request("https://app.example.test/strict")
        sibling.request("https://api.example.test/sibling")
    finally:
        sibling.close()
        strict.close()

    assert strict_transport.starts == [Decimal("0")]
    assert sibling_transport.starts == [Decimal("0.5")]
    assert clock.now == Decimal("0.5")
    assert strict.total_request_attempts == 2
    assert sibling.total_request_attempts == 2
    assert strict.last_request_start == Decimal("0.5")
    assert sibling.last_request_start == Decimal("0.5")


def test_exact_origin_executor_views_share_aggregate_concurrency(
    tmp_path,
) -> None:
    _runtime_value, _clock, strict, sibling, _strict_transport, _sibling_transport = (
        _contexts(tmp_path)
    )
    tracker = {
        "lock": threading.Lock(),
        "active": 0,
        "maximum": 0,
        "entered": threading.Event(),
        "overlap": threading.Event(),
        "release": threading.Event(),
    }
    strict.transport = _AggregateBlockingTransport(tracker)
    sibling.transport = _AggregateBlockingTransport(tracker)
    errors: list[BaseException] = []

    def request(executor, url: str) -> None:
        try:
            executor.request(url)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(
        target=request,
        args=(strict, "https://app.example.test/strict"),
    )
    second = threading.Thread(
        target=request,
        args=(sibling, "https://api.example.test/sibling"),
    )
    first.start()
    assert tracker["entered"].wait(timeout=1)
    second.start()
    assert not tracker["overlap"].wait(timeout=0.1)
    tracker["release"].set()
    first.join(timeout=2)
    second.join(timeout=2)
    sibling.close()
    strict.close()

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert tracker["maximum"] == 1


@pytest.mark.parametrize("rejecting_context", ("strict", "sibling"))
def test_http_429_terminal_state_is_shared_in_both_directions(
    tmp_path,
    rejecting_context: str,
) -> None:
    _runtime_value, _clock, strict, sibling, strict_transport, sibling_transport = (
        _contexts(tmp_path)
    )
    rejecting = strict if rejecting_context == "strict" else sibling
    blocked = sibling if rejecting_context == "strict" else strict
    rejecting_transport = (
        strict_transport if rejecting_context == "strict" else sibling_transport
    )
    blocked_transport = (
        sibling_transport if rejecting_context == "strict" else strict_transport
    )
    rejecting.transport = _RecordingTransport(lambda _url: (429, b"slow down"))
    rejecting_transport = rejecting.transport
    try:
        with pytest.raises(HTTPRateRejected):
            rejecting.request(
                "https://app.example.test/reject"
                if rejecting is strict
                else "https://api.example.test/reject"
            )
        with pytest.raises(HTTPRateRejected):
            blocked.request(
                "https://api.example.test/blocked"
                if blocked is sibling
                else "https://app.example.test/blocked"
            )
    finally:
        sibling.close()
        strict.close()

    assert len(rejecting_transport.requests) == 1
    assert blocked_transport.requests == []


def test_closing_temporary_executor_view_is_handle_local(
    tmp_path,
) -> None:
    _runtime_value, _clock, strict, sibling, strict_transport, _sibling_transport = (
        _contexts(tmp_path)
    )
    sibling.close()

    with pytest.raises(HTTPExecutorClosed):
        sibling.request("https://api.example.test/closed")
    response = strict.request("https://app.example.test/still-live")
    strict.close()

    assert response.status_code == 200
    assert len(strict_transport.requests) == 1


def test_executor_view_preserves_policy_but_keeps_exact_origin_authority_local(
    tmp_path,
) -> None:
    runtime, _clock, strict, sibling, strict_transport, sibling_transport = _contexts(
        tmp_path
    )
    blocked_view = _shared_view(strict, ("https://service.other.test",))
    blocked_transport = _RecordingTransport(lambda _url: (200, b"must not run"))
    blocked_view.transport = blocked_transport
    try:
        assert sibling.configuration.maximum_request_starts_per_second == (
            strict.configuration.maximum_request_starts_per_second
        )
        assert sibling.configuration.maximum_concurrent_requests == (
            strict.configuration.maximum_concurrent_requests
        )
        assert sibling.configuration.user_agent == strict.configuration.user_agent
        assert sibling.configuration.identification_headers == (
            strict.configuration.identification_headers
        )
        assert sibling.configuration.redirect_policy == strict.configuration.redirect_policy
        assert sibling.configuration.maximum_redirect_hops == (
            strict.configuration.maximum_redirect_hops
        )
        assert sibling.configuration.approved_origins != strict.configuration.approved_origins

        with pytest.raises(ValueError, match="origin is not approved"):
            strict.request("https://api.example.test/not-strict")
        with pytest.raises(ValueError, match="origin is not approved"):
            sibling.request("https://app.example.test/not-sibling")
        assert sibling.request("https://api.example.test/allowed").status_code == 200
        with pytest.raises(HTTPProgrammeScopeRefused):
            blocked_view.request("https://service.other.test/not-programme-authorised")
    finally:
        blocked_view.close()
        sibling.close()
        strict.close()

    assert strict_transport.requests == []
    assert len(sibling_transport.requests) == 1
    assert blocked_transport.requests == []
