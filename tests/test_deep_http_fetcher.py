"""Tests for the bounded Deep urllib HTTP fetcher."""

from __future__ import annotations

from dataclasses import replace
from urllib.error import HTTPError

import bugslyce.recon.deep_http_fetcher as fetcher_module
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionRequest,
    default_deep_collection_bounds,
    evaluate_deep_collection_requests,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.deep_http_fetcher import urllib_deep_http_fetcher
from bugslyce.recon.deep_metadata_collector import (
    DeepHTTPResponse,
    collect_deep_metadata_from_plan,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_get_request_uses_get_user_agent_timeout_and_bounded_read(monkeypatch) -> None:
    calls = []
    opener = _FakeOpener(
        _FakeResponse(
            "http://example.test/robots.txt",
            status=200,
            headers=(("content-type", "text/plain"),),
            body=b"abcdef",
        ),
        calls,
    )
    _install_fake_opener(monkeypatch, opener)
    bounds = replace(default_deep_collection_bounds(), max_response_bytes=3, timeout_seconds=7)

    response = urllib_deep_http_fetcher(
        _request("http://example.test/robots.txt", method="GET"),
        bounds,
    )

    assert isinstance(response, DeepHTTPResponse)
    assert response.url == "http://example.test/robots.txt"
    assert response.final_url == "http://example.test/robots.txt"
    assert response.status_code == 200
    assert response.headers == (("content-type", "text/plain"),)
    assert response.body == b"abcd"
    assert response.elapsed_seconds >= 0
    assert len(calls) == 1
    urllib_request, timeout = calls[0]
    assert urllib_request.get_method() == "GET"
    assert urllib_request.full_url == "http://example.test/robots.txt"
    assert urllib_request.get_header("User-agent") == "BugSlyce/0.3 authorised-recon"
    assert timeout == 7
    assert opener.response.read_sizes == [4]


def test_head_request_uses_head(monkeypatch) -> None:
    calls = []
    opener = _FakeOpener(_FakeResponse("https://example.test/security.txt"), calls)
    _install_fake_opener(monkeypatch, opener)

    urllib_deep_http_fetcher(
        _request("https://example.test/security.txt", method="HEAD"),
        default_deep_collection_bounds(),
    )

    assert calls[0][0].get_method() == "HEAD"


def test_fetcher_rejects_unsafe_or_unsupported_request_shapes() -> None:
    bounds = default_deep_collection_bounds()
    cases = (
        (_request("http://example.test/robots.txt", method="POST"), "method_not_allowed"),
        (_request("ftp://example.test/robots.txt"), "unsupported_scheme"),
        (_request("http://user:pass@example.test/robots.txt"), "url_userinfo_not_allowed"),
        (_request("http://example.test/robots.txt#frag"), "url_fragment_not_allowed"),
        (_request("http://example.test/search?q=test"), "query_string_not_allowed"),
    )

    for request, expected_message in cases:
        try:
            urllib_deep_http_fetcher(request, bounds)
        except ValueError as error:
            assert str(error) == expected_message
        else:
            raise AssertionError(f"expected {expected_message}")


def test_query_strings_are_allowed_when_bounds_allow_them(monkeypatch) -> None:
    calls = []
    opener = _FakeOpener(_FakeResponse("http://example.test/search?q=test"), calls)
    _install_fake_opener(monkeypatch, opener)
    bounds = replace(default_deep_collection_bounds(), allow_query_strings=True)

    response = urllib_deep_http_fetcher(
        _request("http://example.test/search?q=test"),
        bounds,
    )

    assert response.url == "http://example.test/search?q=test"
    assert calls[0][0].full_url == "http://example.test/search?q=test"


def test_http_error_response_is_returned_not_raised(monkeypatch) -> None:
    error = HTTPError(
        "http://example.test/missing.txt",
        404,
        "Not Found",
        _FakeHeaders((("content-type", "text/plain"),)),
        _FakeBody(b"missing"),
    )
    calls = []
    opener = _FakeOpener(error, calls)
    _install_fake_opener(monkeypatch, opener)

    response = urllib_deep_http_fetcher(
        _request("http://example.test/missing.txt"),
        default_deep_collection_bounds(),
    )

    assert response.status_code == 404
    assert response.final_url == "http://example.test/missing.txt"
    assert response.headers == (("content-type", "text/plain"),)
    assert response.body == b"missing"


def test_redirects_are_not_automatically_followed(monkeypatch) -> None:
    captured_handlers = []

    def fake_build_opener(*handlers):
        captured_handlers.extend(handlers)
        return _FakeOpener(
            _FakeResponse(
                "http://example.test/login",
                status=302,
                headers=(("location", "http://other.test/"),),
                body=b"",
            ),
            [],
        )

    monkeypatch.setattr(fetcher_module, "build_opener", fake_build_opener)

    response = urllib_deep_http_fetcher(
        _request("http://example.test/login"),
        default_deep_collection_bounds(),
    )

    assert response.status_code == 302
    assert response.final_url == "http://example.test/login"
    assert response.headers == (("location", "http://other.test/"),)
    assert len(captured_handlers) == 1
    handler = captured_handlers[0]()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://other.test/") is None


def test_request_has_no_cookie_or_auth_headers(monkeypatch) -> None:
    calls = []
    opener = _FakeOpener(_FakeResponse("http://example.test/robots.txt"), calls)
    _install_fake_opener(monkeypatch, opener)

    urllib_deep_http_fetcher(
        _request("http://example.test/robots.txt"),
        default_deep_collection_bounds(),
    )

    headers = calls[0][0].headers
    assert "Cookie" not in headers
    assert "Authorization" not in headers
    assert set(headers) == {"User-agent"}


def test_collector_integration_with_urllib_fetcher_uses_fake_opener_only(monkeypatch) -> None:
    calls = []
    opener = _FakeOpener(_FakeResponse("http://example.test/robots.txt", body=b"robots"), calls)
    _install_fake_opener(monkeypatch, opener)
    metadata = _request("http://example.test/robots.txt", source="metadata_coverage")
    route = _request("http://example.test/login.php", source="source_route_coverage")
    plan = _plan((metadata, route), allowed_origins=("http://example.test",))

    result = collect_deep_metadata_from_plan(plan, fetcher=urllib_deep_http_fetcher)

    assert tuple(item.url for item in result.collected) == ("http://example.test/robots.txt",)
    assert tuple(item.reason for item in result.skipped) == ("non_metadata_request",)
    assert len(calls) == 1
    assert calls[0][0].full_url == "http://example.test/robots.txt"


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _install_fake_opener(monkeypatch, opener: "_FakeOpener") -> None:
    monkeypatch.setattr(fetcher_module, "build_opener", lambda *handlers: opener)


def _plan(
    requests: tuple[DeepCollectionRequest, ...],
    *,
    allowed_origins: tuple[str, ...],
) -> DeepCollectionRequestPlan:
    return DeepCollectionRequestPlan(
        allowed_origins=allowed_origins,
        proposed_requests=requests,
        policy_summary=evaluate_deep_collection_requests(
            requests,
            allowed_origins=allowed_origins,
        ),
        source_counts=(),
    )


def _request(
    url: str,
    *,
    method: str = "GET",
    source: str = "metadata_coverage",
) -> DeepCollectionRequest:
    return DeepCollectionRequest(
        url=url,
        method=method,
        source=source,
        reason="unit-test",
        origin="",
        path="",
        evidence_ids=("EVID-1",),
        tags=("metadata",) if source == "metadata_coverage" else ("route",),
    )


class _FakeOpener:
    def __init__(self, response, calls: list) -> None:
        self.response = response
        self.calls = calls

    def open(self, request, *, timeout: int):
        self.calls.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status: int = 200,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"ok",
    ) -> None:
        self._url = url
        self.status = status
        self.headers = _FakeHeaders(headers)
        self._body = body
        self.read_sizes: list[int] = []

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self._body[:size]


class _FakeHeaders:
    def __init__(self, headers: tuple[tuple[str, str], ...]) -> None:
        self._headers = headers

    def items(self):
        return self._headers


class _FakeBody:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.read_sizes: list[int] = []

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self._body[:size]

    def close(self) -> None:
        pass
