"""Tests for offline Deep collection policy evaluation."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionRequest,
    default_deep_collection_bounds,
    evaluate_deep_collection_request,
    evaluate_deep_collection_requests,
    render_deep_collection_policy_summary_markdown,
)
from bugslyce.recon.http_origin import http_origin_from_url, same_http_origin
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_default_bounds_are_restrictive() -> None:
    bounds = default_deep_collection_bounds()

    assert bounds.max_total_requests == 100
    assert bounds.max_requests_per_origin == 25
    assert bounds.timeout_seconds == 10
    assert bounds.max_response_bytes == 1_000_000
    assert bounds.allowed_methods == ("GET", "HEAD")
    assert bounds.allowed_schemes == ("http", "https")
    assert bounds.allow_query_strings is False
    assert bounds.allow_cross_origin is False
    assert bounds.allow_form_submission is False
    assert bounds.allow_authentication is False
    assert bounds.allow_payloads is False
    assert bounds.allow_browser_execution is False


def test_get_and_head_to_allowed_origin_are_allowed() -> None:
    get_decision = evaluate_deep_collection_request(
        _request("http://example.test/robots.txt", "GET"),
        allowed_origins=("http://example.test",),
    )
    head_decision = evaluate_deep_collection_request(
        _request("http://example.test/robots.txt", "HEAD"),
        allowed_origins=("http://example.test",),
    )

    assert get_decision.allowed is True
    assert head_decision.allowed is True
    assert get_decision.reason == "policy_allowed"
    assert get_decision.policy_notes == (
        "method_allowed",
        "scheme_allowed",
        "origin_allowed",
        "within_request_bounds",
        "read_only_request",
    )


def test_default_origin_policy_blocks_without_explicit_allowed_origin() -> None:
    decision = evaluate_deep_collection_request(
        _request("http://example.test/robots.txt", "GET"),
    )

    assert decision.allowed is False
    assert decision.reason == "cross_origin_not_allowed"
    assert decision.origin == "http://example.test"


def test_http_https_and_non_default_ports_are_distinct_origins() -> None:
    http = evaluate_deep_collection_request(
        _request("http://example.test/"),
        allowed_origins=("http://example.test",),
    )
    https = evaluate_deep_collection_request(
        _request("https://example.test/"),
        allowed_origins=("https://example.test",),
    )
    port = evaluate_deep_collection_request(
        _request("http://example.test:8080/admin"),
        allowed_origins=("http://example.test:8080",),
    )

    assert http.origin == "http://example.test"
    assert https.origin == "https://example.test"
    assert port.origin == "http://example.test:8080"
    assert port.path == "/admin"


def test_http_origin_helper_normalises_scheme_host_default_ports_and_ipv6() -> None:
    assert http_origin_from_url("HTTP://Example.TEST.:80/path").origin_url == "http://example.test"
    assert same_http_origin("HTTP://Example.TEST.:80/path", "http://example.test/other")
    assert same_http_origin("http://example.test", "http://example.test:80")
    assert same_http_origin("https://example.test", "https://example.test:443")
    assert not same_http_origin("http://example.test", "https://example.test")
    assert not same_http_origin("http://example.test", "http://example.test:8080")
    assert same_http_origin("http://[2001:db8::1]/", "http://[2001:db8::1]:80/path")
    assert same_http_origin("https://[2001:db8::1]/", "https://[2001:db8::1]:443/path")


def test_http_origin_helper_fails_closed_for_unsafe_or_malformed_urls() -> None:
    assert http_origin_from_url("http://user:pass@example.test/") is None
    assert http_origin_from_url("http://example.test:bad/") is None
    assert http_origin_from_url("//example.test/path") is None
    assert http_origin_from_url("/relative") is None
    assert same_http_origin("http://example.test/path?x=1#frag", "http://example.test/other")


def test_invalid_missing_hostname_and_unsupported_scheme_are_blocked() -> None:
    assert _blocked_reason("not a url") == "invalid_url"
    assert _blocked_reason("http:///robots.txt") == "missing_hostname"
    assert _blocked_reason("ftp://example.test/robots.txt") == "unsupported_scheme"


def test_unsafe_methods_are_blocked() -> None:
    for method in ("POST", "PUT", "DELETE"):
        decision = evaluate_deep_collection_request(
            _request("http://example.test/login", method),
            allowed_origins=("http://example.test",),
        )
        assert decision.allowed is False
        assert decision.reason == "method_not_allowed"


def test_userinfo_fragment_query_and_cross_origin_are_blocked() -> None:
    assert _blocked_reason("http://user:pass@example.test/") == "url_userinfo_not_allowed"
    assert _blocked_reason("http://example.test/robots.txt#frag") == "url_fragment_not_allowed"
    assert _blocked_reason("http://example.test/search?q=test") == "query_string_not_allowed"

    decision = evaluate_deep_collection_request(
        _request("https://other.test/"),
        allowed_origins=("https://example.test",),
    )
    assert decision.reason == "cross_origin_not_allowed"


def test_request_limits_are_enforced() -> None:
    bounds = replace(default_deep_collection_bounds(), max_total_requests=1, max_requests_per_origin=1)

    total = evaluate_deep_collection_request(
        _request("http://example.test/second"),
        bounds=bounds,
        allowed_origins=("http://example.test",),
        already_seen_total=1,
    )
    per_origin = evaluate_deep_collection_request(
        _request("http://example.test/second"),
        bounds=bounds,
        allowed_origins=("http://example.test",),
        already_seen_counts_by_origin={"http://example.test": 1},
    )

    assert total.reason == "total_request_limit_exceeded"
    assert per_origin.reason == "per_origin_limit_exceeded"


def test_unsafe_intent_tags_reasons_and_sources_are_blocked() -> None:
    cases = (
        _request("http://example.test/form", tags=("form_submission",)),
        _request("http://example.test/login", reason="login_attempt candidate"),
        _request("http://example.test/payload", source="payload generator"),
        _request("http://example.test/browser", tags=("browser_execution",)),
    )

    for request in cases:
        decision = evaluate_deep_collection_request(
            request,
            allowed_origins=("http://example.test",),
        )
        assert decision.allowed is False
        assert decision.reason == "unsafe_request_intent_blocked"


def test_evaluate_multiple_requests_counts_allowed_blocked_and_reasons() -> None:
    bounds = replace(default_deep_collection_bounds(), max_total_requests=2, max_requests_per_origin=2)
    requests = (
        _request("http://example.test/one"),
        _request("http://example.test/two"),
        _request("http://example.test/three"),
        _request("https://other.test/"),
        _request("ftp://example.test/file"),
    )

    first = evaluate_deep_collection_requests(
        requests,
        bounds=bounds,
        allowed_origins=("http://example.test",),
    )
    second = evaluate_deep_collection_requests(
        requests,
        bounds=bounds,
        allowed_origins=("http://example.test",),
    )

    assert first == second
    assert first.allowed_count == 2
    assert first.blocked_count == 3
    assert first.blocked_reasons == (
        ("cross_origin_not_allowed", 1),
        ("total_request_limit_exceeded", 1),
        ("unsupported_scheme", 1),
    )


def test_renderer_includes_bounds_decisions_and_safety_wording() -> None:
    summary = evaluate_deep_collection_requests(
        (
            _request("http://example.test/robots.txt"),
            _request("http://example.test/login", "POST"),
            _request("https://other.test/"),
        ),
        allowed_origins=("http://example.test",),
    )
    rendered = render_deep_collection_policy_summary_markdown(summary)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Collection Policy Summary\n")
    assert "### Bounds" in rendered
    assert "- Allowed methods: `GET`, `HEAD`" in rendered
    assert "- Allowed schemes: `http`, `https`" in rendered
    assert "- Max total requests: 100" in rendered
    assert "- Max requests per origin: 25" in rendered
    assert "- Max response bytes: 1000000" in rendered
    assert "- Form submission allowed: no" in rendered
    assert "- Authentication allowed: no" in rendered
    assert "- Payloads allowed: no" in rendered
    assert "- Browser execution allowed: no" in rendered
    assert "### Allowed Requests" in rendered
    assert "### Blocked Requests" in rendered
    assert "does not fetch URLs" in rendered
    assert "run live recon" in rendered
    assert "execute Deep Recon" in rendered
    assert "policy validation view, not a collection result" in rendered
    assert "Allowed means policy-permitted for future collection, not fetched" in rendered
    assert "Deep Recon was not executed" in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit found",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
        "confirmed exposure",
    ):
        assert forbidden not in lowered


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _blocked_reason(url: str) -> str:
    return evaluate_deep_collection_request(
        _request(url),
        allowed_origins=("http://example.test",),
    ).reason


def _request(
    url: str,
    method: str = "GET",
    *,
    source: str = "unit-test",
    reason: str = "metadata preview",
    tags: tuple[str, ...] = (),
) -> DeepCollectionRequest:
    return DeepCollectionRequest(
        url=url,
        method=method,
        source=source,
        reason=reason,
        origin="",
        path="",
        evidence_ids=("EVID-0001",),
        tags=tags,
    )
