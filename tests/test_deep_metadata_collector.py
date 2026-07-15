"""Tests for bounded Deep metadata collection core."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionDecision,
    DeepCollectionPolicySummary,
    DeepCollectionRequest,
    default_deep_collection_bounds,
    evaluate_deep_collection_requests,
)
from bugslyce.recon.deep_collection_request_plan import (
    DeepCollectionRequestPlan,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepHTTPResponse,
    collect_deep_metadata_from_plan,
    render_deep_metadata_collection_result_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_plan_returns_empty_result() -> None:
    calls: list[str] = []
    result = collect_deep_metadata_from_plan(
        _plan(()),
        fetcher=_fake_fetcher(calls),
    )

    assert result.collected == ()
    assert result.skipped == ()
    assert result.total_considered == 0
    assert result.total_collected == 0
    assert result.total_skipped == 0
    assert calls == []


def test_collector_fetches_only_allowed_metadata_requests() -> None:
    calls: list[str] = []
    metadata = _request("http://example.test/robots.txt", source="metadata_coverage")
    route = _request("http://example.test/login.php", source="source_route_coverage")
    blocked = _request("http://example.test/account?id=1", source="metadata_coverage")

    result = collect_deep_metadata_from_plan(
        _plan((metadata, route, blocked), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(calls, body=b"User-agent: *\n"),
    )

    assert calls == ["http://example.test/robots.txt"]
    assert tuple(item.url for item in result.collected) == ("http://example.test/robots.txt",)
    assert tuple(item.reason for item in result.skipped) == (
        "non_metadata_request",
        "policy_blocked",
    )
    assert result.total_considered == 3
    assert result.total_collected == 1
    assert result.total_skipped == 2


def test_collector_skips_non_get_head_and_missing_requests() -> None:
    post_request = _request("http://example.test/robots.txt", method="POST", source="metadata_coverage")
    missing_decision = DeepCollectionDecision(
        url="http://example.test/sitemap.xml",
        method="GET",
        allowed=True,
        reason="policy_allowed",
        policy_notes=(),
        origin="http://example.test",
        path="/sitemap.xml",
        evidence_ids=("EVID-MISSING",),
    )
    summary = DeepCollectionPolicySummary(
        bounds=default_deep_collection_bounds(),
        decisions=(
            evaluate_deep_collection_requests(
                (post_request,),
                allowed_origins=("http://example.test",),
            ).decisions[0],
            missing_decision,
        ),
        allowed_count=1,
        blocked_count=1,
        blocked_reasons=(("method_not_allowed", 1),),
    )
    result = collect_deep_metadata_from_plan(
        DeepCollectionRequestPlan(
            allowed_origins=("http://example.test",),
            proposed_requests=(post_request,),
            policy_summary=summary,
            source_counts=(),
        ),
        fetcher=_fake_fetcher([]),
    )

    assert tuple(item.reason for item in result.skipped) == (
        "method_not_allowed",
        "request_not_found",
    )
    assert result.collected == ()


def test_fetcher_exception_creates_fetch_error_skip() -> None:
    request = _request("http://example.test/robots.txt", source="metadata_coverage")

    def failing_fetcher(_request, _bounds):
        raise RuntimeError("network failed")

    result = collect_deep_metadata_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=failing_fetcher,
    )

    assert result.collected == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "fetch_error"
    assert result.skipped[0].url == "http://example.test/robots.txt"


def test_collected_item_has_bounded_preview_hash_headers_and_no_full_body() -> None:
    body = ("remember-this-" * 80).encode()
    calls: list[str] = []
    request = _request(
        "http://example.test/robots.txt",
        source="metadata_coverage",
        evidence_ids=("EVID-1", "EVID-1", "EVID-2"),
    )

    result = collect_deep_metadata_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(
            calls,
            body=body,
            headers=(("content-type", "text/plain"),),
            elapsed_seconds=0.42,
        ),
    )

    item = result.collected[0]
    assert calls == ["http://example.test/robots.txt"]
    assert not hasattr(item, "body")
    assert item.body_bytes == len(body)
    assert len(item.body_preview) == 500
    assert item.body_sha256 == sha256(body).hexdigest()
    assert item.headers == (("content-type", "text/plain"),)
    assert item.elapsed_seconds == 0.42
    assert item.evidence_ids == ("EVID-1", "EVID-2")


def test_bounds_are_passed_to_fetcher_and_oversized_response_is_skipped() -> None:
    captured = []
    body = b"0123456789abcdef"
    bounds = replace(default_deep_collection_bounds(), max_response_bytes=5)
    request = _request("http://example.test/robots.txt", source="metadata_coverage")

    def fetcher(request_arg, bounds_arg):
        captured.append((request_arg.url, bounds_arg.max_response_bytes, bounds_arg.timeout_seconds))
        return DeepHTTPResponse(
            url=request_arg.url,
            final_url=request_arg.url,
            status_code=200,
            headers=(),
            body=body,
            elapsed_seconds=0.01,
        )

    result = collect_deep_metadata_from_plan(
        _plan((request,), bounds=bounds, allowed_origins=("http://example.test",)),
        fetcher=fetcher,
    )

    assert captured == [("http://example.test/robots.txt", 5, bounds.timeout_seconds)]
    assert result.collected == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "response_too_large"
    assert result.skipped[0].url == "http://example.test/robots.txt"
    assert result.skipped[0].method == "GET"
    assert result.skipped[0].source == "metadata_coverage"
    assert result.skipped[0].evidence_ids == ("EVID-1",)


def test_collection_order_is_deterministic() -> None:
    first = _request("http://example.test/robots.txt", source="metadata_coverage")
    second = _request("http://example.test/sitemap.xml", source="metadata_coverage")

    result = collect_deep_metadata_from_plan(
        _plan((first, second), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher([]),
    )

    assert tuple(item.url for item in result.collected) == (
        "http://example.test/robots.txt",
        "http://example.test/sitemap.xml",
    )


def test_renderer_includes_sections_safety_wording_and_no_finding_language() -> None:
    request = _request("http://example.test/robots.txt", source="metadata_coverage")
    oversized = _request("http://example.test/sitemap.xml", source="metadata_coverage")

    def fetcher(request_arg, bounds_arg):
        if request_arg.url.endswith("/sitemap.xml"):
            return DeepHTTPResponse(
                url=request_arg.url,
                final_url=request_arg.url,
                status_code=200,
                headers=(),
                body=b"x" * (bounds_arg.max_response_bytes + 1),
                elapsed_seconds=0.01,
            )
        return DeepHTTPResponse(
            url=request_arg.url,
            final_url=request_arg.url,
            status_code=200,
            headers=(("content-type", "text/plain"),),
            body=b"robots body",
            elapsed_seconds=0.01,
        )

    result = collect_deep_metadata_from_plan(
        _plan((request, oversized), allowed_origins=("http://example.test",)),
        fetcher=fetcher,
    )
    rendered = render_deep_metadata_collection_result_markdown(result)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Metadata Collection Result\n")
    assert "### Summary" in rendered
    assert "### Collected Metadata" in rendered
    assert "### Skipped Requests" in rendered
    assert "### Safety Notes" in rendered
    assert "http://example.test/robots.txt" in rendered
    assert "Status: `200`" in rendered
    assert "Body SHA-256" in rendered
    assert "Body preview: `robots body`" in rendered
    assert "response_too_large" in rendered
    assert "http://example.test/sitemap.xml" in rendered
    assert "|" not in rendered
    for required in (
        "This is a bounded metadata collection result.",
        "It does not submit forms.",
        "It does not authenticate.",
        "It does not brute force.",
        "It does not inject payloads.",
        "It does not execute browser JavaScript.",
        "It does not crawl.",
        "It does not collect non-metadata routes.",
        "It does not confirm vulnerabilities.",
        "This stage produces static manual-review context only.",
    ):
        assert required in rendered
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


def _plan(
    requests: tuple[DeepCollectionRequest, ...],
    *,
    bounds=None,
    allowed_origins: tuple[str, ...] = (),
) -> DeepCollectionRequestPlan:
    return DeepCollectionRequestPlan(
        allowed_origins=allowed_origins,
        proposed_requests=requests,
        policy_summary=evaluate_deep_collection_requests(
            requests,
            bounds=bounds,
            allowed_origins=allowed_origins,
        ),
        source_counts=(),
    )


def _request(
    url: str,
    *,
    method: str = "GET",
    source: str,
    reason: str = "unit-test",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepCollectionRequest:
    return DeepCollectionRequest(
        url=url,
        method=method,
        source=source,
        reason=reason,
        origin="",
        path="",
        evidence_ids=evidence_ids,
        tags=("metadata",) if source == "metadata_coverage" else ("route",),
    )


def _fake_fetcher(
    calls: list[str],
    *,
    body: bytes = b"ok",
    headers: tuple[tuple[str, str], ...] = (("content-type", "text/plain"),),
    elapsed_seconds: float = 0.01,
):
    def fetcher(request: DeepCollectionRequest, _bounds):
        calls.append(request.url)
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=headers,
            body=body,
            elapsed_seconds=elapsed_seconds,
        )

    return fetcher
