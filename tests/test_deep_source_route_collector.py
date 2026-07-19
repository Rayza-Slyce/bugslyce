"""Tests for bounded Deep source/route collection core."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionDecision,
    DeepCollectionPolicySummary,
    DeepCollectionRequest,
    default_deep_collection_bounds,
    evaluate_deep_collection_requests,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.deep_source_route_collector import (
    collect_deep_source_routes_from_plan,
    render_deep_source_route_collection_result_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_collects_only_policy_allowed_source_route_get_requests() -> None:
    calls: list[str] = []
    route = _request("http://example.test/login.php", source="source_route_coverage")
    metadata = _request("http://example.test/robots.txt", source="metadata_coverage")

    result = collect_deep_source_routes_from_plan(
        _plan((route, metadata), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(calls, body=b"<html>login</html>"),
    )

    assert calls == ["http://example.test/login.php"]
    assert tuple(item.url for item in result.collected) == ("http://example.test/login.php",)
    assert tuple(item.reason for item in result.skipped) == ("metadata_request",)
    assert result.total_considered == 2
    assert result.total_collected == 1
    assert result.total_skipped == 1


def test_skips_policy_blocked_and_unsupported_methods() -> None:
    post_request = _request(
        "http://example.test/login.php",
        method="POST",
        source="source_route_coverage",
    )
    blocked = _request("https://other.test/admin", source="source_route_coverage")

    result = collect_deep_source_routes_from_plan(
        _plan((post_request, blocked), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher([]),
    )

    assert result.collected == ()
    assert tuple(item.reason for item in result.skipped) == (
        "method_not_allowed",
        "policy_blocked",
    )


def test_skips_query_string_urls_even_if_policy_marked_allowed() -> None:
    query = _request(
        "http://example.test/admin?sort=name",
        source="source_route_coverage",
    )
    decision = DeepCollectionDecision(
        url=query.url,
        method=query.method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=("unit_test_allowed",),
        origin="http://example.test",
        path="/admin",
        evidence_ids=query.evidence_ids,
    )

    result = collect_deep_source_routes_from_plan(
        _manual_plan((query,), (decision,)),
        fetcher=_fake_fetcher([]),
    )

    assert result.collected == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "query_string_not_allowed"


def test_manual_cross_origin_allowed_decision_is_rejected_before_fetch() -> None:
    calls: list[str] = []
    external = _request(
        "http://other.test/admin",
        source="source_route_coverage",
    )
    decision = DeepCollectionDecision(
        url=external.url,
        method=external.method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=("unit_test_allowed",),
        origin="http://other.test",
        path="/admin",
        evidence_ids=external.evidence_ids,
    )

    result = collect_deep_source_routes_from_plan(
        _manual_plan((external,), (decision,)),
        fetcher=_fake_fetcher(calls),
    )

    assert calls == []
    assert result.collected == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "cross_origin_not_allowed"


@pytest.mark.parametrize(
    "url",
    (
        "http://user:pass@example.test/admin",
        "http://example.test:bad/admin",
        "https://example.test/admin",
        "http://other.test/admin",
        "http://example.test:8080/admin",
    ),
)
def test_manual_unsafe_or_different_origin_decision_is_rejected_before_fetch(url: str) -> None:
    calls: list[str] = []
    request = _request(url, source="source_route_coverage")
    decision = DeepCollectionDecision(
        url=request.url,
        method=request.method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=("unit_test_allowed",),
        origin="unit-test",
        path="/admin",
        evidence_ids=request.evidence_ids,
    )

    result = collect_deep_source_routes_from_plan(
        _manual_plan((request,), (decision,)),
        fetcher=_fake_fetcher(calls),
    )

    assert calls == []
    assert result.collected == ()
    assert result.skipped[0].reason == "cross_origin_not_allowed"


def test_manual_explicit_default_port_decision_remains_same_origin() -> None:
    calls: list[str] = []
    request = _request("http://example.test:80/admin", source="source_route_coverage")
    decision = DeepCollectionDecision(
        url=request.url,
        method=request.method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=("unit_test_allowed",),
        origin="http://example.test",
        path="/admin",
        evidence_ids=request.evidence_ids,
    )

    result = collect_deep_source_routes_from_plan(
        _manual_plan((request,), (decision,)),
        fetcher=_fake_fetcher(calls),
    )

    assert calls == ["http://example.test:80/admin"]
    assert result.total_collected == 1


def test_fetcher_exception_and_oversized_response_are_skipped() -> None:
    failing = _request("http://example.test/login.php", source="source_route_coverage")
    oversized = _request("http://example.test/admin", source="source_route_coverage")
    bounds = replace(default_deep_collection_bounds(), max_response_bytes=5)

    def fetcher(request: DeepCollectionRequest, bounds_arg):
        assert bounds_arg.max_response_bytes == 5
        if request.url.endswith("/login.php"):
            raise RuntimeError("network failed")
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(),
            body=b"0123456789",
            elapsed_seconds=0.01,
        )

    result = collect_deep_source_routes_from_plan(
        _plan(
            (failing, oversized),
            bounds=bounds,
            allowed_origins=("http://example.test",),
        ),
        fetcher=fetcher,
    )

    assert result.collected == ()
    assert tuple(item.reason for item in result.skipped) == (
        "fetch_error",
        "response_too_large",
    )


def test_head_response_with_empty_body_is_collected_safely() -> None:
    request = _request(
        "http://example.test/server-status",
        method="HEAD",
        source="source_route_coverage",
    )

    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher([], body=b"", headers=(("server", "unit"),)),
    )

    item = result.collected[0]
    assert item.method == "HEAD"
    assert item.body_preview == ""
    assert item.body_bytes == 0
    assert item.body_sha256 == sha256(b"").hexdigest()
    assert item.headers == (("server", "unit"),)
    rendered = render_deep_source_route_collection_result_markdown(result)
    assert "Body preview:" not in rendered


def test_collected_item_has_bounded_preview_hash_headers_and_in_memory_body() -> None:
    body = ("source-body-" * 80).encode()
    request = _request(
        "http://example.test/login.php",
        source="source_route_coverage",
        evidence_ids=("EVID-1", "EVID-1", "EVID-2"),
    )

    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(
            [],
            body=body,
            headers=(("content-type", "text/html"),),
            elapsed_seconds=0.42,
        ),
    )

    item = result.collected[0]
    assert item.body == body
    assert item.body_bytes == len(body)
    assert len(item.body_preview) == 500
    assert item.body_sha256 == sha256(body).hexdigest()
    assert item.headers == (("content-type", "text/html"),)
    assert item.elapsed_seconds == 0.42
    assert item.evidence_ids == ("EVID-1", "EVID-2")


def test_human_collection_markdown_redacts_retained_set_cookie_values() -> None:
    request = _request(
        "http://example.test/session",
        source="source_route_coverage",
    )
    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(
            [],
            body=b"session response",
            headers=(
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "session_id=target-secret; Path=/; HttpOnly; SameSite=Lax"),
            ),
        ),
    )

    rendered = render_deep_source_route_collection_result_markdown(result)

    assert result.collected[0].headers[1][1].startswith("session_id=target-secret")
    assert "target-secret" not in rendered
    assert "session_id=<redacted>; Path=/; HttpOnly; SameSite=Lax" in rendered
    assert "Sensitive evidence notice" not in rendered
    assert "cookie values" not in rendered


def test_full_body_is_available_but_not_represented_or_rendered() -> None:
    secret = "FULL_BODY_SECRET_NOT_IN_PREVIEW"
    body = ("<html>" + ("A" * 600) + secret + "</html>").encode()
    request = _request("http://example.test/full", source="source_route_coverage")

    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(
            [],
            body=body,
            headers=(("content-type", "text/html"),),
        ),
    )

    item = result.collected[0]
    rendered = render_deep_source_route_collection_result_markdown(result)

    assert item.body == body
    assert secret not in item.body_preview
    assert secret not in repr(item)
    assert secret not in repr(result)
    assert secret not in rendered
    assert "body=" not in repr(item)


def test_renderer_compacts_preview_without_changing_collected_item() -> None:
    body_text = (
        "<main>\n"
        + ("alpha beta " * 25)
        + "</p>\n\n\n"
        + ("tailtoken " * 80)
    )
    body = body_text.encode("utf-8")
    request = _request("http://example.test/login.php", source="source_route_coverage")

    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher([], body=body),
    )

    item = result.collected[0]
    stored_preview = item.body_preview
    rendered = render_deep_source_route_collection_result_markdown(result)

    assert item.body_preview == stored_preview
    assert len(item.body_preview) == 500
    assert item.body_bytes == len(body)
    assert item.body_sha256 == sha256(body).hexdigest()
    assert "[preview truncated]" in rendered
    assert body_text[:500] not in rendered
    assert "alpha beta alpha beta" in rendered
    assert "tailtoken ... [preview truncated]" in rendered
    rendered_preview_line = next(
        line for line in rendered.splitlines() if "Body preview:" in line
    )
    assert len(rendered_preview_line) < len("  - Body preview: `" + stored_preview + "`")


def test_renderer_handles_replacement_characters_safely() -> None:
    request = _request("http://example.test/login.php", source="source_route_coverage")

    result = collect_deep_source_routes_from_plan(
        _plan((request,), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher([], body=b"\xff\xfeinvalid"),
    )
    rendered = render_deep_source_route_collection_result_markdown(result)

    assert "Body preview:" in rendered
    assert "invalid" in rendered


def test_collection_order_is_deterministic_and_plan_is_not_mutated() -> None:
    first = _request("http://example.test/login.php", source="source_route_coverage")
    second = _request("http://example.test/admin", source="source_route_coverage")
    plan = _plan((first, second), allowed_origins=("http://example.test",))
    before_requests = plan.proposed_requests
    before_decisions = plan.policy_summary.decisions

    result = collect_deep_source_routes_from_plan(plan, fetcher=_fake_fetcher([]))

    assert tuple(item.url for item in result.collected) == (
        "http://example.test/login.php",
        "http://example.test/admin",
    )
    assert plan.proposed_requests == before_requests
    assert plan.policy_summary.decisions == before_decisions


def test_fake_fetcher_receives_only_allowed_source_route_requests() -> None:
    calls: list[str] = []
    route = _request("http://example.test/login.php", source="source_route_coverage")
    blocked = _request("https://other.test/admin", source="source_route_coverage")
    metadata = _request("http://example.test/robots.txt", source="metadata_coverage")

    collect_deep_source_routes_from_plan(
        _plan((route, blocked, metadata), allowed_origins=("http://example.test",)),
        fetcher=_fake_fetcher(calls),
    )

    assert calls == ["http://example.test/login.php"]


def test_renderer_includes_sections_safety_wording_and_no_finding_language() -> None:
    request = _request("http://example.test/login.php", source="source_route_coverage")
    query = _request(
        "http://example.test/admin?sort=name",
        source="source_route_coverage",
    )
    decision = DeepCollectionDecision(
        url=query.url,
        method=query.method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=("unit_test_allowed",),
        origin="http://example.test",
        path="/admin",
        evidence_ids=query.evidence_ids,
    )
    plan = _manual_plan(
        (request, query),
        (
            evaluate_deep_collection_requests(
                (request,),
                allowed_origins=("http://example.test",),
            ).decisions[0],
            decision,
        ),
    )

    result = collect_deep_source_routes_from_plan(
        plan,
        fetcher=_fake_fetcher(
            [],
            body=b"<html>login</html>",
            headers=(("content-type", "text/html"),),
        ),
    )
    rendered = render_deep_source_route_collection_result_markdown(result)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Source/Route Collection Result\n")
    assert "### Summary" in rendered
    assert "### Collected Source/Route Responses" in rendered
    assert "### Skipped Requests" in rendered
    assert "### Safety Notes" in rendered
    assert "http://example.test/login.php" in rendered
    assert "Status: `200`" in rendered
    assert "Body SHA-256" in rendered
    assert "Body preview: `<html>login</html>`" in rendered
    assert "query_string_not_allowed" in rendered
    assert "|" not in rendered
    for required in (
        "This is a bounded source/route collection result.",
        "It collects only policy-allowed source_route_coverage requests.",
        "It does not submit forms.",
        "It does not authenticate.",
        "It does not brute force.",
        "It does not inject payloads.",
        "It does not execute browser JavaScript.",
        "It does not crawl.",
        "It does not collect query-string URLs.",
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


def _manual_plan(
    requests: tuple[DeepCollectionRequest, ...],
    decisions: tuple[DeepCollectionDecision, ...],
) -> DeepCollectionRequestPlan:
    return DeepCollectionRequestPlan(
        allowed_origins=("http://example.test",),
        proposed_requests=requests,
        policy_summary=DeepCollectionPolicySummary(
            bounds=default_deep_collection_bounds(),
            decisions=decisions,
            allowed_count=sum(1 for decision in decisions if decision.allowed),
            blocked_count=sum(1 for decision in decisions if not decision.allowed),
            blocked_reasons=(),
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
