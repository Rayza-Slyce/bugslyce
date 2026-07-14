"""Tests for offline Deep source/route collection review summaries."""

from __future__ import annotations

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_source_route_collection_review import (
    build_deep_source_route_collection_review,
    render_deep_source_route_collection_review_markdown,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_status_buckets_group_deterministically() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-200"),
            _collected("http://example.test/portal.php", 302, "hash-302"),
            _collected("http://example.test/server-status", 403, "hash-403"),
            _collected("http://example.test/missing", 404, "hash-404"),
            _collected("http://example.test/error", 500, "hash-500"),
            _collected("http://example.test/early", 102, "hash-102"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert tuple(bucket.name for bucket in summary.status_buckets) == (
        "2xx_success",
        "3xx_redirect",
        "403_forbidden",
        "4xx_client_error",
        "5xx_server_error",
        "other_status",
    )
    assert tuple(bucket.status_codes for bucket in summary.status_buckets) == (
        (200,),
        (302,),
        (403,),
        (404,),
        (500,),
        (102,),
    )
    assert tuple(bucket.count for bucket in summary.status_buckets) == (
        1,
        1,
        1,
        1,
        1,
        1,
    )


def test_portal_redirect_creates_redirect_login_cookie_and_auth_leads() -> None:
    result = _result(
        collected=(
            _collected(
                "http://example.test/portal.php",
                302,
                "hash-portal",
                headers=(
                    ("Location", "/login.php"),
                    ("Set-Cookie", "session=secret; HttpOnly"),
                    ("Content-Type", "text/html"),
                ),
                evidence_ids=("EVID-PORTAL",),
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}
    rendered = render_deep_source_route_collection_review_markdown(summary)

    assert "route_redirect" in categories
    assert "redirect_to_login" in categories
    assert "cookie_set_on_redirect" in categories
    assert "auth_route_response" in categories
    assert "location /login.php" in rendered
    assert "set-cookie present" in rendered
    assert "session=secret" not in rendered


def test_server_status_403_creates_forbidden_and_admin_leads() -> None:
    result = _result(
        collected=(
            _collected(
                "http://example.test/server-status",
                403,
                "hash-status",
                headers=(("Server", "Apache"),),
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}

    assert "403_forbidden" in {bucket.name for bucket in summary.status_buckets}
    assert "forbidden_admin_or_status_route" in categories
    assert "admin_status_route_response" in categories


def test_success_route_creates_route_success() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-index"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert summary.review_leads[0].category == "route_success"
    assert summary.review_leads[0].lead_id == "DEEP-SRC-REV-0001"


def test_high_signal_leads_are_ordered_before_generic_success() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-index"),
            _collected(
                "http://example.test/portal.php",
                302,
                "hash-portal",
                headers=(
                    ("Location", "/login.php"),
                    ("Set-Cookie", "session=secret; HttpOnly"),
                ),
            ),
            _collected("http://example.test/server-status", 403, "hash-status"),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = tuple(lead.category for lead in summary.review_leads)
    success_index = categories.index("route_success")

    assert categories[:7] == (
        "redirect_to_login",
        "cookie_set_on_redirect",
        "auth_route_response",
        "forbidden_admin_or_status_route",
        "admin_status_route_response",
        "route_redirect",
        "route_success",
    )
    assert all(
        categories.index(category) < success_index
        for category in (
            "redirect_to_login",
            "cookie_set_on_redirect",
            "auth_route_response",
            "forbidden_admin_or_status_route",
            "admin_status_route_response",
            "route_redirect",
        )
    )
    assert tuple(lead.lead_id for lead in summary.review_leads[:7]) == (
        "DEEP-SRC-REV-0001",
        "DEEP-SRC-REV-0002",
        "DEEP-SRC-REV-0003",
        "DEEP-SRC-REV-0004",
        "DEEP-SRC-REV-0005",
        "DEEP-SRC-REV-0006",
        "DEEP-SRC-REV-0007",
    )


def test_repeated_non_empty_body_hash_creates_signature_and_lead() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/a", 200, "same-hash"),
            _collected("http://example.test/b", 200, "same-hash"),
            _collected("http://example.test/c", 200, "other-hash"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert len(summary.body_signatures) == 1
    assert summary.body_signatures[0].body_sha256 == "same-hash"
    assert summary.body_signatures[0].count == 2
    assert summary.body_signatures[0].urls == (
        "http://example.test/a",
        "http://example.test/b",
    )
    assert "repeated_body_signature" in {
        lead.category for lead in summary.review_leads
    }


def test_empty_body_creates_lead_but_not_repeated_signature() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/redirect-a", 302, "empty-hash", body_bytes=0),
            _collected("http://example.test/redirect-b", 302, "empty-hash", body_bytes=0),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert summary.body_signatures == ()
    assert "empty_body_response" in {lead.category for lead in summary.review_leads}


def test_skip_reason_leads_and_counts_are_deterministic() -> None:
    result = _result(
        skipped=(
            _skipped("http://example.test/assets?C=N", "query_string_not_allowed"),
            _skipped("http://example.test/assets?C=M", "query_string_not_allowed"),
            _skipped("http://example.test/robots.txt", "metadata_request"),
            _skipped("https://other.test/admin", "policy_blocked"),
            _skipped("http://example.test/admin", "fetch_error"),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}
    metadata_lead = next(
        lead for lead in summary.review_leads if lead.category == "metadata_request_skipped"
    )

    assert summary.skip_reasons == (
        ("query_string_not_allowed", 2),
        ("fetch_error", 1),
        ("metadata_request", 1),
        ("policy_blocked", 1),
    )
    assert "query_string_route_skipped" in categories
    assert "metadata_request_skipped" in categories
    assert "policy_blocked_skipped" in categories
    assert "fetch_error_skipped" in categories
    assert "metadata is handled by the Deep metadata collection path" in metadata_lead.reason


def test_renderer_sections_compact_urls_safety_and_no_full_body() -> None:
    result = _result(
        collected=tuple(
            _collected(
                f"http://example.test/route-{index}",
                200,
                f"hash-{index}",
                body_preview="FULL_BODY_CONTENT_SHOULD_NOT_RENDER",
            )
            for index in range(8)
        ),
        skipped=(_skipped("http://example.test/assets?C=N", "query_string_not_allowed"),),
    )
    summary = build_deep_source_route_collection_review(result)

    rendered = render_deep_source_route_collection_review_markdown(summary)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Source/Route Collection Review\n")
    assert "### Summary" in rendered
    assert "### Status Buckets" in rendered
    assert "### Review Leads" in rendered
    assert "### Repeated Body Signatures" in rendered
    assert "### Skip Reasons" in rendered
    assert "### Safety Notes" in rendered
    assert "... 2 more" in rendered
    assert "FULL_BODY_CONTENT_SHOULD_NOT_RENDER" not in rendered
    assert "|" not in rendered
    for required in (
        "Offline review only.",
        "No network requests were made by this review.",
        "No crawling was performed.",
        "No forms were submitted.",
        "No authentication was attempted.",
        "No payloads were injected.",
        "Deep Recon full mode was not enabled.",
    ):
        assert required in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit",
        "confirmed exposure",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
    ):
        assert forbidden not in lowered


def test_input_result_is_not_mutated() -> None:
    result = _result(
        collected=(_collected("http://example.test/index.html", 200, "hash-index"),),
        skipped=(_skipped("http://example.test/robots.txt", "metadata_request"),),
    )
    before = result

    build_deep_source_route_collection_review(result)

    assert result == before


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _result(
    *,
    collected: tuple[DeepSourceRouteCollectedItem, ...] = (),
    skipped: tuple[DeepSourceRouteSkippedItem, ...] = (),
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=collected,
        skipped=skipped,
        total_considered=len(collected) + len(skipped),
        total_collected=len(collected),
        total_skipped=len(skipped),
    )


def _collected(
    url: str,
    status_code: int,
    body_sha256: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body_bytes: int = 128,
    body_preview: str = "preview",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=url,
        headers=headers,
        body_preview=body_preview,
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="unit-test",
        evidence_ids=evidence_ids,
    )


def _skipped(
    url: str,
    reason: str,
    *,
    source: str = "source_route_coverage",
    evidence_ids: tuple[str, ...] = ("EVID-SKIP",),
) -> DeepSourceRouteSkippedItem:
    return DeepSourceRouteSkippedItem(
        url=url,
        method="GET",
        reason=reason,
        source=source,
        evidence_ids=evidence_ids,
    )
