"""Tests for offline Deep metadata collection review summaries."""

from __future__ import annotations

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_metadata_collection_review import (
    build_deep_metadata_collection_review,
    render_deep_metadata_collection_review_markdown,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
    DeepMetadataSkippedItem,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_result_renders_cleanly() -> None:
    summary = build_deep_metadata_collection_review(
        DeepMetadataCollectionResult(
            collected=(),
            skipped=(),
            total_considered=0,
            total_collected=0,
            total_skipped=0,
        )
    )
    rendered = render_deep_metadata_collection_review_markdown(summary)

    assert summary.total_collected == 0
    assert summary.total_skipped == 0
    assert summary.status_buckets == ()
    assert summary.duplicate_body_signatures == ()
    assert summary.leads == ()
    assert summary.skip_reasons == ()
    assert rendered.startswith("## Deep Metadata Collection Review")
    assert "- Metadata responses collected: 0" in rendered
    assert rendered.count("- None.") >= 4
    assert "No HTTP requests were made by this review." in rendered
    assert "No files were written by this review." in rendered
    assert "This stage produces static manual-review context only." in rendered


def test_status_buckets_group_deterministically() -> None:
    result = DeepMetadataCollectionResult(
        collected=(
            _collected("http://example.test/other", 102, "h-other"),
            _collected("http://example.test/missing", 404, "h-404"),
            _collected("http://example.test/robots.txt", 200, "h-200"),
            _collected("http://example.test/redirect", 302, "h-302"),
            _collected("http://example.test/error", 503, "h-503"),
        ),
        skipped=(),
        total_considered=5,
        total_collected=5,
        total_skipped=0,
    )

    summary = build_deep_metadata_collection_review(result)

    assert tuple(bucket.status_group for bucket in summary.status_buckets) == (
        "2xx_success",
        "3xx_redirect",
        "4xx_client_error",
        "5xx_server_error",
        "other_status",
    )
    assert tuple(bucket.count for bucket in summary.status_buckets) == (1, 1, 1, 1, 1)
    assert summary.status_buckets[0].urls == ("http://example.test/robots.txt",)


def test_duplicate_body_signatures_and_repeated_404_leads_are_concise() -> None:
    result = DeepMetadataCollectionResult(
        collected=(
            _collected(
                "http://example.test/security.txt",
                404,
                "same-404",
                preview="default not found page",
                evidence_ids=("EVID-1",),
            ),
            _collected(
                "http://example.test/humans.txt",
                404,
                "same-404",
                preview="default not found page",
                evidence_ids=("EVID-2",),
            ),
            _collected(
                "http://example.test/favicon.ico",
                404,
                "same-404",
                preview="default not found page",
                evidence_ids=("EVID-3",),
            ),
            _collected(
                "http://example.test/robots.txt",
                200,
                "robots-hash",
                preview="User-agent: *",
                evidence_ids=("EVID-4",),
            ),
        ),
        skipped=(),
        total_considered=4,
        total_collected=4,
        total_skipped=0,
    )

    summary = build_deep_metadata_collection_review(result)
    rendered = render_deep_metadata_collection_review_markdown(summary)

    assert len(summary.duplicate_body_signatures) == 1
    signature = summary.duplicate_body_signatures[0]
    assert signature.body_sha256 == "same-404"
    assert signature.count == 3
    assert signature.status_codes == (404,)
    assert signature.urls == (
        "http://example.test/security.txt",
        "http://example.test/humans.txt",
        "http://example.test/favicon.ico",
    )
    categories = tuple(lead.category for lead in summary.leads)
    assert "metadata_missing" in categories
    assert "metadata_repeated_body" in categories
    repeated = next(lead for lead in summary.leads if lead.category == "metadata_repeated_body")
    assert repeated.body_sha256 == "same-404"
    assert repeated.evidence_ids == ("EVID-1", "EVID-2", "EVID-3")
    assert "Multiple metadata endpoints returned the same body" in rendered
    assert "default not found page" in rendered
    assert "full body" not in rendered.lower()


def test_404_and_non_404_client_errors_get_distinct_leads() -> None:
    result = DeepMetadataCollectionResult(
        collected=(
            _collected(
                "http://example.test/security.txt",
                404,
                "h-404",
                evidence_ids=("EVID-404",),
            ),
            _collected(
                "http://example.test/.well-known/security.txt",
                403,
                "h-403",
                evidence_ids=("EVID-403",),
            ),
            _collected(
                "http://example.test/humans.txt",
                401,
                "h-401",
                evidence_ids=("EVID-401",),
            ),
        ),
        skipped=(),
        total_considered=3,
        total_collected=3,
        total_skipped=0,
    )

    summary = build_deep_metadata_collection_review(result)

    assert tuple(bucket.status_group for bucket in summary.status_buckets) == (
        "4xx_client_error",
    )
    assert summary.status_buckets[0].count == 3
    missing = next(lead for lead in summary.leads if lead.category == "metadata_missing")
    client_error = next(
        lead for lead in summary.leads if lead.category == "metadata_client_error"
    )
    assert missing.severity == "info"
    assert missing.title == "Metadata endpoint returned not found"
    assert missing.urls == ("http://example.test/security.txt",)
    assert missing.evidence_ids == ("EVID-404",)
    assert client_error.severity == "review"
    assert client_error.title == "Metadata endpoint returned a client-error response"
    assert "not found" not in client_error.title.lower()
    assert client_error.urls == (
        "http://example.test/.well-known/security.txt",
        "http://example.test/humans.txt",
    )
    assert client_error.evidence_ids == ("EVID-403", "EVID-401")


def test_skip_reason_leads_and_counts_are_deterministic() -> None:
    result = DeepMetadataCollectionResult(
        collected=(),
        skipped=(
            _skipped("http://example.test/login.php", "non_metadata_request", ("EVID-R1",)),
            _skipped("http://example.test/admin", "non_metadata_request", ("EVID-R2",)),
            _skipped("http://example.test/search?q=1", "policy_blocked", ("EVID-P1",)),
            _skipped("http://example.test/fail", "fetch_error", ("EVID-F1",)),
        ),
        total_considered=4,
        total_collected=0,
        total_skipped=4,
    )

    summary = build_deep_metadata_collection_review(result)

    assert summary.skip_reasons == (
        ("non_metadata_request", 2),
        ("fetch_error", 1),
        ("policy_blocked", 1),
    )
    categories = tuple(lead.category for lead in summary.leads)
    assert "metadata_skipped_policy" in categories
    assert "metadata_skipped_non_metadata" in categories
    non_metadata = next(
        lead for lead in summary.leads if lead.category == "metadata_skipped_non_metadata"
    )
    assert non_metadata.urls == (
        "http://example.test/login.php",
        "http://example.test/admin",
    )
    assert non_metadata.evidence_ids == ("EVID-R1", "EVID-R2")


def test_renderer_compacts_long_url_lists_and_avoids_finding_language() -> None:
    result = DeepMetadataCollectionResult(
        collected=tuple(
            _collected(f"http://example.test/metadata-{index}.txt", 200, f"h-{index}")
            for index in range(8)
        ),
        skipped=(),
        total_considered=8,
        total_collected=8,
        total_skipped=0,
    )

    summary = build_deep_metadata_collection_review(result)
    rendered = render_deep_metadata_collection_review_markdown(summary)
    lowered = rendered.lower()

    assert "### Summary" in rendered
    assert "### Status Buckets" in rendered
    assert "### Review Leads" in rendered
    assert "### Duplicate Body Signatures" in rendered
    assert "### Skip Reasons" in rendered
    assert "### Safety Notes" in rendered
    assert "... 2 more" in rendered
    assert "|" not in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit",
        "confirmed exposure",
        "credentials found",
        "password found",
    ):
        assert forbidden not in lowered


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _collected(
    url: str,
    status_code: int,
    body_sha256: str,
    *,
    preview: str = "preview",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepMetadataCollectedItem:
    return DeepMetadataCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=url,
        headers=(("content-type", "text/plain"),),
        body_preview=preview,
        body_sha256=body_sha256,
        body_bytes=len(preview.encode("utf-8")),
        elapsed_seconds=0.01,
        source="metadata_coverage",
        reason="planned_uncollected_metadata",
        evidence_ids=evidence_ids,
    )


def _skipped(
    url: str,
    reason: str,
    evidence_ids: tuple[str, ...],
) -> DeepMetadataSkippedItem:
    return DeepMetadataSkippedItem(
        url=url,
        method="GET",
        reason=reason,
        source="metadata_coverage",
        evidence_ids=evidence_ids,
    )
