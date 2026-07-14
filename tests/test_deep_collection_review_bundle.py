"""Tests for offline Deep post-collection review bundles."""

from __future__ import annotations

import inspect

import pytest

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_review_bundle import (
    DeepCollectionReviewSummaryCounts,
    MAX_PRIORITIES,
    build_deep_collection_review_bundle,
    render_deep_collection_review_bundle_markdown,
)
from bugslyce.recon.deep_metadata_collection_review import (
    DeepMetadataCollectionReviewLead,
    DeepMetadataCollectionReviewSummary,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
    DeepSourceRouteReviewLead,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_summaries_produce_safe_empty_bundle() -> None:
    bundle = build_deep_collection_review_bundle(
        _empty_metadata_summary(),
        _empty_source_summary(),
    )
    rendered = render_deep_collection_review_bundle_markdown(bundle)

    assert bundle.priorities == ()
    assert bundle.summary_counts == DeepCollectionReviewSummaryCounts(
        metadata_responses_collected=0,
        metadata_requests_skipped=0,
        metadata_review_leads=0,
        source_route_responses_collected=0,
        source_route_requests_skipped=0,
        source_route_review_leads=0,
        generated_unified_priorities=0,
    )
    assert rendered.startswith("## Deep Collection Review Bundle\n")
    assert "### Summary" in rendered
    assert "### Unified Review Priorities" in rendered
    assert "### Review Source Overview" in rendered
    assert "### Safety Notes" in rendered
    assert "No unified review priorities were generated." in rendered
    assert "No network requests were made by this bundle." in rendered
    assert "Deep Recon full mode was not enabled." in rendered


def test_bundle_retains_original_summaries_and_counts() -> None:
    metadata = _metadata_summary(
        total_collected=2,
        total_skipped=1,
        leads=(
            _metadata_lead("metadata_found", ("http://example.test/robots.txt",)),
        ),
    )
    source = _source_summary(
        total_collected=3,
        total_skipped=2,
        leads=(
            _source_lead("route_success", ("http://example.test/index.html",)),
            _source_lead("query_string_route_skipped", ("http://example.test/a?C=N",)),
        ),
    )

    bundle = build_deep_collection_review_bundle(metadata, source)

    assert bundle.metadata_review is metadata
    assert bundle.source_route_review is source
    assert bundle.summary_counts.metadata_responses_collected == 2
    assert bundle.summary_counts.metadata_requests_skipped == 1
    assert bundle.summary_counts.metadata_review_leads == 1
    assert bundle.summary_counts.source_route_responses_collected == 3
    assert bundle.summary_counts.source_route_requests_skipped == 2
    assert bundle.summary_counts.source_route_review_leads == 2
    assert bundle.summary_counts.generated_unified_priorities == 3


def test_summary_counts_are_frozen() -> None:
    bundle = build_deep_collection_review_bundle(
        _empty_metadata_summary(),
        _empty_source_summary(),
    )

    with pytest.raises(Exception, match="cannot assign to field"):
        bundle.summary_counts.metadata_responses_collected = 99


def test_priorities_are_deterministic_and_ids_assigned_after_sorting() -> None:
    metadata = _metadata_summary(
        leads=(
            _metadata_lead("metadata_found", ("http://example.test/robots.txt",)),
            _metadata_lead("metadata_redirect", ("http://example.test/security.txt",)),
        )
    )
    source = _source_summary(
        leads=(
            _source_lead("route_success", ("http://example.test/index.html",)),
            _source_lead(
                "redirect_to_login",
                ("http://example.test/portal.php",),
                signals=("location /login.php",),
            ),
            _source_lead(
                "cookie_set_on_redirect",
                ("http://example.test/portal.php",),
                signals=("set-cookie present",),
            ),
            _source_lead(
                "forbidden_admin_or_status_route",
                ("http://example.test/server-status",),
            ),
        )
    )

    first = build_deep_collection_review_bundle(metadata, source)
    second = build_deep_collection_review_bundle(metadata, source)
    categories = tuple(priority.category for priority in first.priorities)

    assert first == second
    assert categories == (
        "redirect_to_login",
        "cookie_set_on_redirect",
        "forbidden_admin_or_status_route",
        "metadata_found",
        "metadata_redirect",
        "route_success",
    )
    assert tuple(priority.priority_id for priority in first.priorities) == (
        "DEEP-COLL-REV-0001",
        "DEEP-COLL-REV-0002",
        "DEEP-COLL-REV-0003",
        "DEEP-COLL-REV-0004",
        "DEEP-COLL-REV-0005",
        "DEEP-COLL-REV-0006",
    )


def test_informational_skip_context_appears_after_stronger_signals() -> None:
    bundle = build_deep_collection_review_bundle(
        _metadata_summary(
            leads=(
                _metadata_lead("metadata_missing", ("http://example.test/humans.txt",)),
                _metadata_lead("metadata_skipped_policy", ("https://other.test/robots.txt",)),
            )
        ),
        _source_summary(
            leads=(
                _source_lead("route_success", ("http://example.test/index.html",)),
                _source_lead("metadata_request_skipped", ("http://example.test/robots.txt",)),
                _source_lead("query_string_route_skipped", ("http://example.test/a?C=N",)),
                _source_lead("admin_status_route_response", ("http://example.test/server-status",)),
            )
        ),
    )
    categories = tuple(priority.category for priority in bundle.priorities)

    assert categories.index("admin_status_route_response") < categories.index("route_success")
    assert categories.index("route_success") < categories.index("metadata_missing")
    assert categories.index("metadata_missing") < categories.index("metadata_skipped_policy")
    assert categories.index("query_string_route_skipped") < categories.index("metadata_request_skipped")


def test_priority_list_is_bounded() -> None:
    source = _source_summary(
        leads=tuple(
            _source_lead("route_success", (f"http://example.test/route-{index}",))
            for index in range(MAX_PRIORITIES + 5)
        )
    )

    bundle = build_deep_collection_review_bundle(_empty_metadata_summary(), source)

    assert len(bundle.priorities) == MAX_PRIORITIES
    assert bundle.summary_counts.generated_unified_priorities == MAX_PRIORITIES


def test_duplicate_priorities_merge_evidence_and_signals() -> None:
    source = _source_summary(
        leads=(
            _source_lead(
                "redirect_to_login",
                ("http://example.test/portal.php",),
                evidence_ids=("EVID-1",),
                signals=("location /login.php",),
                title="First title",
            ),
            _source_lead(
                "redirect_to_login",
                ("http://example.test/portal.php",),
                evidence_ids=("EVID-1", "EVID-2"),
                signals=("location /login.php", "status 302"),
                title="Second title",
            ),
        )
    )

    bundle = build_deep_collection_review_bundle(_empty_metadata_summary(), source)

    assert len(bundle.priorities) == 1
    priority = bundle.priorities[0]
    assert priority.title == "First title"
    assert priority.related_evidence_ids == ("EVID-1", "EVID-2")
    assert priority.signals == ("location /login.php", "status 302")


def test_duplicate_priorities_use_url_set_but_preserve_first_seen_url_order() -> None:
    first_urls = ("https://example.test/a", "https://example.test/b")
    second_urls = ("https://example.test/b", "https://example.test/a")
    source = _source_summary(
        leads=(
            _source_lead(
                "redirect_to_login",
                first_urls,
                evidence_ids=("EVID-1",),
                signals=("location /login.php",),
                title="First title",
            ),
            _source_lead(
                "redirect_to_login",
                second_urls,
                evidence_ids=("EVID-2",),
                signals=("status 302",),
                title="Second title",
            ),
        )
    )

    bundle = build_deep_collection_review_bundle(_empty_metadata_summary(), source)

    assert len(bundle.priorities) == 1
    priority = bundle.priorities[0]
    assert priority.title == "First title"
    assert priority.related_urls == first_urls
    assert priority.related_evidence_ids == ("EVID-1", "EVID-2")
    assert priority.signals == ("location /login.php", "status 302")


def test_distinct_categories_for_same_url_are_preserved() -> None:
    source = _source_summary(
        leads=(
            _source_lead("redirect_to_login", ("http://example.test/portal.php",)),
            _source_lead("cookie_set_on_redirect", ("http://example.test/portal.php",)),
        )
    )

    bundle = build_deep_collection_review_bundle(_empty_metadata_summary(), source)

    assert tuple(priority.category for priority in bundle.priorities) == (
        "redirect_to_login",
        "cookie_set_on_redirect",
    )


def test_partial_inputs_generate_priorities_from_available_summary_only() -> None:
    metadata_only = build_deep_collection_review_bundle(
        _metadata_summary(
            leads=(
                _metadata_lead("metadata_found", ("http://example.test/robots.txt",)),
            )
        ),
        _empty_source_summary(),
    )
    source_only = build_deep_collection_review_bundle(
        _empty_metadata_summary(),
        _source_summary(
            leads=(
                _source_lead("route_success", ("http://example.test/index.html",)),
            )
        ),
    )

    assert tuple(priority.category for priority in metadata_only.priorities) == (
        "metadata_found",
    )
    assert tuple(priority.category for priority in source_only.priorities) == (
        "route_success",
    )


def test_renderer_compacts_long_values_and_uses_review_only_language() -> None:
    source = _source_summary(
        leads=(
            _source_lead(
                "redirect_to_login",
                tuple(f"http://example.test/route-{index}" for index in range(8)),
                evidence_ids=tuple(f"EVID-{index}" for index in range(8)),
                signals=tuple(f"signal-{index}" for index in range(8)),
            ),
        )
    )
    bundle = build_deep_collection_review_bundle(_empty_metadata_summary(), source)

    rendered = render_deep_collection_review_bundle_markdown(bundle)
    lowered = rendered.lower()

    assert "### Summary" in rendered
    assert "### Unified Review Priorities" in rendered
    assert "### Review Source Overview" in rendered
    assert "### Safety Notes" in rendered
    assert "... +2 more" in rendered
    assert "Review-only priority; not a confirmed finding." in rendered
    assert "This bundle combines existing offline Deep collection review summaries." in rendered
    assert "No collection or network activity is performed by the bundle." in rendered
    assert "No network requests were made by this bundle." in rendered
    assert "Deep Recon full mode was not enabled." in rendered
    assert "|" not in rendered
    for forbidden in (
        "confirmed vulnerability",
        "confirmed exposure",
        "credentials found",
        "password found",
        "login bypass",
        "exploitable",
        "attack this route",
        "fetch this url",
        "no vulnerabilities found",
    ):
        assert forbidden not in lowered


def test_builder_and_renderer_do_not_use_file_or_network_io() -> None:
    import bugslyce.recon.deep_collection_review_bundle as module

    source = inspect.getsource(module)

    for forbidden in (
        "open(",
        "read_text",
        "write_text",
        "requests.",
        "httpx.",
        "socket.",
        "urllib",
        "subprocess",
        "os.system",
    ):
        assert forbidden not in source


def test_existing_review_objects_are_not_mutated() -> None:
    metadata = _metadata_summary(
        leads=(
            _metadata_lead("metadata_found", ("http://example.test/robots.txt",)),
        )
    )
    source = _source_summary(
        leads=(
            _source_lead("redirect_to_login", ("http://example.test/portal.php",)),
        )
    )
    before = (metadata, source)

    bundle = build_deep_collection_review_bundle(metadata, source)
    render_deep_collection_review_bundle_markdown(bundle)

    assert (metadata, source) == before


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _empty_metadata_summary() -> DeepMetadataCollectionReviewSummary:
    return _metadata_summary()


def _metadata_summary(
    *,
    total_collected: int = 0,
    total_skipped: int = 0,
    leads: tuple[DeepMetadataCollectionReviewLead, ...] = (),
) -> DeepMetadataCollectionReviewSummary:
    return DeepMetadataCollectionReviewSummary(
        total_collected=total_collected,
        total_skipped=total_skipped,
        status_buckets=(),
        duplicate_body_signatures=(),
        leads=leads,
        skip_reasons=(),
    )


def _metadata_lead(
    category: str,
    urls: tuple[str, ...],
    *,
    evidence_ids: tuple[str, ...] = ("EVID-META",),
    severity: str = "review",
    body_sha256: str | None = None,
) -> DeepMetadataCollectionReviewLead:
    return DeepMetadataCollectionReviewLead(
        category=category,
        severity=severity,
        title=f"Metadata lead {category}",
        detail=f"Metadata detail for {category}.",
        urls=urls,
        evidence_ids=evidence_ids,
        body_sha256=body_sha256,
    )


def _empty_source_summary() -> DeepSourceRouteCollectionReviewSummary:
    return _source_summary()


def _source_summary(
    *,
    total_collected: int = 0,
    total_skipped: int = 0,
    leads: tuple[DeepSourceRouteReviewLead, ...] = (),
) -> DeepSourceRouteCollectionReviewSummary:
    return DeepSourceRouteCollectionReviewSummary(
        total_collected=total_collected,
        total_skipped=total_skipped,
        status_buckets=(),
        body_signatures=(),
        skip_reasons=(),
        review_leads=leads,
        safety_notes=(),
    )


def _source_lead(
    category: str,
    urls: tuple[str, ...],
    *,
    evidence_ids: tuple[str, ...] = ("EVID-SRC",),
    signals: tuple[str, ...] = (),
    title: str | None = None,
) -> DeepSourceRouteReviewLead:
    return DeepSourceRouteReviewLead(
        lead_id="DEEP-SRC-REV-9999",
        category=category,
        title=title or f"Source lead {category}",
        urls=urls,
        evidence_ids=evidence_ids,
        reason=f"Source detail for {category}.",
        signals=signals,
    )
