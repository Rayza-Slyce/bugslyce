"""Tests for offline post-follow-up JavaScript route extraction."""

from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import inspect

from bugslyce.recon.deep_post_followup_javascript_route_extraction import (
    build_deep_post_followup_javascript_route_extraction,
    render_deep_post_followup_javascript_route_extraction_markdown,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)


def test_retained_shallow_javascript_surfaces_late_only_route_with_provenance() -> None:
    body = b'const route = "/api/late-only";'
    item = _item(
        request_id="DEEP-SHALLOW-REQ-0007",
        url="https://example.test/app.js",
        body=body,
        source_route_candidate_ids=("DEEP-JS-ROUTE-0003",),
        evidence_ids=("EVID-SHALLOW-0007",),
    )

    result = build_deep_post_followup_javascript_route_extraction(_result(item))

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.candidate_id == "DEEP-JS-POST-ROUTE-0001"
    assert candidate.safe_candidate == "/api/late-only"
    assert candidate.safe_resolved_url == "https://example.test/api/late-only"
    assert candidate.shallow_request_ids == ("DEEP-SHALLOW-REQ-0007",)
    assert candidate.upstream_route_candidate_ids == ("DEEP-JS-ROUTE-0003",)
    assert candidate.safe_requested_urls == ("https://example.test/app.js",)
    assert candidate.safe_final_urls == ("https://example.test/app.js",)
    assert candidate.source_body_sha256s == (hashlib.sha256(body).hexdigest(),)
    assert candidate.evidence_ids == ("EVID-SHALLOW-0007",)
    assert candidate.source_model_kinds == ("javascript_route",)


def test_full_retained_body_is_analysed_beyond_preview() -> None:
    body = (b"const padding = '" + (b"x" * 700) + b"'; const route = '/api/beyond-preview';")
    item = _item(
        url="https://example.test/assets/full.js",
        body=body,
        body_preview=body[:500].decode(),
    )

    result = build_deep_post_followup_javascript_route_extraction(_result(item))

    assert tuple(candidate.path for candidate in result.candidates) == (
        "/api/beyond-preview",
    )


def test_non_javascript_response_is_skipped_even_when_route_text_is_present() -> None:
    item = _item(
        url="https://example.test/image.txt",
        headers=(("Content-Type", "image/svg+xml"),),
        body=b'const route = "/must-not-be-imported";',
    )

    result = build_deep_post_followup_javascript_route_extraction(_result(item))

    assert result.candidates == ()
    assert result.summary_counts.javascript_responses_scanned == 0
    assert result.summary_counts.non_javascript_responses_skipped == 1


def test_reversed_shallow_input_is_fully_deterministic() -> None:
    first = _item(
        request_id="DEEP-SHALLOW-REQ-0002",
        url="https://example.test/b.js",
        body=b'{ const route = "/shared"; } { const route = "/b"; }',
        source_route_candidate_ids=("DEEP-JS-ROUTE-0002",),
        evidence_ids=("EVID-B",),
    )
    second = _item(
        request_id="DEEP-SHALLOW-REQ-0001",
        url="https://example.test/a.js",
        body=b'{ const route = "/shared"; } { const route = "/a"; }',
        source_route_candidate_ids=("DEEP-JS-ROUTE-0001",),
        evidence_ids=("EVID-A",),
    )

    normal = build_deep_post_followup_javascript_route_extraction(_result(first, second))
    reversed_result = build_deep_post_followup_javascript_route_extraction(_result(second, first))

    assert reversed_result == normal
    assert render_deep_post_followup_javascript_route_extraction_markdown(reversed_result) == (
        render_deep_post_followup_javascript_route_extraction_markdown(normal)
    )
    assert tuple(candidate.candidate_id for candidate in normal.candidates) == (
        "DEEP-JS-POST-ROUTE-0001",
        "DEEP-JS-POST-ROUTE-0002",
        "DEEP-JS-POST-ROUTE-0003",
    )


def test_same_semantic_candidate_aggregates_all_shallow_provenance() -> None:
    first = _item(
        request_id="DEEP-SHALLOW-REQ-0001",
        url="https://example.test/a.js",
        body=b'const route = "/api/shared";',
        source_route_candidate_ids=("DEEP-JS-ROUTE-0001",),
        evidence_ids=("EVID-A",),
    )
    second = _item(
        request_id="DEEP-SHALLOW-REQ-0002",
        url="https://example.test/b.js",
        body=b'const route = "https://example.test/api/shared";',
        source_route_candidate_ids=("DEEP-JS-ROUTE-0002",),
        evidence_ids=("EVID-B",),
    )

    result = build_deep_post_followup_javascript_route_extraction(_result(first, second))

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.safe_resolved_url == "https://example.test/api/shared"
    assert candidate.observed_safe_candidates == (
        "/api/shared",
        "https://example.test/api/shared",
    )
    assert candidate.shallow_request_ids == (
        "DEEP-SHALLOW-REQ-0001",
        "DEEP-SHALLOW-REQ-0002",
    )
    assert candidate.upstream_route_candidate_ids == (
        "DEEP-JS-ROUTE-0001",
        "DEEP-JS-ROUTE-0002",
    )
    assert candidate.evidence_ids == ("EVID-A", "EVID-B")
    assert candidate.occurrence_count == 2
    assert len(candidate.source_observations) == 2
    assert result.summary_counts.duplicate_candidate_occurrences_aggregated == 1


def test_aggregated_candidate_preserves_relational_source_observations() -> None:
    first = replace(
        _item(
            request_id="DEEP-SHALLOW-REQ-A",
            url="https://example.test/a.js",
            body=b'const route = "/api/shared"; // source A',
            source_route_candidate_ids=("DEEP-JS-ROUTE-A",),
            evidence_ids=("EVID-A",),
        ),
        final_url="https://example.test/a-v2.js",
    )
    second = _item(
        request_id="DEEP-SHALLOW-REQ-B",
        url="https://example.test/b.js",
        body=b'const route = "/api/shared"; // source B',
        source_route_candidate_ids=("DEEP-JS-ROUTE-B",),
        evidence_ids=("EVID-B",),
    )

    result = build_deep_post_followup_javascript_route_extraction(
        _result(first, second)
    )

    assert len(result.candidates) == 1
    observations = result.candidates[0].source_observations
    assert len(observations) == 2
    assert observations[0].shallow_request_id == "DEEP-SHALLOW-REQ-A"
    assert observations[0].upstream_route_candidate_ids == ("DEEP-JS-ROUTE-A",)
    assert observations[0].safe_requested_url == "https://example.test/a.js"
    assert observations[0].safe_final_url == "https://example.test/a-v2.js"
    assert observations[0].source_body_sha256 == hashlib.sha256(first.body).hexdigest()
    assert observations[0].evidence_ids == ("EVID-A",)
    assert observations[1].shallow_request_id == "DEEP-SHALLOW-REQ-B"
    assert observations[1].upstream_route_candidate_ids == ("DEEP-JS-ROUTE-B",)
    assert observations[1].safe_requested_url == "https://example.test/b.js"
    assert observations[1].safe_final_url == "https://example.test/b.js"
    assert observations[1].source_body_sha256 == hashlib.sha256(second.body).hexdigest()
    assert observations[1].evidence_ids == ("EVID-B",)
    rendered = render_deep_post_followup_javascript_route_extraction_markdown(result)
    first_source = rendered.index("Source observation 1")
    second_source = rendered.index("Source observation 2")
    assert "DEEP-SHALLOW-REQ-A" in rendered[first_source:second_source]
    assert "DEEP-JS-ROUTE-A" in rendered[first_source:second_source]
    assert "EVID-A" in rendered[first_source:second_source]
    assert "DEEP-SHALLOW-REQ-B" not in rendered[first_source:second_source]
    assert "DEEP-SHALLOW-REQ-B" in rendered[second_source:]
    assert "DEEP-JS-ROUTE-B" in rendered[second_source:]
    assert "EVID-B" in rendered[second_source:]


def test_identical_body_at_same_host_document_paths_keeps_resolution_distinct() -> None:
    body = b'const route = "?view=detail";'
    first = _item(
        request_id="DEEP-SHALLOW-REQ-0001",
        url="https://example.test/js/app.js",
        body=body,
    )
    second = _item(
        request_id="DEEP-SHALLOW-REQ-0002",
        url="https://example.test/assets/app.js",
        body=body,
    )

    result = build_deep_post_followup_javascript_route_extraction(_result(first, second))

    assert tuple(candidate.safe_resolved_url for candidate in result.candidates) == (
        "https://example.test/assets/app.js?view",
        "https://example.test/js/app.js?view",
    )
    assert tuple(
        candidate.source_observations[0].safe_final_url
        for candidate in result.candidates
    ) == (
        "https://example.test/assets/app.js",
        "https://example.test/js/app.js",
    )
    assert all(
        candidate.source_observations[0].source_body_sha256
        == hashlib.sha256(body).hexdigest()
        for candidate in result.candidates
    )
    assert all(
        candidate.source_observations[0].resolution_contexts
        == ("javascript_source_origin",)
        for candidate in result.candidates
    )


def test_exact_duplicate_source_observation_is_deduplicated_by_complete_chain() -> None:
    item = _item(
        url="https://example.test/app.js",
        body=b'const route = "/api/duplicate";',
    )

    result = build_deep_post_followup_javascript_route_extraction(
        _result(item, item)
    )

    assert len(result.candidates) == 1
    assert len(result.candidates[0].source_observations) == 1
    assert result.candidates[0].occurrence_count == 1


def test_builder_has_one_offline_input_and_no_network_or_planning_surface() -> None:
    signature = inspect.signature(build_deep_post_followup_javascript_route_extraction)

    assert tuple(signature.parameters) == ("shallow_followups",)
    candidate_field_names = {
        field.name
        for field in fields(
            build_deep_post_followup_javascript_route_extraction(_result()).__class__
        )
    }
    assert candidate_field_names == {"candidates", "summary_counts", "safety_notes"}


def _result(
    *items: DeepShallowRouteFollowupCollectedItem,
) -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=tuple(items),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=len(items),
            responses_collected=len(items),
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=("fixture",),
    )


def _item(
    *,
    request_id: str = "DEEP-SHALLOW-REQ-0001",
    url: str,
    body: bytes,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/javascript"),),
    body_preview: str = "",
    source_route_candidate_ids: tuple[str, ...] = ("DEEP-JS-ROUTE-0001",),
    evidence_ids: tuple[str, ...] = ("EVID-SHALLOW-0001",),
) -> DeepShallowRouteFollowupCollectedItem:
    return DeepShallowRouteFollowupCollectedItem(
        request_id=request_id,
        requested_url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=headers,
        body_preview=body_preview or body[:500].decode("utf-8", errors="replace"),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source_model_kinds=("javascript_route",),
        source_route_candidate_ids=source_route_candidate_ids,
        query_parameter_names=(),
        evidence_ids=evidence_ids,
        interpretation="Collected by the bounded shallow follow-up fixture.",
        body=body,
    )
