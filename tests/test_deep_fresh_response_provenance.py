"""RED contracts for provenance owned by successful Deep HTTP collection."""

from __future__ import annotations

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionRequest,
    evaluate_deep_collection_requests,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult,
    DeepHtmlRouteExtractionSummaryCounts,
    DeepHtmlRouteReference,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteExtractionResult,
    DeepJavaScriptRouteExtractionSummaryCounts,
)
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.deep_shallow_route_followup import (
    build_deep_shallow_route_followup_plan,
    collect_deep_shallow_route_followups,
)
from bugslyce.recon.deep_source_route_collector import (
    collect_deep_source_routes_from_plan,
)
from bugslyce.recon.http_enforcement import HTTPTransportFailure


def test_successful_source_route_response_without_antecedent_evidence_gains_collection_provenance() -> None:
    request = _source_route_request(evidence_ids=())
    plan = _source_route_plan(request)

    assert plan.policy_summary.decisions[0].allowed is True
    result = collect_deep_source_routes_from_plan(
        plan,
        fetcher=lambda item, _bounds: _response(item.url),
    )

    assert request.evidence_ids == ()
    assert len(result.collected) == 1
    assert result.collected[0].evidence_ids


def test_source_route_collection_retains_nonempty_antecedent_evidence() -> None:
    request = _source_route_request(evidence_ids=("EVID-ANTECEDENT",))

    result = collect_deep_source_routes_from_plan(
        _source_route_plan(request),
        fetcher=lambda item, _bounds: _response(item.url),
    )

    assert result.collected[0].evidence_ids.count("EVID-ANTECEDENT") == 1


def test_source_route_transport_failure_does_not_create_successful_response_provenance() -> None:
    request = _source_route_request(evidence_ids=())

    def failing_fetcher(_request, _bounds):
        raise HTTPTransportFailure("dns_error")

    result = collect_deep_source_routes_from_plan(
        _source_route_plan(request),
        fetcher=failing_fetcher,
    )

    assert result.collected == ()
    assert result.skipped[0].reason == "fetch_error:dns_error"
    assert result.skipped[0].evidence_ids == ()


def test_successful_shallow_followup_without_antecedent_evidence_gains_collection_provenance() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result_with_evidence(()),
        _empty_javascript_result(),
    )

    assert len(plan.requests) == 1
    assert plan.requests[0].source_request_urls == ("https://example.test/index",)
    assert plan.requests[0].evidence_ids == ()
    result = collect_deep_shallow_route_followups(
        plan,
        fetcher=lambda item, _bounds: _response(item.url),
    )

    assert len(result.collected) == 1
    assert result.collected[0].evidence_ids


def test_invalid_shallow_followup_response_remains_skipped_without_collection_provenance() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result_with_evidence(()),
        _empty_javascript_result(),
    )

    result = collect_deep_shallow_route_followups(
        plan,
        fetcher=lambda item, _bounds: DeepHTTPResponse(
            url=item.url,
            final_url=item.url,
            status_code=200,
            headers=(),
            body="not-bytes",  # type: ignore[arg-type]
            elapsed_seconds=0.01,
        ),
    )

    assert result.collected == ()
    assert result.skipped[0].reason == "invalid_fetch_response"
    assert result.skipped[0].evidence_ids == ()


def _source_route_request(*, evidence_ids: tuple[str, ...]) -> DeepCollectionRequest:
    return DeepCollectionRequest(
        url="https://example.test/static/app.js",
        method="GET",
        source="source_route_coverage",
        reason="bounded source/route coverage",
        origin="https://example.test",
        path="/static/app.js",
        evidence_ids=evidence_ids,
        tags=("route",),
    )


def _source_route_plan(request: DeepCollectionRequest) -> DeepCollectionRequestPlan:
    return DeepCollectionRequestPlan(
        allowed_origins=("https://example.test",),
        proposed_requests=(request,),
        policy_summary=evaluate_deep_collection_requests(
            (request,),
            allowed_origins=("https://example.test",),
        ),
        source_counts=(),
    )


def _html_result_with_evidence(
    evidence_ids: tuple[str, ...],
) -> DeepHtmlRouteExtractionResult:
    return DeepHtmlRouteExtractionResult(
        routes=(
            DeepHtmlRouteReference(
                route_id="DEEP-HTML-ROUTE-0001",
                safe_resolved_url="https://example.test/account",
                path="/account",
                query_parameter_names=(),
                origin_relationship="same_origin",
                reference_forms=("root_relative",),
                tag_attribute_sources=("a[href]",),
                source_response_ids=("DEEP-HTML-SOURCE-0001",),
                source_request_urls=("https://example.test/index",),
                source_collection_sections=("source_route_coverage",),
                source_selection_reasons=("content_type",),
                occurrence_count=1,
                evidence_ids=evidence_ids,
                interpretation="same-origin static route",
            ),
        ),
        summary_counts=DeepHtmlRouteExtractionSummaryCounts(
            total_collected_responses_considered=1,
            responses_selected_by_content_type=1,
            responses_selected_by_body_sniff=0,
            non_html_responses_skipped=0,
            html_bodies_parsed=1,
            total_allowed_attribute_references_observed=1,
            accepted_http_route_occurrences=1,
            unique_extracted_routes=1,
            same_origin_routes=1,
            cross_origin_routes=0,
            not_comparable_routes=0,
            fragment_only_references_skipped=0,
            unsupported_scheme_references_skipped=0,
            empty_references_skipped=0,
            unresolved_references_skipped=0,
            duplicate_accepted_occurrences_aggregated=0,
            responses_using_valid_html_base_url=0,
        ),
        safety_notes=(),
    )


def _empty_javascript_result() -> DeepJavaScriptRouteExtractionResult:
    return DeepJavaScriptRouteExtractionResult(
        candidates=(),
        summary_counts=DeepJavaScriptRouteExtractionSummaryCounts(
            total_collected_responses_considered=0,
            javascript_responses_selected_by_content_type=0,
            javascript_responses_selected_by_extension_sniff=0,
            html_responses_selected_for_inline_scripts=0,
            non_javascript_non_html_responses_skipped=0,
            javascript_response_bodies_scanned=0,
            inline_script_blocks_considered=0,
            inline_javascript_blocks_scanned=0,
            total_complete_string_literals_observed=0,
            accepted_static_route_occurrences=0,
            unique_aggregated_candidates=0,
            candidates_with_safe_resolved_urls=0,
            unresolved_relative_candidates_retained=0,
            fragment_only_strings_skipped=0,
            unsupported_scheme_strings_skipped=0,
            not_route_like_strings_skipped=0,
            empty_strings_skipped=0,
            malformed_strings_skipped=0,
            dynamic_template_strings_skipped=0,
            dynamic_concatenation_strings_skipped=0,
            duplicate_accepted_occurrences_aggregated=0,
            html_responses_using_valid_base_url=0,
        ),
        safety_notes=(),
    )


def _response(url: str) -> DeepHTTPResponse:
    return DeepHTTPResponse(
        url=url,
        final_url=url,
        status_code=200,
        headers=(("content-type", "text/plain"),),
        body=b"collected response",
        elapsed_seconds=0.01,
    )
