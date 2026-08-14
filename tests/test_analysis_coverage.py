"""Tests for report-only, fail-closed analysis coverage derivation."""

from __future__ import annotations

from dataclasses import replace

import pytest

from bugslyce.project_pipeline import PipelineStep
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteCandidate,
    DeepInitialRetainedJavaScriptRouteSourceObservation,
    empty_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_parameter_inventory import build_deep_parameter_inventory
from bugslyce.recon.deep_post_followup_javascript_route_extraction import (
    build_deep_post_followup_javascript_route_extraction,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageExecutionNote,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnit,
    AnalysisCoverageUnknownReason,
    build_analysis_coverage,
    coverage_evidence_from_deep_javascript_routes,
    coverage_evidence_from_initial_retained_javascript_routes,
    coverage_evidence_from_deep_parameter_inventory,
    coverage_evidence_from_pipeline_steps,
    coverage_evidence_from_post_followup_javascript_routes,
)


def test_explicit_execution_proofs_cover_each_approved_state() -> None:
    evidence = (
        _execution("finding", finding_count=2, finding_identity="finding-a"),
        _execution("clean", finding_count=0),
        _execution(
            "unsupported",
            input_membership_proven=False,
            invocation_proven=False,
            completed=False,
            not_run_outcome=AnalysisCoverageOutcome.UNSUPPORTED,
        ),
        _execution(
            "bounded",
            input_membership_proven=False,
            invocation_proven=False,
            completed=False,
            not_run_outcome=AnalysisCoverageOutcome.BOUNDED_SKIPPED,
        ),
        _execution(
            "not-collected",
            input_membership_proven=False,
            invocation_proven=False,
            completed=False,
            not_run_outcome=AnalysisCoverageOutcome.NOT_COLLECTED,
        ),
        _execution(
            "no-op",
            input_membership_proven=False,
            invocation_proven=False,
            completed=False,
            not_run_outcome=AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
        ),
        _execution(
            "partial",
            completed=False,
            attempted=True,
            partial_failure=True,
        ),
        _execution("unknown", input_membership_proven=False),
    )

    records = build_analysis_coverage(evidence).items
    by_id = {record.unit.source_id: record for record in records}

    assert (by_id["finding"].state, by_id["finding"].outcome) == (
        AnalysisCoverageState.ANALYSED,
        AnalysisCoverageOutcome.FINDING_PRESENT,
    )
    assert by_id["finding"].finding_count == 2
    assert (by_id["clean"].state, by_id["clean"].outcome) == (
        AnalysisCoverageState.ANALYSED,
        AnalysisCoverageOutcome.NO_FINDING,
    )
    assert by_id["clean"].finding_count == 0
    assert (by_id["unsupported"].state, by_id["unsupported"].outcome) == (
        AnalysisCoverageState.NOT_RUN,
        AnalysisCoverageOutcome.UNSUPPORTED,
    )
    assert (by_id["bounded"].state, by_id["bounded"].outcome) == (
        AnalysisCoverageState.NOT_RUN,
        AnalysisCoverageOutcome.BOUNDED_SKIPPED,
    )
    assert (by_id["not-collected"].state, by_id["not-collected"].outcome) == (
        AnalysisCoverageState.NOT_RUN,
        AnalysisCoverageOutcome.NOT_COLLECTED,
    )
    assert (by_id["no-op"].state, by_id["no-op"].outcome) == (
        AnalysisCoverageState.NOT_RUN,
        AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
    )
    assert (by_id["partial"].state, by_id["partial"].outcome) == (
        AnalysisCoverageState.INCOMPLETE,
        AnalysisCoverageOutcome.PARTIAL_FAILED,
    )
    assert by_id["unknown"].state is AnalysisCoverageState.UNKNOWN
    assert by_id["unknown"].outcome is None


def test_zero_aggregate_without_exact_membership_fails_closed_to_unknown() -> None:
    record = build_analysis_coverage(
        (
            AnalysisCoverageExecutionEvidence(
                unit=_unit("source-c"),
                input_membership_proven=False,
                invocation_proven=False,
                completed=True,
                finding_count=0,
            ),
        )
    ).items[0]

    assert record.state is AnalysisCoverageState.UNKNOWN
    assert record.outcome is None
    assert record.finding_count is None


def test_reused_completed_result_is_an_execution_note_not_a_state() -> None:
    record = build_analysis_coverage(
        (_execution("reused", finding_count=0, reused_completed_result=True),)
    ).items[0]

    assert record.state is AnalysisCoverageState.ANALYSED
    assert record.outcome is AnalysisCoverageOutcome.NO_FINDING
    assert record.execution_note is AnalysisCoverageExecutionNote.REUSED_COMPLETED_RESULT


def test_contradictory_or_unidentified_execution_proof_is_rejected() -> None:
    with pytest.raises(ValueError, match="exact finding identity"):
        _execution("unidentified", finding_count=1)

    with pytest.raises(ValueError, match="Not-run coverage"):
        _execution(
            "contradictory",
            not_run_outcome=AnalysisCoverageOutcome.UNSUPPORTED,
        )


def test_deep_javascript_candidate_proves_positive_source_coverage_only() -> None:
    result = build_deep_javascript_route_extraction(
        _source_result(
            _source_item(
                "https://example.test/app.js",
                b'const route = "/api/covered";',
            ),
            _source_item(
                "https://example.test/empty.js",
                b"const dynamic = `/api/${id}`;",
            ),
        )
    )

    coverage = build_analysis_coverage(
        coverage_evidence_from_deep_javascript_routes(result)
    )

    assert len(coverage.items) == 1
    record = coverage.items[0]
    assert record.unit.capability == "deep_javascript_route_extraction"
    assert record.state is AnalysisCoverageState.ANALYSED
    assert record.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
    assert record.finding_count == 1
    assert record.unit.source_id == "DEEP-JS-SRC-0001"
    assert all(item.unit.source_id != "DEEP-JS-SRC-0002" for item in coverage.items)


def test_post_followup_candidate_proves_positive_shallow_source_coverage() -> None:
    body = b'const route = "/api/late-only";'
    shallow = DeepShallowRouteFollowupResult(
        collected=(
            DeepShallowRouteFollowupCollectedItem(
                request_id="DEEP-SHALLOW-REQ-0001",
                method="GET",
                requested_url="https://example.test/app.js",
                final_url="https://example.test/app.js",
                status_code=200,
                headers=(("Content-Type", "application/javascript"),),
                body_preview=body.decode("utf-8"),
                body_sha256="a" * 64,
                body_bytes=len(body),
                elapsed_seconds=0.0,
                evidence_ids=("EVID-SHALLOW-0001",),
                source_model_kinds=("javascript_route",),
                source_route_candidate_ids=("DEEP-JS-ROUTE-0001",),
                query_parameter_names=(),
                body=body,
                interpretation="fixture shallow response",
            ),
        ),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=1,
            responses_collected=1,
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )

    result = build_deep_post_followup_javascript_route_extraction(shallow)
    coverage = build_analysis_coverage(
        coverage_evidence_from_post_followup_javascript_routes(result)
    )

    assert len(coverage.items) == 1
    record = coverage.items[0]
    assert record.unit.capability == "deep_post_followup_javascript_route_extraction"
    assert record.unit.source_id == "DEEP-SHALLOW-REQ-0001"
    assert record.outcome is AnalysisCoverageOutcome.FINDING_PRESENT


def test_parameter_observation_proves_positive_coverage_without_retaining_value() -> None:
    source = _source_result(
        _source_item(
            "https://example.test/app.js",
            b'const route = "/api/items?tenant=blue";',
        )
    )
    javascript = build_deep_javascript_route_extraction(source)
    parameters = build_deep_parameter_inventory(
        source,
        _empty_shallow_result(),
        build_deep_html_route_extraction(source),
        javascript,
    )

    coverage = build_analysis_coverage(
        coverage_evidence_from_deep_parameter_inventory(parameters)
    )

    assert len(coverage.items) == 1
    record = coverage.items[0]
    assert record.unit.capability == "deep_parameter_inventory"
    assert record.unit.source_role == "deep_source_response"
    assert record.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
    assert "blue" not in repr(coverage)


def test_parameter_coverage_groups_multiple_findings_by_existing_analysis_source() -> None:
    parameters = _parameter_inventory_for_javascript(
        b'const route = "/api/items?tenant=blue&lang=en";'
    )

    evidence = coverage_evidence_from_deep_parameter_inventory(parameters)
    coverage = build_analysis_coverage(evidence)

    assert len(coverage.items) == 1
    assert coverage.items[0].unit == AnalysisCoverageUnit(
        capability="deep_parameter_inventory",
        source_role="deep_source_response",
        source_id="DEEP-JS-SRC-0001",
    )
    assert coverage.items[0].finding_count == 2
    assert {item.finding_identity.rsplit("\x00", 1)[-1] for item in evidence} == {
        "lang",
        "tenant",
    }
    assert all("DEEP-PARAM-" not in item.finding_identity for item in evidence)
    assert all("DEEP-PARAM-" not in item.unit.source_id for item in evidence)


def test_parameter_coverage_source_identity_ignores_unrelated_inventory_renumbering() -> None:
    original = _parameter_inventory_for_javascript(
        b'const route = "/api/items?tenant=blue";'
    )
    renumbered = _parameter_inventory_for_javascript(
        b'const first = "/api/alpha?alpha=x"; '
        b'const route = "/api/items?tenant=blue";'
    )

    original_evidence = coverage_evidence_from_deep_parameter_inventory(original)
    renumbered_evidence = coverage_evidence_from_deep_parameter_inventory(renumbered)
    original_tenant = next(
        item for item in original_evidence if item.finding_identity.endswith("\x00tenant")
    )
    renumbered_tenant = next(
        item
        for item in renumbered_evidence
        if item.finding_identity.endswith("\x00tenant")
    )

    assert original.parameters[0].parameter_id == "DEEP-PARAM-0001"
    assert {item.name: item.parameter_id for item in renumbered.parameters} == {
        "alpha": "DEEP-PARAM-0001",
        "tenant": "DEEP-PARAM-0002",
    }
    assert original_tenant.unit == renumbered_tenant.unit
    assert original_tenant.finding_identity == renumbered_tenant.finding_identity


def test_parameter_coverage_keeps_independent_sources_distinct_and_stable() -> None:
    first = _source_item(
        "https://example.test/a.js",
        b'const route = "/api/items?tenant=blue";',
    )
    second = _source_item(
        "https://example.test/b.js",
        b'const route = "/api/items?tenant=green";',
    )

    normal = build_analysis_coverage(
        coverage_evidence_from_deep_parameter_inventory(
            _parameter_inventory_for_sources(first, second)
        )
    )
    reversed_coverage = build_analysis_coverage(
        coverage_evidence_from_deep_parameter_inventory(
            _parameter_inventory_for_sources(second, first)
        )
    )

    assert normal == reversed_coverage
    assert tuple(item.unit.source_id for item in normal.items) == (
        "DEEP-JS-SRC-0001",
        "DEEP-JS-SRC-0002",
    )
    assert all(item.finding_count == 1 for item in normal.items)


def test_contradictory_positive_counts_for_one_finding_fail_closed() -> None:
    unit = _unit("contradictory-source")
    duplicate = AnalysisCoverageExecutionEvidence(
        unit=unit,
        input_membership_proven=True,
        invocation_proven=True,
        completed=True,
        finding_count=1,
        finding_identity="finding-a",
    )
    distinct = AnalysisCoverageExecutionEvidence(
        unit=unit,
        input_membership_proven=True,
        invocation_proven=True,
        completed=True,
        finding_count=1,
        finding_identity="finding-b",
    )
    conflicting = AnalysisCoverageExecutionEvidence(
        unit=unit,
        input_membership_proven=True,
        invocation_proven=True,
        completed=True,
        finding_count=2,
        finding_identity="finding-a",
    )

    exact_duplicate = build_analysis_coverage((duplicate, duplicate)).items[0]
    distinct_findings = build_analysis_coverage((duplicate, distinct)).items[0]
    conflicting_counts = build_analysis_coverage((duplicate, conflicting)).items[0]
    reversed_conflict = build_analysis_coverage((conflicting, duplicate)).items[0]

    assert (
        exact_duplicate.state,
        exact_duplicate.outcome,
        exact_duplicate.finding_count,
    ) == (
        AnalysisCoverageState.ANALYSED,
        AnalysisCoverageOutcome.FINDING_PRESENT,
        1,
    )
    assert (
        distinct_findings.state,
        distinct_findings.outcome,
        distinct_findings.finding_count,
    ) == (
        AnalysisCoverageState.ANALYSED,
        AnalysisCoverageOutcome.FINDING_PRESENT,
        2,
    )
    assert conflicting_counts.state is AnalysisCoverageState.UNKNOWN
    assert (
        conflicting_counts.unknown_reason
        is AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF
    )
    assert reversed_conflict == conflicting_counts


def test_initial_retained_o4d_source_proves_positive_coverage() -> None:
    result = replace(
        empty_deep_initial_retained_javascript_route_extraction(),
        candidates=(
            DeepInitialRetainedJavaScriptRouteCandidate(
                candidate_id="DEEP-JS-INITIAL-ROUTE-0001",
                safe_candidate="/service/status",
                safe_resolved_url="https://example.test/service/status",
                path="/service/status",
                query_parameter_names=(),
                source_observations=(
                    DeepInitialRetainedJavaScriptRouteSourceObservation(
                        source_role="initial_retained_html",
                        source_id="INITIAL-RETAINED-HTML-EXAMPLE",
                        manifest_file="homepage.html",
                        safe_document_url="https://example.test/",
                        source_body_sha256="c" * 64,
                        evidence_ids=(),
                        source_selection_reasons=("html_inline_script",),
                        script_types=("default",),
                        candidate_forms=("root_relative",),
                        resolution_contexts=("html_document_origin",),
                        occurrence_count=1,
                    ),
                ),
                occurrence_count=1,
                interpretation="fixture",
            ),
        ),
    )

    coverage = build_analysis_coverage(
        coverage_evidence_from_initial_retained_javascript_routes(result)
    )

    assert len(coverage.items) == 1
    record = coverage.items[0]
    assert record.unit.capability == "deep_initial_retained_javascript_route_extraction"
    assert record.unit.source_id == "INITIAL-RETAINED-HTML-EXAMPLE"
    assert record.outcome is AnalysisCoverageOutcome.FINDING_PRESENT


def test_explicit_pipeline_noop_and_failure_are_attributable_without_clean_claims() -> None:
    steps = (
        PipelineStep(
            step_id="PIPELINE-STEP-NOOP",
            name="fixture no-op",
            command_kind="fixture",
            status="noop",
        ),
        PipelineStep(
            step_id="PIPELINE-STEP-FAILED",
            name="fixture failed",
            command_kind="fixture",
            status="failed",
        ),
        PipelineStep(
            step_id="PIPELINE-STEP-COMPLETED",
            name="fixture completed",
            command_kind="fixture",
            status="completed",
        ),
    )

    coverage = build_analysis_coverage(coverage_evidence_from_pipeline_steps(steps))

    assert tuple(item.unit.source_id for item in coverage.items) == (
        "PIPELINE-STEP-FAILED",
        "PIPELINE-STEP-NOOP",
    )
    assert coverage.items[0].outcome is AnalysisCoverageOutcome.PARTIAL_FAILED
    assert coverage.items[1].outcome is AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE


def test_coverage_is_permutation_stable_and_dedupes_exact_execution_evidence() -> None:
    first = _execution("source-a", finding_count=1, finding_identity="route-a")
    duplicate = _execution("source-a", finding_count=1, finding_identity="route-a")
    second = _execution("source-b", finding_count=1, finding_identity="route-b")

    normal = build_analysis_coverage((first, duplicate, second))
    reversed_coverage = build_analysis_coverage((second, duplicate, first))

    assert reversed_coverage == normal
    assert tuple(item.unit.source_id for item in normal.items) == (
        "source-a",
        "source-b",
    )
    assert tuple(item.finding_count for item in normal.items) == (1, 1)


def test_high_cardinality_explicit_execution_records_remain_sparse_and_deterministic() -> None:
    evidence = tuple(
        _execution(
            f"source-{index:04d}",
            finding_count=1,
            finding_identity=f"route-{index:04d}",
        )
        for index in reversed(range(400))
    )

    coverage = build_analysis_coverage(evidence)

    assert len(coverage.items) == 400
    assert coverage.items[0].unit.source_id == "source-0000"
    assert coverage.items[-1].unit.source_id == "source-0399"


def _execution(
    source_id: str,
    *,
    input_membership_proven: bool = True,
    invocation_proven: bool = True,
    completed: bool = True,
    finding_count: int | None = None,
    finding_identity: str = "",
    not_run_outcome: AnalysisCoverageOutcome | None = None,
    attempted: bool = False,
    partial_failure: bool = False,
    reused_completed_result: bool = False,
) -> AnalysisCoverageExecutionEvidence:
    return AnalysisCoverageExecutionEvidence(
        unit=_unit(source_id),
        input_membership_proven=input_membership_proven,
        invocation_proven=invocation_proven,
        completed=completed,
        finding_count=finding_count,
        finding_identity=finding_identity,
        not_run_outcome=not_run_outcome,
        attempted=attempted,
        partial_failure=partial_failure,
        reused_completed_result=reused_completed_result,
    )


def _unit(source_id: str) -> AnalysisCoverageUnit:
    return AnalysisCoverageUnit(
        capability="fixture_static_analysis",
        source_role="retained_source",
        source_id=source_id,
    )


def _source_result(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=items,
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _parameter_inventory_for_javascript(body: bytes):
    return _parameter_inventory_for_sources(
        _source_item("https://example.test/app.js", body)
    )


def _parameter_inventory_for_sources(*items: DeepSourceRouteCollectedItem):
    source = _source_result(*items)
    javascript = build_deep_javascript_route_extraction(source)
    return build_deep_parameter_inventory(
        source,
        _empty_shallow_result(),
        build_deep_html_route_extraction(source),
        javascript,
    )


def _empty_shallow_result() -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=(),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=0,
            responses_collected=0,
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )


def _source_item(url: str, body: bytes) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", "application/javascript"),),
        body_preview=body.decode("utf-8"),
        body_sha256="b" * 64,
        body_bytes=len(body),
        elapsed_seconds=0.0,
        source="source_route_coverage",
        reason="fixture",
        evidence_ids=(),
        body=body,
    )
