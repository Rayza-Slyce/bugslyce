"""Shared report-only semantic view assembly contracts."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.core.models import Evidence
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteCandidate,
    DeepInitialRetainedJavaScriptRouteSourceObservation,
    empty_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnit,
    AnalysisCoverageUnknownReason,
    build_analysis_coverage,
    coverage_evidence_from_initial_retained_javascript_routes,
)
from bugslyce.reports.investigation_context import (
    InvestigationContextSources,
    build_primary_investigation_contexts,
)
from bugslyce.reports.operator_report_view import build_operator_report_view
from bugslyce.reports.operator_summary import OperatorSummary, OperatorSummaryLead


def test_shared_view_composes_existing_context_and_coverage_without_new_anchors() -> None:
    summary = OperatorSummary(
        review_first=[_lead("LEAD-0002", 2), _lead("LEAD-0001", 1)],
        low_signal=[],
        coverage=[],
    )
    execution = AnalysisCoverageExecutionEvidence(
        unit=AnalysisCoverageUnit("controlled_analysis", "retained_source", "SOURCE-1"),
        input_membership_proven=True,
        invocation_proven=True,
        completed=True,
        finding_count=0,
    )

    view = build_operator_report_view(
        summary,
        investigation_sources=InvestigationContextSources(),
        coverage_evidence=(execution,),
    )

    assert view.primary_anchor_ids == ("LEAD-0002", "LEAD-0001")
    assert tuple(
        context.anchor_id for context in view.investigation_context.primary_contexts
    ) == view.primary_anchor_ids
    assert len(view.investigation_context.primary_contexts) == len(
        summary.ranked_leads
    )
    assert len(view.analysis_coverage.items) == 1
    assert view.analysis_coverage.items[0].state is AnalysisCoverageState.ANALYSED
    assert (
        view.analysis_coverage.items[0].outcome
        is AnalysisCoverageOutcome.NO_FINDING
    )


def test_shared_view_delegates_exact_semantics_and_is_permutation_stable() -> None:
    summary = OperatorSummary(
        review_first=[_lead("LEAD-EXACT", 1, evidence_ids=("EVID-EXACT",))],
        low_signal=[],
        coverage=[],
    )
    sources = InvestigationContextSources(
        evidence=(
            Evidence("EVID-EXACT", "exact.txt", "fixture", "exact", {}),
            Evidence("EVID-OTHER", "same.txt", "fixture", "other", {}),
        )
    )
    unknown = AnalysisCoverageExecutionEvidence(
        unit=AnalysisCoverageUnit("controlled_analysis", "retained_source", "SOURCE-2")
    )

    forward = build_operator_report_view(
        summary,
        investigation_sources=sources,
        coverage_evidence=(unknown, unknown),
    )
    backward = build_operator_report_view(
        summary,
        investigation_sources=replace(sources, evidence=tuple(reversed(sources.evidence))),
        coverage_evidence=tuple(reversed((unknown, unknown))),
    )

    assert forward == backward
    assert forward.investigation_context == build_primary_investigation_contexts(
        summary.ranked_leads,
        sources,
    )
    assert forward.analysis_coverage == build_analysis_coverage((unknown,))
    assert forward.investigation_context.primary_contexts[0].evidence_ids == (
        "EVID-EXACT",
    )
    coverage = forward.analysis_coverage.items[0]
    assert coverage.state is AnalysisCoverageState.UNKNOWN
    assert coverage.outcome is None
    assert (
        coverage.unknown_reason
        is AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF
    )


def test_o4d_positive_coverage_does_not_promote_typed_route_to_primary_anchor() -> None:
    source = DeepInitialRetainedJavaScriptRouteSourceObservation(
        source_role="initial_retained_html",
        source_id="INITIAL-SOURCE-1",
        manifest_file="raw/index.html",
        safe_document_url="https://example.test/",
        source_body_sha256="a" * 64,
        evidence_ids=("EVID-INITIAL",),
        source_selection_reasons=("manifest_retained_initial_html",),
        script_types=("inline",),
        candidate_forms=("root_relative",),
        resolution_contexts=("https://example.test/",),
        occurrence_count=1,
    )
    route = DeepInitialRetainedJavaScriptRouteCandidate(
        candidate_id="DEEP-JS-INITIAL-ROUTE-0001",
        safe_candidate="/service/status",
        safe_resolved_url="https://example.test/service/status",
        path="/service/status",
        query_parameter_names=(),
        source_observations=(source,),
        occurrence_count=1,
        interpretation="Static route candidate from retained initial HTML.",
    )
    result = replace(
        empty_deep_initial_retained_javascript_route_extraction(),
        candidates=(route,),
    )
    summary = OperatorSummary(
        review_first=[_lead("LEAD-ONLY", 1)],
        low_signal=[],
        coverage=[],
    )

    view = build_operator_report_view(
        summary,
        coverage_evidence=coverage_evidence_from_initial_retained_javascript_routes(
            result
        ),
    )

    assert view.primary_anchor_ids == ("LEAD-ONLY",)
    assert route.candidate_id not in view.primary_anchor_ids
    assert view.analysis_coverage.items[0].unit.source_id == source.source_id
    assert view.analysis_coverage.items[0].outcome is AnalysisCoverageOutcome.FINDING_PRESENT


def test_shared_view_preserves_c2_conflicting_count_fail_closed_semantics() -> None:
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    unit = AnalysisCoverageUnit("controlled_analysis", "retained_source", "SOURCE-3")
    proofs = tuple(
        AnalysisCoverageExecutionEvidence(
            unit=unit,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=count,
            finding_identity="FINDING-A",
        )
        for count in (1, 2)
    )

    item = build_operator_report_view(
        summary,
        coverage_evidence=proofs,
    ).analysis_coverage.items[0]

    assert item.state is AnalysisCoverageState.UNKNOWN
    assert item.outcome is None
    assert (
        item.unknown_reason
        is AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF
    )


def _lead(
    lead_id: str,
    rank: int,
    *,
    evidence_ids: tuple[str, ...] = (),
) -> OperatorSummaryLead:
    return OperatorSummaryLead(
        title=f"Review {lead_id}",
        why="Existing deterministic evidence warrants review.",
        endpoints=[],
        evidence_ids=list(evidence_ids),
        next_action="Review retained evidence offline.",
        signal="direct retained evidence",
        score=90 - rank,
        lead_type="controlled_review",
        lead_id=lead_id,
        rank=rank,
    )
