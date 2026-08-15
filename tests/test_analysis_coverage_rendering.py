"""Operator-facing rendering tests for frozen C2 analysis coverage."""

from __future__ import annotations

from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageOutcome,
    AnalysisCoverageUnit,
    AnalysisCoverageUnknownReason,
    build_analysis_coverage,
)
from bugslyce.reports.analysis_coverage_presentation import (
    build_analysis_coverage_presentation,
)
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.reports.operator_report_view import build_operator_report_view
from bugslyce.reports.operator_summary import OperatorSummary


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def _unit(capability: str, source_role: str, source_id: str) -> AnalysisCoverageUnit:
    return AnalysisCoverageUnit(capability, source_role, source_id)


def _rich_coverage_evidence() -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    positive = _unit("deep_javascript_route_extraction", "deep_source", "SOURCE_alpha")
    plural = _unit(
        "deep_initial_retained_javascript_route_extraction",
        "initial_html",
        "https://example.test/search?a=1&b=2",
    )
    clean = _unit("controlled_analysis", "retained_source", "SOURCE`literal")
    reused = _unit("controlled_analysis", "retained_source", "`leading")
    conflicting = _unit("controlled_analysis", "retained_source", "trailing`")
    return (
        AnalysisCoverageExecutionEvidence(
            unit=positive,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=1,
            finding_identity="finding-one",
        ),
        AnalysisCoverageExecutionEvidence(
            unit=plural,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=1,
            finding_identity="finding-alpha",
        ),
        AnalysisCoverageExecutionEvidence(
            unit=plural,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=1,
            finding_identity="finding-beta",
        ),
        AnalysisCoverageExecutionEvidence(
            unit=clean,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=0,
        ),
        AnalysisCoverageExecutionEvidence(
            unit=reused,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=0,
            reused_completed_result=True,
        ),
        *(
            AnalysisCoverageExecutionEvidence(
                unit=_unit("controlled_analysis", "retained_source", source_id),
                not_run_outcome=outcome,
            )
            for source_id, outcome in (
                ("SOURCE-UNSUPPORTED", AnalysisCoverageOutcome.UNSUPPORTED),
                ("SOURCE-BOUNDED", AnalysisCoverageOutcome.BOUNDED_SKIPPED),
                ("SOURCE-NOT-COLLECTED", AnalysisCoverageOutcome.NOT_COLLECTED),
                ("SOURCE-NOOP", AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE),
            )
        ),
        AnalysisCoverageExecutionEvidence(
            unit=_unit("project_pipeline_step", "standard", "STEP-FAILED"),
            attempted=True,
            partial_failure=True,
        ),
        AnalysisCoverageExecutionEvidence(
            unit=_unit("controlled_analysis", "retained_source", "SOURCE-UNKNOWN"),
        ),
        AnalysisCoverageExecutionEvidence(
            unit=conflicting,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=1,
            finding_identity="conflicting-finding",
        ),
        AnalysisCoverageExecutionEvidence(
            unit=conflicting,
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=2,
            finding_identity="conflicting-finding",
        ),
    )


def test_markdown_renders_existing_operator_report_coverage() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    view = build_operator_report_view(
        summary,
        coverage_evidence=(
            AnalysisCoverageExecutionEvidence(
                unit=AnalysisCoverageUnit(
                    "controlled_analysis",
                    "retained_source",
                    "SOURCE-COVERAGE-1",
                ),
                input_membership_proven=True,
                invocation_proven=True,
                completed=True,
                finding_count=1,
                finding_identity="FINDING-COVERAGE-1",
            ),
        ),
    )

    report = render_markdown_report(
        state,
        [],
        operator_summary=summary,
        operator_report_view=view,
    )

    assert "## Analysis Coverage" in report
    assert "Analysed · Finding present" in report
    assert "SOURCE-COVERAGE-1" in report


def test_coverage_presentation_renders_every_c2_branch_without_new_semantics() -> None:
    presentation = build_analysis_coverage_presentation(
        build_analysis_coverage(_rich_coverage_evidence())
    )
    labels = {item.item.unit.source_id: item.state_label for item in presentation}
    assert labels["SOURCE_alpha"] == "Analysed · Finding present"
    assert labels["SOURCE`literal"] == "Analysed · No finding"
    assert labels["SOURCE-UNSUPPORTED"] == "Not run · Unsupported"
    assert labels["SOURCE-BOUNDED"] == "Not run · Bounded skip"
    assert labels["SOURCE-NOT-COLLECTED"] == "Not run · Input not collected"
    assert labels["SOURCE-NOOP"] == "Not run · Not applicable"
    assert labels["STEP-FAILED"] == "Incomplete · Partial/failed"
    assert labels["SOURCE-UNKNOWN"] == "Unknown"
    assert labels["trailing`"] == "Unknown"

    by_source = {item.item.unit.source_id: item for item in presentation}
    assert by_source["SOURCE_alpha"].finding_count_label == "1 finding"
    assert (
        by_source["https://example.test/search?a=1&b=2"].finding_count_label
        == "2 findings"
    )
    assert (
        by_source["`leading"].execution_note_label
        == "Reused completed result"
    )
    assert (
        by_source["SOURCE-UNKNOWN"].unknown_reason_label
        == "Exact execution proof unavailable"
    )
    assert (
        by_source["trailing`"].item.unknown_reason
        is AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF
    )
    assert (
        by_source["trailing`"].unknown_reason_label
        == "Conflicting exact execution proof"
    )


def test_markdown_coverage_preserves_c2_order_and_safe_literal_identifiers() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    view = build_operator_report_view(
        summary,
        coverage_evidence=_rich_coverage_evidence(),
    )
    report = render_markdown_report(
        state,
        [],
        operator_summary=summary,
        operator_report_view=view,
    )
    coverage = report.split("## Analysis Coverage", 1)[1].split(
        "## Scope Summary", 1
    )[0]

    assert "Analysed · No finding" in coverage
    assert "Not run · Unsupported" in coverage
    assert "Incomplete · Partial/failed" in coverage
    assert "Conflicting exact execution proof" in coverage
    assert "Execution: Reused completed result" in coverage
    assert coverage.count("Execution: Reused completed result") == 1
    assert "1 finding" in coverage
    assert "2 findings" in coverage
    assert "https://example.test/search?a=1&b=2" in coverage
    assert "SOURCE`literal" in coverage
    assert "`leading" in coverage
    assert "trailing`" in coverage
    assert "&amp;" not in coverage
    assert "[controlled](" not in coverage
    assert "coverage %" not in coverage.lower()
    assert "completion %" not in coverage.lower()
    assert "vulnerab" not in coverage.lower()
    assert "safe" not in coverage.lower()
    assert "clean" in coverage.lower()  # The evidence-limited warning is intentional.

    rendered_sources = [
        item.unit.source_id
        for item in view.analysis_coverage.items
    ]
    assert [coverage.index(source) for source in rendered_sources] == sorted(
        coverage.index(source) for source in rendered_sources
    )


def test_empty_coverage_is_evidence_limited_not_a_not_run_claim() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    report = render_markdown_report(
        state,
        [],
        operator_summary=summary,
        operator_report_view=build_operator_report_view(summary),
    )

    coverage = report.split("## Analysis Coverage", 1)[1].split(
        "## Scope Summary", 1
    )[0].lower()
    assert "no source-attributable analysis coverage claims can be proven" in coverage
    assert "no analysis was performed" not in coverage
    assert "not run" not in coverage
    assert "analysed · no finding" not in coverage


def test_markdown_coverage_identifiers_reuse_safe_rpti2_code_literals() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    source_id = "[controlled](javascript:alert(1)) <script>alert(1)</script>"
    view = build_operator_report_view(
        summary,
        coverage_evidence=(
            AnalysisCoverageExecutionEvidence(
                unit=_unit("controlled_analysis", "retained_source", source_id),
                input_membership_proven=True,
                invocation_proven=True,
                completed=True,
                finding_count=1,
                finding_identity="hostile-source-id",
            ),
        ),
    )

    report = render_markdown_report(
        state,
        [],
        operator_summary=summary,
        operator_report_view=view,
    )
    coverage = report.split("## Analysis Coverage", 1)[1].split(
        "## Scope Summary", 1
    )[0]

    assert f"Source identity: `{source_id}`" in coverage
    assert "](#ctx-" not in coverage
