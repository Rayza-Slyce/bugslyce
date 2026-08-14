"""Shared immutable semantic view for operator report assembly."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageView,
    build_analysis_coverage,
)
from bugslyce.reports.investigation_context import (
    InvestigationContextAssembly,
    InvestigationContextSources,
    build_primary_investigation_contexts,
)
from bugslyce.reports.operator_summary import OperatorSummary


@dataclass(frozen=True)
class OperatorReportView:
    """Rebuildable C1/C2 data shared by report presentation paths."""

    investigation_context: InvestigationContextAssembly
    analysis_coverage: AnalysisCoverageView

    @property
    def primary_anchor_ids(self) -> tuple[str, ...]:
        """Expose anchor order from the authoritative C1 assembly."""

        return tuple(
            context.anchor_id
            for context in self.investigation_context.primary_contexts
        )


def build_operator_report_view(
    operator_summary: OperatorSummary,
    *,
    investigation_sources: InvestigationContextSources = InvestigationContextSources(),
    coverage_evidence: Iterable[AnalysisCoverageExecutionEvidence] = (),
) -> OperatorReportView:
    """Compose existing report-only reasoning without adding report authority."""

    ranked_leads = operator_summary.ranked_leads
    return OperatorReportView(
        investigation_context=build_primary_investigation_contexts(
            ranked_leads,
            investigation_sources,
        ),
        analysis_coverage=build_analysis_coverage(coverage_evidence),
    )
