"""Internal Standard interpretation report helper."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bugslyce.core.models import Candidate, ProjectState
from bugslyce.recon.standard_interpretation import (
    StandardInterpretationAssembly,
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.markdown import render_markdown_report


@dataclass(frozen=True)
class StandardInterpretationReport:
    """Rendered Markdown plus interpretation metadata for future Standard Recon."""

    markdown: str
    interpretation_assembly: StandardInterpretationAssembly
    manual_review_leads_markdown: str | None
    review_lead_count: int
    sources_analyzed: int


def render_standard_interpretation_report(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
) -> StandardInterpretationReport:
    """Render a report with offline Standard interpretation review leads."""

    assembly = assemble_standard_interpretation_from_project_state(project_state)
    markdown = render_markdown_report(
        project_state,
        list(candidates),
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
    )
    return StandardInterpretationReport(
        markdown=markdown,
        interpretation_assembly=assembly,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        review_lead_count=assembly.review_lead_count,
        sources_analyzed=assembly.sources_analyzed,
    )
