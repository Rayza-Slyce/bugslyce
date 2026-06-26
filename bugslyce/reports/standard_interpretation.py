"""Internal Standard interpretation report helper."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bugslyce.core.models import Candidate, ProjectState
from bugslyce.recon.investigation_threads import (
    InvestigationThread,
    build_investigation_threads,
    render_investigation_threads_markdown,
)
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
    investigation_threads: tuple[InvestigationThread, ...]
    investigation_threads_markdown: str | None
    review_lead_count: int
    investigation_thread_count: int
    sources_analyzed: int


def render_standard_interpretation_report(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
) -> StandardInterpretationReport:
    """Render a report with offline Standard interpretation review leads."""

    assembly = assemble_standard_interpretation_from_project_state(project_state)
    candidates_list = list(candidates)
    threads = build_investigation_threads(
        project_state,
        candidates_list,
        assembly.review_leads,
    )
    threads_markdown = render_investigation_threads_markdown(
        threads,
        engagement_context=project_state.engagement_context,
    )
    markdown = render_markdown_report(
        project_state,
        candidates_list,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        investigation_threads_markdown=threads_markdown,
    )
    return StandardInterpretationReport(
        markdown=markdown,
        interpretation_assembly=assembly,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        investigation_threads=threads,
        investigation_threads_markdown=threads_markdown,
        review_lead_count=assembly.review_lead_count,
        investigation_thread_count=len(threads),
        sources_analyzed=assembly.sources_analyzed,
    )
