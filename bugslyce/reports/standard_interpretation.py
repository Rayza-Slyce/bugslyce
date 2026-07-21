"""Internal Standard interpretation report helper."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from bugslyce.core.models import Candidate, ProjectState
from bugslyce.recon.collection_confidence import (
    CollectionConfidenceNotice,
    build_collection_confidence_notices_from_project,
    render_collection_confidence_markdown,
)
from bugslyce.recon.investigation_threads import (
    InvestigationThread,
    build_investigation_threads,
    render_investigation_threads_markdown,
)
from bugslyce.recon.route_source_review import (
    RouteSourceLead,
    build_route_source_review,
    render_route_source_review_markdown,
)
from bugslyce.recon.standard_interpretation import (
    StandardInterpretationAssembly,
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.human_triage import (
    HumanTriageBrief,
    build_human_triage_brief,
    render_human_triage_brief_markdown,
    render_readable_evidence_cards_markdown,
)
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


@dataclass(frozen=True)
class StandardInterpretationReport:
    """Rendered Markdown plus interpretation metadata for future Standard Recon."""

    markdown: str
    interpretation_assembly: StandardInterpretationAssembly
    human_triage_brief: HumanTriageBrief
    human_triage_brief_markdown: str | None
    manual_review_leads_markdown: str | None
    investigation_threads: tuple[InvestigationThread, ...]
    investigation_threads_markdown: str | None
    route_source_review_leads: tuple[RouteSourceLead, ...]
    route_source_review_markdown: str | None
    readable_evidence_cards_markdown: str | None
    collection_confidence_notices: tuple[CollectionConfidenceNotice, ...]
    collection_confidence_markdown: str | None
    review_lead_count: int
    investigation_thread_count: int
    route_source_review_count: int
    sources_analyzed: int


def render_standard_interpretation_report(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
) -> StandardInterpretationReport:
    """Render a report with offline Standard interpretation review leads."""

    assembly = assemble_standard_interpretation_from_project_state(project_state)
    candidates_list = list(candidates)
    workflow_leads = build_grouped_workflow_leads(project_state)
    threads = build_investigation_threads(
        project_state,
        candidates_list,
        assembly.review_leads,
        workflow_leads=workflow_leads,
    )
    threads_markdown = render_investigation_threads_markdown(
        threads,
        engagement_context=project_state.engagement_context,
    )
    route_source_leads = build_route_source_review(
        project_state,
        assembly.sources,
    )
    route_source_markdown = render_route_source_review_markdown(
        route_source_leads,
        engagement_context=project_state.engagement_context,
    )
    human_triage_brief = build_human_triage_brief(
        project_state,
        candidates_list,
        engagement_context=project_state.engagement_context,
        workflow_leads=workflow_leads,
    )
    human_triage_markdown = render_human_triage_brief_markdown(human_triage_brief)
    evidence_cards_markdown = render_readable_evidence_cards_markdown(human_triage_brief)
    confidence_notices = build_collection_confidence_notices_from_project(
        project_state,
        Path(project_state.input_dir),
    )
    confidence_markdown = render_collection_confidence_markdown(confidence_notices)
    markdown = render_markdown_report(
        project_state,
        candidates_list,
        human_triage_brief_markdown=human_triage_markdown,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        investigation_threads_markdown=threads_markdown,
        route_source_review_markdown=route_source_markdown,
        readable_evidence_cards_markdown=evidence_cards_markdown,
        collection_confidence_markdown=confidence_markdown,
    )
    return StandardInterpretationReport(
        markdown=markdown,
        interpretation_assembly=assembly,
        human_triage_brief=human_triage_brief,
        human_triage_brief_markdown=human_triage_markdown,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        investigation_threads=threads,
        investigation_threads_markdown=threads_markdown,
        route_source_review_leads=route_source_leads,
        route_source_review_markdown=route_source_markdown,
        readable_evidence_cards_markdown=evidence_cards_markdown,
        collection_confidence_notices=confidence_notices,
        collection_confidence_markdown=confidence_markdown,
        review_lead_count=assembly.review_lead_count,
        investigation_thread_count=len(threads),
        route_source_review_count=len(route_source_leads),
        sources_analyzed=assembly.sources_analyzed,
    )
