"""Offline Standard Recon interpretation assembly helper."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.core.models import ProjectState
from bugslyce.recon.artefact_analysis import ArtefactSource
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.interpretation_collection import (
    InterpretationCollection,
    collect_interpretation_from_sources,
)
from bugslyce.recon.interpretation_sources import (
    DEFAULT_MAX_SOURCE_CHARS,
    artefact_sources_from_project_state,
)


@dataclass(frozen=True)
class StandardInterpretationAssembly:
    """Offline interpretation assembly for future Standard Recon wiring."""

    sources: tuple[ArtefactSource, ...]
    collection: InterpretationCollection
    manual_review_leads_markdown: str | None
    sources_analyzed: int
    review_lead_count: int

    @property
    def review_leads(self) -> tuple[ReviewLead, ...]:
        return self.collection.review_leads


def assemble_standard_interpretation_from_project_state(
    project_state: ProjectState,
    *,
    render_markdown: bool = True,
    max_source_chars: int = DEFAULT_MAX_SOURCE_CHARS,
) -> StandardInterpretationAssembly:
    """Map project state to sources, collect interpretation, and return assembly."""

    sources = artefact_sources_from_project_state(
        project_state,
        max_source_chars=max_source_chars,
    )
    collection = collect_interpretation_from_sources(
        sources,
        render_markdown=render_markdown,
    )
    return StandardInterpretationAssembly(
        sources=sources,
        collection=collection,
        manual_review_leads_markdown=collection.manual_review_leads_markdown,
        sources_analyzed=collection.sources_analyzed,
        review_lead_count=len(collection.review_leads),
    )
