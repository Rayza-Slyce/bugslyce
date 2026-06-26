"""Offline interpretation collection for already-collected evidence text."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bugslyce.recon.artefact_analysis import (
    ArtefactSource,
    HashArtefactCandidate,
    TransformArtefactCandidate,
    find_hash_artefacts,
    find_transform_artefacts,
)
from bugslyce.recon.html_source_analysis import (
    HtmlSourceAnalysis,
    analyse_html_source,
)
from bugslyce.recon.interpretation import (
    ReviewLead,
    aggregate_interpretation_leads,
)
from bugslyce.recon.interpretation_rendering import render_review_leads_markdown
from bugslyce.recon.robots_analysis import RobotsAnalysis, analyse_robots_txt


HTML_MARKERS = (
    "<html",
    "<!--",
    "<body",
    "<script",
    "<form",
    "<a ",
    "<div",
    "<input",
)


@dataclass(frozen=True)
class InterpretationCollection:
    """Collected offline interpretation outputs for provided evidence sources."""

    sources_analyzed: int
    hash_candidates: tuple[HashArtefactCandidate, ...]
    transform_candidates: tuple[TransformArtefactCandidate, ...]
    robots_analyses: tuple[RobotsAnalysis, ...]
    html_source_analyses: tuple[HtmlSourceAnalysis, ...]
    review_leads: tuple[ReviewLead, ...]
    manual_review_leads_markdown: str | None


def collect_interpretation_from_sources(
    sources: Sequence[ArtefactSource],
    *,
    render_markdown: bool = True,
    engagement_context: str | None = None,
) -> InterpretationCollection:
    """Run offline interpretation analysers over already-collected source text."""

    all_hashes: list[HashArtefactCandidate] = []
    all_transforms: list[TransformArtefactCandidate] = []
    generic_hashes: list[HashArtefactCandidate] = []
    generic_transforms: list[TransformArtefactCandidate] = []
    robots_analyses: list[RobotsAnalysis] = []
    html_analyses: list[HtmlSourceAnalysis] = []

    for source in sources:
        if _is_robots_source(source):
            analysis = analyse_robots_txt(source)
            robots_analyses.append(analysis)
            all_hashes.extend(analysis.hash_artefacts)
            all_transforms.extend(analysis.transform_artefacts)
            continue

        if _is_html_source(source):
            analysis = analyse_html_source(source)
            html_analyses.append(analysis)
            all_hashes.extend(analysis.hash_artefacts)
            all_transforms.extend(analysis.transform_artefacts)
            continue

        hashes = find_hash_artefacts(source)
        transforms = find_transform_artefacts(source)
        generic_hashes.extend(hashes)
        generic_transforms.extend(transforms)
        all_hashes.extend(hashes)
        all_transforms.extend(transforms)

    review_leads = aggregate_interpretation_leads(
        hash_candidates=tuple(generic_hashes),
        transform_candidates=tuple(generic_transforms),
        robots_review_leads=tuple(
            lead
            for analysis in robots_analyses
            for lead in analysis.review_leads
        ),
        html_source_review_leads=tuple(
            lead
            for analysis in html_analyses
            for lead in analysis.review_leads
        ),
    )
    markdown = (
        render_review_leads_markdown(
            review_leads,
            engagement_context=engagement_context,
        )
        if render_markdown
        else None
    )
    return InterpretationCollection(
        sources_analyzed=len(sources),
        hash_candidates=tuple(all_hashes),
        transform_candidates=tuple(all_transforms),
        robots_analyses=tuple(robots_analyses),
        html_source_analyses=tuple(html_analyses),
        review_leads=review_leads,
        manual_review_leads_markdown=markdown,
    )


def _is_robots_source(source: ArtefactSource) -> bool:
    if source.source_kind.lower() == "robots_txt":
        return True
    for value in (source.path, source.url):
        if value and _strip_url_suffix(value).endswith("robots.txt"):
            return True
    return False


def _is_html_source(source: ArtefactSource) -> bool:
    kind = source.source_kind.lower()
    if kind in {"html", "html_source"}:
        return True
    if kind == "response_body" and _looks_html_like(source.text):
        return True
    return _looks_html_like(source.text)


def _looks_html_like(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in HTML_MARKERS)


def _strip_url_suffix(value: str) -> str:
    return value.lower().split("?", 1)[0].split("#", 1)[0].rstrip("/")
