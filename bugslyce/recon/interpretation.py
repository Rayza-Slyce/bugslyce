"""Shared offline interpretation lead model for analyser outputs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from collections.abc import Iterable

from bugslyce.recon.artefact_analysis import (
    HashArtefactCandidate,
    TransformArtefactCandidate,
)
from bugslyce.recon.html_source_analysis import HtmlSourceReviewLead
from bugslyce.recon.robots_analysis import RobotsReviewLead


PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class ReviewLead:
    """Normalised review lead from offline interpretation analysers."""

    lead_id: str
    lead_type: str
    category: str
    priority: str
    title: str
    explanation: str
    source_id: str
    source_kind: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    line_number: int | None
    field_name: str | None
    item_type: str | None
    raw_value: str
    decoded_preview: str | None
    nearby_keywords: tuple[str, ...]
    related_artefact_types: tuple[str, ...]
    suggested_manual_validation: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ReviewLeadDraft:
    lead_type: str
    category: str
    priority: str
    title: str
    explanation: str
    source_id: str
    source_kind: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    line_number: int | None
    field_name: str | None
    item_type: str | None
    raw_value: str
    decoded_preview: str | None
    nearby_keywords: tuple[str, ...]
    related_artefact_types: tuple[str, ...]
    suggested_manual_validation: tuple[str, ...]
    evidence_ids: tuple[str, ...]


def normalise_hash_artefacts(
    candidates: tuple[HashArtefactCandidate, ...] | list[HashArtefactCandidate],
) -> tuple[ReviewLead, ...]:
    """Convert hash-shaped artefact candidates into shared review leads."""

    return _assign_ids(_hash_draft(candidate) for candidate in candidates)


def normalise_transform_artefacts(
    candidates: tuple[TransformArtefactCandidate, ...] | list[TransformArtefactCandidate],
) -> tuple[ReviewLead, ...]:
    """Convert transform artefact candidates into shared review leads."""

    return _assign_ids(_transform_draft(candidate) for candidate in candidates)


def normalise_robots_review_leads(
    leads: tuple[RobotsReviewLead, ...] | list[RobotsReviewLead],
) -> tuple[ReviewLead, ...]:
    """Convert robots.txt review leads into shared review leads."""

    return _assign_ids(_robots_draft(lead) for lead in leads)


def normalise_html_source_review_leads(
    leads: tuple[HtmlSourceReviewLead, ...] | list[HtmlSourceReviewLead],
) -> tuple[ReviewLead, ...]:
    """Convert HTML/source review leads into shared review leads."""

    return _assign_ids(_html_source_draft(lead) for lead in leads)


def aggregate_interpretation_leads(
    *,
    hash_candidates: tuple[HashArtefactCandidate, ...] | list[HashArtefactCandidate] = (),
    transform_candidates: tuple[TransformArtefactCandidate, ...] | list[TransformArtefactCandidate] = (),
    robots_review_leads: tuple[RobotsReviewLead, ...] | list[RobotsReviewLead] = (),
    html_source_review_leads: tuple[HtmlSourceReviewLead, ...] | list[HtmlSourceReviewLead] = (),
) -> tuple[ReviewLead, ...]:
    """Aggregate analyser-specific outputs into deterministic review leads."""

    drafts = [
        *(_hash_draft(candidate) for candidate in hash_candidates),
        *(_transform_draft(candidate) for candidate in transform_candidates),
        *(_robots_draft(lead) for lead in robots_review_leads),
        *(_html_source_draft(lead) for lead in html_source_review_leads),
    ]
    return _assign_ids(_dedupe_exact_contexts(drafts))


def _hash_draft(candidate: HashArtefactCandidate) -> _ReviewLeadDraft:
    return _ReviewLeadDraft(
        lead_type="possible_hash",
        category="artefact",
        priority=candidate.priority,
        title="Possible hash candidate detected.",
        explanation=(
            f"{candidate.explanation} Shape alone does not confirm the hash type. "
            "Treat this as a review lead, not proof of vulnerability."
        ),
        source_id=candidate.source_id,
        source_kind=candidate.source_kind,
        source_label=candidate.source_label,
        url=candidate.url,
        path=candidate.path,
        port=candidate.port,
        service=candidate.service,
        line_number=candidate.line_number,
        field_name=candidate.field_name,
        item_type=None,
        raw_value=candidate.value,
        decoded_preview=None,
        nearby_keywords=candidate.nearby_keywords,
        related_artefact_types=(candidate.candidate_type,),
        suggested_manual_validation=candidate.suggested_manual_validation,
        evidence_ids=candidate.evidence_ids,
    )


def _transform_draft(candidate: TransformArtefactCandidate) -> _ReviewLeadDraft:
    return _ReviewLeadDraft(
        lead_type="possible_transform",
        category="artefact",
        priority=candidate.priority,
        title="Possible encoded or transformed artefact detected.",
        explanation=(
            f"{candidate.explanation} Derived previews are advisory and may be incorrect. "
            "Treat this as a review lead, not proof of vulnerability."
        ),
        source_id=candidate.source_id,
        source_kind=candidate.source_kind,
        source_label=candidate.source_label,
        url=candidate.url,
        path=candidate.path,
        port=candidate.port,
        service=candidate.service,
        line_number=candidate.line_number,
        field_name=candidate.field_name,
        item_type=None,
        raw_value=candidate.value,
        decoded_preview=candidate.decoded_preview,
        nearby_keywords=candidate.nearby_keywords,
        related_artefact_types=(candidate.candidate_type,),
        suggested_manual_validation=candidate.suggested_manual_validation,
        evidence_ids=candidate.evidence_ids,
    )


def _robots_draft(lead: RobotsReviewLead) -> _ReviewLeadDraft:
    entry = lead.entry
    return _ReviewLeadDraft(
        lead_type=lead.lead_type,
        category="robots",
        priority=lead.priority,
        title=lead.title,
        explanation=_with_review_lead_caution(lead.explanation),
        source_id=entry.source_id,
        source_kind="robots_txt",
        source_label=entry.source_label,
        url=entry.url,
        path=entry.path,
        port=entry.port,
        service=entry.service,
        line_number=entry.line_number,
        field_name=entry.field_name,
        item_type=None,
        raw_value=entry.raw_value,
        decoded_preview=_first_decoded_preview(lead.transform_artefacts),
        nearby_keywords=lead.nearby_keywords,
        related_artefact_types=_related_artefact_types(
            lead.hash_artefacts,
            lead.transform_artefacts,
        ),
        suggested_manual_validation=lead.suggested_manual_validation,
        evidence_ids=entry.evidence_ids,
    )


def _html_source_draft(lead: HtmlSourceReviewLead) -> _ReviewLeadDraft:
    item = lead.item
    return _ReviewLeadDraft(
        lead_type=lead.lead_type,
        category="html_source",
        priority=lead.priority,
        title=lead.title,
        explanation=_with_review_lead_caution(lead.explanation),
        source_id=item.source_id,
        source_kind=item.source_kind,
        source_label=item.source_label,
        url=item.url,
        path=item.path,
        port=item.port,
        service=item.service,
        line_number=item.line_number,
        field_name=item.attribute_name,
        item_type=item.item_type,
        raw_value=item.raw_value,
        decoded_preview=_first_decoded_preview(lead.transform_artefacts),
        nearby_keywords=lead.nearby_keywords,
        related_artefact_types=_related_artefact_types(
            lead.hash_artefacts,
            lead.transform_artefacts,
        ),
        suggested_manual_validation=lead.suggested_manual_validation,
        evidence_ids=item.evidence_ids,
    )


def _first_decoded_preview(candidates: tuple[TransformArtefactCandidate, ...]) -> str | None:
    for candidate in candidates:
        if candidate.decoded_preview:
            return candidate.decoded_preview
    return None


def _related_artefact_types(
    hash_candidates: tuple[HashArtefactCandidate, ...],
    transform_candidates: tuple[TransformArtefactCandidate, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    related: list[str] = []
    for candidate_type in (
        *(candidate.candidate_type for candidate in hash_candidates),
        *(candidate.candidate_type for candidate in transform_candidates),
    ):
        if candidate_type in seen:
            continue
        seen.add(candidate_type)
        related.append(candidate_type)
    return tuple(related)


def _with_review_lead_caution(explanation: str) -> str:
    if "not proof" in explanation.lower():
        return explanation
    return f"{explanation} Treat this as a review lead, not proof of vulnerability."


def _dedupe_exact_contexts(drafts: list[_ReviewLeadDraft]) -> tuple[_ReviewLeadDraft, ...]:
    deduped: dict[tuple[object, ...], _ReviewLeadDraft] = {}
    for draft in drafts:
        key = (
            draft.lead_type,
            draft.category,
            draft.source_id,
            draft.source_kind,
            draft.url,
            draft.path,
            draft.port,
            draft.line_number,
            draft.field_name,
            draft.item_type,
            draft.raw_value,
            draft.decoded_preview,
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = draft
            continue
        deduped[key] = replace(
            existing,
            evidence_ids=_unique_sorted(
                (*existing.evidence_ids, *draft.evidence_ids)
            ),
        )
    return tuple(deduped.values())


def _assign_ids(drafts: Iterable[_ReviewLeadDraft]) -> tuple[ReviewLead, ...]:
    sorted_drafts = sorted(tuple(drafts), key=_sort_key)
    return tuple(
        ReviewLead(
            lead_id=f"LEAD-{index:04d}",
            lead_type=draft.lead_type,
            category=draft.category,
            priority=draft.priority,
            title=draft.title,
            explanation=draft.explanation,
            source_id=draft.source_id,
            source_kind=draft.source_kind,
            source_label=draft.source_label,
            url=draft.url,
            path=draft.path,
            port=draft.port,
            service=draft.service,
            line_number=draft.line_number,
            field_name=draft.field_name,
            item_type=draft.item_type,
            raw_value=draft.raw_value,
            decoded_preview=draft.decoded_preview,
            nearby_keywords=draft.nearby_keywords,
            related_artefact_types=draft.related_artefact_types,
            suggested_manual_validation=draft.suggested_manual_validation,
            evidence_ids=_unique_sorted(draft.evidence_ids),
        )
        for index, draft in enumerate(sorted_drafts, start=1)
    )


def _sort_key(draft: _ReviewLeadDraft) -> tuple[object, ...]:
    return (
        PRIORITY_ORDER.get(draft.priority, 99),
        draft.source_id,
        draft.line_number or 0,
        draft.category,
        draft.lead_type,
        draft.raw_value,
        draft.decoded_preview or "",
    )


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))
