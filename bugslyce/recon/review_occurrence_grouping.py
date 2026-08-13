"""Derived same-source occurrence grouping for Manual Review presentation."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json

from bugslyce.recon.interpretation import PRIORITY_ORDER, ReviewLead


@dataclass(frozen=True)
class ReviewOccurrenceMember:
    """One unchanged ReviewLead occurrence retained inside a derived group."""

    lead: ReviewLead

    @property
    def lead_id(self) -> str:
        return self.lead.lead_id

    @property
    def line_number(self) -> int | None:
        return self.lead.line_number

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return self.lead.evidence_ids


@dataclass(frozen=True)
class ReviewOccurrenceGroup:
    """One rebuildable operator reason with source-attributable occurrences."""

    group_id: str
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
    field_name: str | None
    item_type: str | None
    raw_value: str
    decoded_preview: str | None
    nearby_keywords: tuple[str, ...]
    related_artefact_types: tuple[str, ...]
    suggested_manual_validation: tuple[str, ...]
    members: tuple[ReviewOccurrenceMember, ...]

    @property
    def occurrence_count(self) -> int:
        return len(self.members)

    @property
    def review_lead_ids(self) -> tuple[str, ...]:
        return tuple(member.lead_id for member in self.members)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return _unique_sorted(
            evidence_id
            for member in self.members
            for evidence_id in member.evidence_ids
        )


def build_review_occurrence_groups(
    leads: Sequence[ReviewLead],
) -> tuple[ReviewOccurrenceGroup, ...]:
    """Group only semantically identical occurrences from one known source."""

    members_by_key: dict[tuple[object, ...], list[ReviewOccurrenceMember]] = {}
    lead_by_key: dict[tuple[object, ...], ReviewLead] = {}
    for lead in leads:
        key = _grouping_key(lead)
        members_by_key.setdefault(key, []).append(ReviewOccurrenceMember(lead))
        lead_by_key.setdefault(key, lead)

    groups = [
        _group_from_members(key, lead_by_key[key], members)
        for key, members in members_by_key.items()
    ]
    return tuple(sorted(groups, key=_group_sort_key))


def _grouping_key(lead: ReviewLead) -> tuple[object, ...]:
    semantic = (
        lead.lead_type,
        lead.category,
        lead.priority,
        lead.title,
        lead.explanation,
        lead.source_id,
        lead.source_kind,
        lead.source_label,
        lead.url,
        lead.path,
        lead.port,
        lead.service,
        lead.field_name,
        lead.item_type,
        lead.raw_value,
        lead.decoded_preview,
        lead.nearby_keywords,
        lead.related_artefact_types,
        lead.suggested_manual_validation,
    )
    if lead.source_id:
        return ("attributed", *semantic)
    # An empty source ID cannot prove common derivation. Existing deterministic
    # lead identity keeps such occurrences separate and attributable as far as
    # the retained model permits.
    return ("unattributed", lead.lead_id, *semantic)


def _group_from_members(
    key: tuple[object, ...],
    lead: ReviewLead,
    members: list[ReviewOccurrenceMember],
) -> ReviewOccurrenceGroup:
    ordered_members = tuple(sorted(members, key=_member_sort_key))
    return ReviewOccurrenceGroup(
        group_id=_group_id(key),
        lead_type=lead.lead_type,
        category=lead.category,
        priority=lead.priority,
        title=lead.title,
        explanation=lead.explanation,
        source_id=lead.source_id,
        source_kind=lead.source_kind,
        source_label=lead.source_label,
        url=lead.url,
        path=lead.path,
        port=lead.port,
        service=lead.service,
        field_name=lead.field_name,
        item_type=lead.item_type,
        raw_value=lead.raw_value,
        decoded_preview=lead.decoded_preview,
        nearby_keywords=lead.nearby_keywords,
        related_artefact_types=lead.related_artefact_types,
        suggested_manual_validation=lead.suggested_manual_validation,
        members=ordered_members,
    )


def _group_id(key: tuple[object, ...]) -> str:
    material = json.dumps(
        {"kind": "review_occurrence_group", "identity": key},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"REVIEW-GROUP-{digest}"


def _member_sort_key(member: ReviewOccurrenceMember) -> tuple[object, ...]:
    lead = member.lead
    return (
        lead.line_number is None,
        lead.line_number or 0,
        lead.lead_id,
        lead.evidence_ids,
    )


def _group_sort_key(group: ReviewOccurrenceGroup) -> tuple[object, ...]:
    first_line = next(
        (
            member.line_number
            for member in group.members
            if member.line_number is not None
        ),
        0,
    )
    return (
        PRIORITY_ORDER.get(group.priority, 99),
        group.source_id,
        group.source_kind,
        group.url or "",
        group.path or "",
        first_line,
        group.category,
        group.lead_type,
        group.raw_value,
        group.decoded_preview or "",
        group.group_id,
    )


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))
