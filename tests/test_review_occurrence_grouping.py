"""Contracts for derived Manual Review occurrence grouping."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.review_occurrence_grouping import (
    build_review_occurrence_groups,
)


def test_same_source_same_reason_groups_occurrences_without_mutating_leads() -> None:
    leads = (
        _lead("LEAD-0001", source_id="source-a", line=2, evidence=("EVID-A",)),
        _lead("LEAD-0002", source_id="source-a", line=3, evidence=("EVID-B",)),
    )

    groups = build_review_occurrence_groups(leads)

    assert len(groups) == 1
    group = groups[0]
    assert group.occurrence_count == 2
    assert group.review_lead_ids == ("LEAD-0001", "LEAD-0002")
    assert tuple(member.line_number for member in group.members) == (2, 3)
    assert group.evidence_ids == ("EVID-A", "EVID-B")
    assert group.source_id == "source-a"
    assert group.raw_value == "/archive/backup.zip"
    assert tuple(member.lead for member in group.members) == leads
    assert tuple(member.lead.lead_id for member in group.members) == tuple(
        lead.lead_id for lead in leads
    )


def test_equivalent_values_under_different_source_ids_remain_separate() -> None:
    groups = build_review_occurrence_groups(
        (
            _lead("LEAD-0001", source_id="source-a", line=2),
            _lead("LEAD-0002", source_id="source-b", line=2),
        )
    )

    assert len(groups) == 2
    assert tuple(group.source_id for group in groups) == ("source-a", "source-b")
    assert all(group.occurrence_count == 1 for group in groups)


def test_independent_sources_with_same_value_remain_attributable() -> None:
    groups = build_review_occurrence_groups(
        (
            _lead(
                "LEAD-0001",
                source_id="source-a",
                url="https://a.example.test/",
                line=2,
            ),
            _lead(
                "LEAD-0002",
                source_id="source-b",
                url="https://b.example.test/",
                line=2,
            ),
        )
    )

    assert len(groups) == 2
    assert {group.url for group in groups} == {
        "https://a.example.test/",
        "https://b.example.test/",
    }


def test_similar_non_identical_values_in_one_source_remain_separate() -> None:
    groups = build_review_occurrence_groups(
        (
            _lead("LEAD-0001", line=2, raw_value="/archive/backup.zip"),
            _lead("LEAD-0002", line=3, raw_value="/archive/backups.zip"),
        )
    )

    assert len(groups) == 2
    assert tuple(group.raw_value for group in groups) == (
        "/archive/backup.zip",
        "/archive/backups.zip",
    )


def test_material_interpretation_differences_do_not_merge() -> None:
    base = _lead("LEAD-0001", line=2)
    variants = (
        replace(base, lead_id="LEAD-0002", line_number=3, category="robots"),
        replace(base, lead_id="LEAD-0003", line_number=4, field_name="action"),
        replace(base, lead_id="LEAD-0004", line_number=5, item_type="script_reference"),
        replace(base, lead_id="LEAD-0005", line_number=6, decoded_preview="/decoded/a"),
        replace(
            base,
            lead_id="LEAD-0006",
            line_number=7,
            suggested_manual_validation=("Use a different offline check.",),
        ),
    )

    groups = build_review_occurrence_groups((base, *variants))

    assert len(groups) == 6
    assert all(group.occurrence_count == 1 for group in groups)


def test_missing_source_id_fails_closed_without_cross_occurrence_grouping() -> None:
    groups = build_review_occurrence_groups(
        (
            _lead("LEAD-0001", source_id="", line=2),
            _lead("LEAD-0002", source_id="", line=3),
        )
    )

    assert len(groups) == 2
    assert all(group.source_id == "" for group in groups)


def test_grouping_is_permutation_stable() -> None:
    leads = (
        _lead("LEAD-0001", source_id="source-a", line=2, evidence=("EVID-B",)),
        _lead("LEAD-0002", source_id="source-a", line=3, evidence=("EVID-A",)),
        _lead("LEAD-0003", source_id="source-b", line=4, evidence=("EVID-C",)),
    )

    forward = build_review_occurrence_groups(leads)
    reverse = build_review_occurrence_groups(tuple(reversed(leads)))

    assert forward == reverse
    assert tuple(group.group_id for group in forward) == tuple(
        group.group_id for group in reverse
    )


def test_occurrence_count_does_not_change_priority() -> None:
    leads = tuple(
        _lead(f"LEAD-{index:04d}", line=index)
        for index in range(1, 5)
    )

    group = build_review_occurrence_groups(leads)[0]

    assert group.occurrence_count == 4
    assert group.priority == "medium"


def test_high_cardinality_grouping_retains_all_members_deterministically() -> None:
    leads = tuple(
        _lead(
            f"LEAD-{index:04d}",
            source_id=f"source-{index % 100:03d}",
            line=index,
            raw_value=f"/archive/item-{index % 10:02d}.zip",
            evidence=(f"EVID-{index:04d}",),
        )
        for index in range(1, 2001)
    )

    groups = build_review_occurrence_groups(leads)

    assert len(groups) == 100
    assert sum(group.occurrence_count for group in groups) == len(leads)
    assert {member.lead_id for group in groups for member in group.members} == {
        lead.lead_id for lead in leads
    }


def _lead(
    lead_id: str,
    *,
    source_id: str = "source-a",
    url: str | None = "https://example.test/",
    line: int = 2,
    raw_value: str = "/archive/backup.zip",
    evidence: tuple[str, ...] = ("EVID-1",),
) -> ReviewLead:
    return ReviewLead(
        lead_id=lead_id,
        lead_type="html_local_reference_review",
        category="html_source",
        priority="medium",
        title="Source attribute contains a suspicious local reference.",
        explanation=(
            "Source-level local reference may justify manual same-origin review if in scope. "
            "Treat this as a review lead, not proof of vulnerability."
        ),
        source_id=source_id,
        source_kind="html",
        source_label="homepage",
        url=url,
        path="homepage.html",
        port=443,
        service="https",
        line_number=line,
        field_name="href",
        item_type="link_reference",
        raw_value=raw_value,
        decoded_preview=None,
        nearby_keywords=(),
        related_artefact_types=(),
        suggested_manual_validation=(
            "Review the referenced source context manually.",
            "Review same-origin paths manually only when they are in scope.",
        ),
        evidence_ids=evidence,
    )
