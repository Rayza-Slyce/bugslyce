"""Markdown rendering for offline interpretation review leads."""

from __future__ import annotations

from collections.abc import Sequence

from bugslyce.core.engagement_context import engagement_context_review_guidance
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.review_occurrence_grouping import (
    ReviewOccurrenceGroup,
    build_review_occurrence_groups,
)


DEFAULT_MAX_VALUE_CHARS = 160


def validate_referenced_direct_lead_count(value: int) -> int:
    """Validate the separate count of direct leads rendered in another section."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("referenced_direct_lead_count must be an integer")
    if value < 0:
        raise ValueError("referenced_direct_lead_count must not be negative")
    return value


def render_review_leads_markdown(
    leads: Sequence[ReviewLead],
    *,
    heading: str = "Manual Review Leads",
    max_value_chars: int = DEFAULT_MAX_VALUE_CHARS,
    engagement_context: str | None = None,
    referenced_direct_lead_count: int = 0,
) -> str:
    """Render interpretation review leads as deterministic Markdown."""

    return render_review_occurrence_groups_markdown(
        build_review_occurrence_groups(leads),
        heading=heading,
        max_value_chars=max_value_chars,
        engagement_context=engagement_context,
        referenced_direct_lead_count=referenced_direct_lead_count,
    )


def render_review_occurrence_groups_markdown(
    groups: Sequence[ReviewOccurrenceGroup],
    *,
    heading: str = "Manual Review Leads",
    max_value_chars: int = DEFAULT_MAX_VALUE_CHARS,
    engagement_context: str | None = None,
    referenced_direct_lead_count: int = 0,
) -> str:
    """Render derived occurrence groups without changing their ReviewLead members."""

    referenced_direct_lead_count = validate_referenced_direct_lead_count(
        referenced_direct_lead_count
    )

    lines = [
        f"## {heading}",
        "",
        (
            "These leads are derived from collected evidence and should be treated "
            "as manual review prompts, not proof of vulnerability."
        ),
        "",
    ]
    if engagement_context is not None:
        lines.extend([engagement_context_review_guidance(engagement_context), ""])

    if not groups and referenced_direct_lead_count:
        lines.extend(
            [
                (
                    f"{referenced_direct_lead_count} direct structured disclosure"
                    f"{'s are' if referenced_direct_lead_count != 1 else ' is'} listed "
                    "once in the Operator Summary as manual-review evidence. No "
                    "additional offline interpretation leads were generated in this section."
                ),
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    if not groups:
        lines.extend(
            [
                "No interpretation review leads were generated from the provided evidence.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    for group in groups:
        if group.occurrence_count == 1:
            lines.extend(
                _render_lead(group.members[0].lead, max_value_chars=max_value_chars)
            )
        else:
            lines.extend(_render_group(group, max_value_chars=max_value_chars))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_group(
    group: ReviewOccurrenceGroup,
    *,
    max_value_chars: int,
) -> list[str]:
    lines = [
        f"### {group.group_id}: {group.title}",
        "",
        f"- Priority: {group.priority}",
        f"- Category: {group.category}",
    ]
    source = _source_summary(group)
    if source:
        lines.append(f"- Source: {source}")
    lines.append(f"- Occurrences in this source: {group.occurrence_count}")
    if group.field_name:
        lines.append(f"- Field: {group.field_name}")
    if group.item_type:
        lines.append(f"- Item type: {group.item_type}")
    if group.raw_value:
        lines.append(
            f"- Raw value: `{_markdown_code(_truncate(group.raw_value, max_value_chars))}`"
        )
    if group.decoded_preview:
        lines.append(
            "- Decoded/derived preview: "
            f"`{_markdown_code(_truncate(group.decoded_preview, max_value_chars))}`"
        )
    if group.nearby_keywords:
        lines.append(f"- Nearby keywords: {', '.join(group.nearby_keywords)}")
    if group.related_artefact_types:
        lines.append(
            "- Related artefact types: "
            + ", ".join(group.related_artefact_types)
        )
    if group.explanation:
        lines.append(f"- Explanation: {group.explanation}")
    lines.append("- Child occurrences:")
    for member in group.members:
        details = []
        if member.line_number is not None:
            details.append(f"line {member.line_number}")
        if member.lead.field_name:
            details.append(f"field {member.lead.field_name}")
        if member.lead.item_type:
            details.append(f"item {member.lead.item_type}")
        if member.evidence_ids:
            details.append("evidence " + ", ".join(member.evidence_ids))
        suffix = f" - {'; '.join(details)}" if details else ""
        lines.append(f"  - `{member.lead_id}`{suffix}")
    if group.suggested_manual_validation:
        lines.append("- Suggested manual validation:")
        lines.extend(
            f"  - {step}" for step in group.suggested_manual_validation
        )
    return lines


def _render_lead(lead: ReviewLead, *, max_value_chars: int) -> list[str]:
    lines = [
        f"### {lead.lead_id}: {lead.title}",
        "",
        f"- Priority: {lead.priority}",
        f"- Category: {lead.category}",
    ]

    source = _source_summary(lead)
    if source:
        lines.append(f"- Source: {source}")
    if lead.line_number is not None:
        lines.append(f"- Line: {lead.line_number}")
    if lead.field_name:
        lines.append(f"- Field: {lead.field_name}")
    if lead.item_type:
        lines.append(f"- Item type: {lead.item_type}")
    if lead.raw_value:
        lines.append(
            f"- Raw value: `{_markdown_code(_truncate(lead.raw_value, max_value_chars))}`"
        )
    if lead.decoded_preview:
        lines.append(
            "- Decoded/derived preview: "
            f"`{_markdown_code(_truncate(lead.decoded_preview, max_value_chars))}`"
        )
    if lead.nearby_keywords:
        lines.append(f"- Nearby keywords: {', '.join(lead.nearby_keywords)}")
    if lead.related_artefact_types:
        lines.append(
            f"- Related artefact types: {', '.join(lead.related_artefact_types)}"
        )
    if lead.explanation:
        lines.append(f"- Explanation: {lead.explanation}")
    if lead.suggested_manual_validation:
        lines.append("- Suggested manual validation:")
        lines.extend(f"  - {step}" for step in lead.suggested_manual_validation)
    return lines


def _source_summary(lead: ReviewLead | ReviewOccurrenceGroup) -> str:
    parts: list[str] = []
    label = lead.source_label or lead.source_id
    if label:
        parts.append(label)
    if lead.source_kind:
        parts.append(f"kind={lead.source_kind}")
    if lead.url:
        parts.append(f"url={lead.url}")
    elif lead.path:
        parts.append(f"path={lead.path}")
    if lead.service and lead.port is not None:
        parts.append(f"service={lead.service}:{lead.port}")
    elif lead.service:
        parts.append(f"service={lead.service}")
    elif lead.port is not None:
        parts.append(f"port={lead.port}")
    return "; ".join(parts)


def _truncate(value: str, max_chars: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 3:
        return normalized[:max_chars]
    return normalized[: max_chars - 3].rstrip() + "..."


def _markdown_code(value: str) -> str:
    return value.replace("`", "\\`")
