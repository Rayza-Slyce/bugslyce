"""Markdown rendering for offline interpretation review leads."""

from __future__ import annotations

from collections.abc import Sequence

from bugslyce.core.engagement_context import engagement_context_review_guidance
from bugslyce.recon.interpretation import ReviewLead


DEFAULT_MAX_VALUE_CHARS = 160


def render_review_leads_markdown(
    leads: Sequence[ReviewLead],
    *,
    heading: str = "Manual Review Leads",
    max_value_chars: int = DEFAULT_MAX_VALUE_CHARS,
    engagement_context: str | None = None,
) -> str:
    """Render interpretation review leads as deterministic Markdown."""

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

    if not leads:
        lines.extend(
            [
                "No interpretation review leads were generated from the provided evidence.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    for lead in leads:
        lines.extend(_render_lead(lead, max_value_chars=max_value_chars))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


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


def _source_summary(lead: ReviewLead) -> str:
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
