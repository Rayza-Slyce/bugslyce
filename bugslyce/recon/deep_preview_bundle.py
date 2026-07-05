"""Offline Deep preview bundle.

This module combines existing local Deep preview summaries only. It does not
read files, write files, fetch URLs, run recon, execute commands, or make Deep
Recon available.
"""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_metadata_coverage import (
    DeepMetadataCoverageSummary,
    build_deep_metadata_coverage_from_project_state,
)
from bugslyce.recon.deep_metadata_review import (
    DeepMetadataReviewSummary,
    build_deep_metadata_review_from_project_state,
)
from bugslyce.recon.deep_source_route_coverage import (
    DeepSourceRouteCoverageSummary,
    build_deep_source_route_coverage_from_project_state,
)


MAX_PRIORITIES = 12
MAX_RENDERED_VALUES = 6
METADATA_CLUE_CATEGORIES = {
    "robots_value",
    "robots_route_hint",
    "sitemap_reference",
    "security_contact",
    "humans_metadata",
}
SOURCE_CONTEXT_SIGNALS = {
    "html_comment",
    "keyword_hit",
    "encoded_like_artifact",
    "hidden_element",
    "form",
    "input",
}
SAFETY_NOTES = (
    "This is a prioritisation view, not a finding list.",
    "Review-only priority; not a confirmed finding.",
    (
        "Do not fetch URLs, submit forms, authenticate, brute force, exploit, "
        "or test routes from this summary unless explicitly authorised and in scope."
    ),
    "Deep Recon was not executed.",
)
INTRO_TEXT = (
    "This bundle combines existing local Deep preview summaries. It does not "
    "fetch URLs, run live recon, or execute Deep Recon."
)


@dataclass(frozen=True)
class DeepPreviewPriority:
    """One bounded manual review priority from offline Deep preview summaries."""

    priority_id: str
    title: str
    category: str
    reason: str
    related_urls: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    source_sections: tuple[str, ...]
    suggested_manual_review: str
    safety_note: str


@dataclass(frozen=True)
class DeepPreviewBundle:
    """Combined offline Deep preview summaries and review priorities."""

    metadata_review: DeepMetadataReviewSummary
    metadata_coverage: DeepMetadataCoverageSummary
    source_route_coverage: DeepSourceRouteCoverageSummary
    priorities: tuple[DeepPreviewPriority, ...]
    summary_counts: dict[str, int]
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PendingPriority:
    title: str
    category: str
    reason: str
    related_urls: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    source_sections: tuple[str, ...]
    suggested_manual_review: str
    safety_note: str


def build_deep_preview_bundle_from_project_state(
    project_state: ProjectState,
) -> DeepPreviewBundle:
    """Build an offline Deep preview bundle from already-loaded ProjectState."""

    metadata_review = build_deep_metadata_review_from_project_state(project_state)
    metadata_coverage = build_deep_metadata_coverage_from_project_state(project_state)
    source_route_coverage = build_deep_source_route_coverage_from_project_state(project_state)
    pending = _build_pending_priorities(
        metadata_review,
        metadata_coverage,
        source_route_coverage,
    )
    priorities = tuple(
        DeepPreviewPriority(
            priority_id=f"DEEP-PREV-{index:04d}",
            title=priority.title,
            category=priority.category,
            reason=priority.reason,
            related_urls=priority.related_urls,
            related_evidence_ids=priority.related_evidence_ids,
            source_sections=priority.source_sections,
            suggested_manual_review=priority.suggested_manual_review,
            safety_note=priority.safety_note,
        )
        for index, priority in enumerate(pending[:MAX_PRIORITIES], start=1)
    )
    return DeepPreviewBundle(
        metadata_review=metadata_review,
        metadata_coverage=metadata_coverage,
        source_route_coverage=source_route_coverage,
        priorities=priorities,
        summary_counts=_summary_counts(metadata_review, metadata_coverage, source_route_coverage, len(priorities)),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_preview_bundle_markdown(bundle: DeepPreviewBundle) -> str:
    """Render the offline Deep preview bundle as terminal-friendly Markdown."""

    lines = [
        "## Deep Preview Bundle",
        "",
        INTRO_TEXT,
        "",
        "### Summary",
        "",
    ]
    for label, key in (
        ("Metadata review leads", "metadata_review_leads"),
        ("Metadata planned URLs", "metadata_planned_urls"),
        ("Metadata collected URLs", "metadata_collected_urls"),
        ("Metadata planned but uncollected URLs", "metadata_planned_uncollected_urls"),
        ("Body/source collected routes", "body_source_collected_routes"),
        ("Discovered but unfetched routes", "discovered_unfetched_routes"),
        ("Referenced-only routes", "referenced_only_routes"),
        ("Static/directory context routes", "static_directory_context_routes"),
        ("Metadata context routes", "metadata_context_routes"),
        ("Manual review priorities", "generated_priorities"),
    ):
        lines.append(f"- {label}: {bundle.summary_counts[key]}")

    lines.extend(["", "### Manual Review Priorities", ""])
    if not bundle.priorities:
        lines.append("- No Deep preview priorities were generated from the collected evidence.")
        lines.append("")
    else:
        for priority in bundle.priorities:
            lines.extend(
                [
                    f"#### {priority.priority_id} - {priority.title}",
                    "",
                    f"- Category: `{priority.category}`",
                    f"- Reason: {priority.reason}",
                ]
            )
            if priority.related_urls:
                lines.append("- Related URLs: " + _format_compact_values(priority.related_urls))
            if priority.related_evidence_ids:
                lines.append(
                    "- Evidence: "
                    + _format_compact_values(priority.related_evidence_ids)
                )
            if priority.source_sections:
                lines.append(
                    "- Source sections: "
                    + _format_compact_values(priority.source_sections)
                )
            lines.extend(
                [
                    f"- Suggested manual review: {priority.suggested_manual_review}",
                    f"- Safety note: {priority.safety_note}",
                    "",
                ]
            )

    lines.extend(
        [
            "### Coverage Notes",
            "",
            "- Metadata gaps are uncollected local evidence, not proof of absence.",
            "- Static/directory context is kept low priority unless it supports a stronger route lead.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in bundle.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _build_pending_priorities(
    metadata_review: DeepMetadataReviewSummary,
    metadata_coverage: DeepMetadataCoverageSummary,
    source_route_coverage: DeepSourceRouteCoverageSummary,
) -> tuple[_PendingPriority, ...]:
    pending: list[_PendingPriority] = []

    pending.extend(
        _priority_from_source_route_item(item, "body_auth")
        for item in source_route_coverage.items
        if item.category == "auth_route" and item.status == "body_collected"
    )
    pending.extend(
        _priority_from_source_route_item(item, "gap_auth")
        for item in source_route_coverage.items
        if item.category == "auth_route" and item.status == "discovered_unfetched"
    )
    pending.extend(
        _priority_from_source_route_item(item, "admin_status")
        for item in source_route_coverage.items
        if item.category == "admin_or_status_route"
    )
    pending.extend(
        _priority_from_source_route_item(item, "api")
        for item in source_route_coverage.items
        if item.category == "api_route"
    )
    pending.extend(
        _priority_from_metadata_lead(lead)
        for lead in metadata_review.leads
        if lead.category in METADATA_CLUE_CATEGORIES
    )
    pending.extend(
        _priority_from_source_route_item(item, "source_context")
        for item in source_route_coverage.items
        if item.signals and any(signal in SOURCE_CONTEXT_SIGNALS for signal in item.signals)
        and item.category not in {"auth_route", "admin_or_status_route", "api_route"}
    )
    metadata_gap_priority = _priority_from_metadata_gaps(
        tuple(item for item in metadata_coverage.items if item.status == "planned_uncollected")
    )
    if metadata_gap_priority is not None:
        pending.append(metadata_gap_priority)
    return _dedupe_priorities(pending)


def _priority_from_source_route_item(item, priority_kind: str) -> _PendingPriority:
    if priority_kind == "body_auth":
        title = "Auth route with collected source/body context"
        category = "auth_route_review"
        reason = "Local source/body evidence exists for an auth-related route."
    elif priority_kind == "gap_auth":
        title = "Auth route discovered without body/source context"
        category = "auth_route_review"
        reason = "A discovered auth-related route has no local body/source evidence in the preview."
    elif priority_kind == "admin_status":
        title = "Admin/status/internal route context observed"
        category = "admin_status_route_review"
        reason = "Local route evidence points to admin, status, internal, or diagnostic context."
    elif priority_kind == "api":
        title = "API or documentation route context observed"
        category = "api_route_review"
        reason = "Local route evidence points to API or documentation-style context."
    else:
        title = "Source context route review"
        category = "source_context_review"
        reason = "Local source-level signals are present for this route."
    return _PendingPriority(
        title=title,
        category=category,
        reason=reason,
        related_urls=(item.url,),
        related_evidence_ids=item.evidence_ids,
        source_sections=("source_route_coverage",),
        suggested_manual_review=item.suggested_manual_review,
        safety_note="Review-only priority; not a confirmed finding.",
    )


def _priority_from_metadata_lead(lead) -> _PendingPriority:
    return _PendingPriority(
        title=lead.title,
        category="metadata_clue_review",
        reason="Metadata review generated a local clue or metadata context prompt.",
        related_urls=(lead.url,),
        related_evidence_ids=lead.evidence_ids,
        source_sections=("metadata_review",),
        suggested_manual_review=lead.suggested_manual_review,
        safety_note="Review-only priority; not a confirmed finding.",
    )


def _priority_from_metadata_gaps(items: tuple[object, ...]) -> _PendingPriority | None:
    if not items:
        return None
    return _PendingPriority(
        title="Metadata coverage gaps observed",
        category="metadata_gap_review",
        reason=(
            "Planned Deep metadata URLs have no collected local evidence; "
            "these are coverage gaps only."
        ),
        related_urls=tuple(_dedupe([item.url for item in items])),
        related_evidence_ids=tuple(
            _dedupe(
                [
                    evidence_id
                    for item in items
                    for evidence_id in item.evidence_ids
                ]
            )
        ),
        source_sections=("metadata_coverage",),
        suggested_manual_review=(
            "Treat these as local evidence gaps only; do not fetch missing URLs "
            "unless explicitly authorised and in scope."
        ),
        safety_note="Review-only priority; not a confirmed finding.",
    )


def _summary_counts(
    metadata_review: DeepMetadataReviewSummary,
    metadata_coverage: DeepMetadataCoverageSummary,
    source_route_coverage: DeepSourceRouteCoverageSummary,
    priority_count: int,
) -> dict[str, int]:
    return {
        "metadata_review_leads": len(metadata_review.leads),
        "metadata_planned_urls": metadata_coverage.planned_count,
        "metadata_collected_urls": metadata_coverage.collected_count,
        "metadata_planned_uncollected_urls": metadata_coverage.planned_uncollected_count,
        "body_source_collected_routes": source_route_coverage.body_collected_count,
        "discovered_unfetched_routes": source_route_coverage.discovered_unfetched_count,
        "referenced_only_routes": source_route_coverage.referenced_only_count,
        "static_directory_context_routes": source_route_coverage.static_noise_count,
        "metadata_context_routes": source_route_coverage.metadata_context_count,
        "generated_priorities": priority_count,
    }


def _dedupe_priorities(priorities: list[_PendingPriority]) -> tuple[_PendingPriority, ...]:
    result: list[_PendingPriority] = []
    by_key: dict[tuple[str, tuple[str, ...]], _PendingPriority] = {}
    for priority in priorities:
        key = (priority.category, priority.related_urls)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = priority
            result.append(priority)
            continue
        merged = _PendingPriority(
            title=existing.title,
            category=existing.category,
            reason=existing.reason,
            related_urls=tuple(_dedupe([*existing.related_urls, *priority.related_urls])),
            related_evidence_ids=tuple(
                _dedupe([*existing.related_evidence_ids, *priority.related_evidence_ids])
            ),
            source_sections=tuple(_dedupe([*existing.source_sections, *priority.source_sections])),
            suggested_manual_review=existing.suggested_manual_review,
            safety_note=existing.safety_note,
        )
        by_key[key] = merged
        result[result.index(existing)] = merged
    return tuple(result)


def _format_compact_values(values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"`{value}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
