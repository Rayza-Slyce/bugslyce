"""Offline bundle for Deep collection review summaries.

This module combines existing Deep metadata and source/route collection review
summaries only. It does not read files, write files, fetch URLs, run
collectors, execute commands, or make Deep Recon available.
"""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_metadata_collection_review import (
    DeepMetadataCollectionReviewLead,
    DeepMetadataCollectionReviewSummary,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
    DeepSourceRouteReviewLead,
)


MAX_PRIORITIES = 12
MAX_RENDERED_VALUES = 6
INTRO_TEXT = (
    "This bundle combines existing offline Deep collection review summaries. "
    "No collection or network activity is performed by the bundle."
)
SAFETY_NOTES = (
    "This is a review-only prioritisation layer, not a collection result.",
    "Review-only priority; not a confirmed finding.",
    "No network requests were made by this bundle.",
    "No files were written by this bundle command.",
    "Existing local collection artefacts were read only.",
    "This stage produces static manual-review context only.",
)
CATEGORY_PRIORITY = {
    "redirect_to_login": 0,
    "cookie_set_on_redirect": 1,
    "auth_route_response": 2,
    "forbidden_admin_or_status_route": 3,
    "admin_status_route_response": 4,
    "metadata_found": 5,
    "metadata_redirect": 6,
    "metadata_error": 7,
    "metadata_client_error": 8,
    "metadata_repeated_body": 9,
    "repeated_body_signature": 10,
    "route_redirect": 11,
    "route_success": 12,
    "empty_body_response": 13,
    "metadata_missing": 14,
    "metadata_skipped_policy": 15,
    "metadata_skipped_non_metadata": 16,
    "query_string_route_skipped": 17,
    "metadata_request_skipped": 18,
    "policy_blocked_skipped": 19,
    "fetch_error_skipped": 20,
}


@dataclass(frozen=True)
class DeepCollectionReviewPriority:
    """One bounded manual review priority from collection review summaries."""

    priority_id: str
    title: str
    category: str
    reason: str
    source_sections: tuple[str, ...]
    related_urls: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    signals: tuple[str, ...]
    suggested_manual_review: str
    safety_note: str


@dataclass(frozen=True)
class DeepCollectionReviewSummaryCounts:
    """Immutable count summary for a Deep collection review bundle."""

    metadata_responses_collected: int
    metadata_requests_skipped: int
    metadata_review_leads: int
    source_route_responses_collected: int
    source_route_requests_skipped: int
    source_route_review_leads: int
    generated_unified_priorities: int


@dataclass(frozen=True)
class DeepCollectionReviewBundle:
    """Combined Deep collection review summaries and unified priorities."""

    metadata_review: DeepMetadataCollectionReviewSummary
    source_route_review: DeepSourceRouteCollectionReviewSummary
    priorities: tuple[DeepCollectionReviewPriority, ...]
    summary_counts: DeepCollectionReviewSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PendingPriority:
    title: str
    category: str
    reason: str
    source_sections: tuple[str, ...]
    related_urls: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    signals: tuple[str, ...]
    suggested_manual_review: str
    safety_note: str


def build_deep_collection_review_bundle(
    metadata_review: DeepMetadataCollectionReviewSummary,
    source_route_review: DeepSourceRouteCollectionReviewSummary,
) -> DeepCollectionReviewBundle:
    """Build a deterministic bundle from existing collection review summaries."""

    pending = _dedupe_pending_priorities(
        [
            *(_priority_from_source_route_lead(lead) for lead in source_route_review.review_leads),
            *(_priority_from_metadata_lead(lead) for lead in metadata_review.leads),
        ]
    )
    ordered = tuple(sorted(pending, key=_priority_sort_key))
    bounded = ordered[:MAX_PRIORITIES]
    priorities = tuple(
        DeepCollectionReviewPriority(
            priority_id=f"DEEP-COLL-REV-{index:04d}",
            title=priority.title,
            category=priority.category,
            reason=priority.reason,
            source_sections=priority.source_sections,
            related_urls=priority.related_urls,
            related_evidence_ids=priority.related_evidence_ids,
            signals=priority.signals,
            suggested_manual_review=priority.suggested_manual_review,
            safety_note=priority.safety_note,
        )
        for index, priority in enumerate(bounded, start=1)
    )
    return DeepCollectionReviewBundle(
        metadata_review=metadata_review,
        source_route_review=source_route_review,
        priorities=priorities,
        summary_counts=_summary_counts(
            metadata_review,
            source_route_review,
            len(priorities),
        ),
        safety_notes=SAFETY_NOTES,
    )


def empty_deep_metadata_collection_review_summary() -> DeepMetadataCollectionReviewSummary:
    """Return a valid empty Deep metadata collection review summary."""

    return DeepMetadataCollectionReviewSummary(
        total_collected=0,
        total_skipped=0,
        status_buckets=(),
        duplicate_body_signatures=(),
        leads=(),
        skip_reasons=(),
    )


def empty_deep_source_route_collection_review_summary() -> DeepSourceRouteCollectionReviewSummary:
    """Return a valid empty Deep source/route collection review summary."""

    return DeepSourceRouteCollectionReviewSummary(
        total_collected=0,
        total_skipped=0,
        status_buckets=(),
        body_signatures=(),
        skip_reasons=(),
        review_leads=(),
        safety_notes=(),
    )


def render_deep_collection_review_bundle_markdown(
    bundle: DeepCollectionReviewBundle,
) -> str:
    """Render the Deep collection review bundle as terminal-friendly Markdown."""

    lines = [
        "## Deep Collection Review Bundle",
        "",
        INTRO_TEXT,
        "",
        "### Summary",
        "",
    ]
    for label, value in (
        ("Metadata responses collected", bundle.summary_counts.metadata_responses_collected),
        ("Metadata requests skipped", bundle.summary_counts.metadata_requests_skipped),
        ("Metadata review leads", bundle.summary_counts.metadata_review_leads),
        (
            "Source/route responses collected",
            bundle.summary_counts.source_route_responses_collected,
        ),
        (
            "Source/route requests skipped",
            bundle.summary_counts.source_route_requests_skipped,
        ),
        ("Source/route review leads", bundle.summary_counts.source_route_review_leads),
        ("Generated unified priorities", bundle.summary_counts.generated_unified_priorities),
    ):
        lines.append(f"- {label}: {value}")

    lines.extend(["", "### Unified Review Priorities", ""])
    if bundle.priorities:
        for priority in bundle.priorities:
            lines.extend(
                [
                    f"#### {priority.priority_id} - {priority.title}",
                    "",
                    f"- Category: `{priority.category}`",
                    f"- Source: {_format_compact_values(priority.source_sections)}",
                    f"- Reason: {priority.reason}",
                ]
            )
            if priority.related_urls:
                lines.append(
                    "- Related URLs: "
                    + _format_compact_values(priority.related_urls)
                )
            if priority.related_evidence_ids:
                lines.append(
                    "- Evidence: "
                    + _format_compact_values(priority.related_evidence_ids)
                )
            if priority.signals:
                lines.append("- Signals: " + _format_compact_values(priority.signals))
            lines.extend(
                [
                    f"- Suggested manual review: {priority.suggested_manual_review}",
                    f"- Safety note: {priority.safety_note}",
                    "",
                ]
            )
    else:
        lines.append("- No unified review priorities were generated.")

    lines.extend(
        [
            "",
            "### Review Source Overview",
            "",
            "- Metadata collection review: "
            f"{bundle.summary_counts.metadata_review_leads} lead(s), "
            f"{bundle.summary_counts.metadata_responses_collected} collected response(s), "
            f"{bundle.summary_counts.metadata_requests_skipped} skipped request(s).",
            "- Source/route collection review: "
            f"{bundle.summary_counts.source_route_review_leads} lead(s), "
            f"{bundle.summary_counts.source_route_responses_collected} collected response(s), "
            f"{bundle.summary_counts.source_route_requests_skipped} skipped request(s).",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in bundle.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _priority_from_metadata_lead(
    lead: DeepMetadataCollectionReviewLead,
) -> _PendingPriority:
    signals: list[str] = [f"severity {lead.severity}"]
    if lead.body_sha256:
        signals.append(f"body sha256 {lead.body_sha256}")
    return _PendingPriority(
        title=lead.title,
        category=lead.category,
        reason=lead.detail,
        source_sections=("metadata_collection_review",),
        related_urls=lead.urls,
        related_evidence_ids=lead.evidence_ids,
        signals=tuple(signals),
        suggested_manual_review=(
            "Review the collected metadata response context manually alongside "
            "scope and service evidence."
        ),
        safety_note="Review-only priority; not a confirmed finding.",
    )


def _priority_from_source_route_lead(
    lead: DeepSourceRouteReviewLead,
) -> _PendingPriority:
    return _PendingPriority(
        title=lead.title,
        category=lead.category,
        reason=lead.reason,
        source_sections=("source_route_collection_review",),
        related_urls=lead.urls,
        related_evidence_ids=lead.evidence_ids,
        signals=lead.signals,
        suggested_manual_review=(
            "Review the collected source/route response context manually; do "
            "not infer correlation beyond the existing review summary."
        ),
        safety_note="Review-only priority; not a confirmed finding.",
    )


def _summary_counts(
    metadata_review: DeepMetadataCollectionReviewSummary,
    source_route_review: DeepSourceRouteCollectionReviewSummary,
    priority_count: int,
) -> DeepCollectionReviewSummaryCounts:
    return DeepCollectionReviewSummaryCounts(
        metadata_responses_collected=metadata_review.total_collected,
        metadata_requests_skipped=metadata_review.total_skipped,
        metadata_review_leads=len(metadata_review.leads),
        source_route_responses_collected=source_route_review.total_collected,
        source_route_requests_skipped=source_route_review.total_skipped,
        source_route_review_leads=len(source_route_review.review_leads),
        generated_unified_priorities=priority_count,
    )


def _dedupe_pending_priorities(
    priorities: list[_PendingPriority],
) -> tuple[_PendingPriority, ...]:
    result: list[_PendingPriority] = []
    by_key: dict[tuple[tuple[str, ...], str, tuple[str, ...]], _PendingPriority] = {}
    for priority in priorities:
        key = (
            priority.source_sections,
            priority.category,
            _canonical_url_set(priority.related_urls),
        )
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = priority
            result.append(priority)
            continue
        merged = _PendingPriority(
            title=existing.title,
            category=existing.category,
            reason=existing.reason,
            source_sections=existing.source_sections,
            related_urls=existing.related_urls,
            related_evidence_ids=tuple(
                _dedupe([*existing.related_evidence_ids, *priority.related_evidence_ids])
            ),
            signals=tuple(_dedupe([*existing.signals, *priority.signals])),
            suggested_manual_review=existing.suggested_manual_review,
            safety_note=existing.safety_note,
        )
        by_key[key] = merged
        result[result.index(existing)] = merged
    return tuple(result)


def _canonical_url_set(urls: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(urls)))


def _priority_sort_key(priority: _PendingPriority) -> tuple[int, str, str, str]:
    category_order = CATEGORY_PRIORITY.get(priority.category, len(CATEGORY_PRIORITY))
    first_url = priority.related_urls[0] if priority.related_urls else ""
    return (category_order, priority.category, priority.title, first_url)


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
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
