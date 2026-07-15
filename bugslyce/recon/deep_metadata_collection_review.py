"""Offline review summary for Deep metadata collection results."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)


STATUS_GROUP_ORDER = (
    "2xx_success",
    "3xx_redirect",
    "4xx_client_error",
    "5xx_server_error",
    "other_status",
)
MAX_RENDERED_URLS = 6
SAFETY_NOTES = (
    "Offline review of existing Deep metadata collection results.",
    "No HTTP requests were made by this review.",
    "No files were written by this review.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepMetadataStatusBucket:
    """Broad status-code grouping for collected metadata responses."""

    status_group: str
    count: int
    urls: tuple[str, ...]


@dataclass(frozen=True)
class DeepMetadataBodySignature:
    """Repeated body hash observed across collected metadata responses."""

    body_sha256: str
    count: int
    status_codes: tuple[int, ...]
    urls: tuple[str, ...]
    body_bytes: int
    body_preview: str


@dataclass(frozen=True)
class DeepMetadataCollectionReviewLead:
    """Human-facing metadata collection review prompt."""

    category: str
    severity: str
    title: str
    detail: str
    urls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    body_sha256: str | None = None


@dataclass(frozen=True)
class DeepMetadataCollectionReviewSummary:
    """Offline review summary for an in-memory metadata collection result."""

    total_collected: int
    total_skipped: int
    status_buckets: tuple[DeepMetadataStatusBucket, ...]
    duplicate_body_signatures: tuple[DeepMetadataBodySignature, ...]
    leads: tuple[DeepMetadataCollectionReviewLead, ...]
    skip_reasons: tuple[tuple[str, int], ...]


def build_deep_metadata_collection_review(
    result: DeepMetadataCollectionResult,
) -> DeepMetadataCollectionReviewSummary:
    """Build a deterministic offline review summary from collection output."""

    status_buckets = _build_status_buckets(result.collected)
    duplicate_body_signatures = _build_duplicate_body_signatures(result.collected)
    skip_reasons = _build_skip_reasons(result)
    leads = _build_leads(result, duplicate_body_signatures, skip_reasons)
    return DeepMetadataCollectionReviewSummary(
        total_collected=result.total_collected,
        total_skipped=result.total_skipped,
        status_buckets=status_buckets,
        duplicate_body_signatures=duplicate_body_signatures,
        leads=leads,
        skip_reasons=skip_reasons,
    )


def render_deep_metadata_collection_review_markdown(
    summary: DeepMetadataCollectionReviewSummary,
) -> str:
    """Render a Deep metadata collection review as terminal-friendly Markdown."""

    lines = [
        "## Deep Metadata Collection Review",
        "",
        "### Summary",
        "",
        f"- Metadata responses collected: {summary.total_collected}",
        f"- Requests skipped: {summary.total_skipped}",
        "",
        "### Status Buckets",
        "",
    ]
    if summary.status_buckets:
        for bucket in summary.status_buckets:
            lines.append(
                f"- `{bucket.status_group}`: {bucket.count} - URLs: {_format_urls(bucket.urls)}"
            )
    else:
        lines.append("- None.")

    lines.extend(["", "### Review Leads", ""])
    if summary.leads:
        for lead in summary.leads:
            lines.extend(
                [
                    f"- **{lead.title}**",
                    f"  - Category: `{lead.category}`",
                    f"  - Severity: `{lead.severity}`",
                    f"  - Detail: {lead.detail}",
                    f"  - URLs: {_format_urls(lead.urls)}",
                ]
            )
            if lead.evidence_ids:
                lines.append(f"  - Evidence: {_format_values(lead.evidence_ids)}")
            if lead.body_sha256:
                lines.append(f"  - Body SHA-256: `{lead.body_sha256}`")
    else:
        lines.append("- None.")

    lines.extend(["", "### Duplicate Body Signatures", ""])
    if summary.duplicate_body_signatures:
        for signature in summary.duplicate_body_signatures:
            lines.extend(
                [
                    f"- `{signature.body_sha256}`",
                    f"  - Count: {signature.count}",
                    f"  - Status codes: {_format_values(tuple(str(code) for code in signature.status_codes))}",
                    f"  - URLs: {_format_urls(signature.urls)}",
                    f"  - Body bytes: `{signature.body_bytes}`",
                ]
            )
            if signature.body_preview:
                lines.append(f"  - Body preview: `{signature.body_preview}`")
    else:
        lines.append("- None.")

    lines.extend(["", "### Skip Reasons", ""])
    if summary.skip_reasons:
        for reason, count in summary.skip_reasons:
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("- None.")

    lines.extend(["", "### Safety Notes", ""])
    lines.extend(f"- {note}" for note in SAFETY_NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _build_status_buckets(
    collected: tuple[DeepMetadataCollectedItem, ...],
) -> tuple[DeepMetadataStatusBucket, ...]:
    urls_by_group: dict[str, list[str]] = {group: [] for group in STATUS_GROUP_ORDER}
    for item in collected:
        urls_by_group[_status_group(item.status_code)].append(item.url)
    return tuple(
        DeepMetadataStatusBucket(
            status_group=group,
            count=len(urls),
            urls=tuple(_dedupe(urls)),
        )
        for group in STATUS_GROUP_ORDER
        if urls_by_group[group]
        for urls in (urls_by_group[group],)
    )


def _build_duplicate_body_signatures(
    collected: tuple[DeepMetadataCollectedItem, ...],
) -> tuple[DeepMetadataBodySignature, ...]:
    items_by_hash: dict[str, list[DeepMetadataCollectedItem]] = defaultdict(list)
    for item in collected:
        items_by_hash[item.body_sha256].append(item)
    signatures: list[DeepMetadataBodySignature] = []
    for body_sha256, items in items_by_hash.items():
        if len(items) <= 1:
            continue
        first = items[0]
        signatures.append(
            DeepMetadataBodySignature(
                body_sha256=body_sha256,
                count=len(items),
                status_codes=tuple(sorted({item.status_code for item in items})),
                urls=tuple(_dedupe([item.url for item in items])),
                body_bytes=first.body_bytes,
                body_preview=first.body_preview,
            )
        )
    return tuple(
        sorted(
            signatures,
            key=lambda signature: (-signature.count, signature.body_sha256),
        )
    )


def _build_skip_reasons(
    result: DeepMetadataCollectionResult,
) -> tuple[tuple[str, int], ...]:
    counts = Counter(item.reason for item in result.skipped)
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _build_leads(
    result: DeepMetadataCollectionResult,
    duplicate_body_signatures: tuple[DeepMetadataBodySignature, ...],
    skip_reasons: tuple[tuple[str, int], ...],
) -> tuple[DeepMetadataCollectionReviewLead, ...]:
    leads: list[DeepMetadataCollectionReviewLead] = []
    by_group: dict[str, list[DeepMetadataCollectedItem]] = defaultdict(list)
    for item in result.collected:
        by_group[_status_group(item.status_code)].append(item)

    lead_specs = (
        (
            "2xx_success",
            "metadata_found",
            "review",
            "Metadata endpoint returned a success response",
            "Collected metadata endpoint returned a success response for manual context review.",
        ),
        (
            "3xx_redirect",
            "metadata_redirect",
            "review",
            "Metadata endpoint returned a redirect",
            "Collected metadata endpoint returned a redirect; review the redirect target in scope context.",
        ),
        (
            "5xx_server_error",
            "metadata_error",
            "review",
            "Metadata endpoint returned a server error",
            "Collected metadata endpoint returned a server-error response; review only as response context.",
        ),
    )
    for group, category, severity, title, detail in lead_specs:
        items = by_group.get(group, [])
        if not items:
            continue
        leads.append(
            DeepMetadataCollectionReviewLead(
                category=category,
                severity=severity,
                title=title,
                detail=detail,
                urls=tuple(_dedupe([item.url for item in items])),
                evidence_ids=_evidence_ids(items),
            )
        )

    missing_items = [
        item
        for item in by_group.get("4xx_client_error", [])
        if item.status_code == 404
    ]
    if missing_items:
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_missing",
                severity="info",
                title="Metadata endpoint returned not found",
                detail="Collected metadata endpoint returned 404 not found; treat this as observed response context only.",
                urls=tuple(_dedupe([item.url for item in missing_items])),
                evidence_ids=_evidence_ids(missing_items),
            )
        )

    non_missing_4xx_items = [
        item
        for item in by_group.get("4xx_client_error", [])
        if item.status_code != 404
    ]
    if non_missing_4xx_items:
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_client_error",
                severity="review",
                title="Metadata endpoint returned a client-error response",
                detail="Collected metadata endpoint returned a non-404 client-error response; review only as response context.",
                urls=tuple(_dedupe([item.url for item in non_missing_4xx_items])),
                evidence_ids=_evidence_ids(non_missing_4xx_items),
            )
        )

    other_items = by_group.get("other_status", [])
    if other_items:
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_error",
                severity="review",
                title="Metadata endpoint returned an unusual status",
                detail="Collected metadata endpoint returned a status outside common 2xx-5xx groups.",
                urls=tuple(_dedupe([item.url for item in other_items])),
                evidence_ids=_evidence_ids(other_items),
            )
        )

    for signature in duplicate_body_signatures:
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_repeated_body",
                severity="info",
                title="Multiple metadata endpoints returned the same body",
                detail="Repeated bodies can indicate default responses or shared error pages; review as context only.",
                urls=signature.urls,
                evidence_ids=_evidence_ids(
                    tuple(
                        item
                        for item in result.collected
                        if item.body_sha256 == signature.body_sha256
                    )
                ),
                body_sha256=signature.body_sha256,
            )
        )

    reason_counts = dict(skip_reasons)
    if reason_counts.get("policy_blocked"):
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_skipped_policy",
                severity="info",
                title="Some planned requests were blocked by policy",
                detail="The restrictive Deep collection policy blocked planned requests before collection.",
                urls=tuple(
                    _dedupe(
                        [
                            item.url
                            for item in result.skipped
                            if item.reason == "policy_blocked"
                        ]
                    )
                ),
                evidence_ids=_skipped_evidence_ids(result, "policy_blocked"),
            )
        )
    if reason_counts.get("non_metadata_request"):
        leads.append(
            DeepMetadataCollectionReviewLead(
                category="metadata_skipped_non_metadata",
                severity="info",
                title="Route/source requests were deliberately not collected",
                detail="The metadata collector skipped non-metadata route/source requests by design.",
                urls=tuple(
                    _dedupe(
                        [
                            item.url
                            for item in result.skipped
                            if item.reason == "non_metadata_request"
                        ]
                    )
                ),
                evidence_ids=_skipped_evidence_ids(result, "non_metadata_request"),
            )
        )
    return tuple(leads)


def _status_group(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "2xx_success"
    if 300 <= status_code <= 399:
        return "3xx_redirect"
    if 400 <= status_code <= 499:
        return "4xx_client_error"
    if 500 <= status_code <= 599:
        return "5xx_server_error"
    return "other_status"


def _evidence_ids(items) -> tuple[str, ...]:
    evidence_ids: list[str] = []
    for item in items:
        evidence_ids.extend(item.evidence_ids)
    return tuple(_dedupe(evidence_ids))


def _skipped_evidence_ids(
    result: DeepMetadataCollectionResult,
    reason: str,
) -> tuple[str, ...]:
    evidence_ids: list[str] = []
    for item in result.skipped:
        if item.reason == reason:
            evidence_ids.extend(item.evidence_ids)
    return tuple(_dedupe(evidence_ids))


def _format_urls(urls: tuple[str, ...]) -> str:
    return _format_values(urls)


def _format_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    visible = values[:MAX_RENDERED_URLS]
    rendered = ", ".join(f"`{value}`" for value in visible)
    remaining = len(values) - len(visible)
    if remaining > 0:
        rendered += f", ... {remaining} more"
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
