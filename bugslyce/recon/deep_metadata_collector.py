"""Bounded Deep metadata collection core.

This module collects only policy-allowed Deep metadata requests using an
explicit injected fetcher. It does not provide CLI exposure, write files,
create directories, crawl, submit forms, authenticate, inject payloads,
execute browser JavaScript, or enable Deep Recon as a full mode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.http_header_display import render_response_headers_for_humans


MAX_BODY_PREVIEW_CHARS = 500
SAFETY_NOTES = (
    "This is a bounded metadata collection result.",
    "It does not submit forms.",
    "It does not authenticate.",
    "It does not brute force.",
    "It does not inject payloads.",
    "It does not execute browser JavaScript.",
    "It does not crawl.",
    "It does not collect non-metadata routes.",
    "It does not confirm vulnerabilities.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepHTTPResponse:
    """HTTP response returned by an injected Deep metadata fetcher."""

    url: str
    final_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_seconds: float


@dataclass(frozen=True)
class DeepMetadataCollectedItem:
    """Collected metadata response summary without storing the full body."""

    url: str
    method: str
    status_code: int
    final_url: str
    headers: tuple[tuple[str, str], ...]
    body_preview: str
    body_sha256: str
    body_bytes: int
    elapsed_seconds: float
    source: str
    reason: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepMetadataSkippedItem:
    """Metadata collection request skipped before or during collection."""

    url: str
    method: str
    reason: str
    source: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepMetadataCollectionResult:
    """In-memory Deep metadata collection result."""

    collected: tuple[DeepMetadataCollectedItem, ...]
    skipped: tuple[DeepMetadataSkippedItem, ...]
    total_considered: int
    total_collected: int
    total_skipped: int


def collect_deep_metadata_from_plan(
    plan: DeepCollectionRequestPlan,
    *,
    fetcher: Callable[[DeepCollectionRequest, DeepCollectionBounds], DeepHTTPResponse],
) -> DeepMetadataCollectionResult:
    """Collect policy-allowed metadata requests through an injected fetcher."""

    requests_by_key = {
        (request.method.upper(), request.url): request
        for request in plan.proposed_requests
    }
    collected: list[DeepMetadataCollectedItem] = []
    skipped: list[DeepMetadataSkippedItem] = []
    bounds = plan.policy_summary.bounds

    for decision in plan.policy_summary.decisions:
        request = requests_by_key.get((decision.method.upper(), decision.url))
        if request is None:
            skipped.append(_skip_from_decision(decision, "request_not_found"))
            continue
        if request.method.upper() not in {"GET", "HEAD"}:
            skipped.append(_skip_from_request(request, "method_not_allowed"))
            continue
        if not decision.allowed:
            skipped.append(_skip_from_request(request, "policy_blocked"))
            continue
        if request.source != "metadata_coverage":
            skipped.append(_skip_from_request(request, "non_metadata_request"))
            continue

        try:
            response = fetcher(request, bounds)
        except Exception:
            skipped.append(_skip_from_request(request, "fetch_error"))
            continue

        body = response.body
        if len(body) > bounds.max_response_bytes:
            skipped.append(_skip_from_request(request, "response_too_large"))
            continue

        collected.append(
            DeepMetadataCollectedItem(
                url=request.url,
                method=request.method.upper(),
                status_code=response.status_code,
                final_url=response.final_url,
                headers=tuple(response.headers),
                body_preview=_body_preview(body),
                body_sha256=sha256(body).hexdigest(),
                body_bytes=len(body),
                elapsed_seconds=response.elapsed_seconds,
                source=request.source,
                reason=request.reason,
                evidence_ids=tuple(_dedupe(list(request.evidence_ids))),
            )
        )

    return DeepMetadataCollectionResult(
        collected=tuple(collected),
        skipped=tuple(skipped),
        total_considered=len(plan.policy_summary.decisions),
        total_collected=len(collected),
        total_skipped=len(skipped),
    )


def render_deep_metadata_collection_result_markdown(
    result: DeepMetadataCollectionResult,
) -> str:
    """Render a Deep metadata collection result as terminal-friendly Markdown."""

    lines = [
        "## Deep Metadata Collection Result",
        "",
        "This is a bounded metadata collection result.",
        "",
        "### Summary",
        "",
        f"- Requests considered: {result.total_considered}",
        f"- Metadata responses collected: {result.total_collected}",
        f"- Requests skipped: {result.total_skipped}",
        "",
        "### Collected Metadata",
        "",
    ]
    if result.collected:
        for item in result.collected:
            lines.extend(_render_collected_item(item))
    else:
        lines.append("- None.")

    lines.extend(["", "### Skipped Requests", ""])
    if result.skipped:
        for item in result.skipped:
            lines.append(
                f"- `{item.method} {item.url}` - reason: {item.reason} - source: `{item.source}`"
            )
    else:
        lines.append("- None.")

    lines.extend(["", "### Safety Notes", ""])
    lines.extend(f"- {note}" for note in SAFETY_NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _render_collected_item(item: DeepMetadataCollectedItem) -> list[str]:
    lines = [
        f"- `{item.method} {item.url}`",
        f"  - Status: `{item.status_code}`",
        f"  - Final URL: `{item.final_url}`",
        f"  - Body bytes: `{item.body_bytes}`",
        f"  - Body SHA-256: `{item.body_sha256}`",
    ]
    if item.body_preview:
        lines.append(f"  - Body preview: `{item.body_preview}`")
    if item.headers:
        headers = ", ".join(
            f"`{value}`" for value in render_response_headers_for_humans(item.headers)
        )
        lines.append(f"  - Headers: {headers}")
    if item.evidence_ids:
        evidence = ", ".join(f"`{evidence_id}`" for evidence_id in item.evidence_ids)
        lines.append(f"  - Evidence: {evidence}")
    return lines


def _skip_from_request(
    request: DeepCollectionRequest,
    reason: str,
) -> DeepMetadataSkippedItem:
    return DeepMetadataSkippedItem(
        url=request.url,
        method=request.method.upper(),
        reason=reason,
        source=request.source,
        evidence_ids=tuple(_dedupe(list(request.evidence_ids))),
    )


def _skip_from_decision(
    decision,
    reason: str,
) -> DeepMetadataSkippedItem:
    return DeepMetadataSkippedItem(
        url=decision.url,
        method=decision.method.upper(),
        reason=reason,
        source="policy_summary",
        evidence_ids=tuple(_dedupe(list(decision.evidence_ids))),
    )


def _body_preview(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    return text[:MAX_BODY_PREVIEW_CHARS]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
