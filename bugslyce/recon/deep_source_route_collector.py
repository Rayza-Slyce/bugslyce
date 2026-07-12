"""Bounded Deep source/route collection core.

This module collects only policy-allowed Deep source/route requests using an
explicit injected fetcher. It does not provide CLI exposure, write files,
create directories, crawl, recursively discover, submit forms, authenticate,
inject payloads, execute browser JavaScript, or enable Deep Recon as a full
mode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from urllib.parse import urlparse

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse


MAX_BODY_PREVIEW_CHARS = 500
MAX_RENDERED_BODY_PREVIEW_CHARS = 300
PREVIEW_TRUNCATED_MARKER = "... [preview truncated]"
SAFETY_NOTES = (
    "This is a bounded source/route collection result.",
    "It collects only policy-allowed source_route_coverage requests.",
    "It does not submit forms.",
    "It does not authenticate.",
    "It does not brute force.",
    "It does not inject payloads.",
    "It does not execute browser JavaScript.",
    "It does not crawl.",
    "It does not collect query-string URLs.",
    "It does not confirm vulnerabilities.",
    "Deep Recon full mode was not enabled.",
)


@dataclass(frozen=True)
class DeepSourceRouteCollectedItem:
    """Collected source/route response summary with in-memory full body."""

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
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class DeepSourceRouteSkippedItem:
    """Source/route collection request skipped before or during collection."""

    url: str
    method: str
    reason: str
    source: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepSourceRouteCollectionResult:
    """In-memory Deep source/route collection result."""

    collected: tuple[DeepSourceRouteCollectedItem, ...]
    skipped: tuple[DeepSourceRouteSkippedItem, ...]
    total_considered: int
    total_collected: int
    total_skipped: int


def collect_deep_source_routes_from_plan(
    plan: DeepCollectionRequestPlan,
    *,
    fetcher: Callable[[DeepCollectionRequest, DeepCollectionBounds], DeepHTTPResponse],
) -> DeepSourceRouteCollectionResult:
    """Collect policy-allowed source/route requests through an injected fetcher."""

    requests_by_key = {
        (request.method.upper(), request.url): request
        for request in plan.proposed_requests
    }
    collected: list[DeepSourceRouteCollectedItem] = []
    skipped: list[DeepSourceRouteSkippedItem] = []
    bounds = plan.policy_summary.bounds

    for decision in plan.policy_summary.decisions:
        request = requests_by_key.get((decision.method.upper(), decision.url))
        if request is None:
            skipped.append(_skip_from_decision(decision, "request_not_found"))
            continue
        if request.method.upper() not in {"GET", "HEAD"}:
            skipped.append(_skip_from_request(request, "method_not_allowed"))
            continue
        if _has_query_string(request.url):
            skipped.append(_skip_from_request(request, "query_string_not_allowed"))
            continue
        if not decision.allowed:
            skipped.append(_skip_from_request(request, "policy_blocked"))
            continue
        if request.source == "metadata_coverage":
            skipped.append(_skip_from_request(request, "metadata_request"))
            continue
        if request.source != "source_route_coverage":
            skipped.append(_skip_from_request(request, "non_source_route_request"))
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
            DeepSourceRouteCollectedItem(
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
                body=body,
            )
        )

    return DeepSourceRouteCollectionResult(
        collected=tuple(collected),
        skipped=tuple(skipped),
        total_considered=len(plan.policy_summary.decisions),
        total_collected=len(collected),
        total_skipped=len(skipped),
    )


def render_deep_source_route_collection_result_markdown(
    result: DeepSourceRouteCollectionResult,
) -> str:
    """Render a Deep source/route collection result as terminal-friendly Markdown."""

    lines = [
        "## Deep Source/Route Collection Result",
        "",
        "This is a bounded source/route collection result.",
        "",
        "### Summary",
        "",
        f"- Requests considered: {result.total_considered}",
        f"- Source/route responses collected: {result.total_collected}",
        f"- Requests skipped: {result.total_skipped}",
        "",
        "### Collected Source/Route Responses",
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


def _render_collected_item(item: DeepSourceRouteCollectedItem) -> list[str]:
    lines = [
        f"- `{item.method} {item.url}`",
        f"  - Status: `{item.status_code}`",
        f"  - Final URL: `{item.final_url}`",
        f"  - Body bytes: `{item.body_bytes}`",
        f"  - Body SHA-256: `{item.body_sha256}`",
    ]
    if item.body_preview:
        lines.append(f"  - Body preview: `{_render_body_preview(item.body_preview)}`")
    if item.headers:
        headers = ", ".join(f"`{name}: {value}`" for name, value in item.headers)
        lines.append(f"  - Headers: {headers}")
    if item.evidence_ids:
        evidence = ", ".join(f"`{evidence_id}`" for evidence_id in item.evidence_ids)
        lines.append(f"  - Evidence: {evidence}")
    return lines


def _skip_from_request(
    request: DeepCollectionRequest,
    reason: str,
) -> DeepSourceRouteSkippedItem:
    return DeepSourceRouteSkippedItem(
        url=request.url,
        method=request.method.upper(),
        reason=reason,
        source=request.source,
        evidence_ids=tuple(_dedupe(list(request.evidence_ids))),
    )


def _skip_from_decision(
    decision,
    reason: str,
) -> DeepSourceRouteSkippedItem:
    return DeepSourceRouteSkippedItem(
        url=decision.url,
        method=decision.method.upper(),
        reason=reason,
        source="policy_summary",
        evidence_ids=tuple(_dedupe(list(decision.evidence_ids))),
    )


def _has_query_string(url: str) -> bool:
    try:
        return bool(urlparse(url).query)
    except ValueError:
        return False


def _body_preview(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    return text[:MAX_BODY_PREVIEW_CHARS]


def _render_body_preview(
    preview: str,
    *,
    max_chars: int = MAX_RENDERED_BODY_PREVIEW_CHARS,
) -> str:
    if not preview:
        return ""

    compact_lines: list[str] = []
    previous_blank = False
    for raw_line in preview.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            if compact_lines and not previous_blank:
                compact_lines.append("")
            previous_blank = True
            continue
        compact_lines.append(line)
        previous_blank = False

    compact = " ".join(line for line in compact_lines if line).strip()
    if len(compact) <= max_chars:
        return compact

    cut = _preview_cut_point(compact, max_chars)
    return f"{compact[:cut].rstrip()} {PREVIEW_TRUNCATED_MARKER}"


def _preview_cut_point(value: str, max_chars: int) -> int:
    segment = value[:max_chars]
    candidates = [segment.rfind(">")]
    candidates.extend(segment.rfind(char) for char in (" ", "\t", "\n"))
    sensible_floor = max(40, max_chars // 2)
    usable = [index for index in candidates if index >= sensible_floor]
    if not usable:
        return max_chars
    boundary = max(usable)
    if segment[boundary] == ">":
        return boundary + 1
    return boundary


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
