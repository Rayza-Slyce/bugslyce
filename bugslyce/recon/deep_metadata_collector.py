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
from urllib.parse import urlparse
from xml.etree import ElementTree

from bugslyce.core.programme_scope import canonicalise_http_url_destination
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
)
from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
from bugslyce.recon.http_header_display import render_response_headers_for_humans
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.recon.http_enforcement import (
    HTTPProgrammeScopeRefused,
    HTTPRateRejected,
    HTTPRedirectHop,
    HTTPRedirectRefused,
    HTTPTransportFailure,
)


MAX_BODY_PREVIEW_CHARS = 500
MAX_SITEMAP_ROUTE_REFERENCES = 64
MAX_SITEMAP_REFERENCE_CHARS = 2048
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
    redirects: tuple[HTTPRedirectHop, ...] = ()


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
    sitemap_route_references: tuple[str, ...] = ()


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
            skipped.append(_skip_from_request(request, decision.reason))
            continue
        if request.source != "metadata_coverage":
            skipped.append(_skip_from_request(request, "non_metadata_request"))
            continue

        try:
            response = fetcher(request, bounds)
        except HTTPRateRejected:
            raise
        except HTTPProgrammeScopeRefused as exc:
            skipped.append(
                _skip_from_request(
                    request,
                    f"programme_scope_refused:{exc.stage}:{exc.reason_code}",
                )
            )
            continue
        except HTTPRedirectRefused as exc:
            skipped.append(
                _skip_from_request(request, f"redirect_refused:{exc.reason}")
            )
            continue
        except HTTPTransportFailure as exc:
            skipped.append(_skip_from_request(request, f"fetch_error:{exc.category}"))
            continue
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
                sitemap_route_references=_extract_sitemap_route_references(
                    request.url,
                    response.status_code,
                    body,
                ),
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
    if item.sitemap_route_references:
        lines.append("  - Bounded sitemap route references:")
        lines.extend(f"    - `{url}`" for url in item.sitemap_route_references)
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


def _extract_sitemap_route_references(
    request_url: str,
    status_code: int,
    body: bytes,
) -> tuple[str, ...]:
    """Extract bounded same-origin loc references from an already-fetched sitemap."""

    try:
        request_path = urlparse(request_url).path
    except ValueError:
        return ()
    if request_path != "/sitemap.xml" or not 200 <= status_code < 300:
        return ()
    lowered_body = body.lower()
    if b"<!doctype" in lowered_body or b"<!entity" in lowered_body:
        return ()
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, LookupError, ValueError):
        return ()
    if _xml_local_name(root.tag) not in {"urlset", "sitemapindex"}:
        return ()

    request_origin = http_origin_from_url(request_url)
    if request_origin is None:
        return ()
    routes: set[str] = set()
    for element in root.iter():
        if _xml_local_name(element.tag) != "loc" or element.text is None:
            continue
        route = _canonical_same_origin_sitemap_url(element.text, request_origin)
        if route is not None:
            routes.add(route)
    return tuple(sorted(routes)[:MAX_SITEMAP_ROUTE_REFERENCES])


def _canonical_same_origin_sitemap_url(
    raw_url: str,
    expected_origin: HttpOrigin,
) -> str | None:
    value = raw_url.strip()
    if (
        not value
        or len(value) > MAX_SITEMAP_REFERENCE_CHARS
        or any(character.isspace() for character in value)
    ):
        return None
    try:
        destination = canonicalise_http_url_destination(value)
    except ValueError:
        return None
    if (
        destination.origin.scheme != expected_origin.scheme
        or destination.origin.host != expected_origin.hostname
        or destination.origin.effective_port != expected_origin.effective_port
    ):
        return None
    return destination.canonical_value


def _xml_local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
