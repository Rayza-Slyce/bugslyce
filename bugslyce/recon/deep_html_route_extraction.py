"""Offline static route extraction from collected Deep HTML bodies.

This module parses full in-memory HTML response bodies already collected by the
bounded Deep source/route collector. It does not read files, write files, fetch
routes, follow links, inspect JavaScript contents, inventory forms, or enable
Deep Recon.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)


ALLOWED_ROUTE_ATTRIBUTES = {
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("script", "src"),
    ("img", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("object", "data"),
    ("embed", "src"),
}
HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
HTML_SNIFF_MARKERS = ("<!doctype html", "<html", "<head", "<body")
MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
SAFETY_NOTES = (
    "This is offline parsing of full HTML bodies already collected in memory.",
    "No route was requested or followed.",
    "No network request was made.",
    "Query values, URL credentials, and fragment contents are not retained.",
    "Unsupported schemes are not executed.",
    "Extracted references are static review context, not confirmed live endpoints.",
    "Forms are not inventoried in this phase.",
    "Inline JavaScript and JavaScript source contents are not analysed.",
    "Deep Recon full mode was not enabled.",
)
ORIGIN_ORDER = {"same_origin": 0, "cross_origin": 1, "not_comparable": 2}
REFERENCE_FORM_ORDER = {
    "absolute_http": 0,
    "absolute_https": 1,
    "scheme_relative": 2,
    "root_relative": 3,
    "path_relative": 4,
    "query_relative": 5,
    "fragment_only": 6,
    "unsupported_scheme": 7,
    "unresolved": 8,
}


@dataclass(frozen=True)
class DeepHtmlRouteReference:
    """One aggregated static HTML route reference."""

    route_id: str
    safe_resolved_url: str
    path: str
    query_parameter_names: tuple[str, ...]
    origin_relationship: str
    reference_forms: tuple[str, ...]
    tag_attribute_sources: tuple[str, ...]
    source_response_ids: tuple[str, ...]
    source_request_urls: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    occurrence_count: int
    evidence_ids: tuple[str, ...]
    interpretation: str


@dataclass(frozen=True)
class DeepHtmlRouteExtractionSummaryCounts:
    """Immutable summary counts for HTML route extraction."""

    total_collected_responses_considered: int
    responses_selected_by_content_type: int
    responses_selected_by_body_sniff: int
    non_html_responses_skipped: int
    html_bodies_parsed: int
    total_allowed_attribute_references_observed: int
    accepted_http_route_occurrences: int
    unique_extracted_routes: int
    same_origin_routes: int
    cross_origin_routes: int
    not_comparable_routes: int
    fragment_only_references_skipped: int
    unsupported_scheme_references_skipped: int
    empty_references_skipped: int
    unresolved_references_skipped: int
    duplicate_accepted_occurrences_aggregated: int
    responses_using_valid_html_base_url: int


@dataclass(frozen=True)
class DeepHtmlRouteExtractionResult:
    """Offline static route extraction result for collected HTML."""

    routes: tuple[DeepHtmlRouteReference, ...]
    summary_counts: DeepHtmlRouteExtractionSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _SourceDocument:
    item: DeepSourceRouteCollectedItem
    source_response_id: str
    safe_source_url: str
    selection_reason: str
    body_text: str


@dataclass(frozen=True)
class _ParsedReference:
    tag_attribute: str
    value: str
    reference_form: str


@dataclass(frozen=True)
class _AcceptedOccurrence:
    safe_resolved_url: str
    path: str
    query_parameter_names: tuple[str, ...]
    origin_relationship: str
    reference_form: str
    tag_attribute: str
    source: _SourceDocument


@dataclass(frozen=True)
class _ParsedHtml:
    references: tuple[_ParsedReference, ...]
    base_hrefs: tuple[str, ...]


class _RouteHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[_ParsedReference] = []
        self.base_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attrs_by_name = {
            name.lower(): value
            for name, value in attrs
            if name
        }
        if tag_name == "base":
            value = (attrs_by_name.get("href") or "").strip()
            if value:
                self.base_hrefs.append(value)
        for attr_name, value in attrs_by_name.items():
            if (tag_name, attr_name) not in ALLOWED_ROUTE_ATTRIBUTES:
                continue
            reference = (value or "").strip()
            self.references.append(
                _ParsedReference(
                    tag_attribute=f"{tag_name}[{attr_name}]",
                    value=reference,
                    reference_form=_reference_form(reference),
                )
            )


def build_deep_html_route_extraction(
    collection_result: DeepSourceRouteCollectionResult,
) -> DeepHtmlRouteExtractionResult:
    """Extract static HTTP/HTTPS route references from full collected HTML bodies."""

    selected, content_type_count, sniff_count, non_html_count = _select_documents(
        collection_result.collected,
    )
    accepted: list[_AcceptedOccurrence] = []
    total_allowed_refs = 0
    fragment_skips = 0
    unsupported_skips = 0
    empty_skips = 0
    unresolved_skips = 0
    base_used_count = 0

    for document in selected:
        parsed = _parse_html(document.body_text)
        base_url, base_used = _resolution_base(document, parsed.base_hrefs)
        if base_used:
            base_used_count += 1
        for reference in parsed.references:
            total_allowed_refs += 1
            if not reference.value.strip():
                empty_skips += 1
                continue
            if reference.reference_form == "fragment_only":
                fragment_skips += 1
                continue
            if reference.reference_form == "unsupported_scheme":
                unsupported_skips += 1
                continue
            if reference.reference_form == "unresolved":
                unresolved_skips += 1
                continue
            resolved = _resolve_reference(base_url, reference.value)
            safe_url = _safe_url(resolved)
            if safe_url == "unresolved":
                unresolved_skips += 1
                continue
            parsed_safe = urlparse(safe_url)
            accepted.append(
                _AcceptedOccurrence(
                    safe_resolved_url=safe_url,
                    path=parsed_safe.path or "/",
                    query_parameter_names=_query_names(parsed_safe.query),
                    origin_relationship=_origin_relationship(document.safe_source_url, safe_url),
                    reference_form=reference.reference_form,
                    tag_attribute=reference.tag_attribute,
                    source=document,
                )
            )

    routes = _build_routes(accepted)
    counts = DeepHtmlRouteExtractionSummaryCounts(
        total_collected_responses_considered=len(collection_result.collected),
        responses_selected_by_content_type=content_type_count,
        responses_selected_by_body_sniff=sniff_count,
        non_html_responses_skipped=non_html_count,
        html_bodies_parsed=len(selected),
        total_allowed_attribute_references_observed=total_allowed_refs,
        accepted_http_route_occurrences=len(accepted),
        unique_extracted_routes=len(routes),
        same_origin_routes=sum(1 for route in routes if route.origin_relationship == "same_origin"),
        cross_origin_routes=sum(1 for route in routes if route.origin_relationship == "cross_origin"),
        not_comparable_routes=sum(1 for route in routes if route.origin_relationship == "not_comparable"),
        fragment_only_references_skipped=fragment_skips,
        unsupported_scheme_references_skipped=unsupported_skips,
        empty_references_skipped=empty_skips,
        unresolved_references_skipped=unresolved_skips,
        duplicate_accepted_occurrences_aggregated=max(0, len(accepted) - len(routes)),
        responses_using_valid_html_base_url=base_used_count,
    )
    return DeepHtmlRouteExtractionResult(
        routes=routes,
        summary_counts=counts,
        safety_notes=SAFETY_NOTES,
    )


def render_deep_html_route_extraction_markdown(
    result: DeepHtmlRouteExtractionResult,
) -> str:
    """Render HTML route extraction as terminal-friendly Markdown."""

    counts = result.summary_counts
    lines = [
        "## Deep HTML Route Extraction",
        "",
        "This is offline parsing of full HTML bodies already collected in memory.",
        "",
        "### Summary",
        "",
        f"- Collected responses considered: {counts.total_collected_responses_considered}",
        f"- Selected by Content-Type: {counts.responses_selected_by_content_type}",
        f"- Selected by conservative body sniff: {counts.responses_selected_by_body_sniff}",
        f"- Non-HTML responses skipped: {counts.non_html_responses_skipped}",
        f"- HTML bodies parsed: {counts.html_bodies_parsed}",
        f"- Allowed attribute references observed: {counts.total_allowed_attribute_references_observed}",
        f"- Accepted HTTP/HTTPS route occurrences: {counts.accepted_http_route_occurrences}",
        f"- Unique extracted routes: {counts.unique_extracted_routes}",
        f"- Same-origin routes: {counts.same_origin_routes}",
        f"- Cross-origin routes: {counts.cross_origin_routes}",
        f"- Not-comparable routes: {counts.not_comparable_routes}",
        f"- Fragment-only references skipped: {counts.fragment_only_references_skipped}",
        f"- Unsupported-scheme references skipped: {counts.unsupported_scheme_references_skipped}",
        f"- Empty references skipped: {counts.empty_references_skipped}",
        f"- Unresolved references skipped: {counts.unresolved_references_skipped}",
        "- Duplicate accepted occurrences aggregated: "
        f"{counts.duplicate_accepted_occurrences_aggregated}",
        f"- Responses using a valid HTML base URL: {counts.responses_using_valid_html_base_url}",
        "",
        "### Extracted Static Routes",
        "",
    ]
    if result.routes:
        for route in result.routes:
            lines.extend(_render_route(route))
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Extraction Interpretation Notes",
            "",
            "- Static route reference observed in collected HTML.",
            "- Same-origin static routes are retained for possible bounded follow-up in a later phase.",
            "- Cross-origin references are neutral context only.",
            "- Extracted references are static review context, not confirmed live endpoints.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in result.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _select_documents(
    items: tuple[DeepSourceRouteCollectedItem, ...],
) -> tuple[tuple[_SourceDocument, ...], int, int, int]:
    selected: list[_SourceDocument] = []
    content_type_count = 0
    sniff_count = 0
    non_html_count = 0
    ordered = sorted(items, key=_source_sort_key)
    for index, item in enumerate(ordered, start=1):
        body = item.body
        if not body:
            non_html_count += 1
            continue
        body_text = body.decode("utf-8", errors="replace")
        content_type = _header_value(item, "content-type")
        media_type = _media_type(content_type)
        if media_type in HTML_MEDIA_TYPES:
            reason = "content_type"
            content_type_count += 1
        elif _sniffs_like_html(body_text):
            reason = "conservative_body_sniff"
            sniff_count += 1
        else:
            non_html_count += 1
            continue
        selected.append(
            _SourceDocument(
                item=item,
                source_response_id=f"DEEP-HTML-SRC-{index:04d}",
                safe_source_url=_safe_url(item.url),
                selection_reason=reason,
                body_text=body_text,
            )
        )
    return tuple(selected), content_type_count, sniff_count, non_html_count


def _parse_html(body_text: str) -> _ParsedHtml:
    parser = _RouteHtmlParser()
    try:
        parser.feed(body_text)
        parser.close()
    except Exception:
        return _ParsedHtml(references=(), base_hrefs=())
    return _ParsedHtml(
        references=tuple(parser.references),
        base_hrefs=tuple(parser.base_hrefs),
    )


def _resolution_base(document: _SourceDocument, base_hrefs: tuple[str, ...]) -> tuple[str, bool]:
    for base_href in base_hrefs:
        resolved = _resolved_valid_base(document.item.url, base_href)
        if resolved is not None:
            return resolved, True
    return document.item.url, False


def _resolved_valid_base(document_url: str, base_href: str) -> str | None:
    try:
        stripped = base_href.strip()
        if not stripped or stripped.startswith(":"):
            return None
        parsed = urlparse(stripped)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None
        resolved = urljoin(document_url, stripped)
        if _safe_url(resolved) == "unresolved":
            return None
        return resolved
    except (TypeError, ValueError):
        return None


def _build_routes(
    accepted: list[_AcceptedOccurrence],
) -> tuple[DeepHtmlRouteReference, ...]:
    grouped: dict[tuple[str, str], list[_AcceptedOccurrence]] = {}
    for occurrence in accepted:
        grouped.setdefault(
            (occurrence.safe_resolved_url, occurrence.origin_relationship),
            [],
        ).append(occurrence)

    pending: list[DeepHtmlRouteReference] = []
    for (_safe_url_value, _origin), values in grouped.items():
        first = sorted(values, key=_occurrence_sort_key)[0]
        pending.append(
            DeepHtmlRouteReference(
                route_id="",
                safe_resolved_url=first.safe_resolved_url,
                path=first.path,
                query_parameter_names=first.query_parameter_names,
                origin_relationship=first.origin_relationship,
                reference_forms=_sort_reference_forms([value.reference_form for value in values]),
                tag_attribute_sources=_unique_sorted([value.tag_attribute for value in values]),
                source_response_ids=_unique_sorted([value.source.source_response_id for value in values]),
                source_request_urls=_unique_sorted([value.source.safe_source_url for value in values]),
                source_collection_sections=_unique_sorted([value.source.item.source for value in values]),
                source_selection_reasons=_unique_sorted([value.source.selection_reason for value in values]),
                occurrence_count=len(values),
                evidence_ids=_unique_sorted(
                    [
                        evidence_id
                        for value in values
                        for evidence_id in value.source.item.evidence_ids
                    ]
                ),
                interpretation=(
                    "Static route reference observed in collected HTML; review-only "
                    "context for possible bounded follow-up in a later phase."
                ),
            )
        )

    ordered = sorted(pending, key=_route_sort_key)
    return tuple(
        DeepHtmlRouteReference(
            route_id=f"DEEP-HTML-ROUTE-{index:04d}",
            safe_resolved_url=route.safe_resolved_url,
            path=route.path,
            query_parameter_names=route.query_parameter_names,
            origin_relationship=route.origin_relationship,
            reference_forms=route.reference_forms,
            tag_attribute_sources=route.tag_attribute_sources,
            source_response_ids=route.source_response_ids,
            source_request_urls=route.source_request_urls,
            source_collection_sections=route.source_collection_sections,
            source_selection_reasons=route.source_selection_reasons,
            occurrence_count=route.occurrence_count,
            evidence_ids=route.evidence_ids,
            interpretation=route.interpretation,
        )
        for index, route in enumerate(ordered, start=1)
    )


def _render_route(route: DeepHtmlRouteReference) -> list[str]:
    lines = [
        f"#### {route.route_id} - Static route reference",
        "",
        f"- URL: `{_compact_single(route.safe_resolved_url)}`",
        f"- Path: `{_compact_single(route.path)}`",
        "- Query parameter names: " + _format_compact_values(route.query_parameter_names),
        f"- Origin relationship: `{route.origin_relationship}`",
        "- Reference forms: " + _format_compact_values(route.reference_forms),
        "- HTML sources: " + _format_compact_values(route.tag_attribute_sources),
        "- Source responses: " + _format_compact_values(route.source_response_ids),
        "- Source request URLs: " + _format_compact_values(route.source_request_urls),
        "- Source sections: " + _format_compact_values(route.source_collection_sections),
        "- Source selection: " + _format_compact_values(route.source_selection_reasons),
        f"- Occurrences: `{route.occurrence_count}`",
    ]
    if route.evidence_ids:
        lines.append("- Evidence: " + _format_compact_values(route.evidence_ids))
    lines.extend([f"- Interpretation: {route.interpretation}", ""])
    return lines


def _reference_form(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "unresolved"
    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if stripped.startswith("//"):
        if not parsed.netloc:
            return "unresolved"
        return "scheme_relative"
    if scheme in {"http", "https"}:
        return f"absolute_{scheme}"
    if scheme:
        return "unsupported_scheme"
    if stripped.startswith("#"):
        return "fragment_only"
    if stripped.startswith("?"):
        return "query_relative"
    if stripped.startswith("/"):
        return "root_relative"
    return "path_relative"


def _resolve_reference(base_url: str, reference: str) -> str:
    try:
        return urljoin(base_url, reference)
    except Exception:
        return ""


def _safe_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
    except (TypeError, ValueError):
        return "unresolved"
    if scheme not in {"http", "https"} or not hostname:
        return "unresolved"

    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority = f"{authority}:{port}"
    path = parsed.path or "/"
    names = _query_names(parsed.query)
    query = f"?{'&'.join(names)}" if names else ""
    return f"{scheme}://{authority}{path}{query}"


def _query_names(query: str) -> tuple[str, ...]:
    return _unique_sorted(
        [
            quote(name, safe="")
            for name, _value in parse_qsl(query, keep_blank_values=True)
            if name
        ]
    )


def _origin_relationship(source_url: str, target_url: str) -> str:
    source = _origin_tuple(source_url)
    target = _origin_tuple(target_url)
    if source is None or target is None:
        return "not_comparable"
    return "same_origin" if source == target else "cross_origin"


def _origin_tuple(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, parsed.hostname.lower(), port)


def _source_sort_key(item: DeepSourceRouteCollectedItem) -> tuple:
    return (
        _safe_url(item.url),
        item.status_code,
        item.body_sha256,
        tuple(sorted(item.evidence_ids)),
    )


def _occurrence_sort_key(occurrence: _AcceptedOccurrence) -> tuple:
    return (
        occurrence.safe_resolved_url,
        occurrence.origin_relationship,
        occurrence.tag_attribute,
        occurrence.source.source_response_id,
    )


def _route_sort_key(route: DeepHtmlRouteReference) -> tuple:
    return (
        ORIGIN_ORDER.get(route.origin_relationship, 99),
        route.safe_resolved_url,
        route.path,
        route.query_parameter_names,
        route.tag_attribute_sources,
        route.source_response_ids,
        route.evidence_ids,
    )


def _media_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _header_value(item: DeepSourceRouteCollectedItem, name: str) -> str | None:
    wanted = name.lower()
    for header_name, value in item.headers:
        if header_name.lower() == wanted:
            return value
    return None


def _sniffs_like_html(body_text: str) -> bool:
    prefix = body_text.lstrip()[:512].lower()
    return any(prefix.startswith(marker) for marker in HTML_SNIFF_MARKERS)


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    compact = " ".join(str(value).strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"


def _unique_sorted(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _sort_reference_forms(values: list[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda value: (REFERENCE_FORM_ORDER.get(value, 99), value),
        )
    )
