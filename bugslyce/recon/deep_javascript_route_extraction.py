"""Offline static route extraction from collected JavaScript evidence.

This module lexically inspects full in-memory JavaScript response bodies and
inline script bodies already collected by the bounded Deep source/route
collector. It does not execute JavaScript, evaluate expressions, read or write
files, fetch routes, follow links, inventory forms, or enable Deep Recon.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, quote, urljoin, urlparse

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)


JAVASCRIPT_MEDIA_TYPES = {
    "application/javascript",
    "text/javascript",
    "application/ecmascript",
    "text/ecmascript",
    "application/x-javascript",
}
EXCLUDED_SCRIPT_TYPES = {
    "application/json",
    "application/ld+json",
    "importmap",
    "speculationrules",
    "text/template",
    "text/x-template",
}
HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
HTML_SNIFF_MARKERS = ("<!doctype html", "<html", "<head", "<body")
JAVASCRIPT_EXTENSIONS = (".js", ".mjs", ".cjs")
JAVASCRIPT_SNIFF_PREFIXES = (
    '"use strict"',
    "'use strict'",
    "const ",
    "let ",
    "var ",
    "function ",
    "class ",
    "import ",
    "export ",
    "async ",
    "(",
    "!",
    "/*",
    "//",
)
RESOURCE_SUFFIXES = (
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".json",
    ".xml",
    ".js",
    ".mjs",
    ".html",
    ".htm",
    ".txt",
    ".map",
)
MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
SAFETY_NOTES = (
    "This is offline lexical inspection of full JavaScript and inline-script bodies already collected in memory.",
    "No JavaScript was executed.",
    "No expression was evaluated.",
    "No route was requested or followed.",
    "No network request was made.",
    "Query values, URL credentials, and fragment contents are not retained.",
    "Relative strings from JavaScript responses may lack reliable browser execution context.",
    "Extracted strings are static review context, not confirmed live endpoints.",
    "Forms are not inventoried.",
    "This stage produces static manual-review context only.",
)
CANDIDATE_FORM_ORDER = {
    "absolute_http": 0,
    "absolute_https": 1,
    "scheme_relative": 2,
    "root_relative": 3,
    "dot_relative": 4,
    "parent_relative": 5,
    "path_relative": 6,
    "query_relative": 7,
}
MIME_TOP_LEVEL_TYPES = {
    "application",
    "audio",
    "font",
    "image",
    "message",
    "model",
    "multipart",
    "text",
    "video",
}
MIME_SHAPE_RE = re.compile(
    r"^(?P<top>[A-Za-z][A-Za-z0-9!#$&^_.+-]*)/"
    r"(?P<sub>[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*(?:\+[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*)*)"
    r"(?:\s*;.*)?$",
)


@dataclass(frozen=True)
class DeepJavaScriptRouteCandidate:
    """One aggregated static JavaScript route-like string candidate."""

    candidate_id: str
    safe_candidate: str
    safe_resolved_url: str | None
    path: str
    query_parameter_names: tuple[str, ...]
    candidate_forms: tuple[str, ...]
    resolution_contexts: tuple[str, ...]
    source_kinds: tuple[str, ...]
    source_response_ids: tuple[str, ...]
    source_request_urls: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    script_types: tuple[str, ...]
    occurrence_count: int
    evidence_ids: tuple[str, ...]
    interpretation: str


@dataclass(frozen=True)
class DeepJavaScriptRouteExtractionSummaryCounts:
    """Immutable summary counts for JavaScript route extraction."""

    total_collected_responses_considered: int
    javascript_responses_selected_by_content_type: int
    javascript_responses_selected_by_extension_sniff: int
    html_responses_selected_for_inline_scripts: int
    non_javascript_non_html_responses_skipped: int
    javascript_response_bodies_scanned: int
    inline_script_blocks_considered: int
    inline_javascript_blocks_scanned: int
    total_complete_string_literals_observed: int
    accepted_static_route_occurrences: int
    unique_aggregated_candidates: int
    candidates_with_safe_resolved_urls: int
    unresolved_relative_candidates_retained: int
    fragment_only_strings_skipped: int
    unsupported_scheme_strings_skipped: int
    not_route_like_strings_skipped: int
    empty_strings_skipped: int
    malformed_strings_skipped: int
    dynamic_template_strings_skipped: int
    dynamic_concatenation_strings_skipped: int
    duplicate_accepted_occurrences_aggregated: int
    html_responses_using_valid_base_url: int


@dataclass(frozen=True)
class DeepJavaScriptRouteExtractionResult:
    """Offline static JavaScript route extraction result."""

    candidates: tuple[DeepJavaScriptRouteCandidate, ...]
    summary_counts: DeepJavaScriptRouteExtractionSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _SourceScript:
    item: DeepSourceRouteCollectedItem
    source_response_id: str
    safe_source_url: str
    source_kind: str
    selection_reason: str
    script_type: str
    resolution_base: str | None
    body_text: str


@dataclass(frozen=True)
class _StringLiteral:
    value: str
    dynamic_template: bool = False
    malformed: bool = False
    dynamic_concatenation: bool = False


@dataclass(frozen=True)
class _AcceptedOccurrence:
    safe_candidate: str
    safe_resolved_url: str | None
    path: str
    query_parameter_names: tuple[str, ...]
    candidate_form: str
    resolution_context: str
    source: _SourceScript


@dataclass(frozen=True)
class _ScriptBlock:
    code: str
    script_type: str


@dataclass(frozen=True)
class _HtmlScripts:
    scripts: tuple[_ScriptBlock, ...]
    base_hrefs: tuple[str, ...]
    inline_blocks_considered: int


class _InlineScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[_ScriptBlock] = []
        self.base_hrefs: list[str] = []
        self.inline_blocks_considered = 0
        self._in_script = False
        self._script_parts: list[str] = []
        self._current_type = ""
        self._current_has_src = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        if tag_name == "base":
            self._handle_tag(tag, attrs)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script" or not self._in_script:
            return
        if not self._current_has_src and _script_type_is_javascript(self._current_type):
            self.scripts.append(
                _ScriptBlock(
                    code="".join(self._script_parts),
                    script_type=_normalise_script_type(self._current_type),
                )
            )
        self._in_script = False
        self._script_parts = []
        self._current_type = ""
        self._current_has_src = False

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attrs_by_name = {name.lower(): value for name, value in attrs if name}
        if tag_name == "base":
            value = (attrs_by_name.get("href") or "").strip()
            if value:
                self.base_hrefs.append(value)
            return
        if tag_name != "script":
            return
        if not bool((attrs_by_name.get("src") or "").strip()):
            self.inline_blocks_considered += 1
        self._in_script = True
        self._script_parts = []
        self._current_type = (attrs_by_name.get("type") or "").strip()
        self._current_has_src = bool((attrs_by_name.get("src") or "").strip())


def build_deep_javascript_route_extraction(
    collection_result: DeepSourceRouteCollectionResult,
) -> DeepJavaScriptRouteExtractionResult:
    """Extract static route-like strings from full collected JavaScript bodies."""

    scripts, selection_counts = _select_scripts(collection_result.collected)
    accepted: list[_AcceptedOccurrence] = []
    literal_count = 0
    fragment_skips = 0
    unsupported_skips = 0
    not_route_skips = 0
    empty_skips = 0
    malformed_skips = 0
    dynamic_template_skips = 0
    concat_skips = 0

    for script in scripts:
        for literal in _scan_javascript_strings(script.body_text):
            if literal.dynamic_template:
                dynamic_template_skips += 1
                continue
            if literal.malformed:
                malformed_skips += 1
                continue
            literal_count += 1
            value = literal.value.strip()
            if not value:
                empty_skips += 1
                continue
            if literal.dynamic_concatenation:
                concat_skips += 1
                continue
            candidate_form = _candidate_form(value)
            if candidate_form == "fragment_only":
                fragment_skips += 1
                continue
            if candidate_form == "unsupported_scheme":
                unsupported_skips += 1
                continue
            if candidate_form == "not_route_like":
                not_route_skips += 1
                continue
            occurrence = _accepted_occurrence(script, value, candidate_form)
            if occurrence is None:
                malformed_skips += 1
                continue
            accepted.append(occurrence)

    candidates = _build_candidates(accepted)
    counts = DeepJavaScriptRouteExtractionSummaryCounts(
        total_collected_responses_considered=len(collection_result.collected),
        javascript_responses_selected_by_content_type=selection_counts["js_content_type"],
        javascript_responses_selected_by_extension_sniff=selection_counts["js_extension_sniff"],
        html_responses_selected_for_inline_scripts=selection_counts["html"],
        non_javascript_non_html_responses_skipped=selection_counts["skipped"],
        javascript_response_bodies_scanned=selection_counts["js_bodies_scanned"],
        inline_script_blocks_considered=selection_counts["inline_blocks_considered"],
        inline_javascript_blocks_scanned=selection_counts["inline_blocks_scanned"],
        total_complete_string_literals_observed=literal_count,
        accepted_static_route_occurrences=len(accepted),
        unique_aggregated_candidates=len(candidates),
        candidates_with_safe_resolved_urls=sum(1 for item in candidates if item.safe_resolved_url),
        unresolved_relative_candidates_retained=sum(1 for item in candidates if not item.safe_resolved_url),
        fragment_only_strings_skipped=fragment_skips,
        unsupported_scheme_strings_skipped=unsupported_skips,
        not_route_like_strings_skipped=not_route_skips,
        empty_strings_skipped=empty_skips,
        malformed_strings_skipped=malformed_skips,
        dynamic_template_strings_skipped=dynamic_template_skips,
        dynamic_concatenation_strings_skipped=concat_skips,
        duplicate_accepted_occurrences_aggregated=max(0, len(accepted) - len(candidates)),
        html_responses_using_valid_base_url=selection_counts["html_base_used"],
    )
    return DeepJavaScriptRouteExtractionResult(
        candidates=candidates,
        summary_counts=counts,
        safety_notes=SAFETY_NOTES,
    )


def render_deep_javascript_route_extraction_markdown(
    result: DeepJavaScriptRouteExtractionResult,
) -> str:
    """Render JavaScript route extraction as terminal-friendly Markdown."""

    counts = result.summary_counts
    lines = [
        "## Deep JavaScript Route Extraction",
        "",
        "This is offline lexical inspection of full JavaScript and inline-script bodies already collected in memory.",
        "",
        "### Summary",
        "",
        f"- Collected responses considered: {counts.total_collected_responses_considered}",
        f"- JavaScript responses selected by Content-Type: {counts.javascript_responses_selected_by_content_type}",
        f"- JavaScript responses selected by extension/sniff: {counts.javascript_responses_selected_by_extension_sniff}",
        f"- HTML responses selected for inline scripts: {counts.html_responses_selected_for_inline_scripts}",
        f"- Non-JavaScript/non-HTML responses skipped: {counts.non_javascript_non_html_responses_skipped}",
        f"- JavaScript response bodies scanned: {counts.javascript_response_bodies_scanned}",
        f"- Inline script blocks considered: {counts.inline_script_blocks_considered}",
        f"- Inline JavaScript blocks scanned: {counts.inline_javascript_blocks_scanned}",
        f"- Complete string literals observed: {counts.total_complete_string_literals_observed}",
        f"- Accepted static route occurrences: {counts.accepted_static_route_occurrences}",
        f"- Unique aggregated candidates: {counts.unique_aggregated_candidates}",
        f"- Candidates with safe resolved URLs: {counts.candidates_with_safe_resolved_urls}",
        f"- Unresolved relative candidates retained: {counts.unresolved_relative_candidates_retained}",
        f"- Fragment-only strings skipped: {counts.fragment_only_strings_skipped}",
        f"- Unsupported-scheme strings skipped: {counts.unsupported_scheme_strings_skipped}",
        f"- Not-route-like strings skipped: {counts.not_route_like_strings_skipped}",
        f"- Empty strings skipped: {counts.empty_strings_skipped}",
        f"- Malformed strings skipped: {counts.malformed_strings_skipped}",
        f"- Dynamic template strings skipped: {counts.dynamic_template_strings_skipped}",
        f"- Dynamic concatenation strings skipped: {counts.dynamic_concatenation_strings_skipped}",
        "- Duplicate accepted occurrences aggregated: "
        f"{counts.duplicate_accepted_occurrences_aggregated}",
        f"- HTML responses using a valid base URL: {counts.html_responses_using_valid_base_url}",
        "",
        "### Extracted Static JavaScript Route Candidates",
        "",
    ]
    if result.candidates:
        for candidate in result.candidates:
            lines.extend(_render_candidate(candidate))
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Extraction Interpretation Notes",
            "",
            "- Static route-like string observed in collected JavaScript source.",
            "- Relative JavaScript route candidates are retained without assuming browser execution context.",
            "- Extracted strings are static review context, not confirmed live endpoints.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in result.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _select_scripts(
    items: tuple[DeepSourceRouteCollectedItem, ...],
) -> tuple[tuple[_SourceScript, ...], dict[str, int]]:
    scripts: list[_SourceScript] = []
    counts = {
        "js_content_type": 0,
        "js_extension_sniff": 0,
        "html": 0,
        "skipped": 0,
        "js_bodies_scanned": 0,
        "inline_blocks_considered": 0,
        "inline_blocks_scanned": 0,
        "html_base_used": 0,
    }
    for index, item in enumerate(sorted(items, key=_source_sort_key), start=1):
        if not item.body:
            counts["skipped"] += 1
            continue
        body_text = item.body.decode("utf-8", errors="replace")
        media = _media_type(_header_value(item, "content-type"))
        safe_source_url = _safe_url(item.url)
        source_response_id = f"DEEP-JS-SRC-{index:04d}"
        if media in JAVASCRIPT_MEDIA_TYPES:
            counts["js_content_type"] += 1
            counts["js_bodies_scanned"] += 1
            scripts.append(
                _SourceScript(
                    item=item,
                    source_response_id=source_response_id,
                    safe_source_url=safe_source_url,
                    source_kind="javascript_response",
                    selection_reason="javascript_content_type",
                    script_type=media,
                    resolution_base=item.url,
                    body_text=body_text,
                )
            )
            continue
        if _content_type_allows_sniff(media) and _has_javascript_extension(item.url) and _sniffs_like_javascript(body_text):
            counts["js_extension_sniff"] += 1
            counts["js_bodies_scanned"] += 1
            scripts.append(
                _SourceScript(
                    item=item,
                    source_response_id=source_response_id,
                    safe_source_url=safe_source_url,
                    source_kind="javascript_response",
                    selection_reason="javascript_extension_and_body_sniff",
                    script_type="extension_sniff",
                    resolution_base=item.url,
                    body_text=body_text,
                )
            )
            continue
        if media in HTML_MEDIA_TYPES or (_content_type_allows_sniff(media) and _sniffs_like_html(body_text)):
            counts["html"] += 1
            parsed = _parse_inline_scripts(body_text)
            base_url, base_used = _html_resolution_base(item.url, parsed.base_hrefs)
            if base_used:
                counts["html_base_used"] += 1
            counts["inline_blocks_considered"] += parsed.inline_blocks_considered
            for block in parsed.scripts:
                counts["inline_blocks_scanned"] += 1
                scripts.append(
                    _SourceScript(
                        item=item,
                        source_response_id=source_response_id,
                        safe_source_url=safe_source_url,
                        source_kind="html_inline_script",
                        selection_reason="html_inline_script",
                        script_type=block.script_type,
                        resolution_base=base_url,
                        body_text=block.code,
                    )
                )
            continue
        counts["skipped"] += 1
    return tuple(scripts), counts


def _scan_javascript_strings(source: str) -> tuple[_StringLiteral, ...]:
    literals: list[_StringLiteral] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        next_char = source[index + 1] if index + 1 < length else ""
        if char == "/" and next_char == "/":
            index = _skip_line_comment(source, index + 2)
            continue
        if char == "/" and next_char == "*":
            index = _skip_block_comment(source, index + 2)
            continue
        if char == "/" and _looks_like_regex_start(source, index):
            index = _skip_regex_literal(source, index + 1)
            continue
        if char in {"'", '"', "`"}:
            literal, index = _read_string_literal(source, index)
            literals.append(literal)
            continue
        index += 1
    return tuple(literals)


def _read_string_literal(source: str, start: int) -> tuple[_StringLiteral, int]:
    quote_char = source[start]
    index = start + 1
    chars: list[str] = []
    dynamic_template = False
    malformed = False
    while index < len(source):
        char = source[index]
        if quote_char == "`" and char == "$" and index + 1 < len(source) and source[index + 1] == "{":
            dynamic_template = True
        if char == quote_char:
            value = "".join(chars)
            return (
                _StringLiteral(
                    value=value,
                    dynamic_template=dynamic_template,
                    malformed=malformed,
                    dynamic_concatenation=_is_concatenated(source, start, index + 1),
                ),
                index + 1,
            )
        if char == "\\":
            decoded, index, bad = _decode_escape(source, index)
            malformed = malformed or bad
            chars.append(decoded)
            continue
        if quote_char != "`" and char in {"\n", "\r"}:
            return _StringLiteral(value="", malformed=True), index + 1
        chars.append(char)
        index += 1
    return _StringLiteral(value="", malformed=True), len(source)


def _decode_escape(source: str, index: int) -> tuple[str, int, bool]:
    if index + 1 >= len(source):
        return "", index + 1, True
    char = source[index + 1]
    if char in {"\n", "\r"}:
        if char == "\r" and index + 2 < len(source) and source[index + 2] == "\n":
            return "", index + 3, True
        return "", index + 2, True
    simple = {
        "\\": "\\",
        "/": "/",
        "'": "'",
        '"': '"',
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
    }
    if char in simple:
        return simple[char], index + 2, False
    if char == "x":
        if index + 3 >= len(source):
            return "", len(source), True
        value = source[index + 2 : index + 4]
        if _is_hex(value):
            return chr(int(value, 16)), index + 4, False
        return "", index + 4, True
    if char == "u":
        if index + 5 >= len(source):
            return "", len(source), True
        value = source[index + 2 : index + 6]
        if _is_hex(value):
            return chr(int(value, 16)), index + 6, False
        return "", index + 6, True
    return "", index + 2, True


def _is_hex(value: str) -> bool:
    return bool(value) and all(char in "0123456789abcdefABCDEF" for char in value)


def _accepted_occurrence(
    script: _SourceScript,
    value: str,
    candidate_form: str,
) -> _AcceptedOccurrence | None:
    safe_candidate = _safe_candidate(value)
    parsed_candidate = urlparse(safe_candidate)
    resolution_context = _resolution_context(script, candidate_form)
    resolved = _resolve_candidate(script, value, candidate_form, resolution_context)
    safe_resolved = _safe_url(resolved) if resolved else None
    if resolved and safe_resolved == "unresolved":
        return None
    safe_for_path = safe_resolved or safe_candidate
    parsed_safe = urlparse(safe_for_path)
    return _AcceptedOccurrence(
        safe_candidate=safe_candidate,
        safe_resolved_url=safe_resolved,
        path=parsed_safe.path or parsed_candidate.path or "/",
        query_parameter_names=_query_names(parsed_safe.query or parsed_candidate.query),
        candidate_form=candidate_form,
        resolution_context=resolution_context,
        source=script,
    )


def _build_candidates(
    accepted: list[_AcceptedOccurrence],
) -> tuple[DeepJavaScriptRouteCandidate, ...]:
    grouped: dict[tuple[str, str, str], list[_AcceptedOccurrence]] = {}
    for occurrence in accepted:
        grouped.setdefault(
            (
                occurrence.safe_candidate,
                occurrence.safe_resolved_url or "",
                occurrence.resolution_context,
            ),
            [],
        ).append(occurrence)

    pending: list[DeepJavaScriptRouteCandidate] = []
    for (_candidate, _resolved, _context), values in grouped.items():
        first = sorted(values, key=_occurrence_sort_key)[0]
        pending.append(
            DeepJavaScriptRouteCandidate(
                candidate_id="",
                safe_candidate=first.safe_candidate,
                safe_resolved_url=first.safe_resolved_url,
                path=first.path,
                query_parameter_names=first.query_parameter_names,
                candidate_forms=_sort_candidate_forms([item.candidate_form for item in values]),
                resolution_contexts=_unique_sorted([item.resolution_context for item in values]),
                source_kinds=_unique_sorted([item.source.source_kind for item in values]),
                source_response_ids=_unique_sorted([item.source.source_response_id for item in values]),
                source_request_urls=_unique_sorted([item.source.safe_source_url for item in values]),
                source_collection_sections=_unique_sorted([item.source.item.source for item in values]),
                source_selection_reasons=_unique_sorted([item.source.selection_reason for item in values]),
                script_types=_unique_sorted([item.source.script_type for item in values if item.source.script_type]),
                occurrence_count=len(values),
                evidence_ids=_unique_sorted(
                    [
                        evidence_id
                        for item in values
                        for evidence_id in item.source.item.evidence_ids
                    ]
                ),
                interpretation=_interpretation(first),
            )
        )

    ordered = sorted(pending, key=_candidate_sort_key)
    return tuple(
        DeepJavaScriptRouteCandidate(
            candidate_id=f"DEEP-JS-ROUTE-{index:04d}",
            safe_candidate=candidate.safe_candidate,
            safe_resolved_url=candidate.safe_resolved_url,
            path=candidate.path,
            query_parameter_names=candidate.query_parameter_names,
            candidate_forms=candidate.candidate_forms,
            resolution_contexts=candidate.resolution_contexts,
            source_kinds=candidate.source_kinds,
            source_response_ids=candidate.source_response_ids,
            source_request_urls=candidate.source_request_urls,
            source_collection_sections=candidate.source_collection_sections,
            source_selection_reasons=candidate.source_selection_reasons,
            script_types=candidate.script_types,
            occurrence_count=candidate.occurrence_count,
            evidence_ids=candidate.evidence_ids,
            interpretation=candidate.interpretation,
        )
        for index, candidate in enumerate(ordered, start=1)
    )


def _render_candidate(candidate: DeepJavaScriptRouteCandidate) -> list[str]:
    lines = [
        f"#### {candidate.candidate_id} - Static JavaScript route candidate",
        "",
        f"- Candidate: `{_compact_single(candidate.safe_candidate)}`",
    ]
    if candidate.safe_resolved_url:
        lines.append(f"- Resolved URL: `{_compact_single(candidate.safe_resolved_url)}`")
    lines.extend(
        [
            f"- Path: `{_compact_single(candidate.path)}`",
            "- Query parameter names: " + _format_compact_values(candidate.query_parameter_names),
            "- Candidate forms: " + _format_compact_values(candidate.candidate_forms),
            "- Resolution contexts: " + _format_compact_values(candidate.resolution_contexts),
            "- Source kinds: " + _format_compact_values(candidate.source_kinds),
            "- Source responses: " + _format_compact_values(candidate.source_response_ids),
            "- Source request URLs: " + _format_compact_values(candidate.source_request_urls),
            "- Source sections: " + _format_compact_values(candidate.source_collection_sections),
            "- Source selection: " + _format_compact_values(candidate.source_selection_reasons),
            "- Script types: " + _format_compact_values(candidate.script_types),
            f"- Occurrences: `{candidate.occurrence_count}`",
        ]
    )
    if candidate.evidence_ids:
        lines.append("- Evidence: " + _format_compact_values(candidate.evidence_ids))
    lines.extend([f"- Interpretation: {candidate.interpretation}", ""])
    return lines


def _parse_inline_scripts(body_text: str) -> _HtmlScripts:
    parser = _InlineScriptParser()
    try:
        parser.feed(body_text)
        parser.close()
    except Exception:
        return _HtmlScripts(scripts=(), base_hrefs=(), inline_blocks_considered=0)
    return _HtmlScripts(
        scripts=tuple(parser.scripts),
        base_hrefs=tuple(parser.base_hrefs),
        inline_blocks_considered=parser.inline_blocks_considered,
    )


def _html_resolution_base(item_url: str, base_hrefs: tuple[str, ...]) -> tuple[str, bool]:
    for base_href in base_hrefs:
        resolved = _resolved_valid_base(item_url, base_href)
        if resolved is not None:
            return resolved, True
    return item_url, False


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


def _script_type_is_javascript(script_type: str) -> bool:
    normalised = _normalise_script_type(script_type)
    if not normalised or normalised == "module":
        return True
    if normalised in EXCLUDED_SCRIPT_TYPES:
        return False
    return normalised in JAVASCRIPT_MEDIA_TYPES


def _normalise_script_type(script_type: str) -> str:
    return _media_type(script_type).lower()


def _candidate_form(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "not_route_like"
    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if stripped.startswith("//"):
        return "scheme_relative" if parsed.netloc else "unresolved"
    if scheme in {"http", "https"}:
        return f"absolute_{scheme}"
    if scheme:
        return "unsupported_scheme"
    if stripped.startswith("#"):
        return "fragment_only"
    if stripped.startswith("?"):
        return "query_relative" if _query_names(parsed.query) else "not_route_like"
    if stripped.startswith("/"):
        return "root_relative"
    if stripped.startswith("./"):
        return "dot_relative"
    if stripped.startswith("../"):
        return "parent_relative"
    if _is_bare_mime_type_shape(stripped):
        return "not_route_like"
    if "/" in stripped or _has_resource_suffix(stripped):
        return "path_relative"
    return "not_route_like"


def _is_bare_mime_type_shape(value: str) -> bool:
    match = MIME_SHAPE_RE.match(value.strip())
    if not match:
        return False
    return match.group("top").casefold() in MIME_TOP_LEVEL_TYPES


def _safe_candidate(value: str) -> str:
    form = _candidate_form(value)
    if form in {"absolute_http", "absolute_https", "scheme_relative"}:
        if form == "scheme_relative":
            safe = _safe_url("http:" + value)
            return safe.removeprefix("http:") if safe != "unresolved" else "unresolved"
        return _safe_url(value)
    if form == "query_relative":
        names = _query_names(urlparse(value).query)
        return f"?{'&'.join(names)}" if names else "?"
    parsed = urlparse(value)
    names = _query_names(parsed.query)
    query = f"?{'&'.join(names)}" if names else ""
    return f"{parsed.path or value.split('?', 1)[0]}{query}"


def _resolve_candidate(
    script: _SourceScript,
    value: str,
    candidate_form: str,
    resolution_context: str,
) -> str | None:
    if candidate_form in {"absolute_http", "absolute_https"}:
        return value
    if candidate_form == "scheme_relative":
        source_scheme = urlparse(script.item.url).scheme or "http"
        return f"{source_scheme}:{value}"
    if script.source_kind == "html_inline_script":
        return urljoin(script.resolution_base or script.item.url, value)
    if candidate_form in {"root_relative", "query_relative"}:
        return urljoin(script.item.url, value)
    return None


def _resolution_context(script: _SourceScript, candidate_form: str) -> str:
    if script.source_kind == "html_inline_script":
        if script.resolution_base and _safe_url(script.resolution_base) != _safe_url(script.item.url):
            return "html_base_url"
        return "html_document_url"
    if candidate_form in {"absolute_http", "absolute_https", "scheme_relative"}:
        return "absolute_or_scheme_relative"
    if candidate_form in {"root_relative", "query_relative"}:
        return "javascript_source_origin"
    return "execution_context_unknown"


def _interpretation(occurrence: _AcceptedOccurrence) -> str:
    if occurrence.resolution_context == "execution_context_unknown":
        return "Relative JavaScript route candidate retained without assuming browser execution context."
    return "Static route-like string observed in collected JavaScript source."


def _has_javascript_extension(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return False
    return path.endswith(JAVASCRIPT_EXTENSIONS)


def _content_type_allows_sniff(media_type: str) -> bool:
    return media_type in {"", "application/octet-stream"}


def _sniffs_like_javascript(body_text: str) -> bool:
    prefix = body_text.lstrip()[:256]
    if prefix.lower().startswith(HTML_SNIFF_MARKERS):
        return False
    lowered = prefix.lower()
    return any(lowered.startswith(value) for value in JAVASCRIPT_SNIFF_PREFIXES)


def _sniffs_like_html(body_text: str) -> bool:
    prefix = body_text.lstrip()[:512].lower()
    return any(prefix.startswith(marker) for marker in HTML_SNIFF_MARKERS)


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
    names = _query_names(parsed.query)
    query = f"?{'&'.join(names)}" if names else ""
    return f"{scheme}://{authority}{parsed.path or '/'}{query}"


def _query_names(query: str) -> tuple[str, ...]:
    return _unique_sorted(
        [
            quote(name, safe="")
            for name, _value in parse_qsl(query, keep_blank_values=True)
            if name
        ]
    )


def _has_resource_suffix(value: str) -> bool:
    path = urlparse(value).path.lower()
    return path.endswith(RESOURCE_SUFFIXES)


def _is_concatenated(source: str, start: int, end: int) -> bool:
    before = start - 1
    while before >= 0 and source[before].isspace():
        before -= 1
    after = end
    while after < len(source) and source[after].isspace():
        after += 1
    return (before >= 0 and source[before] == "+") or (
        after < len(source) and source[after] == "+"
    )


def _looks_like_regex_start(source: str, index: int) -> bool:
    before = index - 1
    while before >= 0 and source[before].isspace():
        before -= 1
    if before < 0:
        return True
    if source[before] in "([{=,:;!&|?":
        return True
    if source[before] == ">" and _previous_significant_char(source, before - 1) == "=":
        return True
    token = _previous_identifier(source, before)
    return token in {"return", "throw", "case", "yield", "await"}


def _previous_significant_char(source: str, index: int) -> str:
    while index >= 0 and source[index].isspace():
        index -= 1
    return source[index] if index >= 0 else ""


def _previous_identifier(source: str, end: int) -> str:
    if end < 0 or not (source[end].isalnum() or source[end] in {"_", "$"}):
        return ""
    start = end
    while start >= 0 and (source[start].isalnum() or source[start] in {"_", "$"}):
        start -= 1
    return source[start + 1 : end + 1]


def _skip_line_comment(source: str, index: int) -> int:
    while index < len(source) and source[index] not in "\r\n":
        index += 1
    return index


def _skip_block_comment(source: str, index: int) -> int:
    end = source.find("*/", index)
    return len(source) if end == -1 else end + 2


def _skip_regex_literal(source: str, index: int) -> int:
    in_class = False
    escaped = False
    while index < len(source):
        char = source[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            return index
        elif char in "\r\n":
            return index
        index += 1
    return index


def _source_sort_key(item: DeepSourceRouteCollectedItem) -> tuple:
    return (
        _safe_url(item.url),
        item.method,
        item.status_code,
        _safe_url(item.final_url),
        tuple(sorted((name.lower(), value) for name, value in item.headers)),
        item.body_sha256,
        item.body_bytes,
        item.source,
        item.reason,
        tuple(sorted(item.evidence_ids)),
    )


def _occurrence_sort_key(occurrence: _AcceptedOccurrence) -> tuple:
    return (
        occurrence.safe_resolved_url or "",
        occurrence.safe_candidate,
        occurrence.resolution_context,
        occurrence.source.source_response_id,
    )


def _candidate_sort_key(candidate: DeepJavaScriptRouteCandidate) -> tuple:
    return (
        0 if candidate.safe_resolved_url else 1,
        candidate.safe_resolved_url or candidate.safe_candidate,
        candidate.resolution_contexts,
        candidate.path,
        candidate.query_parameter_names,
        candidate.source_kinds,
        candidate.source_response_ids,
        candidate.evidence_ids,
    )


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


def _sort_candidate_forms(values: list[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda value: (CANDIDATE_FORM_ORDER.get(value, 99), value),
        )
    )
