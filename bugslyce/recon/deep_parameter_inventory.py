"""Offline Deep parameter-name inventory from collected evidence.

This module inventories parameter names from already collected HTML bodies,
route extraction metadata, JavaScript extraction metadata, and collected URL
metadata. It retains names only: no parameter values, response bodies, raw HTML,
network access, form submission, JavaScript execution, or Deep-mode enablement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from html.parser import HTMLParser
import unicodedata
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse

from bugslyce.recon.deep_html_route_extraction import DeepHtmlRouteExtractionResult
from bugslyce.recon.deep_javascript_route_extraction import DeepJavaScriptRouteExtractionResult
from bugslyce.recon.deep_shallow_route_followup import DeepShallowRouteFollowupResult
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult


MAX_PARAMETER_NAME_CHARS = 256
HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
SNIFFABLE_MEDIA_TYPES = {"", "application/octet-stream"}
HTML_SNIFF_MARKERS = ("<!doctype html", "<html", "<head", "<body")
MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
INPUT_TYPES = {
    "text",
    "search",
    "email",
    "url",
    "tel",
    "password",
    "hidden",
    "file",
    "checkbox",
    "radio",
    "number",
    "range",
    "date",
    "datetime-local",
    "month",
    "week",
    "time",
    "color",
    "submit",
    "reset",
    "button",
    "image",
}
BUTTON_TYPES = {"submit", "reset", "button"}
CONTEXT_ORDER = {
    "form_control": 0,
    "form_action_query": 1,
    "html_route_query": 2,
    "javascript_route_query": 3,
    "source_requested_url_query": 4,
    "source_final_url_query": 5,
    "shallow_observed_query": 6,
    "shallow_final_url_query": 7,
}
SAFETY_NOTES = (
    "This is offline inventory from already collected evidence and existing extraction models.",
    "No network request was made.",
    "No form was submitted.",
    "No form action was fetched.",
    "No JavaScript was executed.",
    "No parameter value was retained.",
    "No parameter value was replayed, guessed, or invented.",
    "No parameter was mutated.",
    "Parameter names are static review context, not confirmed vulnerabilities.",
    "Names may be case-sensitive and were not case-folded.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepParameterInventoryItem:
    """One aggregated parameter-name inventory item."""

    parameter_id: str
    name: str
    contexts: tuple[str, ...]
    control_tags: tuple[str, ...]
    control_types: tuple[str, ...]
    form_methods: tuple[str, ...]
    form_enctypes: tuple[str, ...]
    form_target_kinds: tuple[str, ...]
    safe_form_action_urls: tuple[str, ...]
    safe_route_urls: tuple[str, ...]
    javascript_candidate_references: tuple[str, ...]
    action_resolution_contexts: tuple[str, ...]
    route_origin_relationships: tuple[str, ...]
    javascript_resolution_contexts: tuple[str, ...]
    javascript_candidate_forms: tuple[str, ...]
    javascript_script_types: tuple[str, ...]
    required_occurrences: int
    disabled_occurrences: int
    enabled_occurrences: int
    password_control_occurrences: int
    file_control_occurrences: int
    hidden_control_occurrences: int
    occurrence_count: int
    source_kinds: tuple[str, ...]
    source_ids: tuple[str, ...]
    source_response_ids: tuple[str, ...]
    source_request_ids: tuple[str, ...]
    safe_source_urls: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation: str


@dataclass(frozen=True)
class DeepParameterInventorySkippedItem:
    """Bounded parameter-name inventory skip."""

    source_kind: str
    source_id: str
    context: str
    reason: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepParameterInventorySummaryCounts:
    """Immutable summary counts for parameter-name inventory."""

    source_collection_responses_considered: int
    shallow_followup_responses_considered: int
    source_collection_html_responses_scanned: int
    shallow_followup_html_responses_scanned: int
    empty_bodies_skipped: int
    explicit_non_html_responses_skipped: int
    sniffable_non_html_responses_skipped: int
    form_occurrences_parsed: int
    named_form_controls_observed: int
    unnamed_form_controls_ignored: int
    controls_outside_forms_ignored: int
    disabled_named_controls_observed: int
    form_action_query_name_observations: int
    html_route_query_name_observations: int
    javascript_route_query_name_observations: int
    source_requested_url_observations: int
    source_final_url_observations: int
    shallow_observed_query_name_observations: int
    shallow_final_url_observations: int
    total_parameter_name_occurrences: int
    unique_parameters: int
    duplicate_observations_aggregated: int
    unique_form_control_parameters: int
    unique_url_query_only_parameters: int
    unique_parameters_observed_in_multiple_contexts: int
    unique_password_control_parameters: int
    unique_file_control_parameters: int
    unique_hidden_control_parameters: int
    empty_names_skipped: int
    overlong_names_skipped: int
    invalid_names_skipped: int


@dataclass(frozen=True)
class DeepParameterInventoryResult:
    """Offline Deep parameter-name inventory result."""

    parameters: tuple[DeepParameterInventoryItem, ...]
    skipped: tuple[DeepParameterInventorySkippedItem, ...]
    summary_counts: DeepParameterInventorySummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _Source:
    source_kind: str
    source_id: str
    method: str
    raw_requested_url: str = field(repr=False)
    raw_final_url: str = field(repr=False)
    safe_requested_url: str
    safe_final_url: str
    safe_document_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body_sha256: str
    body_bytes: int
    source_collection_section: str
    source_selection_reason: str
    source_request_id: str
    source_route_candidate_ids: tuple[str, ...]
    shallow_query_parameter_names: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class _Observation:
    name: str
    context: str
    occurrence_count: int
    control_tag: str = ""
    control_type: str = ""
    form_method: str = ""
    form_enctype: str = ""
    form_target_kind: str = ""
    safe_form_action_url: str = ""
    safe_route_url: str = ""
    javascript_candidate_reference: str = ""
    action_resolution_context: str = ""
    route_origin_relationship: str = ""
    javascript_resolution_contexts: tuple[str, ...] = ()
    javascript_candidate_forms: tuple[str, ...] = ()
    javascript_script_types: tuple[str, ...] = ()
    required: bool = False
    disabled: bool = False
    source_kind: str = ""
    source_id: str = ""
    source_response_ids: tuple[str, ...] = ()
    source_request_ids: tuple[str, ...] = ()
    safe_source_urls: tuple[str, ...] = ()
    source_collection_sections: tuple[str, ...] = ()
    source_selection_reasons: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(repr=False)
class _OpenForm:
    action: str
    action_present: bool
    method: str
    enctype: str
    target: str
    flags: set[str]


@dataclass(frozen=True)
class _ParsedForm:
    action_query_names: tuple[str, ...]
    action_query_skip_reasons: tuple[str, ...]
    safe_resolved_action_url: str | None
    action_resolution_context: str
    method: str
    enctype: str
    target_kind: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedControl:
    name: str
    tag: str
    control_type: str
    required: bool
    disabled: bool
    form: _ParsedForm


@dataclass(frozen=True)
class _ParsedHtml:
    forms: tuple[_ParsedForm, ...]
    controls: tuple[_ParsedControl, ...]
    unnamed_controls: int
    empty_parameter_names: int
    controls_outside_forms: int


class _ParameterHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_hrefs: list[str] = []
        self.forms: list[_OpenForm] = []
        self.controls: list[tuple[_OpenForm, str, dict[str, str]]] = []
        self.unnamed_controls = 0
        self.empty_parameter_names = 0
        self.controls_outside_forms = 0
        self._current: _OpenForm | None = None
        self._script_depth = 0
        self._style_depth = 0
        self._template_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_start(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_start(tag, attrs, self_closing=True)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        if tag_name == "script" and self._script_depth:
            self._script_depth -= 1
            return
        if tag_name == "style" and self._style_depth:
            self._style_depth -= 1
            return
        if tag_name == "template" and self._template_depth:
            self._template_depth -= 1
            return
        if self._script_depth or self._style_depth or self._template_depth:
            return
        if tag_name == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self) -> None:
        super().close()
        if self._current is not None:
            self._current.flags.add("unterminated_form")
            self.forms.append(self._current)
            self._current = None

    def _handle_start(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
        *,
        self_closing: bool = False,
    ) -> None:
        tag_name = tag.lower()
        attrs_by_name = _attrs_by_name(attrs)
        if tag_name == "script":
            self._script_depth += 0 if self_closing else 1
            return
        if tag_name == "style":
            self._style_depth += 0 if self_closing else 1
            return
        if tag_name == "template":
            self._template_depth += 0 if self_closing else 1
            return
        if self._script_depth or self._style_depth or self._template_depth:
            return
        if tag_name == "base":
            value = (attrs_by_name.get("href") or "").strip()
            if value:
                self.base_hrefs.append(value)
            return
        if tag_name == "form":
            if self._current is not None:
                self._current.flags.add("nested_form_start")
                self.forms.append(self._current)
            self._current = _OpenForm(
                action=attrs_by_name.get("action") or "",
                action_present="action" in attrs_by_name,
                method=attrs_by_name.get("method") or "",
                enctype=attrs_by_name.get("enctype") or "",
                target=attrs_by_name.get("target") or "",
                flags=set(),
            )
            if self_closing:
                self.forms.append(self._current)
                self._current = None
            return
        if tag_name in {"input", "select", "textarea", "button"}:
            if self._current is None:
                self.controls_outside_forms += 1
                return
            if "name" in attrs_by_name and _ascii_edge_trim(attrs_by_name.get("name") or ""):
                self.controls.append((self._current, tag_name, attrs_by_name))
            elif "name" in attrs_by_name:
                self.empty_parameter_names += 1
            else:
                self.unnamed_controls += 1


def build_deep_parameter_inventory(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
) -> DeepParameterInventoryResult:
    """Build a deterministic offline parameter-name inventory."""

    sources = _canonical_sources(source_collection, shallow_followups)
    observations: list[_Observation] = []
    skipped: list[DeepParameterInventorySkippedItem] = []
    empty_skips = 0
    explicit_non_html_skips = 0
    sniffable_non_html_skips = 0
    source_html_scanned = 0
    shallow_html_scanned = 0
    form_count = 0
    unnamed_controls = 0
    controls_outside = 0

    for source in sources:
        observations.extend(_url_query_observations(source, skipped))
        if not source.body:
            empty_skips += 1
            continue
        media = _media_type(_header_value(source.headers, "content-type"))
        body_text = source.body.decode("utf-8", errors="replace")
        if media in HTML_MEDIA_TYPES:
            pass
        elif media in SNIFFABLE_MEDIA_TYPES:
            if not _sniffs_like_html(body_text):
                sniffable_non_html_skips += 1
                continue
        else:
            explicit_non_html_skips += 1
            continue
        if source.source_kind == "source_route_collection":
            source_html_scanned += 1
        else:
            shallow_html_scanned += 1
        parsed = _parse_html(source, body_text, skipped)
        form_count += len(parsed.forms)
        unnamed_controls += parsed.unnamed_controls
        controls_outside += parsed.controls_outside_forms
        observations.extend(_form_observations(source, parsed, skipped))

    observations.extend(_html_route_observations(html_extraction, skipped))
    observations.extend(_javascript_route_observations(javascript_extraction, skipped))
    parameters = _aggregate_observations(observations)
    skipped_items = tuple(sorted(skipped, key=lambda item: (item.source_kind, item.source_id, item.context, item.reason, item.evidence_ids)))
    counts = _summary_counts(
        source_collection,
        shallow_followups,
        observations,
        parameters,
        empty_skips,
        explicit_non_html_skips,
        sniffable_non_html_skips,
        source_html_scanned,
        shallow_html_scanned,
        form_count,
        unnamed_controls,
        controls_outside,
        skipped_items,
    )
    return DeepParameterInventoryResult(
        parameters=parameters,
        skipped=skipped_items,
        summary_counts=counts,
        safety_notes=SAFETY_NOTES,
    )


def render_deep_parameter_inventory_markdown(result: DeepParameterInventoryResult) -> str:
    """Render a Deep parameter-name inventory result as Markdown."""

    counts = result.summary_counts
    lines = [
        "## Deep Parameter Inventory",
        "",
        "This is offline inventory from already collected evidence and existing extraction models.",
        "",
        "### Summary",
        "",
        f"- Source-collection responses considered: {counts.source_collection_responses_considered}",
        f"- Shallow-follow-up responses considered: {counts.shallow_followup_responses_considered}",
        f"- Source-collection HTML responses scanned: {counts.source_collection_html_responses_scanned}",
        f"- Shallow-follow-up HTML responses scanned: {counts.shallow_followup_html_responses_scanned}",
        f"- Empty bodies skipped: {counts.empty_bodies_skipped}",
        f"- Explicit non-HTML responses skipped: {counts.explicit_non_html_responses_skipped}",
        f"- Sniffable non-HTML responses skipped: {counts.sniffable_non_html_responses_skipped}",
        f"- Form occurrences parsed: {counts.form_occurrences_parsed}",
        f"- Named form controls observed: {counts.named_form_controls_observed}",
        f"- Unnamed form controls ignored: {counts.unnamed_form_controls_ignored}",
        f"- Controls outside forms ignored: {counts.controls_outside_forms_ignored}",
        f"- Disabled named controls observed: {counts.disabled_named_controls_observed}",
        f"- Form-action query-name observations: {counts.form_action_query_name_observations}",
        f"- HTML-route query-name observations: {counts.html_route_query_name_observations}",
        f"- JavaScript-route query-name observations: {counts.javascript_route_query_name_observations}",
        f"- Source requested-URL observations: {counts.source_requested_url_observations}",
        f"- Source final-URL observations: {counts.source_final_url_observations}",
        f"- Shallow observed query-name observations: {counts.shallow_observed_query_name_observations}",
        f"- Shallow final-URL observations: {counts.shallow_final_url_observations}",
        f"- Total parameter-name occurrences: {counts.total_parameter_name_occurrences}",
        f"- Unique parameters: {counts.unique_parameters}",
        f"- Duplicate observations aggregated: {counts.duplicate_observations_aggregated}",
        f"- Unique form-control parameters: {counts.unique_form_control_parameters}",
        f"- Unique URL/query-only parameters: {counts.unique_url_query_only_parameters}",
        f"- Unique multi-context parameters: {counts.unique_parameters_observed_in_multiple_contexts}",
        f"- Unique password-control parameters: {counts.unique_password_control_parameters}",
        f"- Unique file-control parameters: {counts.unique_file_control_parameters}",
        f"- Unique hidden-control parameters: {counts.unique_hidden_control_parameters}",
        f"- Empty names skipped: {counts.empty_names_skipped}",
        f"- Overlong names skipped: {counts.overlong_names_skipped}",
        f"- Invalid names skipped: {counts.invalid_names_skipped}",
        "",
        "### Parameters",
        "",
    ]
    if result.parameters:
        for parameter in result.parameters:
            lines.extend(_render_parameter(parameter))
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Inventory Interpretation Notes",
            "",
            "- Parameter name observed in already collected static evidence; no value was retained, replayed, guessed, or mutated.",
            "- Occurrence counts count one unique query name per URL or form-action occurrence.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in result.safety_notes)
    return "\n".join(lines).rstrip()


def _canonical_sources(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
) -> tuple[_Source, ...]:
    pending: list[_Source] = []
    for item in source_collection.collected:
        pending.append(
            _Source(
                source_kind="source_route_collection",
                source_id="",
                method=item.method.upper(),
                raw_requested_url=item.url,
                raw_final_url=item.final_url,
                safe_requested_url=_safe_url(item.url),
                safe_final_url=_safe_url(item.final_url),
                safe_document_url=_canonical_document_url(item.final_url, item.url),
                status_code=item.status_code,
                headers=_canonical_headers(item.headers),
                body_sha256=sha256(item.body).hexdigest(),
                body_bytes=len(item.body),
                source_collection_section=item.source,
                source_selection_reason=item.reason,
                source_request_id="",
                source_route_candidate_ids=(),
                shallow_query_parameter_names=(),
                evidence_ids=_unique_sorted(item.evidence_ids),
                body=item.body,
            )
        )
    for item in shallow_followups.collected:
        safe_requested_url = _safe_shallow_requested_url(item.requested_url)
        safe_final_url = _safe_url(item.final_url)
        pending.append(
            _Source(
                source_kind="shallow_route_followup",
                source_id="",
                method=item.method.upper(),
                raw_requested_url=item.requested_url,
                raw_final_url=item.final_url,
                safe_requested_url=safe_requested_url,
                safe_final_url=safe_final_url,
                safe_document_url=safe_final_url if safe_final_url != "unresolved" else safe_requested_url,
                status_code=item.status_code,
                headers=_canonical_headers(item.headers),
                body_sha256=sha256(item.body).hexdigest(),
                body_bytes=len(item.body),
                source_collection_section="",
                source_selection_reason="shallow_route_followup",
                source_request_id=item.request_id,
                source_route_candidate_ids=_unique_sorted(item.source_route_candidate_ids),
                shallow_query_parameter_names=_unique_sorted(item.query_parameter_names),
                evidence_ids=_unique_sorted(item.evidence_ids),
                body=item.body,
            )
        )
    ordered = sorted(pending, key=_source_sort_key)
    return tuple(_source_with_id(source, index) for index, source in enumerate(ordered, start=1))


def _source_with_id(source: _Source, index: int) -> _Source:
    return _Source(
        source_kind=source.source_kind,
        source_id=f"DEEP-PARAM-SOURCE-{index:04d}",
        method=source.method,
        raw_requested_url=source.raw_requested_url,
        raw_final_url=source.raw_final_url,
        safe_requested_url=source.safe_requested_url,
        safe_final_url=source.safe_final_url,
        safe_document_url=source.safe_document_url,
        status_code=source.status_code,
        headers=source.headers,
        body_sha256=source.body_sha256,
        body_bytes=source.body_bytes,
        source_collection_section=source.source_collection_section,
        source_selection_reason=source.source_selection_reason,
        source_request_id=source.source_request_id,
        source_route_candidate_ids=source.source_route_candidate_ids,
        shallow_query_parameter_names=source.shallow_query_parameter_names,
        evidence_ids=source.evidence_ids,
        body=source.body,
    )


def _url_query_observations(source: _Source, skipped: list[DeepParameterInventorySkippedItem]) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    if source.source_kind == "source_route_collection":
        observations.extend(_query_observations_from_raw_url(source, source.raw_requested_url, source.safe_requested_url, "source_requested_url_query", skipped))
        observations.extend(_query_observations_from_raw_url(source, source.raw_final_url, source.safe_final_url, "source_final_url_query", skipped))
    else:
        if _shallow_requested_url_invalid(source.raw_requested_url):
            skipped.append(_skip(source.source_kind, source.source_id, "shallow_observed_query", "invalid_source_url", source.evidence_ids))
        source_urls = (source.safe_requested_url,) if source.safe_requested_url != "unresolved" else ()
        observations.extend(_name_observations(source, source.shallow_query_parameter_names, "shallow_observed_query", 1, skipped, metadata_names=True, safe_source_urls=source_urls))
        observations.extend(_query_observations_from_raw_url(source, source.raw_final_url, source.safe_final_url, "shallow_final_url_query", skipped))
    return tuple(observations)


def _parse_html(source: _Source, body_text: str, skipped: list[DeepParameterInventorySkippedItem]) -> _ParsedHtml:
    parser = _ParameterHtmlParser()
    try:
        parser.feed(body_text)
        parser.close()
    except Exception:
        return _ParsedHtml(forms=(), controls=(), unnamed_controls=0, empty_parameter_names=0, controls_outside_forms=0)
    document_url = source.safe_document_url
    base_url, base_used = _resolution_base(document_url, tuple(parser.base_hrefs))
    form_map: dict[int, _ParsedForm] = {}
    parsed_forms: list[_ParsedForm] = []
    for form in parser.forms:
        parsed = _parsed_form(document_url, base_url, base_used, form)
        form_map[id(form)] = parsed
        parsed_forms.append(parsed)
    controls: list[_ParsedControl] = []
    for form, tag, attrs in parser.controls:
        parsed_form = form_map.get(id(form))
        if parsed_form is None:
            continue
        canonical_name = _canonical_parameter_name(attrs.get("name") or "")
        if canonical_name is None:
            skipped.append(_skip(source.source_kind, source.source_id, "form_control", "empty_parameter_name", source.evidence_ids))
            continue
        if len(canonical_name) > MAX_PARAMETER_NAME_CHARS:
            skipped.append(_skip(source.source_kind, source.source_id, "form_control", "overlong_parameter_name", source.evidence_ids))
            continue
        controls.append(
            _ParsedControl(
                name=canonical_name,
                tag=tag,
                control_type=_control_type(tag, attrs.get("type", "")),
                required="required" in attrs,
                disabled="disabled" in attrs,
                form=parsed_form,
            )
        )
    return _ParsedHtml(
        forms=tuple(parsed_forms),
        controls=tuple(controls),
        unnamed_controls=parser.unnamed_controls,
        empty_parameter_names=parser.empty_parameter_names,
        controls_outside_forms=parser.controls_outside_forms,
    )


def _parsed_form(document_url: str, base_url: str, base_used: bool, form: _OpenForm) -> _ParsedForm:
    action = _action(document_url, base_url, form.action, form.action_present, base_used)
    return _ParsedForm(
        action_query_names=action[2],
        action_query_skip_reasons=action[5],
        safe_resolved_action_url=action[1],
        action_resolution_context=action[3],
        method=_method(form.method),
        enctype=_enctype(form.enctype),
        target_kind=_target_kind(form.target),
        flags=_unique_sorted(tuple(form.flags)),
    )


def _form_observations(
    source: _Source,
    parsed: _ParsedHtml,
    skipped: list[DeepParameterInventorySkippedItem],
) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    for _index in range(parsed.empty_parameter_names):
        skipped.append(_skip(source.source_kind, source.source_id, "form_control", "empty_parameter_name", source.evidence_ids))
    for control in parsed.controls:
        observations.append(
            _Observation(
                name=control.name,
                context="form_control",
                occurrence_count=1,
                control_tag=control.tag,
                control_type=control.control_type,
                form_method=control.form.method,
                form_enctype=control.form.enctype,
                form_target_kind=control.form.target_kind,
                safe_form_action_url=control.form.safe_resolved_action_url or "",
                action_resolution_context=control.form.action_resolution_context,
                required=control.required,
                disabled=control.disabled,
                source_kind=source.source_kind,
                source_id=source.source_id,
                source_response_ids=(source.source_id,),
                source_request_ids=(source.source_request_id,) if source.source_request_id else (),
                safe_source_urls=(source.safe_document_url,) if source.safe_document_url != "unresolved" else (),
                source_collection_sections=(source.source_collection_section,) if source.source_collection_section else (),
                source_selection_reasons=(source.source_selection_reason,) if source.source_selection_reason else (),
                evidence_ids=source.evidence_ids,
            )
        )
    for form in parsed.forms:
        for reason in form.action_query_skip_reasons:
            skipped.append(_skip(source.source_kind, source.source_id, "form_action_query", reason, source.evidence_ids))
        observations.extend(
            _name_observations(
                source,
                form.action_query_names,
                "form_action_query",
                1,
                skipped,
                safe_form_action_url=form.safe_resolved_action_url or "",
                action_resolution_context=form.action_resolution_context,
            )
        )
    return tuple(observations)


def _html_route_observations(
    html_extraction: DeepHtmlRouteExtractionResult,
    skipped: list[DeepParameterInventorySkippedItem],
) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    for route in html_extraction.routes:
        accepted, rejected = _metadata_name_results(route.query_parameter_names)
        for reason in rejected:
            skipped.append(_skip("html_route", route.route_id, "html_route_query", reason, route.evidence_ids))
        safe_route_url = _safe_url(route.safe_resolved_url)
        origin = route.origin_relationship if route.origin_relationship in {"same_origin", "cross_origin", "not_comparable"} else "other"
        for canonical in accepted:
            observations.append(
                _Observation(
                    name=canonical,
                    context="html_route_query",
                    occurrence_count=max(1, route.occurrence_count),
                    safe_route_url=safe_route_url if safe_route_url != "unresolved" else "",
                    route_origin_relationship=origin,
                    source_kind="html_route",
                    source_id=route.route_id,
                    source_response_ids=_unique_sorted(route.source_response_ids),
                    safe_source_urls=_valid_safe_urls(route.source_request_urls),
                    source_collection_sections=_unique_sorted(route.source_collection_sections),
                    source_selection_reasons=_unique_sorted(route.source_selection_reasons),
                    evidence_ids=_unique_sorted(route.evidence_ids),
                )
            )
    return tuple(observations)


def _javascript_route_observations(
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
    skipped: list[DeepParameterInventorySkippedItem],
) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    for candidate in javascript_extraction.candidates:
        accepted, rejected = _metadata_name_results(candidate.query_parameter_names)
        for reason in rejected:
            skipped.append(_skip("javascript_route", candidate.candidate_id, "javascript_route_query", reason, candidate.evidence_ids))
        safe_route_url = _safe_url(candidate.safe_resolved_url or "")
        candidate_reference = candidate.safe_candidate if candidate.safe_candidate != "unresolved" else ""
        for canonical in accepted:
            observations.append(
                _Observation(
                    name=canonical,
                    context="javascript_route_query",
                    occurrence_count=max(1, candidate.occurrence_count),
                    safe_route_url=safe_route_url if safe_route_url != "unresolved" else "",
                    javascript_candidate_reference=candidate_reference,
                    javascript_resolution_contexts=_unique_sorted(candidate.resolution_contexts),
                    javascript_candidate_forms=_unique_sorted(candidate.candidate_forms),
                    javascript_script_types=_unique_sorted(candidate.script_types),
                    source_kind="javascript_route",
                    source_id=candidate.candidate_id,
                    source_response_ids=_unique_sorted(candidate.source_response_ids),
                    safe_source_urls=_valid_safe_urls(candidate.source_request_urls),
                    source_collection_sections=_unique_sorted(candidate.source_collection_sections),
                    source_selection_reasons=_unique_sorted(candidate.source_selection_reasons),
                    evidence_ids=_unique_sorted(candidate.evidence_ids),
                )
            )
    return tuple(observations)


def _name_observations(
    source: _Source,
    names: tuple[str, ...],
    context: str,
    occurrence_count: int,
    skipped: list[DeepParameterInventorySkippedItem],
    *,
    safe_form_action_url: str = "",
    action_resolution_context: str = "",
    metadata_names: bool = False,
    safe_source_urls: tuple[str, ...] | None = None,
) -> tuple[_Observation, ...]:
    observations: list[_Observation] = []
    accepted: set[str] = set()
    rejected: set[tuple[str, str]] = set()
    for name in names:
        candidate = unquote(name) if metadata_names else name
        canonical = _canonical_parameter_name(candidate)
        fingerprint = sha256(candidate.encode("utf-8", errors="replace")).hexdigest()
        if canonical is None:
            rejected.add(("empty_parameter_name", fingerprint))
            continue
        if len(canonical) > MAX_PARAMETER_NAME_CHARS:
            rejected.add(("overlong_parameter_name", fingerprint))
            continue
        if metadata_names and _query_name_looks_like_route_path(canonical):
            rejected.add(("invalid_parameter_name", fingerprint))
            continue
        if canonical in accepted:
            continue
        accepted.add(canonical)
        observations.append(
            _Observation(
                name=canonical,
                context=context,
                occurrence_count=occurrence_count,
                safe_form_action_url=safe_form_action_url,
                action_resolution_context=action_resolution_context,
                source_kind=source.source_kind,
                source_id=source.source_id,
                source_response_ids=(source.source_id,),
                source_request_ids=(source.source_request_id,) if source.source_request_id else (),
                safe_source_urls=safe_source_urls if safe_source_urls is not None else ((source.safe_document_url,) if source.safe_document_url != "unresolved" else ()),
                source_collection_sections=(source.source_collection_section,) if source.source_collection_section else (),
                source_selection_reasons=(source.source_selection_reason,) if source.source_selection_reason else (),
                evidence_ids=source.evidence_ids,
            )
        )
    for reason, _fingerprint in sorted(rejected):
        skipped.append(_skip(source.source_kind, source.source_id, context, reason, source.evidence_ids))
    return tuple(observations)


def _query_observations_from_raw_url(
    source: _Source,
    raw_url: str,
    safe_url: str,
    context: str,
    skipped: list[DeepParameterInventorySkippedItem],
) -> tuple[_Observation, ...]:
    if safe_url == "unresolved":
        if raw_url:
            skipped.append(_skip(source.source_kind, source.source_id, context, "invalid_source_url", source.evidence_ids))
        return ()
    try:
        query = urlparse(raw_url).query
    except (TypeError, ValueError):
        skipped.append(_skip(source.source_kind, source.source_id, context, "invalid_source_url", source.evidence_ids))
        return ()
    names, reasons = _query_name_results_from_raw_query(query)
    for reason in reasons:
        skipped.append(_skip(source.source_kind, source.source_id, context, reason, source.evidence_ids))
    return _name_observations(source, names, context, 1, skipped, safe_source_urls=(safe_url,))


def _aggregate_observations(observations: list[_Observation]) -> tuple[DeepParameterInventoryItem, ...]:
    grouped: dict[str, list[_Observation]] = {}
    for observation in observations:
        grouped.setdefault(observation.name, []).append(observation)
    pending: list[DeepParameterInventoryItem] = []
    for name, group in grouped.items():
        pending.append(_parameter_item("", name, tuple(group)))
    ordered = sorted(pending, key=_parameter_sort_key)
    return tuple(_parameter_item(f"DEEP-PARAM-{index:04d}", item.name, tuple(grouped[item.name])) for index, item in enumerate(ordered, start=1))


def _parameter_item(parameter_id: str, name: str, observations: tuple[_Observation, ...]) -> DeepParameterInventoryItem:
    return DeepParameterInventoryItem(
        parameter_id=parameter_id,
        name=name,
        contexts=_ordered_contexts(tuple(obs.context for obs in observations)),
        control_tags=_unique_sorted(tuple(obs.control_tag for obs in observations if obs.control_tag)),
        control_types=_unique_sorted(tuple(obs.control_type for obs in observations if obs.control_type)),
        form_methods=_unique_sorted(tuple(obs.form_method for obs in observations if obs.form_method)),
        form_enctypes=_unique_sorted(tuple(obs.form_enctype for obs in observations if obs.form_enctype)),
        form_target_kinds=_unique_sorted(tuple(obs.form_target_kind for obs in observations if obs.form_target_kind)),
        safe_form_action_urls=_unique_sorted(tuple(obs.safe_form_action_url for obs in observations if obs.safe_form_action_url and obs.safe_form_action_url != "unresolved")),
        safe_route_urls=_unique_sorted(tuple(obs.safe_route_url for obs in observations if obs.safe_route_url and obs.safe_route_url != "unresolved")),
        javascript_candidate_references=_unique_sorted(tuple(obs.javascript_candidate_reference for obs in observations if obs.javascript_candidate_reference)),
        action_resolution_contexts=_unique_sorted(tuple(obs.action_resolution_context for obs in observations if obs.action_resolution_context)),
        route_origin_relationships=_unique_sorted(tuple(obs.route_origin_relationship for obs in observations if obs.route_origin_relationship)),
        javascript_resolution_contexts=_unique_sorted(tuple(value for obs in observations for value in obs.javascript_resolution_contexts)),
        javascript_candidate_forms=_unique_sorted(tuple(value for obs in observations for value in obs.javascript_candidate_forms)),
        javascript_script_types=_unique_sorted(tuple(value for obs in observations for value in obs.javascript_script_types)),
        required_occurrences=sum(obs.occurrence_count for obs in observations if obs.required),
        disabled_occurrences=sum(obs.occurrence_count for obs in observations if obs.disabled),
        enabled_occurrences=sum(obs.occurrence_count for obs in observations if obs.context == "form_control" and not obs.disabled),
        password_control_occurrences=sum(obs.occurrence_count for obs in observations if obs.control_type == "password"),
        file_control_occurrences=sum(obs.occurrence_count for obs in observations if obs.control_type == "file"),
        hidden_control_occurrences=sum(obs.occurrence_count for obs in observations if obs.control_type == "hidden"),
        occurrence_count=sum(obs.occurrence_count for obs in observations),
        source_kinds=_unique_sorted(tuple(obs.source_kind for obs in observations if obs.source_kind)),
        source_ids=_unique_sorted(tuple(obs.source_id for obs in observations if obs.source_id)),
        source_response_ids=_unique_sorted(tuple(value for obs in observations for value in obs.source_response_ids)),
        source_request_ids=_unique_sorted(tuple(value for obs in observations for value in obs.source_request_ids)),
        safe_source_urls=_unique_sorted(tuple(value for obs in observations for value in obs.safe_source_urls if value != "unresolved")),
        source_collection_sections=_unique_sorted(tuple(value for obs in observations for value in obs.source_collection_sections)),
        source_selection_reasons=_unique_sorted(tuple(value for obs in observations for value in obs.source_selection_reasons)),
        evidence_ids=_unique_sorted(tuple(value for obs in observations for value in obs.evidence_ids)),
        interpretation="Parameter name observed in already collected static evidence; no value was retained, replayed, guessed or mutated.",
    )


def _summary_counts(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
    observations: list[_Observation],
    parameters: tuple[DeepParameterInventoryItem, ...],
    empty_skips: int,
    explicit_non_html_skips: int,
    sniffable_non_html_skips: int,
    source_html_scanned: int,
    shallow_html_scanned: int,
    form_count: int,
    unnamed_controls: int,
    controls_outside: int,
    skipped: tuple[DeepParameterInventorySkippedItem, ...],
) -> DeepParameterInventorySummaryCounts:
    total_occurrences = sum(obs.occurrence_count for obs in observations)
    form_control_names = {param.name for param in parameters if "form_control" in param.contexts}
    url_only = tuple(param for param in parameters if "form_control" not in param.contexts)
    return DeepParameterInventorySummaryCounts(
        source_collection_responses_considered=len(source_collection.collected),
        shallow_followup_responses_considered=len(shallow_followups.collected),
        source_collection_html_responses_scanned=source_html_scanned,
        shallow_followup_html_responses_scanned=shallow_html_scanned,
        empty_bodies_skipped=empty_skips,
        explicit_non_html_responses_skipped=explicit_non_html_skips,
        sniffable_non_html_responses_skipped=sniffable_non_html_skips,
        form_occurrences_parsed=form_count,
        named_form_controls_observed=sum(obs.occurrence_count for obs in observations if obs.context == "form_control"),
        unnamed_form_controls_ignored=unnamed_controls,
        controls_outside_forms_ignored=controls_outside,
        disabled_named_controls_observed=sum(obs.occurrence_count for obs in observations if obs.context == "form_control" and obs.disabled),
        form_action_query_name_observations=sum(obs.occurrence_count for obs in observations if obs.context == "form_action_query"),
        html_route_query_name_observations=sum(obs.occurrence_count for obs in observations if obs.context == "html_route_query"),
        javascript_route_query_name_observations=sum(obs.occurrence_count for obs in observations if obs.context == "javascript_route_query"),
        source_requested_url_observations=sum(obs.occurrence_count for obs in observations if obs.context == "source_requested_url_query"),
        source_final_url_observations=sum(obs.occurrence_count for obs in observations if obs.context == "source_final_url_query"),
        shallow_observed_query_name_observations=sum(obs.occurrence_count for obs in observations if obs.context == "shallow_observed_query"),
        shallow_final_url_observations=sum(obs.occurrence_count for obs in observations if obs.context == "shallow_final_url_query"),
        total_parameter_name_occurrences=total_occurrences,
        unique_parameters=len(parameters),
        duplicate_observations_aggregated=max(0, total_occurrences - len(parameters)),
        unique_form_control_parameters=len(form_control_names),
        unique_url_query_only_parameters=len(url_only),
        unique_parameters_observed_in_multiple_contexts=sum(1 for param in parameters if len(param.contexts) > 1),
        unique_password_control_parameters=sum(1 for param in parameters if param.password_control_occurrences),
        unique_file_control_parameters=sum(1 for param in parameters if param.file_control_occurrences),
        unique_hidden_control_parameters=sum(1 for param in parameters if param.hidden_control_occurrences),
        empty_names_skipped=sum(1 for item in skipped if item.reason == "empty_parameter_name"),
        overlong_names_skipped=sum(1 for item in skipped if item.reason == "overlong_parameter_name"),
        invalid_names_skipped=sum(1 for item in skipped if item.reason == "invalid_parameter_name"),
    )


def _render_parameter(parameter: DeepParameterInventoryItem) -> list[str]:
    return [
        f"#### {parameter.parameter_id} - {_format_parameter_name(parameter.name)}",
        "",
        "- Contexts: " + _format_values(parameter.contexts),
        f"- Occurrences: `{parameter.occurrence_count}`",
        "- Control tags: " + _format_values(parameter.control_tags),
        "- Control types: " + _format_values(parameter.control_types),
        "- Form methods: " + _format_values(parameter.form_methods),
        "- Form enctypes: " + _format_values(parameter.form_enctypes),
        "- Form target kinds: " + _format_values(parameter.form_target_kinds),
        "- Safe form action URLs: " + _format_values(parameter.safe_form_action_urls),
        "- Safe route URLs: " + _format_values(parameter.safe_route_urls),
        "- JavaScript candidate references: " + _format_values(parameter.javascript_candidate_references),
        f"- Required/disabled occurrences: `{parameter.required_occurrences}` required, `{parameter.disabled_occurrences}` disabled",
        f"- Enabled occurrences: `{parameter.enabled_occurrences}`",
        "- Route origin relationships: " + _format_values(parameter.route_origin_relationships),
        "- JavaScript resolution contexts: " + _format_values(parameter.javascript_resolution_contexts),
        "- JavaScript candidate forms: " + _format_values(parameter.javascript_candidate_forms),
        "- JavaScript script types: " + _format_values(parameter.javascript_script_types),
        "- Source kinds: " + _format_values(parameter.source_kinds),
        "- Safe source URLs: " + _format_values(parameter.safe_source_urls),
        "- Source IDs: " + _format_values(parameter.source_ids),
        "- Source response IDs: " + _format_values(parameter.source_response_ids),
        "- Source request IDs: " + _format_values(parameter.source_request_ids),
        "- Collection sections: " + _format_values(parameter.source_collection_sections),
        "- Selection reasons: " + _format_values(parameter.source_selection_reasons),
        "- Evidence: " + _format_values(parameter.evidence_ids),
        f"- Interpretation: {parameter.interpretation}",
        "",
    ]


def _action(
    document_url: str,
    base_url: str,
    action: str,
    action_present: bool,
    base_used: bool,
) -> tuple[str, str | None, tuple[str, ...], str, bool, tuple[str, ...]]:
    stripped = action.strip()
    if not action_present or not stripped:
        safe = _safe_url(document_url)
        return (
            "document_url_default",
            None if safe == "unresolved" else safe,
            _query_names_from_safe_url(safe) if safe != "unresolved" else (),
            "document_url_default",
            False,
            (),
        )
    safe_reference, reason, is_absolute = _safe_reference(stripped)
    if reason is not None:
        return (reason, None, (), reason, False, ())
    try:
        resolved = urljoin(base_url, stripped)
    except (TypeError, ValueError):
        return ("malformed_action", None, (), "malformed_action", False, ())
    safe_resolved = _safe_url(resolved)
    if safe_resolved == "unresolved":
        return ("malformed_action", None, (), "malformed_action", False, ())
    used_base = base_used and not is_absolute
    context = "absolute_url" if is_absolute else ("html_base_url" if used_base else "document_url")
    try:
        raw_query = urlparse(resolved).query
    except (TypeError, ValueError):
        raw_query = ""
    names, skip_reasons = _query_name_results_from_raw_query(raw_query)
    return (safe_reference, safe_resolved, names, context, used_base, skip_reasons)


def _safe_reference(value: str) -> tuple[str, str | None, bool]:
    try:
        parsed = urlparse(value)
    except (TypeError, ValueError):
        return ("", "malformed_action", False)
    scheme = parsed.scheme.lower()
    if scheme and scheme not in {"http", "https"}:
        return ("", "unsupported_scheme", False)
    if value.startswith("//") and not parsed.netloc:
        return ("", "malformed_action", False)
    if scheme in {"http", "https"} or value.startswith("//"):
        safe = _safe_url(("http:" if value.startswith("//") else "") + value)
        if safe == "unresolved":
            return ("", "malformed_action", False)
        return (safe.removeprefix("http:") if value.startswith("//") else safe, None, scheme in {"http", "https"})
    if parsed.path == "" and parsed.query == "" and parsed.fragment:
        return ("document_url_reference", None, False)
    query_names = _query_names_from_raw_query(parsed.query)
    query = "?" + "&".join(quote(name, safe="") for name in query_names) if query_names else ""
    path = parsed.path
    return (f"{path}{query}" if path or query else "document_url_reference", None, False)


def _checked_name(
    name: str,
    context: str,
    source_kind: str,
    source_id: str,
    evidence_ids: tuple[str, ...],
    skipped: list[DeepParameterInventorySkippedItem],
) -> str | None:
    canonical = _canonical_parameter_name(name)
    if canonical is None:
        skipped.append(_skip(source_kind, source_id, context, "empty_parameter_name", evidence_ids))
        return None
    if len(canonical) > MAX_PARAMETER_NAME_CHARS:
        skipped.append(_skip(source_kind, source_id, context, "overlong_parameter_name", evidence_ids))
        return None
    return canonical


def _checked_metadata_name(
    name: str,
    context: str,
    source_kind: str,
    source_id: str,
    evidence_ids: tuple[str, ...],
    skipped: list[DeepParameterInventorySkippedItem],
) -> str | None:
    return _checked_name(unquote(name), context, source_kind, source_id, evidence_ids, skipped)


def _canonical_parameter_name(value: str) -> str | None:
    cleaned = unicodedata.normalize("NFC", _ascii_edge_trim(value))
    if not cleaned:
        return None
    result = []
    for char in cleaned:
        code = ord(char)
        if unicodedata.category(char) in {"Cc", "Cf"}:
            if code <= 0xFF:
                result.append(f"\\x{code:02x}")
            elif code <= 0xFFFF:
                result.append(f"\\u{code:04x}")
            else:
                result.append(f"\\U{code:08x}")
        elif code < 32 or code == 127:
            result.append(f"\\x{code:02x}")
        else:
            result.append(char)
    return "".join(result)


def _ascii_edge_trim(value: str) -> str:
    return value.strip(" \t\r\n\f\v")


def _resolution_base(document_url: str, base_hrefs: tuple[str, ...]) -> tuple[str, bool]:
    for base_href in base_hrefs:
        resolved = _resolved_valid_base(document_url, base_href)
        if resolved is not None:
            return resolved, True
    return document_url, False


def _resolved_valid_base(document_url: str, base_href: str) -> str | None:
    try:
        stripped = base_href.strip()
        if not stripped or stripped.startswith(":"):
            return None
        parsed = urlparse(stripped)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None
        resolved = urljoin(document_url, stripped)
        return resolved if _safe_url(resolved) != "unresolved" else None
    except (TypeError, ValueError):
        return None


def _method(value: str) -> str:
    method = value.strip().lower()
    return method if method in {"get", "post", "dialog"} else ("get" if not method else "other")


def _enctype(value: str) -> str:
    enctype = value.strip().lower()
    if not enctype:
        return "application/x-www-form-urlencoded"
    return enctype if enctype in {"application/x-www-form-urlencoded", "multipart/form-data", "text/plain"} else "other"


def _target_kind(value: str) -> str:
    target = value.strip().lower()
    if not target:
        return "none"
    return {
        "_self": "self",
        "_blank": "blank",
        "_parent": "parent",
        "_top": "top",
    }.get(target, "named")


def _control_type(tag: str, value: str) -> str:
    if tag == "input":
        control_type = value.strip().lower() or "text"
        return control_type if control_type in INPUT_TYPES else "other"
    if tag == "button":
        control_type = value.strip().lower() or "submit"
        return control_type if control_type in BUTTON_TYPES else "other_button"
    return tag


def _parameter_sort_key(parameter: DeepParameterInventoryItem) -> tuple:
    context_count = len(parameter.contexts)
    return (
        0 if "form_control" in parameter.contexts and context_count > 1 else 1,
        -context_count,
        0 if parameter.password_control_occurrences else 1,
        0 if parameter.file_control_occurrences else 1,
        0 if parameter.hidden_control_occurrences else 1,
        0 if "post" in parameter.form_methods else 1,
        0 if "form_control" in parameter.contexts else 1,
        -parameter.occurrence_count,
        parameter.name,
        parameter.source_ids,
        parameter.evidence_ids,
    )


def _source_sort_key(source: _Source) -> tuple:
    return (
        source.source_kind,
        source.method,
        source.safe_requested_url,
        source.safe_final_url,
        source.safe_document_url,
        source.status_code,
        source.headers,
        source.body_sha256,
        source.body_bytes,
        source.source_collection_section,
        source.source_selection_reason,
        source.source_request_id,
        source.source_route_candidate_ids,
        source.shallow_query_parameter_names,
        source.evidence_ids,
    )


def _attrs_by_name(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in attrs:
        lowered = name.lower() if name else ""
        if lowered and lowered not in result:
            result[lowered] = value or ""
    return result


def _media_type(content_type: str | None) -> str:
    return "" if not content_type else content_type.split(";", 1)[0].strip().lower()


def _header_value(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    wanted = name.lower()
    for header_name, value in headers:
        if header_name.lower() == wanted:
            return value
    return None


def _canonical_headers(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(name).lower(), str(value)) for name, value in headers))


def _sniffs_like_html(body_text: str) -> bool:
    prefix = body_text.lstrip()[:512].lower()
    return any(prefix.startswith(marker) for marker in HTML_SNIFF_MARKERS)


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
    names = _query_names_from_raw_query(parsed.query)
    query = "?" + "&".join(quote(name, safe="") for name in names) if names else ""
    return f"{scheme}://{authority}{parsed.path or '/'}{query}"


def _canonical_document_url(final_url: str, requested_url: str) -> str:
    safe_final = _safe_url(final_url)
    if safe_final != "unresolved":
        return safe_final
    return _safe_url(requested_url)


def _query_names_from_safe_url(safe_url: str) -> tuple[str, ...]:
    try:
        parsed = urlparse(safe_url)
    except (TypeError, ValueError):
        return ()
    return _query_names_from_raw_query(parsed.query)


def _query_names_from_raw_query(query: str) -> tuple[str, ...]:
    return _query_name_results_from_raw_query(query)[0]


def _metadata_name_results(values: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    accepted: set[str] = set()
    rejected: set[tuple[str, str]] = set()
    for value in values:
        decoded = unquote(value)
        canonical = _canonical_parameter_name(decoded)
        fingerprint = sha256(decoded.encode("utf-8", errors="replace")).hexdigest()
        if canonical is None:
            rejected.add(("empty_parameter_name", fingerprint))
        elif len(canonical) > MAX_PARAMETER_NAME_CHARS:
            rejected.add(("overlong_parameter_name", fingerprint))
        elif _query_name_looks_like_route_path(canonical):
            rejected.add(("invalid_parameter_name", fingerprint))
        else:
            accepted.add(canonical)
    return _unique_sorted(tuple(accepted)), tuple(sorted(reason for reason, _fingerprint in rejected))


def _query_name_results_from_raw_query(query: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    names: list[str] = []
    rejected: set[tuple[str, str]] = set()
    for decoded_name, _value in parse_qsl(query, keep_blank_values=True):
        canonical = _canonical_parameter_name(decoded_name)
        fingerprint = sha256(decoded_name.encode("utf-8", errors="replace")).hexdigest()
        if canonical is None:
            rejected.add(("empty_parameter_name", fingerprint))
        elif len(canonical) > MAX_PARAMETER_NAME_CHARS:
            rejected.add(("overlong_parameter_name", fingerprint))
        elif _query_name_looks_like_route_path(canonical):
            rejected.add(("invalid_parameter_name", fingerprint))
        else:
            names.append(canonical)
    return _unique_sorted(tuple(names)), tuple(sorted(reason for reason, _fingerprint in rejected))


def _query_name_looks_like_route_path(name: str) -> bool:
    lowered = name.lower()
    if "/" in name:
        return True
    return lowered.endswith((".js", ".mjs", ".cjs"))


def _valid_safe_urls(urls: tuple[str, ...]) -> tuple[str, ...]:
    return _unique_sorted(tuple(url for url in (_safe_url(url) for url in urls) if url != "unresolved"))


def _safe_shallow_requested_url(raw_url: str) -> str:
    return "unresolved" if _shallow_requested_url_invalid(raw_url) else _safe_url(raw_url)


def _shallow_requested_url_invalid(raw_url: str) -> bool:
    try:
        parsed = urlparse(raw_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return True
        safe = _safe_url(raw_url)
    except (TypeError, ValueError):
        return True
    return safe == "unresolved" or safe != raw_url


def _ordered_contexts(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}, key=lambda value: (CONTEXT_ORDER.get(value, 99), value)))


def _unique_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def _skip(
    source_kind: str,
    source_id: str,
    context: str,
    reason: str,
    evidence_ids: tuple[str, ...],
) -> DeepParameterInventorySkippedItem:
    return DeepParameterInventorySkippedItem(
        source_kind=source_kind,
        source_id=source_id,
        context=context,
        reason=reason,
        evidence_ids=_unique_sorted(evidence_ids),
    )


def _format_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _format_parameter_name(value: str) -> str:
    display = value
    if len(display) > MAX_RENDERED_VALUE_CHARS:
        display = display[: MAX_RENDERED_VALUE_CHARS - 24] + " ... [truncated]"
    longest = _longest_backtick_run(display)
    fence = "`" * (longest + 1)
    padding = " " if display.startswith("`") or display.endswith("`") else ""
    return f"{fence}{padding}{display}{padding}{fence}"


def _longest_backtick_run(value: str) -> int:
    longest = 0
    current = 0
    for char in value:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    compact = " ".join(str(value).strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"
