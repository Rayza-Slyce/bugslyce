"""Offline Deep form inventory from collected in-memory HTML bodies.

This module inventories static HTML form structure from original source/route
collection responses and shallow follow-up responses already held in memory.
It does not read files, write files, make network requests, submit forms,
execute JavaScript, retain field names or values, or enable Deep Recon.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urljoin, urlparse

from bugslyce.recon.deep_shallow_route_followup import DeepShallowRouteFollowupResult
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult


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
CONTROL_TYPE_ORDER = (
    "button",
    "checkbox",
    "color",
    "date",
    "datetime-local",
    "email",
    "file",
    "hidden",
    "image",
    "month",
    "number",
    "other",
    "other_button",
    "password",
    "radio",
    "range",
    "reset",
    "search",
    "select",
    "submit",
    "tel",
    "text",
    "textarea",
    "time",
    "url",
    "week",
)
METHOD_ORDER = {"post": 0, "get": 1, "dialog": 2, "other": 3}
SAFETY_NOTES = (
    "This is offline inspection of HTML bodies already collected in memory.",
    "No network request was made.",
    "No form was submitted.",
    "No form action was fetched.",
    "No JavaScript was executed.",
    "No field value was retained, replayed, or invented.",
    "Individual control names are deliberately deferred to Phase 92B.",
    "Query parameter names from form actions may be retained, but query values are not.",
    "Extracted structures are review context, not confirmed vulnerabilities.",
    "Deep Recon full mode was not enabled.",
)


@dataclass(frozen=True)
class DeepFormControlSummary:
    """Aggregate control metadata for one form structure."""

    total_controls: int
    named_controls: int
    unnamed_controls: int
    required_controls: int
    disabled_controls: int
    hidden_controls: int
    password_controls: int
    file_controls: int
    submit_capable_controls: int
    control_type_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class DeepFormInventoryItem:
    """One aggregated form inventory item."""

    form_id: str
    safe_action_reference: str
    safe_resolved_action_url: str | None
    action_query_parameter_names: tuple[str, ...]
    action_resolution_contexts: tuple[str, ...]
    methods: tuple[str, ...]
    enctypes: tuple[str, ...]
    target_kinds: tuple[str, ...]
    control_summary: DeepFormControlSummary
    structural_flags: tuple[str, ...]
    source_kinds: tuple[str, ...]
    source_ids: tuple[str, ...]
    source_request_ids: tuple[str, ...]
    safe_document_urls: tuple[str, ...]
    source_route_candidate_ids: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    occurrence_count: int
    evidence_ids: tuple[str, ...]
    interpretation: str


@dataclass(frozen=True)
class DeepFormInventorySummaryCounts:
    """Immutable summary counts for offline form inventory."""

    source_collection_responses_considered: int
    shallow_followup_responses_considered: int
    source_collection_html_responses_scanned: int
    shallow_followup_html_responses_scanned: int
    empty_bodies_skipped: int
    explicit_non_html_responses_skipped: int
    sniffable_non_html_responses_skipped: int
    forms_observed: int
    unique_aggregated_forms: int
    duplicate_form_occurrences_aggregated: int
    get_form_occurrences: int
    post_form_occurrences: int
    dialog_form_occurrences: int
    other_method_form_occurrences: int
    unique_forms_with_resolved_actions: int
    unique_forms_with_unresolved_or_malformed_actions: int
    form_occurrences_using_valid_html_base_url: int
    unique_forms_with_password_controls: int
    unique_forms_with_file_controls: int
    unique_forms_with_hidden_controls: int
    unique_forms_with_named_controls: int
    unique_forms_with_unnamed_controls: int
    nested_or_malformed_form_occurrences: int
    unterminated_form_occurrences: int
    controls_outside_forms_ignored: int


@dataclass(frozen=True)
class DeepFormInventoryResult:
    """Offline Deep form inventory result."""

    forms: tuple[DeepFormInventoryItem, ...]
    summary_counts: DeepFormInventorySummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _Source:
    source_kind: str
    source_id: str
    method: str
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
    evidence_ids: tuple[str, ...]
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class _ParsedForm:
    safe_action_reference: str
    safe_resolved_action_url: str | None
    action_query_parameter_names: tuple[str, ...]
    action_resolution_context: str
    method: str
    enctype: str
    target_kind: str
    control_summary: DeepFormControlSummary
    structural_flags: tuple[str, ...]
    used_base_url: bool
    source: _Source


@dataclass(repr=False)
class _OpenForm:
    action: str
    action_present: bool
    method: str
    enctype: str
    target: str
    controls: list[str]
    named_controls: int = 0
    unnamed_controls: int = 0
    required_controls: int = 0
    disabled_controls: int = 0
    flags: set[str] | None = None


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_hrefs: list[str] = []
        self.forms: list[_OpenForm] = []
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
            self._current.flags = set(self._current.flags or set())
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
                self._current.flags = set(self._current.flags or set())
                self._current.flags.add("nested_form_start")
                self.forms.append(self._current)
            self._current = _OpenForm(
                action=attrs_by_name.get("action") or "",
                action_present="action" in attrs_by_name,
                method=attrs_by_name.get("method") or "",
                enctype=attrs_by_name.get("enctype") or "",
                target=attrs_by_name.get("target") or "",
                controls=[],
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
            self._add_control(tag_name, attrs_by_name)

    def _add_control(self, tag_name: str, attrs_by_name: dict[str, str]) -> None:
        assert self._current is not None
        if tag_name == "input":
            control_type = _input_type(attrs_by_name.get("type", ""))
        elif tag_name == "button":
            control_type = _button_type(attrs_by_name.get("type", ""))
        else:
            control_type = tag_name
        self._current.controls.append(control_type)
        if (attrs_by_name.get("name") or "").strip():
            self._current.named_controls += 1
        else:
            self._current.unnamed_controls += 1
        if "required" in attrs_by_name:
            self._current.required_controls += 1
        if "disabled" in attrs_by_name:
            self._current.disabled_controls += 1


def build_deep_form_inventory(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
) -> DeepFormInventoryResult:
    """Build a deterministic offline form inventory from in-memory HTML bodies."""

    sources = _canonical_sources(source_collection, shallow_followups)
    parsed_forms: list[_ParsedForm] = []
    empty_skips = 0
    explicit_non_html_skips = 0
    sniffable_non_html_skips = 0
    source_html_scanned = 0
    shallow_html_scanned = 0
    controls_outside = 0

    for source in sources:
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
        forms, outside = _parse_forms(source, body_text)
        parsed_forms.extend(forms)
        controls_outside += outside

    forms = _aggregate_forms(parsed_forms)
    counts = _summary_counts(
        source_collection,
        shallow_followups,
        parsed_forms,
        forms,
        empty_skips,
        explicit_non_html_skips,
        sniffable_non_html_skips,
        source_html_scanned,
        shallow_html_scanned,
        controls_outside,
    )
    return DeepFormInventoryResult(
        forms=forms,
        summary_counts=counts,
        safety_notes=SAFETY_NOTES,
    )


def render_deep_form_inventory_markdown(result: DeepFormInventoryResult) -> str:
    """Render a Deep form inventory result as terminal-friendly Markdown."""

    counts = result.summary_counts
    lines = [
        "## Deep Form Inventory",
        "",
        "This is offline inspection of HTML bodies already collected in memory.",
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
        f"- Form occurrences observed: {counts.forms_observed}",
        f"- Unique aggregated forms: {counts.unique_aggregated_forms}",
        f"- Duplicate form occurrences aggregated: {counts.duplicate_form_occurrences_aggregated}",
        f"- GET form occurrences: {counts.get_form_occurrences}",
        f"- POST form occurrences: {counts.post_form_occurrences}",
        f"- Forms with resolved actions: {counts.unique_forms_with_resolved_actions}",
        f"- Forms with unresolved or malformed actions: {counts.unique_forms_with_unresolved_or_malformed_actions}",
        f"- Controls outside forms ignored: {counts.controls_outside_forms_ignored}",
        "",
        "### Forms",
        "",
    ]
    if result.forms:
        for form in result.forms:
            lines.extend(_render_form(form))
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Inventory Interpretation Notes",
            "",
            "- Static HTML form structure observed in an already collected response; no submission was attempted.",
            "- Individual control names and values are not included in this inventory.",
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
                evidence_ids=_unique_sorted(item.evidence_ids),
                body=item.body,
            )
        )
    for item in shallow_followups.collected:
        pending.append(
            _Source(
                source_kind="shallow_route_followup",
                source_id="",
                method=item.method.upper(),
                safe_requested_url=_safe_url(item.requested_url),
                safe_final_url=_safe_url(item.final_url),
                safe_document_url=_canonical_document_url(item.final_url, item.requested_url),
                status_code=item.status_code,
                headers=_canonical_headers(item.headers),
                body_sha256=sha256(item.body).hexdigest(),
                body_bytes=len(item.body),
                source_collection_section="",
                source_selection_reason="shallow_route_followup",
                source_request_id=item.request_id,
                source_route_candidate_ids=_unique_sorted(item.source_route_candidate_ids),
                evidence_ids=_unique_sorted(item.evidence_ids),
                body=item.body,
            )
        )
    ordered = sorted(pending, key=_source_sort_key)
    return tuple(
        _Source(
            source_kind=source.source_kind,
            source_id=f"DEEP-FORM-SOURCE-{index:04d}",
            method=source.method,
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
            evidence_ids=source.evidence_ids,
            body=source.body,
        )
        for index, source in enumerate(ordered, start=1)
    )


def _parse_forms(source: _Source, body_text: str) -> tuple[tuple[_ParsedForm, ...], int]:
    parser = _FormParser()
    try:
        parser.feed(body_text)
        parser.close()
    except Exception:
        return (), 0
    document_url = source.safe_document_url
    base_url, base_used = _resolution_base(document_url, tuple(parser.base_hrefs))
    forms = []
    for form in parser.forms:
        forms.append(_parsed_form(source, form, document_url, base_url, base_used))
    return tuple(forms), parser.controls_outside_forms


def _parsed_form(
    source: _Source,
    form: _OpenForm,
    document_url: str,
    base_url: str,
    base_used: bool,
) -> _ParsedForm:
    method = _method(form.method)
    action = _action(document_url, base_url, form.action, form.action_present, base_used)
    control_summary = _control_summary(form)
    return _ParsedForm(
        safe_action_reference=action[0],
        safe_resolved_action_url=action[1],
        action_query_parameter_names=action[2],
        action_resolution_context=action[3],
        method=method,
        enctype=_enctype(form.enctype),
        target_kind=_target_kind(form.target),
        control_summary=control_summary,
        structural_flags=_unique_sorted(tuple(form.flags or set())),
        used_base_url=action[4],
        source=source,
    )


def _aggregate_forms(parsed_forms: list[_ParsedForm]) -> tuple[DeepFormInventoryItem, ...]:
    grouped: dict[tuple, list[_ParsedForm]] = {}
    for form in parsed_forms:
        grouped.setdefault(_form_identity(form), []).append(form)
    pending: list[DeepFormInventoryItem] = []
    for forms in grouped.values():
        ordered = sorted(forms, key=_parsed_form_sort_key)
        first = ordered[0]
        pending.append(
            DeepFormInventoryItem(
                form_id="",
                safe_action_reference=first.safe_action_reference,
                safe_resolved_action_url=first.safe_resolved_action_url,
                action_query_parameter_names=first.action_query_parameter_names,
                action_resolution_contexts=_unique_sorted(tuple(form.action_resolution_context for form in ordered)),
                methods=_unique_sorted(tuple(form.method for form in ordered)),
                enctypes=_unique_sorted(tuple(form.enctype for form in ordered)),
                target_kinds=_unique_sorted(tuple(form.target_kind for form in ordered)),
                control_summary=first.control_summary,
                structural_flags=_unique_sorted(tuple(flag for form in ordered for flag in form.structural_flags)),
                source_kinds=_unique_sorted(tuple(form.source.source_kind for form in ordered)),
                source_ids=_unique_sorted(tuple(form.source.source_id for form in ordered)),
                source_request_ids=_unique_sorted(tuple(form.source.source_request_id for form in ordered if form.source.source_request_id)),
                safe_document_urls=_unique_sorted(tuple(form.source.safe_document_url for form in ordered if form.source.safe_document_url != "unresolved")),
                source_route_candidate_ids=_unique_sorted(tuple(value for form in ordered for value in form.source.source_route_candidate_ids)),
                source_collection_sections=_unique_sorted(tuple(form.source.source_collection_section for form in ordered if form.source.source_collection_section)),
                source_selection_reasons=_unique_sorted(tuple(form.source.source_selection_reason for form in ordered if form.source.source_selection_reason)),
                occurrence_count=len(ordered),
                evidence_ids=_unique_sorted(tuple(evidence_id for form in ordered for evidence_id in form.source.evidence_ids)),
                interpretation="Static HTML form structure observed in an already collected response; no submission was attempted.",
            )
        )
    ordered_items = sorted(pending, key=_form_sort_key)
    return tuple(
        DeepFormInventoryItem(
            form_id=f"DEEP-FORM-{index:04d}",
            safe_action_reference=item.safe_action_reference,
            safe_resolved_action_url=item.safe_resolved_action_url,
            action_query_parameter_names=item.action_query_parameter_names,
            action_resolution_contexts=item.action_resolution_contexts,
            methods=item.methods,
            enctypes=item.enctypes,
            target_kinds=item.target_kinds,
            control_summary=item.control_summary,
            structural_flags=item.structural_flags,
            source_kinds=item.source_kinds,
            source_ids=item.source_ids,
            source_request_ids=item.source_request_ids,
            safe_document_urls=item.safe_document_urls,
            source_route_candidate_ids=item.source_route_candidate_ids,
            source_collection_sections=item.source_collection_sections,
            source_selection_reasons=item.source_selection_reasons,
            occurrence_count=item.occurrence_count,
            evidence_ids=item.evidence_ids,
            interpretation=item.interpretation,
        )
        for index, item in enumerate(ordered_items, start=1)
    )


def _summary_counts(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
    parsed_forms: list[_ParsedForm],
    forms: tuple[DeepFormInventoryItem, ...],
    empty_skips: int,
    explicit_non_html_skips: int,
    sniffable_non_html_skips: int,
    source_html_scanned: int,
    shallow_html_scanned: int,
    controls_outside: int,
) -> DeepFormInventorySummaryCounts:
    return DeepFormInventorySummaryCounts(
        source_collection_responses_considered=len(source_collection.collected),
        shallow_followup_responses_considered=len(shallow_followups.collected),
        source_collection_html_responses_scanned=source_html_scanned,
        shallow_followup_html_responses_scanned=shallow_html_scanned,
        empty_bodies_skipped=empty_skips,
        explicit_non_html_responses_skipped=explicit_non_html_skips,
        sniffable_non_html_responses_skipped=sniffable_non_html_skips,
        forms_observed=len(parsed_forms),
        unique_aggregated_forms=len(forms),
        duplicate_form_occurrences_aggregated=max(0, len(parsed_forms) - len(forms)),
        get_form_occurrences=sum(1 for form in parsed_forms if form.method == "get"),
        post_form_occurrences=sum(1 for form in parsed_forms if form.method == "post"),
        dialog_form_occurrences=sum(1 for form in parsed_forms if form.method == "dialog"),
        other_method_form_occurrences=sum(1 for form in parsed_forms if form.method == "other"),
        unique_forms_with_resolved_actions=sum(1 for form in forms if form.safe_resolved_action_url),
        unique_forms_with_unresolved_or_malformed_actions=sum(1 for form in forms if not form.safe_resolved_action_url),
        form_occurrences_using_valid_html_base_url=sum(1 for form in parsed_forms if form.used_base_url),
        unique_forms_with_password_controls=sum(1 for form in forms if form.control_summary.password_controls),
        unique_forms_with_file_controls=sum(1 for form in forms if form.control_summary.file_controls),
        unique_forms_with_hidden_controls=sum(1 for form in forms if form.control_summary.hidden_controls),
        unique_forms_with_named_controls=sum(1 for form in forms if form.control_summary.named_controls),
        unique_forms_with_unnamed_controls=sum(1 for form in forms if form.control_summary.unnamed_controls),
        nested_or_malformed_form_occurrences=sum(1 for form in parsed_forms if "nested_form_start" in form.structural_flags),
        unterminated_form_occurrences=sum(1 for form in parsed_forms if "unterminated_form" in form.structural_flags),
        controls_outside_forms_ignored=controls_outside,
    )


def _render_form(form: DeepFormInventoryItem) -> list[str]:
    lines = [
        f"#### {form.form_id} - Static HTML form structure",
        "",
        f"- Action reference: `{_compact_single(form.safe_action_reference)}`",
    ]
    if form.safe_resolved_action_url:
        lines.append(f"- Resolved action URL: `{_compact_single(form.safe_resolved_action_url)}`")
    lines.extend(
        [
            "- Action query parameter names: " + _format_values(form.action_query_parameter_names),
            "- Action resolution: " + _format_values(form.action_resolution_contexts),
            "- Methods: " + _format_values(form.methods),
            "- Enctypes: " + _format_values(form.enctypes),
            "- Target kinds: " + _format_values(form.target_kinds),
            f"- Controls: `{form.control_summary.total_controls}` total, `{form.control_summary.named_controls}` named, `{form.control_summary.unnamed_controls}` unnamed",
            f"- Required/disabled controls: `{form.control_summary.required_controls}` required, `{form.control_summary.disabled_controls}` disabled",
            f"- Password/file/hidden controls: `{form.control_summary.password_controls}` password, `{form.control_summary.file_controls}` file, `{form.control_summary.hidden_controls}` hidden",
            f"- Submit-capable controls: `{form.control_summary.submit_capable_controls}`",
            "- Control types: " + _format_pairs(form.control_summary.control_type_counts),
            "- Structural flags: " + _format_values(form.structural_flags),
            "- Source kinds: " + _format_values(form.source_kinds),
            "- Document URLs: " + _format_values(form.safe_document_urls),
            "- Source IDs: " + _format_values(form.source_ids),
            f"- Occurrences: `{form.occurrence_count}`",
            "- Evidence: " + _format_values(form.evidence_ids),
            f"- Interpretation: {form.interpretation}",
            "",
        ]
    )
    return lines


def _control_summary(form: _OpenForm) -> DeepFormControlSummary:
    counts = Counter(form.controls)
    return DeepFormControlSummary(
        total_controls=len(form.controls),
        named_controls=form.named_controls,
        unnamed_controls=form.unnamed_controls,
        required_controls=form.required_controls,
        disabled_controls=form.disabled_controls,
        hidden_controls=counts.get("hidden", 0),
        password_controls=counts.get("password", 0),
        file_controls=counts.get("file", 0),
        submit_capable_controls=sum(counts.get(name, 0) for name in ("submit", "image")),
        control_type_counts=tuple(
            (name, count)
            for name, count in sorted(
                counts.items(),
                key=lambda item: (CONTROL_TYPE_ORDER.index(item[0]) if item[0] in CONTROL_TYPE_ORDER else 999, item[0]),
            )
        ),
    )


def _action(
    document_url: str,
    base_url: str,
    action: str,
    action_present: bool,
    base_used: bool,
) -> tuple[str, str | None, tuple[str, ...], str, bool]:
    stripped = action.strip()
    if not action_present or not stripped:
        safe = _safe_url(document_url)
        return (
            "document_url_default",
            None if safe == "unresolved" else safe,
            _query_names(urlparse(safe).query if safe != "unresolved" else ""),
            "document_url_default",
            False,
        )
    safe_reference, reason, is_absolute = _safe_reference(stripped)
    if reason is not None:
        return (reason, None, (), reason, False)
    try:
        resolved = urljoin(base_url, stripped)
    except (TypeError, ValueError):
        return ("malformed_action", None, (), "malformed_action", False)
    safe_resolved = _safe_url(resolved)
    if safe_resolved == "unresolved":
        return ("malformed_action", None, (), "malformed_action", False)
    used_base = base_used and not is_absolute
    context = "absolute_url" if is_absolute else ("html_base_url" if used_base else "document_url")
    return (safe_reference, safe_resolved, _query_names(urlparse(safe_resolved).query), context, used_base)


def _safe_reference(value: str) -> tuple[str, str | None, bool]:
    try:
        parsed = urlparse(value)
    except (TypeError, ValueError):
        return ("", "malformed_action", False)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return ("", "unsupported_scheme", False)
    if value.startswith("//") and not parsed.netloc:
        return ("", "malformed_action", False)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"} or value.startswith("//"):
        safe = _safe_url(("http:" if value.startswith("//") else "") + value)
        if safe == "unresolved":
            return ("", "malformed_action", False)
        return (safe.removeprefix("http:") if value.startswith("//") else safe, None, scheme in {"http", "https"})
    if parsed.path == "" and parsed.query == "" and parsed.fragment:
        return ("document_url_reference", None, False)
    query_names = _query_names(parsed.query)
    query = f"?{'&'.join(query_names)}" if query_names else ""
    path = parsed.path
    return (f"{path}{query}" if path or query else "document_url_reference", None, False)


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


def _input_type(value: str) -> str:
    control_type = value.strip().lower() or "text"
    return control_type if control_type in INPUT_TYPES else "other"


def _button_type(value: str) -> str:
    control_type = value.strip().lower() or "submit"
    return control_type if control_type in BUTTON_TYPES else "other_button"


def _form_identity(form: _ParsedForm) -> tuple:
    return (
        form.safe_resolved_action_url if form.safe_resolved_action_url is not None else form.safe_action_reference,
        form.action_query_parameter_names,
        form.method,
        form.enctype,
        form.target_kind,
        form.control_summary,
        form.structural_flags,
    )


def _form_sort_key(form: DeepFormInventoryItem) -> tuple:
    method = form.methods[0] if form.methods else "other"
    return (
        0 if form.safe_resolved_action_url else 1,
        METHOD_ORDER.get(method, 99),
        0 if form.control_summary.password_controls else 1,
        0 if form.control_summary.file_controls else 1,
        0 if form.control_summary.hidden_controls else 1,
        form.safe_resolved_action_url or form.safe_action_reference,
        form.control_summary.control_type_counts,
        form.source_ids,
        form.evidence_ids,
    )


def _parsed_form_sort_key(form: _ParsedForm) -> tuple:
    return (
        form.safe_resolved_action_url or form.safe_action_reference,
        form.safe_action_reference,
        form.action_resolution_context,
        form.method,
        form.enctype,
        form.target_kind,
        form.control_summary,
        form.structural_flags,
        form.source.source_id,
        form.source.evidence_ids,
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
    names = _query_names(parsed.query)
    query = f"?{'&'.join(names)}" if names else ""
    return f"{scheme}://{authority}{parsed.path or '/'}{query}"


def _canonical_document_url(final_url: str, requested_url: str) -> str:
    safe_final = _safe_url(final_url)
    if safe_final != "unresolved":
        return safe_final
    return _safe_url(requested_url)


def _query_names(query: str) -> tuple[str, ...]:
    return _unique_sorted(tuple(quote(name, safe="") for name, _value in parse_qsl(query, keep_blank_values=True) if name))


def _unique_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def _format_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining:
        rendered += f", ... +{remaining} more"
    return rendered


def _format_pairs(values: tuple[tuple[str, int], ...]) -> str:
    if not values:
        return "`none`"
    return ", ".join(f"`{name}: {count}`" for name, count in values[:MAX_RENDERED_VALUES])


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    compact = " ".join(str(value).strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"
