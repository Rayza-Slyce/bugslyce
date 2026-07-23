"""Self-contained offline HTML rendering for existing BugSlyce artefacts."""

from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from urllib.parse import urlsplit

from bugslyce.core.models import HTTPArtifact, ProjectState
from bugslyce.reports.html_model import HtmlReportModel, build_html_report_model


_SOURCE_ARTEFACT_TYPES = frozenset(
    {
        "encoded_like_artifact",
        "form",
        "hidden_element",
        "html_comment",
        "input",
        "link",
        "script_or_asset",
        "transform_like_artifact",
    }
)
_OPERATOR_SUMMARY_CATEGORY = "operator_summary"
_SKIPPED_COLLECTION_CATEGORY = "skipped_collection"
_ENDPOINT_CATEGORY = "endpoint"
_DISCOVERED_PATH_CATEGORY = "discovered_path"
_HTTP_SERVICE_CATEGORY = "http_service"
_HTTP_FINGERPRINT_CATEGORY = "http_fingerprint"
_SUCCESSFUL_DEEP_CONTENT_CATEGORY = "successful_deep_content"
_HTTP_RELATIONSHIP_CATEGORY = "http_route_relationship"
_REDIRECT_CATEGORY = "redirect_auth_flow"
_FORM_PARAMETER_CATEGORY = "form_or_parameter"


def render_html_report(model: HtmlReportModel) -> str:
    """Render a deterministic, self-contained HTML document."""

    sections = _render_sections(model)
    toc = "".join(
        f'<a href="#{section_id}">{_h(title)}</a>'
        for section_id, title, _ in sections
    )
    body = "".join(content for _, _, content in sections)
    project = model.project_state
    content_security_policy = (
        "default-src 'none'; "
        f"style-src 'sha256-{_content_hash(_CSS)}'; "
        f"script-src 'sha256-{_content_hash(_JAVASCRIPT)}'; "
        "img-src 'none'; connect-src 'none'; font-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en-GB">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta http-equiv="Content-Security-Policy" '
        f'content="{content_security_policy}">\n'
        f"<title>BugSlyce Evidence Report - {_h(project.project_name)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        '<aside class="sidebar">'
        '<div class="brand">BugSlyce</div>'
        '<div class="side-title">Evidence report</div>'
        f'<nav aria-label="Report sections">{toc}</nav>'
        "</aside>"
        '<main id="main-content">'
        '<header class="report-header">'
        '<p class="eyebrow">Offline evidence review</p>'
        '<h1>BugSlyce Evidence Report</h1>'
        f'<p class="project-name">{_h(project.project_name)}</p>'
        '<p class="disclaimer"><strong>Reconnaissance review leads are observations, '
        "not confirmed vulnerabilities.</strong> This report presents existing "
        "BugSlyce evidence and deterministic review models; it does not prove "
        "exhaustive coverage.</p>"
        "</header>"
        '<section class="controls" aria-label="Report controls">'
        '<label>Search displayed records<input id="report-search" type="search" '
        'placeholder="Routes, evidence IDs, titles, artefacts..." autocomplete="off"></label>'
        '<label>Status filter<select id="status-filter"><option value="">All statuses</option>'
        f"{_status_options(model)}</select></label>"
        '<label>Evidence category<select id="category-filter">'
        '<option value="">All categories</option>'
        f"{_category_options(model)}</select></label>"
        '<button id="clear-filters" type="button">Clear filters</button>'
        '<p id="filter-result" role="status" aria-live="polite"></p>'
        "</section>"
        f"{body}"
        "</main>"
        f"<script>{_JAVASCRIPT}</script>\n"
        "</body>\n</html>\n"
    )


def write_html_report(input_dir: Path, output: Path) -> Path:
    """Write only the requested HTML output from an existing local directory."""

    output = output.expanduser()
    input_root = input_dir.expanduser().resolve()
    output_path = output.resolve(strict=False)
    if output_path.is_relative_to(input_root):
        raise ValueError(f"output path must be outside the input directory: {output}")
    if output.exists() and not output.is_file():
        raise ValueError(f"output path is not a file: {output}")
    if not output.parent.exists():
        raise ValueError(f"output parent directory does not exist: {output.parent}")
    if not output.parent.is_dir():
        raise ValueError(f"output parent path is not a directory: {output.parent}")
    model = build_html_report_model(input_dir)
    output.write_text(render_html_report(model), encoding="utf-8")
    return output


def _render_sections(model: HtmlReportModel) -> list[tuple[str, str, str]]:
    sections = [
        ("overview", "Overview", _overview_section(model)),
        ("operator-summary", "Operator summary", _operator_summary_section(model)),
        ("confidence", "Collection confidence", _confidence_section(model)),
        ("manual-review", "Manual review leads", _candidate_section(model)),
        ("routes", "Routes and provenance", _routes_section(model)),
        ("http-evidence", "HTTP evidence", _http_section(model)),
    ]
    if (
        model.project_state.warnings
        or model.metadata_collection.skipped
        or model.source_collection.skipped
    ):
        sections.insert(
            3,
            ("limitations", "Warnings and skipped collection", _limitations_section(model)),
        )
    if model.relationship_clusters:
        sections.append(
            ("relationships", "Route relationships", _relationship_section(model))
        )
    if model.redirect_review.observations:
        sections.append(("redirects", "Redirect review", _redirect_section(model)))
    if model.similarity_review.groups:
        sections.append(
            ("similarity", "Response similarity", _similarity_section(model))
        )
    forms = _form_and_parameter_rows(model.project_state)
    if forms:
        sections.append(("forms", "Forms and parameters", _forms_section(forms)))
    source_items = tuple(
        item
        for item in model.project_state.http_artifacts
        if item.artifact_type in _SOURCE_ARTEFACT_TYPES
    )
    if source_items:
        sections.append(("source-evidence", "Source evidence", _source_section(source_items)))
    sections.extend(
        [
            ("evidence", "Evidence records", _evidence_section(model)),
            ("artefacts", "Artefact index", _artefact_section(model)),
        ]
    )
    return sections


def _overview_section(model: HtmlReportModel) -> str:
    state = model.project_state
    target = state.recon_manifest.target if state.recon_manifest else "Not recorded"
    profile = state.recon_manifest.profile if state.recon_manifest else None
    cards = (
        ("Target", target),
        ("Profile", profile or "Not recorded"),
        ("Generated", state.generated_at),
        ("Engagement", state.engagement_context),
        ("Assets", str(len(state.assets))),
        (
            "Unique route URLs",
            str(
                len(
                    {item.url for item in state.endpoints}
                    | {item.url for item in state.discovered_paths}
                )
            ),
        ),
        ("Evidence records", str(len(state.evidence))),
        ("Review leads", str(len(model.candidates))),
    )
    return _section(
        "overview",
        "Overview",
        '<div class="metric-grid">'
        + "".join(
            f'<div class="metric searchable"><span>{_h(label)}</span><strong>{_h(value)}</strong></div>'
            for label, value in cards
        )
        + "</div>"
        + f'<p class="scope searchable"><strong>Scope:</strong> {_h(state.scope_summary)}</p>',
    )


def _operator_summary_section(model: HtmlReportModel) -> str:
    summary = model.operator_summary
    if summary.review_first:
        review = "".join(
            _detail_card(
                lead.title,
                (
                    ("Why", lead.why),
                    ("Endpoint(s)", _joined(lead.endpoints)),
                    ("Evidence", _joined(lead.evidence_ids)),
                    ("Next", lead.next_action),
                    ("Signal", lead.signal),
                ),
                category=_OPERATOR_SUMMARY_CATEGORY,
            )
            for lead in summary.review_first
        )
    else:
        review = _empty("No evidence-backed leads met the existing summary threshold.")
    low_signal = "".join(
        f'<li class="searchable"><strong>{_h(item.title)}</strong>: {_h(item.reason)} '
        f'<span class="provenance">Evidence: {_h(_joined(item.evidence_ids))}</span></li>'
        for item in summary.low_signal
    ) or "<li>No structured low-signal items were identified.</li>"
    coverage = "".join(f'<li class="searchable">{_h(item)}</li>' for item in summary.coverage)
    return _section(
        "operator-summary",
        "Operator summary",
        '<h3>Review first</h3>' + review
        + '<details><summary>Low-signal / avoid rabbit holes</summary><ul>'
        + low_signal
        + "</ul></details>"
        + '<details><summary>Current coverage</summary><ul>'
        + coverage
        + "</ul></details>",
    )


def _confidence_section(model: HtmlReportModel) -> str:
    if not model.confidence_notices:
        content = _empty(
            "No material collection-confidence notice was recorded. This does not prove exhaustive coverage."
        )
    else:
        content = "".join(
            _detail_card(
                notice.title,
                (
                    ("Notice ID", notice.notice_id),
                    ("Category", notice.category),
                    ("Direct fact", notice.direct_fact),
                    ("What remains unknown", notice.operator_implication),
                    ("Stage or tool", notice.stage_or_tool),
                    ("Counts", _counts(notice.counts)),
                    ("Evidence", _joined(notice.evidence_ids)),
                    ("Retained artefact", _joined(notice.artefact_references)),
                ),
                category=notice.category,
            )
            for notice in model.confidence_notices
        )
    return _section(
        "confidence",
        "Collection confidence",
        '<p class="section-note">Absence of a notice does not prove exhaustive coverage.</p>'
        + content,
    )


def _candidate_section(model: HtmlReportModel) -> str:
    if not model.candidates:
        content = _empty("No deterministic manual review lead is present in this artefact set.")
    else:
        content = "".join(
            _detail_card(
                candidate.title,
                (
                    ("Lead ID", candidate.id),
                    ("Type", candidate.candidate_type),
                    ("Manual attention", candidate.priority),
                    ("Existing rationale", candidate.rationale),
                    ("Assets", _joined(candidate.affected_assets)),
                    ("Endpoints", _joined(candidate.affected_endpoints)),
                    ("Evidence", _joined(candidate.evidence_ids)),
                    ("Suggested manual validation", _joined(candidate.suggested_manual_validation)),
                ),
                category=candidate.candidate_type,
            )
            for candidate in model.candidates
        )
    return _section(
        "manual-review",
        "Manual review leads",
        '<p class="section-note">Priority is manual attention priority, not vulnerability severity.</p>'
        + content,
    )


def _limitations_section(model: HtmlReportModel) -> str:
    warnings = "".join(
        f'<li class="searchable">{_h(value)}</li>'
        for value in model.project_state.warnings
    ) or "<li>No project warning was recorded.</li>"
    skipped_rows = [
        _row(
            (
                "Deep metadata collection",
                item.url,
                item.reason,
                item.source,
                _joined(item.evidence_ids),
                "deep_metadata_collection.json",
            ),
            category=_SKIPPED_COLLECTION_CATEGORY,
        )
        for item in model.metadata_collection.skipped
    ]
    skipped_rows.extend(
        _row(
            (
                "Deep source/route collection",
                item.url,
                item.reason,
                item.source,
                _joined(item.evidence_ids),
                "deep_source_route_collection.json",
            ),
            category=_SKIPPED_COLLECTION_CATEGORY,
        )
        for item in model.source_collection.skipped
    )
    skipped = (
        _table(("Stage", "URL", "Reason", "Source", "Evidence", "Artefact"), skipped_rows)
        if skipped_rows
        else _empty("No structured skipped collection record is available.")
    )
    return _section(
        "limitations",
        "Warnings and skipped collection",
        '<details><summary>Project warnings</summary><ul>'
        + warnings
        + "</ul></details><h3>Skipped collection records</h3>"
        + skipped,
    )


def _routes_section(model: HtmlReportModel) -> str:
    rows: list[str] = []
    for endpoint in model.project_state.endpoints:
        rows.append(
            _row(
                (
                    endpoint.url,
                    endpoint.path,
                    "Not recorded",
                    _joined(endpoint.query_params),
                    _joined(endpoint.evidence_ids),
                    "project_state.json",
                ),
                category=_ENDPOINT_CATEGORY,
            )
        )
    for route in model.project_state.discovered_paths:
        rows.append(
            _row(
                (
                    route.url,
                    _url_path(route.url),
                    _status(route.status_code),
                    route.redirect_location or "None recorded",
                    _joined(route.evidence_ids),
                    route.source,
                ),
                status=route.status_code,
                category=_DISCOVERED_PATH_CATEGORY,
            )
        )
    content = (
        _table(
            ("URL", "Path", "Status", "Parameters / redirect", "Evidence", "Source artefact"),
            rows,
        )
        if rows
        else _empty("No structured route records are available.")
    )
    return _section("routes", "Routes and provenance", content)


def _http_section(model: HtmlReportModel) -> str:
    rows: list[str] = []
    for service in model.project_state.http_services:
        rows.append(
            _row(
                (
                    service.url,
                    _status(service.status_code),
                    service.title or "Not recorded",
                    _joined(service.technologies),
                    "Not recorded",
                    _joined(service.evidence_ids),
                ),
                status=service.status_code,
                category=_HTTP_SERVICE_CATEGORY,
            )
        )
    for item in model.http_fingerprints.fingerprints:
        fingerprint = "; ".join(
            value
            for value in (
                f"content-type={item.content_type}" if item.content_type else "",
                f"server={item.server}" if item.server else "",
                f"sha256={item.body_sha256}",
            )
            if value
        )
        rows.append(
            _row(
                (
                    item.requested_url,
                    str(item.status_code),
                    item.title_observed_in_bounded_preview or "Not observed",
                    fingerprint,
                    item.collection_section,
                    _joined(item.evidence_ids),
                ),
                status=item.status_code,
                category=_HTTP_FINGERPRINT_CATEGORY,
            )
        )
    content = (
        _table(("URL", "Status", "Title", "Fingerprint", "Collection", "Evidence"), rows)
        if rows
        else _empty("No structured HTTP service or retained response record is available.")
    )
    if model.successful_content:
        content += '<h3>Successful retained Deep content</h3>' + "".join(
            _detail_card(
                review.canonical_url,
                (
                    ("Review ID", review.review_id),
                    ("Response", f"HTTP {review.status_code}; {review.body_bytes} bytes"),
                    ("Content type", review.content_type or "Not recorded"),
                    ("Bounded preview", review.body_preview),
                    ("Evidence", _joined(review.evidence_ids)),
                    ("Retained artefact", _joined(review.artefact_references)),
                ),
                status=review.status_code,
                category=_SUCCESSFUL_DEEP_CONTENT_CATEGORY,
            )
            for review in model.successful_content
        )
    return _section("http-evidence", "HTTP evidence", content)


def _relationship_section(model: HtmlReportModel) -> str:
    return _section(
        "relationships",
        "Route relationships",
        '<p class="section-note">Only existing direct source-reference and redirect relationships are shown.</p>'
        + "".join(
            _detail_card(
                cluster.title,
                (
                    ("Cluster ID", cluster.cluster_id),
                    ("Existing summary", cluster.summary),
                    ("Routes", _joined(cluster.route_nodes)),
                    ("Manual review order", _joined(cluster.manual_review_order)),
                    ("Evidence", _joined(cluster.evidence_ids)),
                    ("Retained artefacts", _joined(cluster.artefact_references)),
                    (
                        "Edges",
                        _joined(
                            tuple(
                                f"{edge.edge_type}: {edge.source_url} -> {edge.target_url} "
                                f"[{_joined(edge.evidence_ids)}]"
                                for edge in cluster.edges
                            )
                        ),
                    ),
                ),
                category=_HTTP_RELATIONSHIP_CATEGORY,
            )
            for cluster in model.relationship_clusters
        ),
    )


def _redirect_section(model: HtmlReportModel) -> str:
    rows = [
        _row(
            (
                item.observation_id,
                item.safe_source_url,
                str(item.redirect_status_code),
                item.safe_resolved_target_url or "Not recorded",
                item.origin_relationship,
                item.auth_path_transition,
                item.interpretation_note,
                _joined(item.evidence_ids),
            ),
            status=item.redirect_status_code,
            category=_REDIRECT_CATEGORY,
        )
        for item in model.redirect_review.observations
    ]
    return _section(
        "redirects",
        "Redirect and authentication-flow review",
        '<p class="section-note">One-hop retained evidence only; no redirect was followed and no authentication was attempted.</p>'
        + _table(
            ("ID", "Source", "Status", "Target", "Origin", "Auth transition", "Existing interpretation", "Evidence"),
            rows,
        ),
    )


def _similarity_section(model: HtmlReportModel) -> str:
    return _section(
        "similarity",
        "Response similarity",
        '<p class="section-note">Groups are existing bounded evidence signatures, not confirmed semantic identity.</p>'
        + "".join(
            _detail_card(
                group.title,
                (
                    ("Group ID", group.group_id),
                    ("Category", group.category),
                    ("Reason", group.reason),
                    ("URLs", _joined(group.requested_urls)),
                    ("Statuses", _joined(tuple(str(value) for value in group.status_codes))),
                    ("Existing interpretation", group.interpretation),
                    ("Evidence", _joined(group.evidence_ids)),
                ),
                category=group.category,
            )
            for group in model.similarity_review.groups
        ),
    )


def _forms_section(rows: tuple[tuple[str, ...], ...]) -> str:
    rendered = [
        _row(row, category=_FORM_PARAMETER_CATEGORY)
        for row in rows
    ]
    return _section(
        "forms",
        "Forms and parameters",
        '<p class="section-note">This section displays only form and parameter evidence retained in project_state.json.</p>'
        + _table(("Kind", "URL", "Observed value", "Evidence", "Source artefact"), rendered),
    )


def _source_section(items: tuple[HTTPArtifact, ...]) -> str:
    rows = [
        _row(
            (
                item.artifact_type,
                item.url,
                item.value,
                _joined(item.evidence_ids),
                item.source_file,
            ),
            category=item.artifact_type,
        )
        for item in items
    ]
    return _section(
        "source-evidence",
        "Source and JavaScript-derived evidence",
        _table(("Type", "URL", "Observed value", "Evidence", "Source artefact"), rows),
    )


def _evidence_section(model: HtmlReportModel) -> str:
    rows = [
        _row(
            (
                item.id,
                item.evidence_type,
                item.value,
                item.source_file,
                json.dumps(item.context, sort_keys=True, ensure_ascii=True),
            ),
            category=item.evidence_type,
        )
        for item in model.project_state.evidence
    ]
    return _section(
        "evidence",
        "Evidence records",
        _table(("Evidence ID", "Type", "Value", "Source artefact", "Context"), rows)
        if rows
        else _empty("No structured evidence records are available."),
    )


def _artefact_section(model: HtmlReportModel) -> str:
    manifest = model.project_state.recon_manifest
    rows = []
    if manifest:
        rows.extend(
            _row(
                (
                    item.file,
                    item.type,
                    item.description or "Not recorded",
                    item.url or item.base_url or "Not recorded",
                    _status(item.status_code),
                ),
                status=item.status_code,
                category=item.type,
            )
            for item in manifest.artifacts
        )
    content = (
        _table(("Artefact", "Type", "Description", "URL / base URL", "Status"), rows)
        if rows
        else _empty("No recon-manifest artefact entries are available.")
    )
    content += (
        '<details><summary>Files available at the report root</summary><ul>'
        + "".join(
            f'<li class="searchable"><code>{_h(name)}</code></li>'
            for name in model.available_artefacts
        )
        + "</ul></details>"
    )
    return _section("artefacts", "Artefact index", content)


def _section(section_id: str, title: str, content: str) -> str:
    return f'<section id="{section_id}" class="report-section"><h2>{_h(title)}</h2>{content}</section>'


def _detail_card(
    title: str,
    fields: tuple[tuple[str, str], ...],
    *,
    category: str,
    status: int | None = None,
) -> str:
    details = "".join(
        f'<dt>{_h(label)}</dt><dd>{_h(value or "Not recorded")}</dd>'
        for label, value in fields
        if value
    )
    return (
        f'<details class="record searchable" data-category="{_a(category)}" '
        f'data-status="{_a(str(status) if status is not None else "")}">'
        f'<summary>{_h(title)}</summary><dl>{details}</dl></details>'
    )


def _table(headers: tuple[str, ...], rows: list[str]) -> str:
    heading = "".join(f'<th scope="col">{_h(value)}</th>' for value in headers)
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + heading
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _row(
    values: tuple[str, ...],
    *,
    status: int | None = None,
    category: str,
) -> str:
    cells = "".join(f"<td>{_h(value or 'Not recorded')}</td>" for value in values)
    return (
        f'<tr class="record searchable" data-category="{_a(category)}" '
        f'data-status="{_a(str(status) if status is not None else "")}">{cells}</tr>'
    )


def _form_and_parameter_rows(state: ProjectState) -> tuple[tuple[str, ...], ...]:
    rows = [
        (
            item.artifact_type,
            item.url,
            item.value,
            _joined(item.evidence_ids),
            item.source_file,
        )
        for item in state.http_artifacts
        if item.artifact_type in {"form", "input"}
    ]
    rows.extend(
        (
            "query_parameter_names",
            endpoint.url,
            _joined(endpoint.query_params),
            _joined(endpoint.evidence_ids),
            "project_state.json",
        )
        for endpoint in state.endpoints
        if endpoint.query_params
    )
    return tuple(sorted(rows))


def _status_options(model: HtmlReportModel) -> str:
    values = {
        value
        for value in (
            *(item.status_code for item in model.project_state.http_services),
            *(item.status_code for item in model.project_state.discovered_paths),
            *(item.status_code for item in model.http_fingerprints.fingerprints),
        )
        if value is not None
    }
    return "".join(f'<option value="{value}">{value}</option>' for value in sorted(values))


def _category_options(model: HtmlReportModel) -> str:
    return "".join(
        f'<option value="{_a(value)}">{_h(value.replace("_", " "))}</option>'
        for value in _category_values(model)
    )


def _category_values(model: HtmlReportModel) -> tuple[str, ...]:
    state = model.project_state
    values = {
        *(candidate.candidate_type for candidate in model.candidates),
        *(item.evidence_type for item in state.evidence),
        *(
            item.artifact_type
            for item in state.http_artifacts
            if item.artifact_type in _SOURCE_ARTEFACT_TYPES
        ),
        *(notice.category for notice in model.confidence_notices),
        *(group.category for group in model.similarity_review.groups),
        *(
            item.type
            for item in (state.recon_manifest.artifacts if state.recon_manifest else ())
        ),
    }
    if model.operator_summary.review_first:
        values.add(_OPERATOR_SUMMARY_CATEGORY)
    if model.metadata_collection.skipped or model.source_collection.skipped:
        values.add(_SKIPPED_COLLECTION_CATEGORY)
    if state.endpoints:
        values.add(_ENDPOINT_CATEGORY)
    if state.discovered_paths:
        values.add(_DISCOVERED_PATH_CATEGORY)
    if state.http_services:
        values.add(_HTTP_SERVICE_CATEGORY)
    if model.http_fingerprints.fingerprints:
        values.add(_HTTP_FINGERPRINT_CATEGORY)
    if model.successful_content:
        values.add(_SUCCESSFUL_DEEP_CONTENT_CATEGORY)
    if model.relationship_clusters:
        values.add(_HTTP_RELATIONSHIP_CATEGORY)
    if model.redirect_review.observations:
        values.add(_REDIRECT_CATEGORY)
    if _form_and_parameter_rows(state):
        values.add(_FORM_PARAMETER_CATEGORY)
    return tuple(sorted(value for value in values if value))


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _a(value: object) -> str:
    return escape(str(value), quote=True)


def _joined(values: tuple[str, ...] | list[str]) -> str:
    return ", ".join(values) if values else "None recorded"


def _counts(values: tuple[tuple[str, int], ...]) -> str:
    return "; ".join(f"{name}: {value}" for name, value in values) if values else "None recorded"


def _status(value: int | None) -> str:
    return str(value) if value is not None else "Not recorded"


def _url_path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "Not recorded"


def _empty(message: str) -> str:
    return f'<p class="empty searchable">{_h(message)}</p>'


def _content_hash(value: str) -> str:
    return b64encode(sha256(value.encode("utf-8")).digest()).decode("ascii")


_CSS = """
:root { color-scheme: light; --ink: #182025; --muted: #5c686f; --line: #d9dfe2;
  --paper: #f7f8f8; --panel: #fff; --accent: #176b5b; --accent-soft: #e7f2ef;
  --warning: #8a4b08; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 15px/1.5 system-ui, sans-serif; }
.sidebar { position: fixed; inset: 0 auto 0 0; width: 240px; overflow-y: auto; padding: 24px 18px;
  background: #202a2e; color: #fff; }
.brand { font-size: 22px; font-weight: 750; }.side-title { color: #b9c7cc; margin: 2px 0 20px; }
nav { display: grid; gap: 2px; } nav a { color: #e6eeef; padding: 7px 9px; text-decoration: none; border-radius: 4px; }
nav a:hover, nav a:focus { background: #314047; outline: none; }
main { margin-left: 240px; max-width: 1500px; padding: 36px 48px 80px; }
.report-header { max-width: 900px; }.eyebrow { color: var(--accent); font-weight: 700; text-transform: uppercase; font-size: 12px; }
h1 { font-size: 34px; margin: 5px 0 0; letter-spacing: 0; }.project-name { font-size: 19px; color: var(--muted); margin-top: 4px; }
.disclaimer { border-left: 4px solid var(--warning); padding: 10px 14px; background: #fff7ed; }
.controls { display: grid; grid-template-columns: minmax(260px, 2fr) repeat(2, minmax(150px, 1fr)) auto;
  gap: 12px; align-items: end; margin: 28px 0; padding: 16px; border: 1px solid var(--line); background: var(--panel); }
label { display: grid; gap: 5px; font-size: 12px; font-weight: 700; color: var(--muted); }
input, select, button { min-height: 38px; border: 1px solid #aeb9be; border-radius: 4px; background: #fff; color: var(--ink); padding: 7px 9px; font: inherit; }
button { cursor: pointer; font-weight: 700; } #filter-result { grid-column: 1 / -1; margin: 0; color: var(--muted); }
.report-section { margin: 30px 0; scroll-margin-top: 12px; }.report-section > h2 { margin: 0 0 13px; font-size: 23px; border-bottom: 2px solid var(--line); padding-bottom: 7px; }
h3 { font-size: 17px; margin: 18px 0 10px; }.section-note, .scope { color: var(--muted); }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 9px; }
.metric { background: var(--panel); border: 1px solid var(--line); padding: 12px; }.metric span { display: block; color: var(--muted); font-size: 12px; }.metric strong { font-size: 18px; overflow-wrap: anywhere; }
details { background: var(--panel); border: 1px solid var(--line); margin: 8px 0; } summary { cursor: pointer; font-weight: 700; padding: 11px 13px; }
details > dl, details > ul { margin: 0; padding: 3px 18px 15px; } dl { display: grid; grid-template-columns: minmax(120px, 180px) 1fr; gap: 6px 14px; }
dt { color: var(--muted); font-weight: 700; } dd { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); background: var(--panel); } table { border-collapse: collapse; min-width: 100%; }
th, td { text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); padding: 8px 10px; overflow-wrap: anywhere; max-width: 420px; }
th { position: sticky; top: 0; background: #eef2f2; font-size: 12px; } tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #f3f8f7; }.provenance { display: block; color: var(--muted); font-size: 12px; }
.empty { border: 1px dashed #aeb9be; background: var(--panel); padding: 12px; color: var(--muted); } code { overflow-wrap: anywhere; }
[hidden] { display: none !important; }
@media (max-width: 860px) { .sidebar { position: static; width: auto; } main { margin: 0; padding: 24px 18px 60px; }
  nav { grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); }.controls { grid-template-columns: 1fr; } #filter-result { grid-column: auto; } }
@media print { .sidebar, .controls { display: none; } main { margin: 0; padding: 0; } details { break-inside: avoid; } }
"""


_JAVASCRIPT = """
(() => {
  'use strict';
  const search = document.getElementById('report-search');
  const status = document.getElementById('status-filter');
  const category = document.getElementById('category-filter');
  const result = document.getElementById('filter-result');
  const records = Array.from(document.querySelectorAll('.record'));
  const apply = () => {
    const query = search.value.trim().toLocaleLowerCase('en-GB');
    let visible = 0;
    records.forEach((record) => {
      const matchesText = !query || record.textContent.toLocaleLowerCase('en-GB').includes(query);
      const matchesStatus = !status.value || record.dataset.status === status.value;
      const matchesCategory = !category.value || record.dataset.category === category.value;
      record.hidden = !(matchesText && matchesStatus && matchesCategory);
      if (!record.hidden) visible += 1;
    });
    result.textContent = `${visible} of ${records.length} filterable records shown.`;
  };
  [search, status, category].forEach((control) => control.addEventListener('input', apply));
  document.getElementById('clear-filters').addEventListener('click', () => {
    search.value = ''; status.value = ''; category.value = ''; apply(); search.focus();
  });
  apply();
})();
"""
