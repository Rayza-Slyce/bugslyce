"""Self-contained offline HTML rendering for existing BugSlyce artefacts."""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass, replace
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from bugslyce.core.models import HTTPArtifact, ProjectState
from bugslyce.recon.application_service_model import ApplicationServiceModel
from bugslyce.recon.deep_source_route_collector import (
    render_deep_source_route_skip_reason,
)
from bugslyce.recon.review_occurrence_grouping import ReviewOccurrenceGroup
from bugslyce.reports.html_model import (
    HtmlReportModel,
    HtmlRouteGroup,
    build_html_report_model,
)
from bugslyce.reports.analysis_coverage_presentation import (
    build_analysis_coverage_presentation,
)
from bugslyce.reports.investigation_context import (
    InvestigationContextItem,
    ReportNavigationReference,
)
from bugslyce.reports.investigation_context_presentation import (
    InvestigationContextPresentationIndex,
    build_investigation_context_presentation_index,
)


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
_ANALYSIS_COVERAGE_CATEGORY = "analysis_coverage"
_HUMAN_TRIAGE_CATEGORY = "human_triage"
_SKIPPED_COLLECTION_CATEGORY = "skipped_collection"
_ENDPOINT_CATEGORY = "endpoint"
_DISCOVERED_PATH_CATEGORY = "discovered_path"
_HTTP_SERVICE_CATEGORY = "http_service"
_HTTP_FINGERPRINT_CATEGORY = "http_fingerprint"
_SUCCESSFUL_DEEP_CONTENT_CATEGORY = "successful_deep_content"
_HTTP_RELATIONSHIP_CATEGORY = "http_route_relationship"
_REDIRECT_CATEGORY = "redirect_auth_flow"
_FORM_PARAMETER_CATEGORY = "form_or_parameter"
_DEEP_INTERPRETATION_CATEGORY = "deep_interpretation"
_TECHNICAL_INVESTIGATION_CATEGORY = "technical_investigation"
_ROBOTS_CATEGORY = "robots"
_ROUTE_CATEGORY = "route"
_ACRONYMS = {
    "api": "API",
    "html": "HTML",
    "http": "HTTP",
    "json": "JSON",
    "ssh": "SSH",
    "tcp": "TCP",
    "url": "URL",
}
_DISPLAY_WORDS = {"artifact": "artefact"}
PROJECT_HTML_REPORT_FILENAME = "report.html"


@dataclass(frozen=True)
class _HtmlValue:
    value: str


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
        '<p class="disclaimer"><strong>This report distinguishes direct observations, '
        "documentation statements, and deterministic relationships; none is a "
        "confirmed vulnerability.</strong> It presents existing BugSlyce evidence "
        "and review models and does not prove exhaustive coverage.</p>"
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


def write_html_report(
    input_dir: Path,
    output: Path,
    *,
    application_service_model: ApplicationServiceModel | None = None,
) -> Path:
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
    model = (
        build_html_report_model(input_dir)
        if application_service_model is None
        else build_html_report_model(
            input_dir,
            application_service_model=application_service_model,
        )
    )
    output.write_text(render_html_report(model), encoding="utf-8")
    return output


def write_project_html_report(
    input_dir: Path,
    output: Path | None = None,
    *,
    application_service_model: ApplicationServiceModel | None = None,
) -> Path:
    """Atomically write the canonical project-local offline HTML report."""

    input_root = input_dir.expanduser().resolve()
    if not input_root.is_dir():
        raise ValueError(f"input path is not a directory: {input_root}")
    requested = output.expanduser() if output is not None else Path(PROJECT_HTML_REPORT_FILENAME)
    if not requested.is_absolute():
        requested = input_root / requested
    if requested.is_symlink():
        raise ValueError("project HTML report output must not be a symbolic link")
    output_path = requested.resolve(strict=False)
    canonical_output = input_root / PROJECT_HTML_REPORT_FILENAME
    if output_path != canonical_output:
        raise ValueError(f"project HTML report output must be {canonical_output}")
    if output_path.exists() and not output_path.is_file():
        raise ValueError("project HTML report output is not a regular file")
    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as existing:
            prefix = existing.read(8192)
        if "<title>BugSlyce Evidence Report - " not in prefix:
            raise ValueError(
                "existing project HTML report output is not recognised as BugSlyce-owned"
            )

    model = (
        build_html_report_model(input_root)
        if application_service_model is None
        else build_html_report_model(
            input_root,
            application_service_model=application_service_model,
        )
    )
    if PROJECT_HTML_REPORT_FILENAME in getattr(model, "available_artefacts", ()):
        model = replace(
            model,
            available_artefacts=tuple(
                name
                for name in model.available_artefacts
                if name != PROJECT_HTML_REPORT_FILENAME
            ),
        )
    rendered = render_html_report(model)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{PROJECT_HTML_REPORT_FILENAME}.",
        suffix=".tmp",
        dir=input_root,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        if output_path.is_symlink():
            raise ValueError("project HTML report output must not be a symbolic link")
        os.replace(temporary, output_path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    return output_path


def _render_sections(model: HtmlReportModel) -> list[tuple[str, str, str]]:
    context_index = build_investigation_context_presentation_index(
        model.operator_report_view.investigation_context
    )
    sections = [
        ("overview", "Overview", _overview_section(model)),
        (
            "operator-summary",
            "Operator summary",
            _operator_summary_section(model, context_index),
        ),
        ("analysis-coverage", "Analysis coverage", _analysis_coverage_section(model)),
        ("human-triage", "Supporting triage evidence", _human_triage_section(model)),
        ("confidence", "Collection confidence", _confidence_section(model)),
        ("manual-review", "Manual review leads", _candidate_section(model)),
        ("routes", "Routes and provenance", _routes_section(model, context_index)),
        ("http-evidence", "HTTP evidence", _http_section(model)),
    ]
    if model.deep_disclosures:
        sections.insert(
            2,
            (
                "deep-interpretations",
                "Deep interpretations",
                _deep_interpretation_section(model),
            ),
        )
    if (
        model.project_state.warnings
        or model.metadata_collection.skipped
        or model.source_collection.skipped
    ):
        sections.insert(
            3,
            ("limitations", "Warnings and skipped collection", _limitations_section(model)),
        )
    canonical_presentation = model.operator_brief_presentation
    if canonical_presentation is not None:
        legacy_primary_sections = {"operator-summary", "human-triage", "manual-review"}
        sections = [
            section for section in sections if section[0] not in legacy_primary_sections
        ]
        if model.operator_brief.threads:
            sections.insert(
                1,
                (
                    "investigation-priorities",
                    "Investigation priorities",
                    _investigation_priorities_section(model),
                ),
            )
        application_context = tuple(
            item
            for item in canonical_presentation.investigation_subjects
            if item.source_family == "application_service"
            and item.disposition != "supporting_context"
        )
        if application_context:
            sections.append(
                (
                    "documented-application-service-context",
                    "Documented application and service context",
                    _documented_application_service_context_section(
                        application_context
                    ),
                )
            )
        if any(
            item.source_family != "application_service"
            for item in canonical_presentation.investigation_subjects
        ):
            sections.append(
                (
                    "technical-investigation-evidence",
                    "Technical investigation evidence",
                    _technical_investigation_evidence_section(model),
                )
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
    initial_retained_routes = model.initial_retained_javascript_routes
    if (
        initial_retained_routes is not None
        and initial_retained_routes.candidates
    ):
        sections.append(
            (
                "initial-retained-javascript-routes",
                "Initial retained JavaScript routes",
                _initial_retained_javascript_routes_section(model),
            )
        )
    robots_items = tuple(
        item
        for item in model.project_state.http_artifacts
        if item.artifact_type in {"robots", "robots_value"}
    )
    if robots_items:
        sections.append(("robots", "Robots evidence", _robots_section(robots_items)))
    sections.extend(
        [
            ("evidence", "Evidence records", _evidence_section(model, context_index)),
            ("artefacts", "Artefact index", _artefact_section(model)),
        ]
    )
    return sections


def _investigation_priorities_section(model: HtmlReportModel) -> str:
    supporting_by_thread = _application_service_contexts_by_thread(model)
    return _section(
        "investigation-priorities",
        "Investigation priorities",
        "".join(
            _operator_brief_thread(
                thread,
                supporting_by_thread.get(thread.thread_id, ()),
            )
            for thread in model.operator_brief.threads
        ),
    )


def _application_service_contexts_by_thread(
    model: HtmlReportModel,
) -> dict[str, tuple[object, ...]]:
    presentation = model.operator_brief_presentation
    if presentation is None:
        return {}
    grouped: dict[str, list[object]] = {}
    for item in presentation.investigation_subjects:
        if (
            item.source_family == "application_service"
            and item.disposition == "supporting_context"
            and item.thread_id
        ):
            grouped.setdefault(item.thread_id, []).append(item)
    return {
        thread_id: tuple(sorted(values, key=lambda value: value.policy_key))
        for thread_id, values in grouped.items()
    }


def _operator_brief_thread(thread: object, supporting: tuple[object, ...] = ()) -> str:
    metadata = (
        ("Signal", thread.signal),
        ("Endpoints", ", ".join(thread.endpoints)),
        ("Origins", ", ".join(thread.origins)),
    )
    fields = "".join(
        f'<dt>{_h(label)}</dt><dd>{_h(value)}</dd>'
        for label, value in metadata
        if value
    )
    return (
        '<article class="investigation-subject searchable">'
        f'<h3>{_h(thread.title)}</h3>'
        f'<p class="investigation-rank searchable">Rank {_h(thread.rank)}</p>'
        f'<dl class="investigation-meta">{fields}</dl>'
        f'<p class="searchable"><strong>Why review:</strong> {_h(thread.why_review)}</p>'
        f'<p class="searchable"><strong>Next review step:</strong> '
        f'{_h(thread.next_review_step)}</p>'
        f'{_operator_brief_thread_facts(thread.facts)}'
        f'{_application_service_supporting_context(supporting)}'
        f'{_operator_brief_thread_provenance(thread)}'
        "</article>"
    )


def _operator_brief_thread_facts(facts: tuple[object, ...]) -> str:
    if not facts:
        return ""
    rows = "".join(
        f'<li class="searchable">{_truth_badge(fact.semantic_class.value)}'
        f'{_h(fact.summary)}{_operator_brief_fact_context(fact)}</li>'
        for fact in facts
    )
    return (
        '<div class="direct-evidence"><p><strong>Evidence and relationship context</strong></p><ul>'
        + rows
        + "</ul></div>"
    )


def _truth_badge(value: str) -> str:
    label = {
        "observed": "Observed",
        "documented": "Documented",
        "derived": "Derived",
    }.get(value, _human_label(value))
    return f'<span class="truth-badge truth-{_a(value)}">{_h(label)}</span>'


def _application_service_supporting_context(items: tuple[object, ...]) -> str:
    if not items:
        return ""
    return (
        '<div class="application-service-context"><p><strong>'
        'Application/service context</strong></p>'
        + "".join(_investigation_subject(item) for item in items)
        + "</div>"
    )


def _operator_brief_fact_context(fact: object) -> str:
    context = (
        ("Endpoints", ", ".join(fact.endpoints)),
        ("Origins", ", ".join(fact.origins)),
        ("Route", fact.route),
        ("Service", fact.service),
        ("Share", fact.share_name),
        ("Share type", fact.share_type),
        ("Parameter", fact.parameter_name),
        ("Form method", fact.form_method),
        ("Form action", fact.form_action),
        ("HTTP method", fact.http_method),
        ("HTTP status", fact.http_status_code),
    )
    values = "; ".join(
        f"{label}: {value}" for label, value in context if value not in ("", None)
    )
    return f'<span class="fact-context"> ({_h(values)})</span>' if values else ""


def _operator_brief_thread_provenance(thread: object) -> str:
    fact_rows = "".join(
        "<li>"
        f'<code>{_h(fact.fact_id)}</code>'
        f'{_investigation_text_values("Evidence IDs", fact.evidence_ids)}'
        f'{_investigation_text_values("Artefact references", fact.artefact_references)}'
        f'{_investigation_text_values("Source references", tuple(f"{reference.source_kind}:{reference.source_id}" for reference in fact.source_references))}'
        f'{_investigation_text_values("Body SHA-256", (fact.body_sha256,) if fact.body_sha256 else ())}'
        "</li>"
        for fact in thread.facts
    )
    thread_values = (
        _investigation_list_values("Thread ID", (thread.thread_id,)),
        _investigation_list_values("Identity key", (thread.identity_key,)),
        _investigation_list_values("Subject kind", (thread.subject_kind.value,)),
        _investigation_list_values("Evidence IDs", thread.evidence_ids),
        _investigation_list_values("Source lead IDs", thread.source_lead_ids),
        _investigation_list_values("Source artefacts", thread.source_artefacts),
    )
    technical_context = (
        _investigation_conflicts(thread.conflicts)
        + _investigation_coverage(thread.coverage_limitations)
    )
    return (
        '<details class="thread-provenance searchable"><summary>Technical provenance</summary>'
        '<div class="provenance"><p><strong>Provenance</strong></p><ul>'
        + "".join(thread_values)
        + fact_rows
        + "</ul></div>"
        + technical_context
        + "</details>"
    )


def _technical_investigation_evidence_section(model: HtmlReportModel) -> str:
    presentation = model.operator_brief_presentation
    if presentation is None:
        raise ValueError("Technical investigation evidence requires canonical presentation.")
    content = (
        '<p class="section-note">Canonical technical subjects and provenance are retained '
        "for supporting review. These disclosures are not a second priority ranking.</p>"
        + "".join(
            _technical_investigation_subject(item)
            for item in presentation.investigation_subjects
            if item.source_family != "application_service"
        )
    )
    return _section(
        "technical-investigation-evidence",
        "Technical investigation evidence",
        content,
    )


def _documented_application_service_context_section(
    items: tuple[object, ...],
) -> str:
    return (
        '<p class="section-note">Documentation statements and deterministic '
        "relationships are retained as context. They are not runtime observations "
        "or confirmed vulnerabilities.</p>"
        + "".join(_technical_investigation_subject(item) for item in items)
    )


def _technical_investigation_subject(item: object) -> str:
    label = item.display_title
    return (
        '<details class="record searchable technical-investigation-subject" '
        f'data-category="{_a(_TECHNICAL_INVESTIGATION_CATEGORY)}" data-status="">'
        f'<summary>{_h(label)}</summary>{_investigation_subject(item)}</details>'
    )


def _investigation_subject(item: object) -> str:
    metadata = (
        ("Disposition", _human_label(item.disposition)),
        ("Subject kind", item.subject_kind.value),
        ("Source family", item.source_family),
    )
    rank = (
        f'<p class="investigation-rank searchable">Rank {_h(item.rank)}</p>'
        if item.rank is not None
        else ""
    )
    fields = "".join(
        f'<dt>{_h(label)}</dt><dd>{_h(value)}</dd>' for label, value in metadata
    )
    return (
        f'<article class="investigation-subject searchable" '
        f'data-policy-key="{_a(item.policy_key)}">'
        f'<h3>{_h(item.display_title)}</h3>{rank}<dl class="investigation-meta">{fields}</dl>'
        f'{_investigation_facts(item.facts)}'
        f'{_investigation_conflicts(item.conflicts)}'
        f'{_investigation_coverage(item.coverage_limitations)}'
        f'{_investigation_source_native_detail(item.source_native_detail)}'
        f'{_investigation_provenance(item)}'
        "</article>"
    )


def _investigation_facts(facts: tuple[object, ...]) -> str:
    if not facts:
        return ""
    rows = "".join(
        "<li>"
        f'{_truth_badge(fact.semantic_class.value)}{_h(fact.summary)}'
        f'{_investigation_text_values("Evidence IDs", fact.evidence_ids)}'
        f'{_investigation_text_values("Artefact references", fact.artefact_references)}'
        "</li>"
        for fact in facts
    )
    return '<div class="direct-evidence"><p><strong>Evidence and relationship context</strong></p><ul>' + rows + "</ul></div>"


def _investigation_conflicts(conflicts: tuple[object, ...]) -> str:
    if not conflicts:
        return ""
    rows = "".join(
        "<li>"
        f'<code>{_h(conflict.conflict_id)}</code>: {_h(conflict.summary)}'
        + "<ul>"
        + "".join(
            "<li>"
            f'<code>{_h(observation.observation_id)}</code>: '
            f'{_h(observation.method)} {_h(observation.endpoint)} '
            f'(status {_h(observation.status_code)})'
            f'{_investigation_text_values("Evidence IDs", observation.evidence_ids)}'
            f'{_investigation_text_values("Artefact references", observation.artefact_references)}'
            "</li>"
            for observation in conflict.observations
        )
        + "</ul></li>"
        for conflict in conflicts
    )
    return (
        '<div class="conflicting-observations"><p><strong>Conflicting observations</strong></p><ul>'
        + rows
        + "</ul></div>"
    )


def _investigation_coverage(limitations: tuple[object, ...]) -> str:
    if not limitations:
        return ""
    rows = "".join(
        "<li>"
        f'<code>{_h(limitation.source_id)}</code>: {_h(limitation.summary)}'
        "</li>"
        for limitation in limitations
    )
    return (
        '<div class="coverage-limitation"><p><strong>Coverage limitation</strong></p><ul>'
        + rows
        + "</ul></div>"
    )


def _investigation_source_native_detail(detail: object | None) -> str:
    if detail is None:
        return ""
    interpretation = detail.interpretation
    interpretation_fields = "".join(
        f'<li>{_h(label)}: {_h(value)}</li>'
        for label, value in (
            ("Artefact type", getattr(interpretation, "artefact_type", "")),
            ("Value SHA-256", getattr(interpretation, "value_sha256", "")),
        )
        if value
    )
    return (
        '<div class="source-native-detail"><p><strong>Source-native detail</strong></p><ul>'
        f'<li>Family: {_h(detail.family.value)}</li>'
        f'{_investigation_list_values("Endpoints", detail.endpoints)}'
        f'{_investigation_list_values("Origins", detail.origins)}'
        f'{_investigation_list_values("Source references", tuple(reference.source_id for reference in detail.source_references))}'
        f"{interpretation_fields}"
        "</ul></div>"
    )


def _investigation_provenance(item: object) -> str:
    values = (
        _investigation_list_values("Policy key", (item.policy_key,)),
        _investigation_list_values(
            "Semantic subject key",
            (item.semantic_subject_key,) if item.semantic_subject_key else (),
        ),
        _investigation_list_values("Evidence IDs", item.evidence_ids),
        _investigation_list_values("Artefact references", item.artefact_references),
        _investigation_list_values("Source lead IDs", item.source_lead_ids),
    )
    fact_rows = "".join(
        "<li>Fact ID: "
        f'<code>{_h(fact.fact_id)}</code>'
        f'{_investigation_text_values("Source references", tuple(f"{reference.source_kind}:{reference.source_id}" for reference in fact.source_references))}'
        "</li>"
        for fact in item.facts
    )
    return (
        '<div class="provenance"><p><strong>Provenance</strong></p><ul>'
        + "".join(values)
        + fact_rows
        + "</ul></div>"
    )


def _investigation_list_values(label: str, values: tuple[object, ...]) -> str:
    if not values:
        return ""
    return f"<li>{_h(label)}: {_h(', '.join(str(value) for value in values))}</li>"


def _investigation_text_values(label: str, values: tuple[object, ...]) -> str:
    if not values:
        return ""
    return f'<p class="provenance">{_h(label)}: {_h(", ".join(str(value) for value in values))}</p>'


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
            "Assessed-origin URLs",
            str(sum(group.origin_group == "assessed" for group in model.route_groups)),
        ),
        (
            "External references",
            str(sum(group.origin_group == "external" for group in model.route_groups)),
        ),
        (
            "Relative / unclassified",
            str(sum(group.origin_group == "relative" for group in model.route_groups)),
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


def _operator_summary_section(
    model: HtmlReportModel,
    context_index: InvestigationContextPresentationIndex,
) -> str:
    summary = model.operator_summary
    if summary.ranked_leads:
        review = "".join(
            _detail_card(
                f"{lead.rank}. {lead.title}",
                (
                    ("Lead ID", lead.lead_id),
                    ("Type", lead.lead_type),
                    ("Rationale", lead.rationale),
                    ("Endpoint(s)", _compact_list(lead.endpoints, "endpoints")),
                    ("Evidence", _compact_list(lead.evidence_ids, "evidence IDs")),
                    ("Suggested next action", lead.suggested_next_action),
                    ("Signal", lead.signal),
                ),
                category=_OPERATOR_SUMMARY_CATEGORY,
                element_id=(
                    context.anchor_reference.anchor_token if context is not None else ""
                ),
                extra_html=(
                    _html_investigation_context(
                        context.context_items,
                        context_index,
                        frozenset(item.id for item in model.project_state.evidence),
                        frozenset(group.url for group in model.route_groups),
                    )
                    if context is not None and context.context_items
                    else ""
                ),
            )
            for lead in summary.ranked_leads
            for context in (context_index.primary_by_anchor_id.get(lead.lead_id),)
        )
    else:
        review = _empty("No evidence-backed leads met the existing summary threshold.")
    fallback = ""
    if model.operator_summary_fallback:
        fallback = (
            f'<p class="fallback searchable"><strong>{_h(model.operator_summary_fallback)}</strong></p>'
            + (
                '<details class="fallback-details"><summary>Unavailable Deep summary inputs</summary><ul>'
                + "".join(
                    f"<li><code>{_h(name)}</code></li>"
                    for name in model.missing_deep_summary_inputs
                )
                + "</ul></details>"
                if model.missing_deep_summary_inputs
                else ""
            )
        )
    elif model.deep_summary_complete:
        fallback = (
            '<p class="model-status searchable">Operator summary reconstructed from '
            "complete structured Deep inputs.</p>"
        )
    low_signal = "".join(
        f'<li class="searchable"><strong>{_h(item.title)}</strong>: {_h(item.reason)} '
        f'<div class="provenance">Endpoints: {_render_value(_compact_list(item.endpoints, "endpoints"))}</div>'
        f'<div class="provenance">Evidence: {_render_value(_compact_list(item.evidence_ids, "evidence IDs"))}</div></li>'
        for item in summary.low_signal
    ) or "<li>No structured low-signal items were identified.</li>"
    coverage = "".join(f'<li class="searchable">{_h(item)}</li>' for item in summary.coverage)
    return _section(
        "operator-summary",
        "Operator summary",
        fallback + '<h3>Review first</h3>' + review
        + '<details><summary>Low-signal / avoid rabbit holes</summary><ul>'
        + low_signal
        + "</ul></details>"
        + '<details><summary>Current coverage</summary><ul>'
        + coverage
        + "</ul></details>",
    )


def _analysis_coverage_section(model: HtmlReportModel) -> str:
    """Render only source-attributable C2 claims supplied by the shared view."""

    items = build_analysis_coverage_presentation(
        model.operator_report_view.analysis_coverage
    )
    introduction = (
        '<p class="section-note">Coverage is evidence-limited: this report lists only '
        "analysis states proven by retained execution evidence. An analyser/source not "
        "listed here may have run; absence is not a clean result.</p>"
    )
    if not items:
        return _section(
            "analysis-coverage",
            "Analysis coverage",
            introduction
            + _empty(
                "No source-attributable analysis coverage claims can be proven from "
                "the retained execution evidence available to this report."
            ),
        )
    records = "".join(
        _detail_card(
            presentation.state_label,
            (
                ("Capability", presentation.item.unit.capability),
                ("Source role", presentation.item.unit.source_role),
                ("Source identity", presentation.item.unit.source_id),
                ("Finding count", presentation.finding_count_label or ""),
                ("Execution", presentation.execution_note_label or ""),
                ("Reason", presentation.unknown_reason_label or ""),
            ),
            category=_ANALYSIS_COVERAGE_CATEGORY,
        )
        for presentation in items
    )
    return _section("analysis-coverage", "Analysis coverage", introduction + records)


def _html_investigation_context(
    items: tuple[InvestigationContextItem, ...],
    index: InvestigationContextPresentationIndex,
    rendered_evidence_ids: frozenset[str] = frozenset(),
    rendered_route_urls: frozenset[str] = frozenset(),
) -> str:
    rendered = "".join(
        _html_context_item(
            item,
            index,
            rendered_evidence_ids,
            rendered_route_urls,
        )
        for item in items
    )
    return (
        '<div class="investigation-context">'
        "<h4>Investigation context</h4>"
        f'<ul class="context-list">{rendered}</ul></div>'
    )


def _html_context_item(
    item: InvestigationContextItem,
    index: InvestigationContextPresentationIndex,
    rendered_evidence_ids: frozenset[str],
    rendered_route_urls: frozenset[str],
) -> str:
    details: list[str] = []
    if item.route_url:
        route_reference = (
            index.route_reference_by_url.get(item.route_url)
            if item.route_url in rendered_route_urls
            else None
        )
        route = f"<code>{_h(item.route_url)}</code>"
        if route_reference is not None:
            route = f'<a href="#{_a(route_reference.anchor_token)}">{route}</a>'
        details.append(f"route {route}")
    if item.source_ids:
        details.append(
            "source " + ", ".join(f"<code>{_h(value)}</code>" for value in item.source_ids)
        )
    if item.source_urls:
        details.append(
            "source URL "
            + ", ".join(f"<code>{_h(value)}</code>" for value in item.source_urls)
        )
    if item.body_sha256s:
        details.append(
            "body SHA-256 "
            + ", ".join(f"<code>{_h(value)}</code>" for value in item.body_sha256s)
        )
    if item.related_ids:
        details.append(
            "related context "
            + ", ".join(f"<code>{_h(value)}</code>" for value in item.related_ids)
        )
    if item.evidence_ids:
        evidence = []
        for evidence_id in item.evidence_ids:
            reference = (
                index.reference_by_target.get(("evidence", evidence_id))
                if evidence_id in rendered_evidence_ids
                else None
            )
            if reference is None:
                evidence.append(f"<code>{_h(evidence_id)}</code>")
            else:
                evidence.append(
                    f'<a href="#{_a(reference.anchor_token)}"><code>{_h(evidence_id)}</code></a>'
                )
        details.append("evidence " + ", ".join(evidence))
    suffix = f"; {'; '.join(details)}" if details else ""
    return (
        '<li class="context-item">'
        f'<span class="context-kind">{_h(item.relationship_kind.title())}</span> '
        f"{_h(item.label)}{suffix}</li>"
    )


def _html_backlinks(references: tuple[ReportNavigationReference, ...]) -> str:
    links = ", ".join(
        f'<a href="#{_a(reference.anchor_token)}">'
        "Review First context</a>"
        for reference in references
    )
    return f'<p class="context-backlinks"><strong>Back to:</strong> {links}</p>'


def _html_evidence_identity(
    evidence_id: str,
    index: InvestigationContextPresentationIndex,
) -> _HtmlValue:
    backlink = index.evidence_backlink_by_id.get(evidence_id)
    content = _h(evidence_id)
    if backlink is not None:
        content += _html_backlinks(backlink.primary_anchor_references)
    return _HtmlValue(content)


def _human_triage_section(model: HtmlReportModel) -> str:
    brief = model.human_triage_brief
    supporting = "".join(
        _detail_card(
            item.title,
            (
                ("Priority", item.priority),
                ("Category", item.category),
                ("Source", item.source),
                ("URL", item.url),
                ("Value", item.value),
                ("Why it matters", item.why_it_matters),
                ("Suggested manual action", item.suggested_manual_action),
                ("Evidence", _compact_list(item.evidence_ids, "evidence IDs")),
                ("Signal", item.signal),
            ),
            category=_HUMAN_TRIAGE_CATEGORY,
        )
        for item in brief.start_here
    ) or _empty("No additional supporting evidence prompts were identified.")
    values = "".join(
        _detail_card(
            item.title,
            (
                ("Source", item.source),
                ("URL", item.url),
                ("Value", item.value),
                ("Why it matters", item.why_it_matters),
                ("Evidence", _compact_list(item.evidence_ids, "evidence IDs")),
            ),
            category=_HUMAN_TRIAGE_CATEGORY,
        )
        for item in brief.evidence_values
    ) or _empty("No additional source-comment, metadata, or encoded values were promoted.")
    return _section(
        "human-triage",
        "Supporting triage evidence",
        (
            '<p class="section-note">These supporting evidence prompts do not define or alter '
            "the canonical lead ranking in the Operator summary.</p>"
            '<h3>Supporting evidence prompts (not ranked)</h3>'
            + supporting
            + '<h3>Evidence values worth noting</h3>'
            + values
        ),
    )


def _deep_interpretation_section(model: HtmlReportModel) -> str:
    return _section(
        "deep-interpretations",
        "Existing structured Deep interpretations",
        '<p class="section-note">These are existing deterministic interpretations retained by Deep orchestration. Disclosed route values were not requested by this report.</p>'
        + "".join(
            _detail_card(
                disclosure.title,
                (
                    ("Category", _human_label(disclosure.category)),
                    ("Source URL(s)", _compact_list(disclosure.urls, "URLs")),
                    ("Final response URL(s)", _compact_list(disclosure.final_urls, "URLs")),
                    ("Observed values", _compact_list(disclosure.observed_values, "values")),
                    ("Bounded excerpt", _compact_list(disclosure.evidence_excerpt, "lines")),
                    ("Evidence", _compact_list(disclosure.evidence_ids, "evidence IDs")),
                    ("Body SHA-256", disclosure.source_body_sha256),
                    (
                        "Collection boundary",
                        "No request was generated from these disclosed values.",
                    ),
                ),
                category=_DEEP_INTERPRETATION_CATEGORY,
            )
            for disclosure in model.deep_disclosures
        ),
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
                    ("Category", _human_label(notice.category)),
                    ("Direct fact", notice.direct_fact),
                    ("What remains unknown", notice.operator_implication),
                    ("Stage or tool", _human_label(notice.stage_or_tool)),
                    ("Counts", _counts(notice.counts)),
                    ("Evidence", _compact_list(notice.evidence_ids, "evidence IDs")),
                    ("Retained artefact", _path_list(notice.artefact_references)),
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
    if not model.candidates and not model.review_occurrence_groups:
        content = _empty("No deterministic manual review lead is present in this artefact set.")
    else:
        candidate_content = "".join(
            _detail_card(
                candidate.title,
                (
                    ("Lead ID", candidate.id),
                    ("Type", _human_label(candidate.candidate_type)),
                    ("Manual attention", _human_label(candidate.priority)),
                    ("Existing rationale", candidate.rationale),
                    ("Assets", _compact_list(candidate.affected_assets, "assets")),
                    ("Endpoints", _compact_list(candidate.affected_endpoints, "endpoints")),
                    ("Evidence", _compact_list(candidate.evidence_ids, "evidence IDs")),
                    ("Suggested manual validation", _joined(candidate.suggested_manual_validation)),
                ),
                category=candidate.candidate_type,
            )
            for candidate in model.candidates
        )
        occurrence_content = "".join(
            _review_occurrence_group_card(group)
            for group in model.review_occurrence_groups
        )
        content = candidate_content + occurrence_content
    return _section(
        "manual-review",
        "Manual review leads",
        '<p class="section-note">Priority is manual attention priority, not vulnerability severity.</p>'
        + content,
    )


def _review_occurrence_group_card(group: ReviewOccurrenceGroup) -> str:
    members = tuple(
        (
            f"{member.lead_id}: "
            + "; ".join(
                part
                for part in (
                    (
                        f"line {member.line_number}"
                        if member.line_number is not None
                        else "line not recorded"
                    ),
                    (
                        "evidence " + ", ".join(member.evidence_ids)
                        if member.evidence_ids
                        else "evidence not recorded"
                    ),
                )
                if part
            )
        )
        for member in group.members
    )
    source = "; ".join(
        part
        for part in (
            group.source_label or group.source_id,
            f"kind={group.source_kind}" if group.source_kind else "",
            (
                f"url={group.url}"
                if group.url
                else f"path={group.path}"
                if group.path
                else ""
            ),
        )
        if part
    )
    return _detail_card(
        group.title,
        (
            ("Review group ID", group.group_id),
            ("Manual attention", _human_label(group.priority)),
            ("Category", _human_label(group.category)),
            ("Source", source),
            ("Semantic value", group.raw_value),
            ("Occurrence count", group.occurrence_count),
            ("Child occurrences", _joined(members)),
            ("Evidence", _compact_list(group.evidence_ids, "evidence IDs")),
            ("Existing explanation", group.explanation),
            (
                "Suggested manual validation",
                _joined(group.suggested_manual_validation),
            ),
        ),
        category=group.category,
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
                _human_label(item.reason),
                _human_label(item.source),
                _compact_list(item.evidence_ids, "evidence IDs"),
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
                render_deep_source_route_skip_reason(item.reason),
                _human_label(item.source),
                _compact_list(item.evidence_ids, "evidence IDs"),
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


def _routes_section(
    model: HtmlReportModel,
    context_index: InvestigationContextPresentationIndex,
) -> str:
    labels = (
        ("assessed", "Assessed-origin URLs"),
        ("external", "External references"),
        ("relative", "Relative or unclassified values"),
    )
    content = ""
    for group_id, label in labels:
        groups = tuple(group for group in model.route_groups if group.origin_group == group_id)
        if not groups:
            continue
        content += f"<h3>{_h(label)} <span class=\"count\">({len(groups)})</span></h3>"
        content += "".join(
            _route_group_card(group, context_index) for group in groups
        )
    if not content:
        content = _empty("No structured route records are available.")
    return _section("routes", "Routes and provenance", content)


def _route_group_card(
    group: HtmlRouteGroup,
    context_index: InvestigationContextPresentationIndex,
) -> str:
    statuses = tuple(
        str(value)
        for value in sorted(
            {
                item.status_code
                for item in group.observations
                if item.status_code is not None
            }
        )
    )
    redirects = tuple(
        sorted(
            {
                item.redirect_location
                for item in group.observations
                if item.redirect_location
            }
        )
    )
    sources = tuple(sorted({item.source for item in group.observations if item.source}))
    observation_rows = [
        _row(
            (
                _human_label(item.record_kind),
                item.path,
                _status(item.status_code),
                item.redirect_location or "None recorded",
                _joined(item.query_params),
                _compact_list(item.evidence_ids, "evidence IDs"),
                _path_value(item.source),
            ),
            status=item.status_code,
            category=item.record_kind,
        )
        for item in group.observations
    ]
    details = (
        '<dl class="route-summary">'
        f"<dt>Statuses</dt><dd>{_render_value(_compact_list(statuses, 'statuses'))}</dd>"
        f"<dt>Redirects</dt><dd>{_render_value(_compact_list(redirects, 'redirects'))}</dd>"
        f"<dt>Evidence</dt><dd>{_render_value(_compact_list(group.evidence_ids, 'evidence IDs'))}</dd>"
        f"<dt>Sources</dt><dd>{_render_value(_path_list(sources))}</dd>"
        "</dl>"
        '<details class="observation-list"><summary>All underlying observations '
        f"({len(group.observations)})</summary>"
        + _table(
            (
                "Record kind",
                "Path",
                "Status",
                "Redirect",
                "Parameters",
                "Evidence",
                "Source artefact",
            ),
            observation_rows,
        )
        + "</details>"
    )
    backlink = context_index.route_backlink_by_url.get(group.url)
    if backlink is not None:
        details += _html_backlinks(backlink.primary_anchor_references)
    route_statuses = " ".join(statuses)
    route_categories = " ".join(
        sorted({item.record_kind for item in group.observations})
    )
    route_reference = context_index.route_reference_by_url.get(group.url)
    id_attribute = (
        f' id="{_a(route_reference.anchor_token)}"'
        if route_reference is not None
        else ""
    )
    return (
        f'<details{id_attribute} class="record searchable route-group" data-category="{_ROUTE_CATEGORY}" '
        f'data-categories="{_a(route_categories)}" data-status="{_a(route_statuses)}">'
        f'<summary class="route-url">{_h(group.url)}</summary>{details}</details>'
    )


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
                    _compact_list(service.evidence_ids, "evidence IDs"),
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
                    _human_label(item.collection_section),
                    _compact_list(item.evidence_ids, "evidence IDs"),
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
        content += '<h3>Successful 2xx content promoted for priority review</h3>' + "".join(
            _detail_card(
                review.canonical_url,
                (
                    ("Review ID", review.review_id),
                    ("Response", f"HTTP {review.status_code}; {review.body_bytes} bytes"),
                    ("Content type", review.content_type or "Not recorded"),
                    ("Bounded preview", review.body_preview),
                    ("Evidence", _compact_list(review.evidence_ids, "evidence IDs")),
                    ("Retained artefact", _path_list(review.artefact_references)),
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
                    ("Evidence", _compact_list(cluster.evidence_ids, "evidence IDs")),
                    ("Retained artefacts", _path_list(cluster.artefact_references)),
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
                _human_label(item.origin_relationship),
                _human_label(item.auth_path_transition),
                item.interpretation_note,
                _compact_list(item.evidence_ids, "evidence IDs"),
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
                    ("Category", _human_label(group.category)),
                    ("Reason", group.reason),
                    *(
                        (
                            (
                                "Representative request",
                                group.representative_requested_url or "Not recorded",
                            ),
                            ("Member count", str(group.member_count)),
                            (
                                "Member fingerprints",
                                _joined(group.fingerprint_ids),
                            ),
                            (
                                "Member evidence IDs",
                                _joined(group.evidence_ids),
                            ),
                            (
                                "Structural signals",
                                _joined(group.structural_signals),
                            ),
                        )
                        if group.category == "request_reflecting_template_group"
                        else ()
                    ),
                    ("URLs", _joined(group.requested_urls)),
                    ("Statuses", _joined(tuple(str(value) for value in group.status_codes))),
                    ("Existing interpretation", group.interpretation),
                    ("Evidence", _compact_list(group.evidence_ids, "evidence IDs")),
                ),
                category=group.category,
            )
            for group in model.similarity_review.groups
        ),
    )


def _forms_section(rows: tuple[tuple[object, ...], ...]) -> str:
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
                _human_label(item.artifact_type),
                item.url,
                item.value,
                _compact_list(item.evidence_ids, "evidence IDs"),
                _path_value(item.source_file),
                _compact_list(
                    [_human_label(value) for value in item.tags],
                    "tags",
                ),
            ),
            category=item.artifact_type,
        )
        for item in items
    ]
    return _section(
        "source-evidence",
        "Source and JavaScript-derived evidence",
        _table(("Type", "URL", "Observed value", "Evidence", "Source artefact", "Tags"), rows),
    )


def _initial_retained_javascript_routes_section(
    model: HtmlReportModel,
) -> str:
    result = model.initial_retained_javascript_routes
    if result is None or not result.candidates:
        return _section(
            "initial-retained-javascript-routes",
            "Initial retained JavaScript routes",
            _empty("No initial-retained static JavaScript route candidates are available."),
        )

    counts = result.summary_counts
    summary = _detail_card(
        "Analysis summary",
        (
            (
                "Manifest HTML sources considered",
                str(counts.manifest_html_sources_considered),
            ),
            (
                "Retained HTML sources scanned",
                str(counts.retained_html_sources_scanned),
            ),
            (
                "Sources over the Deep source-file limit skipped",
                str(counts.source_limit_sources_skipped),
            ),
            (
                "Duplicate retained observations skipped",
                str(counts.duplicate_retained_observations_skipped),
            ),
            (
                "Already represented by Deep collection skipped",
                str(counts.already_represented_by_deep_collection_skipped),
            ),
            (
                "Missing or unreadable sources skipped",
                str(counts.unreadable_or_missing_sources_skipped),
            ),
            (
                "Oversized sources skipped",
                str(counts.oversized_sources_skipped),
            ),
            (
                "Binary sources skipped",
                str(counts.binary_sources_skipped),
            ),
            (
                "Invalid source URLs skipped",
                str(counts.invalid_source_urls_skipped),
            ),
            (
                "Static candidate occurrences found",
                str(counts.candidate_occurrences_found),
            ),
            (
                "Unique aggregated candidates",
                str(counts.unique_aggregated_candidates),
            ),
            (
                "Dynamic template strings skipped",
                str(counts.dynamic_template_strings_skipped),
            ),
            (
                "Dynamic concatenation strings skipped",
                str(counts.dynamic_concatenation_strings_skipped),
            ),
            (
                "Safety notes",
                _compact_list(
                    result.safety_notes,
                    "safety notes",
                    visible_count=len(result.safety_notes),
                ),
            ),
        ),
        category="route",
    )

    candidate_cards = []
    for candidate in result.candidates:
        source_rows = [
            _row(
                (
                    observation.source_role,
                    _path_value(observation.manifest_file),
                    observation.safe_document_url,
                    observation.source_body_sha256,
                    _compact_list(observation.evidence_ids, "evidence IDs"),
                ),
                category="route",
            )
            for observation in candidate.source_observations
        ]
        candidate_cards.append(
            _detail_card(
                (
                    f"{candidate.candidate_id} - "
                    "Initial retained static route candidate"
                ),
                (
                    ("Candidate", candidate.safe_candidate),
                    ("Resolved URL", candidate.safe_resolved_url or ""),
                    ("Path", candidate.path),
                    (
                        "Query parameter names",
                        _compact_list(
                            candidate.query_parameter_names,
                            "query parameter names",
                        ),
                    ),
                    ("Occurrences", str(candidate.occurrence_count)),
                    ("Interpretation", candidate.interpretation),
                ),
                category="route",
                extra_html=(
                    "<h3>Source provenance</h3>"
                    + _table(
                        (
                            "Role",
                            "Manifest file",
                            "Document URL",
                            "Body SHA-256",
                            "Evidence",
                        ),
                        source_rows,
                    )
                ),
            )
        )

    return _section(
        "initial-retained-javascript-routes",
        "Initial retained JavaScript routes",
        (
            '<p class="section-note">'
            "This is offline static analysis of complete initial HTML retained "
            "through the recon manifest. These sources were not Deep-collected "
            "and extracted candidates were not requested. Static candidates are "
            "manual-review context, not confirmed endpoints."
            "</p>"
            + summary
            + "".join(candidate_cards)
        ),
    )


def _robots_section(items: tuple[HTTPArtifact, ...]) -> str:
    rows = [
        _row(
            (
                _human_label(item.artifact_type),
                item.url,
                item.value,
                _compact_list(item.evidence_ids, "evidence IDs"),
                _path_value(item.source_file),
                _compact_list(
                    [_human_label(value) for value in item.tags],
                    "tags",
                ),
            ),
            category=_ROBOTS_CATEGORY,
        )
        for item in items
    ]
    return _section(
        "robots",
        "Robots evidence",
        '<p class="section-note">Already-collected robots entries are reconnaissance context only.</p>'
        + _table(("Type", "URL", "Directive / value", "Evidence", "Source artefact", "Tags"), rows),
    )


def _evidence_section(
    model: HtmlReportModel,
    context_index: InvestigationContextPresentationIndex,
) -> str:
    rows = [
        _row(
            (
                _html_evidence_identity(item.id, context_index),
                _human_label(item.evidence_type),
                item.value,
                _path_value(item.source_file),
                json.dumps(item.context, sort_keys=True, ensure_ascii=True),
            ),
            category=item.evidence_type,
            row_id=(
                reference.anchor_token
                if (
                    reference := context_index.reference_by_target.get(
                        ("evidence", item.id)
                    )
                ) is not None
                else ""
            ),
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
                    _path_value(item.file),
                    _human_label(item.type),
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
    fields: tuple[tuple[str, object], ...],
    *,
    category: str,
    status: int | None = None,
    element_id: str = "",
    extra_html: str = "",
) -> str:
    details = "".join(
        f'<dt>{_h(label)}</dt><dd>{_render_value(value)}</dd>'
        for label, value in fields
        if value
    )
    id_attribute = f' id="{_a(element_id)}"' if element_id else ""
    return (
        f'<details{id_attribute} '
        f'class="record searchable" data-category="{_a(category)}" '
        f'data-status="{_a(str(status) if status is not None else "")}">'
        f'<summary>{_h(title)}</summary><dl>{details}</dl>{extra_html}</details>'
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
    values: tuple[object, ...],
    *,
    status: int | None = None,
    category: str,
    row_id: str = "",
) -> str:
    cells = "".join(f"<td>{_render_value(value)}</td>" for value in values)
    id_attribute = f' id="{_a(row_id)}"' if row_id else ""
    return (
        f'<tr{id_attribute} '
        f'class="record searchable" data-category="{_a(category)}" '
        f'data-status="{_a(str(status) if status is not None else "")}">{cells}</tr>'
    )


def _form_and_parameter_rows(state: ProjectState) -> tuple[tuple[object, ...], ...]:
    rows = [
        (
            _human_label(item.artifact_type),
            item.url,
            item.value,
            _compact_list(item.evidence_ids, "evidence IDs"),
            _path_value(item.source_file),
        )
        for item in state.http_artifacts
        if item.artifact_type in {"form", "input"}
    ]
    rows.extend(
        (
            _human_label("query_parameter_names"),
            endpoint.url,
            _joined(endpoint.query_params),
            _compact_list(endpoint.evidence_ids, "evidence IDs"),
            "project_state.json",
        )
        for endpoint in state.endpoints
        if endpoint.query_params
    )
    return tuple(
        sorted(
            rows,
            key=lambda row: tuple(
                item.value if isinstance(item, _HtmlValue) else str(item)
                for item in row
            ),
        )
    )


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
        f'<option value="{_a(value)}">{_h(_human_label(value))}</option>'
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
        *(group.category for group in model.review_occurrence_groups),
        *(
            item.type
            for item in (state.recon_manifest.artifacts if state.recon_manifest else ())
        ),
    }
    if model.operator_summary.ranked_leads:
        values.add(_OPERATOR_SUMMARY_CATEGORY)
    if model.operator_brief.threads:
        values.add(_OPERATOR_SUMMARY_CATEGORY)
    if (
        model.operator_brief_presentation is not None
        and model.operator_brief_presentation.investigation_subjects
    ):
        values.add(_TECHNICAL_INVESTIGATION_CATEGORY)
    if model.operator_report_view.analysis_coverage.items:
        values.add(_ANALYSIS_COVERAGE_CATEGORY)
    if model.human_triage_brief.start_here or model.human_triage_brief.evidence_values:
        values.add(_HUMAN_TRIAGE_CATEGORY)
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
    if model.deep_disclosures:
        values.add(_DEEP_INTERPRETATION_CATEGORY)
    if model.route_groups:
        values.add(_ROUTE_CATEGORY)
    if any(
        item.artifact_type in {"robots", "robots_value"}
        for item in state.http_artifacts
    ):
        values.add(_ROBOTS_CATEGORY)
    return tuple(sorted(value for value in values if value))


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _a(value: object) -> str:
    return escape(str(value), quote=True)


def _joined(values: tuple[str, ...] | list[str]) -> str:
    return ", ".join(values) if values else "None recorded"


def _render_value(value: object) -> str:
    if isinstance(value, _HtmlValue):
        return value.value
    return _h(value or "Not recorded")


def _compact_list(
    values: tuple[str, ...] | list[str],
    noun: str,
    *,
    visible_count: int = 4,
) -> _HtmlValue:
    items = tuple(str(value) for value in values if value)
    if not items:
        return _HtmlValue("None recorded")
    if len(items) <= visible_count:
        return _HtmlValue(_h(", ".join(items)))
    visible = ", ".join(items[:visible_count])
    complete = "".join(f"<li>{_h(item)}</li>" for item in items)
    return _HtmlValue(
        f'<span class="compact-list">{_h(str(len(items)))} {_h(noun)}: '
        f'{_h(visible)} ... +{len(items) - visible_count} more</span>'
        f'<details class="complete-list"><summary>Show all {len(items)}</summary>'
        f"<ul>{complete}</ul></details>"
    )


def _path_value(value: str) -> _HtmlValue:
    path = Path(value)
    concise = value if not path.is_absolute() else path.name
    if concise == value:
        return _HtmlValue(f"<code>{_h(concise)}</code>")
    return _HtmlValue(
        f"<code>{_h(concise)}</code>"
        '<details class="full-path"><summary>Full original path</summary>'
        f"<code>{_h(value)}</code></details>"
    )


def _path_list(values: tuple[str, ...] | list[str]) -> _HtmlValue:
    if not values:
        return _HtmlValue("None recorded")
    return _HtmlValue(
        '<ul class="path-list">'
        + "".join(f"<li>{_path_value(value).value}</li>" for value in values)
        + "</ul>"
    )


def _human_label(value: str) -> str:
    words = value.split("_")
    rendered = [
        _ACRONYMS.get(
            word.lower(),
            _DISPLAY_WORDS.get(
                word.lower(),
                word.lower() if index else word.lower().capitalize(),
            ),
        )
        for index, word in enumerate(words)
    ]
    if rendered and rendered[0] in _ACRONYMS.values():
        return " ".join(rendered)
    return " ".join(rendered)


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
.metric { background: var(--panel); border: 1px solid var(--line); padding: 12px; }.metric span { display: block; color: var(--muted); font-size: 12px; }.metric strong { font-size: 18px; white-space: nowrap; }
.investigation-subject { margin: 12px 0; padding: 14px; border: 1px solid var(--line); background: var(--panel); }
.investigation-subject > h3 { margin-top: 0; }.investigation-rank { margin: 0 0 8px; color: var(--accent); font-weight: 700; }
.investigation-meta { margin: 0; }.direct-evidence, .conflicting-observations, .coverage-limitation, .source-native-detail, .investigation-subject .provenance { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--line); }
.direct-evidence > p, .conflicting-observations > p, .coverage-limitation > p, .source-native-detail > p, .investigation-subject .provenance > p { margin: 0 0 6px; }
.truth-badge { display: inline-block; margin-right: 7px; padding: 1px 7px; border: 1px solid var(--line); border-radius: 999px; font-size: .78rem; font-weight: 700; }
.truth-observed { color: var(--good); }.truth-documented { color: var(--accent); }.truth-derived { color: var(--muted); }
.application-service-context { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--line); }
.conflicting-observations { border-left: 3px solid var(--warning); padding-left: 10px; }.coverage-limitation { color: var(--muted); }
details { background: var(--panel); border: 1px solid var(--line); margin: 8px 0; } summary { cursor: pointer; font-weight: 700; padding: 11px 13px; }
details > dl, details > ul { margin: 0; padding: 3px 18px 15px; } dl { display: grid; grid-template-columns: minmax(120px, 180px) 1fr; gap: 6px 14px; }
dt { color: var(--muted); font-weight: 700; } dd { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.fallback { border-left: 4px solid var(--warning); background: #fff7ed; padding: 10px 13px; }.model-status { color: var(--muted); }
.count { color: var(--muted); font-weight: 400; white-space: nowrap; }.route-summary { padding: 3px 18px 12px; }
.observation-list, .complete-list, .full-path { margin: 7px 12px 12px; background: #f9fbfb; }.complete-list summary, .full-path summary { padding: 5px 8px; font-size: 12px; }
.path-list { margin: 0; padding-left: 18px; }.path-list .full-path { margin-left: 0; }.route-url { overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); background: var(--panel); } table { border-collapse: collapse; min-width: 100%; }
th, td { text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); padding: 8px 10px; overflow-wrap: anywhere; max-width: 420px; }
th { position: sticky; top: 0; background: #eef2f2; font-size: 12px; } tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #f3f8f7; }.provenance { display: block; color: var(--muted); font-size: 12px; }
.investigation-context { margin: 4px 18px 15px; padding: 10px 12px; border-left: 3px solid var(--accent); background: var(--accent-soft); }
.investigation-context h4 { margin: 0 0 6px; font-size: 14px; }.context-list { margin: 0; padding-left: 20px; }
.context-item { margin: 4px 0; overflow-wrap: anywhere; }.context-kind { font-weight: 700; }.context-backlinks { margin: 5px 0 0; font-size: 12px; }
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
      const statuses = (record.dataset.status || '').split(/\\s+/);
      const categories = [record.dataset.category || '', ...((record.dataset.categories || '').split(/\\s+/))];
      const matchesStatus = !status.value || statuses.includes(status.value);
      const matchesCategory = !category.value || categories.includes(category.value);
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
