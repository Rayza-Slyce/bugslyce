"""Browser-native, read-only projections of the D1 dashboard model."""

from __future__ import annotations

from html import escape

from bugslyce.dashboard.read_model import DashboardReadModel
from bugslyce.recon.investigation_threads import InvestigationThread


ENDPOINT_PREVIEW_LIMIT = 5


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _label(value: str) -> str:
    return value.replace("_", " ").capitalize().replace(" api", " API").replace(" http", " HTTP")


def _page(model: DashboardReadModel, title: str, content: str) -> bytes:
    name = _text(model.project.name)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_text(title)} · BugSlyce</title>"
        "<link rel=\"stylesheet\" href=\"/assets/dashboard.css\">"
        "</head><body><a class=\"skip-link\" href=\"#main\">Skip to investigations</a>"
        "<div class=\"app-shell\"><header class=\"topbar\">"
        "<a class=\"brand\" href=\"/\" aria-label=\"BugSlyce dashboard home\">"
        "<span class=\"brand-mark\">B<span>·</span></span><span>BugSlyce</span></a>"
        "<span class=\"topbar-mode\">Local investigation dashboard</span>"
        "<span class=\"read-only\">Read-only</span></header>"
        f"<main id=\"main\" class=\"main-content\" aria-label=\"{name} dashboard\">"
        f"{content}</main><footer class=\"footer\">"
        "Local projection of saved BugSlyce evidence · No reconnaissance or project changes"
        "</footer></div></body></html>"
    ).encode("utf-8")


def _authority(model: DashboardReadModel) -> str:
    authority = model.authority
    assessment = authority.engagement_assessment
    if assessment is None:
        if model.project.engagement_context == "internal_authorised":
            return "Private programme policy not bound · internal-authorised project"
        return "Private authority assessment unavailable"
    parts = [f"Policy assessment: {_label(assessment.readiness_state)}"]
    if authority.programme_include_rule_count is not None:
        parts.append(
            f"{authority.programme_include_rule_count} inclusion rules · "
            f"{authority.programme_exclude_rule_count} exclusion rules"
        )
    parts.append("Assessment only; this view does not grant execution authority")
    return " · ".join(parts)


def _project_header(model: DashboardReadModel) -> str:
    primary = model.primary_investigation_threads
    count = "Unavailable" if primary is None else str(len(primary))
    target = (
        f"<span class=\"meta-item\"><span class=\"meta-key\">Configured target</span>"
        f"<span>{_text(model.project.target)}</span></span>"
        if model.project.target else ""
    )
    application = (
        "Application model available"
        if model.application_service_model is not None else "Application model unavailable"
    )
    coverage = model.analysis_coverage_evidence
    coverage_text = (
        "Coverage snapshot unavailable" if coverage is None else
        "No analysis coverage units recorded" if not coverage else
        f"{len(coverage)} saved analysis execution records"
    )
    return (
        "<section class=\"project-header\" aria-labelledby=\"project-title\">"
        "<div class=\"eyebrow\">Saved project <span class=\"eyebrow-rule\"></span> "
        "Investigation overview</div>"
        f"<h1 id=\"project-title\">{_text(model.project.name)}</h1>"
        "<div class=\"project-meta\">"
        f"<span class=\"meta-item\"><span class=\"meta-key\">Context</span>"
        f"<span>{_text(_label(model.project.engagement_context))}</span></span>{target}"
        f"<span class=\"meta-item\"><span class=\"meta-key\">Primary threads</span>"
        f"<span>{_text(count)}</span></span></div>"
        f"<p class=\"authority-note\">{_text(_authority(model))}</p>"
        f"<div class=\"project-state\"><span>{_text(application)}</span>"
        f"<span>{_text(coverage_text)}</span></div>"
        "</section>"
    )


def _notices(model: DashboardReadModel) -> str:
    notices = model.confidence_notices
    if not notices:
        return ""
    visible = notices[:2]
    items = "".join(
        "<div class=\"notice-item\">"
        f"<strong>{_text(notice.title)}</strong>"
        f"<p>{_text(notice.direct_fact)}</p>"
        "</div>" for notice in visible
    )
    more = (
        f"<a class=\"text-link\" href=\"/limitations\">View all {len(notices)} collection notices</a>"
        if len(notices) > len(visible) else ""
    )
    return (
        "<aside class=\"notices\" aria-label=\"Collection limitations\">"
        "<div class=\"section-label\">Collection context</div>"
        f"{items}{more}</aside>"
    )


def _support(thread: InvestigationThread) -> str:
    values = (
        ("Retained evidence", len(thread.related_evidence_ids)),
        ("Native observations", len(thread.related_native_observation_ids)),
        ("Application relationships", len(thread.related_application_relation_ids)),
    )
    return "<div class=\"support-list\" aria-label=\"Supporting references\">" + "".join(
        f"<span class=\"support-item\">{_text(label)} <strong>{number}</strong></span>"
        for label, number in values
    ) + "</div>"


def _limitations(thread: InvestigationThread) -> str:
    if not thread.limitation_codes:
        return ""
    return (
        "<div class=\"limitations\"><span class=\"small-label\">Qualifications</span>"
        + "".join(
            f"<span class=\"limitation\">{_text(_label(code))}</span>"
            for code in thread.limitation_codes
        )
        + "</div>"
    )


def _endpoint_preview(thread: InvestigationThread) -> str:
    endpoints = thread.related_endpoints
    if not endpoints:
        return "<p class=\"muted\">No endpoint attached to this thread.</p>"
    listed = "".join(
        f"<li><span class=\"endpoint\">{_text(endpoint)}</span></li>"
        for endpoint in endpoints[:ENDPOINT_PREVIEW_LIMIT]
    )
    remaining = len(endpoints) - ENDPOINT_PREVIEW_LIMIT
    more = (
        f"<span class=\"more-endpoints\">+{remaining} more</span>"
        if remaining > 0 else ""
    )
    return f"<ul class=\"endpoint-preview\">{listed}</ul>{more}"


def _thread_card(thread: InvestigationThread, order: int) -> str:
    return (
        f"<article class=\"thread-card\" id=\"investigation-{order}\">"
        "<div class=\"thread-topline\">"
        f"<span class=\"thread-index\">{order:02d}</span>"
        f"<span class=\"priority priority-{_text(thread.priority)}\">"
        f"{_text(_label(thread.priority))} priority</span>"
        f"<span class=\"category\">{_text(_label(thread.category))}</span>"
        "</div>"
        f"<h3>{_text(thread.title)}</h3>"
        f"<p class=\"thread-summary\">{_text(thread.summary)}</p>"
        f"<p class=\"thread-why\">{_text(thread.why_it_matters)}</p>"
        f"<div class=\"thread-section\"><span class=\"small-label\">Related endpoints</span>"
        f"{_endpoint_preview(thread)}</div>"
        f"{_support(thread)}{_limitations(thread)}"
        "<div class=\"thread-footer\">"
        f"<a class=\"detail-link\" href=\"/thread/{_text(thread.thread_id)}\">"
        "Review thread detail <span aria-hidden=\"true\">↗</span></a>"
        "</div></article>"
    )


def render_investigation_home(model: DashboardReadModel) -> bytes:
    """Render primary attention in persisted order; do not compose or rank."""

    primary = model.primary_investigation_threads
    if primary is None:
        body = (
            "<div class=\"empty-state\"><h3>Canonical priorities unavailable</h3>"
            "<p>No saved investigation-thread snapshot is present. This dashboard "
            "does not reconstruct legacy priorities.</p></div>"
        )
    elif not primary:
        body = (
            "<div class=\"empty-state\"><h3>No canonical priorities recorded</h3>"
            "<p>The saved investigation-thread snapshot is empty. This is not an "
            "all-clear; review retained project evidence and collection limitations.</p></div>"
        )
    else:
        body = "<div class=\"thread-grid\">" + "".join(
            _thread_card(thread, index) for index, thread in enumerate(primary, 1)
        ) + "</div>"
    content = (
        _project_header(model) + _notices(model)
        + "<section class=\"investigations\" aria-labelledby=\"investigation-title\">"
        "<div class=\"section-heading\"><div>"
        "<div class=\"section-label\">Review first</div>"
        "<h2 id=\"investigation-title\">Investigations</h2></div>"
        "<p>Saved canonical order · reconnaissance context, not vulnerability findings</p>"
        "</div>" + body + "</section>"
    )
    return _page(model, "Investigations", content)


def render_thread_detail(model: DashboardReadModel, thread: InvestigationThread) -> bytes:
    """Render one saved thread. Its full endpoint list is absent from home HTML."""

    all_threads = model.investigation_threads or ()
    children = tuple(value for value in all_threads if value.subsumed_by_thread_id == thread.thread_id)
    child_html = (
        "<section class=\"detail-section\"><h2>Supporting threads</h2><ul>" + "".join(
            f"<li><a href=\"/thread/{_text(child.thread_id)}\">{_text(child.title)}</a></li>"
            for child in children
        ) + "</ul></section>"
        if children else ""
    )
    steps = "".join(f"<li>{_text(step)}</li>" for step in thread.suggested_manual_review_order)
    endpoints = "".join(
        f"<li><span class=\"endpoint\">{_text(endpoint)}</span></li>"
        for endpoint in thread.related_endpoints
    )
    kill = (
        f"<p>{_text(thread.kill_switch_guidance)}</p>"
        if thread.kill_switch_guidance else "<p>No deprioritisation guidance recorded.</p>"
    )
    body = (
        "<nav class=\"breadcrumbs\" aria-label=\"Breadcrumb\">"
        "<a href=\"/\">Investigations</a><span aria-hidden=\"true\">/</span>"
        "<span>Thread detail</span></nav>"
        "<section class=\"detail-header\">"
        f"<div class=\"thread-topline\"><span class=\"priority priority-{_text(thread.priority)}\">"
        f"{_text(_label(thread.priority))} priority</span>"
        f"<span class=\"category\">{_text(_label(thread.category))}</span></div>"
        f"<h1>{_text(thread.title)}</h1>"
        f"<p>{_text(thread.summary)}</p>"
        f"<div class=\"thread-id\">Canonical ID · {_text(thread.thread_id)}</div>"
        "</section><div class=\"detail-grid\"><div>"
        "<section class=\"detail-section\"><h2>Why this matters</h2>"
        f"<p>{_text(thread.why_it_matters)}</p></section>"
        "<section class=\"detail-section\"><h2>Suggested manual review</h2>"
        f"<ol class=\"review-steps\">{steps}</ol></section>"
        "<section class=\"detail-section\"><h2>When to deprioritise</h2>"
        f"{kill}</section>{child_html}</div><div>"
        "<section class=\"detail-section\"><h2>Support and qualifications</h2>"
        f"{_support(thread)}{_limitations(thread)}</section>"
        "<section class=\"detail-section\"><h2>Related endpoints "
        f"<span class=\"count\">{len(thread.related_endpoints)}</span></h2>"
        "<p class=\"muted\">Saved concrete endpoints; no reachability is implied by listing.</p>"
        f"<div class=\"endpoint-scroll\"><ol class=\"endpoint-full\">{endpoints}</ol></div>"
        "</section></div></div>"
    )
    return _page(model, thread.title, body)


def render_limitations(model: DashboardReadModel) -> bytes:
    notices = model.confidence_notices
    items = "".join(
        "<article class=\"detail-section\">"
        f"<h2>{_text(notice.title)}</h2><p>{_text(notice.direct_fact)}</p>"
        f"<p class=\"muted\">{_text(notice.operator_implication)}</p></article>"
        for notice in notices
    ) or "<p>No saved collection-confidence notices are available. This does not prove complete coverage.</p>"
    body = (
        "<nav class=\"breadcrumbs\" aria-label=\"Breadcrumb\">"
        "<a href=\"/\">Investigations</a><span aria-hidden=\"true\">/</span>"
        "<span>Collection context</span></nav>"
        "<section class=\"detail-header\"><div class=\"eyebrow\">Saved execution context</div>"
        "<h1>Collection limitations</h1>"
        "<p>These are collection qualifications, not application findings.</p>"
        f"</section><div class=\"notice-detail-list\">{items}</div>"
    )
    return _page(model, "Collection limitations", body)
