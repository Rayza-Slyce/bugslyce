"""Bounded, read-only navigation over the persisted application/service model.

This index groups existing typed objects for browser navigation. It does not
compose relationships, decide reachability, rank origins, or grant authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil

from bugslyce.dashboard.presentation import _page, _text
from bugslyce.dashboard.read_model import DashboardReadModel
from bugslyce.recon.application_service_composition import (
    ApplicationServiceHttpOrigin,
    ApplicationServiceHttpRoute,
    ApplicationServiceRelation,
    ApplicationServiceSourceSemantic,
    ApplicationServiceSupportBasis,
)
from bugslyce.recon.application_service_model import (
    ApplicationServiceModel,
    ApplicationServiceModelRelation,
    ApplicationServiceModelRelationKind,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeRedirectRelationship,
    NativeStructuredResponseFact,
)


ROUTE_PAGE_SIZE = 60
RELATION_PAGE_SIZE = 24
DOCUMENTATION_PAGE_SIZE = 40
NATIVE_PREVIEW_SIZE = 8

_SOURCE_LABELS = {
    ApplicationServiceSourceSemantic.HTTP_REDIRECT: "HTTP redirect",
    ApplicationServiceSourceSemantic.NATIVE_HTTP_REDIRECT: "Native HTTP redirect",
    ApplicationServiceSourceSemantic.SITEMAP_DECLARATION: "Sitemap declaration",
    ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE: "HTML reference",
    ApplicationServiceSourceSemantic.JAVASCRIPT_REQUEST_CALL: "JavaScript request call",
    ApplicationServiceSourceSemantic.JAVASCRIPT_ROUTE_CONFIGURATION: "JavaScript route configuration",
}
_BASIS_LABELS = {
    ApplicationServiceSupportBasis.DIRECT_OBSERVATION: "Direct observation",
    ApplicationServiceSupportBasis.DIRECT_DOCUMENTATION: "Direct documentation",
    ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION: "Deterministic derivation / reference",
}


@dataclass(frozen=True)
class OriginRelation:
    relation: ApplicationServiceRelation
    roles: tuple[str, ...]


@dataclass(frozen=True)
class OriginNavigation:
    origin: ApplicationServiceHttpOrigin
    routes: tuple[ApplicationServiceHttpRoute, ...]
    relations: tuple[OriginRelation, ...]
    structured: tuple[NativeStructuredResponseFact, ...]
    redirect_sources: tuple[NativeRedirectRelationship, ...]
    redirect_targets: tuple[NativeRedirectRelationship, ...]
    mobile: tuple[NativeMobileAssociationDeclaration, ...]
    correspondences: tuple[ApplicationServiceModelRelation, ...]


@dataclass(frozen=True)
class ApplicationNavigation:
    model: ApplicationServiceModel | None
    origins: tuple[OriginNavigation, ...]
    documentation_items: tuple[tuple[str, object], ...]

    def origin_for_id(self, entity_id: str) -> OriginNavigation | None:
        return next((value for value in self.origins if value.origin.entity_id == entity_id), None)


def build_application_navigation(model: ApplicationServiceModel | None) -> ApplicationNavigation:
    """Index canonical entities once, using lexical origin order for navigation only."""

    if model is None:
        return ApplicationNavigation(None, (), ())
    composition = model.application_composition
    origins = sorted(composition.origins, key=lambda item: (item.origin.origin_url, item.entity_id))
    origin_id_by_value = {item.origin: item.entity_id for item in origins}
    route_by_id = {item.entity_id: item for item in composition.routes}
    source_set_by_id = {item.entity_id: item for item in composition.source_sets}
    routes: dict[str, list[ApplicationServiceHttpRoute]] = {item.entity_id: [] for item in origins}
    relationships: dict[str, list[OriginRelation]] = {item.entity_id: [] for item in origins}
    structured: dict[str, list[NativeStructuredResponseFact]] = {item.entity_id: [] for item in origins}
    redirect_sources: dict[str, list[NativeRedirectRelationship]] = {item.entity_id: [] for item in origins}
    redirect_targets: dict[str, list[NativeRedirectRelationship]] = {item.entity_id: [] for item in origins}
    mobile: dict[str, list[NativeMobileAssociationDeclaration]] = {item.entity_id: [] for item in origins}
    correspondences: dict[str, list[ApplicationServiceModelRelation]] = {item.entity_id: [] for item in origins}

    for route in composition.routes:
        routes[route.origin_id].append(route)
    for relation in composition.relations:
        roles: dict[str, set[str]] = {}
        source_route = route_by_id.get(relation.source_entity_id)
        source_set = source_set_by_id.get(relation.source_entity_id)
        target_route = route_by_id[relation.target_entity_id]
        if source_route is not None:
            roles.setdefault(source_route.origin_id, set()).add("source route")
        elif source_set is not None:
            for origin_id in source_set.origin_ids:
                roles.setdefault(origin_id, set()).add("source resource")
        roles.setdefault(target_route.origin_id, set()).add("target route")
        for origin_id, labels in roles.items():
            relationships[origin_id].append(OriginRelation(relation, tuple(sorted(labels))))

    def origin_id(url: str) -> str | None:
        value = http_origin_from_url(url)
        return origin_id_by_value.get(value) if value is not None else None

    native = model.native_observation_evidence
    for fact in native.structured_responses:
        key = origin_id(fact.request_url)
        if key is not None:
            structured[key].append(fact)
    for relation in native.redirect_relationships:
        source = origin_id(relation.source_url)
        target = origin_id(relation.target_url)
        if source is not None:
            redirect_sources[source].append(relation)
        if target is not None:
            redirect_targets[target].append(relation)
    for declaration in native.mobile_association_declarations:
        key = origin_id(declaration.document_url)
        if key is not None:
            mobile[key].append(declaration)
    for relation in model.relations:
        if relation.relation_kind is ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN:
            correspondences[relation.target.entity_id].append(relation)

    values = tuple(
        OriginNavigation(
            origin=item,
            routes=tuple(sorted(routes[item.entity_id], key=lambda value: value.canonical_url)),
            relations=tuple(sorted(relationships[item.entity_id], key=lambda value: value.relation.relation_id)),
            structured=tuple(structured[item.entity_id]),
            redirect_sources=tuple(redirect_sources[item.entity_id]),
            redirect_targets=tuple(redirect_targets[item.entity_id]),
            mobile=tuple(mobile[item.entity_id]),
            correspondences=tuple(correspondences[item.entity_id]),
        )
        for item in origins
    )
    documentation_items = (
        tuple(
            ("service", value)
            for value in sorted(
                model.documented_http_services,
                key=lambda item: item.value.canonical_url,
            )
        )
        + tuple(
            ("realtime", value)
            for value in sorted(
                model.documented_realtime_endpoints,
                key=lambda item: item.value.canonical_url,
            )
        )
        + tuple(("relation", value) for value in model.relations)
    )
    return ApplicationNavigation(model, values, documentation_items)


def page_count(total: int, size: int) -> int:
    return max(1, ceil(total / size))


def _pager(base: str, page: int, total: int, size: int, *, label: str) -> str:
    first = (page - 1) * size + 1 if total else 0
    last = min(page * size, total)
    previous = f'<a href="{base}/{page - 1}">Previous</a>' if page > 1 else ""
    following = f'<a href="{base}/{page + 1}">Next</a>' if page < page_count(total, size) else ""
    return (
        f'<nav class="pager" aria-label="{_text(label)} pages">'
        f'<span>Showing {first}–{last} of {total} · page {page} of {page_count(total, size)}</span>'
        f'<span class="pager-links">{previous}{following}</span></nav>'
    )


def _application_intro(index: ApplicationNavigation) -> str:
    model = index.model
    assert model is not None
    composition = model.application_composition
    return (
        '<section class="detail-header estate-header"><div class="eyebrow">Saved application model</div>'
        '<h1>Application and service estate</h1>'
        '<p>Origin membership may come from observations, references, or documentation. '
        'It does not establish reachability, ownership, scope, or permission to test.</p>'
        '<div class="estate-counts">'
        f'<span><strong>{len(composition.origins)}</strong> origins</span>'
        f'<span><strong>{len(composition.routes)}</strong> routes</span>'
        f'<span><strong>{len(composition.relations)}</strong> A1 relationships</span>'
        f'<span><strong>{len(model.documented_http_services)}</strong> documented HTTP services</span>'
        f'<span><strong>{len(model.documented_realtime_endpoints)}</strong> documented realtime endpoints</span>'
        '</div></section>'
    )


def render_application_home(read_model: DashboardReadModel, index: ApplicationNavigation) -> bytes:
    if index.model is None:
        return _page(
            read_model, "Application unavailable",
            '<section class="empty-state"><h1>Application model unavailable</h1>'
            '<p>No saved application-service model is present. This dashboard does not '
            'reconstruct one from project files.</p></section>', active="application",
        )
    model = index.model
    if index.origins:
        rows = []
        for value in index.origins:
            direct = sum(
                any(
                    support.basis is ApplicationServiceSupportBasis.DIRECT_OBSERVATION
                    for support in item.relation.supports
                )
                for item in value.relations
            )
            referenced = len(value.relations) - direct
            rows.append(
                '<li class="origin-row"><div class="origin-main">'
                f'<a class="origin-link" href="/application/origin/{value.origin.entity_id}">'
                f'{_text(value.origin.origin.origin_url)}</a>'
                '<span class="muted">Canonical HTTP origin · navigation order, not priority</span>'
                '</div><div class="origin-stats">'
                f'<span>{len(value.routes)} routes</span>'
                f'<span>{direct} directly observed links</span>'
                f'<span>{referenced} derived/reference links</span>'
                f'<span>{len(value.redirect_sources)} native redirect observations from this origin</span>'
                f'<span>{len(value.correspondences)} documented-service correspondences</span>'
                '</div></li>'
            )
        estate = '<ol class="origin-list">' + ''.join(rows) + '</ol>'
    else:
        estate = (
            '<div class="empty-state"><h3>No HTTP origins recorded</h3>'
            '<p>The saved application model contains no HTTP origins.</p></div>'
        )
    native = model.native_observation_evidence
    structured_preview = ''.join(
        '<li><strong>Structured JSON observed</strong> · '
        f'{_text(item.request_url)} · HTTP {item.status_code} · '
        'not a confirmed API</li>'
        for item in native.structured_responses[:NATIVE_PREVIEW_SIZE]
    )
    mobile_preview = ''.join(
        '<li><strong>Android declaration</strong> · '
        f'{_text(item.package_name)} · {_text(item.document_url)} · '
        'ownership not confirmed</li>'
        for item in native.mobile_association_declarations[:NATIVE_PREVIEW_SIZE]
    )
    extra_facts = max(0, len(native.structured_responses) - NATIVE_PREVIEW_SIZE) + max(
        0, len(native.mobile_association_declarations) - NATIVE_PREVIEW_SIZE
    )
    fact_preview = (
        f'<ul class="native-list native-fact-preview">{structured_preview}{mobile_preview}</ul>'
        if structured_preview or mobile_preview else ''
    )
    if extra_facts:
        fact_preview += (
            f'<p class="muted">+{extra_facts} further typed facts retained '
            'in the canonical model.</p>'
        )
    native_summary = (
        '<section class="detail-section native-overview"><h2>Typed native observations</h2>'
        '<p>These are saved direct facts; no additional requests are made here.</p>'
        '<div class="estate-counts">'
        f'<span><strong>{len(native.structured_responses)}</strong> structured JSON responses (not confirmed APIs)</span>'
        f'<span><strong>{len(native.redirect_relationships)}</strong> redirects (destination fetch not implied)</span>'
        f'<span><strong>{len(native.mobile_association_declarations)}</strong> mobile declarations (ownership unconfirmed)</span>'
        f'</div>{fact_preview}</section>'
    )
    docs = (
        '<section class="detail-section"><h2>Documentation-backed context</h2>'
        f'<p>{len(index.documentation_items)} saved documented entities and A3 relationships. '
        'Documentation is not a live reachability observation.</p>'
        '<a href="/application/documentation">Browse documentation context</a></section>'
        if index.documentation_items else
        '<section class="detail-section"><h2>Documentation-backed context</h2>'
        '<p>No documented services, realtime endpoints, or A3 relationships are recorded. '
        'This is not a collection failure claim.</p></section>'
    )
    body = (
        _application_intro(index) +
        '<section class="estate-section"><div class="section-heading"><div>'
        '<div class="section-label">Origin-first navigation</div><h2>HTTP origins</h2></div>'
        '<p>Lexical origin order · not security priority</p></div>'
        f'{estate}</section>{native_summary}{docs}'
    )
    return _page(read_model, "Application", body, active="application")


def _entity_label(index: ApplicationNavigation, entity_id: str) -> str:
    assert index.model is not None
    composition = index.model.application_composition
    route = next((value for value in composition.routes if value.entity_id == entity_id), None)
    if route is not None:
        return route.canonical_url
    source_set = next((value for value in composition.source_sets if value.entity_id == entity_id), None)
    if source_set is not None:
        urls = source_set.resource_urls
        return ', '.join(urls[:2]) + (f' (+{len(urls) - 2} resources)' if len(urls) > 2 else '')
    return entity_id


def _relation_row(index: ApplicationNavigation, value: OriginRelation) -> str:
    relation = value.relation
    support_rows = []
    for support in relation.supports[:3]:
        qualification = (
            ' · redirect target is not proven fetched by this relation'
            if support.source_semantic is ApplicationServiceSourceSemantic.NATIVE_HTTP_REDIRECT
            else ''
        )
        support_rows.append(
            '<li>'
            f'<span class="basis">{_text(_BASIS_LABELS[support.basis])}</span> · '
            f'{_text(_SOURCE_LABELS[support.source_semantic])} · '
            f'{len(support.evidence_ids)} provenance references'
            f'{_text(qualification)}'
            '<details class="support-provenance"><summary>Source provenance</summary>'
            f'<div class="machine-id">{_text(support.source_reference.owner_kind.value)} · '
            f'{_text(support.source_reference.source_id)}</div>'
            f'<div class="machine-id">Evidence IDs: {_text(", ".join(support.evidence_ids[:4]))}'
            f'{" +" + str(len(support.evidence_ids) - 4) + " more" if len(support.evidence_ids) > 4 else ""}</div>'
            '</details></li>'
        )
    more = f'<li>+{len(relation.supports) - 3} additional typed supports</li>' if len(relation.supports) > 3 else ''
    return (
        '<li class="relation-row">'
        f'<div class="relation-heading">{_text(relation.relation_kind.value.replace("_", " ").title())}'
        f'<span class="muted"> · this origin: {_text(", ".join(value.roles))}</span></div>'
        f'<div class="relation-endpoints">{_text(_entity_label(index, relation.source_entity_id))}'
        ' <span aria-hidden="true">→</span> '
        f'{_text(_entity_label(index, relation.target_entity_id))}</div>'
        f'<ul class="relation-support">{"".join(support_rows)}{more}</ul>'
        f'<div class="machine-id">{_text(relation.relation_id)}</div></li>'
    )


def render_origin_detail(
    read_model: DashboardReadModel,
    index: ApplicationNavigation,
    value: OriginNavigation,
    *,
    routes_page: int = 1,
    relations_page: int = 1,
) -> bytes:
    origin = value.origin.origin.origin_url
    base = f'/application/origin/{value.origin.entity_id}'
    routes = value.routes[
        (routes_page - 1) * ROUTE_PAGE_SIZE:routes_page * ROUTE_PAGE_SIZE
    ]
    relations = value.relations[
        (relations_page - 1) * RELATION_PAGE_SIZE:relations_page * RELATION_PAGE_SIZE
    ]
    route_rows = ''.join(
        f'<li class="route-row"><span class="endpoint">{_text(item.canonical_url)}</span></li>'
        for item in routes
    ) or '<li class="muted">No routes recorded for this origin.</li>'
    relation_rows = ''.join(_relation_row(index, item) for item in relations) or (
        '<li class="muted">No A1 relationships recorded for this origin.</li>'
    )
    native_rows = ''.join(
        '<li><strong>Structured JSON response</strong> · '
        f'{_text(item.request_url)} · HTTP {item.status_code} · '
        'direct observation, not a confirmed API</li>'
        for item in value.structured[:NATIVE_PREVIEW_SIZE]
    ) + ''.join(
        '<li><strong>Native redirect</strong> · '
        f'{_text(item.source_url)} → {_text(item.target_url)} '
        f'(raw Location: {_text(item.raw_location)}) · '
        'direct observation; destination not shown as fetched</li>'
        for item in value.redirect_sources[:NATIVE_PREVIEW_SIZE]
    ) + ''.join(
        '<li><strong>Android association declaration</strong> · '
        f'{_text(item.package_name)} · {_text(item.document_url)} · '
        'ownership not confirmed</li>'
        for item in value.mobile[:NATIVE_PREVIEW_SIZE]
    )
    native_more = sum((len(value.structured), len(value.redirect_sources), len(value.mobile))) - (
        min(len(value.structured), NATIVE_PREVIEW_SIZE)
        + min(len(value.redirect_sources), NATIVE_PREVIEW_SIZE)
        + min(len(value.mobile), NATIVE_PREVIEW_SIZE)
    )
    native_more_note = (
        f'<p class="muted">+{native_more} further native facts represented '
        'in the canonical model.</p>'
        if native_more else ''
    )
    service_url_by_id = {
        service.entity_id: service.value.canonical_url
        for service in index.model.documented_http_services
    }
    correspondence = ''.join(
        f'<li>Documented service correspondence · deterministic derivation · '
        f'{_text(service_url_by_id[item.source.entity_id])} '
        f'· {len(item.supports)} exact supports</li>'
        for item in value.correspondences
    ) or '<li>No documented-service correspondence recorded.</li>'
    body = (
        '<nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/application">Application</a>'
        '<span aria-hidden="true">/</span><span>Origin detail</span></nav>'
        '<section class="detail-header estate-header"><div class="eyebrow">Canonical HTTP origin</div>'
        f'<h1>{_text(origin)}</h1>'
        '<p>Saved origin context only; listed routes and redirect targets are not '
        'all independently observed or authorised for testing.</p>'
        '<div class="estate-counts">'
        f'<span><strong>{len(value.routes)}</strong> routes</span>'
        f'<span><strong>{len(value.relations)}</strong> A1 relationships</span>'
        f'<span><strong>{len(value.structured)}</strong> structured responses</span>'
        f'<span><strong>{len(value.redirect_sources)}</strong> native redirects from this origin</span>'
        f'<span><strong>{len(value.redirect_targets)}</strong> native redirect targets at this origin (not proof of fetch)</span>'
        f'<span><strong>{len(value.mobile)}</strong> mobile declarations</span>'
        '</div></section>'
        '<div class="estate-detail-grid"><div>'
        '<section class="detail-section"><h2>Routes</h2>'
        f'{_pager(base + "/routes", routes_page, len(value.routes), ROUTE_PAGE_SIZE, label="Route")}'
        f'<ol class="route-list">{route_rows}</ol></section>'
        '<section class="detail-section"><h2>Typed A1 relationships</h2>'
        f'{_pager(base + "/relations", relations_page, len(value.relations), RELATION_PAGE_SIZE, label="Relationship")}'
        f'<ol class="relation-list">{relation_rows}</ol></section></div><div>'
        '<section class="detail-section"><h2>Native direct evidence</h2>'
        f'<ul class="native-list">{native_rows or "<li>No native facts directly associated with this origin.</li>"}</ul>'
        f'{native_more_note}'
        '</section><section class="detail-section"><h2>Documented-service correspondence</h2>'
        f'<ul class="native-list">{correspondence}</ul>'
        '<p class="muted">Correspondence does not establish live documented-service behaviour.</p>'
        '</section></div></div>'
    )
    return _page(read_model, origin, body, active="application")


def render_documentation_page(
    read_model: DashboardReadModel, index: ApplicationNavigation, *, page: int = 1
) -> bytes:
    assert index.model is not None
    model = index.model
    origin_by_id = {item.origin.entity_id: item.origin.origin.origin_url for item in index.origins}
    resource_by_id = {
        item.entity_id: item.source_reference.final_url
        for item in model.documentation_resources
    }
    service_by_id = {
        item.entity_id: item.value.canonical_url
        for item in model.documented_http_services
    }
    realtime_by_id = {
        item.entity_id: item.value.canonical_url
        for item in model.documented_realtime_endpoints
    }
    items = index.documentation_items[
        (page - 1) * DOCUMENTATION_PAGE_SIZE:page * DOCUMENTATION_PAGE_SIZE
    ]
    rows = []
    for kind, item in items:
        if kind == "service":
            rows.append(
                '<li class="relation-row"><strong>Documented HTTP service</strong>'
                f'<p class="endpoint">{_text(item.value.canonical_url)}</p>'
                '<p>Documented, not independently proven reachable.</p></li>'
            )
        elif kind == "realtime":
            rows.append(
                '<li class="relation-row"><strong>Documented realtime endpoint</strong>'
                f'<p class="endpoint">{_text(item.value.canonical_url)}</p>'
                '<p>Documented, not independently proven reachable.</p></li>'
            )
        else:
            relation = item
            assert isinstance(relation, ApplicationServiceModelRelation)
            source = (
                resource_by_id.get(relation.source.entity_id)
                or service_by_id.get(relation.source.entity_id)
                or relation.source.entity_id
            )
            target = (
                service_by_id.get(relation.target.entity_id)
                or realtime_by_id.get(relation.target.entity_id)
                or origin_by_id.get(relation.target.entity_id)
                or relation.target.entity_id
            )
            basis = (
                "Deterministic correspondence"
                if relation.relation_kind
                is ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN
                else "Direct documentation"
            )
            link = (
                f' · <a href="/application/origin/{relation.target.entity_id}">Open origin</a>'
                if relation.target.entity_id in origin_by_id else ""
            )
            rows.append(
                f'<li class="relation-row"><strong>{_text(relation.relation_kind.value.replace("_", " ").title())}</strong>'
                f'<p>{_text(basis)} · {len(relation.supports)} typed supports{link}</p>'
                f'<p class="relation-endpoints">{_text(source)} → {_text(target)}</p></li>'
            )
    body = (
        '<nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/application">Application</a>'
        '<span aria-hidden="true">/</span><span>Documentation context</span></nav>'
        '<section class="detail-header estate-header"><div class="eyebrow">Saved A3 model</div>'
        '<h1>Documentation context</h1><p>Documentation and deterministic correspondence '
        'are distinct from directly observed application behaviour.</p></section>'
        '<section class="detail-section">'
        f'{_pager("/application/documentation/page", page, len(index.documentation_items), DOCUMENTATION_PAGE_SIZE, label="Documentation")}'
        f'<ol class="relation-list">{"".join(rows)}</ol></section>'
    )
    return _page(read_model, "Documentation context", body, active="application")
