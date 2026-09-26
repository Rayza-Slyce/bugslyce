"""Bounded navigation across saved, distinct provenance identity domains.

This module indexes loaded snapshots only. It does not inspect recorded source
paths, reconstruct semantics, or validate evidence-pack closure.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re
from types import MappingProxyType
from typing import Mapping

from bugslyce.core.models import Evidence
from bugslyce.dashboard.application_view import _BASIS_LABELS, _SOURCE_LABELS, _pager
from bugslyce.dashboard.presentation import _page, _text
from bugslyce.dashboard.read_model import DashboardReadModel
from bugslyce.recon.application_service_composition import (
    ApplicationServiceRelation,
    ApplicationServiceRelationSupport,
)
from bugslyce.recon.investigation_threads import InvestigationThread
from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeRedirectRelationship,
    NativeStructuredResponseFact,
)


GENERIC_PAGE_SIZE = 80
NATIVE_PAGE_SIZE = 60
RELATION_PAGE_SIZE = 32
SUPPORT_PAGE_SIZE = 40
LANDING_PREVIEW_SIZE = 6
CONTEXT_KEYS_LIMIT = 20
CONTEXT_ITEMS_LIMIT = 12
CONTEXT_DEPTH_LIMIT = 3
CONTEXT_STRING_LIMIT = 320
VALUE_LIMIT = 4000
_NATIVE_ID = re.compile(r"native-observation:(0|[1-9][0-9]*):(0|[1-9][0-9]*)\Z")


def _generic_locator(evidence_id: str) -> str:
    """Opaque HTTP route locator, never a replacement provenance identity."""

    return sha256(evidence_id.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True)
class NativeSource:
    source_id: str
    candidate_index: int
    exchange_index: int
    facts: tuple[NativeStructuredResponseFact | NativeRedirectRelationship |
                 NativeMobileAssociationDeclaration, ...]


@dataclass(frozen=True)
class EvidenceNavigation:
    generic: tuple[Evidence, ...] | None
    generic_by_id: Mapping[str, Evidence]
    generic_by_locator: Mapping[str, Evidence]
    native_sources: tuple[NativeSource, ...]
    native_by_id: Mapping[str, NativeSource]
    relations: tuple[ApplicationServiceRelation, ...] | None
    relation_by_id: Mapping[str, ApplicationServiceRelation]
    generic_backlinks: Mapping[str, tuple[InvestigationThread, ...]]
    native_backlinks: Mapping[str, tuple[InvestigationThread, ...]]
    relation_backlinks: Mapping[str, tuple[InvestigationThread, ...]]
    entity_labels: Mapping[str, str]

    def generic_path(self, evidence_id: str) -> str | None:
        item = self.generic_by_id.get(evidence_id)
        if item is not None:
            locator = _generic_locator(evidence_id)
            if self.generic_by_locator.get(locator) is item:
                return f"/evidence/generic/id/{locator}"
        return None

    def native_path(self, source_id: str) -> str | None:
        source = self.native_by_id.get(source_id)
        if source is None:
            return None
        return f"/evidence/native/{source.candidate_index}/{source.exchange_index}"

    def relation_path(self, relation_id: str) -> str | None:
        if relation_id in self.relation_by_id and re.fullmatch(
            r"APP-RELATION-[0-9a-f]{64}", relation_id
        ):
            return f"/evidence/application/{relation_id}"
        return None


def build_evidence_navigation(model: DashboardReadModel) -> EvidenceNavigation:
    """Index canonical owner order once; reverse links use explicit saved IDs.

    Generic order is persisted ProjectState order. Native order is numeric
    candidate/exchange order. A1 navigation is lexical canonical relation ID
    order. None of these navigation orders expresses priority.
    """

    generic = model.generic_evidence
    generic_by_id: dict[str, Evidence] = {}
    duplicate_ids: set[str] = set()
    for item in generic or ():
        if item.id in generic_by_id:
            duplicate_ids.add(item.id)
        else:
            generic_by_id[item.id] = item
    for evidence_id in duplicate_ids:
        del generic_by_id[evidence_id]
    generic_by_locator: dict[str, Evidence] = {}
    ambiguous_locators: set[str] = set()
    for item in generic_by_id.values():
        locator = _generic_locator(item.id)
        if locator in generic_by_locator:
            ambiguous_locators.add(locator)
        else:
            generic_by_locator[locator] = item
    for locator in ambiguous_locators:
        del generic_by_locator[locator]

    application = model.application_service_model
    native_groups: dict[tuple[int, int], list[
        NativeStructuredResponseFact | NativeRedirectRelationship |
        NativeMobileAssociationDeclaration
    ]] = {}
    if application is not None:
        facts = application.native_observation_evidence
        for item in (
            *facts.structured_responses,
            *facts.redirect_relationships,
            *facts.mobile_association_declarations,
        ):
            native_groups.setdefault((item.candidate_index, item.exchange_index), []).append(item)
    native_sources = tuple(
        NativeSource(
            f"native-observation:{candidate}:{exchange}", candidate, exchange, tuple(items)
        )
        for (candidate, exchange), items in sorted(native_groups.items())
    )
    native_by_id = {item.source_id: item for item in native_sources}

    relations = (
        tuple(sorted(application.application_composition.relations,
                     key=lambda item: item.relation_id))
        if application is not None else None
    )
    relation_by_id = {item.relation_id: item for item in relations or ()}
    entity_labels: dict[str, str] = {}
    if application is not None:
        composition = application.application_composition
        entity_labels.update(
            (item.entity_id, item.canonical_url) for item in composition.routes
        )
        entity_labels.update(
            (item.entity_id, ", ".join(item.resource_urls[:2]) +
             (f" (+{len(item.resource_urls) - 2} resources)" if len(item.resource_urls) > 2 else ""))
            for item in composition.source_sets
        )

    all_threads = model.investigation_threads or ()
    primary = model.primary_investigation_threads or ()
    primary_by_id = {thread.thread_id: thread for thread in primary}
    generic_links: dict[str, tuple[InvestigationThread, ...]] = {}
    primary_order = {thread.thread_id: position for position, thread in enumerate(primary)}
    for backlink in model.operator_report_view.investigation_context.evidence_backlinks:
        threads = (
            primary_by_id[reference.target_id]
            for reference in backlink.primary_anchor_references
            if reference.target_kind == "investigation_thread"
            and reference.target_id in primary_by_id
        )
        generic_links[backlink.target_identity] = tuple(
            sorted(threads, key=lambda thread: primary_order[thread.thread_id])
        )

    native_links: dict[str, list[InvestigationThread]] = {}
    relation_links: dict[str, list[InvestigationThread]] = {}
    for thread in all_threads:
        for source_id in dict.fromkeys(thread.related_native_observation_ids):
            native_links.setdefault(source_id, []).append(thread)
        for relation_id in dict.fromkeys(thread.related_application_relation_ids):
            relation_links.setdefault(relation_id, []).append(thread)
    return EvidenceNavigation(
        generic, MappingProxyType(generic_by_id), MappingProxyType(generic_by_locator), native_sources,
        MappingProxyType(native_by_id), relations, MappingProxyType(relation_by_id),
        MappingProxyType(generic_links),
        MappingProxyType({key: tuple(value) for key, value in native_links.items()}),
        MappingProxyType({key: tuple(value) for key, value in relation_links.items()}),
        MappingProxyType(entity_labels),
    )


def _bounded(value: str, limit: int) -> tuple[str, bool]:
    return (value[:limit], True) if len(value) > limit else (value, False)


def _context_value(value: object, depth: int = 0) -> tuple[object, bool]:
    """Make saved JSON-like context stable and small without object repr."""

    if isinstance(value, str):
        return _bounded(value, CONTEXT_STRING_LIMIT)
    if isinstance(value, float) and not math.isfinite(value):
        return "[non-finite saved number]", True
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if depth >= CONTEXT_DEPTH_LIMIT:
        return "[nested value omitted for display]", True
    if isinstance(value, dict):
        pairs = sorted(
            ((key, item) for key, item in value.items() if isinstance(key, str)),
            key=lambda pair: pair[0],
        )
        result: dict[str, object] = {}
        truncated = len(pairs) > CONTEXT_ITEMS_LIMIT or len(pairs) != len(value)
        for key, item in pairs[:CONTEXT_ITEMS_LIMIT]:
            result[key], clipped = _context_value(item, depth + 1)
            truncated |= clipped
        return result, truncated
    if isinstance(value, (list, tuple)):
        result = []
        truncated = len(value) > CONTEXT_ITEMS_LIMIT
        for item in value[:CONTEXT_ITEMS_LIMIT]:
            shown, clipped = _context_value(item, depth + 1)
            result.append(shown)
            truncated |= clipped
        return result, truncated
    return "[unsupported saved value]", True


def _context(context: dict[str, object]) -> str:
    if not context:
        return '<p class="muted">No context fields recorded.</p>'
    keys = sorted(key for key in context if isinstance(key, str))
    truncated = len(keys) > CONTEXT_KEYS_LIMIT or len(keys) != len(context)
    rows = []
    for key in keys[:CONTEXT_KEYS_LIMIT]:
        value, clipped = _context_value(context[key])
        truncated |= clipped
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
        shown_key, key_clipped = _bounded(key, CONTEXT_STRING_LIMIT)
        truncated |= key_clipped
        rows.append(f'<div class="context-pair"><dt>{_text(shown_key)}</dt>'
                    f'<dd>{_text(rendered)}</dd></div>')
    note = '<p class="muted">Context truncated for display; saved data was not changed.</p>' if truncated else ''
    return f'<dl class="context-list">{"".join(rows)}</dl>{note}'


def _backlinks(threads: tuple[InvestigationThread, ...], empty: str) -> str:
    if not threads:
        return f'<p class="muted">{empty}</p>'
    return '<ol class="backlink-list">' + ''.join(
        f'<li><a href="/thread/{_text(thread.thread_id)}">{_text(thread.title)}</a>'
        f' <span class="machine-id">{_text(thread.thread_id)}</span></li>'
        for thread in threads
    ) + '</ol>'


def _header(title: str, domain: str, description: str) -> str:
    return (
        '<nav class="breadcrumbs" aria-label="Breadcrumb">'
        '<a href="/evidence">Evidence</a><span aria-hidden="true">/</span>'
        f'<span>{_text(domain)}</span></nav>'
        '<section class="detail-header evidence-header">'
        f'<div class="eyebrow">{_text(domain)}</div><h1>{_text(title)}</h1>'
        f'<p>{_text(description)}</p>'
        '<p class="muted">Evidence membership does not establish target scope, '
        'ownership, reachability, or permission to test.</p></section>'
    )


def _generic_row(nav: EvidenceNavigation, item: Evidence) -> str:
    path = nav.generic_path(item.id)
    title = f'<a href="{path}">{_text(item.id)}</a>' if path else _text(item.id)
    value, clipped = _bounded(item.value, 180)
    source, source_clipped = _bounded(item.source_file, 240)
    return (
        '<li class="evidence-row">'
        f'<strong>{title}</strong><span class="domain-tag">{_text(item.evidence_type)}</span>'
        f'<p>{_text(value)}{"…" if clipped else ""}</p>'
        f'<span class="muted">Recorded source: {_text(source)}{"…" if source_clipped else ""}</span></li>'
    )


def _native_summary(source: NativeSource) -> str:
    labels = []
    for fact in source.facts:
        if isinstance(fact, NativeStructuredResponseFact):
            labels.append("structured response")
        elif isinstance(fact, NativeRedirectRelationship):
            labels.append("redirect")
        else:
            labels.append("Android declaration")
    return ", ".join(dict.fromkeys(labels))


def _native_row(nav: EvidenceNavigation, source: NativeSource) -> str:
    return (
        '<li class="evidence-row">'
        f'<strong><a href="{nav.native_path(source.source_id)}">{_text(source.source_id)}</a></strong>'
        '<span class="domain-tag">Native observation</span>'
        f'<p>{_text(_native_summary(source))} · {len(source.facts)} typed facts</p></li>'
    )


def _relation_row(nav: EvidenceNavigation, relation: ApplicationServiceRelation) -> str:
    path = nav.relation_path(relation.relation_id)
    title = f'<a href="{path}">{_text(relation.relation_id)}</a>' if path else _text(relation.relation_id)
    return (
        '<li class="evidence-row">'
        f'<strong>{title}</strong><span class="domain-tag">A1 relationship</span>'
        f'<p>{_text(relation.relation_kind.value.replace("_", " "))} · '
        f'{_text(nav.entity_labels.get(relation.source_entity_id, relation.source_entity_id))} → '
        f'{_text(nav.entity_labels.get(relation.target_entity_id, relation.target_entity_id))}</p>'
        f'<span class="muted">{len(relation.supports)} typed supports</span></li>'
    )


def render_evidence_landing(model: DashboardReadModel, nav: EvidenceNavigation) -> bytes:
    generic_count = 'Unavailable' if nav.generic is None else str(len(nav.generic))
    native_count = 'Unavailable' if nav.relations is None else str(len(nav.native_sources))
    relation_count = 'Unavailable' if nav.relations is None else str(len(nav.relations))
    sections = (
        ('Generic retained Evidence', generic_count, nav.generic or (), _generic_row,
         '/evidence/generic/page/1', 'Persisted project-state records in saved tuple order.'),
        ('Native observation identities', native_count, nav.native_sources, _native_row,
         '/evidence/native/page/1', 'Typed facts grouped by candidate and exchange identity.'),
        ('Application A1 relationships', relation_count, nav.relations or (), _relation_row,
         '/evidence/application/page/1', 'Canonical A1 relation IDs; supports retain their own types.'),
    )
    blocks = []
    for title, count, values, row, path, description in sections:
        preview = ''.join(row(nav, item) for item in values[:LANDING_PREVIEW_SIZE])
        state = '<p class="muted">Snapshot unavailable.</p>' if count == 'Unavailable' else (
            '<p class="muted">No records in this loaded snapshot.</p>' if not values else
            f'<ol class="evidence-list">{preview}</ol>'
        )
        blocks.append(
            '<section class="detail-section evidence-domain">'
            f'<h2>{title} <span class="count">{count}</span></h2>'
            f'<p>{description}</p>{state}'
            f'<a href="{path}">Browse {title.lower()}</a></section>'
        )
    application = model.application_service_model
    if application is None:
        documentation = (
            '<section class="detail-section"><h2>Documentation provenance unavailable</h2>'
            '<p>No saved Application model is loaded. Documentation context cannot be '
            'opened from this snapshot.</p></section>'
        )
    elif not (
        application.documented_http_services
        or application.documented_realtime_endpoints
        or application.relations
    ):
        documentation = (
            '<section class="detail-section"><h2>Documentation provenance</h2>'
            '<p>No documented services, realtime endpoints, or A3 relationships are recorded. '
            'This is an authoritative empty saved Application model, not a collection failure claim.</p>'
            '</section>'
        )
    else:
        documentation = (
            '<section class="detail-section"><h2>Documentation provenance</h2>'
            '<p>Application documentation context has its own saved A3 owner.</p>'
            '<a href="/application/documentation">Open Application documentation context</a>'
            '</section>'
        )
    body = (
        '<section class="detail-header evidence-header"><div class="eyebrow">Saved provenance</div>'
        '<h1>Evidence</h1><p>BugSlyce retains distinct provenance domains. '
        'A generic Evidence record, native observation identity, and Application A1 '
        'relationship are not interchangeable counts or findings.</p>'
        '<p>Evidence membership does not establish target scope, ownership, '
        'reachability, or permission to test.</p>'
        '<p>This view resolves references available in the currently loaded project '
        'snapshots; it is not an evidence-pack closure check.</p></section>'
        f'<div class="evidence-domains">{"".join(blocks)}</div>'
        f'{documentation}'
    )
    return _page(model, 'Evidence', body, active='evidence')


def render_evidence_index(
    model: DashboardReadModel, nav: EvidenceNavigation, domain: str, page: int
) -> bytes:
    if domain == 'generic':
        values, size, row, title = nav.generic or (), GENERIC_PAGE_SIZE, _generic_row, 'Generic retained Evidence'
        available = nav.generic is not None
    elif domain == 'native':
        values, size, row, title = nav.native_sources, NATIVE_PAGE_SIZE, _native_row, 'Native observation identities'
        available = nav.relations is not None
    else:
        values, size, row, title = nav.relations or (), RELATION_PAGE_SIZE, _relation_row, 'Application A1 relationships'
        available = nav.relations is not None
    items = values[(page - 1) * size:page * size]
    content = (
        '<p class="muted">Snapshot unavailable.</p>' if not available else
        '<p class="muted">No records in this loaded snapshot.</p>' if not values else
        '<ol class="evidence-list">' + ''.join(row(nav, item) for item in items) + '</ol>'
    )
    body = _header(title, title, 'Navigation order only; no priority or scope claim is implied.') + (
        '<section class="detail-section">'
        f'{_pager("/evidence/" + domain + "/page", page, len(values), size, label=title)}'
        f'{content}</section>'
    )
    return _page(model, title, body, active='evidence')


def render_generic_detail(model: DashboardReadModel, nav: EvidenceNavigation, item: Evidence) -> bytes:
    value, clipped = _bounded(item.value, VALUE_LIMIT)
    note = '<p class="muted">Value truncated for display; saved data was not changed.</p>' if clipped else ''
    body = _header(item.id, 'Generic retained Evidence',
                   'Saved project-state record, not a vulnerability finding. '
                   'The recorded source is provenance text, not a file link.') + (
        '<div class="detail-grid"><section class="detail-section">'
        f'<h2>Saved record</h2><dl class="context-list">'
        f'<div class="context-pair"><dt>Evidence ID</dt><dd>{_text(item.id)}</dd></div>'
        f'<div class="context-pair"><dt>Evidence type</dt><dd>{_text(item.evidence_type)}</dd></div>'
        f'<div class="context-pair"><dt>Recorded source file</dt><dd>{_text(item.source_file)}</dd></div>'
        f'</dl><h3>Saved value</h3><p class="saved-value">{_text(value)}</p>{note}'
        f'<h3>Saved context</h3>{_context(item.context)}</section>'
        '<section class="detail-section"><h2>Primary Investigation backlinks</h2>'
        f'{_backlinks(nav.generic_backlinks.get(item.id, ()), "No primary Investigation thread currently references this generic evidence record.")}'
        '<p class="muted">An absent backlink does not establish irrelevance.</p></section></div>'
    )
    return _page(model, item.id, body, active='evidence')


def render_native_detail(model: DashboardReadModel, nav: EvidenceNavigation, source: NativeSource) -> bytes:
    rows = []
    for fact in source.facts:
        if isinstance(fact, NativeStructuredResponseFact):
            rows.append(
                '<li class="evidence-row"><strong>Structured response fact</strong>'
                f'<p>Request URL: {_text(fact.request_url)}</p>'
                f'<p>HTTP status: {fact.status_code} · Body SHA-256: {_text(fact.body_sha256)}</p>'
                '<p>Direct observation; structured response does not confirm API status. '
                'A semantic fact does not prove a full body is retained.</p></li>'
            )
        elif isinstance(fact, NativeRedirectRelationship):
            rows.append(
                '<li class="evidence-row"><strong>Native HTTP redirect</strong>'
                f'<p>Source: {_text(fact.source_url)}</p>'
                f'<p>Raw Location: {_text(fact.raw_location)}</p>'
                f'<p>Target: {_text(fact.target_url)}</p>'
                '<p>Direct observation; destination fetch not implied.</p></li>'
            )
        else:
            rows.append(
                '<li class="evidence-row"><strong>Android association declaration</strong>'
                f'<p>Document URL: {_text(fact.document_url)}</p>'
                f'<p>Package: {_text(fact.package_name)} · Platform: {_text(fact.platform)}</p>'
                f'<p>Body SHA-256: {_text(fact.body_sha256)}</p>'
                '<p>Direct declaration observation; ownership unconfirmed. '
                'A semantic fact does not prove a full body is retained.</p></li>'
            )
    body = _header(source.source_id, 'Native observation',
                   'One retained exchange identity with its loaded typed semantic facts.') + (
        '<div class="detail-grid"><section class="detail-section"><h2>Typed facts</h2>'
        f'<ol class="evidence-list">{"".join(rows)}</ol></section>'
        '<section class="detail-section"><h2>Explicit Investigation backlinks</h2>'
        f'{_backlinks(nav.native_backlinks.get(source.source_id, ()), "No Investigation thread explicitly references this native observation.")}'
        '</section></div>'
    )
    return _page(model, source.source_id, body, active='evidence')


def _reference_list(values: tuple[str, ...], label: str) -> str:
    if not values:
        return f'<p class="muted">No {label.lower()} recorded.</p>'
    shown = values[:CONTEXT_ITEMS_LIMIT]
    more = len(values) - len(shown)
    return (
        f'<p>{label}:</p><ul class="reference-list">'
        + ''.join(f'<li>{_text(value)}</li>' for value in shown)
        + '</ul>' + (f'<p class="muted">+{more} more {label.lower()} retained; display bounded.</p>' if more else '')
    )


def _support_row(nav: EvidenceNavigation, support: ApplicationServiceRelationSupport) -> str:
    source = support.source_reference
    source_path = nav.native_path(source.source_id) if _NATIVE_ID.fullmatch(source.source_id) else None
    source_id = (
        f'<a href="{source_path}">{_text(source.source_id)}</a>'
        if source_path else _text(source.source_id)
    )
    evidence = []
    for evidence_id in support.evidence_ids[:CONTEXT_ITEMS_LIMIT]:
        path = nav.generic_path(evidence_id)
        if path:
            evidence.append(f'<li><a href="{path}">{_text(evidence_id)}</a> · generic Evidence</li>')
        else:
            evidence.append(f'<li>{_text(evidence_id)} · retained support reference · no matching generic Evidence record in this snapshot</li>')
    extra_evidence = len(support.evidence_ids) - CONTEXT_ITEMS_LIMIT
    if extra_evidence > 0:
        evidence.append(f'<li>+{extra_evidence} more evidence IDs retained; display bounded.</li>')
    return (
        '<li class="evidence-row">'
        f'<strong>{_text(_BASIS_LABELS[support.basis])}</strong>'
        f'<p>Source semantic: {_text(_SOURCE_LABELS[support.source_semantic])} '
        f'({_text(support.source_semantic.value)})</p>'
        f'<p>Source owner: {_text(source.owner_kind.value)} · Source ID: {source_id}</p>'
        f'<p>HTTP status: {support.http_status_code if support.http_status_code is not None else "not recorded"}</p>'
        f'<p>Evidence IDs:</p><ul class="reference-list">{"".join(evidence)}</ul>'
        f'{_reference_list(support.artefact_references, "Artefact references")}'
        f'{_reference_list(support.raw_references, "Raw references")}'
        '</li>'
    )


def render_relation_detail(
    model: DashboardReadModel, nav: EvidenceNavigation,
    relation: ApplicationServiceRelation, *, page: int = 1,
) -> bytes:
    supports = relation.supports[(page - 1) * SUPPORT_PAGE_SIZE:page * SUPPORT_PAGE_SIZE]
    source = nav.entity_labels.get(relation.source_entity_id, relation.source_entity_id)
    target = nav.entity_labels.get(relation.target_entity_id, relation.target_entity_id)
    body = _header(relation.relation_id, 'Application A1 relationship',
                   'Typed supports distinguish observations, documentation, and derived references. '
                   'A reference is not proof of a reached or working route.') + (
        '<section class="detail-section"><h2>Relationship</h2>'
        f'<p>Relation kind: {_text(relation.relation_kind.value.replace("_", " "))}</p>'
        f'<p>Source entity: {_text(relation.source_entity_id)} · {_text(source)}</p>'
        f'<p>Target route/entity: {_text(relation.target_entity_id)} · {_text(target)}</p>'
        '</section><div class="detail-grid"><section class="detail-section">'
        f'<h2>Typed supports <span class="count">{len(relation.supports)}</span></h2>'
        f'{_pager("/evidence/application/" + relation.relation_id + "/supports", page, len(relation.supports), SUPPORT_PAGE_SIZE, label="Support")}'
        f'<ol class="evidence-list">{"".join(_support_row(nav, item) for item in supports)}</ol>'
        '</section><section class="detail-section"><h2>Explicit Investigation backlinks</h2>'
        f'{_backlinks(nav.relation_backlinks.get(relation.relation_id, ()), "No Investigation thread explicitly references this Application relationship.")}'
        '</section></div>'
    )
    return _page(model, relation.relation_id, body, active='evidence')
