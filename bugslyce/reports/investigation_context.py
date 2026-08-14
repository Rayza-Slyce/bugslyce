"""Immutable report-only context assembled from existing deterministic facts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import re

from bugslyce.core.models import Evidence
from bugslyce.recon.deep_form_inventory import DeepFormInventoryItem
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteCandidate,
)
from bugslyce.recon.deep_javascript_route_extraction import DeepJavaScriptRouteCandidate
from bugslyce.recon.deep_parameter_inventory import DeepParameterInventoryItem
from bugslyce.recon.deep_post_followup_javascript_route_extraction import (
    DeepPostFollowupJavaScriptRouteCandidate,
)
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    HttpRouteRelationshipEdge,
    canonical_relationship_url,
)
from bugslyce.recon.reasoning_relationships import (
    MAPPING_MAPPED,
    RouteReasoningContext,
    RouteReasoningReview,
)
from bugslyce.recon.route_provenance import canonical_route_url
from bugslyce.reports.operator_summary import OperatorSummaryLead
from bugslyce.triage.workflow_leads import WorkflowLead


OBSERVED = "observed"
DERIVED = "derived"
RELATED = "related"
_SAFE_TOKEN = re.compile(r"[^a-z0-9._-]+")


@dataclass(frozen=True)
class ReportReferenceTarget:
    """One semantic report target before a deterministic anchor is assigned."""

    target_kind: str
    target_id: str
    identity_parts: tuple[str, ...]


@dataclass(frozen=True)
class ReportNavigationReference:
    """A deterministic internal report reference with no external navigation."""

    target_kind: str
    target_id: str
    anchor_token: str


@dataclass(frozen=True)
class InvestigationContextItem:
    """One existing deterministic fact attached to an explicit semantic anchor."""

    context_kind: str
    relationship_kind: str
    target_kind: str
    target_id: str
    label: str
    route_url: str
    evidence_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    source_urls: tuple[str, ...]
    body_sha256s: tuple[str, ...]
    related_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationContextView:
    """One rebuildable report-only context for an existing selected anchor."""

    anchor_kind: str
    anchor_id: str
    anchor_label: str
    anchor_reference: ReportNavigationReference
    context_items: tuple[InvestigationContextItem, ...]
    navigation_references: tuple[ReportNavigationReference, ...]

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return _unique_sorted(
            evidence_id
            for item in self.context_items
            for evidence_id in item.evidence_ids
        )


@dataclass(frozen=True)
class InvestigationContextBacklink:
    """Reverse references from one represented fact to primary lead anchors."""

    target_identity: str
    primary_anchor_references: tuple[ReportNavigationReference, ...]


@dataclass(frozen=True)
class InvestigationContextAssembly:
    """Primary contexts and bounded reverse indexes for future report rendering."""

    primary_contexts: tuple[InvestigationContextView, ...]
    evidence_backlinks: tuple[InvestigationContextBacklink, ...]
    route_backlinks: tuple[InvestigationContextBacklink, ...]


@dataclass(frozen=True)
class InvestigationContextSources:
    """Explicit current semantic inputs consumed by report-only context assembly."""

    evidence: tuple[Evidence, ...] = ()
    route_reasoning: RouteReasoningReview | None = None
    successful_content: tuple[SuccessfulDeepContentReview, ...] = ()
    route_relationships: tuple[HttpRouteRelationshipCluster, ...] = ()
    forms: tuple[DeepFormInventoryItem, ...] = ()
    parameters: tuple[DeepParameterInventoryItem, ...] = ()
    workflow_leads: tuple[WorkflowLead, ...] = ()


RouteCandidate = (
    DeepInitialRetainedJavaScriptRouteCandidate
    | DeepJavaScriptRouteCandidate
    | DeepPostFollowupJavaScriptRouteCandidate
)


def build_primary_investigation_contexts(
    ranked_leads: Sequence[OperatorSummaryLead],
    sources: InvestigationContextSources = InvestigationContextSources(),
) -> InvestigationContextAssembly:
    """Build exactly one context per canonical lead without changing lead order."""

    indexes = _ContextIndexes(sources)
    drafts = [
        (
            ReportReferenceTarget(
                "operator_summary_lead",
                lead.lead_id,
                _lead_identity(lead),
            ),
            lead.title,
            indexes.items_for_lead(lead),
        )
        for lead in ranked_leads
    ]
    references = build_report_navigation_references(
        target
        for target, _, items in drafts
        for target in (target, *(_target_for_item(item) for item in items))
    )
    reference_by_key = {
        (reference.target_kind, reference.target_id): reference
        for reference in references
    }
    contexts = tuple(
        _context_view(
            "operator_summary_lead",
            target,
            label,
            items,
            reference_by_key,
        )
        for target, label, items in drafts
    )
    return InvestigationContextAssembly(
        primary_contexts=contexts,
        evidence_backlinks=_backlinks(contexts, "evidence"),
        route_backlinks=_backlinks(contexts, "route"),
    )


def build_context_for_route(
    route: RouteCandidate,
    sources: InvestigationContextSources = InvestigationContextSources(),
) -> InvestigationContextView:
    """Build context for one caller-selected typed route without enumerating routes."""

    indexes = _ContextIndexes(sources)
    route_url = _candidate_route_url(route)
    items = _route_candidate_items(route)
    if route_url:
        items.extend(indexes.items_for_routes((route_url,)))
    ordered_items = _ordered_items(items)
    target = ReportReferenceTarget(
        "typed_route",
        route.candidate_id,
        (route.candidate_id, route_url, route.safe_candidate),
    )
    references = build_report_navigation_references(
        (target, *(_target_for_item(item) for item in ordered_items))
    )
    reference_by_key = {
        (reference.target_kind, reference.target_id): reference
        for reference in references
    }
    return _context_view(
        "typed_route",
        target,
        route.safe_candidate,
        ordered_items,
        reference_by_key,
    )


def build_report_navigation_references(
    targets: Iterable[ReportReferenceTarget],
) -> tuple[ReportNavigationReference, ...]:
    """Assign permutation-stable internal anchors with deterministic collisions."""

    unique = {
        (target.target_kind, target.target_id, target.identity_parts): target
        for target in targets
        if target.target_kind and (target.target_id or target.identity_parts)
    }
    prepared: list[tuple[ReportReferenceTarget, str, str]] = []
    for target in unique.values():
        digest = _identity_digest(target)
        preferred = _safe_fragment(target.target_id)
        base = f"ctx-{_safe_fragment(target.target_kind)}-{preferred or digest[:16]}"
        prepared.append((target, base, digest))

    by_base: dict[str, set[str]] = defaultdict(set)
    for _, base, digest in prepared:
        by_base[base].add(digest)
    references = [
        ReportNavigationReference(
            target_kind=target.target_kind,
            target_id=target.target_id or f"REF-{digest.upper()}",
            anchor_token=(
                base if len(by_base[base]) == 1 else f"{base}-{digest}"
            ),
        )
        for target, base, digest in prepared
    ]
    return tuple(
        sorted(
            references,
            key=lambda item: (item.target_kind, item.target_id, item.anchor_token),
        )
    )


class _ContextIndexes:
    def __init__(self, sources: InvestigationContextSources) -> None:
        self.evidence = {item.id: item for item in sources.evidence if item.id}
        self.reasoning = (
            sources.route_reasoning.by_page_key()
            if sources.route_reasoning is not None
            else {}
        )
        self.responses = _index_by_route(
            sources.successful_content,
            lambda item: item.canonical_url,
        )
        self.route_edges = _index_relationship_edges(sources.route_relationships)
        self.forms = _index_many_by_route(
            sources.forms,
            lambda item: (item.safe_resolved_action_url or "",),
        )
        self.parameters = _index_many_by_route(
            sources.parameters,
            lambda item: item.safe_route_urls,
        )
        self.workflows = _index_many_by_route(
            sources.workflow_leads,
            lambda item: item.covered_urls,
        )

    def items_for_lead(self, lead: OperatorSummaryLead) -> tuple[InvestigationContextItem, ...]:
        items = [
            _evidence_item(self.evidence[evidence_id])
            for evidence_id in lead.evidence_ids
            if evidence_id in self.evidence
        ]
        items.extend(self.items_for_routes(lead.endpoints))
        return _ordered_items(items)

    def items_for_routes(self, routes: Iterable[str]) -> list[InvestigationContextItem]:
        items: list[InvestigationContextItem] = []
        exact_routes = _unique_sorted(
            canonical_relationship_url(route) for route in routes
        )
        for route in exact_routes:
            page_key = canonical_route_url(route)
            context = self.reasoning.get(page_key)
            if context is not None and _reasoning_covers_exact_route(context, route):
                items.extend(_reasoning_items(context))
            items.extend(_response_item(item) for item in self.responses.get(route, ()))
            items.extend(
                _route_relationship_item(item)
                for item in self.route_edges.get(route, ())
                if item.edge_type == "redirect"
            )
            items.extend(_form_item(item, route) for item in self.forms.get(route, ()))
            items.extend(
                parameter_item
                for item in self.parameters.get(route, ())
                if (parameter_item := _parameter_item(item, route)) is not None
            )
            items.extend(
                _workflow_item(item, route) for item in self.workflows.get(route, ())
            )
        return items


def _reasoning_items(context: RouteReasoningContext) -> list[InvestigationContextItem]:
    items = [
        InvestigationContextItem(
            context_kind="route_reasoning",
            relationship_kind=DERIVED,
            target_kind="route_reasoning_context",
            target_id=context.context_id,
            label=context.mapping.reason,
            route_url=context.canonical_page_key,
            evidence_ids=_unique_sorted(
                (
                    *context.request_evidence_ids,
                    *context.independent_reference_evidence_ids,
                    *context.retained_response_evidence_ids,
                )
            ),
            source_ids=context.retained_response_review_ids,
            source_urls=(),
            body_sha256s=(),
            related_ids=context.mapping.relationship_node_keys,
        )
    ]
    items.extend(
        InvestigationContextItem(
            context_kind="route_source_reference",
            relationship_kind=RELATED,
            target_kind="route_source_reference",
            target_id="",
            label="Existing direct route-source relationship",
            route_url=reference.target_url,
            evidence_ids=reference.evidence_ids,
            source_ids=(reference.source_url,),
            source_urls=(reference.source_url, reference.target_url),
            body_sha256s=(),
            related_ids=(reference.cluster_id, *reference.artefact_references),
        )
        for reference in context.source_references
    )
    items.extend(
        InvestigationContextItem(
            context_kind="response_family",
            relationship_kind=RELATED,
            target_kind="response_similarity_group",
            target_id=group.group_id,
            label=group.category,
            route_url=context.canonical_page_key,
            evidence_ids=group.evidence_ids,
            source_ids=(),
            source_urls=(),
            body_sha256s=(),
            related_ids=("policy_relevant" if group.policy_relevant else "context_only",),
        )
        for group in context.weakening_groups
    )
    return items


def _evidence_item(evidence: Evidence) -> InvestigationContextItem:
    return InvestigationContextItem(
        context_kind="evidence",
        relationship_kind=OBSERVED,
        target_kind="evidence",
        target_id=evidence.id,
        label=evidence.evidence_type,
        route_url="",
        evidence_ids=(evidence.id,),
        source_ids=(evidence.source_file,) if evidence.source_file else (),
        source_urls=(),
        body_sha256s=(),
        related_ids=(),
    )


def _response_item(item: SuccessfulDeepContentReview) -> InvestigationContextItem:
    return InvestigationContextItem(
        context_kind="direct_response",
        relationship_kind=OBSERVED,
        target_kind="successful_content_review",
        target_id=item.review_id,
        label=f"Retained HTTP {item.status_code} response",
        route_url=canonical_relationship_url(item.canonical_url),
        evidence_ids=item.evidence_ids,
        source_ids=item.requested_urls,
        source_urls=_unique_sorted((*item.requested_urls, item.canonical_url)),
        body_sha256s=(item.body_sha256,) if item.body_sha256 else (),
        related_ids=item.artefact_references,
    )


def _route_relationship_item(
    item: HttpRouteRelationshipEdge,
) -> InvestigationContextItem:
    return InvestigationContextItem(
        context_kind="redirect_relationship",
        relationship_kind=RELATED,
        target_kind="route_relationship",
        target_id="",
        label="Existing represented HTTP redirect relationship",
        route_url=item.target_url,
        evidence_ids=item.evidence_ids,
        source_ids=(),
        source_urls=(item.source_url, item.target_url),
        body_sha256s=(),
        related_ids=_unique_sorted(
            (*item.artefact_references, *item.corroborated_review_ids)
        ),
    )


def _form_item(item: DeepFormInventoryItem, route: str) -> InvestigationContextItem:
    return InvestigationContextItem(
        context_kind="form_action",
        relationship_kind=RELATED,
        target_kind="deep_form",
        target_id=item.form_id,
        label="Exact represented form action",
        route_url=route,
        evidence_ids=item.evidence_ids,
        source_ids=item.source_ids,
        source_urls=item.safe_document_urls,
        body_sha256s=(),
        related_ids=item.methods,
    )


def _parameter_item(
    item: DeepParameterInventoryItem,
    route: str,
) -> InvestigationContextItem | None:
    observations = tuple(
        observation
        for observation in item.observations
        if canonical_relationship_url(observation.safe_route_url) == route
    )
    if not observations:
        return None
    exact_item = DeepParameterInventoryItem(
        parameter_id=item.parameter_id,
        observations=observations,
        interpretation=item.interpretation,
    )
    return InvestigationContextItem(
        context_kind="route_parameter",
        relationship_kind=RELATED,
        target_kind="deep_parameter",
        target_id=item.parameter_id,
        label=exact_item.name,
        route_url=route,
        evidence_ids=exact_item.evidence_ids,
        source_ids=exact_item.source_ids,
        source_urls=exact_item.safe_source_urls,
        body_sha256s=_parameter_body_sha256s(observations),
        related_ids=exact_item.contexts,
    )


def _parameter_body_sha256s(
    observations: Iterable[object],
) -> tuple[str, ...]:
    return _unique_sorted(
        (
            getattr(
                getattr(observation, "post_followup_source_observation", None),
                "source_body_sha256",
                "",
            )
            or getattr(
                getattr(observation, "initial_retained_source_observation", None),
                "source_body_sha256",
                "",
            )
        )
        for observation in observations
    )


def _workflow_item(item: WorkflowLead, route: str) -> InvestigationContextItem:
    return InvestigationContextItem(
        context_kind="workflow",
        relationship_kind=RELATED,
        target_kind="workflow_lead",
        target_id="",
        label=item.title,
        route_url=route,
        evidence_ids=item.evidence_ids,
        source_ids=(),
        source_urls=item.covered_urls,
        body_sha256s=(),
        related_ids=(item.category, item.priority),
    )


def _route_candidate_items(route: RouteCandidate) -> list[InvestigationContextItem]:
    route_url = _candidate_route_url(route)
    observations = getattr(route, "source_observations", ())
    if observations:
        return [
            InvestigationContextItem(
                context_kind="typed_route_source",
                relationship_kind=DERIVED,
                target_kind="route_source_observation",
                target_id="",
                label="Existing typed static-route source observation",
                route_url=route_url,
                evidence_ids=_unique_sorted(getattr(observation, "evidence_ids", ())),
                source_ids=_unique_sorted(
                    (
                        getattr(observation, "source_id", ""),
                        getattr(observation, "shallow_request_id", ""),
                    )
                ),
                source_urls=_unique_sorted(
                    (
                        getattr(observation, "safe_document_url", ""),
                        getattr(observation, "safe_requested_url", ""),
                        getattr(observation, "safe_final_url", ""),
                    )
                ),
                body_sha256s=_unique_sorted(
                    (getattr(observation, "source_body_sha256", ""),)
                ),
                related_ids=_unique_sorted(
                    (
                        route.candidate_id,
                        getattr(observation, "manifest_file", ""),
                        *getattr(observation, "upstream_route_candidate_ids", ()),
                    )
                ),
            )
            for observation in observations
        ]
    return [
        InvestigationContextItem(
            context_kind="typed_route_source",
            relationship_kind=DERIVED,
            target_kind="route_candidate",
            target_id=route.candidate_id,
            label="Existing typed static-route candidate",
            route_url=route_url,
            evidence_ids=_unique_sorted(getattr(route, "evidence_ids", ())),
            source_ids=_unique_sorted(getattr(route, "source_response_ids", ())),
            source_urls=_unique_sorted(getattr(route, "source_request_urls", ())),
            body_sha256s=(),
            related_ids=(),
        )
    ]


def _candidate_route_url(route: RouteCandidate) -> str:
    return canonical_relationship_url(route.safe_resolved_url) or route.safe_candidate


def _context_view(
    anchor_kind: str,
    target: ReportReferenceTarget,
    label: str,
    items: tuple[InvestigationContextItem, ...],
    references: dict[tuple[str, str], ReportNavigationReference],
) -> InvestigationContextView:
    anchor_target_id = target.target_id or _generated_target_id(target)
    anchor_reference = references[(target.target_kind, anchor_target_id)]
    item_refs = _unique_references(
        references[(ref.target_kind, ref.target_id or _generated_target_id(ref))]
        for item in items
        for ref in (_target_for_item(item),)
        if (ref.target_kind, ref.target_id or _generated_target_id(ref)) in references
    )
    return InvestigationContextView(
        anchor_kind=anchor_kind,
        anchor_id=anchor_target_id,
        anchor_label=label,
        anchor_reference=anchor_reference,
        context_items=items,
        navigation_references=(anchor_reference, *item_refs),
    )


def _target_for_item(item: InvestigationContextItem) -> ReportReferenceTarget:
    if item.target_id:
        return ReportReferenceTarget(
            item.target_kind,
            item.target_id,
            (item.target_id,),
        )
    return ReportReferenceTarget(
        item.target_kind,
        item.target_id,
        (
            item.context_kind,
            item.relationship_kind,
            item.route_url,
            item.label,
            *item.evidence_ids,
            *item.source_ids,
            *item.source_urls,
            *item.body_sha256s,
            *item.related_ids,
        ),
    )


def _backlinks(
    contexts: tuple[InvestigationContextView, ...],
    kind: str,
) -> tuple[InvestigationContextBacklink, ...]:
    anchors: dict[str, set[ReportNavigationReference]] = defaultdict(set)
    for context in contexts:
        values = (
            context.evidence_ids
            if kind == "evidence"
            else _unique_sorted(item.route_url for item in context.context_items)
        )
        for value in values:
            anchors[value].add(context.anchor_reference)
    return tuple(
        InvestigationContextBacklink(
            target_identity=value,
            primary_anchor_references=tuple(
                sorted(
                    anchors[value],
                    key=lambda item: (item.target_kind, item.target_id),
                )
            ),
        )
        for value in sorted(anchors)
    )


def _reasoning_covers_exact_route(
    context: RouteReasoningContext,
    route: str,
) -> bool:
    """Require an existing mapped node before attaching page-keyed reasoning."""

    if context.mapping.status != MAPPING_MAPPED:
        return False
    return route in {
        canonical_relationship_url(node)
        for node in context.mapping.relationship_node_keys
    }


def _index_by_route(
    items: Iterable[object],
    route_getter: Callable[[object], str],
) -> dict[str, tuple[object, ...]]:
    return _index_many_by_route(items, lambda item: (route_getter(item),))


def _index_many_by_route(
    items: Iterable[object],
    routes_getter: Callable[[object], Iterable[str]],
) -> dict[str, tuple[object, ...]]:
    indexed: dict[str, list[object]] = defaultdict(list)
    for item in items:
        for raw_route in routes_getter(item):
            route = canonical_relationship_url(raw_route)
            if route:
                indexed[route].append(item)
    return {
        route: tuple(sorted(values, key=_domain_sort_key))
        for route, values in indexed.items()
    }


def _index_relationship_edges(
    clusters: Iterable[HttpRouteRelationshipCluster],
) -> dict[str, tuple[HttpRouteRelationshipEdge, ...]]:
    indexed: dict[str, set[HttpRouteRelationshipEdge]] = defaultdict(set)
    for cluster in clusters:
        for edge in cluster.edges:
            for raw_route in (edge.source_url, edge.target_url):
                route = canonical_relationship_url(raw_route)
                if route:
                    indexed[route].add(edge)
    return {
        route: tuple(
            sorted(
                edges,
                key=lambda item: (
                    item.edge_type,
                    item.source_url,
                    item.target_url,
                    item.evidence_ids,
                ),
            )
        )
        for route, edges in indexed.items()
    }


def _domain_sort_key(item: object) -> tuple[str, ...]:
    return (
        str(getattr(item, "review_id", "")),
        str(getattr(item, "form_id", "")),
        str(getattr(item, "parameter_id", "")),
        str(getattr(item, "category", "")),
        str(getattr(item, "title", "")),
        repr(item),
    )


def _ordered_items(
    items: Iterable[InvestigationContextItem],
) -> tuple[InvestigationContextItem, ...]:
    unique = {item: item for item in items}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.context_kind,
                item.relationship_kind,
                item.route_url,
                item.target_kind,
                item.target_id,
                item.label,
                item.source_ids,
                item.source_urls,
                item.body_sha256s,
                item.evidence_ids,
                item.related_ids,
            ),
        )
    )


def _lead_identity(lead: OperatorSummaryLead) -> tuple[str, ...]:
    return (
        lead.lead_type,
        lead.title,
        lead.why,
        lead.signal,
        str(lead.score),
        *lead.endpoints,
        *lead.evidence_ids,
        lead.next_action,
    )


def _identity_digest(target: ReportReferenceTarget) -> str:
    material = json.dumps(
        {
            "target_kind": target.target_kind,
            "target_id": target.target_id,
            "identity_parts": target.identity_parts,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _generated_target_id(target: ReportReferenceTarget) -> str:
    return f"REF-{_identity_digest(target).upper()}"


def _safe_fragment(value: str) -> str:
    return _SAFE_TOKEN.sub("-", value.strip().lower()).strip("-._")


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def _unique_references(
    references: Iterable[ReportNavigationReference],
) -> tuple[ReportNavigationReference, ...]:
    return tuple(dict.fromkeys(references))
