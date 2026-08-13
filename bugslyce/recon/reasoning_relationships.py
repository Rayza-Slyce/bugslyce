"""Deterministic composition of existing route evidence for offline reasoning."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    PAGE_REVIEW_WEAKENING_GROUP_CATEGORIES,
)
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    canonical_relationship_url,
)
from bugslyce.recon.route_provenance import (
    INDEPENDENT_REFERENCE_EVIDENCE_TYPES,
    REQUEST_EVIDENCE_TYPES,
    canonical_route_url,
)


MAPPING_MAPPED = "mapped"
MAPPING_UNMAPPED = "unmapped"
MAPPING_AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class RouteRelationshipMapping:
    """One deterministic page-key to exact relationship-node mapping outcome."""

    page_key: str
    relationship_node_keys: tuple[str, ...]
    status: str
    reason: str


@dataclass(frozen=True)
class RouteSourceReference:
    """One eligible existing source-reference edge attached to a route."""

    cluster_id: str
    source_url: str
    target_url: str
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]


@dataclass(frozen=True)
class RouteWeakeningGroup:
    """One existing response-family group relevant to route interpretation."""

    group_id: str
    category: str
    evidence_ids: tuple[str, ...]
    policy_relevant: bool


@dataclass(frozen=True)
class RouteReasoningContext:
    """Derived route evidence composition with no collection authority."""

    context_id: str
    mapping: RouteRelationshipMapping
    request_evidence_ids: tuple[str, ...]
    independent_reference_evidence_ids: tuple[str, ...]
    retained_response_review_ids: tuple[str, ...]
    retained_response_evidence_ids: tuple[str, ...]
    source_references: tuple[RouteSourceReference, ...]
    weakening_groups: tuple[RouteWeakeningGroup, ...]

    @property
    def canonical_page_key(self) -> str:
        """Return the canonical page identity used to index this context."""

        return self.mapping.page_key

    @property
    def response_observed(self) -> bool:
        """Return whether an eligible retained response maps unambiguously."""

        return (
            self.mapping.status == MAPPING_MAPPED
            and bool(self.retained_response_review_ids)
        )

    @property
    def independent_confirmation(self) -> bool:
        """Return whether an eligible source edge and retained response coincide."""

        return self.response_observed and bool(self.source_references)

    @property
    def request_derived(self) -> bool:
        """Return whether request-derived provenance exists for the route."""

        return bool(self.request_evidence_ids)

    @property
    def weakening_family(self) -> bool:
        """Return whether current page policy treats a response family as weakening."""

        return any(group.policy_relevant for group in self.weakening_groups)

    @property
    def distinct_response_corroboration_allowed(self) -> bool:
        """Return whether literal corroboration is not weakened for distinctness."""

        return self.independent_confirmation and not self.weakening_family

    @property
    def corroborating_evidence_ids(self) -> tuple[str, ...]:
        """Return only evidence IDs from eligible source-reference edges."""

        return _unique_sorted(
            evidence_id
            for reference in self.source_references
            for evidence_id in reference.evidence_ids
        )


@dataclass(frozen=True)
class RouteReasoningReview:
    """Immutable derived route contexts keyed by canonical page identity."""

    contexts: tuple[RouteReasoningContext, ...]

    def by_page_key(self) -> dict[str, RouteReasoningContext]:
        """Return a fresh page-key lookup for bounded downstream consumption."""

        return {context.canonical_page_key: context for context in self.contexts}


def map_relationship_nodes(
    page_key: str,
    relationship_node_keys: Iterable[str],
) -> RouteRelationshipMapping:
    """Map exact relationship nodes to one query-free page key, failing closed."""

    nodes = _unique_sorted(
        node
        for value in relationship_node_keys
        if (node := canonical_relationship_url(value))
        and canonical_route_url(node) == page_key
    )
    if not page_key:
        return RouteRelationshipMapping(
            page_key=page_key,
            relationship_node_keys=(),
            status=MAPPING_UNMAPPED,
            reason="The canonical page key is empty or unsupported.",
        )
    if not nodes:
        return RouteRelationshipMapping(
            page_key=page_key,
            relationship_node_keys=(),
            status=MAPPING_UNMAPPED,
            reason="No relationship node maps to the canonical page key.",
        )
    if len(nodes) == 1:
        return RouteRelationshipMapping(
            page_key=page_key,
            relationship_node_keys=nodes,
            status=MAPPING_MAPPED,
            reason="One relationship node maps to the canonical page key.",
        )
    return RouteRelationshipMapping(
        page_key=page_key,
        relationship_node_keys=nodes,
        status=MAPPING_AMBIGUOUS,
        reason=(
            "Multiple materially distinct relationship nodes map to the "
            "canonical page key."
        ),
    )


def build_route_reasoning_review(
    project_state: ProjectState,
    *,
    successful_reviews: Sequence[SuccessfulDeepContentReview] = (),
    relationship_clusters: Sequence[HttpRouteRelationshipCluster] = (),
    response_similarity_review: DeepResponseSimilarityReview | None = None,
) -> RouteReasoningReview:
    """Compose existing route facts once using indexed, offline-only lookups."""

    evidence_types = {
        evidence.id: evidence.evidence_type
        for evidence in getattr(project_state, "evidence", ())
        if evidence.id
    }
    page_keys: set[str] = set()
    request_ids_by_page: dict[str, set[str]] = defaultdict(set)
    independent_ids_by_page: dict[str, set[str]] = defaultdict(set)

    for path in getattr(project_state, "discovered_paths", ()):
        page_key = canonical_route_url(path.url)
        if not page_key:
            continue
        page_keys.add(page_key)
        request_ids_by_page[page_key].update(path.evidence_ids)

    for endpoint in getattr(project_state, "endpoints", ()):
        page_key = canonical_route_url(endpoint.url)
        if not page_key:
            continue
        page_keys.add(page_key)
        for evidence_id in endpoint.evidence_ids:
            evidence_type = evidence_types.get(evidence_id)
            if evidence_type in REQUEST_EVIDENCE_TYPES:
                request_ids_by_page[page_key].add(evidence_id)
            elif evidence_type in INDEPENDENT_REFERENCE_EVIDENCE_TYPES:
                independent_ids_by_page[page_key].add(evidence_id)

    reviews_by_node: dict[str, list[SuccessfulDeepContentReview]] = defaultdict(list)
    review_nodes_by_page: dict[str, set[str]] = defaultdict(set)
    for review in successful_reviews:
        relationship_node = canonical_relationship_url(review.canonical_url)
        page_key = canonical_route_url(relationship_node)
        if not relationship_node or not page_key:
            continue
        page_keys.add(page_key)
        reviews_by_node[relationship_node].append(review)
        review_nodes_by_page[page_key].add(relationship_node)

    relationship_nodes_by_page: dict[str, set[str]] = defaultdict(set)
    source_references_by_page: dict[str, list[RouteSourceReference]] = defaultdict(list)
    for cluster in relationship_clusters:
        for node in cluster.route_nodes:
            page_key = canonical_route_url(node)
            if not page_key:
                continue
            page_keys.add(page_key)
            relationship_nodes_by_page[page_key].add(node)
        for edge in cluster.edges:
            if edge.edge_type != "source_reference":
                continue
            page_key = canonical_route_url(edge.target_url)
            if not page_key:
                continue
            source_references_by_page[page_key].append(
                RouteSourceReference(
                    cluster_id=cluster.cluster_id,
                    source_url=edge.source_url,
                    target_url=edge.target_url,
                    evidence_ids=_unique_sorted(edge.evidence_ids),
                    artefact_references=_unique_sorted(edge.artefact_references),
                )
            )

    weakening_by_node: dict[str, list[RouteWeakeningGroup]] = defaultdict(list)
    for group in (
        response_similarity_review.groups
        if response_similarity_review is not None
        else ()
    ):
        for value in group.requested_urls:
            relationship_node = canonical_relationship_url(value)
            if not relationship_node:
                continue
            page_key = canonical_route_url(relationship_node)
            if not page_key:
                continue
            page_keys.add(page_key)
            weakening_by_node[relationship_node].append(
                RouteWeakeningGroup(
                    group_id=group.group_id,
                    category=group.category,
                    evidence_ids=_unique_sorted(group.evidence_ids),
                    policy_relevant=(
                        group.category in PAGE_REVIEW_WEAKENING_GROUP_CATEGORIES
                    ),
                )
            )

    contexts: list[RouteReasoningContext] = []
    for page_key in sorted(page_keys):
        candidate_nodes = {
            *relationship_nodes_by_page.get(page_key, ()),
            *review_nodes_by_page.get(page_key, ()),
        }
        mapping = map_relationship_nodes(page_key, candidate_nodes)
        reviews = tuple(
            review
            for node in mapping.relationship_node_keys
            for review in sorted(
                reviews_by_node.get(node, ()),
                key=lambda item: (item.review_id, item.canonical_url),
            )
        )
        references = tuple(
            sorted(
                (
                    reference
                    for reference in source_references_by_page.get(page_key, ())
                    if reference.target_url in mapping.relationship_node_keys
                ),
                key=lambda item: (
                    item.target_url,
                    item.source_url,
                    item.cluster_id,
                    item.evidence_ids,
                ),
            )
        )
        independent_ids = _unique_sorted(
            (
                *independent_ids_by_page.get(page_key, ()),
                *(evidence_id for reference in references for evidence_id in reference.evidence_ids),
            )
        )
        weakening_groups = tuple(
            sorted(
                (
                    group
                    for node in mapping.relationship_node_keys
                    for group in weakening_by_node.get(node, ())
                ),
                key=lambda item: (item.category, item.group_id),
            )
        )
        contexts.append(
            RouteReasoningContext(
                context_id=_context_id(page_key, mapping.relationship_node_keys),
                mapping=mapping,
                request_evidence_ids=_unique_sorted(
                    request_ids_by_page.get(page_key, ())
                ),
                independent_reference_evidence_ids=independent_ids,
                retained_response_review_ids=_unique_sorted(
                    review.review_id for review in reviews
                ),
                retained_response_evidence_ids=_unique_sorted(
                    evidence_id
                    for review in reviews
                    for evidence_id in review.evidence_ids
                ),
                source_references=references,
                weakening_groups=weakening_groups,
            )
        )

    return RouteReasoningReview(contexts=tuple(contexts))


def _context_id(page_key: str, relationship_node_keys: tuple[str, ...]) -> str:
    material = json.dumps(
        {
            "kind": "route_reasoning_context",
            "page_key": page_key,
            "relationship_node_keys": relationship_node_keys,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"ROUTE-CONTEXT-{digest}"


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))
