"""Pure programme-origin graph and authorised HTTP work-item planning."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from bugslyce.core.programme_scope import (
    DESTINATION_HTTP_URL,
    OUTCOME_ALLOWED,
    ProgrammeScopePolicy,
    ScopeDecision,
    build_programme_scope_policy,
    build_programme_scope_rule,
    canonicalise_http_url_destination,
    evaluate_raw_scope_destination,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url


RELATIONSHIP_CONFIGURED_SEED = "configured_seed"
RELATIONSHIP_OBSERVED_REDIRECT = "observed_redirect"
RELATIONSHIP_OBSERVED_REFERENCE = "observed_reference"
RELATIONSHIP_DOCUMENTED_SERVICE = "documented_service"

SUPPORTED_PROGRAMME_RELATIONSHIP_TYPES = frozenset(
    {
        RELATIONSHIP_CONFIGURED_SEED,
        RELATIONSHIP_OBSERVED_REDIRECT,
        RELATIONSHIP_OBSERVED_REFERENCE,
        RELATIONSHIP_DOCUMENTED_SERVICE,
    }
)

MAXIMUM_PROVENANCE_VALUE_CHARS = 4096
_NODE_ID_PREFIX = "PROGRAMME-ORIGIN-"
_RELATIONSHIP_ID_PREFIX = "PROGRAMME-RELATIONSHIP-"
_WORK_ITEM_ID_PREFIX = "PROGRAMME-HTTP-WORK-"


@dataclass(frozen=True)
class ProgrammeRelationshipEvidence:
    """One canonical typed relationship fact supplied to the pure graph."""

    relationship_type: str
    source_origin: str | None
    destination_origin: str
    evidence_ids: tuple[str, ...]
    provenance_sources: tuple[str, ...]


@dataclass(frozen=True)
class ProgrammeOriginRelationship:
    """One coalesced relationship with an independent destination decision."""

    relationship_id: str
    relationship_type: str
    source_origin: str | None
    destination_origin: str
    evidence_ids: tuple[str, ...]
    provenance_sources: tuple[str, ...]
    destination_scope_decision: ScopeDecision
    destination_materialisation_eligible: bool


@dataclass(frozen=True)
class ProgrammeOriginNode:
    """One exact HTTP origin and its canonical programme-scope state."""

    node_id: str
    canonical_origin: str
    origin: HttpOrigin
    scope_decision: ScopeDecision
    materialisation_eligible: bool
    configured_seed: bool
    relationship_ids: tuple[str, ...]


@dataclass(frozen=True)
class ProgrammeGraph:
    """Immutable deterministic exact-origin programme topology."""

    programme_scope_policy: ProgrammeScopePolicy = field(repr=False)
    nodes: tuple[ProgrammeOriginNode, ...]
    relationships: tuple[ProgrammeOriginRelationship, ...]


@dataclass(frozen=True)
class ProgrammeHTTPWorkItem:
    """One exact allowed HTTP origin ready for later bounded orchestration."""

    work_item_id: str
    canonical_origin: str
    node_id: str
    scope_decision: ScopeDecision
    inclusion_rule_ids: tuple[str, ...]
    configured_seed: bool
    dynamically_materialised: bool
    relationship_ids: tuple[str, ...]


@dataclass
class _RelationshipAccumulator:
    evidence_ids: set[str]
    provenance_sources: set[str]


def build_programme_relationship_evidence(
    *,
    relationship_type: object,
    source_origin: object,
    destination_origin: object,
    evidence_ids: object,
    provenance_sources: object,
) -> ProgrammeRelationshipEvidence:
    """Build one canonical offline relationship input without granting authority."""

    if (
        not isinstance(relationship_type, str)
        or relationship_type not in SUPPORTED_PROGRAMME_RELATIONSHIP_TYPES
    ):
        raise ValueError("Programme relationship type is unsupported.")

    if relationship_type == RELATIONSHIP_CONFIGURED_SEED:
        if source_origin is not None:
            raise ValueError("Configured programme seed must not have a source origin.")
        canonical_source = None
    else:
        if source_origin is None:
            raise ValueError("Programme relationship requires an exact source origin.")
        canonical_source = _canonical_origin(source_origin).origin_url

    canonical_destination = _canonical_origin(destination_origin).origin_url
    canonical_evidence_ids = _canonical_text_tuple(
        evidence_ids,
        label="Programme relationship evidence IDs",
        allow_empty=relationship_type == RELATIONSHIP_CONFIGURED_SEED,
    )
    canonical_provenance = _canonical_text_tuple(
        provenance_sources,
        label="Programme relationship provenance sources",
        allow_empty=False,
    )
    return ProgrammeRelationshipEvidence(
        relationship_type=relationship_type,
        source_origin=canonical_source,
        destination_origin=canonical_destination,
        evidence_ids=canonical_evidence_ids,
        provenance_sources=canonical_provenance,
    )


def build_programme_graph(
    policy: ProgrammeScopePolicy,
    *,
    relationship_evidence: tuple[ProgrammeRelationshipEvidence, ...],
) -> ProgrammeGraph:
    """Build an evidence graph with one independent scope decision per origin."""

    canonical_policy = _canonical_policy_copy(policy)
    if not isinstance(relationship_evidence, tuple):
        raise ValueError("Programme relationship evidence must be an immutable tuple.")

    accumulators: dict[
        tuple[str, str | None, str],
        _RelationshipAccumulator,
    ] = {}
    for supplied in relationship_evidence:
        canonical = _canonical_evidence_copy(supplied)
        key = _relationship_key(canonical)
        accumulator = accumulators.setdefault(
            key,
            _RelationshipAccumulator(evidence_ids=set(), provenance_sources=set()),
        )
        accumulator.evidence_ids.update(canonical.evidence_ids)
        accumulator.provenance_sources.update(canonical.provenance_sources)

    origins = {
        origin
        for _relationship_type, source, destination in accumulators
        for origin in (source, destination)
        if origin is not None
    }
    decisions = {
        origin: evaluate_raw_scope_destination(
            canonical_policy,
            DESTINATION_HTTP_URL,
            f"{origin}/",
        )
        for origin in origins
    }

    relationships = tuple(
        _relationship_from_accumulator(key, accumulators[key], decisions)
        for key in sorted(accumulators, key=_relationship_sort_key)
    )
    relationship_ids_by_origin: dict[str, set[str]] = {
        origin: set() for origin in origins
    }
    configured_seeds: set[str] = set()
    for relationship in relationships:
        if relationship.source_origin is not None:
            relationship_ids_by_origin[relationship.source_origin].add(
                relationship.relationship_id
            )
        relationship_ids_by_origin[relationship.destination_origin].add(
            relationship.relationship_id
        )
        if relationship.relationship_type == RELATIONSHIP_CONFIGURED_SEED:
            configured_seeds.add(relationship.destination_origin)

    nodes = tuple(
        _node_from_origin(
            origin,
            decisions[origin],
            configured_seed=origin in configured_seeds,
            relationship_ids=tuple(sorted(relationship_ids_by_origin[origin])),
        )
        for origin in sorted(origins, key=_origin_sort_key)
    )
    return ProgrammeGraph(
        programme_scope_policy=canonical_policy,
        nodes=nodes,
        relationships=relationships,
    )


def build_programme_http_work_items(
    graph: ProgrammeGraph,
) -> tuple[ProgrammeHTTPWorkItem, ...]:
    """Plan exact origins only for graph nodes positively allowed by scope."""

    canonical_graph = _canonical_graph_copy(graph)
    items = tuple(
        ProgrammeHTTPWorkItem(
            work_item_id=_stable_id(_WORK_ITEM_ID_PREFIX, node.canonical_origin),
            canonical_origin=node.canonical_origin,
            node_id=node.node_id,
            scope_decision=node.scope_decision,
            inclusion_rule_ids=node.scope_decision.matched_inclusion_rule_ids,
            configured_seed=node.configured_seed,
            dynamically_materialised=not node.configured_seed,
            relationship_ids=node.relationship_ids,
        )
        for node in canonical_graph.nodes
        if node.scope_decision.outcome == OUTCOME_ALLOWED
    )
    return tuple(sorted(items, key=lambda item: _origin_sort_key(item.canonical_origin)))


def _canonical_origin(value: object) -> HttpOrigin:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Programme relationship origin must be an exact HTTP origin.")
    try:
        destination = canonicalise_http_url_destination(value)
    except ValueError:
        raise ValueError(
            "Programme relationship origin must be an exact HTTP origin."
        ) from None
    if destination.path != "/" or destination.query is not None:
        raise ValueError("Programme relationship origin must not contain route data.")
    origin = http_origin_from_url(destination.origin.canonical_value)
    if origin is None:
        raise ValueError("Programme relationship origin must be an exact HTTP origin.")
    return origin


def _canonical_text_tuple(
    values: object,
    *,
    label: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{label} must be an immutable tuple.")
    canonical: set[str] = set()
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > MAXIMUM_PROVENANCE_VALUE_CHARS
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError(f"{label} contain an invalid value.")
        canonical.add(value)
    if not canonical and not allow_empty:
        raise ValueError(f"{label} must not be empty.")
    return tuple(sorted(canonical))


def _canonical_policy_copy(policy: ProgrammeScopePolicy) -> ProgrammeScopePolicy:
    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("Programme graph requires a canonical programme scope policy.")
    try:
        rules = tuple(
            build_programme_scope_rule(
                rule_id=rule.rule_id,
                action=rule.action,
                kind=rule.kind,
                value=rule.canonical_value,
                scheme=rule.scheme,
                port=rule.port,
                private_note=rule.private_note,
                private_source_wording=rule.private_source_wording,
            )
            for rule in policy.rules
        )
        canonical = build_programme_scope_policy(
            rules,
            schema_version=policy.schema_version,
            engagement_context=policy.engagement_context,
            updated_at=policy.updated_at,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError(
            "Programme graph requires a canonical programme scope policy."
        ) from None
    if canonical != policy:
        raise ValueError("Programme graph requires a canonical programme scope policy.")
    return canonical


def _canonical_evidence_copy(
    supplied: object,
) -> ProgrammeRelationshipEvidence:
    if not isinstance(supplied, ProgrammeRelationshipEvidence):
        raise ValueError("Programme graph relationship evidence is invalid.")
    try:
        canonical = build_programme_relationship_evidence(
            relationship_type=supplied.relationship_type,
            source_origin=supplied.source_origin,
            destination_origin=supplied.destination_origin,
            evidence_ids=supplied.evidence_ids,
            provenance_sources=supplied.provenance_sources,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Programme graph relationship evidence is invalid.") from None
    if canonical != supplied:
        raise ValueError("Programme graph relationship evidence is not canonical.")
    return canonical


def _canonical_graph_copy(graph: object) -> ProgrammeGraph:
    if not isinstance(graph, ProgrammeGraph):
        raise ValueError("Programme HTTP work-item planning requires a canonical graph.")
    try:
        relationship_evidence = tuple(
            build_programme_relationship_evidence(
                relationship_type=relationship.relationship_type,
                source_origin=relationship.source_origin,
                destination_origin=relationship.destination_origin,
                evidence_ids=relationship.evidence_ids,
                provenance_sources=relationship.provenance_sources,
            )
            for relationship in graph.relationships
        )
        canonical = build_programme_graph(
            graph.programme_scope_policy,
            relationship_evidence=relationship_evidence,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError(
            "Programme HTTP work-item planning requires a canonical graph."
        ) from None
    if canonical != graph:
        raise ValueError(
            "Programme HTTP work-item planning requires a canonical graph."
        )
    return canonical


def _relationship_from_accumulator(
    key: tuple[str, str | None, str],
    accumulator: _RelationshipAccumulator,
    decisions: dict[str, ScopeDecision],
) -> ProgrammeOriginRelationship:
    relationship_type, source, destination = key
    decision = decisions[destination]
    return ProgrammeOriginRelationship(
        relationship_id=_stable_id(_RELATIONSHIP_ID_PREFIX, key),
        relationship_type=relationship_type,
        source_origin=source,
        destination_origin=destination,
        evidence_ids=tuple(sorted(accumulator.evidence_ids)),
        provenance_sources=tuple(sorted(accumulator.provenance_sources)),
        destination_scope_decision=decision,
        destination_materialisation_eligible=decision.outcome == OUTCOME_ALLOWED,
    )


def _node_from_origin(
    canonical_origin: str,
    decision: ScopeDecision,
    *,
    configured_seed: bool,
    relationship_ids: tuple[str, ...],
) -> ProgrammeOriginNode:
    origin = http_origin_from_url(canonical_origin)
    if origin is None:
        raise ValueError("Programme graph contains an invalid canonical origin.")
    return ProgrammeOriginNode(
        node_id=_stable_id(_NODE_ID_PREFIX, canonical_origin),
        canonical_origin=canonical_origin,
        origin=origin,
        scope_decision=decision,
        materialisation_eligible=decision.outcome == OUTCOME_ALLOWED,
        configured_seed=configured_seed,
        relationship_ids=relationship_ids,
    )


def _relationship_key(
    evidence: ProgrammeRelationshipEvidence,
) -> tuple[str, str | None, str]:
    return (
        evidence.relationship_type,
        evidence.source_origin,
        evidence.destination_origin,
    )


def _relationship_sort_key(
    key: tuple[str, str | None, str],
) -> tuple[str, str, str]:
    relationship_type, source, destination = key
    return relationship_type, source or "", destination


def _origin_sort_key(value: str) -> tuple[str, str, int]:
    origin = http_origin_from_url(value)
    if origin is None:
        raise ValueError("Programme graph contains an invalid canonical origin.")
    return origin.scheme, origin.hostname, origin.effective_port


def _stable_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}{hashlib.sha256(encoded).hexdigest()[:24]}"
