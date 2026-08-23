"""Pure normalized composition of retained source clues and HTTP routes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin

from bugslyce.core.models import DiscoveredPath, Evidence, ProjectState
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.http_route_relationships import (
    SOURCE_REFERENCE_TYPES,
    HttpRouteRelationshipCluster,
    canonical_relationship_url,
)
from bugslyce.recon.robots_analysis import RobotsAnalysis
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)


@dataclass(frozen=True)
class OperatorBriefSourceClueObservation:
    """One exact textual clue observed in retained source content."""

    observation_id: str
    source_kind: str
    origin: str
    source_endpoint: str
    clue_type: str
    value: str
    resolved_endpoint: str | None
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefRouteProvenance:
    """One atomic retained route state and its direct provenance."""

    status_codes: tuple[int, ...]
    status_unknown: bool
    redirect_locations: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefRouteObservation:
    """One normalized route observed in retained project evidence."""

    observation_id: str
    source_kind: str
    origin: str
    endpoint: str
    status_codes: tuple[int, ...]
    status_unknown: bool
    redirect_locations: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]
    provenance_records: tuple[OperatorBriefRouteProvenance, ...]


@dataclass(frozen=True)
class OperatorBriefRouteRelationship:
    """One directional relationship derived from retained route evidence."""

    relationship_id: str
    relationship_type: str
    source_endpoint: str
    target_endpoint: str
    status_code: int | None
    raw_references: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefWebContextCompositionInput:
    """Normalized clues, routes, and relationships accepted by the composer."""

    clues: tuple[OperatorBriefSourceClueObservation, ...] = ()
    routes: tuple[OperatorBriefRouteObservation, ...] = ()
    relationships: tuple[OperatorBriefRouteRelationship, ...] = ()


@dataclass(frozen=True)
class OperatorBriefWebContextSubject:
    """One provisional exact-endpoint content subject."""

    subject_id: str
    subject_kind: OperatorBriefSubjectKind
    endpoint: str
    origin: str
    clue_observation_ids: tuple[str, ...]
    route_observation_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    fact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefWebContextComposition:
    """Self-contained normalized web-context subjects and semantic records."""

    subjects: tuple[OperatorBriefWebContextSubject, ...]
    facts: tuple[OperatorBriefFact, ...]
    clues: tuple[OperatorBriefSourceClueObservation, ...]
    routes: tuple[OperatorBriefRouteObservation, ...]
    relationships: tuple[OperatorBriefRouteRelationship, ...]


def build_operator_brief_source_clue_observation(
    *,
    source_kind: str,
    source_id: str,
    source_endpoint: str,
    clue_type: str,
    value: str,
    resolved_endpoint: str | None = None,
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefSourceClueObservation:
    canonical_source_kind = _required_text(source_kind, "clue source kind")
    canonical_source_id = _required_text(source_id, "clue source ID")
    canonical_source_endpoint = _http_endpoint(
        source_endpoint,
        "clue source endpoint",
    )
    canonical_clue_type = _required_text(clue_type, "clue type").casefold()
    canonical_value = _required_text(value, "clue value")
    canonical_resolved_endpoint = (
        None
        if resolved_endpoint is None
        else _http_endpoint(resolved_endpoint, "clue resolved endpoint")
    )
    origin = _http_origin(canonical_source_endpoint)
    return OperatorBriefSourceClueObservation(
        observation_id=_stable_id(
            "WEB-CLUE",
            (
                canonical_source_kind,
                canonical_source_endpoint,
                canonical_clue_type,
                canonical_value,
                canonical_resolved_endpoint or "",
            ),
        ),
        source_kind=canonical_source_kind,
        origin=origin,
        source_endpoint=canonical_source_endpoint,
        clue_type=canonical_clue_type,
        value=canonical_value,
        resolved_endpoint=canonical_resolved_endpoint,
        evidence_ids=_text_membership(evidence_ids, "clue evidence IDs"),
        artefact_references=_text_membership(
            artefact_references,
            "clue artefact references",
        ),
        source_references=(
            OperatorBriefSourceReference(
                source_kind=canonical_source_kind,
                source_id=canonical_source_id,
            ),
        ),
    )


def build_operator_brief_route_observation(
    *,
    source_kind: str,
    source_id: str,
    endpoint: str,
    status_codes: tuple[int, ...] = (),
    status_unknown: bool = False,
    redirect_locations: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefRouteObservation:
    canonical_source_kind = _required_text(source_kind, "route source kind")
    canonical_source_id = _required_text(source_id, "route source ID")
    canonical_endpoint = _http_endpoint(endpoint, "route endpoint")
    if not isinstance(status_unknown, bool):
        raise ValueError("route unknown-status state must be boolean")
    canonical_status_codes = _status_codes(status_codes)
    canonical_redirect_locations = _text_membership(
        redirect_locations,
        "route redirect locations",
    )
    canonical_evidence_ids = _text_membership(
        evidence_ids,
        "route evidence IDs",
    )
    canonical_artefact_references = _text_membership(
        artefact_references,
        "route artefact references",
    )
    source_references = (
        OperatorBriefSourceReference(
            source_kind=canonical_source_kind,
            source_id=canonical_source_id,
        ),
    )
    return OperatorBriefRouteObservation(
        observation_id=_stable_id(
            "WEB-ROUTE",
            (canonical_source_kind, canonical_endpoint),
        ),
        source_kind=canonical_source_kind,
        origin=_http_origin(canonical_endpoint),
        endpoint=canonical_endpoint,
        status_codes=canonical_status_codes,
        status_unknown=status_unknown,
        redirect_locations=canonical_redirect_locations,
        evidence_ids=canonical_evidence_ids,
        artefact_references=canonical_artefact_references,
        source_references=source_references,
        provenance_records=(
            OperatorBriefRouteProvenance(
                status_codes=canonical_status_codes,
                status_unknown=status_unknown,
                redirect_locations=canonical_redirect_locations,
                evidence_ids=canonical_evidence_ids,
                artefact_references=canonical_artefact_references,
                source_references=source_references,
            ),
        ),
    )


def build_operator_brief_route_relationship(
    *,
    source_kind: str,
    source_id: str,
    relationship_type: str,
    source_endpoint: str,
    target_endpoint: str,
    status_code: int | None = None,
    raw_references: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefRouteRelationship:
    canonical_source_kind = _required_text(
        source_kind,
        "route relationship source kind",
    )
    canonical_source_id = _required_text(
        source_id,
        "route relationship source ID",
    )
    canonical_relationship_type = _required_text(
        relationship_type,
        "route relationship type",
    ).casefold()
    canonical_source_endpoint = _http_endpoint(
        source_endpoint,
        "route relationship source endpoint",
    )
    canonical_target_endpoint = _http_endpoint(
        target_endpoint,
        "route relationship target endpoint",
    )
    if status_code is not None and (
        isinstance(status_code, bool) or not isinstance(status_code, int)
    ):
        raise ValueError("route relationship status must be an integer or null")
    return OperatorBriefRouteRelationship(
        relationship_id=_stable_id(
            "WEB-ROUTE-REL",
            (
                canonical_relationship_type,
                canonical_source_endpoint,
                canonical_target_endpoint,
                "" if status_code is None else str(status_code),
            ),
        ),
        relationship_type=canonical_relationship_type,
        source_endpoint=canonical_source_endpoint,
        target_endpoint=canonical_target_endpoint,
        status_code=status_code,
        raw_references=_text_membership(
            raw_references,
            "route relationship raw references",
        ),
        evidence_ids=_text_membership(
            evidence_ids,
            "route relationship evidence IDs",
        ),
        artefact_references=_text_membership(
            artefact_references,
            "route relationship artefact references",
        ),
        source_references=(
            OperatorBriefSourceReference(
                source_kind=canonical_source_kind,
                source_id=canonical_source_id,
            ),
        ),
    )


def build_operator_brief_web_context_inputs_from_project_state(
    project_state: ProjectState,
    *,
    robots_analyses: tuple[RobotsAnalysis, ...] = (),
    relationship_clusters: tuple[HttpRouteRelationshipCluster, ...] = (),
) -> OperatorBriefWebContextCompositionInput:
    if not isinstance(project_state, ProjectState):
        raise TypeError("web-context composition requires ProjectState")
    if not isinstance(robots_analyses, tuple) or any(
        not isinstance(item, RobotsAnalysis) for item in robots_analyses
    ):
        raise TypeError("robots analyses must be a tuple of RobotsAnalysis")
    if not isinstance(relationship_clusters, tuple) or any(
        not isinstance(item, HttpRouteRelationshipCluster)
        for item in relationship_clusters
    ):
        raise TypeError(
            "relationship clusters must be a tuple of HttpRouteRelationshipCluster"
        )

    clues: list[OperatorBriefSourceClueObservation] = []
    for analysis in robots_analyses:
        for entry in analysis.entries:
            if entry.field_name not in {"allow", "disallow", "sitemap"}:
                continue
            if not entry.url or not entry.raw_value.strip():
                continue
            resolved = canonical_relationship_url(
                urljoin(entry.url, entry.raw_value.strip())
            )
            if not resolved:
                continue
            references = (
                ()
                if not entry.path
                else (
                    _logical_artefact_reference(
                        entry.path,
                        project_state.input_dir,
                    ),
                )
            )
            clues.append(
                build_operator_brief_source_clue_observation(
                    source_kind="robots_txt",
                    source_id=f"{entry.source_id}:{entry.line_number}",
                    source_endpoint=entry.url,
                    clue_type=entry.field_name,
                    value=entry.raw_value,
                    resolved_endpoint=resolved,
                    evidence_ids=entry.evidence_ids,
                    artefact_references=references,
                )
            )

    for artefact in project_state.http_artifacts:
        if artefact.artifact_type not in SOURCE_REFERENCE_TYPES:
            continue
        raw_value = artefact.value.strip()
        if not artefact.url or not raw_value or raw_value.startswith("#"):
            continue
        resolved = canonical_relationship_url(urljoin(artefact.url, raw_value))
        if not resolved:
            continue
        logical_source = _logical_artefact_reference(
            artefact.source_file,
            project_state.input_dir,
        )
        clues.append(
            build_operator_brief_source_clue_observation(
                source_kind="retained_source_reference",
                source_id=_stable_id(
                    "PROJECT-SOURCE-CLUE",
                    (
                        artefact.url,
                        artefact.artifact_type,
                        raw_value,
                        logical_source,
                    ),
                ),
                source_endpoint=artefact.url,
                clue_type=artefact.artifact_type,
                value=raw_value,
                resolved_endpoint=resolved,
                evidence_ids=tuple(artefact.evidence_ids),
                artefact_references=(logical_source,),
            )
        )

    evidence_by_id = {
        evidence.id: evidence
        for evidence in project_state.evidence
        if evidence.id
    }
    routes = tuple(
        sorted(
            (
                build_operator_brief_route_observation(
                    source_kind="project_state_discovered_path",
                    source_id=_stable_id(
                        "PROJECT-DISCOVERED-PATH",
                        (
                            path.url,
                            _discovered_path_source_identity(
                                path,
                                evidence_by_id,
                                project_state.input_dir,
                            ),
                            (
                                ""
                                if path.status_code is None
                                else str(path.status_code)
                            ),
                            path.redirect_location or "",
                        ),
                    ),
                    endpoint=path.url,
                    status_codes=(
                        ()
                        if path.status_code is None
                        else (path.status_code,)
                    ),
                    status_unknown=path.status_code is None,
                    redirect_locations=(
                        ()
                        if not path.redirect_location
                        else (path.redirect_location,)
                    ),
                    evidence_ids=tuple(path.evidence_ids),
                    artefact_references=_discovered_path_artefact_references(
                        path,
                        evidence_by_id,
                        project_state.input_dir,
                    ),
                )
                for path in project_state.discovered_paths
            ),
            key=lambda item: item.observation_id,
        )
    )
    relationships = tuple(
        sorted(
            (
                build_operator_brief_route_relationship(
                    source_kind="http_route_relationship_edge",
                    source_id=_stable_id(
                        "PROJECT-ROUTE-EDGE",
                        (
                            cluster.cluster_id,
                            edge.edge_type,
                            edge.source_url,
                            edge.target_url,
                            (
                                ""
                                if edge.status_code is None
                                else str(edge.status_code)
                            ),
                        ),
                    ),
                    relationship_type=edge.edge_type,
                    source_endpoint=edge.source_url,
                    target_endpoint=edge.target_url,
                    status_code=edge.status_code,
                    raw_references=edge.raw_references,
                    evidence_ids=edge.evidence_ids,
                    artefact_references=tuple(
                        _logical_artefact_reference(
                            reference,
                            project_state.input_dir,
                        )
                        for reference in edge.artefact_references
                    ),
                )
                for cluster in relationship_clusters
                for edge in cluster.edges
            ),
            key=lambda item: item.relationship_id,
        )
    )
    return combine_operator_brief_web_context_inputs(
        OperatorBriefWebContextCompositionInput(
            clues=tuple(sorted(clues, key=lambda item: item.observation_id)),
            routes=routes,
            relationships=relationships,
        )
    )


def combine_operator_brief_web_context_inputs(
    *inputs: OperatorBriefWebContextCompositionInput,
) -> OperatorBriefWebContextCompositionInput:
    clues: dict[str, OperatorBriefSourceClueObservation] = {}
    routes: dict[str, OperatorBriefRouteObservation] = {}
    relationships: dict[str, OperatorBriefRouteRelationship] = {}
    for item in inputs:
        if not isinstance(item, OperatorBriefWebContextCompositionInput):
            raise TypeError("web-context combiner requires normalized inputs")
        for clue in item.clues:
            if not isinstance(clue, OperatorBriefSourceClueObservation):
                raise TypeError("web-context input contains an invalid clue")
            current = clues.get(clue.observation_id)
            clues[clue.observation_id] = (
                clue if current is None else _combine_clues(current, clue)
            )
        for route in item.routes:
            if not isinstance(route, OperatorBriefRouteObservation):
                raise TypeError("web-context input contains an invalid route")
            current = routes.get(route.observation_id)
            routes[route.observation_id] = (
                route if current is None else _combine_routes(current, route)
            )
        for relationship in item.relationships:
            if not isinstance(relationship, OperatorBriefRouteRelationship):
                raise TypeError(
                    "web-context input contains an invalid route relationship"
                )
            current = relationships.get(relationship.relationship_id)
            relationships[relationship.relationship_id] = (
                relationship
                if current is None
                else _combine_relationships(current, relationship)
            )
    return OperatorBriefWebContextCompositionInput(
        clues=tuple(sorted(clues.values(), key=lambda item: item.observation_id)),
        routes=tuple(sorted(routes.values(), key=lambda item: item.observation_id)),
        relationships=tuple(
            sorted(
                relationships.values(),
                key=lambda item: item.relationship_id,
            )
        ),
    )


def compose_operator_brief_web_context(
    inputs: OperatorBriefWebContextCompositionInput,
) -> OperatorBriefWebContextComposition:
    normalized = combine_operator_brief_web_context_inputs(inputs)
    clue_facts = {
        clue.observation_id: _clue_fact(clue) for clue in normalized.clues
    }
    route_facts = {
        route.observation_id: _route_fact(route) for route in normalized.routes
    }
    relationship_facts = {
        relationship.relationship_id: _relationship_fact(relationship)
        for relationship in normalized.relationships
    }

    clues_by_endpoint: dict[str, list[OperatorBriefSourceClueObservation]] = {}
    for clue in normalized.clues:
        clues_by_endpoint.setdefault(_clue_subject_endpoint(clue), []).append(clue)
    routes_by_endpoint: dict[str, list[OperatorBriefRouteObservation]] = {}
    for route in normalized.routes:
        routes_by_endpoint.setdefault(route.endpoint, []).append(route)

    subjects: list[OperatorBriefWebContextSubject] = []
    for endpoint in sorted(set((*clues_by_endpoint, *routes_by_endpoint))):
        clues = tuple(
            sorted(
                clues_by_endpoint.get(endpoint, ()),
                key=lambda item: item.observation_id,
            )
        )
        routes = tuple(
            sorted(
                routes_by_endpoint.get(endpoint, ()),
                key=lambda item: item.observation_id,
            )
        )
        relationships = tuple(
            relationship
            for relationship in normalized.relationships
            if endpoint
            in (relationship.source_endpoint, relationship.target_endpoint)
        )
        facts = tuple(
            sorted(
                (
                    *(clue_facts[item.observation_id] for item in clues),
                    *(route_facts[item.observation_id] for item in routes),
                    *(
                        relationship_facts[item.relationship_id]
                        for item in relationships
                    ),
                ),
                key=lambda item: item.fact_id,
            )
        )
        source_records = (*clues, *routes, *relationships)
        subjects.append(
            OperatorBriefWebContextSubject(
                subject_id=_stable_id("WEB-CONTEXT-SUBJECT", (endpoint,)),
                subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
                endpoint=endpoint,
                origin=_http_origin(endpoint),
                clue_observation_ids=tuple(
                    item.observation_id for item in clues
                ),
                route_observation_ids=tuple(
                    item.observation_id for item in routes
                ),
                relationship_ids=tuple(
                    item.relationship_id for item in relationships
                ),
                fact_ids=tuple(item.fact_id for item in facts),
                evidence_ids=tuple(
                    sorted(
                        {
                            value
                            for item in source_records
                            for value in item.evidence_ids
                        }
                    )
                ),
                artefact_references=tuple(
                    sorted(
                        {
                            value
                            for item in source_records
                            for value in item.artefact_references
                        }
                    )
                ),
                source_references=tuple(
                    sorted(
                        {
                            value
                            for item in source_records
                            for value in item.source_references
                        }
                    )
                ),
            )
        )

    facts = tuple(
        sorted(
            (
                *clue_facts.values(),
                *route_facts.values(),
                *relationship_facts.values(),
            ),
            key=lambda item: item.fact_id,
        )
    )
    return OperatorBriefWebContextComposition(
        subjects=tuple(sorted(subjects, key=lambda item: item.subject_id)),
        facts=facts,
        clues=normalized.clues,
        routes=normalized.routes,
        relationships=normalized.relationships,
    )


def _stable_id(prefix: str, values: tuple[str, ...]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    digest = sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _combine_clues(
    first: OperatorBriefSourceClueObservation,
    second: OperatorBriefSourceClueObservation,
) -> OperatorBriefSourceClueObservation:
    first_core = (
        first.source_kind,
        first.origin,
        first.source_endpoint,
        first.clue_type,
        first.value,
        first.resolved_endpoint,
    )
    second_core = (
        second.source_kind,
        second.origin,
        second.source_endpoint,
        second.clue_type,
        second.value,
        second.resolved_endpoint,
    )
    if first_core != second_core:
        raise ValueError("duplicate clue observation has conflicting semantics")
    return replace(
        first,
        evidence_ids=_union(first.evidence_ids, second.evidence_ids),
        artefact_references=_union(
            first.artefact_references,
            second.artefact_references,
        ),
        source_references=tuple(
            sorted(set((*first.source_references, *second.source_references)))
        ),
    )


def _combine_route_provenance_records(
    first: tuple[OperatorBriefRouteProvenance, ...],
    second: tuple[OperatorBriefRouteProvenance, ...],
) -> tuple[OperatorBriefRouteProvenance, ...]:
    records: dict[
        tuple[tuple[int, ...], bool, tuple[str, ...]],
        OperatorBriefRouteProvenance,
    ] = {}
    for record in (*first, *second):
        if not isinstance(record, OperatorBriefRouteProvenance):
            raise TypeError("route provenance contains an invalid record")
        key = (
            record.status_codes,
            record.status_unknown,
            record.redirect_locations,
        )
        current = records.get(key)
        records[key] = (
            record
            if current is None
            else replace(
                current,
                evidence_ids=_union(current.evidence_ids, record.evidence_ids),
                artefact_references=_union(
                    current.artefact_references,
                    record.artefact_references,
                ),
                source_references=tuple(
                    sorted(
                        set(
                            (
                                *current.source_references,
                                *record.source_references,
                            )
                        )
                    )
                ),
            )
        )
    return tuple(records[key] for key in sorted(records))


def _combine_routes(
    first: OperatorBriefRouteObservation,
    second: OperatorBriefRouteObservation,
) -> OperatorBriefRouteObservation:
    first_core = (first.source_kind, first.origin, first.endpoint)
    second_core = (second.source_kind, second.origin, second.endpoint)
    if first_core != second_core:
        raise ValueError("duplicate route observation has conflicting semantics")
    return replace(
        first,
        status_codes=tuple(sorted(set((*first.status_codes, *second.status_codes)))),
        status_unknown=first.status_unknown or second.status_unknown,
        redirect_locations=_union(
            first.redirect_locations,
            second.redirect_locations,
        ),
        evidence_ids=_union(first.evidence_ids, second.evidence_ids),
        artefact_references=_union(
            first.artefact_references,
            second.artefact_references,
        ),
        source_references=tuple(
            sorted(set((*first.source_references, *second.source_references)))
        ),
        provenance_records=_combine_route_provenance_records(
            first.provenance_records,
            second.provenance_records,
        ),
    )


def _combine_relationships(
    first: OperatorBriefRouteRelationship,
    second: OperatorBriefRouteRelationship,
) -> OperatorBriefRouteRelationship:
    first_core = (
        first.relationship_type,
        first.source_endpoint,
        first.target_endpoint,
        first.status_code,
    )
    second_core = (
        second.relationship_type,
        second.source_endpoint,
        second.target_endpoint,
        second.status_code,
    )
    if first_core != second_core:
        raise ValueError("duplicate route relationship has conflicting semantics")
    return replace(
        first,
        raw_references=_union(first.raw_references, second.raw_references),
        evidence_ids=_union(first.evidence_ids, second.evidence_ids),
        artefact_references=_union(
            first.artefact_references,
            second.artefact_references,
        ),
        source_references=tuple(
            sorted(set((*first.source_references, *second.source_references)))
        ),
    )


def _union(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set((*first, *second))))


def _clue_fact(clue: OperatorBriefSourceClueObservation) -> OperatorBriefFact:
    endpoints = {clue.source_endpoint}
    if clue.resolved_endpoint:
        endpoints.add(clue.resolved_endpoint)
    return OperatorBriefFact(
        fact_id=_stable_id(
            "WEB-CONTEXT-FACT",
            (OperatorBriefFactKind.SOURCE_ROBOTS_CLUE.value, clue.observation_id),
        ),
        kind=OperatorBriefFactKind.SOURCE_ROBOTS_CLUE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label=f"Retained {clue.clue_type} clue",
        summary=(
            f"Retained {clue.clue_type} clue {clue.value} in "
            f"{clue.source_endpoint}."
        ),
        endpoints=tuple(sorted(endpoints)),
        origins=(clue.origin,),
        evidence_ids=clue.evidence_ids,
        artefact_references=clue.artefact_references,
        source_references=clue.source_references,
        route=clue.value,
    )


def _route_fact(route: OperatorBriefRouteObservation) -> OperatorBriefFact:
    if route.status_codes:
        noun = "status" if len(route.status_codes) == 1 else "statuses"
        status_text = f"with {noun} {', '.join(map(str, route.status_codes))}"
        if route.status_unknown:
            status_text += "; another retained observation had no recorded status"
    else:
        status_text = "without a recorded response status"
    return OperatorBriefFact(
        fact_id=_stable_id(
            "WEB-CONTEXT-FACT",
            (OperatorBriefFactKind.HTTP_ROUTE.value, route.observation_id),
        ),
        kind=OperatorBriefFactKind.HTTP_ROUTE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label=f"Retained route {route.endpoint}",
        summary=f"Route {route.endpoint} was retained {status_text}.",
        endpoints=(route.endpoint,),
        origins=(route.origin,),
        evidence_ids=route.evidence_ids,
        artefact_references=route.artefact_references,
        source_references=route.source_references,
        route=route.endpoint,
    )


def _relationship_fact(
    relationship: OperatorBriefRouteRelationship,
) -> OperatorBriefFact:
    return OperatorBriefFact(
        fact_id=_stable_id(
            "WEB-CONTEXT-FACT",
            (
                OperatorBriefFactKind.ROUTE_RELATIONSHIP.value,
                relationship.relationship_id,
            ),
        ),
        kind=OperatorBriefFactKind.ROUTE_RELATIONSHIP,
        semantic_class=OperatorBriefSemanticClass.DERIVED,
        role=OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
        label=f"Derived {relationship.relationship_type} route relationship",
        summary=(
            f"Derived {relationship.relationship_type} route relationship from "
            f"{relationship.source_endpoint} to {relationship.target_endpoint}."
        ),
        endpoints=(
            relationship.source_endpoint,
            relationship.target_endpoint,
        ),
        origins=tuple(
            sorted(
                {
                    _http_origin(relationship.source_endpoint),
                    _http_origin(relationship.target_endpoint),
                }
            )
        ),
        evidence_ids=relationship.evidence_ids,
        artefact_references=relationship.artefact_references,
        source_references=relationship.source_references,
        http_status_code=relationship.status_code,
    )


def _clue_subject_endpoint(clue: OperatorBriefSourceClueObservation) -> str:
    if (
        clue.resolved_endpoint
        and _http_origin(clue.resolved_endpoint) == clue.origin
    ):
        return clue.resolved_endpoint
    return clue.source_endpoint


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonblank text")
    return value.strip()


def _text_membership(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{label} must be a tuple")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} cannot contain blank values")
    return tuple(sorted(set(values)))


def _status_codes(values: tuple[int, ...]) -> tuple[int, ...]:
    if not isinstance(values, tuple):
        raise ValueError("route status codes must be a tuple")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("route status codes must be integers")
    return tuple(sorted(set(values)))


def _http_endpoint(value: object, label: str) -> str:
    endpoint = canonical_relationship_url(_required_text(value, label))
    if not endpoint:
        raise ValueError(f"{label} must be a canonical HTTP(S) endpoint")
    return endpoint


def _http_origin(endpoint: str) -> str:
    origin = http_origin_from_url(endpoint)
    if origin is None:
        raise ValueError("web-context endpoint has no valid HTTP(S) origin")
    return origin.origin_url


def _logical_artefact_reference(value: str, input_dir: str) -> str:
    text = _required_text(value, "web-context source artefact")
    source = Path(text)
    root = Path(_required_text(input_dir, "ProjectState input directory"))
    if source.is_absolute():
        try:
            source = source.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "web-context source artefact is outside the project"
            ) from exc
    if ".." in source.parts or not source.parts:
        raise ValueError("web-context source artefact is unsafe")
    return PurePosixPath(*source.parts).as_posix()


def _discovered_path_artefact_references(
    path: DiscoveredPath,
    evidence_by_id: dict[str, Evidence],
    input_dir: str,
) -> tuple[str, ...]:
    source_text = _required_text(path.source, "discovered-path source")
    if Path(source_text).is_absolute():
        return (_logical_artefact_reference(source_text, input_dir),)

    logical_source = _logical_artefact_reference(source_text, input_dir)
    for evidence_id in path.evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None or not evidence.source_file.strip():
            continue
        if (
            _logical_artefact_reference(evidence.source_file, input_dir)
            == logical_source
        ):
            return (logical_source,)
    return ()


def _discovered_path_source_identity(
    path: DiscoveredPath,
    evidence_by_id: dict[str, Evidence],
    input_dir: str,
) -> str:
    references = _discovered_path_artefact_references(
        path,
        evidence_by_id,
        input_dir,
    )
    if references:
        return references[0]
    return _required_text(path.source, "discovered-path source")
