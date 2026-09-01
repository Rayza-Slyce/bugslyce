"""Deterministic application/service composition from retained recon evidence.

This module composes typed, offline reconnaissance evidence.  Its models do
not grant request authority, schedule work, execute HTTP, or own persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
from typing import Iterable

from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult,
    DeepHtmlRouteReference,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteCandidate,
    DeepJavaScriptRouteExtractionResult,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipEdge,
    canonical_relationship_url,
)


class ApplicationServiceEntityKind(Enum):
    HTTP_ORIGIN = "http_origin"
    HTTP_ROUTE = "http_route"
    SOURCE_SET = "source_set"


class ApplicationServiceRelationKind(Enum):
    REDIRECTS_TO = "redirects_to"
    DECLARES_ROUTE = "declares_route"
    REFERENCES_ROUTE = "references_route"


class ApplicationServiceSupportBasis(Enum):
    DIRECT_OBSERVATION = "direct_observation"
    DIRECT_DOCUMENTATION = "direct_documentation"
    DETERMINISTIC_DERIVATION = "deterministic_derivation"


class ApplicationServiceSourceSemantic(Enum):
    HTTP_REDIRECT = "http_redirect"
    SITEMAP_DECLARATION = "sitemap_declaration"
    HTML_ROUTE_REFERENCE = "html_route_reference"
    JAVASCRIPT_REQUEST_CALL = "javascript_request_call"
    JAVASCRIPT_ROUTE_CONFIGURATION = "javascript_route_configuration"


class ApplicationServiceSourceOwnerKind(Enum):
    HTTP_ROUTE_RELATIONSHIP_EDGE = "http_route_relationship_edge"
    DEEP_METADATA_COLLECTED_ITEM = "deep_metadata_collected_item"
    DEEP_HTML_ROUTE_REFERENCE = "deep_html_route_reference"
    DEEP_JAVASCRIPT_ROUTE_CANDIDATE = "deep_javascript_route_candidate"


_VALID_SUPPORT_KINDS = {
    ApplicationServiceSourceSemantic.HTTP_REDIRECT: (
        ApplicationServiceSupportBasis.DIRECT_OBSERVATION,
        ApplicationServiceSourceOwnerKind.HTTP_ROUTE_RELATIONSHIP_EDGE,
    ),
    ApplicationServiceSourceSemantic.SITEMAP_DECLARATION: (
        ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        ApplicationServiceSourceOwnerKind.DEEP_METADATA_COLLECTED_ITEM,
    ),
    ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE: (
        ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE,
    ),
    ApplicationServiceSourceSemantic.JAVASCRIPT_REQUEST_CALL: (
        ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        ApplicationServiceSourceOwnerKind.DEEP_JAVASCRIPT_ROUTE_CANDIDATE,
    ),
    ApplicationServiceSourceSemantic.JAVASCRIPT_ROUTE_CONFIGURATION: (
        ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        ApplicationServiceSourceOwnerKind.DEEP_JAVASCRIPT_ROUTE_CANDIDATE,
    ),
}

_VALID_RELATION_SEMANTICS = {
    ApplicationServiceRelationKind.REDIRECTS_TO: frozenset(
        {ApplicationServiceSourceSemantic.HTTP_REDIRECT}
    ),
    ApplicationServiceRelationKind.DECLARES_ROUTE: frozenset(
        {ApplicationServiceSourceSemantic.SITEMAP_DECLARATION}
    ),
    ApplicationServiceRelationKind.REFERENCES_ROUTE: frozenset(
        {
            ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE,
            ApplicationServiceSourceSemantic.JAVASCRIPT_REQUEST_CALL,
            ApplicationServiceSourceSemantic.JAVASCRIPT_ROUTE_CONFIGURATION,
        }
    ),
}


def _normalised_strings(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            }
        )
    )


def _semantic_id(prefix: str, *parts: object) -> str:
    """Return an internal stable ID without defining a persisted encoding."""

    digest = sha256()
    for part in parts:
        value = part.value if isinstance(part, Enum) else str(part)
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{prefix}-{digest.hexdigest()}"


def _origin_id(origin: HttpOrigin) -> str:
    return _semantic_id(
        "APP-ORIGIN",
        origin.scheme,
        origin.hostname,
        origin.effective_port,
    )


def _route_id(canonical_url: str) -> str:
    return _semantic_id("APP-ROUTE", canonical_url)


def _source_set_id(resource_urls: tuple[str, ...]) -> str:
    return _semantic_id("APP-SOURCE-SET", *resource_urls)


def _relation_id(
    relation_kind: ApplicationServiceRelationKind,
    source_entity_id: str,
    target_entity_id: str,
) -> str:
    return _semantic_id(
        "APP-RELATION",
        relation_kind,
        source_entity_id,
        target_entity_id,
    )


@dataclass(frozen=True)
class ApplicationServiceSourceReference:
    owner_kind: ApplicationServiceSourceOwnerKind
    source_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.owner_kind, ApplicationServiceSourceOwnerKind):
            raise TypeError("source owner kind must be typed")
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source id must be non-blank")
        object.__setattr__(self, "source_id", self.source_id.strip())


@dataclass(frozen=True)
class ApplicationServiceRelationSupport:
    basis: ApplicationServiceSupportBasis
    source_semantic: ApplicationServiceSourceSemantic
    source_reference: ApplicationServiceSourceReference
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...] = ()
    raw_references: tuple[str, ...] = ()
    http_status_code: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.basis, ApplicationServiceSupportBasis):
            raise TypeError("support basis must be typed")
        if not isinstance(self.source_semantic, ApplicationServiceSourceSemantic):
            raise TypeError("source semantic must be typed")
        if not isinstance(self.source_reference, ApplicationServiceSourceReference):
            raise TypeError("source reference must be typed")
        expected = _VALID_SUPPORT_KINDS[self.source_semantic]
        actual = (self.basis, self.source_reference.owner_kind)
        if actual != expected:
            raise ValueError(
                "source semantic, support basis, and source owner are contradictory"
            )
        evidence_ids = _normalised_strings(self.evidence_ids)
        if not evidence_ids:
            raise ValueError("relation support requires concrete evidence provenance")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        object.__setattr__(
            self,
            "artefact_references",
            _normalised_strings(self.artefact_references),
        )
        object.__setattr__(
            self,
            "raw_references",
            _normalised_strings(self.raw_references),
        )
        if self.http_status_code is not None and (
            isinstance(self.http_status_code, bool)
            or not isinstance(self.http_status_code, int)
            or not 100 <= self.http_status_code <= 599
        ):
            raise ValueError("HTTP status code must be an integer from 100 to 599")


@dataclass(frozen=True)
class ApplicationServiceHttpOrigin:
    entity_id: str
    origin: HttpOrigin
    kind: ApplicationServiceEntityKind = ApplicationServiceEntityKind.HTTP_ORIGIN

    def __post_init__(self) -> None:
        if self.kind is not ApplicationServiceEntityKind.HTTP_ORIGIN:
            raise ValueError("HTTP origin entity has an invalid kind")
        if not isinstance(self.origin, HttpOrigin):
            raise TypeError("origin must be an HttpOrigin")


@dataclass(frozen=True)
class ApplicationServiceHttpRoute:
    entity_id: str
    canonical_url: str
    origin_id: str
    kind: ApplicationServiceEntityKind = ApplicationServiceEntityKind.HTTP_ROUTE

    def __post_init__(self) -> None:
        if self.kind is not ApplicationServiceEntityKind.HTTP_ROUTE:
            raise ValueError("HTTP route entity has an invalid kind")
        if not isinstance(self.canonical_url, str) or not self.canonical_url.strip():
            raise ValueError("HTTP route URL must be non-blank")
        if self.canonical_url != self.canonical_url.strip():
            raise ValueError("HTTP route URL must already use its owner representation")
        origin = http_origin_from_url(self.canonical_url)
        if origin is None:
            raise ValueError("HTTP route URL must have a valid HTTP origin")
        if self.entity_id != _route_id(self.canonical_url):
            raise ValueError("HTTP route entity id does not match its URL")
        if self.origin_id != _origin_id(origin):
            raise ValueError("HTTP route origin id does not match its URL origin")


@dataclass(frozen=True)
class ApplicationServiceSourceSet:
    entity_id: str
    resource_urls: tuple[str, ...]
    origin_ids: tuple[str, ...]
    kind: ApplicationServiceEntityKind = ApplicationServiceEntityKind.SOURCE_SET

    def __post_init__(self) -> None:
        if self.kind is not ApplicationServiceEntityKind.SOURCE_SET:
            raise ValueError("source set entity has an invalid kind")
        urls = _normalised_strings(self.resource_urls)
        if not urls:
            raise ValueError("source set requires at least one resource URL")
        if urls != self.resource_urls:
            raise ValueError("source set resource URLs must be sorted and unique")
        origins = tuple(http_origin_from_url(url) for url in urls)
        if any(origin is None for origin in origins):
            raise ValueError("source set resource URL must have a valid HTTP origin")
        expected_origin_ids = tuple(
            sorted({_origin_id(origin) for origin in origins if origin is not None})
        )
        if self.origin_ids != expected_origin_ids:
            raise ValueError("source set origin ids do not match its resource URLs")
        if self.entity_id != _source_set_id(urls):
            raise ValueError("source set entity id does not match its resource URLs")


def _support_sort_key(support: ApplicationServiceRelationSupport) -> tuple[object, ...]:
    return (
        support.basis.value,
        support.source_semantic.value,
        support.source_reference.owner_kind.value,
        support.source_reference.source_id,
        support.evidence_ids,
        support.artefact_references,
        support.raw_references,
        -1 if support.http_status_code is None else support.http_status_code,
    )


@dataclass(frozen=True)
class ApplicationServiceRelation:
    relation_id: str
    relation_kind: ApplicationServiceRelationKind
    source_entity_id: str
    target_entity_id: str
    supports: tuple[ApplicationServiceRelationSupport, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.relation_kind, ApplicationServiceRelationKind):
            raise TypeError("relation kind must be typed")
        if not self.source_entity_id or not self.target_entity_id:
            raise ValueError("relation entity references must be non-blank")
        supports = tuple(sorted(set(self.supports), key=_support_sort_key))
        if not supports:
            raise ValueError("relation requires concrete support")
        if any(
            support.source_semantic not in _VALID_RELATION_SEMANTICS[self.relation_kind]
            for support in supports
        ):
            raise ValueError("relation support semantic contradicts relation kind")
        object.__setattr__(self, "supports", supports)


def _deduplicate_entities(values, *, label: str):
    by_id = {}
    for value in values:
        existing = by_id.get(value.entity_id)
        if existing is not None and existing != value:
            raise ValueError(f"duplicate {label} id has conflicting semantic content")
        by_id[value.entity_id] = value
    return tuple(sorted(by_id.values(), key=lambda value: value.entity_id))


@dataclass(frozen=True)
class ApplicationServiceComposition:
    origins: tuple[ApplicationServiceHttpOrigin, ...]
    routes: tuple[ApplicationServiceHttpRoute, ...]
    source_sets: tuple[ApplicationServiceSourceSet, ...]
    relations: tuple[ApplicationServiceRelation, ...]

    def __post_init__(self) -> None:
        origins = _deduplicate_entities(self.origins, label="origin")
        routes = _deduplicate_entities(self.routes, label="route")
        source_sets = _deduplicate_entities(self.source_sets, label="source set")

        relation_values: dict[str, ApplicationServiceRelation] = {}
        for relation in self.relations:
            existing = relation_values.get(relation.relation_id)
            if existing is None:
                relation_values[relation.relation_id] = relation
                continue
            if (
                existing.relation_kind != relation.relation_kind
                or existing.source_entity_id != relation.source_entity_id
                or existing.target_entity_id != relation.target_entity_id
            ):
                raise ValueError("duplicate relation id has conflicting semantic content")
            relation_values[relation.relation_id] = replace(
                existing,
                supports=(*existing.supports, *relation.supports),
            )
        relations = tuple(
            sorted(relation_values.values(), key=lambda value: value.relation_id)
        )

        origin_by_id = {value.entity_id: value for value in origins}
        route_by_id = {value.entity_id: value for value in routes}
        source_set_by_id = {value.entity_id: value for value in source_sets}
        entities = {**origin_by_id, **route_by_id, **source_set_by_id}
        if len(entities) != len(origins) + len(routes) + len(source_sets):
            raise ValueError("entity ids conflict across entity kinds")

        for origin in origins:
            if origin.entity_id != _origin_id(origin.origin):
                raise ValueError("HTTP origin entity id does not match its origin")
        for route in routes:
            origin = origin_by_id.get(route.origin_id)
            expected_origin = http_origin_from_url(route.canonical_url)
            if origin is None or origin.origin != expected_origin:
                raise ValueError("route origin reference does not match its URL")
        for source_set in source_sets:
            if any(origin_id not in origin_by_id for origin_id in source_set.origin_ids):
                raise ValueError("source set origin reference does not exist")
        for relation in relations:
            source = entities.get(relation.source_entity_id)
            target = entities.get(relation.target_entity_id)
            if source is None or target is None:
                raise ValueError("relation references an entity that does not exist")
            if relation.relation_kind is ApplicationServiceRelationKind.REDIRECTS_TO:
                valid_shape = (
                    source.kind is ApplicationServiceEntityKind.HTTP_ROUTE
                    and target.kind is ApplicationServiceEntityKind.HTTP_ROUTE
                )
                shape_name = "HTTP route"
            else:
                valid_shape = (
                    source.kind is ApplicationServiceEntityKind.SOURCE_SET
                    and target.kind is ApplicationServiceEntityKind.HTTP_ROUTE
                )
                shape_name = "source set to HTTP route"
            if not valid_shape:
                raise ValueError(
                    f"{relation.relation_kind.value} requires {shape_name} entities"
                )
            expected_relation_id = _relation_id(
                relation.relation_kind,
                relation.source_entity_id,
                relation.target_entity_id,
            )
            if relation.relation_id != expected_relation_id:
                raise ValueError("relation id does not match relation meaning")

        object.__setattr__(self, "origins", origins)
        object.__setattr__(self, "routes", routes)
        object.__setattr__(self, "source_sets", source_sets)
        object.__setattr__(self, "relations", relations)


class _CompositionBuilder:
    def __init__(self) -> None:
        self.origins: dict[str, ApplicationServiceHttpOrigin] = {}
        self.routes: dict[str, ApplicationServiceHttpRoute] = {}
        self.source_sets: dict[str, ApplicationServiceSourceSet] = {}
        self.relations: dict[str, ApplicationServiceRelation] = {}

    def add_origin(self, origin: HttpOrigin) -> ApplicationServiceHttpOrigin:
        entity = ApplicationServiceHttpOrigin(
            entity_id=_origin_id(origin),
            origin=origin,
        )
        self._add_entity(self.origins, entity, "origin")
        return entity

    def add_route(self, canonical_url: str) -> ApplicationServiceHttpRoute:
        origin = http_origin_from_url(canonical_url)
        if origin is None:
            raise ValueError("route evidence does not contain a valid HTTP URL")
        origin_entity = self.add_origin(origin)
        entity = ApplicationServiceHttpRoute(
            entity_id=_route_id(canonical_url),
            canonical_url=canonical_url,
            origin_id=origin_entity.entity_id,
        )
        self._add_entity(self.routes, entity, "route")
        return entity

    def add_source_set(self, resource_urls: Iterable[str]) -> ApplicationServiceSourceSet:
        urls = _normalised_strings(resource_urls)
        if not urls:
            raise ValueError("source evidence does not contain a resource URL")
        origins = []
        for url in urls:
            origin = http_origin_from_url(url)
            if origin is None:
                raise ValueError("source evidence contains an invalid HTTP URL")
            origins.append(self.add_origin(origin))
        entity = ApplicationServiceSourceSet(
            entity_id=_source_set_id(urls),
            resource_urls=urls,
            origin_ids=tuple(sorted({origin.entity_id for origin in origins})),
        )
        self._add_entity(self.source_sets, entity, "source set")
        return entity

    def add_relation(
        self,
        relation_kind: ApplicationServiceRelationKind,
        source_entity_id: str,
        target_entity_id: str,
        support: ApplicationServiceRelationSupport,
    ) -> None:
        relation_id = _relation_id(
            relation_kind,
            source_entity_id,
            target_entity_id,
        )
        existing = self.relations.get(relation_id)
        supports = (support,) if existing is None else (*existing.supports, support)
        self.relations[relation_id] = ApplicationServiceRelation(
            relation_id=relation_id,
            relation_kind=relation_kind,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            supports=supports,
        )

    @staticmethod
    def _add_entity(store, entity, label: str) -> None:
        existing = store.get(entity.entity_id)
        if existing is not None and existing != entity:
            raise ValueError(f"duplicate {label} id has conflicting semantic content")
        store[entity.entity_id] = entity

    def finish(self) -> ApplicationServiceComposition:
        return ApplicationServiceComposition(
            origins=tuple(self.origins.values()),
            routes=tuple(self.routes.values()),
            source_sets=tuple(self.source_sets.values()),
            relations=tuple(self.relations.values()),
        )


def _support(
    *,
    basis: ApplicationServiceSupportBasis,
    semantic: ApplicationServiceSourceSemantic,
    owner: ApplicationServiceSourceOwnerKind,
    source_id: str,
    evidence_ids: tuple[str, ...],
    artefact_references: tuple[str, ...] = (),
    raw_references: tuple[str, ...] = (),
    status_code: int | None = None,
) -> ApplicationServiceRelationSupport:
    return ApplicationServiceRelationSupport(
        basis=basis,
        source_semantic=semantic,
        source_reference=ApplicationServiceSourceReference(
            owner_kind=owner,
            source_id=source_id,
        ),
        evidence_ids=evidence_ids,
        artefact_references=artefact_references,
        raw_references=raw_references,
        http_status_code=status_code,
    )


def _add_redirect(builder: _CompositionBuilder, edge: HttpRouteRelationshipEdge) -> None:
    if not isinstance(edge, HttpRouteRelationshipEdge):
        raise TypeError("redirect evidence must be an HttpRouteRelationshipEdge")
    if edge.edge_type != "redirect":
        raise ValueError("redirect adapter accepts only redirect relationship edges")
    source_url = canonical_relationship_url(edge.source_url)
    target_url = canonical_relationship_url(edge.target_url)
    if not source_url or not target_url:
        raise ValueError("redirect relationship contains an invalid HTTP route")
    source = builder.add_route(source_url)
    target = builder.add_route(target_url)
    source_id = _semantic_id(
        "HTTP-ROUTE-EDGE",
        edge.edge_type,
        source_url,
        target_url,
        edge.status_code if edge.status_code is not None else "",
        *_normalised_strings(edge.raw_references),
    )
    builder.add_relation(
        ApplicationServiceRelationKind.REDIRECTS_TO,
        source.entity_id,
        target.entity_id,
        _support(
            basis=ApplicationServiceSupportBasis.DIRECT_OBSERVATION,
            semantic=ApplicationServiceSourceSemantic.HTTP_REDIRECT,
            owner=ApplicationServiceSourceOwnerKind.HTTP_ROUTE_RELATIONSHIP_EDGE,
            source_id=source_id,
            evidence_ids=edge.evidence_ids,
            artefact_references=edge.artefact_references,
            raw_references=edge.raw_references,
            status_code=edge.status_code,
        ),
    )


def _metadata_source_id(item: DeepMetadataCollectedItem) -> str:
    return _semantic_id(
        "DEEP-METADATA-ITEM",
        item.url,
        item.final_url,
        item.method.upper(),
        item.body_sha256,
    )


def _add_metadata_item(
    builder: _CompositionBuilder,
    item: DeepMetadataCollectedItem,
) -> None:
    if not isinstance(item, DeepMetadataCollectedItem):
        raise TypeError("metadata collection contains an invalid collected item")
    if not item.sitemap_route_references:
        return
    source = builder.add_source_set((item.url,))
    support = _support(
        basis=ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        semantic=ApplicationServiceSourceSemantic.SITEMAP_DECLARATION,
        owner=ApplicationServiceSourceOwnerKind.DEEP_METADATA_COLLECTED_ITEM,
        source_id=_metadata_source_id(item),
        evidence_ids=item.evidence_ids,
    )
    for route_url in item.sitemap_route_references:
        if not isinstance(route_url, str) or not route_url.strip():
            raise ValueError("sitemap route reference must be non-blank")
        route = builder.add_route(route_url)
        builder.add_relation(
            ApplicationServiceRelationKind.DECLARES_ROUTE,
            source.entity_id,
            route.entity_id,
            support,
        )


def _add_html_route(
    builder: _CompositionBuilder,
    route: DeepHtmlRouteReference,
) -> None:
    if not isinstance(route, DeepHtmlRouteReference):
        raise TypeError("HTML extraction contains an invalid route reference")
    if not route.safe_resolved_url:
        raise ValueError("HTML route reference lacks a safe resolved URL")
    source = builder.add_source_set(route.source_request_urls)
    target = builder.add_route(route.safe_resolved_url)
    builder.add_relation(
        ApplicationServiceRelationKind.REFERENCES_ROUTE,
        source.entity_id,
        target.entity_id,
        _support(
            basis=ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
            semantic=ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE,
            owner=ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE,
            source_id=route.route_id,
            evidence_ids=route.evidence_ids,
        ),
    )


_JAVASCRIPT_SEMANTICS = {
    "request_call": ApplicationServiceSourceSemantic.JAVASCRIPT_REQUEST_CALL,
    "route_configuration": (
        ApplicationServiceSourceSemantic.JAVASCRIPT_ROUTE_CONFIGURATION
    ),
}


def _add_javascript_candidate(
    builder: _CompositionBuilder,
    candidate: DeepJavaScriptRouteCandidate,
) -> None:
    if not isinstance(candidate, DeepJavaScriptRouteCandidate):
        raise TypeError("JavaScript extraction contains an invalid route candidate")
    if not candidate.safe_resolved_url:
        return
    accepted_semantics = tuple(
        _JAVASCRIPT_SEMANTICS[context]
        for context in candidate.semantic_contexts
        if context in _JAVASCRIPT_SEMANTICS
    )
    if not accepted_semantics:
        return
    source = builder.add_source_set(candidate.source_request_urls)
    target = builder.add_route(candidate.safe_resolved_url)
    for semantic in accepted_semantics:
        builder.add_relation(
            ApplicationServiceRelationKind.REFERENCES_ROUTE,
            source.entity_id,
            target.entity_id,
            _support(
                basis=ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
                semantic=semantic,
                owner=(
                    ApplicationServiceSourceOwnerKind.DEEP_JAVASCRIPT_ROUTE_CANDIDATE
                ),
                source_id=candidate.candidate_id,
                evidence_ids=candidate.evidence_ids,
            ),
        )


def build_application_service_composition(
    *,
    redirect_edges: tuple[HttpRouteRelationshipEdge, ...] = (),
    metadata_collection: DeepMetadataCollectionResult | None = None,
    html_extraction: DeepHtmlRouteExtractionResult | None = None,
    javascript_extraction: DeepJavaScriptRouteExtractionResult | None = None,
) -> ApplicationServiceComposition:
    """Compose deterministic semantic relationships from retained typed evidence."""

    builder = _CompositionBuilder()
    for edge in redirect_edges:
        _add_redirect(builder, edge)
    if metadata_collection is not None:
        if not isinstance(metadata_collection, DeepMetadataCollectionResult):
            raise TypeError("metadata collection must use its typed result model")
        for item in metadata_collection.collected:
            _add_metadata_item(builder, item)
    if html_extraction is not None:
        if not isinstance(html_extraction, DeepHtmlRouteExtractionResult):
            raise TypeError("HTML extraction must use its typed result model")
        for route in html_extraction.routes:
            _add_html_route(builder, route)
    if javascript_extraction is not None:
        if not isinstance(
            javascript_extraction,
            DeepJavaScriptRouteExtractionResult,
        ):
            raise TypeError("JavaScript extraction must use its typed result model")
        for candidate in javascript_extraction.candidates:
            _add_javascript_candidate(builder, candidate)
    return builder.finish()
