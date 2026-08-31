"""Immutable application/service model composed from A1 and A2 evidence.

This module is an offline semantic composition layer.  It does not collect
evidence, grant authority, schedule work, execute requests, or own
persistence and presentation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256

from bugslyce.recon.application_service_composition import (
    ApplicationServiceComposition,
    ApplicationServiceEntityKind,
    ApplicationServiceRelation,
    ApplicationServiceRelationKind,
    ApplicationServiceRelationSupport,
    ApplicationServiceSourceSemantic,
    ApplicationServiceSupportBasis,
)
from bugslyce.recon.documentation_assertions import (
    DocumentedRealtimeEndpoint,
    DocumentedServiceBaseURL,
    DocumentationAssertion,
    DocumentationAssertionExtractionResult,
    DocumentationAssertionKind,
    DocumentationAssertionSourceReference,
    DocumentationAssertionSupport,
)


class ApplicationServiceModelEntityKind(Enum):
    DOCUMENTATION_RESOURCE = "documentation_resource"
    DOCUMENTED_HTTP_SERVICE = "documented_http_service"
    DOCUMENTED_REALTIME_ENDPOINT = "documented_realtime_endpoint"
    HTTP_ORIGIN = "http_origin"


class ApplicationServiceModelRelationKind(Enum):
    DESCRIBES_SERVICE = "describes_service"
    DOCUMENTS_REALTIME_ENDPOINT = "documents_realtime_endpoint"
    CORRESPONDS_TO_OBSERVED_ORIGIN = "corresponds_to_observed_origin"


class ApplicationServiceModelSupportBasis(Enum):
    DIRECT_DOCUMENTATION = "direct_documentation"
    DETERMINISTIC_DERIVATION = "deterministic_derivation"


def _require_non_blank(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-blank")
    return value.strip()


def _semantic_id(prefix: str, *parts: object) -> str:
    """Return a stable internal semantic ID without defining persistence."""

    digest = sha256()
    for part in parts:
        value = part.value if isinstance(part, Enum) else str(part)
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{prefix}-{digest.hexdigest()}"


def _service_id(value: DocumentedServiceBaseURL) -> str:
    return _semantic_id("APP-MODEL-SERVICE", value.canonical_url)


def _realtime_endpoint_id(value: DocumentedRealtimeEndpoint) -> str:
    return _semantic_id("APP-MODEL-REALTIME", value.canonical_url)


def _relation_id(
    relation_kind: ApplicationServiceModelRelationKind,
    source: ApplicationServiceModelEntityReference,
    target: ApplicationServiceModelEntityReference,
) -> str:
    return _semantic_id(
        "APP-MODEL-RELATION",
        relation_kind,
        source.entity_kind,
        source.entity_id,
        target.entity_kind,
        target.entity_id,
    )


@dataclass(frozen=True)
class ApplicationServiceModelEntityReference:
    entity_kind: ApplicationServiceModelEntityKind
    entity_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.entity_kind, ApplicationServiceModelEntityKind):
            raise ValueError("model entity reference kind must be typed")
        object.__setattr__(
            self,
            "entity_id",
            _require_non_blank(self.entity_id, label="model entity reference id"),
        )


@dataclass(frozen=True)
class ApplicationServiceDocumentationResource:
    entity_id: str
    source_reference: DocumentationAssertionSourceReference
    kind: ApplicationServiceModelEntityKind = (
        ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE
    )

    def __post_init__(self) -> None:
        if self.kind is not ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE:
            raise ValueError("documentation resource has an invalid entity kind")
        if not isinstance(
            self.source_reference,
            DocumentationAssertionSourceReference,
        ):
            raise ValueError("documentation resource source reference must be typed")
        if self.entity_id != self.source_reference.source_id:
            raise ValueError(
                "documentation resource id does not match its source reference"
            )


@dataclass(frozen=True)
class ApplicationServiceDocumentedHttpService:
    entity_id: str
    value: DocumentedServiceBaseURL
    kind: ApplicationServiceModelEntityKind = (
        ApplicationServiceModelEntityKind.DOCUMENTED_HTTP_SERVICE
    )

    def __post_init__(self) -> None:
        if self.kind is not ApplicationServiceModelEntityKind.DOCUMENTED_HTTP_SERVICE:
            raise ValueError("documented HTTP service has an invalid entity kind")
        if not isinstance(self.value, DocumentedServiceBaseURL):
            raise ValueError("documented HTTP service value must be typed")
        if self.entity_id != _service_id(self.value):
            raise ValueError(
                "documented HTTP service id does not match its canonical URL"
            )


@dataclass(frozen=True)
class ApplicationServiceDocumentedRealtimeEndpoint:
    entity_id: str
    value: DocumentedRealtimeEndpoint
    kind: ApplicationServiceModelEntityKind = (
        ApplicationServiceModelEntityKind.DOCUMENTED_REALTIME_ENDPOINT
    )

    def __post_init__(self) -> None:
        if (
            self.kind
            is not ApplicationServiceModelEntityKind.DOCUMENTED_REALTIME_ENDPOINT
        ):
            raise ValueError("documented realtime endpoint has an invalid entity kind")
        if not isinstance(self.value, DocumentedRealtimeEndpoint):
            raise ValueError("documented realtime endpoint value must be typed")
        if self.entity_id != _realtime_endpoint_id(self.value):
            raise ValueError(
                "documented realtime endpoint id does not match its canonical URL"
            )


@dataclass(frozen=True)
class ApplicationServiceDocumentationRelationSupport:
    basis: ApplicationServiceModelSupportBasis
    assertion_id: str
    assertion_support: DocumentationAssertionSupport

    def __post_init__(self) -> None:
        if self.basis is not ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION:
            raise ValueError(
                "documentation relation support must be direct documentation"
            )
        object.__setattr__(
            self,
            "assertion_id",
            _require_non_blank(
                self.assertion_id,
                label="documentation relation assertion id",
            ),
        )
        if not isinstance(self.assertion_support, DocumentationAssertionSupport):
            raise ValueError("documentation relation support must retain typed support")


@dataclass(frozen=True)
class ApplicationServiceObservedOriginCorrespondenceSupport:
    basis: ApplicationServiceModelSupportBasis
    documentation_assertion_id: str
    documentation_support: DocumentationAssertionSupport
    observed_relation_id: str
    observation_support: ApplicationServiceRelationSupport

    def __post_init__(self) -> None:
        if (
            self.basis
            is not ApplicationServiceModelSupportBasis.DETERMINISTIC_DERIVATION
        ):
            raise ValueError(
                "observed-origin correspondence must be deterministic derivation"
            )
        object.__setattr__(
            self,
            "documentation_assertion_id",
            _require_non_blank(
                self.documentation_assertion_id,
                label="correspondence documentation assertion id",
            ),
        )
        object.__setattr__(
            self,
            "observed_relation_id",
            _require_non_blank(
                self.observed_relation_id,
                label="correspondence observed relation id",
            ),
        )
        if not isinstance(self.documentation_support, DocumentationAssertionSupport):
            raise ValueError("correspondence documentation support must be typed")
        if not isinstance(self.observation_support, ApplicationServiceRelationSupport):
            raise ValueError("correspondence observation support must be typed")
        if (
            self.observation_support.basis
            is not ApplicationServiceSupportBasis.DIRECT_OBSERVATION
        ):
            raise ValueError(
                "correspondence observation support must be direct observation"
            )


ApplicationServiceModelRelationSupport = (
    ApplicationServiceDocumentationRelationSupport
    | ApplicationServiceObservedOriginCorrespondenceSupport
)


_RELATION_RULES = {
    ApplicationServiceModelRelationKind.DESCRIBES_SERVICE: (
        ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION,
        ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE,
        ApplicationServiceModelEntityKind.DOCUMENTED_HTTP_SERVICE,
        ApplicationServiceDocumentationRelationSupport,
    ),
    ApplicationServiceModelRelationKind.DOCUMENTS_REALTIME_ENDPOINT: (
        ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION,
        ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE,
        ApplicationServiceModelEntityKind.DOCUMENTED_REALTIME_ENDPOINT,
        ApplicationServiceDocumentationRelationSupport,
    ),
    ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN: (
        ApplicationServiceModelSupportBasis.DETERMINISTIC_DERIVATION,
        ApplicationServiceModelEntityKind.DOCUMENTED_HTTP_SERVICE,
        ApplicationServiceModelEntityKind.HTTP_ORIGIN,
        ApplicationServiceObservedOriginCorrespondenceSupport,
    ),
}


def _documentation_support_sort_key(
    support: DocumentationAssertionSupport,
) -> tuple[object, ...]:
    return (
        support.source_reference.source_id,
        support.start_offset,
        support.end_offset,
        support.structural_context.value,
        support.structural_locator,
        support.matched_excerpt,
    )


def _observation_support_sort_key(
    support: ApplicationServiceRelationSupport,
) -> tuple[object, ...]:
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


def _relation_support_sort_key(
    support: ApplicationServiceModelRelationSupport,
) -> tuple[object, ...]:
    if isinstance(support, ApplicationServiceDocumentationRelationSupport):
        return (
            0,
            support.basis.value,
            support.assertion_id,
            _documentation_support_sort_key(support.assertion_support),
        )
    return (
        1,
        support.basis.value,
        support.documentation_assertion_id,
        _documentation_support_sort_key(support.documentation_support),
        support.observed_relation_id,
        _observation_support_sort_key(support.observation_support),
    )


@dataclass(frozen=True)
class ApplicationServiceModelRelation:
    relation_id: str
    relation_kind: ApplicationServiceModelRelationKind
    basis: ApplicationServiceModelSupportBasis
    source: ApplicationServiceModelEntityReference
    target: ApplicationServiceModelEntityReference
    supports: tuple[ApplicationServiceModelRelationSupport, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.relation_kind, ApplicationServiceModelRelationKind):
            raise ValueError("model relation kind must be typed")
        if not isinstance(self.basis, ApplicationServiceModelSupportBasis):
            raise ValueError("model relation support basis must be typed")
        if not isinstance(self.source, ApplicationServiceModelEntityReference):
            raise ValueError("model relation source reference must be typed")
        if not isinstance(self.target, ApplicationServiceModelEntityReference):
            raise ValueError("model relation target reference must be typed")

        expected_basis, source_kind, target_kind, support_type = _RELATION_RULES[
            self.relation_kind
        ]
        if (
            self.basis is not expected_basis
            or self.source.entity_kind is not source_kind
            or self.target.entity_kind is not target_kind
        ):
            raise ValueError("model relation kind, basis, and entity shape contradict")

        supports = tuple(sorted(set(self.supports), key=_relation_support_sort_key))
        if not supports:
            raise ValueError("model relation requires support")
        if any(not isinstance(support, support_type) for support in supports):
            raise ValueError("model relation support type contradicts relation kind")
        object.__setattr__(self, "supports", supports)

        if self.relation_id != _relation_id(
            self.relation_kind,
            self.source,
            self.target,
        ):
            raise ValueError("model relation id does not match relation meaning")


def _deduplicate_entities(values, *, label: str):
    by_id = {}
    for value in values:
        existing = by_id.get(value.entity_id)
        if existing is not None and existing != value:
            raise ValueError(f"duplicate {label} id has conflicting semantic content")
        by_id[value.entity_id] = value
    return tuple(sorted(by_id.values(), key=lambda value: value.entity_id))


def _canonical_relations(
    values: tuple[ApplicationServiceModelRelation, ...],
) -> tuple[ApplicationServiceModelRelation, ...]:
    by_id: dict[str, ApplicationServiceModelRelation] = {}
    for relation in values:
        if not isinstance(relation, ApplicationServiceModelRelation):
            raise ValueError("model relation must be typed")
        existing = by_id.get(relation.relation_id)
        if existing is None:
            by_id[relation.relation_id] = relation
            continue
        if (
            existing.relation_kind is not relation.relation_kind
            or existing.basis is not relation.basis
            or existing.source != relation.source
            or existing.target != relation.target
        ):
            raise ValueError("duplicate relation id has conflicting semantic content")
        by_id[relation.relation_id] = replace(
            existing,
            supports=(*existing.supports, *relation.supports),
        )
    return tuple(sorted(by_id.values(), key=lambda value: value.relation_id))


def _assertions_for_id(
    assertions: tuple[DocumentationAssertion, ...],
    assertion_id: str,
) -> tuple[DocumentationAssertion, ...]:
    return tuple(
        assertion
        for assertion in assertions
        if assertion.assertion_id == assertion_id
    )


def _resolve_assertion(
    assertions: tuple[DocumentationAssertion, ...],
    *,
    assertion_id: str,
    support: DocumentationAssertionSupport,
) -> DocumentationAssertion:
    candidates = _assertions_for_id(assertions, assertion_id)
    if not candidates:
        raise ValueError("relation assertion id is not present in documentation")
    matching = tuple(
        assertion for assertion in candidates if support in assertion.supports
    )
    if not matching:
        raise ValueError("relation assertion support does not belong to assertion")
    first = matching[0]
    if any(
        assertion.kind is not first.kind or assertion.value != first.value
        for assertion in matching[1:]
    ):
        raise ValueError("duplicate assertion id has conflicting semantic content")
    return first


def _validate_documentation_relation(
    relation: ApplicationServiceModelRelation,
    *,
    assertions: tuple[DocumentationAssertion, ...],
    resources: dict[str, ApplicationServiceDocumentationResource],
    services: dict[str, ApplicationServiceDocumentedHttpService],
    realtime_endpoints: dict[
        str,
        ApplicationServiceDocumentedRealtimeEndpoint,
    ],
) -> None:
    resource = resources.get(relation.source.entity_id)
    if resource is None:
        raise ValueError("documentation relation source entity does not exist")

    if relation.relation_kind is ApplicationServiceModelRelationKind.DESCRIBES_SERVICE:
        target = services.get(relation.target.entity_id)
        expected_kind = DocumentationAssertionKind.SERVICE_BASE_URL
    else:
        target = realtime_endpoints.get(relation.target.entity_id)
        expected_kind = DocumentationAssertionKind.REALTIME_ENDPOINT
    if target is None:
        raise ValueError("documentation relation target entity does not exist")

    for support in relation.supports:
        if not isinstance(support, ApplicationServiceDocumentationRelationSupport):
            raise ValueError("documentation relation support type is invalid")
        assertion = _resolve_assertion(
            assertions,
            assertion_id=support.assertion_id,
            support=support.assertion_support,
        )
        if assertion.kind is not expected_kind:
            raise ValueError("documentation assertion kind contradicts relation kind")
        if assertion.value != target.value:
            raise ValueError("documentation assertion value contradicts target entity")
        if (
            resource.source_reference
            != support.assertion_support.source_reference
        ):
            raise ValueError(
                "documentation resource and assertion source reference contradict"
            )


def _validate_correspondence_relation(
    relation: ApplicationServiceModelRelation,
    *,
    application_composition: ApplicationServiceComposition,
    assertions: tuple[DocumentationAssertion, ...],
    resources: dict[str, ApplicationServiceDocumentationResource],
    services: dict[str, ApplicationServiceDocumentedHttpService],
) -> None:
    service = services.get(relation.source.entity_id)
    if service is None:
        raise ValueError("correspondence service entity does not exist")
    origin = next(
        (
            candidate
            for candidate in application_composition.origins
            if candidate.entity_id == relation.target.entity_id
        ),
        None,
    )
    if origin is None:
        raise ValueError("correspondence HTTP origin entity does not exist")
    if service.value.origin != origin.origin:
        raise ValueError("correspondence service and HTTP origin do not match")

    relation_by_id = {
        candidate.relation_id: candidate
        for candidate in application_composition.relations
    }
    route_by_id = {
        candidate.entity_id: candidate
        for candidate in application_composition.routes
    }

    for support in relation.supports:
        if not isinstance(
            support,
            ApplicationServiceObservedOriginCorrespondenceSupport,
        ):
            raise ValueError("correspondence support type is invalid")
        assertion = _resolve_assertion(
            assertions,
            assertion_id=support.documentation_assertion_id,
            support=support.documentation_support,
        )
        if assertion.kind is not DocumentationAssertionKind.SERVICE_BASE_URL:
            raise ValueError(
                "correspondence documentation assertion kind is not service base URL"
            )
        if assertion.value != service.value:
            raise ValueError(
                "correspondence documentation assertion and service contradict"
            )
        resource = resources.get(
            support.documentation_support.source_reference.source_id
        )
        if (
            resource is None
            or resource.source_reference
            != support.documentation_support.source_reference
        ):
            raise ValueError(
                "correspondence documentation source reference is not retained"
            )

        observed_relation = relation_by_id.get(support.observed_relation_id)
        if observed_relation is None:
            raise ValueError("correspondence observed relation does not exist")
        if support.observation_support not in observed_relation.supports:
            raise ValueError(
                "correspondence observation support does not belong to relation"
            )
        if (
            support.observation_support.basis
            is not ApplicationServiceSupportBasis.DIRECT_OBSERVATION
        ):
            raise ValueError(
                "correspondence observation support is not direct observation"
            )
        if (
            observed_relation.relation_kind
            is not ApplicationServiceRelationKind.REDIRECTS_TO
            or support.observation_support.source_semantic
            is not ApplicationServiceSourceSemantic.HTTP_REDIRECT
        ):
            raise ValueError(
                "correspondence observation is not an observed HTTP redirect"
            )
        source_route = route_by_id.get(observed_relation.source_entity_id)
        if (
            source_route is None
            or source_route.kind is not ApplicationServiceEntityKind.HTTP_ROUTE
        ):
            raise ValueError(
                "correspondence observed relation source is not an HTTP route"
            )
        if source_route.origin_id != origin.entity_id:
            raise ValueError(
                "correspondence observed source route origin does not match target"
            )


@dataclass(frozen=True)
class ApplicationServiceModel:
    application_composition: ApplicationServiceComposition
    documentation_assertions: DocumentationAssertionExtractionResult
    documentation_resources: tuple[ApplicationServiceDocumentationResource, ...]
    documented_http_services: tuple[ApplicationServiceDocumentedHttpService, ...]
    documented_realtime_endpoints: tuple[
        ApplicationServiceDocumentedRealtimeEndpoint,
        ...,
    ]
    relations: tuple[ApplicationServiceModelRelation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.application_composition, ApplicationServiceComposition):
            raise ValueError("application composition must be typed")
        if not isinstance(
            self.documentation_assertions,
            DocumentationAssertionExtractionResult,
        ):
            raise ValueError("documentation assertions must be typed")

        resources = _deduplicate_entities(
            self.documentation_resources,
            label="documentation resource",
        )
        services = _deduplicate_entities(
            self.documented_http_services,
            label="documented HTTP service",
        )
        realtime_endpoints = _deduplicate_entities(
            self.documented_realtime_endpoints,
            label="documented realtime endpoint",
        )
        relations = _canonical_relations(self.relations)

        resource_by_id = {value.entity_id: value for value in resources}
        service_by_id = {value.entity_id: value for value in services}
        realtime_by_id = {value.entity_id: value for value in realtime_endpoints}
        origin_by_id = {
            value.entity_id: value
            for value in self.application_composition.origins
        }

        for relation in relations:
            if (
                relation.relation_kind
                is ApplicationServiceModelRelationKind.DESCRIBES_SERVICE
                or relation.relation_kind
                is ApplicationServiceModelRelationKind.DOCUMENTS_REALTIME_ENDPOINT
            ):
                _validate_documentation_relation(
                    relation,
                    assertions=self.documentation_assertions.assertions,
                    resources=resource_by_id,
                    services=service_by_id,
                    realtime_endpoints=realtime_by_id,
                )
            else:
                if relation.target.entity_id not in origin_by_id:
                    raise ValueError(
                        "correspondence references an HTTP origin that does not exist"
                    )
                _validate_correspondence_relation(
                    relation,
                    application_composition=self.application_composition,
                    assertions=self.documentation_assertions.assertions,
                    resources=resource_by_id,
                    services=service_by_id,
                )

        object.__setattr__(self, "documentation_resources", resources)
        object.__setattr__(self, "documented_http_services", services)
        object.__setattr__(
            self,
            "documented_realtime_endpoints",
            realtime_endpoints,
        )
        object.__setattr__(self, "relations", relations)


def _entity_reference(
    entity_kind: ApplicationServiceModelEntityKind,
    entity_id: str,
) -> ApplicationServiceModelEntityReference:
    return ApplicationServiceModelEntityReference(
        entity_kind=entity_kind,
        entity_id=entity_id,
    )


def _model_relation(
    *,
    relation_kind: ApplicationServiceModelRelationKind,
    basis: ApplicationServiceModelSupportBasis,
    source: ApplicationServiceModelEntityReference,
    target: ApplicationServiceModelEntityReference,
    support: ApplicationServiceModelRelationSupport,
) -> ApplicationServiceModelRelation:
    return ApplicationServiceModelRelation(
        relation_id=_relation_id(relation_kind, source, target),
        relation_kind=relation_kind,
        basis=basis,
        source=source,
        target=target,
        supports=(support,),
    )


def _documentation_resource(
    support: DocumentationAssertionSupport,
) -> ApplicationServiceDocumentationResource:
    return ApplicationServiceDocumentationResource(
        entity_id=support.source_reference.source_id,
        source_reference=support.source_reference,
    )


def _observed_redirect_supports_by_source_origin(
    composition: ApplicationServiceComposition,
) -> dict[str, tuple[tuple[ApplicationServiceRelation, ApplicationServiceRelationSupport], ...]]:
    route_by_id = {route.entity_id: route for route in composition.routes}
    values: dict[
        str,
        list[tuple[ApplicationServiceRelation, ApplicationServiceRelationSupport]],
    ] = {}
    for relation in composition.relations:
        if relation.relation_kind is not ApplicationServiceRelationKind.REDIRECTS_TO:
            continue
        source_route = route_by_id.get(relation.source_entity_id)
        if (
            source_route is None
            or source_route.kind is not ApplicationServiceEntityKind.HTTP_ROUTE
        ):
            continue
        for support in relation.supports:
            if (
                support.basis
                is ApplicationServiceSupportBasis.DIRECT_OBSERVATION
                and support.source_semantic
                is ApplicationServiceSourceSemantic.HTTP_REDIRECT
            ):
                values.setdefault(source_route.origin_id, []).append(
                    (relation, support)
                )
    return {
        origin_id: tuple(
            sorted(
                supports,
                key=lambda value: (
                    value[0].relation_id,
                    _observation_support_sort_key(value[1]),
                ),
            )
        )
        for origin_id, supports in values.items()
    }


def build_application_service_model(
    *,
    application_composition: ApplicationServiceComposition,
    documentation_assertions: DocumentationAssertionExtractionResult,
) -> ApplicationServiceModel:
    """Compose immutable A3 entities and relations from exact A1/A2 results."""

    if not isinstance(application_composition, ApplicationServiceComposition):
        raise ValueError("application composition must be typed")
    if not isinstance(
        documentation_assertions,
        DocumentationAssertionExtractionResult,
    ):
        raise ValueError("documentation assertions must be typed")

    resources: list[ApplicationServiceDocumentationResource] = []
    services: list[ApplicationServiceDocumentedHttpService] = []
    realtime_endpoints: list[
        ApplicationServiceDocumentedRealtimeEndpoint
    ] = []
    relations: list[ApplicationServiceModelRelation] = []

    observed_by_origin = _observed_redirect_supports_by_source_origin(
        application_composition
    )
    origins_by_value = {}
    for origin in application_composition.origins:
        origins_by_value.setdefault(origin.origin, []).append(origin)

    for assertion in documentation_assertions.assertions:
        if assertion.kind is DocumentationAssertionKind.SERVICE_BASE_URL:
            if not isinstance(assertion.value, DocumentedServiceBaseURL):
                raise ValueError(
                    "service base assertion does not retain a typed service value"
                )
            service = ApplicationServiceDocumentedHttpService(
                entity_id=_service_id(assertion.value),
                value=assertion.value,
            )
            services.append(service)
            service_reference = _entity_reference(
                ApplicationServiceModelEntityKind.DOCUMENTED_HTTP_SERVICE,
                service.entity_id,
            )
            for documentation_support in assertion.supports:
                resource = _documentation_resource(documentation_support)
                resources.append(resource)
                relations.append(
                    _model_relation(
                        relation_kind=(
                            ApplicationServiceModelRelationKind.DESCRIBES_SERVICE
                        ),
                        basis=(
                            ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
                        ),
                        source=_entity_reference(
                            ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE,
                            resource.entity_id,
                        ),
                        target=service_reference,
                        support=ApplicationServiceDocumentationRelationSupport(
                            basis=(
                                ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
                            ),
                            assertion_id=assertion.assertion_id,
                            assertion_support=documentation_support,
                        ),
                    )
                )

                for origin in origins_by_value.get(assertion.value.origin, ()):
                    for observed_relation, observation_support in observed_by_origin.get(
                        origin.entity_id,
                        (),
                    ):
                        relations.append(
                            _model_relation(
                                relation_kind=(
                                    ApplicationServiceModelRelationKind
                                    .CORRESPONDS_TO_OBSERVED_ORIGIN
                                ),
                                basis=(
                                    ApplicationServiceModelSupportBasis
                                    .DETERMINISTIC_DERIVATION
                                ),
                                source=service_reference,
                                target=_entity_reference(
                                    ApplicationServiceModelEntityKind.HTTP_ORIGIN,
                                    origin.entity_id,
                                ),
                                support=(
                                    ApplicationServiceObservedOriginCorrespondenceSupport(
                                        basis=(
                                            ApplicationServiceModelSupportBasis
                                            .DETERMINISTIC_DERIVATION
                                        ),
                                        documentation_assertion_id=(
                                            assertion.assertion_id
                                        ),
                                        documentation_support=documentation_support,
                                        observed_relation_id=(
                                            observed_relation.relation_id
                                        ),
                                        observation_support=observation_support,
                                    )
                                ),
                            )
                        )

        elif assertion.kind is DocumentationAssertionKind.REALTIME_ENDPOINT:
            if not isinstance(assertion.value, DocumentedRealtimeEndpoint):
                raise ValueError(
                    "realtime assertion does not retain a typed realtime value"
                )
            endpoint = ApplicationServiceDocumentedRealtimeEndpoint(
                entity_id=_realtime_endpoint_id(assertion.value),
                value=assertion.value,
            )
            realtime_endpoints.append(endpoint)
            endpoint_reference = _entity_reference(
                ApplicationServiceModelEntityKind.DOCUMENTED_REALTIME_ENDPOINT,
                endpoint.entity_id,
            )
            for documentation_support in assertion.supports:
                resource = _documentation_resource(documentation_support)
                resources.append(resource)
                relations.append(
                    _model_relation(
                        relation_kind=(
                            ApplicationServiceModelRelationKind
                            .DOCUMENTS_REALTIME_ENDPOINT
                        ),
                        basis=(
                            ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
                        ),
                        source=_entity_reference(
                            ApplicationServiceModelEntityKind.DOCUMENTATION_RESOURCE,
                            resource.entity_id,
                        ),
                        target=endpoint_reference,
                        support=ApplicationServiceDocumentationRelationSupport(
                            basis=(
                                ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
                            ),
                            assertion_id=assertion.assertion_id,
                            assertion_support=documentation_support,
                        ),
                    )
                )

    return ApplicationServiceModel(
        application_composition=application_composition,
        documentation_assertions=documentation_assertions,
        documentation_resources=tuple(resources),
        documented_http_services=tuple(services),
        documented_realtime_endpoints=tuple(realtime_endpoints),
        relations=tuple(relations),
    )
