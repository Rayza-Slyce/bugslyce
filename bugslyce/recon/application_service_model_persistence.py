"""Canonical schema-1 persistence for the application/service model."""

from __future__ import annotations

from enum import Enum
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import TypeVar

from bugslyce.recon.application_service_composition import (
    ApplicationServiceComposition,
    ApplicationServiceEntityKind,
    ApplicationServiceHttpOrigin,
    ApplicationServiceHttpRoute,
    ApplicationServiceRelation,
    ApplicationServiceRelationKind,
    ApplicationServiceRelationSupport,
    ApplicationServiceSourceOwnerKind,
    ApplicationServiceSourceReference,
    ApplicationServiceSourceSemantic,
    ApplicationServiceSourceSet,
    ApplicationServiceSupportBasis,
)
from bugslyce.recon.application_service_model import (
    ApplicationServiceDocumentationRelationSupport,
    ApplicationServiceDocumentationResource,
    ApplicationServiceDocumentedHttpService,
    ApplicationServiceDocumentedRealtimeEndpoint,
    ApplicationServiceModel,
    ApplicationServiceModelEntityKind,
    ApplicationServiceModelEntityReference,
    ApplicationServiceModelRelation,
    ApplicationServiceModelRelationKind,
    ApplicationServiceModelSupportBasis,
    ApplicationServiceObservedOriginCorrespondenceSupport,
)
from bugslyce.recon.documentation_assertions import (
    DocumentedAuthentication,
    DocumentedHttpOperation,
    DocumentedOAuthScope,
    DocumentedRealtimeEndpoint,
    DocumentedRequiredHeader,
    DocumentedServiceBaseURL,
    DocumentationAssertion,
    DocumentationAssertionExtractionResult,
    DocumentationAssertionKind,
    DocumentationAssertionSourceReference,
    DocumentationAssertionSupport,
    DocumentationAuthenticationScheme,
    DocumentationSourceOwnerKind,
    DocumentationSourceSkip,
    DocumentationSourceSkipReason,
    DocumentationStructuralContext,
)
from bugslyce.recon.http_origin import HttpOrigin


APPLICATION_SERVICE_MODEL_FILENAME = "application_service_model.json"

_SCHEMA_VERSION = 1
_GENERATED_BY = "bugslyce.application_service_model"
_MAX_FILE_BYTES = 16 * 1024 * 1024
_EnumT = TypeVar("_EnumT", bound=Enum)


def _mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has missing or unexpected fields")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _enum(enum_type: type[_EnumT], value: object, label: str) -> _EnumT:
    try:
        return enum_type(_text(value, label))
    except ValueError as exc:
        raise ValueError(f"{label} has an unsupported value") from exc


def _texts(value: object, label: str) -> tuple[str, ...]:
    return tuple(_text(item, f"{label} item") for item in _array(value, label))


def _origin_to_dict(value: HttpOrigin) -> dict[str, object]:
    return {
        "scheme": value.scheme,
        "hostname": value.hostname,
        "effective_port": value.effective_port,
    }


def _origin_from_dict(value: object, label: str) -> HttpOrigin:
    item = _mapping(value, {"scheme", "hostname", "effective_port"}, label)
    return HttpOrigin(
        scheme=_text(item["scheme"], f"{label}.scheme"),
        hostname=_text(item["hostname"], f"{label}.hostname"),
        effective_port=_integer(item["effective_port"], f"{label}.effective_port"),
    )


def _a1_source_to_dict(value: ApplicationServiceSourceReference) -> dict[str, object]:
    return {"owner_kind": value.owner_kind.value, "source_id": value.source_id}


def _a1_source_from_dict(value: object, label: str) -> ApplicationServiceSourceReference:
    item = _mapping(value, {"owner_kind", "source_id"}, label)
    return ApplicationServiceSourceReference(
        owner_kind=_enum(ApplicationServiceSourceOwnerKind, item["owner_kind"], f"{label}.owner_kind"),
        source_id=_text(item["source_id"], f"{label}.source_id"),
    )


def _a1_support_to_dict(value: ApplicationServiceRelationSupport) -> dict[str, object]:
    return {
        "basis": value.basis.value,
        "source_semantic": value.source_semantic.value,
        "source_reference": _a1_source_to_dict(value.source_reference),
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "raw_references": list(value.raw_references),
        "http_status_code": value.http_status_code,
    }


def _a1_support_from_dict(value: object, label: str) -> ApplicationServiceRelationSupport:
    keys = {"basis", "source_semantic", "source_reference", "evidence_ids", "artefact_references", "raw_references", "http_status_code"}
    item = _mapping(value, keys, label)
    return ApplicationServiceRelationSupport(
        basis=_enum(ApplicationServiceSupportBasis, item["basis"], f"{label}.basis"),
        source_semantic=_enum(ApplicationServiceSourceSemantic, item["source_semantic"], f"{label}.source_semantic"),
        source_reference=_a1_source_from_dict(item["source_reference"], f"{label}.source_reference"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        raw_references=_texts(item["raw_references"], f"{label}.raw_references"),
        http_status_code=_optional_integer(item["http_status_code"], f"{label}.http_status_code"),
    )


def _a1_to_dict(value: ApplicationServiceComposition) -> dict[str, object]:
    return {
        "origins": [{"entity_id": item.entity_id, "origin": _origin_to_dict(item.origin), "kind": item.kind.value} for item in value.origins],
        "routes": [{"entity_id": item.entity_id, "canonical_url": item.canonical_url, "origin_id": item.origin_id, "kind": item.kind.value} for item in value.routes],
        "source_sets": [{"entity_id": item.entity_id, "resource_urls": list(item.resource_urls), "origin_ids": list(item.origin_ids), "kind": item.kind.value} for item in value.source_sets],
        "relations": [{"relation_id": item.relation_id, "relation_kind": item.relation_kind.value, "source_entity_id": item.source_entity_id, "target_entity_id": item.target_entity_id, "supports": [_a1_support_to_dict(support) for support in item.supports]} for item in value.relations],
    }


def _a1_from_dict(value: object) -> ApplicationServiceComposition:
    item = _mapping(value, {"origins", "routes", "source_sets", "relations"}, "application_composition")
    origins = tuple(
        ApplicationServiceHttpOrigin(
            entity_id=_text(raw["entity_id"], f"origins[{index}].entity_id"),
            origin=_origin_from_dict(raw["origin"], f"origins[{index}].origin"),
            kind=_enum(ApplicationServiceEntityKind, raw["kind"], f"origins[{index}].kind"),
        )
        for index, value in enumerate(_array(item["origins"], "origins"))
        for raw in [_mapping(value, {"entity_id", "origin", "kind"}, f"origins[{index}]")]
    )
    routes = tuple(
        ApplicationServiceHttpRoute(
            entity_id=_text(raw["entity_id"], f"routes[{index}].entity_id"),
            canonical_url=_text(raw["canonical_url"], f"routes[{index}].canonical_url"),
            origin_id=_text(raw["origin_id"], f"routes[{index}].origin_id"),
            kind=_enum(ApplicationServiceEntityKind, raw["kind"], f"routes[{index}].kind"),
        )
        for index, value in enumerate(_array(item["routes"], "routes"))
        for raw in [_mapping(value, {"entity_id", "canonical_url", "origin_id", "kind"}, f"routes[{index}]")]
    )
    source_sets = tuple(
        ApplicationServiceSourceSet(
            entity_id=_text(raw["entity_id"], f"source_sets[{index}].entity_id"),
            resource_urls=_texts(raw["resource_urls"], f"source_sets[{index}].resource_urls"),
            origin_ids=_texts(raw["origin_ids"], f"source_sets[{index}].origin_ids"),
            kind=_enum(ApplicationServiceEntityKind, raw["kind"], f"source_sets[{index}].kind"),
        )
        for index, value in enumerate(_array(item["source_sets"], "source_sets"))
        for raw in [_mapping(value, {"entity_id", "resource_urls", "origin_ids", "kind"}, f"source_sets[{index}]")]
    )
    relations = tuple(
        ApplicationServiceRelation(
            relation_id=_text(raw["relation_id"], f"a1.relations[{index}].relation_id"),
            relation_kind=_enum(ApplicationServiceRelationKind, raw["relation_kind"], f"a1.relations[{index}].relation_kind"),
            source_entity_id=_text(raw["source_entity_id"], f"a1.relations[{index}].source_entity_id"),
            target_entity_id=_text(raw["target_entity_id"], f"a1.relations[{index}].target_entity_id"),
            supports=tuple(_a1_support_from_dict(support, f"a1.relations[{index}].supports[{support_index}]") for support_index, support in enumerate(_array(raw["supports"], f"a1.relations[{index}].supports"))),
        )
        for index, value in enumerate(_array(item["relations"], "a1.relations"))
        for raw in [_mapping(value, {"relation_id", "relation_kind", "source_entity_id", "target_entity_id", "supports"}, f"a1.relations[{index}]")]
    )
    return ApplicationServiceComposition(origins=origins, routes=routes, source_sets=source_sets, relations=relations)


def _a2_source_to_dict(value: DocumentationAssertionSourceReference) -> dict[str, object]:
    return {
        "owner_kind": value.owner_kind.value,
        "source_id": value.source_id,
        "request_url": value.request_url,
        "final_url": value.final_url,
        "method": value.method,
        "status_code": value.status_code,
        "body_sha256": value.body_sha256,
        "body_bytes": value.body_bytes,
        "evidence_ids": list(value.evidence_ids),
        "media_type": value.media_type,
    }


def _a2_source_from_dict(value: object, label: str) -> DocumentationAssertionSourceReference:
    keys = {"owner_kind", "source_id", "request_url", "final_url", "method", "status_code", "body_sha256", "body_bytes", "evidence_ids", "media_type"}
    item = _mapping(value, keys, label)
    return DocumentationAssertionSourceReference(
        owner_kind=_enum(DocumentationSourceOwnerKind, item["owner_kind"], f"{label}.owner_kind"),
        source_id=_text(item["source_id"], f"{label}.source_id"),
        request_url=_text(item["request_url"], f"{label}.request_url"),
        final_url=_text(item["final_url"], f"{label}.final_url"),
        method=_text(item["method"], f"{label}.method"),
        status_code=_integer(item["status_code"], f"{label}.status_code"),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        body_bytes=_integer(item["body_bytes"], f"{label}.body_bytes"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        media_type=_text(item["media_type"], f"{label}.media_type"),
    )


def _a2_support_to_dict(value: DocumentationAssertionSupport) -> dict[str, object]:
    return {
        "source_reference": _a2_source_to_dict(value.source_reference),
        "structural_context": value.structural_context.value,
        "start_offset": value.start_offset,
        "end_offset": value.end_offset,
        "line_number": value.line_number,
        "structural_locator": value.structural_locator,
        "matched_excerpt": value.matched_excerpt,
    }


def _a2_support_from_dict(value: object, label: str) -> DocumentationAssertionSupport:
    keys = {"source_reference", "structural_context", "start_offset", "end_offset", "line_number", "structural_locator", "matched_excerpt"}
    item = _mapping(value, keys, label)
    return DocumentationAssertionSupport(
        source_reference=_a2_source_from_dict(item["source_reference"], f"{label}.source_reference"),
        structural_context=_enum(DocumentationStructuralContext, item["structural_context"], f"{label}.structural_context"),
        start_offset=_integer(item["start_offset"], f"{label}.start_offset"),
        end_offset=_integer(item["end_offset"], f"{label}.end_offset"),
        line_number=_integer(item["line_number"], f"{label}.line_number"),
        structural_locator=_text(item["structural_locator"], f"{label}.structural_locator"),
        matched_excerpt=_text(item["matched_excerpt"], f"{label}.matched_excerpt"),
    )


def _value_to_dict(kind: DocumentationAssertionKind, value: object) -> dict[str, object]:
    if kind is DocumentationAssertionKind.SERVICE_BASE_URL:
        assert isinstance(value, DocumentedServiceBaseURL)
        return {"canonical_url": value.canonical_url, "origin": _origin_to_dict(value.origin)}
    if kind is DocumentationAssertionKind.HTTP_OPERATION:
        assert isinstance(value, DocumentedHttpOperation)
        return {"method": value.method, "route": value.route}
    if kind is DocumentationAssertionKind.REQUIRED_HEADER:
        assert isinstance(value, DocumentedRequiredHeader)
        return {"header_name": value.header_name}
    if kind is DocumentationAssertionKind.AUTHENTICATION_SCHEME:
        assert isinstance(value, DocumentedAuthentication)
        return {"scheme": value.scheme.value}
    if kind is DocumentationAssertionKind.OAUTH_SCOPE:
        assert isinstance(value, DocumentedOAuthScope)
        return {"scope": value.scope}
    assert kind is DocumentationAssertionKind.REALTIME_ENDPOINT and isinstance(value, DocumentedRealtimeEndpoint)
    return {"canonical_url": value.canonical_url, "scheme": value.scheme, "hostname": value.hostname, "effective_port": value.effective_port, "path": value.path, "query": value.query}


def _value_from_dict(kind: DocumentationAssertionKind, value: object, label: str) -> object:
    if kind is DocumentationAssertionKind.SERVICE_BASE_URL:
        item = _mapping(value, {"canonical_url", "origin"}, label)
        return DocumentedServiceBaseURL(_text(item["canonical_url"], f"{label}.canonical_url"), _origin_from_dict(item["origin"], f"{label}.origin"))
    if kind is DocumentationAssertionKind.HTTP_OPERATION:
        item = _mapping(value, {"method", "route"}, label)
        return DocumentedHttpOperation(_text(item["method"], f"{label}.method"), _text(item["route"], f"{label}.route"))
    if kind is DocumentationAssertionKind.REQUIRED_HEADER:
        item = _mapping(value, {"header_name"}, label)
        return DocumentedRequiredHeader(_text(item["header_name"], f"{label}.header_name"))
    if kind is DocumentationAssertionKind.AUTHENTICATION_SCHEME:
        item = _mapping(value, {"scheme"}, label)
        return DocumentedAuthentication(_enum(DocumentationAuthenticationScheme, item["scheme"], f"{label}.scheme"))
    if kind is DocumentationAssertionKind.OAUTH_SCOPE:
        item = _mapping(value, {"scope"}, label)
        return DocumentedOAuthScope(_text(item["scope"], f"{label}.scope"))
    item = _mapping(value, {"canonical_url", "scheme", "hostname", "effective_port", "path", "query"}, label)
    return DocumentedRealtimeEndpoint(
        canonical_url=_text(item["canonical_url"], f"{label}.canonical_url"),
        scheme=_text(item["scheme"], f"{label}.scheme"),
        hostname=_text(item["hostname"], f"{label}.hostname"),
        effective_port=_integer(item["effective_port"], f"{label}.effective_port"),
        path=_text(item["path"], f"{label}.path"),
        query=_text(item["query"], f"{label}.query"),
    )


def _a2_to_dict(value: DocumentationAssertionExtractionResult) -> dict[str, object]:
    return {
        "assertions": [{"assertion_id": item.assertion_id, "kind": item.kind.value, "value": _value_to_dict(item.kind, item.value), "supports": [_a2_support_to_dict(support) for support in item.supports]} for item in value.assertions],
        "skipped_sources": [{"source_id": item.source_id, "request_url": item.request_url, "body_sha256": item.body_sha256, "evidence_ids": list(item.evidence_ids), "reason": item.reason.value} for item in value.skipped_sources],
        "sources_considered": value.sources_considered,
        "sources_eligible": value.sources_eligible,
    }


def _a2_from_dict(value: object) -> DocumentationAssertionExtractionResult:
    item = _mapping(value, {"assertions", "skipped_sources", "sources_considered", "sources_eligible"}, "documentation_assertions")
    assertions = []
    for index, value in enumerate(_array(item["assertions"], "assertions")):
        raw = _mapping(value, {"assertion_id", "kind", "value", "supports"}, f"assertions[{index}]")
        kind = _enum(DocumentationAssertionKind, raw["kind"], f"assertions[{index}].kind")
        assertions.append(DocumentationAssertion(
            assertion_id=_text(raw["assertion_id"], f"assertions[{index}].assertion_id"),
            kind=kind,
            value=_value_from_dict(kind, raw["value"], f"assertions[{index}].value"),
            supports=tuple(_a2_support_from_dict(support, f"assertions[{index}].supports[{support_index}]") for support_index, support in enumerate(_array(raw["supports"], f"assertions[{index}].supports"))),
        ))
    skipped = tuple(
        DocumentationSourceSkip(
            source_id=_text(raw["source_id"], f"skipped_sources[{index}].source_id"),
            request_url=_text(raw["request_url"], f"skipped_sources[{index}].request_url"),
            body_sha256=_text(raw["body_sha256"], f"skipped_sources[{index}].body_sha256"),
            evidence_ids=_texts(raw["evidence_ids"], f"skipped_sources[{index}].evidence_ids"),
            reason=_enum(DocumentationSourceSkipReason, raw["reason"], f"skipped_sources[{index}].reason"),
        )
        for index, value in enumerate(_array(item["skipped_sources"], "skipped_sources"))
        for raw in [_mapping(value, {"source_id", "request_url", "body_sha256", "evidence_ids", "reason"}, f"skipped_sources[{index}]")]
    )
    return DocumentationAssertionExtractionResult(
        assertions=tuple(assertions),
        skipped_sources=skipped,
        sources_considered=_integer(item["sources_considered"], "sources_considered"),
        sources_eligible=_integer(item["sources_eligible"], "sources_eligible"),
    )


def _a3_support_to_dict(value: object) -> dict[str, object]:
    if isinstance(value, ApplicationServiceDocumentationRelationSupport):
        return {"support_type": "documentation", "basis": value.basis.value, "assertion_id": value.assertion_id, "assertion_support": _a2_support_to_dict(value.assertion_support)}
    if isinstance(value, ApplicationServiceObservedOriginCorrespondenceSupport):
        return {"support_type": "observed_origin_correspondence", "basis": value.basis.value, "documentation_assertion_id": value.documentation_assertion_id, "documentation_support": _a2_support_to_dict(value.documentation_support), "observed_relation_id": value.observed_relation_id, "observation_support": _a1_support_to_dict(value.observation_support)}
    raise TypeError("application/service model support must be typed")


def _a3_support_from_dict(value: object, label: str) -> object:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    support_type = _text(value.get("support_type"), f"{label}.support_type")
    if support_type == "documentation":
        item = _mapping(value, {"support_type", "basis", "assertion_id", "assertion_support"}, label)
        return ApplicationServiceDocumentationRelationSupport(
            basis=_enum(ApplicationServiceModelSupportBasis, item["basis"], f"{label}.basis"),
            assertion_id=_text(item["assertion_id"], f"{label}.assertion_id"),
            assertion_support=_a2_support_from_dict(item["assertion_support"], f"{label}.assertion_support"),
        )
    if support_type == "observed_origin_correspondence":
        item = _mapping(value, {"support_type", "basis", "documentation_assertion_id", "documentation_support", "observed_relation_id", "observation_support"}, label)
        return ApplicationServiceObservedOriginCorrespondenceSupport(
            basis=_enum(ApplicationServiceModelSupportBasis, item["basis"], f"{label}.basis"),
            documentation_assertion_id=_text(item["documentation_assertion_id"], f"{label}.documentation_assertion_id"),
            documentation_support=_a2_support_from_dict(item["documentation_support"], f"{label}.documentation_support"),
            observed_relation_id=_text(item["observed_relation_id"], f"{label}.observed_relation_id"),
            observation_support=_a1_support_from_dict(item["observation_support"], f"{label}.observation_support"),
        )
    raise ValueError(f"{label}.support_type has an unsupported value")


def _entity_reference_to_dict(value: ApplicationServiceModelEntityReference) -> dict[str, object]:
    return {"entity_kind": value.entity_kind.value, "entity_id": value.entity_id}


def _entity_reference_from_dict(value: object, label: str) -> ApplicationServiceModelEntityReference:
    item = _mapping(value, {"entity_kind", "entity_id"}, label)
    return ApplicationServiceModelEntityReference(
        entity_kind=_enum(ApplicationServiceModelEntityKind, item["entity_kind"], f"{label}.entity_kind"),
        entity_id=_text(item["entity_id"], f"{label}.entity_id"),
    )


def application_service_model_to_dict(model: ApplicationServiceModel) -> dict[str, object]:
    """Return the canonical schema-1 structured representation."""

    if not isinstance(model, ApplicationServiceModel):
        raise TypeError("application/service model persistence requires a typed model")
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "generated_by": _GENERATED_BY,
        "application_composition": _a1_to_dict(model.application_composition),
        "documentation_assertions": _a2_to_dict(model.documentation_assertions),
        "documentation_resources": [{"entity_id": item.entity_id, "source_reference": _a2_source_to_dict(item.source_reference), "kind": item.kind.value} for item in model.documentation_resources],
        "documented_http_services": [{"entity_id": item.entity_id, "value": _value_to_dict(DocumentationAssertionKind.SERVICE_BASE_URL, item.value), "kind": item.kind.value} for item in model.documented_http_services],
        "documented_realtime_endpoints": [{"entity_id": item.entity_id, "value": _value_to_dict(DocumentationAssertionKind.REALTIME_ENDPOINT, item.value), "kind": item.kind.value} for item in model.documented_realtime_endpoints],
        "relations": [{"relation_id": item.relation_id, "relation_kind": item.relation_kind.value, "basis": item.basis.value, "source": _entity_reference_to_dict(item.source), "target": _entity_reference_to_dict(item.target), "supports": [_a3_support_to_dict(support) for support in item.supports]} for item in model.relations],
    }
    for relation in model.application_composition.relations:
        for support in relation.supports:
            for reference in support.artefact_references:
                path = PurePosixPath(reference)
                if not reference or "\\" in reference or path.is_absolute() or ".." in path.parts:
                    raise ValueError("application/service model has an unsafe artefact reference")
    return payload


def application_service_model_from_dict(payload: object) -> ApplicationServiceModel:
    """Strictly reconstruct one canonical schema-1 model."""

    keys = {"schema_version", "generated_by", "application_composition", "documentation_assertions", "documentation_resources", "documented_http_services", "documented_realtime_endpoints", "relations"}
    top = _mapping(payload, keys, APPLICATION_SERVICE_MODEL_FILENAME)
    if _integer(top["schema_version"], "schema_version") != _SCHEMA_VERSION:
        raise ValueError("application/service model has an unsupported schema version")
    if _text(top["generated_by"], "generated_by") != _GENERATED_BY:
        raise ValueError("application/service model has an invalid generated_by value")
    a1 = _a1_from_dict(top["application_composition"])
    a2 = _a2_from_dict(top["documentation_assertions"])
    resources = tuple(
        ApplicationServiceDocumentationResource(
            entity_id=_text(raw["entity_id"], f"documentation_resources[{index}].entity_id"),
            source_reference=_a2_source_from_dict(raw["source_reference"], f"documentation_resources[{index}].source_reference"),
            kind=_enum(ApplicationServiceModelEntityKind, raw["kind"], f"documentation_resources[{index}].kind"),
        )
        for index, value in enumerate(_array(top["documentation_resources"], "documentation_resources"))
        for raw in [_mapping(value, {"entity_id", "source_reference", "kind"}, f"documentation_resources[{index}]")]
    )
    services = tuple(
        ApplicationServiceDocumentedHttpService(
            entity_id=_text(raw["entity_id"], f"documented_http_services[{index}].entity_id"),
            value=_value_from_dict(DocumentationAssertionKind.SERVICE_BASE_URL, raw["value"], f"documented_http_services[{index}].value"),
            kind=_enum(ApplicationServiceModelEntityKind, raw["kind"], f"documented_http_services[{index}].kind"),
        )
        for index, value in enumerate(_array(top["documented_http_services"], "documented_http_services"))
        for raw in [_mapping(value, {"entity_id", "value", "kind"}, f"documented_http_services[{index}]")]
    )
    realtime = tuple(
        ApplicationServiceDocumentedRealtimeEndpoint(
            entity_id=_text(raw["entity_id"], f"documented_realtime_endpoints[{index}].entity_id"),
            value=_value_from_dict(DocumentationAssertionKind.REALTIME_ENDPOINT, raw["value"], f"documented_realtime_endpoints[{index}].value"),
            kind=_enum(ApplicationServiceModelEntityKind, raw["kind"], f"documented_realtime_endpoints[{index}].kind"),
        )
        for index, value in enumerate(_array(top["documented_realtime_endpoints"], "documented_realtime_endpoints"))
        for raw in [_mapping(value, {"entity_id", "value", "kind"}, f"documented_realtime_endpoints[{index}]")]
    )
    relations = tuple(
        ApplicationServiceModelRelation(
            relation_id=_text(raw["relation_id"], f"relations[{index}].relation_id"),
            relation_kind=_enum(ApplicationServiceModelRelationKind, raw["relation_kind"], f"relations[{index}].relation_kind"),
            basis=_enum(ApplicationServiceModelSupportBasis, raw["basis"], f"relations[{index}].basis"),
            source=_entity_reference_from_dict(raw["source"], f"relations[{index}].source"),
            target=_entity_reference_from_dict(raw["target"], f"relations[{index}].target"),
            supports=tuple(_a3_support_from_dict(support, f"relations[{index}].supports[{support_index}]") for support_index, support in enumerate(_array(raw["supports"], f"relations[{index}].supports"))),
        )
        for index, value in enumerate(_array(top["relations"], "relations"))
        for raw in [_mapping(value, {"relation_id", "relation_kind", "basis", "source", "target", "supports"}, f"relations[{index}]")]
    )
    model = ApplicationServiceModel(
        application_composition=a1,
        documentation_assertions=a2,
        documentation_resources=resources,
        documented_http_services=services,
        documented_realtime_endpoints=realtime,
        relations=relations,
    )
    if application_service_model_to_dict(model) != top:
        raise ValueError("application/service model payload is not canonical")
    return model


def _object_without_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("application/service model JSON has a duplicate object member")
        result[key] = value
    return result


def _path(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("application/service model root must be a Path")
    return root / APPLICATION_SERVICE_MODEL_FILENAME


def _validate_file(path: Path, *, allow_absent: bool) -> bool:
    if path.is_symlink():
        raise ValueError("application/service model artefact must be a regular file")
    if not path.exists():
        return not allow_absent
    if not path.is_file():
        raise ValueError("application/service model artefact must be a regular file")
    return True


def write_application_service_model_artifact(root: Path, model: ApplicationServiceModel) -> Path:
    """Atomically write one canonical application/service model artefact."""

    payload = application_service_model_to_dict(model)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    root.mkdir(parents=True, exist_ok=True)
    path = _path(root)
    _validate_file(path, allow_absent=False)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{APPLICATION_SERVICE_MODEL_FILENAME}.", dir=root, delete=False) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_file(path, allow_absent=False)
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise ValueError(f"could not write {APPLICATION_SERVICE_MODEL_FILENAME}: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def load_application_service_model_artifact(root: Path) -> ApplicationServiceModel | None:
    """Load a canonical model, or return None when the optional artefact is absent."""

    path = _path(root)
    if not _validate_file(path, allow_absent=True):
        return None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
            raise ValueError("application/service model artefact is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(_MAX_FILE_BYTES + 1)
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError("application/service model artefact exceeds the size limit")
        payload = json.loads(content.decode("utf-8"), object_pairs_hook=_object_without_duplicate_members)
        return application_service_model_from_dict(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse {APPLICATION_SERVICE_MODEL_FILENAME} JSON: {exc}") from exc
    except ValueError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError) as exc:
        raise ValueError(f"{APPLICATION_SERVICE_MODEL_FILENAME} is malformed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
