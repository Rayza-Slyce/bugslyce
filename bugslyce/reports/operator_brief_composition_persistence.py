"""Deterministic persistence for canonical Operator Brief composition snapshots."""

from __future__ import annotations

from enum import Enum
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import TypeVar

from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionNote,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnknownReason,
)
from bugslyce.reports.operator_brief import (
    DEPRIORITISED_CONTEXT,
    EVIDENCE_ONLY,
    PRIMARY_THREAD,
    SUPPORTING_CONTEXT,
    OperatorBriefConflict,
    OperatorBriefConflictKind,
    OperatorBriefConflictObservation,
    OperatorBriefCoverageLimitation,
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceRanking,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpComposition,
    OperatorBriefHttpSubject,
)
from bugslyce.reports.operator_brief_network import (
    OperatorBriefNetworkComposition,
    OperatorBriefNetworkSubject,
    OperatorBriefServiceObservation,
    OperatorBriefSmbShareObservation,
)
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefAccessBoundaryInterpretation,
    OperatorBriefAccessBoundarySignalKind,
    OperatorBriefAccountWorkflowInterpretation,
    OperatorBriefCredentialIndicatorClass,
    OperatorBriefCredentialInterpretation,
    OperatorBriefDirectoryListingInterpretation,
    OperatorBriefEncodedArtifactInterpretation,
    OperatorBriefObjectReferenceInterpretation,
    OperatorBriefSourceNativeComposition,
    OperatorBriefSourceNativeFamily,
    OperatorBriefSourceNativeSubject,
    OperatorBriefStructuredDisclosureInterpretation,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefAttentionSignal,
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicyDecision,
    OperatorBriefThreadPolicyReason,
    OperatorBriefThreadPolicyResult,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefRouteObservation,
    OperatorBriefRouteProvenance,
    OperatorBriefRouteRelationship,
    OperatorBriefSourceClueObservation,
    OperatorBriefWebContextComposition,
    OperatorBriefWebContextSubject,
)
from bugslyce.triage.workflow_leads import (
    WorkflowAccountObservation,
    WorkflowAccountObservationKind,
)


OPERATOR_BRIEF_COMPOSITION_FILENAME = "operator_brief_composition.json"

_SCHEMA_VERSION = 1
_GENERATED_BY = "bugslyce.operator_brief_composition"
_MAX_FILE_BYTES = 16 * 1024 * 1024
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "generated_by",
        "http",
        "network",
        "web_context",
        "source_native",
        "thread_policy_result",
    }
)
_OWNER_FAMILIES = frozenset({"http", "network", "web_context", "source_native"})
_NORMALIZED_FAMILIES = frozenset({"http", "network", "web_context"})
_THREAD_ID_PATTERN = re.compile(r"THREAD-[0-9A-F]{16}\Z")

_EnumT = TypeVar("_EnumT", bound=Enum)


def _object_without_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Operator Brief composition JSON has a duplicate object member.")
        result[key] = value
    return result


def _mapping(value: object, keys: set[str] | frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object.")
    actual = set(value)
    if actual != set(keys):
        raise ValueError(f"{label} has missing or unexpected fields.")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list.")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text.")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer.")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean.")
    return value


def _enum(enum_type: type[_EnumT], value: object, label: str) -> _EnumT:
    text = _text(value, label)
    try:
        return enum_type(text)
    except ValueError as exc:
        raise ValueError(f"{label} has an unsupported value.") from exc


def _texts(value: object, label: str) -> tuple[str, ...]:
    return tuple(_text(item, f"{label} item") for item in _array(value, label))


def _integers(value: object, label: str) -> tuple[int, ...]:
    return tuple(_integer(item, f"{label} item") for item in _array(value, label))


def _enum_values(values: tuple[Enum, ...]) -> list[str]:
    return [item.value for item in values]


def _source_reference_to_dict(value: OperatorBriefSourceReference) -> dict[str, object]:
    return {"source_kind": value.source_kind, "source_id": value.source_id}


def _source_reference_from_dict(value: object, label: str) -> OperatorBriefSourceReference:
    item = _mapping(value, {"source_kind", "source_id"}, label)
    return OperatorBriefSourceReference(
        source_kind=_text(item["source_kind"], f"{label}.source_kind"),
        source_id=_text(item["source_id"], f"{label}.source_id"),
    )


def _source_references(value: object, label: str) -> tuple[OperatorBriefSourceReference, ...]:
    return tuple(
        _source_reference_from_dict(item, f"{label}[{index}]")
        for index, item in enumerate(_array(value, label))
    )


def _fact_to_dict(value: OperatorBriefFact) -> dict[str, object]:
    return {
        "fact_id": value.fact_id,
        "kind": value.kind.value,
        "semantic_class": value.semantic_class.value,
        "role": value.role.value,
        "label": value.label,
        "summary": value.summary,
        "endpoints": list(value.endpoints),
        "origins": list(value.origins),
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
        "route": value.route,
        "parameter_name": value.parameter_name,
        "form_method": value.form_method,
        "form_action": value.form_action,
        "service": value.service,
        "share_name": value.share_name,
        "share_type": value.share_type,
        "body_sha256": value.body_sha256,
        "http_method": value.http_method,
        "http_status_code": value.http_status_code,
    }


_FACT_KEYS = frozenset(
    {
        "fact_id", "kind", "semantic_class", "role", "label", "summary",
        "endpoints", "origins", "evidence_ids", "artefact_references",
        "source_references", "route", "parameter_name", "form_method",
        "form_action", "service", "share_name", "share_type", "body_sha256",
        "http_method", "http_status_code",
    }
)


def _fact_from_dict(value: object, label: str) -> OperatorBriefFact:
    item = _mapping(value, _FACT_KEYS, label)
    return OperatorBriefFact(
        fact_id=_text(item["fact_id"], f"{label}.fact_id"),
        kind=_enum(OperatorBriefFactKind, item["kind"], f"{label}.kind"),
        semantic_class=_enum(
            OperatorBriefSemanticClass, item["semantic_class"], f"{label}.semantic_class"
        ),
        role=_enum(OperatorBriefFactRole, item["role"], f"{label}.role"),
        label=_text(item["label"], f"{label}.label"),
        summary=_text(item["summary"], f"{label}.summary"),
        endpoints=_texts(item["endpoints"], f"{label}.endpoints"),
        origins=_texts(item["origins"], f"{label}.origins"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(
            item["artefact_references"], f"{label}.artefact_references"
        ),
        source_references=_source_references(
            item["source_references"], f"{label}.source_references"
        ),
        route=_text(item["route"], f"{label}.route"),
        parameter_name=_text(item["parameter_name"], f"{label}.parameter_name"),
        form_method=_text(item["form_method"], f"{label}.form_method"),
        form_action=_text(item["form_action"], f"{label}.form_action"),
        service=_text(item["service"], f"{label}.service"),
        share_name=_text(item["share_name"], f"{label}.share_name"),
        share_type=_text(item["share_type"], f"{label}.share_type"),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        http_method=_text(item["http_method"], f"{label}.http_method"),
        http_status_code=_optional_integer(
            item["http_status_code"], f"{label}.http_status_code"
        ),
    )


def _conflict_observation_to_dict(value: OperatorBriefConflictObservation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id,
        "endpoint": value.endpoint,
        "method": value.method,
        "status_code": value.status_code,
        "collection_stage": value.collection_stage,
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
    }


def _conflict_observation_from_dict(value: object, label: str) -> OperatorBriefConflictObservation:
    item = _mapping(
        value,
        {"observation_id", "endpoint", "method", "status_code", "collection_stage", "evidence_ids", "artefact_references"},
        label,
    )
    return OperatorBriefConflictObservation(
        observation_id=_text(item["observation_id"], f"{label}.observation_id"),
        endpoint=_text(item["endpoint"], f"{label}.endpoint"),
        method=_text(item["method"], f"{label}.method"),
        status_code=_integer(item["status_code"], f"{label}.status_code"),
        collection_stage=_text(item["collection_stage"], f"{label}.collection_stage"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
    )


def _conflict_to_dict(value: OperatorBriefConflict) -> dict[str, object]:
    return {
        "conflict_id": value.conflict_id,
        "kind": value.kind.value,
        "subject_endpoint": value.subject_endpoint,
        "observations": [_conflict_observation_to_dict(item) for item in value.observations],
        "summary": value.summary,
    }


def _conflict_from_dict(value: object, label: str) -> OperatorBriefConflict:
    item = _mapping(value, {"conflict_id", "kind", "subject_endpoint", "observations", "summary"}, label)
    return OperatorBriefConflict(
        conflict_id=_text(item["conflict_id"], f"{label}.conflict_id"),
        kind=_enum(OperatorBriefConflictKind, item["kind"], f"{label}.kind"),
        subject_endpoint=_text(item["subject_endpoint"], f"{label}.subject_endpoint"),
        observations=tuple(
            _conflict_observation_from_dict(raw, f"{label}.observations[{index}]")
            for index, raw in enumerate(_array(item["observations"], f"{label}.observations"))
        ),
        summary=_text(item["summary"], f"{label}.summary"),
    )


def _limitation_to_dict(value: OperatorBriefCoverageLimitation) -> dict[str, object]:
    return {
        "limitation_id": value.limitation_id,
        "capability": value.capability,
        "source_role": value.source_role,
        "source_id": value.source_id,
        "state": value.state.value,
        "outcome": None if value.outcome is None else value.outcome.value,
        "unknown_reason": None if value.unknown_reason is None else value.unknown_reason.value,
        "execution_note": None if value.execution_note is None else value.execution_note.value,
        "summary": value.summary,
    }


def _optional_enum(enum_type: type[_EnumT], value: object, label: str) -> _EnumT | None:
    if value is None:
        return None
    return _enum(enum_type, value, label)


def _limitation_from_dict(value: object, label: str) -> OperatorBriefCoverageLimitation:
    item = _mapping(
        value,
        {"limitation_id", "capability", "source_role", "source_id", "state", "outcome", "unknown_reason", "execution_note", "summary"},
        label,
    )
    return OperatorBriefCoverageLimitation(
        limitation_id=_text(item["limitation_id"], f"{label}.limitation_id"),
        capability=_text(item["capability"], f"{label}.capability"),
        source_role=_text(item["source_role"], f"{label}.source_role"),
        source_id=_text(item["source_id"], f"{label}.source_id"),
        state=_enum(AnalysisCoverageState, item["state"], f"{label}.state"),
        outcome=_optional_enum(AnalysisCoverageOutcome, item["outcome"], f"{label}.outcome"),
        unknown_reason=_optional_enum(
            AnalysisCoverageUnknownReason, item["unknown_reason"], f"{label}.unknown_reason"
        ),
        execution_note=_optional_enum(
            AnalysisCoverageExecutionNote, item["execution_note"], f"{label}.execution_note"
        ),
        summary=_text(item["summary"], f"{label}.summary"),
    )


def _ranking_to_dict(value: OperatorBriefSourceRanking) -> dict[str, object]:
    return {"source_lead_id": value.source_lead_id, "rank": value.rank, "score": value.score, "signal": value.signal}


def _ranking_from_dict(value: object, label: str) -> OperatorBriefSourceRanking:
    item = _mapping(value, {"source_lead_id", "rank", "score", "signal"}, label)
    return OperatorBriefSourceRanking(
        source_lead_id=_text(item["source_lead_id"], f"{label}.source_lead_id"),
        rank=_integer(item["rank"], f"{label}.rank"),
        score=_integer(item["score"], f"{label}.score"),
        signal=_text(item["signal"], f"{label}.signal"),
    )


def _http_subject_to_dict(value: OperatorBriefHttpSubject) -> dict[str, object]:
    return {
        "subject_id": value.subject_id,
        "observation_ids": list(value.observation_ids),
        "endpoints": list(value.endpoints),
        "origins": list(value.origins),
        "fact_ids": list(value.fact_ids),
        "conflict_ids": list(value.conflict_ids),
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
    }


def _http_subject_from_dict(value: object, label: str) -> OperatorBriefHttpSubject:
    item = _mapping(value, {"subject_id", "observation_ids", "endpoints", "origins", "fact_ids", "conflict_ids", "evidence_ids", "artefact_references"}, label)
    return OperatorBriefHttpSubject(
        subject_id=_text(item["subject_id"], f"{label}.subject_id"),
        observation_ids=_texts(item["observation_ids"], f"{label}.observation_ids"),
        endpoints=_texts(item["endpoints"], f"{label}.endpoints"),
        origins=_texts(item["origins"], f"{label}.origins"),
        fact_ids=_texts(item["fact_ids"], f"{label}.fact_ids"),
        conflict_ids=_texts(item["conflict_ids"], f"{label}.conflict_ids"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
    )


def _http_to_dict(value: OperatorBriefHttpComposition) -> dict[str, object]:
    return {
        "subjects": [_http_subject_to_dict(item) for item in value.subjects],
        "facts": [_fact_to_dict(item) for item in value.facts],
        "conflicts": [_conflict_to_dict(item) for item in value.conflicts],
    }


def _http_from_dict(value: object) -> OperatorBriefHttpComposition:
    item = _mapping(value, {"subjects", "facts", "conflicts"}, "http")
    return OperatorBriefHttpComposition(
        subjects=tuple(_http_subject_from_dict(raw, f"http.subjects[{index}]") for index, raw in enumerate(_array(item["subjects"], "http.subjects"))),
        facts=tuple(_fact_from_dict(raw, f"http.facts[{index}]") for index, raw in enumerate(_array(item["facts"], "http.facts"))),
        conflicts=tuple(_conflict_from_dict(raw, f"http.conflicts[{index}]") for index, raw in enumerate(_array(item["conflicts"], "http.conflicts"))),
    )


def _smb_to_dict(value: OperatorBriefSmbShareObservation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id, "source_kind": value.source_kind,
        "host": value.host, "port": value.port, "share_name": value.share_name,
        "share_type": value.share_type, "comment": value.comment,
        "trigger_service_names": list(value.trigger_service_names),
        "trigger_evidence_ids": list(value.trigger_evidence_ids),
        "trigger_artefact_references": list(value.trigger_artefact_references),
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _smb_from_dict(value: object, label: str) -> OperatorBriefSmbShareObservation:
    keys = {"observation_id", "source_kind", "host", "port", "share_name", "share_type", "comment", "trigger_service_names", "trigger_evidence_ids", "trigger_artefact_references", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefSmbShareObservation(
        observation_id=_text(item["observation_id"], f"{label}.observation_id"),
        source_kind=_text(item["source_kind"], f"{label}.source_kind"),
        host=_text(item["host"], f"{label}.host"),
        port=_integer(item["port"], f"{label}.port"),
        share_name=_text(item["share_name"], f"{label}.share_name"),
        share_type=_text(item["share_type"], f"{label}.share_type"),
        comment=_text(item["comment"], f"{label}.comment"),
        trigger_service_names=_texts(item["trigger_service_names"], f"{label}.trigger_service_names"),
        trigger_evidence_ids=_texts(item["trigger_evidence_ids"], f"{label}.trigger_evidence_ids"),
        trigger_artefact_references=_texts(item["trigger_artefact_references"], f"{label}.trigger_artefact_references"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _service_to_dict(value: OperatorBriefServiceObservation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id, "source_kind": value.source_kind,
        "host": value.host, "port": value.port, "protocol": value.protocol,
        "state": value.state, "service": value.service, "product": value.product,
        "version": value.version, "http_capable": value.http_capable,
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _service_from_dict(value: object, label: str) -> OperatorBriefServiceObservation:
    keys = {"observation_id", "source_kind", "host", "port", "protocol", "state", "service", "product", "version", "http_capable", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefServiceObservation(
        observation_id=_text(item["observation_id"], f"{label}.observation_id"),
        source_kind=_text(item["source_kind"], f"{label}.source_kind"),
        host=_text(item["host"], f"{label}.host"),
        port=_integer(item["port"], f"{label}.port"),
        protocol=_text(item["protocol"], f"{label}.protocol"),
        state=_text(item["state"], f"{label}.state"),
        service=_text(item["service"], f"{label}.service"),
        product=_text(item["product"], f"{label}.product"),
        version=_text(item["version"], f"{label}.version"),
        http_capable=_boolean(item["http_capable"], f"{label}.http_capable"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _network_subject_to_dict(value: OperatorBriefNetworkSubject) -> dict[str, object]:
    return {
        "subject_id": value.subject_id, "subject_kind": value.subject_kind.value,
        "host": value.host, "ports": list(value.ports), "protocols": list(value.protocols),
        "smb_share_observation_ids": list(value.smb_share_observation_ids),
        "service_observation_ids": list(value.service_observation_ids),
        "fact_ids": list(value.fact_ids), "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _network_subject_from_dict(value: object, label: str) -> OperatorBriefNetworkSubject:
    keys = {"subject_id", "subject_kind", "host", "ports", "protocols", "smb_share_observation_ids", "service_observation_ids", "fact_ids", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefNetworkSubject(
        subject_id=_text(item["subject_id"], f"{label}.subject_id"),
        subject_kind=_enum(OperatorBriefSubjectKind, item["subject_kind"], f"{label}.subject_kind"),
        host=_text(item["host"], f"{label}.host"),
        ports=_integers(item["ports"], f"{label}.ports"),
        protocols=_texts(item["protocols"], f"{label}.protocols"),
        smb_share_observation_ids=_texts(item["smb_share_observation_ids"], f"{label}.smb_share_observation_ids"),
        service_observation_ids=_texts(item["service_observation_ids"], f"{label}.service_observation_ids"),
        fact_ids=_texts(item["fact_ids"], f"{label}.fact_ids"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _network_to_dict(value: OperatorBriefNetworkComposition) -> dict[str, object]:
    return {
        "subjects": [_network_subject_to_dict(item) for item in value.subjects],
        "facts": [_fact_to_dict(item) for item in value.facts],
        "smb_shares": [_smb_to_dict(item) for item in value.smb_shares],
        "services": [_service_to_dict(item) for item in value.services],
    }


def _network_from_dict(value: object) -> OperatorBriefNetworkComposition:
    item = _mapping(value, {"subjects", "facts", "smb_shares", "services"}, "network")
    return OperatorBriefNetworkComposition(
        subjects=tuple(_network_subject_from_dict(raw, f"network.subjects[{index}]") for index, raw in enumerate(_array(item["subjects"], "network.subjects"))),
        facts=tuple(_fact_from_dict(raw, f"network.facts[{index}]") for index, raw in enumerate(_array(item["facts"], "network.facts"))),
        smb_shares=tuple(_smb_from_dict(raw, f"network.smb_shares[{index}]") for index, raw in enumerate(_array(item["smb_shares"], "network.smb_shares"))),
        services=tuple(_service_from_dict(raw, f"network.services[{index}]") for index, raw in enumerate(_array(item["services"], "network.services"))),
    )


def _clue_to_dict(value: OperatorBriefSourceClueObservation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id, "source_kind": value.source_kind,
        "origin": value.origin, "source_endpoint": value.source_endpoint,
        "clue_type": value.clue_type, "value": value.value,
        "resolved_endpoint": value.resolved_endpoint,
        "evidence_ids": list(value.evidence_ids), "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _clue_from_dict(value: object, label: str) -> OperatorBriefSourceClueObservation:
    keys = {"observation_id", "source_kind", "origin", "source_endpoint", "clue_type", "value", "resolved_endpoint", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefSourceClueObservation(
        observation_id=_text(item["observation_id"], f"{label}.observation_id"),
        source_kind=_text(item["source_kind"], f"{label}.source_kind"),
        origin=_text(item["origin"], f"{label}.origin"),
        source_endpoint=_text(item["source_endpoint"], f"{label}.source_endpoint"),
        clue_type=_text(item["clue_type"], f"{label}.clue_type"),
        value=_text(item["value"], f"{label}.value"),
        resolved_endpoint=_optional_text(item["resolved_endpoint"], f"{label}.resolved_endpoint"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _provenance_to_dict(value: OperatorBriefRouteProvenance) -> dict[str, object]:
    return {
        "status_codes": list(value.status_codes), "status_unknown": value.status_unknown,
        "redirect_locations": list(value.redirect_locations), "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _provenance_from_dict(value: object, label: str) -> OperatorBriefRouteProvenance:
    item = _mapping(value, {"status_codes", "status_unknown", "redirect_locations", "evidence_ids", "artefact_references", "source_references"}, label)
    return OperatorBriefRouteProvenance(
        status_codes=_integers(item["status_codes"], f"{label}.status_codes"),
        status_unknown=_boolean(item["status_unknown"], f"{label}.status_unknown"),
        redirect_locations=_texts(item["redirect_locations"], f"{label}.redirect_locations"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _route_to_dict(value: OperatorBriefRouteObservation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id, "source_kind": value.source_kind,
        "origin": value.origin, "endpoint": value.endpoint, "status_codes": list(value.status_codes),
        "status_unknown": value.status_unknown, "redirect_locations": list(value.redirect_locations),
        "evidence_ids": list(value.evidence_ids), "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
        "provenance_records": [_provenance_to_dict(item) for item in value.provenance_records],
    }


def _route_from_dict(value: object, label: str) -> OperatorBriefRouteObservation:
    keys = {"observation_id", "source_kind", "origin", "endpoint", "status_codes", "status_unknown", "redirect_locations", "evidence_ids", "artefact_references", "source_references", "provenance_records"}
    item = _mapping(value, keys, label)
    return OperatorBriefRouteObservation(
        observation_id=_text(item["observation_id"], f"{label}.observation_id"),
        source_kind=_text(item["source_kind"], f"{label}.source_kind"),
        origin=_text(item["origin"], f"{label}.origin"), endpoint=_text(item["endpoint"], f"{label}.endpoint"),
        status_codes=_integers(item["status_codes"], f"{label}.status_codes"),
        status_unknown=_boolean(item["status_unknown"], f"{label}.status_unknown"),
        redirect_locations=_texts(item["redirect_locations"], f"{label}.redirect_locations"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
        provenance_records=tuple(_provenance_from_dict(raw, f"{label}.provenance_records[{index}]") for index, raw in enumerate(_array(item["provenance_records"], f"{label}.provenance_records"))),
    )


def _relationship_to_dict(value: OperatorBriefRouteRelationship) -> dict[str, object]:
    return {
        "relationship_id": value.relationship_id, "relationship_type": value.relationship_type,
        "source_endpoint": value.source_endpoint, "target_endpoint": value.target_endpoint,
        "status_code": value.status_code, "raw_references": list(value.raw_references),
        "evidence_ids": list(value.evidence_ids), "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _relationship_from_dict(value: object, label: str) -> OperatorBriefRouteRelationship:
    keys = {"relationship_id", "relationship_type", "source_endpoint", "target_endpoint", "status_code", "raw_references", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefRouteRelationship(
        relationship_id=_text(item["relationship_id"], f"{label}.relationship_id"),
        relationship_type=_text(item["relationship_type"], f"{label}.relationship_type"),
        source_endpoint=_text(item["source_endpoint"], f"{label}.source_endpoint"),
        target_endpoint=_text(item["target_endpoint"], f"{label}.target_endpoint"),
        status_code=_optional_integer(item["status_code"], f"{label}.status_code"),
        raw_references=_texts(item["raw_references"], f"{label}.raw_references"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _web_subject_to_dict(value: OperatorBriefWebContextSubject) -> dict[str, object]:
    return {
        "subject_id": value.subject_id, "subject_kind": value.subject_kind.value,
        "endpoint": value.endpoint, "origin": value.origin,
        "clue_observation_ids": list(value.clue_observation_ids),
        "route_observation_ids": list(value.route_observation_ids),
        "relationship_ids": list(value.relationship_ids), "fact_ids": list(value.fact_ids),
        "evidence_ids": list(value.evidence_ids), "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
    }


def _web_subject_from_dict(value: object, label: str) -> OperatorBriefWebContextSubject:
    keys = {"subject_id", "subject_kind", "endpoint", "origin", "clue_observation_ids", "route_observation_ids", "relationship_ids", "fact_ids", "evidence_ids", "artefact_references", "source_references"}
    item = _mapping(value, keys, label)
    return OperatorBriefWebContextSubject(
        subject_id=_text(item["subject_id"], f"{label}.subject_id"),
        subject_kind=_enum(OperatorBriefSubjectKind, item["subject_kind"], f"{label}.subject_kind"),
        endpoint=_text(item["endpoint"], f"{label}.endpoint"), origin=_text(item["origin"], f"{label}.origin"),
        clue_observation_ids=_texts(item["clue_observation_ids"], f"{label}.clue_observation_ids"),
        route_observation_ids=_texts(item["route_observation_ids"], f"{label}.route_observation_ids"),
        relationship_ids=_texts(item["relationship_ids"], f"{label}.relationship_ids"),
        fact_ids=_texts(item["fact_ids"], f"{label}.fact_ids"), evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
    )


def _web_to_dict(value: OperatorBriefWebContextComposition) -> dict[str, object]:
    return {
        "subjects": [_web_subject_to_dict(item) for item in value.subjects],
        "facts": [_fact_to_dict(item) for item in value.facts],
        "clues": [_clue_to_dict(item) for item in value.clues],
        "routes": [_route_to_dict(item) for item in value.routes],
        "relationships": [_relationship_to_dict(item) for item in value.relationships],
    }


def _web_from_dict(value: object) -> OperatorBriefWebContextComposition:
    item = _mapping(value, {"subjects", "facts", "clues", "routes", "relationships"}, "web_context")
    return OperatorBriefWebContextComposition(
        subjects=tuple(_web_subject_from_dict(raw, f"web_context.subjects[{index}]") for index, raw in enumerate(_array(item["subjects"], "web_context.subjects"))),
        facts=tuple(_fact_from_dict(raw, f"web_context.facts[{index}]") for index, raw in enumerate(_array(item["facts"], "web_context.facts"))),
        clues=tuple(_clue_from_dict(raw, f"web_context.clues[{index}]") for index, raw in enumerate(_array(item["clues"], "web_context.clues"))),
        routes=tuple(_route_from_dict(raw, f"web_context.routes[{index}]") for index, raw in enumerate(_array(item["routes"], "web_context.routes"))),
        relationships=tuple(_relationship_from_dict(raw, f"web_context.relationships[{index}]") for index, raw in enumerate(_array(item["relationships"], "web_context.relationships"))),
    )


def _workflow_observation_to_dict(value: WorkflowAccountObservation) -> dict[str, object]:
    return {
        "kind": value.kind.value,
        "url": value.url,
        "evidence_ids": list(value.evidence_ids),
        "methods": list(value.methods),
        "field_names": list(value.field_names),
        "redirect_target_url": value.redirect_target_url,
    }


def _workflow_observation_from_dict(value: object, label: str) -> WorkflowAccountObservation:
    item = _mapping(value, {"kind", "url", "evidence_ids", "methods", "field_names", "redirect_target_url"}, label)
    return WorkflowAccountObservation(
        kind=_enum(WorkflowAccountObservationKind, item["kind"], f"{label}.kind"),
        url=_text(item["url"], f"{label}.url"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        methods=_texts(item["methods"], f"{label}.methods"),
        field_names=_texts(item["field_names"], f"{label}.field_names"),
        redirect_target_url=_optional_text(item["redirect_target_url"], f"{label}.redirect_target_url"),
    )


def _interpretation_to_dict(value: object) -> dict[str, object]:
    if isinstance(value, OperatorBriefStructuredDisclosureInterpretation):
        return {
            "type": "structured_disclosure",
            "category": value.category,
            "source_url": value.source_url,
            "final_url": value.final_url,
            "body_sha256": value.body_sha256,
            "disclosed_routes": list(value.disclosed_routes),
            "redacted_excerpt_lines": list(value.redacted_excerpt_lines),
        }
    if isinstance(value, OperatorBriefDirectoryListingInterpretation):
        return {
            "type": "directory_listing",
            "canonical_url": value.canonical_url,
            "requested_urls": list(value.requested_urls),
            "status_code": value.status_code,
            "content_type": value.content_type,
            "body_sha256": value.body_sha256,
            "listing_path": value.listing_path,
        }
    if isinstance(value, OperatorBriefAccessBoundaryInterpretation):
        return {
            "type": "access_boundary",
            "fingerprint_id": value.fingerprint_id,
            "requested_url": value.requested_url,
            "final_url": value.final_url,
            "method": value.method,
            "status_code": value.status_code,
            "body_sha256": value.body_sha256,
            "signal_kinds": _enum_values(value.signal_kinds),
            "contrast_category": value.contrast_category,
            "comparison_endpoints": list(value.comparison_endpoints),
            "comparison_statuses": list(value.comparison_statuses),
            "member_count": value.member_count,
        }
    if isinstance(value, OperatorBriefCredentialInterpretation):
        return {
            "type": "credential",
            "source_url": value.source_url,
            "artefact_types": list(value.artefact_types),
            "assignment_labels": list(value.assignment_labels),
            "indicator_classes": _enum_values(value.indicator_classes),
        }
    if isinstance(value, OperatorBriefAccountWorkflowInterpretation):
        return {
            "type": "account_workflow",
            "origin": value.origin,
            "covered_urls": list(value.covered_urls),
            "observations": [_workflow_observation_to_dict(item) for item in value.observations],
        }
    if isinstance(value, OperatorBriefObjectReferenceInterpretation):
        return {
            "type": "object_reference",
            "origin": value.origin,
            "covered_urls": list(value.covered_urls),
            "parameter_names": list(value.parameter_names),
        }
    if isinstance(value, OperatorBriefEncodedArtifactInterpretation):
        return {
            "type": "encoded_artifact",
            "classification_category": value.classification_category,
            "source_url": value.source_url,
            "artefact_type": value.artefact_type,
            "value_sha256": value.value_sha256,
            "value_length": value.value_length,
        }
    raise ValueError("Source-native interpretation type is unsupported.")


def _interpretation_from_dict(value: object, label: str) -> object:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    variant = _text(value.get("type"), f"{label}.type")
    if variant == "structured_disclosure":
        item = _mapping(value, {"type", "category", "source_url", "final_url", "body_sha256", "disclosed_routes", "redacted_excerpt_lines"}, label)
        return OperatorBriefStructuredDisclosureInterpretation(
            category=_text(item["category"], f"{label}.category"),
            source_url=_text(item["source_url"], f"{label}.source_url"),
            final_url=_text(item["final_url"], f"{label}.final_url"),
            body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
            disclosed_routes=_texts(item["disclosed_routes"], f"{label}.disclosed_routes"),
            redacted_excerpt_lines=_texts(item["redacted_excerpt_lines"], f"{label}.redacted_excerpt_lines"),
        )
    if variant == "directory_listing":
        item = _mapping(value, {"type", "canonical_url", "requested_urls", "status_code", "content_type", "body_sha256", "listing_path"}, label)
        return OperatorBriefDirectoryListingInterpretation(
            canonical_url=_text(item["canonical_url"], f"{label}.canonical_url"),
            requested_urls=_texts(item["requested_urls"], f"{label}.requested_urls"),
            status_code=_integer(item["status_code"], f"{label}.status_code"),
            content_type=_optional_text(item["content_type"], f"{label}.content_type"),
            body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
            listing_path=_text(item["listing_path"], f"{label}.listing_path"),
        )
    if variant == "access_boundary":
        item = _mapping(value, {"type", "fingerprint_id", "requested_url", "final_url", "method", "status_code", "body_sha256", "signal_kinds", "contrast_category", "comparison_endpoints", "comparison_statuses", "member_count"}, label)
        return OperatorBriefAccessBoundaryInterpretation(
            fingerprint_id=_text(item["fingerprint_id"], f"{label}.fingerprint_id"),
            requested_url=_text(item["requested_url"], f"{label}.requested_url"),
            final_url=_text(item["final_url"], f"{label}.final_url"),
            method=_text(item["method"], f"{label}.method"),
            status_code=_integer(item["status_code"], f"{label}.status_code"),
            body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
            signal_kinds=tuple(
                _enum(OperatorBriefAccessBoundarySignalKind, raw, f"{label}.signal_kinds[{index}]")
                for index, raw in enumerate(_array(item["signal_kinds"], f"{label}.signal_kinds"))
            ),
            contrast_category=_text(item["contrast_category"], f"{label}.contrast_category"),
            comparison_endpoints=_texts(item["comparison_endpoints"], f"{label}.comparison_endpoints"),
            comparison_statuses=_integers(item["comparison_statuses"], f"{label}.comparison_statuses"),
            member_count=_integer(item["member_count"], f"{label}.member_count"),
        )
    if variant == "credential":
        item = _mapping(value, {"type", "source_url", "artefact_types", "assignment_labels", "indicator_classes"}, label)
        return OperatorBriefCredentialInterpretation(
            source_url=_text(item["source_url"], f"{label}.source_url"),
            artefact_types=_texts(item["artefact_types"], f"{label}.artefact_types"),
            assignment_labels=_texts(item["assignment_labels"], f"{label}.assignment_labels"),
            indicator_classes=tuple(
                _enum(OperatorBriefCredentialIndicatorClass, raw, f"{label}.indicator_classes[{index}]")
                for index, raw in enumerate(_array(item["indicator_classes"], f"{label}.indicator_classes"))
            ),
        )
    if variant == "account_workflow":
        item = _mapping(value, {"type", "origin", "covered_urls", "observations"}, label)
        return OperatorBriefAccountWorkflowInterpretation(
            origin=_text(item["origin"], f"{label}.origin"),
            covered_urls=_texts(item["covered_urls"], f"{label}.covered_urls"),
            observations=tuple(
                _workflow_observation_from_dict(raw, f"{label}.observations[{index}]")
                for index, raw in enumerate(_array(item["observations"], f"{label}.observations"))
            ),
        )
    if variant == "object_reference":
        item = _mapping(value, {"type", "origin", "covered_urls", "parameter_names"}, label)
        return OperatorBriefObjectReferenceInterpretation(
            origin=_text(item["origin"], f"{label}.origin"),
            covered_urls=_texts(item["covered_urls"], f"{label}.covered_urls"),
            parameter_names=_texts(item["parameter_names"], f"{label}.parameter_names"),
        )
    if variant == "encoded_artifact":
        item = _mapping(value, {"type", "classification_category", "source_url", "artefact_type", "value_sha256", "value_length"}, label)
        return OperatorBriefEncodedArtifactInterpretation(
            classification_category=_text(item["classification_category"], f"{label}.classification_category"),
            source_url=_text(item["source_url"], f"{label}.source_url"),
            artefact_type=_text(item["artefact_type"], f"{label}.artefact_type"),
            value_sha256=_text(item["value_sha256"], f"{label}.value_sha256"),
            value_length=_integer(item["value_length"], f"{label}.value_length"),
        )
    raise ValueError(f"{label} has an unknown interpretation type.")


def _source_native_subject_to_dict(value: OperatorBriefSourceNativeSubject) -> dict[str, object]:
    return {
        "subject_id": value.subject_id,
        "family": value.family.value,
        "policy_key": value.policy_subject.policy_key,
        "endpoints": list(value.endpoints),
        "origins": list(value.origins),
        "evidence_ids": list(value.evidence_ids),
        "artefact_references": list(value.artefact_references),
        "source_references": [_source_reference_to_dict(item) for item in value.source_references],
        "interpretation": _interpretation_to_dict(value.interpretation),
    }


_SOURCE_NATIVE_SUBJECT_KEYS = frozenset(
    {"subject_id", "family", "policy_key", "endpoints", "origins", "evidence_ids", "artefact_references", "source_references", "interpretation"}
)


def _reference_to_dict(value: OperatorBriefThreadPolicySubjectReference | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {"subject_kind": value.subject_kind.value, "semantic_subject_key": value.semantic_subject_key}


def _reference_from_dict(value: object, label: str) -> OperatorBriefThreadPolicySubjectReference | None:
    if value is None:
        return None
    item = _mapping(value, {"subject_kind", "semantic_subject_key"}, label)
    return OperatorBriefThreadPolicySubjectReference(
        subject_kind=_enum(OperatorBriefSubjectKind, item["subject_kind"], f"{label}.subject_kind"),
        semantic_subject_key=_text(item["semantic_subject_key"], f"{label}.semantic_subject_key"),
    )


def _owner_subjects(composition: OperatorBriefComposition) -> dict[str, tuple[object, ...]]:
    return {
        "http": composition.http.subjects,
        "network": composition.network.subjects,
        "web_context": composition.web_context.subjects,
        "source_native": composition.source_native.subjects,
    }


def _owner_references(composition: OperatorBriefComposition) -> dict[str, tuple[str, str]]:
    owners = _owner_subjects(composition)
    source_by_policy_identity = {
        id(item.policy_subject): item.subject_id for item in composition.source_native.subjects
    }
    result: dict[str, tuple[str, str]] = {}
    used: set[tuple[str, str]] = set()
    for policy in composition.policy_subjects:
        source_id = source_by_policy_identity.get(id(policy))
        if source_id is not None:
            owner = ("source_native", source_id)
        else:
            matches: list[tuple[str, str]] = []
            semantic_key = policy.semantic_subject_key or ""
            for family, namespace in (("http", "http"), ("network", "network"), ("web_context", "web")):
                for subject in owners[family]:
                    subject_id = getattr(subject, "subject_id", None)
                    if semantic_key == f"{namespace}:{subject_id}":
                        matches.append((family, subject_id))
            if len(matches) != 1:
                raise ValueError("Policy subject owner reference is missing or ambiguous.")
            owner = matches[0]
        if owner in used:
            raise ValueError("Policy subjects contain duplicate owner references.")
        used.add(owner)
        result[policy.policy_key] = owner
    expected = {
        (family, getattr(subject, "subject_id"))
        for family, subjects in owners.items()
        for subject in subjects
    }
    if used != expected:
        raise ValueError("Policy owner references are incomplete.")
    return result


def _fact_identity_registry(composition: OperatorBriefComposition) -> dict[int, tuple[str, str]]:
    result: dict[int, tuple[str, str]] = {}
    for family, owner in (("http", composition.http), ("network", composition.network), ("web_context", composition.web_context)):
        for fact in owner.facts:
            if id(fact) in result:
                raise ValueError("Owner fact instances are ambiguous.")
            result[id(fact)] = (family, fact.fact_id)
    return result


def _policy_subject_to_dict(
    value: OperatorBriefThreadPolicySubject,
    owner: tuple[str, str],
    fact_registry: dict[int, tuple[str, str]],
    conflict_registry: dict[int, str],
) -> dict[str, object]:
    family, subject_id = owner
    facts: list[dict[str, object]] = []
    for fact in value.facts:
        reference = fact_registry.get(id(fact))
        if reference is None or reference[0] != family or family not in _NORMALIZED_FAMILIES:
            raise ValueError("Policy fact does not resolve to its canonical owner.")
        facts.append({"owner": reference[0], "fact_id": reference[1]})
    conflicts: list[dict[str, object]] = []
    for conflict in value.conflicts:
        conflict_id = conflict_registry.get(id(conflict))
        if conflict_id is None or family != "http":
            raise ValueError("Policy conflict does not resolve to its canonical owner.")
        conflicts.append({"owner": "http", "conflict_id": conflict_id})
    if family == "source_native" and (facts or conflicts):
        raise ValueError("Source-native policy payload cannot duplicate facts or conflicts.")
    return {
        "policy_key": value.policy_key,
        "semantic_subject_key": value.semantic_subject_key,
        "subject_kind": value.subject_kind.value,
        "materiality": value.materiality.value,
        "specificity": value.specificity.value,
        "evidence_basis": value.evidence_basis.value,
        "independent": value.independent,
        "associated_subject_reference": _reference_to_dict(value.associated_subject_reference),
        "replaced_by_subject_reference": _reference_to_dict(value.replaced_by_subject_reference),
        "facts": facts,
        "conflicts": conflicts,
        "coverage_limitations": [_limitation_to_dict(item) for item in value.coverage_limitations],
        "source_rankings": [_ranking_to_dict(item) for item in value.source_rankings],
        "source_lead_ids": list(value.source_lead_ids),
        "owner_reference": {"family": family, "subject_id": subject_id},
    }


_POLICY_SUBJECT_KEYS = frozenset(
    {"policy_key", "semantic_subject_key", "subject_kind", "materiality", "specificity", "evidence_basis", "independent", "associated_subject_reference", "replaced_by_subject_reference", "facts", "conflicts", "coverage_limitations", "source_rankings", "source_lead_ids", "owner_reference"}
)


def _decision_to_dict(value: OperatorBriefThreadPolicyDecision) -> dict[str, object]:
    return {
        "policy_key": value.policy_key,
        "disposition": value.disposition,
        "signal": value.signal.value,
        "thread_id": value.thread_id,
        "rank": value.rank,
        "reason_codes": _enum_values(value.reason_codes),
    }


def _decision_from_dict(value: object, label: str) -> OperatorBriefThreadPolicyDecision:
    item = _mapping(value, {"policy_key", "disposition", "signal", "thread_id", "rank", "reason_codes"}, label)
    return OperatorBriefThreadPolicyDecision(
        policy_key=_text(item["policy_key"], f"{label}.policy_key"),
        disposition=_text(item["disposition"], f"{label}.disposition"),
        signal=_enum(OperatorBriefAttentionSignal, item["signal"], f"{label}.signal"),
        thread_id=_text(item["thread_id"], f"{label}.thread_id"),
        rank=_optional_integer(item["rank"], f"{label}.rank"),
        reason_codes=tuple(
            _enum(OperatorBriefThreadPolicyReason, raw, f"{label}.reason_codes[{index}]")
            for index, raw in enumerate(_array(item["reason_codes"], f"{label}.reason_codes"))
        ),
    )


def _registry(values: tuple[object, ...], attribute: str, label: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for value in values:
        identifier = getattr(value, attribute, None)
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"{label} contains an invalid identity.")
        if identifier in result:
            raise ValueError(f"{label} contains duplicate identities.")
        result[identifier] = value
    return result


def _validate_owner_graph(composition: OperatorBriefComposition) -> None:
    if not isinstance(composition.http, OperatorBriefHttpComposition):
        raise ValueError("HTTP composition is invalid.")
    if not isinstance(composition.network, OperatorBriefNetworkComposition):
        raise ValueError("Network composition is invalid.")
    if not isinstance(composition.web_context, OperatorBriefWebContextComposition):
        raise ValueError("Web-context composition is invalid.")
    if not isinstance(composition.source_native, OperatorBriefSourceNativeComposition):
        raise ValueError("Source-native composition is invalid.")
    if not isinstance(composition.thread_policy_result, OperatorBriefThreadPolicyResult):
        raise ValueError("Thread-policy result is invalid.")

    http_subjects = _registry(composition.http.subjects, "subject_id", "HTTP subjects")
    http_facts = _registry(composition.http.facts, "fact_id", "HTTP facts")
    http_conflicts = _registry(composition.http.conflicts, "conflict_id", "HTTP conflicts")
    for subject in http_subjects.values():
        if not isinstance(subject, OperatorBriefHttpSubject):
            raise ValueError("HTTP subjects are invalid.")
        if len(set(subject.fact_ids)) != len(subject.fact_ids) or any(key not in http_facts for key in subject.fact_ids):
            raise ValueError("HTTP subject facts contain duplicate or dangling references.")
        if len(set(subject.conflict_ids)) != len(subject.conflict_ids) or any(key not in http_conflicts for key in subject.conflict_ids):
            raise ValueError("HTTP subject conflicts contain duplicate or dangling references.")

    network_subjects = _registry(composition.network.subjects, "subject_id", "Network subjects")
    network_facts = _registry(composition.network.facts, "fact_id", "Network facts")
    smb_shares = _registry(composition.network.smb_shares, "observation_id", "SMB observations")
    services = _registry(composition.network.services, "observation_id", "Service observations")
    if any(not isinstance(item, OperatorBriefSmbShareObservation) for item in smb_shares.values()):
        raise ValueError("SMB observations are invalid.")
    if any(not isinstance(item, OperatorBriefServiceObservation) for item in services.values()):
        raise ValueError("Service observations are invalid.")
    for subject in network_subjects.values():
        if not isinstance(subject, OperatorBriefNetworkSubject):
            raise ValueError("Network subjects are invalid.")
        references = (
            (subject.fact_ids, network_facts, "Network subject facts"),
            (subject.smb_share_observation_ids, smb_shares, "Network SMB observations"),
            (subject.service_observation_ids, services, "Network service observations"),
        )
        for identifiers, registry, label in references:
            if len(set(identifiers)) != len(identifiers) or any(key not in registry for key in identifiers):
                raise ValueError(f"{label} contain duplicate or dangling references.")

    web_subjects = _registry(composition.web_context.subjects, "subject_id", "Web-context subjects")
    web_facts = _registry(composition.web_context.facts, "fact_id", "Web-context facts")
    clues = _registry(composition.web_context.clues, "observation_id", "Web-context clues")
    routes = _registry(composition.web_context.routes, "observation_id", "Web-context routes")
    relationships = _registry(composition.web_context.relationships, "relationship_id", "Web-context relationships")
    for subject in web_subjects.values():
        if not isinstance(subject, OperatorBriefWebContextSubject):
            raise ValueError("Web-context subjects are invalid.")
        references = (
            (subject.fact_ids, web_facts, "Web-context subject facts"),
            (subject.clue_observation_ids, clues, "Web-context subject clues"),
            (subject.route_observation_ids, routes, "Web-context subject routes"),
            (subject.relationship_ids, relationships, "Web-context subject relationships"),
        )
        for identifiers, registry, label in references:
            if len(set(identifiers)) != len(identifiers) or any(key not in registry for key in identifiers):
                raise ValueError(f"{label} contain duplicate or dangling references.")

    _registry(composition.source_native.subjects, "subject_id", "Source-native subjects")


_INTERPRETATION_BY_FAMILY = {
    OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY: OperatorBriefStructuredDisclosureInterpretation,
    OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES: OperatorBriefStructuredDisclosureInterpretation,
    OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE: OperatorBriefDirectoryListingInterpretation,
    OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE: OperatorBriefAccessBoundaryInterpretation,
    OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW: OperatorBriefCredentialInterpretation,
    OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW: OperatorBriefAccountWorkflowInterpretation,
    OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE: OperatorBriefObjectReferenceInterpretation,
    OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT: OperatorBriefEncodedArtifactInterpretation,
}


def _validate_source_native_graph(composition: OperatorBriefComposition) -> None:
    canonical_by_key = {item.policy_key: item for item in composition.policy_subjects}
    if len(canonical_by_key) != len(composition.policy_subjects):
        raise ValueError("Canonical policy subjects contain duplicate keys.")
    for subject in composition.source_native.subjects:
        if not isinstance(subject, OperatorBriefSourceNativeSubject):
            raise ValueError("Source-native subjects are invalid.")
        canonical = canonical_by_key.get(subject.policy_subject.policy_key)
        if canonical is not subject.policy_subject:
            raise ValueError("Source-native policy alias is not canonical.")
        expected_type = _INTERPRETATION_BY_FAMILY.get(subject.family)
        if expected_type is None or not isinstance(subject.interpretation, expected_type):
            raise ValueError("Source-native family and interpretation are inconsistent.")
        expected_kind = (
            OperatorBriefSubjectKind.ACCOUNT_WORKFLOW
            if subject.family is OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW
            else OperatorBriefSubjectKind.CONTENT_SURFACE
        )
        if subject.policy_subject.subject_kind is not expected_kind:
            raise ValueError("Source-native family and policy kind are inconsistent.")
        if subject.policy_subject.facts or subject.policy_subject.conflicts:
            raise ValueError("Source-native policy facts or conflicts are unsupported.")


def _validate_decision_graph(result: OperatorBriefThreadPolicyResult) -> None:
    subject_keys = tuple(item.policy_key for item in result.subjects)
    decision_keys = tuple(item.policy_key for item in result.decisions)
    if subject_keys != tuple(sorted(subject_keys)):
        raise ValueError("Policy subjects are not in canonical storage order.")
    if decision_keys != tuple(sorted(decision_keys)):
        raise ValueError("Policy decisions are not in canonical storage order.")
    if subject_keys != decision_keys:
        raise ValueError("Policy subjects and decisions do not share canonical coverage.")

    identities: dict[OperatorBriefThreadPolicySubjectReference, OperatorBriefThreadPolicySubject] = {}
    for subject in result.subjects:
        if subject.semantic_subject_key is not None:
            identity = OperatorBriefThreadPolicySubjectReference(
                subject_kind=subject.subject_kind,
                semantic_subject_key=subject.semantic_subject_key,
            )
            if identity in identities:
                raise ValueError("Policy subjects contain duplicate semantic identities.")
            identities[identity] = subject
        if subject.associated_subject_reference is not None and subject.replaced_by_subject_reference is not None:
            raise ValueError("Policy association and replacement are mutually exclusive.")
        for reference in (subject.associated_subject_reference, subject.replaced_by_subject_reference):
            if reference is not None and reference not in identities and not any(
                candidate.subject_kind is reference.subject_kind
                and candidate.semantic_subject_key == reference.semantic_subject_key
                for candidate in result.subjects
            ):
                raise ValueError("Policy relationship has a dangling target.")

    subjects_by_key = {item.policy_key: item for item in result.subjects}
    decisions_by_key = {item.policy_key: item for item in result.decisions}
    primary_decisions = [item for item in result.decisions if item.disposition == PRIMARY_THREAD]
    ranks = [item.rank for item in primary_decisions]
    if any(rank is None for rank in ranks) or sorted(ranks) != list(range(1, len(ranks) + 1)):
        raise ValueError("Primary policy ranks must be positive, unique, and contiguous.")
    primary_threads: dict[str, OperatorBriefThreadPolicyDecision] = {}
    for decision in primary_decisions:
        if not _THREAD_ID_PATTERN.fullmatch(decision.thread_id):
            raise ValueError("Primary thread ID is invalid.")
        if decision.thread_id in primary_threads:
            raise ValueError("Primary thread IDs must be unique.")
        primary_threads[decision.thread_id] = decision

    identity_to_decision = {
        OperatorBriefThreadPolicySubjectReference(subject.subject_kind, subject.semantic_subject_key): decisions_by_key[subject.policy_key]
        for subject in result.subjects
        if subject.semantic_subject_key is not None
    }
    for decision in result.decisions:
        subject = subjects_by_key[decision.policy_key]
        if decision.disposition == PRIMARY_THREAD:
            if subject.associated_subject_reference is not None or subject.replaced_by_subject_reference is not None:
                raise ValueError("Primary decision cannot carry a relationship.")
            continue
        if decision.rank is not None:
            raise ValueError("Only primary decisions may carry attention ranks.")
        if decision.disposition == SUPPORTING_CONTEXT:
            if not _THREAD_ID_PATTERN.fullmatch(decision.thread_id):
                raise ValueError("Supporting thread ID is invalid.")
            reference = subject.associated_subject_reference or subject.replaced_by_subject_reference
            if reference is None:
                raise ValueError("Supporting decision requires a relationship target.")
            target = identity_to_decision.get(reference)
            if target is None or target.disposition != PRIMARY_THREAD or target.thread_id != decision.thread_id:
                raise ValueError("Supporting decision has an invalid primary thread target.")
        elif decision.disposition in {DEPRIORITISED_CONTEXT, EVIDENCE_ONLY}:
            if decision.thread_id:
                raise ValueError("Non-threaded decision cannot carry a thread ID.")
        else:
            raise ValueError("Policy decision disposition is invalid.")


def _validate_graph(composition: OperatorBriefComposition) -> dict[str, tuple[str, str]]:
    if not isinstance(composition, OperatorBriefComposition):
        raise TypeError("Operator Brief composition persistence requires an OperatorBriefComposition.")
    if composition.policy_subjects is not composition.thread_policy_result.subjects:
        raise ValueError("Composition policy-subject alias is invalid.")
    _validate_owner_graph(composition)
    owner_references = _owner_references(composition)
    fact_registry = _fact_identity_registry(composition)
    conflict_registry = {id(item): item.conflict_id for item in composition.http.conflicts}
    for policy in composition.policy_subjects:
        family, _ = owner_references[policy.policy_key]
        for fact in policy.facts:
            reference = fact_registry.get(id(fact))
            if reference is None or reference[0] != family:
                raise ValueError("Normalized policy fact alias is invalid.")
        for conflict in policy.conflicts:
            if family != "http" or id(conflict) not in conflict_registry:
                raise ValueError("Normalized policy conflict alias is invalid.")
    _validate_source_native_graph(composition)
    _validate_decision_graph(composition.thread_policy_result)
    return owner_references


def _is_safe_artefact_reference(value: str) -> bool:
    if not value or "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and str(path) == value


def _validate_artefact_references(value: object, label: str = "payload") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.endswith("artefact_references"):
                references = _array(nested, f"{label}.{key}")
                for index, reference in enumerate(references):
                    text = _text(reference, f"{label}.{key}[{index}]")
                    if not _is_safe_artefact_reference(text):
                        raise ValueError("Operator Brief artefact reference is unsafe.")
            else:
                _validate_artefact_references(nested, f"{label}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _validate_artefact_references(nested, f"{label}[{index}]")


def _payload_from_composition(composition: OperatorBriefComposition) -> dict[str, object]:
    owner_references = _validate_graph(composition)
    fact_registry = _fact_identity_registry(composition)
    conflict_registry = {id(item): item.conflict_id for item in composition.http.conflicts}
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "generated_by": _GENERATED_BY,
        "http": _http_to_dict(composition.http),
        "network": _network_to_dict(composition.network),
        "web_context": _web_to_dict(composition.web_context),
        "source_native": {
            "subjects": [_source_native_subject_to_dict(item) for item in composition.source_native.subjects]
        },
        "thread_policy_result": {
            "subjects": [
                _policy_subject_to_dict(
                    item,
                    owner_references[item.policy_key],
                    fact_registry,
                    conflict_registry,
                )
                for item in composition.policy_subjects
            ],
            "decisions": [_decision_to_dict(item) for item in composition.thread_policy_result.decisions],
        },
    }
    _validate_artefact_references(payload)
    return payload


def _owner_reference_from_dict(value: object, label: str) -> tuple[str, str]:
    item = _mapping(value, {"family", "subject_id"}, label)
    family = _text(item["family"], f"{label}.family")
    if family not in _OWNER_FAMILIES:
        raise ValueError("Policy owner family is unsupported.")
    subject_id = _text(item["subject_id"], f"{label}.subject_id")
    if not subject_id:
        raise ValueError("Policy owner subject ID cannot be blank.")
    return family, subject_id


def _policy_subject_from_dict(
    value: object,
    label: str,
    facts: dict[tuple[str, str], OperatorBriefFact],
    conflicts: dict[tuple[str, str], OperatorBriefConflict],
) -> tuple[OperatorBriefThreadPolicySubject, tuple[str, str]]:
    item = _mapping(value, _POLICY_SUBJECT_KEYS, label)
    owner = _owner_reference_from_dict(item["owner_reference"], f"{label}.owner_reference")
    family, _ = owner
    resolved_facts: list[OperatorBriefFact] = []
    for index, raw in enumerate(_array(item["facts"], f"{label}.facts")):
        reference = _mapping(raw, {"owner", "fact_id"}, f"{label}.facts[{index}]")
        fact_owner = _text(reference["owner"], f"{label}.facts[{index}].owner")
        fact_id = _text(reference["fact_id"], f"{label}.facts[{index}].fact_id")
        if fact_owner not in _NORMALIZED_FAMILIES or fact_owner != family:
            raise ValueError("Policy fact references the wrong owner family.")
        try:
            resolved_facts.append(facts[(fact_owner, fact_id)])
        except KeyError as exc:
            raise ValueError("Policy fact reference is dangling.") from exc
    resolved_conflicts: list[OperatorBriefConflict] = []
    for index, raw in enumerate(_array(item["conflicts"], f"{label}.conflicts")):
        reference = _mapping(raw, {"owner", "conflict_id"}, f"{label}.conflicts[{index}]")
        conflict_owner = _text(reference["owner"], f"{label}.conflicts[{index}].owner")
        conflict_id = _text(reference["conflict_id"], f"{label}.conflicts[{index}].conflict_id")
        if conflict_owner != "http" or family != "http":
            raise ValueError("Policy conflict references the wrong owner family.")
        try:
            resolved_conflicts.append(conflicts[(conflict_owner, conflict_id)])
        except KeyError as exc:
            raise ValueError("Policy conflict reference is dangling.") from exc
    if family == "source_native" and (resolved_facts or resolved_conflicts):
        raise ValueError("Source-native policy facts or conflicts are unsupported.")
    policy = OperatorBriefThreadPolicySubject(
        policy_key=_text(item["policy_key"], f"{label}.policy_key"),
        semantic_subject_key=_optional_text(item["semantic_subject_key"], f"{label}.semantic_subject_key"),
        subject_kind=_enum(OperatorBriefSubjectKind, item["subject_kind"], f"{label}.subject_kind"),
        materiality=_enum(OperatorBriefThreadMateriality, item["materiality"], f"{label}.materiality"),
        specificity=_enum(OperatorBriefThreadSpecificity, item["specificity"], f"{label}.specificity"),
        evidence_basis=_enum(OperatorBriefThreadEvidenceBasis, item["evidence_basis"], f"{label}.evidence_basis"),
        independent=_boolean(item["independent"], f"{label}.independent"),
        associated_subject_reference=_reference_from_dict(item["associated_subject_reference"], f"{label}.associated_subject_reference"),
        replaced_by_subject_reference=_reference_from_dict(item["replaced_by_subject_reference"], f"{label}.replaced_by_subject_reference"),
        facts=tuple(resolved_facts),
        conflicts=tuple(resolved_conflicts),
        coverage_limitations=tuple(
            _limitation_from_dict(raw, f"{label}.coverage_limitations[{index}]")
            for index, raw in enumerate(_array(item["coverage_limitations"], f"{label}.coverage_limitations"))
        ),
        source_rankings=tuple(
            _ranking_from_dict(raw, f"{label}.source_rankings[{index}]")
            for index, raw in enumerate(_array(item["source_rankings"], f"{label}.source_rankings"))
        ),
        source_lead_ids=_texts(item["source_lead_ids"], f"{label}.source_lead_ids"),
    )
    return policy, owner


def _source_native_subject_from_dict(
    value: object,
    label: str,
    policies: dict[str, OperatorBriefThreadPolicySubject],
) -> OperatorBriefSourceNativeSubject:
    item = _mapping(value, _SOURCE_NATIVE_SUBJECT_KEYS, label)
    policy_key = _text(item["policy_key"], f"{label}.policy_key")
    try:
        policy = policies[policy_key]
    except KeyError as exc:
        raise ValueError("Source-native policy-key reference is dangling.") from exc
    return OperatorBriefSourceNativeSubject(
        subject_id=_text(item["subject_id"], f"{label}.subject_id"),
        family=_enum(OperatorBriefSourceNativeFamily, item["family"], f"{label}.family"),
        policy_subject=policy,
        endpoints=_texts(item["endpoints"], f"{label}.endpoints"),
        origins=_texts(item["origins"], f"{label}.origins"),
        evidence_ids=_texts(item["evidence_ids"], f"{label}.evidence_ids"),
        artefact_references=_texts(item["artefact_references"], f"{label}.artefact_references"),
        source_references=_source_references(item["source_references"], f"{label}.source_references"),
        interpretation=_interpretation_from_dict(item["interpretation"], f"{label}.interpretation"),  # type: ignore[arg-type]
    )


def _owner_id_sets(
    http: OperatorBriefHttpComposition,
    network: OperatorBriefNetworkComposition,
    web_context: OperatorBriefWebContextComposition,
    raw_source_subjects: list[object],
) -> dict[str, set[str]]:
    source_ids: set[str] = set()
    for index, raw in enumerate(raw_source_subjects):
        item = _mapping(raw, _SOURCE_NATIVE_SUBJECT_KEYS, f"source_native.subjects[{index}]")
        subject_id = _text(item["subject_id"], f"source_native.subjects[{index}].subject_id")
        if subject_id in source_ids:
            raise ValueError("Source-native subjects contain duplicate identities.")
        source_ids.add(subject_id)
    return {
        "http": set(_registry(http.subjects, "subject_id", "HTTP subjects")),
        "network": set(_registry(network.subjects, "subject_id", "Network subjects")),
        "web_context": set(_registry(web_context.subjects, "subject_id", "Web-context subjects")),
        "source_native": source_ids,
    }


def _composition_from_payload(payload: object) -> OperatorBriefComposition:
    top = _mapping(payload, _TOP_LEVEL_KEYS, OPERATOR_BRIEF_COMPOSITION_FILENAME)
    if _integer(top["schema_version"], "schema_version") != _SCHEMA_VERSION:
        raise ValueError("Operator Brief composition has an unsupported schema version.")
    if _text(top["generated_by"], "generated_by") != _GENERATED_BY:
        raise ValueError("Operator Brief composition has an invalid generated_by value.")
    _validate_artefact_references(top)

    http = _http_from_dict(top["http"])
    network = _network_from_dict(top["network"])
    web_context = _web_from_dict(top["web_context"])
    source_section = _mapping(top["source_native"], {"subjects"}, "source_native")
    raw_source_subjects = _array(source_section["subjects"], "source_native.subjects")
    owner_ids = _owner_id_sets(http, network, web_context, raw_source_subjects)

    facts: dict[tuple[str, str], OperatorBriefFact] = {}
    for family, values in (("http", http.facts), ("network", network.facts), ("web_context", web_context.facts)):
        for fact_id, fact in _registry(values, "fact_id", f"{family} facts").items():
            facts[(family, fact_id)] = fact  # type: ignore[assignment]
    conflicts = {
        ("http", conflict_id): conflict
        for conflict_id, conflict in _registry(http.conflicts, "conflict_id", "HTTP conflicts").items()
    }

    result_section = _mapping(top["thread_policy_result"], {"subjects", "decisions"}, "thread_policy_result")
    raw_policies = _array(result_section["subjects"], "thread_policy_result.subjects")
    raw_policy_keys = tuple(
        _text(_mapping(raw, _POLICY_SUBJECT_KEYS, f"thread_policy_result.subjects[{index}]")["policy_key"], f"thread_policy_result.subjects[{index}].policy_key")
        for index, raw in enumerate(raw_policies)
    )
    if raw_policy_keys != tuple(sorted(raw_policy_keys)):
        raise ValueError("Policy subjects are not in canonical storage order.")

    policies: list[OperatorBriefThreadPolicySubject] = []
    persisted_owners: dict[str, tuple[str, str]] = {}
    used_owners: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_policies):
        policy, owner = _policy_subject_from_dict(
            raw,
            f"thread_policy_result.subjects[{index}]",
            facts,
            conflicts,  # type: ignore[arg-type]
        )
        family, subject_id = owner
        if subject_id not in owner_ids[family]:
            raise ValueError("Policy owner reference is dangling.")
        if owner in used_owners:
            raise ValueError("Policy owner reference is duplicated.")
        used_owners.add(owner)
        if policy.policy_key in persisted_owners:
            raise ValueError("Canonical policy key is duplicated.")
        persisted_owners[policy.policy_key] = owner
        policies.append(policy)
    expected_owners = {(family, subject_id) for family, identifiers in owner_ids.items() for subject_id in identifiers}
    if used_owners != expected_owners:
        raise ValueError("Policy owner references are incomplete.")
    policy_by_key = {item.policy_key: item for item in policies}

    raw_source_policy_keys = tuple(
        _text(_mapping(raw, _SOURCE_NATIVE_SUBJECT_KEYS, f"source_native.subjects[{index}]")["policy_key"], f"source_native.subjects[{index}].policy_key")
        for index, raw in enumerate(raw_source_subjects)
    )
    if raw_source_policy_keys != tuple(sorted(raw_source_policy_keys)):
        raise ValueError("Source-native subjects are not in canonical storage order.")
    source_native = OperatorBriefSourceNativeComposition(
        subjects=tuple(
            _source_native_subject_from_dict(raw, f"source_native.subjects[{index}]", policy_by_key)
            for index, raw in enumerate(raw_source_subjects)
        )
    )
    for source_subject in source_native.subjects:
        if persisted_owners.get(source_subject.policy_subject.policy_key) != ("source_native", source_subject.subject_id):
            raise ValueError("Source-native policy owner reference is inconsistent.")

    raw_decisions = _array(result_section["decisions"], "thread_policy_result.decisions")
    raw_decision_keys = tuple(
        _text(_mapping(raw, {"policy_key", "disposition", "signal", "thread_id", "rank", "reason_codes"}, f"thread_policy_result.decisions[{index}]")["policy_key"], f"thread_policy_result.decisions[{index}].policy_key")
        for index, raw in enumerate(raw_decisions)
    )
    if raw_decision_keys != tuple(sorted(raw_decision_keys)):
        raise ValueError("Policy decisions are not in canonical storage order.")
    decisions = tuple(
        _decision_from_dict(raw, f"thread_policy_result.decisions[{index}]")
        for index, raw in enumerate(raw_decisions)
    )
    result = OperatorBriefThreadPolicyResult(subjects=tuple(policies), decisions=decisions)
    composition = OperatorBriefComposition(
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
        thread_policy_result=result,
    )
    reconstructed_owners = _validate_graph(composition)
    if reconstructed_owners != persisted_owners:
        raise ValueError("Persisted policy owner references are inconsistent.")
    if _payload_from_composition(composition) != top:
        raise ValueError("Operator Brief composition payload is not canonical.")
    return composition


def _canonical_path(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("Operator Brief composition root must be a Path.")
    return root / OPERATOR_BRIEF_COMPOSITION_FILENAME


def _validate_canonical_file(path: Path, *, allow_absent: bool) -> bool:
    if path.is_symlink():
        raise ValueError("Operator Brief composition artefact must be a regular file.")
    if not path.exists():
        if allow_absent:
            return False
        return True
    if not path.is_file():
        raise ValueError("Operator Brief composition artefact must be a regular file.")
    return True


def write_operator_brief_composition_artifact(
    root: Path,
    composition: OperatorBriefComposition,
) -> Path:
    """Persist one canonical Stage 5 semantic snapshot without recomposition."""

    if not isinstance(composition, OperatorBriefComposition):
        raise TypeError("Operator Brief composition persistence requires an OperatorBriefComposition.")
    payload = _payload_from_composition(composition)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    root.mkdir(parents=True, exist_ok=True)
    path = _canonical_path(root)
    _validate_canonical_file(path, allow_absent=False)

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{OPERATOR_BRIEF_COMPOSITION_FILENAME}.",
            dir=root,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_canonical_file(path, allow_absent=False)
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise ValueError(f"could not write {OPERATOR_BRIEF_COMPOSITION_FILENAME}: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def load_operator_brief_composition_artifact(
    root: Path,
) -> OperatorBriefComposition | None:
    """Load one canonical Stage 5 semantic snapshot, or None when absent."""

    path = _canonical_path(root)
    if not _validate_canonical_file(path, allow_absent=True):
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Operator Brief composition artefact must be a regular file.")
            if metadata.st_size > _MAX_FILE_BYTES:
                raise ValueError("Operator Brief composition artefact exceeds the size limit.")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                content = handle.read(_MAX_FILE_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError("Operator Brief composition artefact exceeds the size limit.")
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_members,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"could not parse {OPERATOR_BRIEF_COMPOSITION_FILENAME} JSON: {exc}"
        ) from exc
    except ValueError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"could not parse {OPERATOR_BRIEF_COMPOSITION_FILENAME}: {exc}") from exc
    try:
        return _composition_from_payload(payload)
    except ValueError:
        raise
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError(f"{OPERATOR_BRIEF_COMPOSITION_FILENAME} is malformed.") from exc
