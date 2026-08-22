"""Pure normalized composition of retained SMB and service evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

from bugslyce.core.normalise import normalise_hostname
from bugslyce.core.models import ProjectState
from bugslyce.parsers.nmap import is_http_capable_port_service
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)


@dataclass(frozen=True)
class OperatorBriefSmbShareObservation:
    """One retained SMB share observation and its trigger provenance."""

    observation_id: str
    source_kind: str
    host: str
    port: int
    share_name: str
    share_type: str
    comment: str
    trigger_service_names: tuple[str, ...]
    trigger_evidence_ids: tuple[str, ...]
    trigger_artefact_references: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefServiceObservation:
    """One retained port/service observation."""

    observation_id: str
    source_kind: str
    host: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    http_capable: bool
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefNetworkCompositionInput:
    """Normalized SMB and service observations accepted by the composer."""

    smb_shares: tuple[OperatorBriefSmbShareObservation, ...] = ()
    services: tuple[OperatorBriefServiceObservation, ...] = ()


@dataclass(frozen=True)
class OperatorBriefNetworkSubject:
    """One provisional network subject without ranking or disposition."""

    subject_id: str
    subject_kind: OperatorBriefSubjectKind
    host: str
    ports: tuple[int, ...]
    protocols: tuple[str, ...]
    smb_share_observation_ids: tuple[str, ...]
    service_observation_ids: tuple[str, ...]
    fact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]


@dataclass(frozen=True)
class OperatorBriefNetworkComposition:
    """Deterministic provisional network subjects and direct facts."""

    subjects: tuple[OperatorBriefNetworkSubject, ...]
    facts: tuple[OperatorBriefFact, ...]
    smb_shares: tuple[OperatorBriefSmbShareObservation, ...]
    services: tuple[OperatorBriefServiceObservation, ...]


def build_operator_brief_smb_share_observation(
    *,
    source_kind: str,
    source_id: str,
    host: str,
    port: int,
    share_name: str,
    share_type: str,
    comment: str,
    trigger_service_names: tuple[str, ...] = (),
    trigger_evidence_ids: tuple[str, ...] = (),
    trigger_artefact_references: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefSmbShareObservation:
    canonical_host = _host(host)
    canonical_port = _port(port)
    canonical_share_name = _required_text(share_name, "SMB share name")
    canonical_source_kind = _required_text(source_kind, "SMB source kind")
    canonical_source_id = _required_text(source_id, "SMB source ID")
    return OperatorBriefSmbShareObservation(
        observation_id=_stable_id(
            "SMB-OBS",
            (canonical_host, str(canonical_port), canonical_share_name),
        ),
        source_kind=canonical_source_kind,
        host=canonical_host,
        port=canonical_port,
        share_name=canonical_share_name,
        share_type=_optional_text(share_type),
        comment=_optional_text(comment),
        trigger_service_names=_text_membership(
            trigger_service_names,
            "SMB trigger service names",
        ),
        trigger_evidence_ids=_text_membership(
            trigger_evidence_ids,
            "SMB trigger evidence IDs",
        ),
        trigger_artefact_references=_text_membership(
            trigger_artefact_references,
            "SMB trigger artefact references",
        ),
        evidence_ids=_text_membership(evidence_ids, "SMB evidence IDs"),
        artefact_references=_text_membership(
            artefact_references,
            "SMB artefact references",
        ),
        source_references=(
            OperatorBriefSourceReference(
                source_kind=canonical_source_kind,
                source_id=canonical_source_id,
            ),
        ),
    )


def build_operator_brief_service_observation(
    *,
    source_kind: str,
    source_id: str,
    host: str,
    port: int,
    protocol: str,
    state: str,
    service: str | None,
    product: str | None,
    version: str | None,
    http_capable: bool,
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefServiceObservation:
    canonical_host = _host(host)
    canonical_port = _port(port)
    canonical_protocol = _required_text(protocol, "service protocol").casefold()
    canonical_state = _required_text(state, "service state").casefold()
    canonical_source_kind = _required_text(source_kind, "service source kind")
    canonical_source_id = _required_text(source_id, "service source ID")
    if not isinstance(http_capable, bool):
        raise ValueError("service HTTP capability must be boolean")
    return OperatorBriefServiceObservation(
        observation_id=_stable_id(
            "SERVICE-OBS",
            (canonical_host, str(canonical_port), canonical_protocol),
        ),
        source_kind=canonical_source_kind,
        host=canonical_host,
        port=canonical_port,
        protocol=canonical_protocol,
        state=canonical_state,
        service=_optional_text(service),
        product=_optional_text(product),
        version=_optional_text(version),
        http_capable=http_capable,
        evidence_ids=_text_membership(evidence_ids, "service evidence IDs"),
        artefact_references=_text_membership(
            artefact_references,
            "service artefact references",
        ),
        source_references=(
            OperatorBriefSourceReference(
                source_kind=canonical_source_kind,
                source_id=canonical_source_id,
            ),
        ),
    )


def build_operator_brief_network_inputs_from_project_state(
    project_state: ProjectState,
) -> OperatorBriefNetworkCompositionInput:
    if not isinstance(project_state, ProjectState):
        raise TypeError("network composition requires ProjectState")
    smb_shares = tuple(
        sorted(
            (
                build_operator_brief_smb_share_observation(
                    source_kind="project_state_smb_share",
                    source_id=_stable_id(
                        "PROJECT-SMB-SOURCE",
                        (
                            _host(share.host),
                            str(_port(share.port)),
                            _required_text(share.share_name, "SMB share name"),
                        ),
                    ),
                    host=share.host,
                    port=share.port,
                    share_name=share.share_name,
                    share_type=share.share_type,
                    comment=share.comment,
                    trigger_service_names=tuple(share.trigger_service_names),
                    trigger_evidence_ids=tuple(share.trigger_evidence_ids),
                    trigger_artefact_references=tuple(
                        _logical_artefact_reference(value, project_state.input_dir)
                        for value in share.trigger_source_files
                    ),
                    evidence_ids=tuple(share.evidence_ids),
                    artefact_references=(
                        _logical_artefact_reference(
                            share.source_file,
                            project_state.input_dir,
                        ),
                    ),
                )
                for share in project_state.smb_shares
            ),
            key=lambda item: item.observation_id,
        )
    )
    services = tuple(
        sorted(
            (
                build_operator_brief_service_observation(
                    source_kind="project_state_port_service",
                    source_id=_stable_id(
                        "PROJECT-SERVICE-SOURCE",
                        (
                            _host(service.host),
                            str(_port(service.port)),
                            _required_text(
                                service.protocol,
                                "service protocol",
                            ).casefold(),
                        ),
                    ),
                    host=service.host,
                    port=service.port,
                    protocol=service.protocol,
                    state=service.state,
                    service=service.service,
                    product=service.product,
                    version=service.version,
                    http_capable=is_http_capable_port_service(service),
                    evidence_ids=tuple(service.evidence_ids),
                    artefact_references=(
                        _logical_artefact_reference(
                            service.source_file,
                            project_state.input_dir,
                        ),
                    ),
                )
                for service in project_state.port_services
            ),
            key=lambda item: item.observation_id,
        )
    )
    return OperatorBriefNetworkCompositionInput(
        smb_shares=smb_shares,
        services=services,
    )


def combine_operator_brief_network_inputs(
    *inputs: OperatorBriefNetworkCompositionInput,
) -> OperatorBriefNetworkCompositionInput:
    if any(not isinstance(item, OperatorBriefNetworkCompositionInput) for item in inputs):
        raise TypeError("network combiner requires normalized composition inputs")
    smb_by_id: dict[str, OperatorBriefSmbShareObservation] = {}
    service_by_id: dict[str, OperatorBriefServiceObservation] = {}
    for inputs_item in inputs:
        for observation in inputs_item.smb_shares:
            existing = smb_by_id.get(observation.observation_id)
            smb_by_id[observation.observation_id] = (
                observation
                if existing is None
                else _combine_smb_observations(existing, observation)
            )
        for observation in inputs_item.services:
            existing = service_by_id.get(observation.observation_id)
            service_by_id[observation.observation_id] = (
                observation
                if existing is None
                else _combine_service_observations(existing, observation)
            )
    return OperatorBriefNetworkCompositionInput(
        smb_shares=tuple(smb_by_id[key] for key in sorted(smb_by_id)),
        services=tuple(service_by_id[key] for key in sorted(service_by_id)),
    )


def compose_operator_brief_network(
    inputs: OperatorBriefNetworkCompositionInput,
) -> OperatorBriefNetworkComposition:
    if not isinstance(inputs, OperatorBriefNetworkCompositionInput):
        raise TypeError("network composer requires normalized composition input")
    normalized = combine_operator_brief_network_inputs(inputs)
    smb_facts = {
        observation.observation_id: _smb_fact(observation)
        for observation in normalized.smb_shares
    }
    service_facts = {
        observation.observation_id: _service_fact(observation)
        for observation in normalized.services
    }
    smb_by_surface: dict[
        tuple[str, int],
        list[OperatorBriefSmbShareObservation],
    ] = {}
    for observation in normalized.smb_shares:
        smb_by_surface.setdefault(
            (observation.host, observation.port),
            [],
        ).append(observation)

    service_by_surface = {
        (observation.host, observation.port): observation
        for observation in normalized.services
        if _is_smb_service(observation)
    }
    matched_service_ids: set[str] = set()
    subjects: list[OperatorBriefNetworkSubject] = []
    for (host, port), shares in sorted(smb_by_surface.items()):
        service = service_by_surface.get((host, port))
        services = (service,) if service is not None else ()
        if service is not None:
            matched_service_ids.add(service.observation_id)
        subjects.append(
            _smb_subject(
                host,
                port,
                tuple(sorted(shares, key=lambda item: item.observation_id)),
                services,
                smb_facts,
                service_facts,
            )
        )

    for service in normalized.services:
        if service.observation_id in matched_service_ids:
            continue
        fact = service_facts[service.observation_id]
        subjects.append(
            OperatorBriefNetworkSubject(
                subject_id=_stable_id(
                    "NETWORK-SERVICE-SUBJECT",
                    (service.host, str(service.port), service.protocol),
                ),
                subject_kind=OperatorBriefSubjectKind.SERVICE_SURFACE,
                host=service.host,
                ports=(service.port,),
                protocols=(service.protocol,),
                smb_share_observation_ids=(),
                service_observation_ids=(service.observation_id,),
                fact_ids=(fact.fact_id,),
                evidence_ids=service.evidence_ids,
                artefact_references=service.artefact_references,
                source_references=service.source_references,
            )
        )

    facts = tuple(
        sorted(
            (*smb_facts.values(), *service_facts.values()),
            key=lambda item: item.fact_id,
        )
    )
    return OperatorBriefNetworkComposition(
        subjects=tuple(sorted(subjects, key=lambda item: item.subject_id)),
        facts=facts,
        smb_shares=normalized.smb_shares,
        services=normalized.services,
    )


def _stable_id(prefix: str, values: tuple[str, ...]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    digest = sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _combine_smb_observations(
    first: OperatorBriefSmbShareObservation,
    second: OperatorBriefSmbShareObservation,
) -> OperatorBriefSmbShareObservation:
    first_core = (
        first.source_kind,
        first.host,
        first.port,
        first.share_name,
        first.share_type,
        first.comment,
    )
    second_core = (
        second.source_kind,
        second.host,
        second.port,
        second.share_name,
        second.share_type,
        second.comment,
    )
    if first_core != second_core:
        raise ValueError("duplicate SMB observation has conflicting semantics")
    return replace(
        first,
        trigger_service_names=_union(
            first.trigger_service_names,
            second.trigger_service_names,
        ),
        trigger_evidence_ids=_union(
            first.trigger_evidence_ids,
            second.trigger_evidence_ids,
        ),
        trigger_artefact_references=_union(
            first.trigger_artefact_references,
            second.trigger_artefact_references,
        ),
        evidence_ids=_union(first.evidence_ids, second.evidence_ids),
        artefact_references=_union(
            first.artefact_references,
            second.artefact_references,
        ),
        source_references=tuple(
            sorted(set((*first.source_references, *second.source_references)))
        ),
    )


def _combine_service_observations(
    first: OperatorBriefServiceObservation,
    second: OperatorBriefServiceObservation,
) -> OperatorBriefServiceObservation:
    first_core = (
        first.source_kind,
        first.host,
        first.port,
        first.protocol,
        first.state,
        first.service,
        first.product,
        first.version,
        first.http_capable,
    )
    second_core = (
        second.source_kind,
        second.host,
        second.port,
        second.protocol,
        second.state,
        second.service,
        second.product,
        second.version,
        second.http_capable,
    )
    if first_core != second_core:
        raise ValueError("duplicate service observation has conflicting semantics")
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


def _union(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set((*first, *second))))


def _smb_fact(
    observation: OperatorBriefSmbShareObservation,
) -> OperatorBriefFact:
    return OperatorBriefFact(
        fact_id=_stable_id(
            "NETWORK-FACT",
            (OperatorBriefFactKind.SMB_SHARE.value, observation.observation_id),
        ),
        kind=OperatorBriefFactKind.SMB_SHARE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label=f"SMB share {observation.share_name}",
        summary=f"SMB share {observation.share_name} was observed.",
        endpoints=(f"{observation.host}:{observation.port}",),
        evidence_ids=observation.evidence_ids,
        artefact_references=observation.artefact_references,
        source_references=observation.source_references,
        share_name=observation.share_name,
        share_type=observation.share_type,
    )


def _service_fact(
    observation: OperatorBriefServiceObservation,
) -> OperatorBriefFact:
    service_label = observation.service or "unknown service"
    details = " ".join(
        value for value in (observation.product, observation.version) if value
    )
    summary = (
        f"{observation.protocol.upper()} service {service_label} was observed on "
        f"{observation.host}:{observation.port}."
    )
    if details:
        summary += f" Retained product/version context: {details}."
    return OperatorBriefFact(
        fact_id=_stable_id(
            "NETWORK-FACT",
            (OperatorBriefFactKind.SERVICE.value, observation.observation_id),
        ),
        kind=OperatorBriefFactKind.SERVICE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label=f"{observation.protocol.upper()} service {service_label}",
        summary=summary,
        endpoints=(
            f"{observation.host}:{observation.port}/{observation.protocol}",
        ),
        evidence_ids=observation.evidence_ids,
        artefact_references=observation.artefact_references,
        source_references=observation.source_references,
        service=observation.service,
    )


def _is_smb_service(observation: OperatorBriefServiceObservation) -> bool:
    return (
        observation.protocol == "tcp"
        and observation.state == "open"
        and observation.service.casefold() in {"microsoft-ds", "netbios-ssn"}
    )


def _smb_subject(
    host: str,
    port: int,
    shares: tuple[OperatorBriefSmbShareObservation, ...],
    services: tuple[OperatorBriefServiceObservation, ...],
    smb_facts: dict[str, OperatorBriefFact],
    service_facts: dict[str, OperatorBriefFact],
) -> OperatorBriefNetworkSubject:
    evidence_ids = {
        evidence_id
        for share in shares
        for evidence_id in (*share.evidence_ids, *share.trigger_evidence_ids)
    }
    evidence_ids.update(
        evidence_id for service in services for evidence_id in service.evidence_ids
    )
    artefact_references = {
        reference
        for share in shares
        for reference in (
            *share.artefact_references,
            *share.trigger_artefact_references,
        )
    }
    artefact_references.update(
        reference
        for service in services
        for reference in service.artefact_references
    )
    source_references = {
        reference
        for observation in (*shares, *services)
        for reference in observation.source_references
    }
    share_ids = tuple(share.observation_id for share in shares)
    service_ids = tuple(service.observation_id for service in services)
    return OperatorBriefNetworkSubject(
        subject_id=_stable_id(
            "NETWORK-SMB-SUBJECT",
            (host, str(port)),
        ),
        subject_kind=OperatorBriefSubjectKind.SMB_SURFACE,
        host=host,
        ports=(port,),
        protocols=tuple(sorted({service.protocol for service in services})),
        smb_share_observation_ids=share_ids,
        service_observation_ids=service_ids,
        fact_ids=tuple(
            sorted(
                (
                    *(smb_facts[item].fact_id for item in share_ids),
                    *(service_facts[item].fact_id for item in service_ids),
                )
            )
        ),
        evidence_ids=tuple(sorted(evidence_ids)),
        artefact_references=tuple(sorted(artefact_references)),
        source_references=tuple(sorted(source_references)),
    )


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonblank text")
    return value.strip()


def _optional_text(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("optional network semantics must be text or null")
    return value.strip()


def _host(value: object) -> str:
    text = _required_text(value, "network host")
    canonical = normalise_hostname(text)
    if not canonical:
        raise ValueError("network host must be nonblank")
    return canonical


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("network port must be a positive integer")
    return value


def _text_membership(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{label} must be a tuple")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} cannot contain blank values")
    return tuple(sorted(set(values)))


def _logical_artefact_reference(value: str, input_dir: str) -> str:
    text = _required_text(value, "network source artefact")
    source = Path(text)
    root = Path(_required_text(input_dir, "ProjectState input directory"))
    if source.is_absolute():
        try:
            source = source.relative_to(root)
        except ValueError as exc:
            raise ValueError("network source artefact is outside the project") from exc
    if ".." in source.parts or not source.parts:
        raise ValueError("network source artefact is unsafe")
    return PurePosixPath(*source.parts).as_posix()
