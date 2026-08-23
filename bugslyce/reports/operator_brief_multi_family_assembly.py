"""Pure assembly of normalized evidence families into thread-policy subjects."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import TypeVar

from bugslyce.reports.operator_brief import (
    OperatorBriefConflict,
    OperatorBriefFact,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpComposition,
    OperatorBriefHttpSubject,
)
from bugslyce.reports.operator_brief_network import (
    OperatorBriefNetworkComposition,
    OperatorBriefNetworkSubject,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefWebContextComposition,
    OperatorBriefWebContextSubject,
)


_IdentifiedValue = TypeVar("_IdentifiedValue")


def _semantic_key(family: str, subject_id: str) -> str:
    return f"{family}:{subject_id}"


def _policy_key(
    subject_kind: OperatorBriefSubjectKind,
    semantic_subject_key: str,
) -> str:
    payload = json.dumps(
        {
            "semantic_subject_key": semantic_subject_key,
            "subject_kind": subject_kind.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = sha256(payload.encode("utf-8")).hexdigest()[:16].upper()
    return f"POLICY-{digest}"


def _validate_subject_ids(family: str, subjects: tuple[object, ...]) -> None:
    subject_ids = tuple(getattr(subject, "subject_id") for subject in subjects)
    if len(set(subject_ids)) != len(subject_ids):
        raise ValueError(f"{family} composition contains duplicate subject IDs.")


def _lookup_by_id(
    values: tuple[_IdentifiedValue, ...],
    *,
    id_name: str,
    label: str,
) -> dict[str, _IdentifiedValue]:
    lookup = {getattr(item, id_name): item for item in values}
    if len(lookup) != len(values):
        raise ValueError(f"{label} contains duplicate IDs.")
    return lookup


def _resolve(
    identifiers: tuple[str, ...],
    lookup: dict[str, _IdentifiedValue],
    *,
    label: str,
    id_name: str,
) -> tuple[_IdentifiedValue, ...]:
    if len(set(identifiers)) != len(identifiers):
        raise ValueError(f"{label} contains duplicate references.")
    try:
        values = tuple(lookup[identifier] for identifier in identifiers)
    except KeyError as exc:
        raise ValueError(f"{label} references an unknown ID.") from exc
    return tuple(sorted(values, key=lambda item: getattr(item, id_name)))


def _evidence_basis(
    facts: tuple[OperatorBriefFact, ...],
) -> OperatorBriefThreadEvidenceBasis:
    direct = False
    derived = False
    for fact in facts:
        if fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE:
            if fact.semantic_class is not OperatorBriefSemanticClass.OBSERVED:
                raise ValueError("Direct facts require observed semantics.")
            direct = True
        elif fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT:
            if fact.semantic_class is not OperatorBriefSemanticClass.DERIVED:
                raise ValueError("Relationship facts require derived semantics.")
            derived = True
        else:
            raise ValueError("Normalized subject contains an unsupported fact role.")
    if direct:
        return OperatorBriefThreadEvidenceBasis.DIRECT
    if derived:
        return OperatorBriefThreadEvidenceBasis.DERIVED
    raise ValueError("Normalized subject requires at least one referenced fact.")


def _policy_subject(
    *,
    family: str,
    subject_id: str,
    subject_kind: OperatorBriefSubjectKind,
    materiality: OperatorBriefThreadMateriality,
    specificity: OperatorBriefThreadSpecificity,
    independent: bool,
    facts: tuple[OperatorBriefFact, ...],
    conflicts: tuple[OperatorBriefConflict, ...] = (),
    associated_subject_reference: (
        OperatorBriefThreadPolicySubjectReference | None
    ) = None,
) -> OperatorBriefThreadPolicySubject:
    semantic_subject_key = _semantic_key(family, subject_id)
    return OperatorBriefThreadPolicySubject(
        policy_key=_policy_key(subject_kind, semantic_subject_key),
        semantic_subject_key=semantic_subject_key,
        subject_kind=subject_kind,
        materiality=materiality,
        specificity=specificity,
        evidence_basis=_evidence_basis(facts),
        independent=independent,
        associated_subject_reference=associated_subject_reference,
        replaced_by_subject_reference=None,
        facts=facts,
        conflicts=conflicts,
        coverage_limitations=(),
        source_rankings=(),
        source_lead_ids=(),
    )


def _http_subjects(
    composition: OperatorBriefHttpComposition,
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    fact_by_id = _lookup_by_id(
        composition.facts,
        id_name="fact_id",
        label="HTTP facts",
    )
    conflict_by_id = _lookup_by_id(
        composition.conflicts,
        id_name="conflict_id",
        label="HTTP conflicts",
    )
    projected = []
    for subject in composition.subjects:
        facts = _resolve(
            subject.fact_ids,
            fact_by_id,
            label="HTTP subject facts",
            id_name="fact_id",
        )
        if _evidence_basis(facts) is not OperatorBriefThreadEvidenceBasis.DIRECT:
            raise ValueError("HTTP subjects require direct normalized evidence.")
        conflicts = _resolve(
            subject.conflict_ids,
            conflict_by_id,
            label="HTTP subject conflicts",
            id_name="conflict_id",
        )
        projected.append(
            _policy_subject(
                family="http",
                subject_id=subject.subject_id,
                subject_kind=OperatorBriefSubjectKind.APPLICATION,
                materiality=OperatorBriefThreadMateriality.MATERIAL,
                specificity=OperatorBriefThreadSpecificity.SPECIFIC,
                independent=True,
                facts=facts,
                conflicts=conflicts,
            )
        )
    return tuple(projected)


def _network_subjects(
    composition: OperatorBriefNetworkComposition,
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    fact_by_id = _lookup_by_id(
        composition.facts,
        id_name="fact_id",
        label="network facts",
    )
    projected = []
    for subject in composition.subjects:
        facts = _resolve(
            subject.fact_ids,
            fact_by_id,
            label="network subject facts",
            id_name="fact_id",
        )
        if _evidence_basis(facts) is not OperatorBriefThreadEvidenceBasis.DIRECT:
            raise ValueError("Network subjects require direct normalized evidence.")
        if subject.subject_kind is OperatorBriefSubjectKind.SMB_SURFACE:
            specificity = OperatorBriefThreadSpecificity.SPECIFIC
        elif subject.subject_kind is OperatorBriefSubjectKind.SERVICE_SURFACE:
            specificity = OperatorBriefThreadSpecificity.GENERAL
        else:
            raise ValueError("Network subject kind is unsupported by normalized assembly.")
        projected.append(
            _policy_subject(
                family="network",
                subject_id=subject.subject_id,
                subject_kind=subject.subject_kind,
                materiality=OperatorBriefThreadMateriality.MATERIAL,
                specificity=specificity,
                independent=True,
                facts=facts,
            )
        )
    return tuple(projected)


def _matching_http_subjects(
    web_subject: OperatorBriefWebContextSubject,
    http_subjects: tuple[OperatorBriefHttpSubject, ...],
) -> tuple[OperatorBriefHttpSubject, ...]:
    return tuple(
        subject for subject in http_subjects if web_subject.origin in subject.origins
    )


def _web_subjects(
    composition: OperatorBriefWebContextComposition,
    http_subjects: tuple[OperatorBriefHttpSubject, ...],
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    fact_by_id = _lookup_by_id(
        composition.facts,
        id_name="fact_id",
        label="web-context facts",
    )
    projected = []
    for subject in composition.subjects:
        if subject.subject_kind is not OperatorBriefSubjectKind.CONTENT_SURFACE:
            raise ValueError("Web-context subject kind is unsupported by assembly.")
        facts = _resolve(
            subject.fact_ids,
            fact_by_id,
            label="web-context subject facts",
            id_name="fact_id",
        )
        basis = _evidence_basis(facts)
        matches = _matching_http_subjects(subject, http_subjects)
        if basis is OperatorBriefThreadEvidenceBasis.DIRECT and len(matches) == 1:
            materiality = OperatorBriefThreadMateriality.CONTEXT
            specificity = OperatorBriefThreadSpecificity.SPECIFIC
            independent = False
            association = OperatorBriefThreadPolicySubjectReference(
                subject_kind=OperatorBriefSubjectKind.APPLICATION,
                semantic_subject_key=_semantic_key("http", matches[0].subject_id),
            )
        elif basis is OperatorBriefThreadEvidenceBasis.DIRECT:
            materiality = OperatorBriefThreadMateriality.MATERIAL
            specificity = OperatorBriefThreadSpecificity.SPECIFIC
            independent = True
            association = None
        else:
            materiality = OperatorBriefThreadMateriality.CONTEXT
            specificity = OperatorBriefThreadSpecificity.GENERAL
            independent = False
            association = None
        projected.append(
            _policy_subject(
                family="web",
                subject_id=subject.subject_id,
                subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
                materiality=materiality,
                specificity=specificity,
                independent=independent,
                facts=facts,
                associated_subject_reference=association,
            )
        )
    return tuple(projected)


def assemble_operator_brief_policy_subjects(
    *,
    http: OperatorBriefHttpComposition,
    network: OperatorBriefNetworkComposition,
    web_context: OperatorBriefWebContextComposition,
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    """Project normalized family subjects into canonical thread-policy inputs."""

    if not isinstance(http, OperatorBriefHttpComposition):
        raise TypeError("normalized assembly requires an HTTP composition")
    if not isinstance(network, OperatorBriefNetworkComposition):
        raise TypeError("normalized assembly requires a network composition")
    if not isinstance(web_context, OperatorBriefWebContextComposition):
        raise TypeError("normalized assembly requires a web-context composition")

    _validate_subject_ids("HTTP", http.subjects)
    _validate_subject_ids("network", network.subjects)
    _validate_subject_ids("web-context", web_context.subjects)

    subjects = (
        *_http_subjects(http),
        *_network_subjects(network),
        *_web_subjects(web_context, http.subjects),
    )
    ordered = tuple(sorted(subjects, key=lambda subject: subject.policy_key))
    if len({subject.policy_key for subject in ordered}) != len(ordered):
        raise ValueError("Normalized assembly produced duplicate policy keys.")
    return ordered
