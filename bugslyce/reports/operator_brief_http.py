"""Standalone deterministic composition of retained Deep HTTP observations."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from typing import Iterable

from bugslyce.recon.deep_http_fingerprint_summary import (
    EMPTY_BODY_SHA256,
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.recon.http_route_relationships import canonical_relationship_url
from bugslyce.reports.operator_brief import (
    OperatorBriefConflict,
    OperatorBriefConflictKind,
    OperatorBriefConflictObservation,
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
)


_ARTEFACT_BY_COLLECTION_STAGE = {
    "metadata_collection": DEEP_METADATA_COLLECTION_JSON,
    "source_route_collection": DEEP_SOURCE_ROUTE_COLLECTION_JSON,
}
_FINGERPRINT_SOURCE_KIND = "deep_http_fingerprint"
_REPEATED_BODY_SOURCE_KIND = "deep_http_repeated_body_group"


@dataclass(frozen=True)
class OperatorBriefHttpObservation:
    """One normalized retained Deep HTTP response observation."""

    observation_id: str
    source_fingerprint_id: str
    endpoint: str
    final_url: str
    origin: HttpOrigin
    method: str
    status_code: int
    status_bucket: str
    body_sha256: str
    body_bytes: int
    body_empty: bool
    collection_stage: str
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]


@dataclass(frozen=True)
class OperatorBriefHttpExactEquivalence:
    """Authoritative exact non-empty response-body relationship."""

    equivalence_id: str
    source_repeated_body_group_id: str
    body_sha256: str
    observation_ids: tuple[str, ...]


@dataclass(frozen=True)
class OperatorBriefHttpCompositionInput:
    """Normalized Deep inputs accepted by the standalone HTTP composer."""

    observations: tuple[OperatorBriefHttpObservation, ...]
    exact_equivalences: tuple[OperatorBriefHttpExactEquivalence, ...]


@dataclass(frozen=True)
class OperatorBriefHttpSubject:
    """One provisional HTTP composition subject without rank or disposition."""

    subject_id: str
    observation_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    origins: tuple[str, ...]
    fact_ids: tuple[str, ...]
    conflict_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]


@dataclass(frozen=True)
class OperatorBriefHttpComposition:
    """Deterministic provisional HTTP subjects and their semantic records."""

    subjects: tuple[OperatorBriefHttpSubject, ...]
    facts: tuple[OperatorBriefFact, ...]
    conflicts: tuple[OperatorBriefConflict, ...]


def build_operator_brief_http_inputs_from_deep(
    summary: DeepHttpFingerprintSummary,
) -> OperatorBriefHttpCompositionInput:
    """Normalize the authoritative Deep HTTP summary for composition."""

    observations = tuple(
        sorted(
            (_observation_from_fingerprint(item) for item in summary.fingerprints),
            key=_observation_sort_key,
        )
    )
    observation_by_fingerprint = {
        item.source_fingerprint_id: item for item in observations
    }
    exact_equivalences: list[OperatorBriefHttpExactEquivalence] = []
    for group in summary.repeated_body_groups:
        try:
            members = tuple(
                observation_by_fingerprint[fingerprint_id]
                for fingerprint_id in group.fingerprint_ids
            )
        except KeyError as exc:
            raise ValueError(
                "Deep repeated-body group references an unknown fingerprint."
            ) from exc
        observation_ids = tuple(sorted(item.observation_id for item in members))
        exact_equivalences.append(
            OperatorBriefHttpExactEquivalence(
                equivalence_id=_semantic_id(
                    "HTTP-EQUIV",
                    (group.body_sha256, *observation_ids),
                ),
                source_repeated_body_group_id=group.repeated_body_id,
                body_sha256=group.body_sha256,
                observation_ids=observation_ids,
            )
        )
    return OperatorBriefHttpCompositionInput(
        observations=observations,
        exact_equivalences=tuple(
            sorted(exact_equivalences, key=lambda item: item.equivalence_id)
        ),
    )


def compose_operator_brief_http(
    inputs: OperatorBriefHttpCompositionInput,
) -> OperatorBriefHttpComposition:
    """Compose normalized Deep HTTP observations into provisional subjects."""

    observations = tuple(sorted(inputs.observations, key=_observation_sort_key))
    observation_by_id = {item.observation_id: item for item in observations}
    if len(observation_by_id) != len(observations):
        raise ValueError("Deep HTTP observations contain duplicate semantic IDs.")

    equivalences = tuple(
        sorted(inputs.exact_equivalences, key=lambda item: item.equivalence_id)
    )
    parent = {item.observation_id: item.observation_id for item in observations}
    for equivalence in equivalences:
        members = _equivalence_members(equivalence, observation_by_id)
        if _is_merge_candidate(equivalence, members):
            first_id = members[0].observation_id
            for member in members[1:]:
                _union(parent, first_id, member.observation_id)

    direct_facts = tuple(_direct_fact(item) for item in observations)
    direct_fact_by_observation_id = {
        observation.observation_id: fact
        for observation, fact in zip(observations, direct_facts, strict=True)
    }
    equivalence_facts = tuple(
        _equivalence_fact(item, _equivalence_members(item, observation_by_id))
        for item in equivalences
    )
    facts = tuple(
        sorted((*direct_facts, *equivalence_facts), key=_fact_sort_key)
    )
    conflicts = _build_status_conflicts(observations)

    grouped: dict[str, list[OperatorBriefHttpObservation]] = {}
    for observation in observations:
        grouped.setdefault(_find(parent, observation.observation_id), []).append(
            observation
        )
    provisional_subjects = tuple(
        sorted(
            (
                _subject(
                    tuple(members),
                    equivalences=equivalences,
                    direct_fact_by_observation_id=direct_fact_by_observation_id,
                    equivalence_facts=equivalence_facts,
                    conflicts=conflicts,
                )
                for members in grouped.values()
            ),
            key=lambda item: (item.endpoints, item.observation_ids, item.subject_id),
        )
    )
    subjects = _resolve_subject_id_collisions(provisional_subjects)
    return OperatorBriefHttpComposition(
        subjects=subjects,
        facts=facts,
        conflicts=conflicts,
    )


def _observation_from_fingerprint(
    fingerprint: DeepHttpResponseFingerprint,
) -> OperatorBriefHttpObservation:
    endpoint = canonical_relationship_url(fingerprint.requested_url)
    final_url = canonical_relationship_url(fingerprint.final_url)
    origin = http_origin_from_url(endpoint)
    if not endpoint or not final_url or origin is None:
        raise ValueError("Deep HTTP fingerprint contains an invalid HTTP endpoint.")
    try:
        artefact = _ARTEFACT_BY_COLLECTION_STAGE[fingerprint.collection_section]
    except KeyError as exc:
        raise ValueError("Deep HTTP fingerprint has an unknown collection stage.") from exc
    observation_id = _semantic_id(
        "HTTP-OBS",
        (
            fingerprint.collection_section,
            endpoint,
            final_url,
            fingerprint.method,
            str(fingerprint.status_code),
            fingerprint.body_sha256,
            str(fingerprint.body_bytes),
        ),
    )
    return OperatorBriefHttpObservation(
        observation_id=observation_id,
        source_fingerprint_id=fingerprint.fingerprint_id,
        endpoint=endpoint,
        final_url=final_url,
        origin=origin,
        method=fingerprint.method,
        status_code=fingerprint.status_code,
        status_bucket=fingerprint.status_bucket,
        body_sha256=fingerprint.body_sha256,
        body_bytes=fingerprint.body_bytes,
        body_empty=fingerprint.body_empty,
        collection_stage=fingerprint.collection_section,
        evidence_ids=tuple(sorted(set(fingerprint.evidence_ids))),
        artefact_references=(artefact,),
    )


def _direct_fact(observation: OperatorBriefHttpObservation) -> OperatorBriefFact:
    return OperatorBriefFact(
        fact_id=_semantic_id("HTTP-FACT", (observation.observation_id,)),
        kind=OperatorBriefFactKind.HTTP_RESPONSE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="Retained HTTP response",
        summary="Retained HTTP response with explicit method and status.",
        endpoints=(observation.endpoint,),
        origins=(observation.origin.origin_url,),
        evidence_ids=observation.evidence_ids,
        artefact_references=observation.artefact_references,
        source_references=(
            OperatorBriefSourceReference(
                source_kind=_FINGERPRINT_SOURCE_KIND,
                source_id=observation.source_fingerprint_id,
            ),
        ),
        route=observation.endpoint,
        body_sha256=observation.body_sha256,
        http_method=observation.method,
        http_status_code=observation.status_code,
    )


def _equivalence_fact(
    equivalence: OperatorBriefHttpExactEquivalence,
    members: tuple[OperatorBriefHttpObservation, ...],
) -> OperatorBriefFact:
    source_references = [
        OperatorBriefSourceReference(
            source_kind=_REPEATED_BODY_SOURCE_KIND,
            source_id=equivalence.source_repeated_body_group_id,
        )
    ]
    source_references.extend(
        OperatorBriefSourceReference(
            source_kind=_FINGERPRINT_SOURCE_KIND,
            source_id=item.source_fingerprint_id,
        )
        for item in members
    )
    return OperatorBriefFact(
        fact_id=_semantic_id("HTTP-EQUIV-FACT", (equivalence.equivalence_id,)),
        kind=OperatorBriefFactKind.RESPONSE_EQUIVALENCE,
        semantic_class=OperatorBriefSemanticClass.DERIVED,
        role=OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
        label="Exact retained response-body equivalence",
        summary="Retained response bodies have the same SHA-256.",
        endpoints=tuple(sorted({item.endpoint for item in members})),
        origins=tuple(sorted({item.origin.origin_url for item in members})),
        evidence_ids=_membership(item.evidence_ids for item in members),
        artefact_references=_membership(
            item.artefact_references for item in members
        ),
        source_references=tuple(source_references),
        body_sha256=equivalence.body_sha256,
    )


def _build_status_conflicts(
    observations: tuple[OperatorBriefHttpObservation, ...],
) -> tuple[OperatorBriefConflict, ...]:
    by_endpoint: dict[str, list[OperatorBriefHttpObservation]] = {}
    for observation in observations:
        by_endpoint.setdefault(observation.endpoint, []).append(observation)
    conflicts: list[OperatorBriefConflict] = []
    for endpoint, members in sorted(by_endpoint.items()):
        if len({item.status_code for item in members}) < 2:
            continue
        conflict_observations = tuple(
            OperatorBriefConflictObservation(
                observation_id=item.observation_id,
                endpoint=item.endpoint,
                method=item.method,
                status_code=item.status_code,
                collection_stage=item.collection_stage,
                evidence_ids=item.evidence_ids,
                artefact_references=item.artefact_references,
            )
            for item in sorted(
                members,
                key=lambda item: (
                    item.status_code,
                    item.method,
                    item.collection_stage,
                    item.observation_id,
                ),
            )
        )
        conflicts.append(
            OperatorBriefConflict(
                conflict_id=_semantic_id(
                    "HTTP-CONFLICT",
                    (endpoint, *(item.observation_id for item in conflict_observations)),
                ),
                kind=OperatorBriefConflictKind.DIFFERING_HTTP_STATUS,
                subject_endpoint=endpoint,
                observations=conflict_observations,
                summary=(
                    "Retained observations record differing HTTP status codes "
                    "for this endpoint."
                ),
            )
        )
    return tuple(conflicts)


def _subject(
    members: tuple[OperatorBriefHttpObservation, ...],
    *,
    equivalences: tuple[OperatorBriefHttpExactEquivalence, ...],
    direct_fact_by_observation_id: dict[str, OperatorBriefFact],
    equivalence_facts: tuple[OperatorBriefFact, ...],
    conflicts: tuple[OperatorBriefConflict, ...],
) -> OperatorBriefHttpSubject:
    ordered_members = tuple(sorted(members, key=_observation_sort_key))
    observation_ids = tuple(item.observation_id for item in ordered_members)
    observation_id_set = set(observation_ids)
    direct_facts = tuple(
        direct_fact_by_observation_id[item.observation_id]
        for item in ordered_members
    )
    relevant_equivalence_facts = tuple(
        fact
        for equivalence, fact in zip(equivalences, equivalence_facts, strict=True)
        if observation_id_set.intersection(equivalence.observation_ids)
    )
    relevant_conflicts = tuple(
        item
        for item in conflicts
        if item.subject_endpoint in {member.endpoint for member in ordered_members}
    )
    referenced_facts = (*direct_facts, *relevant_equivalence_facts)
    evidence_groups = [item.evidence_ids for item in ordered_members]
    evidence_groups.extend(item.evidence_ids for item in referenced_facts)
    evidence_groups.extend(
        observation.evidence_ids
        for conflict in relevant_conflicts
        for observation in conflict.observations
    )
    artefact_groups = [item.artefact_references for item in ordered_members]
    artefact_groups.extend(item.artefact_references for item in referenced_facts)
    artefact_groups.extend(
        observation.artefact_references
        for conflict in relevant_conflicts
        for observation in conflict.observations
    )
    subject_anchors = tuple(
        sorted({_subject_anchor(item) for item in ordered_members})
    )
    return OperatorBriefHttpSubject(
        subject_id=_semantic_id("HTTP-SUBJECT", subject_anchors),
        observation_ids=observation_ids,
        endpoints=tuple(sorted({item.endpoint for item in ordered_members})),
        origins=tuple(sorted({item.origin.origin_url for item in ordered_members})),
        fact_ids=tuple(sorted(item.fact_id for item in referenced_facts)),
        conflict_ids=tuple(sorted(item.conflict_id for item in relevant_conflicts)),
        evidence_ids=_membership(evidence_groups),
        artefact_references=_membership(artefact_groups),
    )


def _equivalence_members(
    equivalence: OperatorBriefHttpExactEquivalence,
    observation_by_id: dict[str, OperatorBriefHttpObservation],
) -> tuple[OperatorBriefHttpObservation, ...]:
    if len(equivalence.observation_ids) < 2:
        raise ValueError("Exact HTTP equivalence requires multiple observations.")
    if len(set(equivalence.observation_ids)) != len(equivalence.observation_ids):
        raise ValueError("Exact HTTP equivalence contains duplicate observations.")
    try:
        members = tuple(
            sorted(
                (observation_by_id[item] for item in equivalence.observation_ids),
                key=_observation_sort_key,
            )
        )
    except KeyError as exc:
        raise ValueError(
            "Exact HTTP equivalence references an unknown observation."
        ) from exc
    if any(item.body_sha256 != equivalence.body_sha256 for item in members):
        raise ValueError("Exact HTTP equivalence member digests do not match.")
    return members


def _is_merge_candidate(
    equivalence: OperatorBriefHttpExactEquivalence,
    members: tuple[OperatorBriefHttpObservation, ...],
) -> bool:
    return bool(
        len(members) > 1
        and equivalence.body_sha256 != EMPTY_BODY_SHA256
        and all(
            not item.body_empty
            and item.body_bytes > 0
            and item.body_sha256 == equivalence.body_sha256
            and 200 <= item.status_code <= 299
            and item.status_bucket == "2xx_success"
            for item in members
        )
        and len({item.origin for item in members}) == 1
        and len({item.method for item in members}) == 1
        and len({item.status_code for item in members}) == 1
    )


def _observation_sort_key(item: OperatorBriefHttpObservation) -> tuple:
    return (
        item.endpoint,
        item.collection_stage,
        item.method,
        item.status_code,
        item.final_url,
        item.body_sha256,
        item.observation_id,
    )


def _subject_anchor(item: OperatorBriefHttpObservation) -> str:
    return _semantic_id(
        "HTTP-SUBJECT-ANCHOR",
        (
            item.endpoint,
            item.final_url,
            item.method,
            str(item.status_code),
            item.body_sha256,
            str(item.body_bytes),
        ),
    )


def _resolve_subject_id_collisions(
    subjects: tuple[OperatorBriefHttpSubject, ...],
) -> tuple[OperatorBriefHttpSubject, ...]:
    by_base_id: dict[str, list[OperatorBriefHttpSubject]] = {}
    for subject in subjects:
        by_base_id.setdefault(subject.subject_id, []).append(subject)

    resolved: list[OperatorBriefHttpSubject] = []
    for base_id, members in sorted(by_base_id.items()):
        if len(members) == 1:
            resolved.extend(members)
            continue
        for subject in sorted(members, key=lambda item: item.observation_ids):
            resolved.append(
                replace(
                    subject,
                    subject_id=_semantic_id(
                        "HTTP-SUBJECT",
                        ("collision", base_id, *sorted(subject.observation_ids)),
                    ),
                )
            )

    final = tuple(
        sorted(
            resolved,
            key=lambda item: (item.endpoints, item.observation_ids, item.subject_id),
        )
    )
    if len({item.subject_id for item in final}) != len(final):
        raise ValueError("Deep HTTP composition contains duplicate subject IDs.")
    return final


def _fact_sort_key(item: OperatorBriefFact) -> tuple[str, str]:
    return item.kind.value, item.fact_id


def _find(parent: dict[str, str], item: str) -> str:
    while parent[item] != item:
        parent[item] = parent[parent[item]]
        item = parent[item]
    return item


def _union(parent: dict[str, str], first: str, second: str) -> None:
    first_root = _find(parent, first)
    second_root = _find(parent, second)
    if first_root == second_root:
        return
    low, high = sorted((first_root, second_root))
    parent[high] = low


def _membership(values: Iterable[tuple[str, ...]]) -> tuple[str, ...]:
    return tuple(sorted({value for group in values for value in group}))


def _semantic_id(prefix: str, values: tuple[str, ...]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    digest = sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"
