"""Standalone deterministic composition of retained HTTP evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from typing import Iterable, TypeAlias

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
class OperatorBriefHttpRetainedBodyObservation:
    """One endpoint-associated retained body without response semantics."""

    observation_id: str
    source_kind: str
    endpoint: str
    origin: HttpOrigin
    body_sha256: str
    body_bytes: int
    body_empty: bool
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]

    def __post_init__(self) -> None:
        if not self.observation_id.strip() or not self.source_kind.strip():
            raise ValueError("Retained HTTP content requires semantic identities.")
        if not self.endpoint or self.origin != http_origin_from_url(self.endpoint):
            raise ValueError(
                "Retained HTTP content requires a canonical HTTP endpoint."
            )
        if not self.body_sha256.strip():
            raise ValueError("Retained HTTP content requires a body digest.")
        if (
            isinstance(self.body_bytes, bool)
            or not isinstance(self.body_bytes, int)
            or self.body_bytes < 0
        ):
            raise ValueError("Retained HTTP content byte count must be non-negative.")
        if self.body_empty != (self.body_bytes == 0):
            raise ValueError("Retained HTTP content empty state must match byte count.")


_HttpMember: TypeAlias = (
    OperatorBriefHttpObservation | OperatorBriefHttpRetainedBodyObservation
)


@dataclass(frozen=True)
class OperatorBriefHttpExactEquivalence:
    """Authoritative exact retained-body relationship."""

    equivalence_id: str
    body_sha256: str
    observation_ids: tuple[str, ...]
    authority_references: tuple[OperatorBriefSourceReference, ...]

    def __post_init__(self) -> None:
        if not self.equivalence_id.strip() or not self.body_sha256.strip():
            raise ValueError("Exact HTTP equivalence requires semantic identities.")
        if not self.authority_references:
            raise ValueError("Exact HTTP equivalence requires authority provenance.")
        deep_ids = {
            item.source_id
            for item in self.authority_references
            if item.source_kind == _REPEATED_BODY_SOURCE_KIND
        }
        if len(deep_ids) > 1:
            raise ValueError("Exact HTTP equivalence has ambiguous Deep authority.")

    @property
    def source_repeated_body_group_id(self) -> str | None:
        deep_ids = {
            item.source_id
            for item in self.authority_references
            if item.source_kind == _REPEATED_BODY_SOURCE_KIND
        }
        return next(iter(deep_ids)) if deep_ids else None


@dataclass(frozen=True)
class OperatorBriefHttpCompositionInput:
    """Normalized inputs accepted by the standalone HTTP composer."""

    observations: tuple[OperatorBriefHttpObservation, ...]
    exact_equivalences: tuple[OperatorBriefHttpExactEquivalence, ...]
    retained_content: tuple[OperatorBriefHttpRetainedBodyObservation, ...] = ()


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


def build_operator_brief_http_retained_body_observation(
    *,
    source_kind: str,
    source_id: str,
    endpoint: str,
    body_sha256: str,
    body_bytes: int,
    evidence_ids: tuple[str, ...] = (),
    artefact_references: tuple[str, ...] = (),
) -> OperatorBriefHttpRetainedBodyObservation:
    """Build one normalized partial retained-body observation."""

    if not isinstance(source_kind, str) or not source_kind.strip():
        raise ValueError("Retained HTTP content requires a source kind.")
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("Retained HTTP content requires a source ID.")
    if isinstance(body_bytes, bool) or not isinstance(body_bytes, int):
        raise ValueError("Retained HTTP content byte count must be an integer.")
    canonical_endpoint = canonical_relationship_url(endpoint)
    origin = http_origin_from_url(canonical_endpoint)
    if not canonical_endpoint or origin is None:
        raise ValueError("Retained HTTP content contains an invalid HTTP endpoint.")
    evidence = _normalised_membership(evidence_ids, "evidence IDs")
    artefacts = _normalised_membership(
        artefact_references, "artefact references"
    )
    return OperatorBriefHttpRetainedBodyObservation(
        observation_id=_semantic_id(
            "HTTP-RETAINED",
            (
                source_kind,
                canonical_endpoint,
                body_sha256,
                str(body_bytes),
            ),
        ),
        source_kind=source_kind,
        endpoint=canonical_endpoint,
        origin=origin,
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        body_empty=body_bytes == 0,
        evidence_ids=evidence,
        artefact_references=artefacts,
        source_references=(OperatorBriefSourceReference(source_kind, source_id),),
    )


def build_operator_brief_http_exact_equivalence(
    *,
    body_sha256: str,
    observation_ids: tuple[str, ...],
    authority_references: tuple[OperatorBriefSourceReference, ...],
) -> OperatorBriefHttpExactEquivalence:
    """Build one generic exact retained-byte relationship."""

    if not isinstance(body_sha256, str) or not body_sha256.strip():
        raise ValueError("Exact HTTP equivalence requires a body digest.")
    member_ids = _normalised_membership(observation_ids, "observation IDs")
    if len(observation_ids) < 2:
        raise ValueError("Exact HTTP equivalence requires multiple observations.")
    if len(set(observation_ids)) != len(observation_ids):
        raise ValueError("Exact HTTP equivalence contains duplicate observations.")
    authorities = tuple(sorted(set(authority_references)))
    return OperatorBriefHttpExactEquivalence(
        equivalence_id=_semantic_id(
            "HTTP-EQUIV", (body_sha256, *member_ids)
        ),
        body_sha256=body_sha256,
        observation_ids=member_ids,
        authority_references=authorities,
    )


def combine_operator_brief_http_inputs(
    *inputs: OperatorBriefHttpCompositionInput,
) -> OperatorBriefHttpCompositionInput:
    """Combine independently normalized HTTP composition inputs."""

    observations_by_id: dict[str, OperatorBriefHttpObservation] = {}
    retained_by_id: dict[str, OperatorBriefHttpRetainedBodyObservation] = {}
    equivalences_by_id: dict[str, OperatorBriefHttpExactEquivalence] = {}
    for source in inputs:
        for observation in source.observations:
            existing = observations_by_id.get(observation.observation_id)
            if existing is not None and existing != observation:
                raise ValueError(
                    "Complete HTTP observations contain a conflicting semantic ID."
                )
            observations_by_id[observation.observation_id] = observation
        for retained in source.retained_content:
            existing = retained_by_id.get(retained.observation_id)
            if existing is None:
                retained_by_id[retained.observation_id] = retained
                continue
            if _retained_semantic_core(existing) != _retained_semantic_core(
                retained
            ):
                raise ValueError(
                    "Retained HTTP content contains a conflicting semantic ID."
                )
            retained_by_id[retained.observation_id] = replace(
                existing,
                evidence_ids=_membership(
                    (existing.evidence_ids, retained.evidence_ids)
                ),
                artefact_references=_membership(
                    (
                        existing.artefact_references,
                        retained.artefact_references,
                    )
                ),
                source_references=tuple(
                    sorted(
                        set(existing.source_references)
                        | set(retained.source_references)
                    )
                ),
            )
        for equivalence in source.exact_equivalences:
            existing = equivalences_by_id.get(equivalence.equivalence_id)
            if existing is None:
                equivalences_by_id[equivalence.equivalence_id] = equivalence
                continue
            if _equivalence_semantic_core(existing) != _equivalence_semantic_core(
                equivalence
            ):
                raise ValueError(
                    "Exact HTTP equivalences contain a conflicting semantic ID."
                )
            equivalences_by_id[equivalence.equivalence_id] = replace(
                existing,
                authority_references=tuple(
                    sorted(
                        set(existing.authority_references)
                        | set(equivalence.authority_references)
                    )
                ),
            )

    if set(observations_by_id).intersection(retained_by_id):
        raise ValueError("HTTP member types contain a conflicting semantic ID.")
    return OperatorBriefHttpCompositionInput(
        observations=tuple(
            sorted(observations_by_id.values(), key=_observation_sort_key)
        ),
        exact_equivalences=tuple(
            sorted(
                equivalences_by_id.values(),
                key=lambda item: item.equivalence_id,
            )
        ),
        retained_content=tuple(
            sorted(retained_by_id.values(), key=_retained_sort_key)
        ),
    )


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
            build_operator_brief_http_exact_equivalence(
                body_sha256=group.body_sha256,
                observation_ids=observation_ids,
                authority_references=(
                    OperatorBriefSourceReference(
                        _REPEATED_BODY_SOURCE_KIND, group.repeated_body_id
                    ),
                ),
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
    """Compose normalized HTTP observations into provisional subjects."""

    observations = tuple(sorted(inputs.observations, key=_observation_sort_key))
    retained_content = tuple(
        sorted(inputs.retained_content, key=_retained_sort_key)
    )
    members: tuple[_HttpMember, ...] = (*observations, *retained_content)
    member_by_id = {item.observation_id: item for item in members}
    if len(member_by_id) != len(members):
        raise ValueError("HTTP composition inputs contain duplicate semantic IDs.")

    equivalences = tuple(
        sorted(inputs.exact_equivalences, key=lambda item: item.equivalence_id)
    )
    parent = {item.observation_id: item.observation_id for item in members}
    for equivalence in equivalences:
        equivalence_members = _equivalence_members(equivalence, member_by_id)
        if _is_merge_candidate(equivalence, equivalence_members):
            first_id = equivalence_members[0].observation_id
            for member in equivalence_members[1:]:
                _union(parent, first_id, member.observation_id)

    direct_facts = tuple(_direct_fact(item) for item in observations) + tuple(
        _retained_direct_fact(item) for item in retained_content
    )
    direct_fact_by_observation_id = {
        observation.observation_id: fact
        for observation, fact in zip(members, direct_facts, strict=True)
    }
    equivalence_facts = tuple(
        _equivalence_fact(item, _equivalence_members(item, member_by_id))
        for item in equivalences
    )
    facts = tuple(
        sorted((*direct_facts, *equivalence_facts), key=_fact_sort_key)
    )
    conflicts = _build_status_conflicts(observations)

    grouped: dict[str, list[_HttpMember]] = {}
    for observation in members:
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


def _retained_direct_fact(
    observation: OperatorBriefHttpRetainedBodyObservation,
) -> OperatorBriefFact:
    return OperatorBriefFact(
        fact_id=_semantic_id("HTTP-RETAINED-FACT", (observation.observation_id,)),
        kind=OperatorBriefFactKind.RETAINED_CONTENT,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="Retained HTTP content",
        summary="Exact retained content associated with an HTTP endpoint.",
        endpoints=(observation.endpoint,),
        origins=(observation.origin.origin_url,),
        evidence_ids=observation.evidence_ids,
        artefact_references=observation.artefact_references,
        source_references=observation.source_references,
        route=observation.endpoint,
        body_sha256=observation.body_sha256,
    )


def _equivalence_fact(
    equivalence: OperatorBriefHttpExactEquivalence,
    members: tuple[_HttpMember, ...],
) -> OperatorBriefFact:
    source_references = list(equivalence.authority_references)
    source_references.extend(
        reference
        for item in members
        for reference in _member_source_references(item)
    )
    return OperatorBriefFact(
        fact_id=_semantic_id("HTTP-EQUIV-FACT", (equivalence.equivalence_id,)),
        kind=OperatorBriefFactKind.RESPONSE_EQUIVALENCE,
        semantic_class=OperatorBriefSemanticClass.DERIVED,
        role=OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
        label="Exact retained-body equivalence",
        summary="Retained body bytes have the same SHA-256.",
        endpoints=tuple(sorted({item.endpoint for item in members})),
        origins=tuple(sorted({item.origin.origin_url for item in members})),
        evidence_ids=_membership(item.evidence_ids for item in members),
        artefact_references=_membership(
            item.artefact_references for item in members
        ),
        source_references=tuple(sorted(set(source_references))),
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
    members: tuple[_HttpMember, ...],
    *,
    equivalences: tuple[OperatorBriefHttpExactEquivalence, ...],
    direct_fact_by_observation_id: dict[str, OperatorBriefFact],
    equivalence_facts: tuple[OperatorBriefFact, ...],
    conflicts: tuple[OperatorBriefConflict, ...],
) -> OperatorBriefHttpSubject:
    ordered_members = tuple(sorted(members, key=_member_sort_key))
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
    observation_by_id: dict[str, _HttpMember],
) -> tuple[_HttpMember, ...]:
    if len(equivalence.observation_ids) < 2:
        raise ValueError("Exact HTTP equivalence requires multiple observations.")
    if len(set(equivalence.observation_ids)) != len(equivalence.observation_ids):
        raise ValueError("Exact HTTP equivalence contains duplicate observations.")
    try:
        members = tuple(
            sorted(
                (observation_by_id[item] for item in equivalence.observation_ids),
                key=_member_sort_key,
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
    members: tuple[_HttpMember, ...],
) -> bool:
    return bool(
        len(members) > 1
        and equivalence.body_sha256 != EMPTY_BODY_SHA256
        and all(isinstance(item, OperatorBriefHttpObservation) for item in members)
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


def _retained_sort_key(
    item: OperatorBriefHttpRetainedBodyObservation,
) -> tuple:
    return (
        item.endpoint,
        item.source_kind,
        item.body_sha256,
        item.body_bytes,
        item.observation_id,
    )


def _member_sort_key(item: _HttpMember) -> tuple:
    if isinstance(item, OperatorBriefHttpObservation):
        return (0, *_observation_sort_key(item))
    return (1, *_retained_sort_key(item))


def _subject_anchor(item: _HttpMember) -> str:
    if isinstance(item, OperatorBriefHttpRetainedBodyObservation):
        return _semantic_id(
            "HTTP-RETAINED-SUBJECT-ANCHOR", (item.observation_id,)
        )
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


def _member_source_references(
    item: _HttpMember,
) -> tuple[OperatorBriefSourceReference, ...]:
    if isinstance(item, OperatorBriefHttpRetainedBodyObservation):
        return item.source_references
    return (
        OperatorBriefSourceReference(
            source_kind=_FINGERPRINT_SOURCE_KIND,
            source_id=item.source_fingerprint_id,
        ),
    )


def _retained_semantic_core(
    item: OperatorBriefHttpRetainedBodyObservation,
) -> tuple:
    return (
        item.source_kind,
        item.endpoint,
        item.origin,
        item.body_sha256,
        item.body_bytes,
        item.body_empty,
    )


def _equivalence_semantic_core(
    item: OperatorBriefHttpExactEquivalence,
) -> tuple[str, tuple[str, ...]]:
    return item.body_sha256, item.observation_ids


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
        raise ValueError("HTTP composition contains duplicate subject IDs.")
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


def _normalised_membership(
    values: tuple[str, ...], label: str
) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"HTTP composition {label} cannot contain blanks.")
    return tuple(sorted(set(values)))


def _semantic_id(prefix: str, values: tuple[str, ...]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    digest = sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"
