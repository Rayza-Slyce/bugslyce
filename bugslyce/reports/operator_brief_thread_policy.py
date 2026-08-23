"""Pure deterministic policy for assembled Operator Brief subjects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json

from bugslyce.reports.operator_brief import (
    DEPRIORITISED_CONTEXT,
    EVIDENCE_ONLY,
    PRIMARY_THREAD,
    SUPPORTING_CONTEXT,
    OperatorBriefConflict,
    OperatorBriefCoverageLimitation,
    OperatorBriefFact,
    OperatorBriefSourceRanking,
    OperatorBriefSubjectKind,
)


class OperatorBriefThreadMateriality(str, Enum):
    MATERIAL = "material"
    CONTEXT = "context"
    EVIDENCE_ONLY = "evidence_only"


class OperatorBriefThreadSpecificity(str, Enum):
    SPECIFIC = "specific"
    GENERAL = "general"


class OperatorBriefThreadEvidenceBasis(str, Enum):
    DIRECT = "direct"
    DERIVED = "derived"
    LEGACY = "legacy"


class OperatorBriefAttentionSignal(str, Enum):
    SPECIFIC_DIRECT = "specific_direct"
    GENERAL_DIRECT = "general_direct"
    SPECIFIC_LEGACY = "specific_legacy"
    GENERAL_LEGACY = "general_legacy"
    SPECIFIC_DERIVED = "specific_derived"
    GENERAL_DERIVED = "general_derived"
    EVIDENCE_ONLY = "evidence_only"


class OperatorBriefThreadPolicyReason(str, Enum):
    MATERIAL_INDEPENDENT = "material_independent"
    ASSOCIATED_CONTEXT = "associated_context"
    UNASSOCIATED_CONTEXT = "unassociated_context"
    RETAINED_EVIDENCE_ONLY = "retained_evidence_only"
    SPECIFIC_EVIDENCE = "specific_evidence"
    GENERAL_EVIDENCE = "general_evidence"
    DIRECT_EVIDENCE = "direct_evidence"
    DERIVED_CONTEXT = "derived_context"
    LEGACY_MATERIAL = "legacy_material"
    NORMALIZED_REPLACEMENT = "normalized_replacement"
    CONFLICTING_OBSERVATIONS = "conflicting_observations"
    COVERAGE_LIMITED = "coverage_limited"
    SEMANTIC_TIEBREAK = "semantic_tiebreak"
    STABLE_IDENTITY_MISSING = "stable_identity_missing"


_VALID_DISPOSITIONS = frozenset(
    {PRIMARY_THREAD, SUPPORTING_CONTEXT, DEPRIORITISED_CONTEXT, EVIDENCE_ONLY}
)
_REASON_ORDER = {
    reason: index for index, reason in enumerate(OperatorBriefThreadPolicyReason)
}


def _nonblank(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} cannot be blank.")
    return value


def _optional_nonblank(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    return _nonblank(value, label)


def _canonical_items(values: tuple[object, ...], item_type: type, id_name: str, label: str):
    if any(not isinstance(item, item_type) for item in values):
        raise ValueError(f"{label} are invalid.")
    identifiers = [getattr(item, id_name) for item in values]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError(f"{label} contain duplicate identities.")
    return tuple(sorted(values, key=lambda item: getattr(item, id_name)))


@dataclass(frozen=True)
class OperatorBriefThreadPolicySubjectReference:
    """Composite semantic identity for one assembled policy subject."""

    subject_kind: OperatorBriefSubjectKind
    semantic_subject_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.subject_kind, OperatorBriefSubjectKind):
            raise ValueError("Operator Brief policy reference subject kind is invalid.")
        _nonblank(
            self.semantic_subject_key,
            "Operator Brief policy reference semantic subject key",
        )


@dataclass(frozen=True)
class OperatorBriefThreadPolicySubject:
    """One assembly-resolved semantic subject supplied to thread policy."""

    policy_key: str
    semantic_subject_key: str | None
    subject_kind: OperatorBriefSubjectKind
    materiality: OperatorBriefThreadMateriality
    specificity: OperatorBriefThreadSpecificity
    evidence_basis: OperatorBriefThreadEvidenceBasis
    independent: bool
    associated_subject_reference: (
        OperatorBriefThreadPolicySubjectReference | None
    ) = None
    replaced_by_subject_reference: (
        OperatorBriefThreadPolicySubjectReference | None
    ) = None
    facts: tuple[OperatorBriefFact, ...] = ()
    conflicts: tuple[OperatorBriefConflict, ...] = ()
    coverage_limitations: tuple[OperatorBriefCoverageLimitation, ...] = ()
    source_rankings: tuple[OperatorBriefSourceRanking, ...] = ()
    source_lead_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _nonblank(self.policy_key, "Operator Brief policy key")
        _optional_nonblank(
            self.semantic_subject_key, "Operator Brief semantic subject key"
        )
        if not isinstance(self.subject_kind, OperatorBriefSubjectKind):
            raise ValueError("Operator Brief policy subject kind is invalid.")
        if not isinstance(self.materiality, OperatorBriefThreadMateriality):
            raise ValueError("Operator Brief policy materiality is invalid.")
        if not isinstance(self.specificity, OperatorBriefThreadSpecificity):
            raise ValueError("Operator Brief policy specificity is invalid.")
        if not isinstance(self.evidence_basis, OperatorBriefThreadEvidenceBasis):
            raise ValueError("Operator Brief policy evidence basis is invalid.")
        if not isinstance(self.independent, bool):
            raise ValueError("Operator Brief policy independence must be boolean.")
        if self.associated_subject_reference is not None and not isinstance(
            self.associated_subject_reference,
            OperatorBriefThreadPolicySubjectReference,
        ):
            raise ValueError("Operator Brief policy association reference is invalid.")
        if self.replaced_by_subject_reference is not None and not isinstance(
            self.replaced_by_subject_reference,
            OperatorBriefThreadPolicySubjectReference,
        ):
            raise ValueError("Operator Brief policy replacement reference is invalid.")

        facts = _canonical_items(
            self.facts, OperatorBriefFact, "fact_id", "Operator Brief policy facts"
        )
        conflicts = _canonical_items(
            self.conflicts,
            OperatorBriefConflict,
            "conflict_id",
            "Operator Brief policy conflicts",
        )
        limitations = _canonical_items(
            self.coverage_limitations,
            OperatorBriefCoverageLimitation,
            "limitation_id",
            "Operator Brief policy coverage limitations",
        )
        rankings = _canonical_items(
            self.source_rankings,
            OperatorBriefSourceRanking,
            "source_lead_id",
            "Operator Brief policy source rankings",
        )
        if any(
            not isinstance(value, str) or not value.strip()
            for value in self.source_lead_ids
        ):
            raise ValueError("Operator Brief policy source lead IDs cannot be blank.")
        source_lead_ids = tuple(sorted(set(self.source_lead_ids)))
        if len(source_lead_ids) != len(self.source_lead_ids):
            raise ValueError("Operator Brief policy source lead IDs contain duplicates.")
        if not {
            item.source_lead_id for item in rankings
        }.issubset(set(source_lead_ids)):
            raise ValueError(
                "Operator Brief policy source rankings must reference source lead IDs."
            )

        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "conflicts", conflicts)
        object.__setattr__(self, "coverage_limitations", limitations)
        object.__setattr__(self, "source_rankings", rankings)
        object.__setattr__(self, "source_lead_ids", source_lead_ids)


@dataclass(frozen=True)
class OperatorBriefThreadPolicyDecision:
    """One deterministic policy outcome for one policy input."""

    policy_key: str
    disposition: str
    signal: OperatorBriefAttentionSignal
    thread_id: str = ""
    rank: int | None = None
    reason_codes: tuple[OperatorBriefThreadPolicyReason, ...] = ()

    def __post_init__(self) -> None:
        _nonblank(self.policy_key, "Operator Brief policy decision key")
        if self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("Operator Brief policy disposition is invalid.")
        if not isinstance(self.signal, OperatorBriefAttentionSignal):
            raise ValueError("Operator Brief policy attention signal is invalid.")
        if self.rank is not None and (
            isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank < 1
        ):
            raise ValueError("Operator Brief policy rank must be positive or null.")
        if any(
            not isinstance(reason, OperatorBriefThreadPolicyReason)
            for reason in self.reason_codes
        ):
            raise ValueError("Operator Brief policy reasons are invalid.")
        canonical_reasons = tuple(
            sorted(set(self.reason_codes), key=_REASON_ORDER.__getitem__)
        )
        object.__setattr__(self, "reason_codes", canonical_reasons)


@dataclass(frozen=True)
class OperatorBriefThreadPolicyResult:
    """Canonical subjects and their complete deterministic policy decisions."""

    subjects: tuple[OperatorBriefThreadPolicySubject, ...] = ()
    decisions: tuple[OperatorBriefThreadPolicyDecision, ...] = ()

    def __post_init__(self) -> None:
        if any(
            not isinstance(item, OperatorBriefThreadPolicySubject)
            for item in self.subjects
        ):
            raise ValueError("Operator Brief policy result subjects are invalid.")
        if any(
            not isinstance(item, OperatorBriefThreadPolicyDecision)
            for item in self.decisions
        ):
            raise ValueError("Operator Brief policy result decisions are invalid.")
        subject_keys = [item.policy_key for item in self.subjects]
        decision_keys = [item.policy_key for item in self.decisions]
        if len(set(subject_keys)) != len(subject_keys):
            raise ValueError("Operator Brief policy result contains duplicate subjects.")
        if len(set(decision_keys)) != len(decision_keys):
            raise ValueError("Operator Brief policy result contains duplicate decisions.")
        if set(subject_keys) != set(decision_keys):
            raise ValueError("Operator Brief policy result decisions are incomplete.")


def _attention_signal(
    subject: OperatorBriefThreadPolicySubject,
) -> OperatorBriefAttentionSignal:
    if subject.materiality is OperatorBriefThreadMateriality.EVIDENCE_ONLY:
        return OperatorBriefAttentionSignal.EVIDENCE_ONLY
    return OperatorBriefAttentionSignal(
        f"{subject.specificity.value}_{subject.evidence_basis.value}"
    )


def _thread_id(subject: OperatorBriefThreadPolicySubject) -> str:
    if subject.semantic_subject_key is None:
        raise ValueError("Operator Brief thread identity requires a semantic subject key.")
    payload = json.dumps(
        {
            "semantic_subject_key": subject.semantic_subject_key,
            "subject_kind": subject.subject_kind.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"THREAD-{sha256(payload.encode('utf-8')).hexdigest()[:16].upper()}"


def _semantic_identity(
    subject: OperatorBriefThreadPolicySubject,
) -> OperatorBriefThreadPolicySubjectReference | None:
    if subject.semantic_subject_key is None:
        return None
    return OperatorBriefThreadPolicySubjectReference(
        subject_kind=subject.subject_kind,
        semantic_subject_key=subject.semantic_subject_key,
    )


def _rank_key(
    subject: OperatorBriefThreadPolicySubject,
) -> tuple[int, int, str, str]:
    specificity = {
        OperatorBriefThreadSpecificity.SPECIFIC: 0,
        OperatorBriefThreadSpecificity.GENERAL: 1,
    }[subject.specificity]
    basis = {
        OperatorBriefThreadEvidenceBasis.DIRECT: 0,
        OperatorBriefThreadEvidenceBasis.LEGACY: 1,
    }[subject.evidence_basis]
    assert subject.semantic_subject_key is not None
    return (
        specificity,
        basis,
        subject.semantic_subject_key,
        subject.subject_kind.value,
    )


def _base_reasons(
    subject: OperatorBriefThreadPolicySubject,
) -> set[OperatorBriefThreadPolicyReason]:
    reasons = {
        (
            OperatorBriefThreadPolicyReason.SPECIFIC_EVIDENCE
            if subject.specificity is OperatorBriefThreadSpecificity.SPECIFIC
            else OperatorBriefThreadPolicyReason.GENERAL_EVIDENCE
        )
    }
    reasons.add(
        {
            OperatorBriefThreadEvidenceBasis.DIRECT: (
                OperatorBriefThreadPolicyReason.DIRECT_EVIDENCE
            ),
            OperatorBriefThreadEvidenceBasis.DERIVED: (
                OperatorBriefThreadPolicyReason.DERIVED_CONTEXT
            ),
            OperatorBriefThreadEvidenceBasis.LEGACY: (
                OperatorBriefThreadPolicyReason.LEGACY_MATERIAL
            ),
        }[subject.evidence_basis]
    )
    if subject.conflicts:
        reasons.add(OperatorBriefThreadPolicyReason.CONFLICTING_OBSERVATIONS)
    if subject.coverage_limitations:
        reasons.add(OperatorBriefThreadPolicyReason.COVERAGE_LIMITED)
    return reasons


def apply_operator_brief_thread_policy(
    subjects: tuple[OperatorBriefThreadPolicySubject, ...],
) -> OperatorBriefThreadPolicyResult:
    """Apply disposition, attention, identity, and rank policy without I/O."""

    if not isinstance(subjects, tuple) or any(
        not isinstance(item, OperatorBriefThreadPolicySubject) for item in subjects
    ):
        raise ValueError("Operator Brief policy input must contain policy subjects.")
    policy_keys = [item.policy_key for item in subjects]
    if len(set(policy_keys)) != len(policy_keys):
        raise ValueError("Operator Brief policy input contains duplicate policy keys.")

    canonical_subjects = tuple(sorted(subjects, key=lambda item: item.policy_key))
    semantic_identities = tuple(
        identity
        for subject in canonical_subjects
        if (identity := _semantic_identity(subject)) is not None
    )
    if len(set(semantic_identities)) != len(semantic_identities):
        raise ValueError(
            "Operator Brief policy input contains duplicate semantic identities."
        )

    for subject in canonical_subjects:
        if (
            subject.associated_subject_reference is not None
            and subject.replaced_by_subject_reference is not None
        ):
            raise ValueError(
                "Operator Brief policy association and replacement are mutually exclusive."
            )
        if subject.associated_subject_reference is not None:
            if subject.materiality is OperatorBriefThreadMateriality.MATERIAL:
                raise ValueError(
                    "A material policy subject cannot carry an association."
                )
            if subject.materiality is OperatorBriefThreadMateriality.EVIDENCE_ONLY:
                raise ValueError(
                    "An evidence-only policy subject cannot carry an association."
                )
            if subject.independent:
                raise ValueError(
                    "A policy association requires non-independent context."
                )
        if subject.replaced_by_subject_reference is not None and (
            subject.materiality is not OperatorBriefThreadMateriality.MATERIAL
            or subject.evidence_basis is not OperatorBriefThreadEvidenceBasis.LEGACY
        ):
            raise ValueError(
                "An Operator Brief replacement requires a material legacy subject."
            )
        if (
            subject.materiality is OperatorBriefThreadMateriality.MATERIAL
            and subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DERIVED
        ):
            raise ValueError("A material derived-only subject cannot become primary.")
        if (
            subject.materiality is OperatorBriefThreadMateriality.MATERIAL
            and subject.evidence_basis is not OperatorBriefThreadEvidenceBasis.LEGACY
            and subject.semantic_subject_key is None
        ):
            raise ValueError("A material subject requires a stable semantic key.")

    primary_subjects = tuple(
        sorted(
            (
                subject
                for subject in canonical_subjects
                if subject.materiality is OperatorBriefThreadMateriality.MATERIAL
                and subject.independent
                and subject.semantic_subject_key is not None
                and subject.replaced_by_subject_reference is None
            ),
            key=_rank_key,
        )
    )
    primary_by_identity = {
        _semantic_identity(subject): (subject, rank)
        for rank, subject in enumerate(primary_subjects, start=1)
    }
    trait_counts: dict[
        tuple[OperatorBriefThreadSpecificity, OperatorBriefThreadEvidenceBasis], int
    ] = {}
    for subject in primary_subjects:
        traits = subject.specificity, subject.evidence_basis
        trait_counts[traits] = trait_counts.get(traits, 0) + 1

    decisions: list[OperatorBriefThreadPolicyDecision] = []
    for subject in canonical_subjects:
        reasons = _base_reasons(subject)
        disposition: str
        thread_id = ""
        rank: int | None = None

        if subject.materiality is OperatorBriefThreadMateriality.EVIDENCE_ONLY:
            disposition = EVIDENCE_ONLY
            reasons.add(OperatorBriefThreadPolicyReason.RETAINED_EVIDENCE_ONLY)
        elif subject.replaced_by_subject_reference is not None:
            replacement = primary_by_identity.get(
                subject.replaced_by_subject_reference
            )
            if replacement is None:
                raise ValueError(
                    "Operator Brief normalized replacement must reference a primary subject."
                )
            if (
                replacement[0].evidence_basis
                is not OperatorBriefThreadEvidenceBasis.DIRECT
            ):
                raise ValueError(
                    "Operator Brief normalized replacement target must be direct."
                )
            disposition = SUPPORTING_CONTEXT
            thread_id = _thread_id(replacement[0])
            reasons.add(OperatorBriefThreadPolicyReason.ASSOCIATED_CONTEXT)
            reasons.add(OperatorBriefThreadPolicyReason.NORMALIZED_REPLACEMENT)
            if subject.semantic_subject_key is None:
                reasons.add(OperatorBriefThreadPolicyReason.STABLE_IDENTITY_MISSING)
        elif (
            subject.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
            and subject.materiality is OperatorBriefThreadMateriality.MATERIAL
            and subject.semantic_subject_key is None
        ):
            disposition = DEPRIORITISED_CONTEXT
            reasons.add(OperatorBriefThreadPolicyReason.STABLE_IDENTITY_MISSING)
        elif subject.materiality is OperatorBriefThreadMateriality.MATERIAL:
            if not subject.independent:
                raise ValueError("A material policy subject must be independent.")
            disposition = PRIMARY_THREAD
            identity = _semantic_identity(subject)
            assert identity is not None
            primary, rank = primary_by_identity[identity]
            thread_id = _thread_id(primary)
            reasons.add(OperatorBriefThreadPolicyReason.MATERIAL_INDEPENDENT)
            if trait_counts[(subject.specificity, subject.evidence_basis)] > 1:
                reasons.add(OperatorBriefThreadPolicyReason.SEMANTIC_TIEBREAK)
        elif subject.associated_subject_reference is not None:
            association = primary_by_identity.get(subject.associated_subject_reference)
            if association is None:
                raise ValueError(
                    "Operator Brief context association must reference a primary subject."
                )
            disposition = SUPPORTING_CONTEXT
            thread_id = _thread_id(association[0])
            reasons.add(OperatorBriefThreadPolicyReason.ASSOCIATED_CONTEXT)
        else:
            disposition = DEPRIORITISED_CONTEXT
            reasons.add(OperatorBriefThreadPolicyReason.UNASSOCIATED_CONTEXT)

        decisions.append(
            OperatorBriefThreadPolicyDecision(
                policy_key=subject.policy_key,
                disposition=disposition,
                signal=_attention_signal(subject),
                thread_id=thread_id,
                rank=rank,
                reason_codes=tuple(reasons),
            )
        )

    return OperatorBriefThreadPolicyResult(
        subjects=canonical_subjects,
        decisions=tuple(decisions),
    )
