"""Pure presentation projection for canonical Operator Brief compositions."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.application_service_model import ApplicationServiceModel
from bugslyce.reports.operator_brief import (
    OperatorBriefConflict,
    OperatorBriefCoverageLimitation,
    OperatorBriefFact,
    OperatorBriefSourceRanking,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_application_service import (
    OperatorBriefApplicationServiceSubject,
    compose_operator_brief_application_service,
)
from bugslyce.reports.operator_brief_http import OperatorBriefHttpSubject
from bugslyce.reports.operator_brief_network import OperatorBriefNetworkSubject
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefSourceNativeFamily,
    OperatorBriefSourceNativeInterpretation,
    OperatorBriefSourceNativeSubject,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefAttentionSignal,
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicyDecision,
    OperatorBriefThreadPolicyReason,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
)
from bugslyce.reports.operator_brief_web_context import OperatorBriefWebContextSubject


@dataclass(frozen=True)
class OperatorBriefSourceNativePresentationDetail:
    """Owner-native source detail retained for a source-native subject."""

    family: OperatorBriefSourceNativeFamily
    endpoints: tuple[str, ...]
    origins: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]
    interpretation: OperatorBriefSourceNativeInterpretation


@dataclass(frozen=True)
class OperatorBriefInvestigationSubject:
    """One canonical policy subject prepared for a later HTML renderer."""

    policy_key: str
    display_title: str
    semantic_subject_key: str | None
    subject_kind: OperatorBriefSubjectKind
    materiality: OperatorBriefThreadMateriality
    specificity: OperatorBriefThreadSpecificity
    evidence_basis: OperatorBriefThreadEvidenceBasis
    independent: bool
    associated_subject_reference: OperatorBriefThreadPolicySubjectReference | None
    replaced_by_subject_reference: OperatorBriefThreadPolicySubjectReference | None
    thread_id: str
    rank: int | None
    disposition: str
    signal: OperatorBriefAttentionSignal
    reason_codes: tuple[OperatorBriefThreadPolicyReason, ...]
    facts: tuple[OperatorBriefFact, ...]
    conflicts: tuple[OperatorBriefConflict, ...]
    coverage_limitations: tuple[OperatorBriefCoverageLimitation, ...]
    source_family: str
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_rankings: tuple[OperatorBriefSourceRanking, ...]
    source_lead_ids: tuple[str, ...]
    source_native_detail: OperatorBriefSourceNativePresentationDetail | None


@dataclass(frozen=True)
class OperatorBriefHtmlPresentation:
    """Canonical operator-facing data available to the future HTML renderer."""

    investigation_subjects: tuple[OperatorBriefInvestigationSubject, ...]


_OperatorBriefOwner = (
    OperatorBriefHttpSubject
    | OperatorBriefNetworkSubject
    | OperatorBriefWebContextSubject
    | OperatorBriefSourceNativeSubject
    | OperatorBriefApplicationServiceSubject
)


def _decision_by_policy_key(
    policy_subjects: tuple[OperatorBriefThreadPolicySubject, ...],
    decisions_input: tuple[OperatorBriefThreadPolicyDecision, ...],
) -> dict[str, OperatorBriefThreadPolicyDecision]:
    decisions: dict[str, OperatorBriefThreadPolicyDecision] = {}
    for decision in decisions_input:
        if decision.policy_key in decisions:
            raise ValueError("Operator Brief presentation contains duplicate decisions.")
        decisions[decision.policy_key] = decision
    subject_keys = {subject.policy_key for subject in policy_subjects}
    if set(decisions) != subject_keys:
        raise ValueError("Operator Brief presentation decisions are incomplete.")
    return decisions


def _owner_by_policy_key(
    composition: OperatorBriefComposition,
    application_subjects: tuple[OperatorBriefApplicationServiceSubject, ...] = (),
) -> dict[str, tuple[str, _OperatorBriefOwner]]:
    """Resolve every policy subject to one owner through canonical identities."""

    policy_subjects_by_semantic_key: dict[str, OperatorBriefThreadPolicySubject] = {}
    policy_subjects_by_key: dict[str, OperatorBriefThreadPolicySubject] = {}
    for subject in composition.policy_subjects:
        if subject.policy_key in policy_subjects_by_key:
            raise ValueError("Operator Brief presentation contains duplicate policy subjects.")
        policy_subjects_by_key[subject.policy_key] = subject
        if subject.semantic_subject_key is not None:
            if subject.semantic_subject_key in policy_subjects_by_semantic_key:
                raise ValueError(
                    "Operator Brief presentation contains duplicate semantic subjects."
                )
            policy_subjects_by_semantic_key[subject.semantic_subject_key] = subject

    for owner in application_subjects:
        subject = owner.policy_subject
        if subject.policy_key in policy_subjects_by_key:
            raise ValueError("Operator Brief presentation contains duplicate policy subjects.")
        policy_subjects_by_key[subject.policy_key] = subject
        if subject.semantic_subject_key is not None:
            if subject.semantic_subject_key in policy_subjects_by_semantic_key:
                raise ValueError(
                    "Operator Brief presentation contains duplicate semantic subjects."
                )
            policy_subjects_by_semantic_key[subject.semantic_subject_key] = subject

    resolved: dict[str, tuple[str, _OperatorBriefOwner]] = {}

    def add_normalized_owners(
        family: str,
        semantic_family: str,
        owners: tuple[
            OperatorBriefHttpSubject
            | OperatorBriefNetworkSubject
            | OperatorBriefWebContextSubject,
            ...,
        ],
    ) -> None:
        for owner in owners:
            semantic_key = f"{semantic_family}:{owner.subject_id}"
            subject = policy_subjects_by_semantic_key.get(semantic_key)
            if subject is None:
                raise ValueError("Operator Brief presentation owner is missing.")
            _add_owner(resolved, subject.policy_key, family, owner)

    add_normalized_owners("http", "http", composition.http.subjects)
    add_normalized_owners("network", "network", composition.network.subjects)
    add_normalized_owners("web_context", "web", composition.web_context.subjects)

    for owner in composition.source_native.subjects:
        subject = policy_subjects_by_key.get(owner.policy_subject.policy_key)
        if subject != owner.policy_subject:
            raise ValueError("Operator Brief presentation source-native owner is missing.")
        _add_owner(resolved, subject.policy_key, "source_native", owner)

    for owner in application_subjects:
        subject = policy_subjects_by_key.get(owner.policy_subject.policy_key)
        if subject != owner.policy_subject:
            raise ValueError("Operator Brief application/service owner is missing.")
        _add_owner(resolved, subject.policy_key, "application_service", owner)

    if set(resolved) != set(policy_subjects_by_key):
        raise ValueError("Operator Brief presentation subjects do not all have owners.")
    return resolved


def _add_owner(
    resolved: dict[str, tuple[str, _OperatorBriefOwner]],
    policy_key: str,
    family: str,
    owner: _OperatorBriefOwner,
) -> None:
    if policy_key in resolved:
        raise ValueError("Operator Brief presentation owner is ambiguous.")
    resolved[policy_key] = (family, owner)


def _source_native_detail(
    owner: _OperatorBriefOwner,
) -> OperatorBriefSourceNativePresentationDetail | None:
    if not isinstance(owner, OperatorBriefSourceNativeSubject):
        return None
    return OperatorBriefSourceNativePresentationDetail(
        family=owner.family,
        endpoints=owner.endpoints,
        origins=owner.origins,
        source_references=owner.source_references,
        interpretation=owner.interpretation,
    )


def build_operator_brief_html_presentation(
    composition: OperatorBriefComposition,
    *,
    application_service_model: ApplicationServiceModel | None = None,
) -> OperatorBriefHtmlPresentation:
    """Project one authoritative composition without replaying semantic assembly."""

    if application_service_model is None:
        application_subjects: tuple[OperatorBriefApplicationServiceSubject, ...] = ()
        policy_subjects = composition.policy_subjects
        policy_decisions = composition.thread_policy_result.decisions
    else:
        application_adaptation = compose_operator_brief_application_service(
            application_service_model,
            operator_brief_composition=composition,
        )
        application_subjects = application_adaptation.subjects
        policy_subjects = application_adaptation.thread_policy_result.subjects
        policy_decisions = application_adaptation.thread_policy_result.decisions
    decisions = _decision_by_policy_key(policy_subjects, policy_decisions)
    owners = _owner_by_policy_key(composition, application_subjects)
    ranked_subjects = tuple(
        sorted(
            (
                subject
                for subject in policy_subjects
                if decisions[subject.policy_key].rank is not None
            ),
            key=lambda subject: decisions[subject.policy_key].rank,
        )
    )
    unranked_subjects = tuple(
        subject
        for subject in policy_subjects
        if decisions[subject.policy_key].rank is None
    )

    return OperatorBriefHtmlPresentation(
        investigation_subjects=tuple(
            _presentation_subject(subject, decisions[subject.policy_key], owners[subject.policy_key])
            for subject in (*ranked_subjects, *unranked_subjects)
        )
    )


def _presentation_subject(
    subject: OperatorBriefThreadPolicySubject,
    decision: OperatorBriefThreadPolicyDecision,
    owner_data: tuple[str, _OperatorBriefOwner],
) -> OperatorBriefInvestigationSubject:
    family, owner = owner_data
    return OperatorBriefInvestigationSubject(
        policy_key=subject.policy_key,
        display_title=(
            owner.title
            if isinstance(owner, OperatorBriefApplicationServiceSubject)
            else (subject.facts[0].label if subject.facts else subject.subject_kind.value)
        ),
        semantic_subject_key=subject.semantic_subject_key,
        subject_kind=subject.subject_kind,
        materiality=subject.materiality,
        specificity=subject.specificity,
        evidence_basis=subject.evidence_basis,
        independent=subject.independent,
        associated_subject_reference=subject.associated_subject_reference,
        replaced_by_subject_reference=subject.replaced_by_subject_reference,
        thread_id=decision.thread_id,
        rank=decision.rank,
        disposition=decision.disposition,
        signal=decision.signal,
        reason_codes=decision.reason_codes,
        facts=subject.facts,
        conflicts=subject.conflicts,
        coverage_limitations=subject.coverage_limitations,
        source_family=family,
        evidence_ids=owner.evidence_ids,
        artefact_references=owner.artefact_references,
        source_rankings=subject.source_rankings,
        source_lead_ids=subject.source_lead_ids,
        source_native_detail=_source_native_detail(owner),
    )
