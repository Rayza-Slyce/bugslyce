"""Truthful Operator Brief adaptation of the accepted application/service model."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from bugslyce.recon.application_service_model import (
    ApplicationServiceModel,
    ApplicationServiceModelRelationKind,
    ApplicationServiceObservedOriginCorrespondenceSupport,
)
from bugslyce.recon.documentation_assertions import (
    DocumentedAuthentication,
    DocumentedHttpOperation,
    DocumentedOAuthScope,
    DocumentedRequiredHeader,
    DocumentationAssertion,
    DocumentationAssertionKind,
)
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicyResult,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
    apply_operator_brief_thread_policy,
)


_INDEPENDENT_DOCUMENTATION_KINDS = frozenset(
    {
        DocumentationAssertionKind.HTTP_OPERATION,
        DocumentationAssertionKind.REQUIRED_HEADER,
        DocumentationAssertionKind.AUTHENTICATION_SCHEME,
        DocumentationAssertionKind.OAUTH_SCOPE,
    }
)


def _semantic_id(prefix: str, *parts: object) -> str:
    payload = json.dumps([str(part) for part in parts], separators=(",", ":"))
    return f"{prefix}-{sha256(payload.encode('utf-8')).hexdigest()[:20].upper()}"


def _policy_key(subject_kind: OperatorBriefSubjectKind, semantic_key: str) -> str:
    payload = json.dumps(
        {"semantic_subject_key": semantic_key, "subject_kind": subject_kind.value},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"POLICY-{sha256(payload.encode('utf-8')).hexdigest()[:16].upper()}"


def _membership(values) -> tuple[str, ...]:
    return tuple(sorted({item for group in values for item in group if item}))


@dataclass(frozen=True)
class OperatorBriefApplicationServiceSubject:
    """One human-scale documented application/service context owner."""

    subject_id: str
    title: str
    subject_kind: OperatorBriefSubjectKind
    fact_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    origins: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]
    policy_subject: OperatorBriefThreadPolicySubject

    def __post_init__(self) -> None:
        if not self.subject_id.strip() or not self.title.strip():
            raise ValueError("application/service presentation subject requires identity")
        if self.policy_subject.subject_kind is not self.subject_kind:
            raise ValueError("application/service subject and policy kinds contradict")
        if set(self.fact_ids) != {fact.fact_id for fact in self.policy_subject.facts}:
            raise ValueError("application/service subject facts contradict policy facts")


@dataclass(frozen=True)
class OperatorBriefApplicationServiceComposition:
    """Transient report adaptation retaining the exact accepted A3 model."""

    application_service_model: ApplicationServiceModel
    subjects: tuple[OperatorBriefApplicationServiceSubject, ...]
    facts: tuple[OperatorBriefFact, ...]
    thread_policy_result: OperatorBriefThreadPolicyResult


def _service_fact(model: ApplicationServiceModel, service) -> OperatorBriefFact:
    relations = tuple(
        relation
        for relation in model.relations
        if relation.relation_kind is ApplicationServiceModelRelationKind.DESCRIBES_SERVICE
        and relation.target.entity_id == service.entity_id
    )
    supports = tuple(
        support.assertion_support
        for relation in relations
        for support in relation.supports
    )
    assertion_ids = tuple(
        support.assertion_id
        for relation in relations
        for support in relation.supports
    )
    references = {
        OperatorBriefSourceReference("application_service_entity", service.entity_id),
        *(OperatorBriefSourceReference("documentation_assertion", value) for value in assertion_ids),
        *(
            OperatorBriefSourceReference("documentation_source", support.source_reference.source_id)
            for support in supports
        ),
    }
    return OperatorBriefFact(
        fact_id=_semantic_id("APP-SERVICE-FACT", service.entity_id),
        kind=OperatorBriefFactKind.DOCUMENTED_SERVICE,
        semantic_class=OperatorBriefSemanticClass.DOCUMENTED,
        role=OperatorBriefFactRole.DOCUMENTATION_EVIDENCE,
        label="Documented HTTP service",
        summary=f"Documentation describes the HTTP service base {service.value.canonical_url}.",
        endpoints=(service.value.canonical_url,),
        origins=(service.value.origin.origin_url,),
        evidence_ids=_membership(support.source_reference.evidence_ids for support in supports),
        source_references=tuple(sorted(references)),
        service=service.value.canonical_url,
    )


def _realtime_fact(model: ApplicationServiceModel, endpoint) -> OperatorBriefFact:
    relations = tuple(
        relation
        for relation in model.relations
        if relation.relation_kind is ApplicationServiceModelRelationKind.DOCUMENTS_REALTIME_ENDPOINT
        and relation.target.entity_id == endpoint.entity_id
    )
    supports = tuple(
        support.assertion_support
        for relation in relations
        for support in relation.supports
    )
    assertion_ids = tuple(
        support.assertion_id
        for relation in relations
        for support in relation.supports
    )
    references = {
        OperatorBriefSourceReference("application_service_entity", endpoint.entity_id),
        *(OperatorBriefSourceReference("documentation_assertion", value) for value in assertion_ids),
        *(
            OperatorBriefSourceReference("documentation_source", support.source_reference.source_id)
            for support in supports
        ),
    }
    return OperatorBriefFact(
        fact_id=_semantic_id("APP-REALTIME-FACT", endpoint.entity_id),
        kind=OperatorBriefFactKind.DOCUMENTED_REALTIME_ENDPOINT,
        semantic_class=OperatorBriefSemanticClass.DOCUMENTED,
        role=OperatorBriefFactRole.DOCUMENTATION_EVIDENCE,
        label="Documented realtime endpoint",
        summary=(
            "Documentation names the non-executable realtime endpoint "
            f"{endpoint.value.canonical_url}; BugSlyce did not connect to it."
        ),
        endpoints=(endpoint.value.canonical_url,),
        evidence_ids=_membership(support.source_reference.evidence_ids for support in supports),
        source_references=tuple(sorted(references)),
        service=endpoint.value.canonical_url,
    )


def _correspondence_fact(relation) -> OperatorBriefFact:
    supports = tuple(
        support
        for support in relation.supports
        if isinstance(support, ApplicationServiceObservedOriginCorrespondenceSupport)
    )
    references = {
        OperatorBriefSourceReference("application_service_relation", relation.relation_id),
        *(
            OperatorBriefSourceReference(
                "documentation_assertion",
                support.documentation_assertion_id,
            )
            for support in supports
        ),
        *(
            OperatorBriefSourceReference(
                "application_service_observed_relation",
                support.observed_relation_id,
            )
            for support in supports
        ),
        *(
            OperatorBriefSourceReference(
                f"application_service_{support.observation_support.source_reference.owner_kind.value}",
                support.observation_support.source_reference.source_id,
            )
            for support in supports
        ),
        *(
            OperatorBriefSourceReference(
                "documentation_source",
                support.documentation_support.source_reference.source_id,
            )
            for support in supports
        ),
    }
    return OperatorBriefFact(
        fact_id=_semantic_id("APP-CORRESPONDENCE-FACT", relation.relation_id),
        kind=OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE,
        semantic_class=OperatorBriefSemanticClass.DERIVED,
        role=OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
        label="Documented service on independently observed origin",
        summary=(
            "Documentation describes this service on an HTTP origin from which "
            "BugSlyce independently observed a redirect response. This does not "
            "establish that the documented service endpoint responded."
        ),
        evidence_ids=_membership(
            (
                *support.documentation_support.source_reference.evidence_ids,
                *support.observation_support.evidence_ids,
            )
            for support in supports
        ),
        artefact_references=_membership(
            support.observation_support.artefact_references for support in supports
        ),
        source_references=tuple(sorted(references)),
    )


def _independent_value(assertion: DocumentationAssertion) -> tuple[str, str, OperatorBriefFactKind]:
    value = assertion.value
    if isinstance(value, DocumentedHttpOperation):
        return "Documented HTTP operation", f"{value.method} {value.route}", OperatorBriefFactKind.DOCUMENTED_HTTP_OPERATION
    if isinstance(value, DocumentedRequiredHeader):
        return "Documented required header", value.header_name, OperatorBriefFactKind.DOCUMENTED_REQUIREMENT
    if isinstance(value, DocumentedAuthentication):
        return "Documented authentication scheme", value.scheme.value, OperatorBriefFactKind.DOCUMENTED_REQUIREMENT
    if isinstance(value, DocumentedOAuthScope):
        return "Documented OAuth scope", value.scope, OperatorBriefFactKind.DOCUMENTED_REQUIREMENT
    raise ValueError("unsupported independent documentation assertion")


def _policy_subject(
    *,
    subject_id: str,
    subject_kind: OperatorBriefSubjectKind,
    facts: tuple[OperatorBriefFact, ...],
    materiality: OperatorBriefThreadMateriality,
    association: OperatorBriefThreadPolicySubjectReference | None = None,
) -> OperatorBriefThreadPolicySubject:
    semantic_key = f"application_service:{subject_id}"
    return OperatorBriefThreadPolicySubject(
        policy_key=_policy_key(subject_kind, semantic_key),
        semantic_subject_key=semantic_key,
        subject_kind=subject_kind,
        materiality=materiality,
        specificity=OperatorBriefThreadSpecificity.SPECIFIC,
        evidence_basis=OperatorBriefThreadEvidenceBasis.DOCUMENTED,
        independent=False,
        associated_subject_reference=association,
        facts=facts,
    )


def _owner(
    *,
    subject_id: str,
    title: str,
    subject_kind: OperatorBriefSubjectKind,
    facts: tuple[OperatorBriefFact, ...],
    materiality: OperatorBriefThreadMateriality,
    association: OperatorBriefThreadPolicySubjectReference | None = None,
) -> OperatorBriefApplicationServiceSubject:
    policy = _policy_subject(
        subject_id=subject_id,
        subject_kind=subject_kind,
        facts=facts,
        materiality=materiality,
        association=association,
    )
    return OperatorBriefApplicationServiceSubject(
        subject_id=subject_id,
        title=title,
        subject_kind=subject_kind,
        fact_ids=tuple(sorted(fact.fact_id for fact in facts)),
        endpoints=_membership(fact.endpoints for fact in facts),
        origins=_membership(fact.origins for fact in facts),
        evidence_ids=_membership(fact.evidence_ids for fact in facts),
        artefact_references=_membership(fact.artefact_references for fact in facts),
        source_references=tuple(sorted({reference for fact in facts for reference in fact.source_references})),
        policy_subject=policy,
    )


def compose_operator_brief_application_service(
    model: ApplicationServiceModel,
    *,
    operator_brief_composition: OperatorBriefComposition,
) -> OperatorBriefApplicationServiceComposition:
    """Adapt one exact A3 model without changing or replaying lower evidence."""

    if not isinstance(model, ApplicationServiceModel):
        raise TypeError("application/service Operator Brief adapter requires a typed model")
    if not isinstance(operator_brief_composition, OperatorBriefComposition):
        raise TypeError("application/service adapter requires an Operator Brief composition")

    facts: list[OperatorBriefFact] = []
    subjects: list[OperatorBriefApplicationServiceSubject] = []
    correspondence_by_service = {
        service.entity_id: tuple(
            relation
            for relation in model.relations
            if relation.relation_kind is ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN
            and relation.source.entity_id == service.entity_id
        )
        for service in model.documented_http_services
    }
    services_by_origin: dict[object, list[object]] = {}
    for service in model.documented_http_services:
        services_by_origin.setdefault(service.value.origin, []).append(service)
    for origin, services in sorted(services_by_origin.items(), key=lambda item: item[0]):
        group_facts = [_service_fact(model, service) for service in services]
        correspondences = tuple(
            relation
            for service in services
            for relation in correspondence_by_service[service.entity_id]
        )
        group_facts.extend(_correspondence_fact(relation) for relation in correspondences)
        matching_http = tuple(
            subject
            for subject in operator_brief_composition.http.subjects
            if origin.origin_url in subject.origins
        )
        association = None
        if correspondences and len(matching_http) == 1:
            association = OperatorBriefThreadPolicySubjectReference(
                subject_kind=OperatorBriefSubjectKind.APPLICATION,
                semantic_subject_key=f"http:{matching_http[0].subject_id}",
            )
        subject_id = _semantic_id("APP-DOCUMENTED-HTTP", origin.origin_url)
        owner = _owner(
            subject_id=subject_id,
            title=f"Documented HTTP service on {origin.origin_url}",
            subject_kind=OperatorBriefSubjectKind.DOCUMENTED_APPLICATION_SERVICE,
            facts=tuple(group_facts),
            materiality=OperatorBriefThreadMateriality.CONTEXT,
            association=association,
        )
        facts.extend(group_facts)
        subjects.append(owner)

    realtime_by_authority: dict[tuple[str, str, int], list[object]] = {}
    for endpoint in model.documented_realtime_endpoints:
        key = (endpoint.value.scheme, endpoint.value.hostname, endpoint.value.effective_port)
        realtime_by_authority.setdefault(key, []).append(endpoint)
    for key, endpoints in sorted(realtime_by_authority.items()):
        group_facts = tuple(_realtime_fact(model, endpoint) for endpoint in endpoints)
        owner = _owner(
            subject_id=_semantic_id("APP-DOCUMENTED-REALTIME", *key),
            title=f"Documented realtime service on {key[0]}://{key[1]}:{key[2]}",
            subject_kind=OperatorBriefSubjectKind.DOCUMENTED_REALTIME_SERVICE,
            facts=group_facts,
            materiality=OperatorBriefThreadMateriality.CONTEXT,
        )
        facts.extend(group_facts)
        subjects.append(owner)

    resource_facts: dict[str, list[OperatorBriefFact]] = {}
    for assertion in model.documentation_assertions.assertions:
        if assertion.kind not in _INDEPENDENT_DOCUMENTATION_KINDS:
            continue
        label, value, kind = _independent_value(assertion)
        for support in assertion.supports:
            source_id = support.source_reference.source_id
            fact = OperatorBriefFact(
                fact_id=_semantic_id("APP-DOCUMENTATION-CONTEXT", assertion.assertion_id, source_id),
                kind=kind,
                semantic_class=OperatorBriefSemanticClass.DOCUMENTED,
                role=OperatorBriefFactRole.DOCUMENTATION_EVIDENCE,
                label=label,
                summary=(
                    f"Documentation states {value}. This statement is retained as "
                    "resource-scoped context; no service or operation association is established."
                ),
                evidence_ids=support.source_reference.evidence_ids,
                source_references=(
                    OperatorBriefSourceReference("documentation_assertion", assertion.assertion_id),
                    OperatorBriefSourceReference("documentation_source", source_id),
                ),
            )
            resource_facts.setdefault(source_id, []).append(fact)
    for source_id, values in sorted(resource_facts.items()):
        group_facts = tuple(sorted(set(values), key=lambda fact: fact.fact_id))
        owner = _owner(
            subject_id=_semantic_id("APP-DOCUMENTATION-RESOURCE", source_id),
            title="Independent documentation context",
            subject_kind=OperatorBriefSubjectKind.DOCUMENTATION_CONTEXT,
            facts=group_facts,
            materiality=OperatorBriefThreadMateriality.EVIDENCE_ONLY,
        )
        facts.extend(group_facts)
        subjects.append(owner)

    ordered_subjects = tuple(sorted(subjects, key=lambda subject: subject.subject_id))
    combined_subjects = tuple(
        sorted(
            (
                *operator_brief_composition.policy_subjects,
                *(subject.policy_subject for subject in ordered_subjects),
            ),
            key=lambda subject: subject.policy_key,
        )
    )
    return OperatorBriefApplicationServiceComposition(
        application_service_model=model,
        subjects=ordered_subjects,
        facts=tuple(sorted(set(facts), key=lambda fact: fact.fact_id)),
        thread_policy_result=apply_operator_brief_thread_policy(combined_subjects),
    )
