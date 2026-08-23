"""RED contract for pure normalized multi-family Operator Brief assembly."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from inspect import Parameter, signature
import json
from typing import get_type_hints

import pytest

from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.reports.operator_brief import (
    PRIMARY_THREAD,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpComposition,
    OperatorBriefHttpCompositionInput,
    OperatorBriefHttpObservation,
    build_operator_brief_http_retained_body_observation,
    compose_operator_brief_http,
)
from bugslyce.reports.operator_brief_network import (
    OperatorBriefNetworkComposition,
    OperatorBriefNetworkCompositionInput,
    build_operator_brief_service_observation,
    build_operator_brief_smb_share_observation,
    compose_operator_brief_network,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadSpecificity,
    apply_operator_brief_thread_policy,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefWebContextComposition,
    OperatorBriefWebContextCompositionInput,
    build_operator_brief_route_observation,
    build_operator_brief_route_relationship,
    compose_operator_brief_web_context,
)


def _assembly_api():
    from bugslyce.reports.operator_brief_multi_family_assembly import (
        assemble_operator_brief_policy_subjects,
    )

    return assemble_operator_brief_policy_subjects


def _empty_http() -> OperatorBriefHttpComposition:
    return OperatorBriefHttpComposition(subjects=(), facts=(), conflicts=())


def _empty_network() -> OperatorBriefNetworkComposition:
    return OperatorBriefNetworkComposition(
        subjects=(), facts=(), smb_shares=(), services=()
    )


def _empty_web() -> OperatorBriefWebContextComposition:
    return OperatorBriefWebContextComposition(
        subjects=(), facts=(), clues=(), routes=(), relationships=()
    )


def _assemble(
    *,
    http: OperatorBriefHttpComposition | None = None,
    network: OperatorBriefNetworkComposition | None = None,
    web_context: OperatorBriefWebContextComposition | None = None,
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    return _assembly_api()(
        http=_empty_http() if http is None else http,
        network=_empty_network() if network is None else network,
        web_context=_empty_web() if web_context is None else web_context,
    )


def _http(
    *endpoints: str,
    source_prefix: str = "HTTP-SOURCE",
) -> OperatorBriefHttpComposition:
    retained = tuple(
        build_operator_brief_http_retained_body_observation(
            source_kind="retained_http_body",
            source_id=f"{source_prefix}-{index}",
            endpoint=endpoint,
            body_sha256=sha256(f"body-{index}".encode()).hexdigest(),
            body_bytes=64 + index,
            evidence_ids=(f"EVID-HTTP-{index}",),
            artefact_references=(f"http-{index}.json",),
        )
        for index, endpoint in enumerate(endpoints, start=1)
    )
    return compose_operator_brief_http(
        OperatorBriefHttpCompositionInput(
            observations=(), exact_equivalences=(), retained_content=retained
        )
    )


def _service(
    *,
    host: str = "service.example.test",
    port: int = 22,
    service: str = "ssh",
    http_capable: bool = False,
    source_id: str = "SERVICE-SOURCE",
) -> OperatorBriefNetworkComposition:
    observation = build_operator_brief_service_observation(
        source_kind="retained_service",
        source_id=source_id,
        host=host,
        port=port,
        protocol="tcp",
        state="open",
        service=service,
        product="",
        version="",
        http_capable=http_capable,
        evidence_ids=(f"EVID-SERVICE-{port}",),
        artefact_references=("services.json",),
    )
    return compose_operator_brief_network(
        OperatorBriefNetworkCompositionInput(services=(observation,))
    )


def _smb() -> OperatorBriefNetworkComposition:
    share = build_operator_brief_smb_share_observation(
        source_kind="retained_smb_share",
        source_id="SMB-SHARE-SOURCE",
        host="files.example.test",
        port=445,
        share_name="review",
        share_type="Disk",
        comment="Retained share",
        evidence_ids=("EVID-SMB",),
        artefact_references=("smb-shares.json",),
    )
    service = build_operator_brief_service_observation(
        source_kind="retained_service",
        source_id="SMB-SERVICE-SOURCE",
        host="files.example.test",
        port=445,
        protocol="tcp",
        state="open",
        service="microsoft-ds",
        product="",
        version="",
        http_capable=False,
        evidence_ids=("EVID-SMB-SERVICE",),
        artefact_references=("services.json",),
    )
    return compose_operator_brief_network(
        OperatorBriefNetworkCompositionInput(
            smb_shares=(share,), services=(service,)
        )
    )


def _web(
    endpoint: str = "https://web.example.test/review",
    *,
    with_relationship: bool = False,
) -> OperatorBriefWebContextComposition:
    route = build_operator_brief_route_observation(
        source_kind="retained_route",
        source_id=f"ROUTE-SOURCE-{endpoint}",
        endpoint=endpoint,
        status_codes=(200,),
        evidence_ids=("EVID-ROUTE",),
        artefact_references=("routes.json",),
    )
    relationships = ()
    if with_relationship:
        relationships = (
            build_operator_brief_route_relationship(
                source_kind="retained_route_relationship",
                source_id="RELATIONSHIP-SOURCE",
                relationship_type="source_reference",
                source_endpoint=endpoint,
                target_endpoint=f"{endpoint}/child",
                raw_references=("child",),
                evidence_ids=("EVID-RELATIONSHIP",),
                artefact_references=("source.html",),
            ),
        )
    return compose_operator_brief_web_context(
        OperatorBriefWebContextCompositionInput(
            routes=(route,), relationships=relationships
        )
    )


def _http_with_conflict() -> OperatorBriefHttpComposition:
    endpoint = "https://conflict.example.test/review"
    origin = http_origin_from_url(endpoint)
    assert origin is not None
    observations = tuple(
        OperatorBriefHttpObservation(
            observation_id=f"HTTP-CONFLICT-OBS-{status}",
            source_fingerprint_id=f"FINGERPRINT-{status}",
            endpoint=endpoint,
            final_url=endpoint,
            origin=origin,
            method="GET",
            status_code=status,
            status_bucket="2xx_success" if status == 200 else "4xx_client_error",
            body_sha256=sha256(f"status-{status}".encode()).hexdigest(),
            body_bytes=32,
            body_empty=False,
            collection_stage="source_route_collection",
            evidence_ids=(f"EVID-{status}",),
            artefact_references=(f"response-{status}.json",),
        )
        for status in (200, 404)
    )
    return compose_operator_brief_http(
        OperatorBriefHttpCompositionInput(
            observations=observations, exact_equivalences=()
        )
    )


def _subject_for_key(
    subjects: tuple[OperatorBriefThreadPolicySubject, ...], semantic_key: str
) -> OperatorBriefThreadPolicySubject:
    return next(item for item in subjects if item.semantic_subject_key == semantic_key)


def _expected_policy_key(
    subject_kind: OperatorBriefSubjectKind, semantic_subject_key: str
) -> str:
    payload = json.dumps(
        {
            "semantic_subject_key": semantic_subject_key,
            "subject_kind": subject_kind.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"POLICY-{sha256(payload.encode()).hexdigest()[:16].upper()}"


# Existing-source fixture controls remain green before the assembly API exists.


def test_current_source_http_fixture_is_one_direct_normalized_subject() -> None:
    composition = _http("https://app.example.test/home")

    assert len(composition.subjects) == 1
    assert all(
        fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
        and fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
        for fact in composition.facts
    )


def test_current_source_smb_fixture_already_owns_matching_service_context() -> None:
    composition = _smb()

    assert len(composition.subjects) == 1
    assert composition.subjects[0].subject_kind is OperatorBriefSubjectKind.SMB_SURFACE
    assert len(composition.subjects[0].smb_share_observation_ids) == 1
    assert len(composition.subjects[0].service_observation_ids) == 1


def test_current_source_web_fixture_preserves_direct_and_derived_roles() -> None:
    composition = _web(with_relationship=True)

    subject = composition.subjects[0]
    facts = {fact.fact_id: fact for fact in composition.facts}
    subject_facts = tuple(facts[fact_id] for fact_id in subject.fact_ids)
    assert {fact.role for fact in subject_facts} == {
        OperatorBriefFactRole.DIRECT_EVIDENCE,
        OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
    }
    assert {
        fact.semantic_class for fact in subject_facts
    } == {OperatorBriefSemanticClass.OBSERVED, OperatorBriefSemanticClass.DERIVED}


def test_current_source_http_conflict_fixture_is_typed_and_subject_scoped() -> None:
    composition = _http_with_conflict()

    assert len(composition.subjects) == 2
    assert len(composition.conflicts) == 1
    assert all(subject.conflict_ids for subject in composition.subjects)


def test_current_source_relationship_only_web_input_emits_no_policy_subject_anchor() -> None:
    relationship = build_operator_brief_route_relationship(
        source_kind="retained_route_relationship",
        source_id="RELATIONSHIP-ONLY-SOURCE",
        relationship_type="source_reference",
        source_endpoint="https://web.example.test/source",
        target_endpoint="https://web.example.test/target",
    )
    composition = compose_operator_brief_web_context(
        OperatorBriefWebContextCompositionInput(relationships=(relationship,))
    )

    assert composition.subjects == ()
    assert len(composition.facts) == 1
    assert composition.facts[0].role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT


# Future pure assembly API and behavioral contract.


def test_future_assembly_api_is_keyword_only_and_typed() -> None:
    function = _assembly_api()
    parameters = signature(function).parameters
    hints = get_type_hints(function)

    assert tuple(parameters) == ("http", "network", "web_context")
    assert all(
        item.kind is Parameter.KEYWORD_ONLY for item in parameters.values()
    )
    assert hints["http"] is OperatorBriefHttpComposition
    assert hints["network"] is OperatorBriefNetworkComposition
    assert hints["web_context"] is OperatorBriefWebContextComposition
    assert hints["return"] == tuple[OperatorBriefThreadPolicySubject, ...]


def test_empty_normalized_family_assembly_returns_empty_tuple() -> None:
    assert _assemble() == ()


def test_http_subject_projects_application_traits_semantic_key_and_policy_key() -> None:
    composition = _http("https://app.example.test/home")
    source = composition.subjects[0]
    semantic_key = f"http:{source.subject_id}"
    subject = _subject_for_key(_assemble(http=composition), semantic_key)

    assert subject.subject_kind is OperatorBriefSubjectKind.APPLICATION
    assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert subject.specificity is OperatorBriefThreadSpecificity.SPECIFIC
    assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert subject.independent is True
    assert subject.policy_key == _expected_policy_key(
        OperatorBriefSubjectKind.APPLICATION, semantic_key
    )


def test_smb_surface_projects_once_with_specific_direct_material_traits() -> None:
    composition = _smb()
    subjects = _assemble(network=composition)

    assert len(subjects) == 1
    subject = subjects[0]
    assert subject.semantic_subject_key == (
        f"network:{composition.subjects[0].subject_id}"
    )
    assert subject.subject_kind is OperatorBriefSubjectKind.SMB_SURFACE
    assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert subject.specificity is OperatorBriefThreadSpecificity.SPECIFIC
    assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert subject.independent is True
    assert {fact.kind for fact in subject.facts} == {
        OperatorBriefFactKind.SMB_SHARE,
        OperatorBriefFactKind.SERVICE,
    }


def test_service_surface_projects_general_direct_material_traits() -> None:
    composition = _service()
    subject = _assemble(network=composition)[0]

    assert subject.subject_kind is OperatorBriefSubjectKind.SERVICE_SURFACE
    assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert subject.specificity is OperatorBriefThreadSpecificity.GENERAL
    assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert subject.independent is True


def test_http_capable_network_service_does_not_associate_to_http() -> None:
    http = _http("https://app.example.test/home")
    network = _service(
        host="app.example.test",
        port=443,
        service="https",
        http_capable=True,
    )
    service_subject = next(
        item
        for item in _assemble(http=http, network=network)
        if item.subject_kind is OperatorBriefSubjectKind.SERVICE_SURFACE
    )

    assert service_subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert service_subject.specificity is OperatorBriefThreadSpecificity.GENERAL
    assert service_subject.independent is True
    assert service_subject.associated_subject_reference is None


def test_web_without_http_match_remains_independent_specific_material() -> None:
    composition = _web("https://web.example.test/review")
    subject = _assemble(web_context=composition)[0]

    assert subject.subject_kind is OperatorBriefSubjectKind.CONTENT_SURFACE
    assert subject.semantic_subject_key == (
        f"web:{composition.subjects[0].subject_id}"
    )
    assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert subject.specificity is OperatorBriefThreadSpecificity.SPECIFIC
    assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert subject.independent is True
    assert subject.associated_subject_reference is None


def test_web_unique_exact_origin_match_associates_to_http_application() -> None:
    http = _http("https://app.example.test/home")
    web = _web("https://app.example.test/review")
    subjects = _assemble(http=http, web_context=web)
    application = next(
        item for item in subjects if item.subject_kind is OperatorBriefSubjectKind.APPLICATION
    )
    content = next(
        item
        for item in subjects
        if item.subject_kind is OperatorBriefSubjectKind.CONTENT_SURFACE
    )

    assert content.materiality is OperatorBriefThreadMateriality.CONTEXT
    assert content.specificity is OperatorBriefThreadSpecificity.SPECIFIC
    assert content.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert content.independent is False
    assert content.associated_subject_reference is not None
    assert content.associated_subject_reference.subject_kind is (
        OperatorBriefSubjectKind.APPLICATION
    )
    assert content.associated_subject_reference.semantic_subject_key == (
        application.semantic_subject_key
    )
    assert content.semantic_subject_key != application.semantic_subject_key
    assert content.facts == web.facts


def test_web_ambiguous_same_origin_http_matches_do_not_choose_association() -> None:
    http = _http(
        "https://app.example.test/one",
        "https://app.example.test/two",
    )
    assert len(http.subjects) == 2
    web = _web("https://app.example.test/review")
    content = next(
        item
        for item in _assemble(http=http, web_context=web)
        if item.subject_kind is OperatorBriefSubjectKind.CONTENT_SURFACE
    )

    assert content.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert content.independent is True
    assert content.associated_subject_reference is None


def test_web_hostname_match_with_different_scheme_does_not_associate() -> None:
    http = _http("https://app.example.test/home")
    web = _web("http://app.example.test/review")
    content = next(
        item
        for item in _assemble(http=http, web_context=web)
        if item.subject_kind is OperatorBriefSubjectKind.CONTENT_SURFACE
    )

    assert content.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert content.independent is True
    assert content.associated_subject_reference is None


def test_web_direct_plus_derived_facts_remains_direct_and_preserves_roles() -> None:
    composition = _web(with_relationship=True)
    subject = _assemble(web_context=composition)[0]

    assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.DIRECT
    assert tuple(fact.fact_id for fact in subject.facts) == tuple(
        sorted(fact.fact_id for fact in subject.facts)
    )
    assert {fact.role for fact in subject.facts} == {
        OperatorBriefFactRole.DIRECT_EVIDENCE,
        OperatorBriefFactRole.RELATIONSHIP_CONTEXT,
    }
    assert any(
        fact.semantic_class is OperatorBriefSemanticClass.DERIVED
        for fact in subject.facts
    )


def test_equal_raw_subject_ids_across_families_remain_namespaced_and_distinct() -> None:
    shared_id = "SHARED-SUBJECT-ID"
    http = _http("https://app.example.test/home")
    network = _service()
    web = _web()
    http = replace(
        http, subjects=(replace(http.subjects[0], subject_id=shared_id),)
    )
    network = replace(
        network, subjects=(replace(network.subjects[0], subject_id=shared_id),)
    )
    web = replace(web, subjects=(replace(web.subjects[0], subject_id=shared_id),))

    subjects = _assemble(http=http, network=network, web_context=web)

    assert {item.semantic_subject_key for item in subjects} == {
        f"http:{shared_id}",
        f"network:{shared_id}",
        f"web:{shared_id}",
    }
    assert len({(item.subject_kind, item.semantic_subject_key) for item in subjects}) == 3


def test_duplicate_subject_id_inside_one_family_fails_closed() -> None:
    composition = _service()
    malformed = replace(
        composition,
        subjects=(composition.subjects[0], composition.subjects[0]),
    )

    with pytest.raises(ValueError):
        _assemble(network=malformed)


def test_subject_fact_and_conflict_input_permutation_is_deterministic() -> None:
    http = _http_with_conflict()
    network = compose_operator_brief_network(
        OperatorBriefNetworkCompositionInput(
            services=(
                build_operator_brief_service_observation(
                    source_kind="retained_service",
                    source_id=f"SOURCE-{port}",
                    host="services.example.test",
                    port=port,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="",
                    version="",
                    http_capable=False,
                )
                for port in (22, 2222)
            )
        )
    )
    web = _web(with_relationship=True)
    permuted_http = replace(
        http,
        subjects=tuple(reversed(http.subjects)),
        facts=tuple(reversed(http.facts)),
        conflicts=tuple(reversed(http.conflicts)),
    )
    permuted_network = replace(
        network,
        subjects=tuple(reversed(network.subjects)),
        facts=tuple(reversed(network.facts)),
    )
    permuted_web = replace(
        web,
        subjects=tuple(reversed(web.subjects)),
        facts=tuple(reversed(web.facts)),
    )

    assert _assemble(http=http, network=network, web_context=web) == _assemble(
        http=permuted_http,
        network=permuted_network,
        web_context=permuted_web,
    )


def test_output_and_projected_facts_are_canonical() -> None:
    subjects = _assemble(
        http=_http("https://app.example.test/home"),
        network=_smb(),
        web_context=_web(with_relationship=True),
    )

    assert tuple(item.policy_key for item in subjects) == tuple(
        sorted(item.policy_key for item in subjects)
    )
    assert all(
        tuple(fact.fact_id for fact in item.facts)
        == tuple(sorted(fact.fact_id for fact in item.facts))
        for item in subjects
    )


def test_family_facts_project_as_original_typed_objects() -> None:
    http = _http("https://app.example.test/home")
    network = _smb()
    web = _web(with_relationship=True)
    subjects = _assemble(http=http, network=network, web_context=web)
    compositions = {
        "http": http,
        "network": network,
        "web": web,
    }

    for subject in subjects:
        family = subject.semantic_subject_key.split(":", 1)[0]
        composition = compositions[family]
        source_id = subject.semantic_subject_key.split(":", 1)[1]
        source_subject = next(
            item for item in composition.subjects if item.subject_id == source_id
        )
        expected = tuple(
            sorted(
                (
                    fact
                    for fact in composition.facts
                    if fact.fact_id in source_subject.fact_ids
                ),
                key=lambda item: item.fact_id,
            )
        )
        assert subject.facts == expected


def test_http_conflicts_remain_typed_and_attached_to_referenced_subjects() -> None:
    composition = _http_with_conflict()
    subjects = _assemble(http=composition)

    assert len(subjects) == 2
    assert all(subject.conflicts == composition.conflicts for subject in subjects)
    assert all(
        tuple(item.conflict_id for item in subject.conflicts)
        == tuple(sorted(item.conflict_id for item in subject.conflicts))
        for subject in subjects
    )


def test_six_independent_normalized_subjects_survive_policy_as_six_primaries() -> None:
    services = tuple(
        build_operator_brief_service_observation(
            source_kind="retained_service",
            source_id=f"SERVICE-SOURCE-{port}",
            host="services.example.test",
            port=port,
            protocol="tcp",
            state="open",
            service="ssh",
            product="",
            version="",
            http_capable=False,
        )
        for port in (22, 2222, 2223, 2224, 2225, 2226)
    )
    network = compose_operator_brief_network(
        OperatorBriefNetworkCompositionInput(services=services)
    )

    subjects = _assemble(network=network)
    result = apply_operator_brief_thread_policy(subjects)

    assert len(subjects) == 6
    assert all(item.materiality is OperatorBriefThreadMateriality.MATERIAL for item in subjects)
    assert all(item.independent for item in subjects)
    assert {item.disposition for item in result.decisions} == {PRIMARY_THREAD}
    assert sorted(item.rank for item in result.decisions if item.rank is not None) == list(
        range(1, 7)
    )


def test_normalized_projection_has_no_coverage_rankings_leads_or_replacements() -> None:
    subjects = _assemble(
        http=_http("https://app.example.test/home"),
        network=_service(),
        web_context=_web(),
    )

    assert all(item.coverage_limitations == () for item in subjects)
    assert all(item.source_rankings == () for item in subjects)
    assert all(item.source_lead_ids == () for item in subjects)
    assert all(item.replaced_by_subject_reference is None for item in subjects)


def test_output_is_directly_accepted_by_closed_thread_policy() -> None:
    subjects = _assemble(
        http=_http("https://app.example.test/home"),
        network=_service(),
        web_context=_web("https://other.example.test/review"),
    )

    result = apply_operator_brief_thread_policy(subjects)

    assert result.subjects == subjects
    assert len(result.decisions) == len(subjects)
    assert len(
        {
            (item.subject_kind, item.semantic_subject_key)
            for item in subjects
        }
    ) == len(subjects)


def test_derived_fact_density_does_not_change_web_identity_or_traits() -> None:
    sparse = _assemble(web_context=_web())[0]
    dense = _assemble(web_context=_web(with_relationship=True))[0]

    assert sparse.semantic_subject_key == dense.semantic_subject_key
    assert sparse.policy_key == dense.policy_key
    assert sparse.subject_kind is dense.subject_kind
    assert sparse.materiality is dense.materiality
    assert sparse.specificity is dense.specificity
    assert sparse.evidence_basis is dense.evidence_basis
    assert sparse.independent is dense.independent
    assert len(dense.facts) > len(sparse.facts)
