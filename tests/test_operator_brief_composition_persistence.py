"""RED contract for canonical persisted Stage 5 Operator Brief snapshots."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from inspect import Parameter, signature
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.reports.operator_brief import (
    PRIMARY_THREAD,
    SUPPORTING_CONTEXT,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_assembly import (
    OperatorBriefComposition,
    assemble_operator_brief,
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
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefWebContextComposition,
    OperatorBriefWebContextCompositionInput,
    build_operator_brief_route_observation,
    build_operator_brief_route_relationship,
    compose_operator_brief_web_context,
)
from bugslyce.triage.workflow_leads import (
    WorkflowAccountObservation,
    WorkflowAccountObservationKind,
)


_FUTURE_MODULE = "bugslyce.reports.operator_brief_composition_persistence"
_FILENAME = "operator_brief_composition.json"
_GENERATED_BY = "bugslyce.operator_brief_composition"
_ORIGIN = "https://persistence.example.test"


def _future_api() -> SimpleNamespace:
    module = importlib.import_module(_FUTURE_MODULE)
    names = (
        "OPERATOR_BRIEF_COMPOSITION_FILENAME",
        "write_operator_brief_composition_artifact",
        "load_operator_brief_composition_artifact",
    )
    return SimpleNamespace(**{name: getattr(module, name) for name in names})


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


def _http(*, conflict: bool = False) -> OperatorBriefHttpComposition:
    endpoint = f"{_ORIGIN}/application"
    retained = build_operator_brief_http_retained_body_observation(
        source_kind="retained_http_body",
        source_id="PERSIST-HTTP-BODY",
        endpoint=endpoint,
        body_sha256=sha256(b"application").hexdigest(),
        body_bytes=11,
        evidence_ids=("EVID-HTTP",),
        artefact_references=("deep/http.json",),
    )
    if not conflict:
        return compose_operator_brief_http(
            OperatorBriefHttpCompositionInput(
                observations=(), exact_equivalences=(), retained_content=(retained,)
            )
        )

    conflict_endpoint = "https://conflict.persistence.example.test/review"
    origin = http_origin_from_url(conflict_endpoint)
    assert origin is not None
    observations = tuple(
        OperatorBriefHttpObservation(
            observation_id=f"PERSIST-CONFLICT-{status}",
            source_fingerprint_id=f"PERSIST-FINGERPRINT-{status}",
            endpoint=conflict_endpoint,
            final_url=conflict_endpoint,
            origin=origin,
            method="GET",
            status_code=status,
            status_bucket="2xx_success" if status == 200 else "4xx_client_error",
            body_sha256=sha256(f"status-{status}".encode()).hexdigest(),
            body_bytes=32,
            body_empty=False,
            collection_stage="source_route_collection",
            evidence_ids=(f"EVID-CONFLICT-{status}",),
            artefact_references=(f"deep/response-{status}.json",),
        )
        for status in (200, 404)
    )
    return compose_operator_brief_http(
        OperatorBriefHttpCompositionInput(
            observations=observations,
            exact_equivalences=(),
            retained_content=(retained,),
        )
    )


def _network() -> OperatorBriefNetworkComposition:
    service = build_operator_brief_service_observation(
        source_kind="nmap_service",
        source_id="PERSIST-SERVICE",
        host="persistence.example.test",
        port=445,
        protocol="tcp",
        state="open",
        service="microsoft-ds",
        product="Samba",
        version="4.18",
        http_capable=False,
        evidence_ids=("EVID-SERVICE",),
        artefact_references=("network/services.json",),
    )
    share = build_operator_brief_smb_share_observation(
        source_kind="smb_share",
        source_id="PERSIST-SHARE",
        host="persistence.example.test",
        port=445,
        share_name="public",
        share_type="disk",
        comment="public files",
        trigger_service_names=("microsoft-ds",),
        trigger_evidence_ids=("EVID-SERVICE",),
        trigger_artefact_references=("network/services.json",),
        evidence_ids=("EVID-SHARE",),
        artefact_references=("network/shares.json",),
    )
    return compose_operator_brief_network(
        OperatorBriefNetworkCompositionInput(smb_shares=(share,), services=(service,))
    )


def _web() -> OperatorBriefWebContextComposition:
    endpoint = f"{_ORIGIN}/application"
    route = build_operator_brief_route_observation(
        source_kind="retained_route",
        source_id="PERSIST-WEB-ROUTE",
        endpoint=endpoint,
        status_codes=(200,),
        evidence_ids=("EVID-WEB",),
        artefact_references=("web/routes.json",),
    )
    relationship = build_operator_brief_route_relationship(
        source_kind="retained_route_relationship",
        source_id="PERSIST-WEB-RELATIONSHIP",
        relationship_type="source_reference",
        source_endpoint=endpoint,
        target_endpoint=f"{_ORIGIN}/docs",
        evidence_ids=("EVID-WEB-REL",),
        artefact_references=("web/routes.json",),
    )
    return compose_operator_brief_web_context(
        OperatorBriefWebContextCompositionInput(
            routes=(route,), relationships=(relationship,)
        )
    )


def _policy(
    token: str,
    *,
    family: OperatorBriefSourceNativeFamily = OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT,
    materiality: OperatorBriefThreadMateriality = OperatorBriefThreadMateriality.MATERIAL,
    independent: bool = True,
    association: OperatorBriefThreadPolicySubjectReference | None = None,
) -> OperatorBriefThreadPolicySubject:
    kind = (
        OperatorBriefSubjectKind.ACCOUNT_WORKFLOW
        if family is OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW
        else OperatorBriefSubjectKind.CONTENT_SURFACE
    )
    return OperatorBriefThreadPolicySubject(
        policy_key=f"POLICY-SOURCE-NATIVE-{token}",
        semantic_subject_key=f"source-native:persistence:{token}",
        subject_kind=kind,
        materiality=materiality,
        specificity=OperatorBriefThreadSpecificity.SPECIFIC,
        evidence_basis=OperatorBriefThreadEvidenceBasis.LEGACY,
        independent=independent,
        associated_subject_reference=association,
    )


def _encoded_interpretation(token: str) -> OperatorBriefEncodedArtifactInterpretation:
    endpoint = f"{_ORIGIN}/assets/{token}.js"
    return OperatorBriefEncodedArtifactInterpretation(
        classification_category="likely_signal",
        source_url=endpoint,
        artefact_type="encoded_like_artifact",
        value_sha256=sha256(token.encode()).hexdigest(),
        value_length=32,
    )


def _source_subject(
    policy: OperatorBriefThreadPolicySubject,
    *,
    family: OperatorBriefSourceNativeFamily = OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT,
    interpretation: object | None = None,
) -> OperatorBriefSourceNativeSubject:
    endpoint = f"{_ORIGIN}/native/{policy.policy_key.lower()}"
    if interpretation is None:
        interpretation = _encoded_interpretation(policy.policy_key)
    return OperatorBriefSourceNativeSubject(
        subject_id=f"SOURCE-NATIVE-{policy.policy_key}",
        family=family,
        policy_subject=policy,
        endpoints=(endpoint,),
        origins=(_ORIGIN,),
        evidence_ids=(f"EVID-{policy.policy_key}",),
        artefact_references=("native/source.js",),
        source_references=(OperatorBriefSourceReference("persistence_fixture", policy.policy_key),),
        interpretation=interpretation,  # type: ignore[arg-type]
    )


def _source_native(
    *policies: OperatorBriefThreadPolicySubject,
) -> OperatorBriefSourceNativeComposition:
    return OperatorBriefSourceNativeComposition(
        subjects=tuple(_source_subject(policy) for policy in policies)
    )


def _variant_interpretations() -> tuple[object, ...]:
    account_observation = WorkflowAccountObservation(
        kind=WorkflowAccountObservationKind.OBSERVED_FORM,
        url=f"{_ORIGIN}/login?secret=not-retained",
        evidence_ids=("EVID-ACCOUNT",),
        methods=("post",),
        field_names=("username",),
    )
    return (
        OperatorBriefStructuredDisclosureInterpretation(
            category="structured_configuration_body",
            source_url=f"{_ORIGIN}/runtime.conf",
            final_url=f"{_ORIGIN}/runtime.conf",
            body_sha256="a" * 64,
            disclosed_routes=("/api/v1",),
            redacted_excerpt_lines=("api_key=[REDACTED]",),
        ),
        OperatorBriefStructuredDisclosureInterpretation(
            category="structured_json_routes",
            source_url=f"{_ORIGIN}/routes.json",
            final_url=f"{_ORIGIN}/routes.json",
            body_sha256="d" * 64,
            disclosed_routes=("/api/v2",),
            redacted_excerpt_lines=("route=[REDACTED]",),
        ),
        OperatorBriefDirectoryListingInterpretation(
            canonical_url=f"{_ORIGIN}/public/",
            requested_urls=(f"{_ORIGIN}/public/",),
            status_code=200,
            content_type="text/html",
            body_sha256="b" * 64,
            listing_path="/public/",
        ),
        OperatorBriefAccessBoundaryInterpretation(
            fingerprint_id="PERSIST-FINGERPRINT",
            requested_url=f"{_ORIGIN}/admin",
            final_url=f"{_ORIGIN}/admin",
            method="GET",
            status_code=401,
            body_sha256="c" * 64,
            signal_kinds=(OperatorBriefAccessBoundarySignalKind.WWW_AUTHENTICATE,),
            contrast_category="client_error_signature_group",
            comparison_endpoints=(f"{_ORIGIN}/admin",),
            comparison_statuses=(401,),
            member_count=1,
        ),
        OperatorBriefCredentialInterpretation(
            source_url=f"{_ORIGIN}/assets/config.js",
            artefact_types=("sensitive_assignment",),
            assignment_labels=("api_key",),
            indicator_classes=(OperatorBriefCredentialIndicatorClass.SENSITIVE_ASSIGNMENT,),
        ),
        OperatorBriefAccountWorkflowInterpretation(
            origin=_ORIGIN,
            covered_urls=(f"{_ORIGIN}/login",),
            observations=(account_observation,),
        ),
        OperatorBriefObjectReferenceInterpretation(
            origin=_ORIGIN,
            covered_urls=(f"{_ORIGIN}/objects",),
            parameter_names=("id",),
        ),
        _encoded_interpretation("VARIANT"),
    )


def _variant_source_native() -> OperatorBriefSourceNativeComposition:
    families = (
        OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY,
        OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES,
        OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE,
        OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE,
        OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW,
        OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW,
        OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE,
        OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT,
    )
    return OperatorBriefSourceNativeComposition(
        subjects=tuple(
            _source_subject(
                _policy(f"VARIANT-{index}", family=family),
                family=family,
                interpretation=interpretation,
            )
            for index, (family, interpretation) in enumerate(
                zip(families, _variant_interpretations(), strict=True), start=1
            )
        )
    )


def _representative_composition() -> OperatorBriefComposition:
    http = _http(conflict=True)
    network = _network()
    web_context = _web()
    # The retained-body subject is the only HTTP subject at this origin.
    normalized_primary = next(
        item
        for item in assemble_operator_brief(
            http=http,
            network=_empty_network(),
            web_context=_empty_web(),
            source_native=OperatorBriefSourceNativeComposition(subjects=()),
        ).policy_subjects
        if item.subject_kind is OperatorBriefSubjectKind.APPLICATION
        and item.facts[0].endpoints == (f"{_ORIGIN}/application",)
    )
    associated = _policy(
        "ASSOCIATED",
        materiality=OperatorBriefThreadMateriality.CONTEXT,
        independent=False,
        association=OperatorBriefThreadPolicySubjectReference(
            normalized_primary.subject_kind,
            normalized_primary.semantic_subject_key or "",
        ),
    )
    source_native = _source_native(_policy("MATERIAL"), associated)
    return assemble_operator_brief(
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
    )


def _sparse_composition() -> OperatorBriefComposition:
    return assemble_operator_brief(
        http=_empty_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=_source_native(_policy("SPARSE")),
    )


def _empty_composition() -> OperatorBriefComposition:
    return assemble_operator_brief(
        http=_empty_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=OperatorBriefSourceNativeComposition(subjects=()),
    )


def _no_cap_composition() -> OperatorBriefComposition:
    return assemble_operator_brief(
        http=_empty_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=_source_native(*(_policy(f"CAP-{index:02d}") for index in range(6))),
    )


def _write(api: SimpleNamespace, root: Path, composition: OperatorBriefComposition) -> Path:
    return api.write_operator_brief_composition_artifact(root, composition)


def _composition_with_unsafe_artefact_reference(
    artefact_reference: str,
) -> OperatorBriefComposition:
    composition = _representative_composition()
    original = composition.http.facts[0]
    unsafe = replace(original, artefact_references=(artefact_reference,))
    http = replace(
        composition.http,
        facts=tuple(
            unsafe if item.fact_id == original.fact_id else item
            for item in composition.http.facts
        ),
    )
    policies = tuple(
        replace(
            item,
            facts=tuple(
                unsafe if fact.fact_id == original.fact_id else fact
                for fact in item.facts
            ),
        )
        if any(fact.fact_id == original.fact_id for fact in item.facts)
        else item
        for item in composition.policy_subjects
    )
    return replace(
        composition,
        http=http,
        thread_policy_result=replace(
            composition.thread_policy_result,
            subjects=policies,
        ),
    )


# Existing-source controls: these deliberately do not import the future module.


def test_source_control_representative_fixture_is_closed_stage5_graph() -> None:
    composition = _representative_composition()
    decisions = {item.policy_key: item for item in composition.thread_policy_result.decisions}
    http_owner = next(
        item
        for item in composition.http.subjects
        if f"{_ORIGIN}/application" in item.endpoints
    )
    expected_http_reference = OperatorBriefThreadPolicySubjectReference(
        OperatorBriefSubjectKind.APPLICATION,
        f"http:{http_owner.subject_id}",
    )
    web_policy = next(
        item
        for item in composition.policy_subjects
        if (item.semantic_subject_key or "").startswith("web:")
    )
    source_native_policy = next(
        item
        for item in composition.source_native.policy_subjects
        if item.associated_subject_reference is not None
    )

    assert isinstance(composition, OperatorBriefComposition)
    assert composition.http.conflicts
    assert composition.network.subjects
    assert composition.web_context.subjects
    assert composition.source_native.subjects
    assert web_policy.associated_subject_reference is not None
    assert web_policy.associated_subject_reference.subject_kind is OperatorBriefSubjectKind.APPLICATION
    assert web_policy.associated_subject_reference == expected_http_reference
    assert source_native_policy.associated_subject_reference is not None
    assert source_native_policy.associated_subject_reference == expected_http_reference
    assert any(item.disposition == PRIMARY_THREAD for item in decisions.values())
    assert any(item.disposition == SUPPORTING_CONTEXT for item in decisions.values())


def test_source_control_no_hard_cap_fixture_has_six_primary_decisions() -> None:
    composition = _no_cap_composition()

    assert len(composition.policy_subjects) == 6
    assert sorted(
        item.rank
        for item in composition.thread_policy_result.decisions
        if item.disposition == PRIMARY_THREAD
    ) == list(range(1, 7))


def test_source_control_every_closed_source_native_interpretation_variant_is_typed() -> None:
    composition = _variant_source_native()

    assert tuple(item.family for item in composition.subjects) == (
        OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY,
        OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES,
        OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE,
        OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE,
        OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW,
        OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW,
        OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE,
        OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT,
    )
    assert all(item.interpretation is not None for item in composition.subjects)


def test_source_control_storage_order_and_attention_rank_are_independent() -> None:
    direct = assemble_operator_brief(
        http=_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=OperatorBriefSourceNativeComposition(subjects=()),
    ).policy_subjects[0]
    legacy = replace(_policy("ATTENTION"), policy_key="AAA-LEGACY-STORAGE-FIRST")
    composition = assemble_operator_brief(
        http=_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=_source_native(legacy),
    )
    decisions = {item.policy_key: item for item in composition.thread_policy_result.decisions}

    assert composition.policy_subjects[0] is legacy
    assert decisions[direct.policy_key].rank == 1
    assert decisions[legacy.policy_key].rank == 2


# Future persistence contract. Every test below should currently fail only at _future_api().


def test_public_api_contract() -> None:
    api = _future_api()

    assert api.OPERATOR_BRIEF_COMPOSITION_FILENAME == _FILENAME
    write_parameters = signature(api.write_operator_brief_composition_artifact).parameters
    assert tuple(write_parameters) == ("root", "composition")
    assert all(item.kind is Parameter.POSITIONAL_OR_KEYWORD for item in write_parameters.values())
    assert get_type_hints(api.write_operator_brief_composition_artifact) == {
        "root": Path,
        "composition": OperatorBriefComposition,
        "return": Path,
    }
    assert get_type_hints(api.load_operator_brief_composition_artifact) == {
        "root": Path,
        "return": OperatorBriefComposition | None,
    }


def test_writer_rejects_noncomposition_input(tmp_path: Path) -> None:
    api = _future_api()

    with pytest.raises(TypeError):
        _write(api, tmp_path, object())  # type: ignore[arg-type]


@pytest.mark.parametrize("builder", (_empty_composition, _sparse_composition, _representative_composition))
def test_round_trip_preserves_empty_sparse_and_mixed_snapshots(
    tmp_path: Path, builder
) -> None:
    api = _future_api()
    live = builder()

    path = _write(api, tmp_path, live)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)

    assert path == tmp_path / _FILENAME
    assert loaded == live


def test_round_trip_restores_canonical_aliases(tmp_path: Path) -> None:
    api = _future_api()
    live = _representative_composition()
    _write(api, tmp_path, live)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)
    assert loaded is not None

    assert loaded.policy_subjects is loaded.thread_policy_result.subjects
    policy_by_key = {item.policy_key: item for item in loaded.policy_subjects}
    for source_subject in loaded.source_native.subjects:
        assert source_subject.policy_subject is policy_by_key[source_subject.policy_subject.policy_key]
    owner_facts = {
        fact.fact_id: fact
        for composition in (loaded.http, loaded.network, loaded.web_context)
        for fact in composition.facts
    }
    owner_conflicts = {item.conflict_id: item for item in loaded.http.conflicts}
    for policy in loaded.policy_subjects:
        for fact in policy.facts:
            assert fact is owner_facts[fact.fact_id]
        for conflict in policy.conflicts:
            assert conflict is owner_conflicts[conflict.conflict_id]


def test_persisted_graph_uses_owner_and_fact_conflict_references_once(tmp_path: Path) -> None:
    api = _future_api()
    _write(api, tmp_path, _representative_composition())
    payload = json.loads((tmp_path / _FILENAME).read_text(encoding="utf-8"))

    assert tuple(payload) == (
        "generated_by",
        "http",
        "network",
        "schema_version",
        "source_native",
        "thread_policy_result",
        "web_context",
    )
    assert payload["schema_version"] == 1
    assert payload["generated_by"] == _GENERATED_BY
    policies = payload["thread_policy_result"]["subjects"]
    assert all(set(item["owner_reference"]) == {"family", "subject_id"} for item in policies)
    assert all("policy_subject" not in item for item in payload["source_native"]["subjects"])
    normalized = [item for item in policies if item["owner_reference"]["family"] != "source_native"]
    assert all(all(set(ref) == {"owner", "fact_id"} for ref in item["facts"]) for item in normalized)
    assert all(all(set(ref) == {"owner", "conflict_id"} for ref in item["conflicts"]) for item in normalized)


def test_all_source_native_variants_round_trip_as_tagged_typed_interpretations(tmp_path: Path) -> None:
    api = _future_api()
    live = assemble_operator_brief(
        http=_empty_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=_variant_source_native(),
    )

    _write(api, tmp_path, live)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)

    assert loaded is not None
    assert tuple(type(item.interpretation) for item in loaded.source_native.subjects) == tuple(
        type(item.interpretation) for item in live.source_native.subjects
    )
    assert loaded.source_native == live.source_native


def test_no_hard_cap_and_storage_order_survive_round_trip(tmp_path: Path) -> None:
    api = _future_api()
    live = _no_cap_composition()
    _write(api, tmp_path, live)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)
    assert loaded is not None

    assert len(loaded.policy_subjects) == 6
    assert tuple(item.policy_key for item in loaded.policy_subjects) == tuple(
        sorted(item.policy_key for item in loaded.policy_subjects)
    )
    assert tuple(item.policy_key for item in loaded.thread_policy_result.decisions) == tuple(
        item.policy_key for item in loaded.policy_subjects
    )
    assert sorted(item.rank for item in loaded.thread_policy_result.decisions if item.rank) == list(range(1, 7))


def test_storage_order_remains_distinct_from_persisted_attention_rank(tmp_path: Path) -> None:
    api = _future_api()
    direct = assemble_operator_brief(
        http=_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=OperatorBriefSourceNativeComposition(subjects=()),
    ).policy_subjects[0]
    legacy = replace(_policy("ATTENTION"), policy_key="AAA-LEGACY-STORAGE-FIRST")
    live = assemble_operator_brief(
        http=_http(),
        network=_empty_network(),
        web_context=_empty_web(),
        source_native=_source_native(legacy),
    )
    _write(api, tmp_path, live)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)
    assert loaded is not None

    decisions = {item.policy_key: item for item in loaded.thread_policy_result.decisions}
    assert loaded.policy_subjects[0].policy_key == legacy.policy_key
    assert decisions[direct.policy_key].rank == 1
    assert decisions[legacy.policy_key].rank == 2


def test_writer_is_deterministic_and_replaces_only_regular_canonical_file(tmp_path: Path) -> None:
    api = _future_api()
    composition = _representative_composition()

    first = _write(api, tmp_path, composition).read_bytes()
    second = _write(api, tmp_path, composition).read_bytes()

    assert first == second
    assert first.endswith(b"\n")
    assert b"\n  \"generated_by\": \"bugslyce.operator_brief_composition\"" in first


def test_raw_duplicate_top_level_json_member_fails_closed(tmp_path: Path) -> None:
    api = _future_api()
    _write(api, tmp_path, _representative_composition())
    path = tmp_path / _FILENAME
    content = path.read_text(encoding="utf-8")
    valid_member = '  "schema_version": 1,'

    assert content.count(valid_member) == 1
    content = content.replace(
        valid_member,
        '  "schema_version": 999,\n' + valid_member,
        1,
    )
    assert content.index('  "schema_version": 999,') < content.index(valid_member)
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        api.load_operator_brief_composition_artifact(tmp_path)


def test_raw_duplicate_nested_policy_json_member_fails_closed(tmp_path: Path) -> None:
    api = _future_api()
    composition = _representative_composition()
    _write(api, tmp_path, composition)
    path = tmp_path / _FILENAME
    content = path.read_text(encoding="utf-8")
    subjects_start = content.index('    "subjects": [', content.index('  "thread_policy_result": {'))
    valid_policy_key = composition.policy_subjects[0].policy_key
    valid_member = f'        "policy_key": "{valid_policy_key}",'
    valid_member_start = content.index(valid_member, subjects_start)
    invalid_member = '        "policy_key": "POLICY-INVALID-DUPLICATE",\n'

    content = content[:valid_member_start] + invalid_member + content[valid_member_start:]
    assert content.index(invalid_member, subjects_start) < content.index(
        valid_member, subjects_start
    )
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        api.load_operator_brief_composition_artifact(tmp_path)


def test_writer_and_loader_do_not_semantically_replay_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    composition = _representative_composition()
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("semantic replay is forbidden during persistence")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_assembly.assemble_operator_brief", forbidden
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_multi_family_assembly.assemble_operator_brief_policy_subjects",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_http.compose_operator_brief_http", forbidden
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_network.compose_operator_brief_network", forbidden
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_web_context.compose_operator_brief_web_context",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_source_native.compose_operator_brief_source_native",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_thread_policy.apply_operator_brief_thread_policy",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_http.build_operator_brief_http_inputs_from_deep",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_network.build_operator_brief_network_inputs_from_project_state",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_web_context.build_operator_brief_web_context_inputs_from_project_state",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.artifact_classifier.classify_encoded_artifact", forbidden
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_source_native.classify_encoded_artifact",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.recon.deep_successful_content.directory_listing_title", forbidden
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_source_native.directory_listing_title",
        forbidden,
    )

    api = _future_api()
    _write(api, tmp_path, composition)
    loaded = api.load_operator_brief_composition_artifact(tmp_path)

    assert loaded == composition
    assert loaded.thread_policy_result.decisions == composition.thread_policy_result.decisions


def _json_copy(value: object) -> object:
    return json.loads(json.dumps(value))


def _policy_with(payload: dict[str, object], key: str) -> dict[str, object]:
    policies = payload["thread_policy_result"]["subjects"]  # type: ignore[index]
    return next(item for item in policies if item[key])  # type: ignore[index]


def _subject_with_fact(payload: dict[str, object]) -> dict[str, object]:
    policies = payload["thread_policy_result"]["subjects"]  # type: ignore[index]
    return next(item for item in policies if item["facts"])  # type: ignore[index]


def _subject_with_conflict(payload: dict[str, object]) -> dict[str, object]:
    policies = payload["thread_policy_result"]["subjects"]  # type: ignore[index]
    return next(item for item in policies if item["conflicts"])  # type: ignore[index]


def _duplicate_policy(payload: dict[str, object]) -> None:
    policies = payload["thread_policy_result"]["subjects"]  # type: ignore[index]
    policies.append(_json_copy(policies[0]))  # type: ignore[index]


def _duplicate_semantic_identity(payload: dict[str, object]) -> None:
    policies = payload["thread_policy_result"]["subjects"]  # type: ignore[index]
    duplicate = _json_copy(policies[0])  # type: ignore[index]
    duplicate["policy_key"] = "POLICY-DUPLICATE"  # type: ignore[index]
    policies.append(duplicate)  # type: ignore[index]


def _duplicate_decision(payload: dict[str, object]) -> None:
    decisions = payload["thread_policy_result"]["decisions"]  # type: ignore[index]
    decisions.append(_json_copy(decisions[0]))  # type: ignore[index]


def _missing_decision(payload: dict[str, object]) -> None:
    payload["thread_policy_result"]["decisions"].pop()  # type: ignore[index]


def _unknown_decision_subject(payload: dict[str, object]) -> None:
    payload["thread_policy_result"]["decisions"][0]["policy_key"] = "POLICY-UNKNOWN"  # type: ignore[index]


def _dangling_owner(payload: dict[str, object]) -> None:
    _policy_with(payload, "owner_reference")["owner_reference"]["subject_id"] = "MISSING"  # type: ignore[index]


def _dangling_fact(payload: dict[str, object]) -> None:
    _subject_with_fact(payload)["facts"][0]["fact_id"] = "MISSING"  # type: ignore[index]


def _dangling_conflict(payload: dict[str, object]) -> None:
    _subject_with_conflict(payload)["conflicts"][0]["conflict_id"] = "MISSING"  # type: ignore[index]


def _dangling_association(payload: dict[str, object]) -> None:
    subject = next(
        item
        for item in payload["thread_policy_result"]["subjects"]  # type: ignore[index]
        if item["associated_subject_reference"] is not None
    )
    subject["associated_subject_reference"]["semantic_subject_key"] = "http:missing"  # type: ignore[index]


def _dangling_replacement(payload: dict[str, object]) -> None:
    subject = next(
        item
        for item in payload["thread_policy_result"]["subjects"]  # type: ignore[index]
        if item["owner_reference"]["family"] == "source_native"
        and item["associated_subject_reference"] is None
    )
    subject["replaced_by_subject_reference"] = {
        "subject_kind": "application",
        "semantic_subject_key": "http:missing",
    }


def _association_and_replacement(payload: dict[str, object]) -> None:
    subject = next(
        item
        for item in payload["thread_policy_result"]["subjects"]  # type: ignore[index]
        if item["associated_subject_reference"] is not None
    )
    subject["replaced_by_subject_reference"] = _json_copy(subject["associated_subject_reference"])


def _invalid_thread_id(payload: dict[str, object]) -> None:
    decision = next(
        item
        for item in payload["thread_policy_result"]["decisions"]  # type: ignore[index]
        if item["disposition"] == PRIMARY_THREAD
    )
    decision["thread_id"] = "invalid"


def _invalid_supporting_thread_target(payload: dict[str, object]) -> None:
    decision = next(
        item
        for item in payload["thread_policy_result"]["decisions"]  # type: ignore[index]
        if item["disposition"] == SUPPORTING_CONTEXT
    )
    decision["thread_id"] = "THREAD-0000000000000000"


def _duplicate_primary_rank(payload: dict[str, object]) -> None:
    primaries = [
        item
        for item in payload["thread_policy_result"]["decisions"]  # type: ignore[index]
        if item["disposition"] == PRIMARY_THREAD
    ]
    primaries[1]["rank"] = primaries[0]["rank"]


def _non_contiguous_primary_rank(payload: dict[str, object]) -> None:
    primary = next(
        item
        for item in payload["thread_policy_result"]["decisions"]  # type: ignore[index]
        if item["disposition"] == PRIMARY_THREAD and item["rank"] == 1
    )
    primary["rank"] = 9


def _noncanonical_subject_order(payload: dict[str, object]) -> None:
    payload["thread_policy_result"]["subjects"].reverse()  # type: ignore[index]


def _noncanonical_decision_order(payload: dict[str, object]) -> None:
    payload["thread_policy_result"]["decisions"].reverse()  # type: ignore[index]


def _unknown_interpretation_type(payload: dict[str, object]) -> None:
    payload["source_native"]["subjects"][0]["interpretation"]["type"] = "unknown"  # type: ignore[index]


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload.__setitem__("schema_version", 999),
        lambda payload: payload.__setitem__("generated_by", "wrong"),
        lambda payload: payload.__setitem__("unexpected", "rejected"),
        lambda payload: payload.pop("http"),
        lambda payload: payload.__setitem__("network", []),
        _duplicate_policy,
        _duplicate_semantic_identity,
        _duplicate_decision,
        _missing_decision,
        _unknown_decision_subject,
        _dangling_owner,
        _dangling_fact,
        _dangling_conflict,
        _dangling_association,
        _dangling_replacement,
        _association_and_replacement,
        _invalid_thread_id,
        _invalid_supporting_thread_target,
        _duplicate_primary_rank,
        _non_contiguous_primary_rank,
        _noncanonical_subject_order,
        _noncanonical_decision_order,
        _unknown_interpretation_type,
    ),
    ids=(
        "unsupported_schema",
        "wrong_generated_by",
        "unexpected_top_level_field",
        "missing_required_section",
        "wrong_section_type",
        "duplicate_policy_key",
        "duplicate_semantic_identity",
        "duplicate_decision_key",
        "missing_decision",
        "decision_for_unknown_subject",
        "dangling_owner_reference",
        "dangling_fact_reference",
        "dangling_conflict_reference",
        "dangling_association",
        "dangling_replacement",
        "association_and_replacement",
        "invalid_thread_id",
        "invalid_supporting_thread_target",
        "duplicate_primary_rank",
        "noncontiguous_primary_ranks",
        "noncanonical_subject_order",
        "noncanonical_decision_order",
        "unknown_interpretation_type",
    ),
)
def test_structural_corruption_fails_closed(tmp_path: Path, mutation) -> None:
    api = _future_api()
    _write(api, tmp_path, _representative_composition())
    path = tmp_path / _FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutation(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        api.load_operator_brief_composition_artifact(tmp_path)


def test_wrong_top_level_json_type_fails_closed(tmp_path: Path) -> None:
    api = _future_api()
    (tmp_path / _FILENAME).write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError):
        api.load_operator_brief_composition_artifact(tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("artefact_references", ["/absolute.json"]),
        ("artefact_references", ["../escape.json"]),
        ("artefact_references", ["safe\u0000name.json"]),
        ("artefact_references", [""]),
    ),
)
def test_unsafe_persisted_artefact_references_fail_closed(
    tmp_path: Path, field: str, value: list[str]
) -> None:
    api = _future_api()
    _write(api, tmp_path, _representative_composition())
    path = tmp_path / _FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["http"]["facts"][0][field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="artefact|path"):
        api.load_operator_brief_composition_artifact(tmp_path)


def test_writer_rejects_constructor_valid_unsafe_artefact_reference(
    tmp_path: Path,
) -> None:
    composition = _composition_with_unsafe_artefact_reference("/absolute.json")
    assert composition.http.facts[0].artefact_references == ("/absolute.json",)
    api = _future_api()

    with pytest.raises(ValueError, match="artefact|path"):
        _write(api, tmp_path, composition)


def test_absent_canonical_file_returns_none_even_when_legacy_exists(tmp_path: Path) -> None:
    api = _future_api()
    (tmp_path / "operator_brief.json").write_text("{}", encoding="utf-8")

    assert api.load_operator_brief_composition_artifact(tmp_path) is None


def test_corrupt_canonical_file_never_falls_back_to_legacy(tmp_path: Path) -> None:
    api = _future_api()
    (tmp_path / "operator_brief.json").write_text("{}", encoding="utf-8")
    (tmp_path / _FILENAME).write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON|composition"):
        api.load_operator_brief_composition_artifact(tmp_path)


@pytest.mark.parametrize("kind", ("symlink", "directory"))
def test_canonical_destination_rejects_non_regular_filesystem_objects(
    tmp_path: Path, kind: str
) -> None:
    api = _future_api()
    path = tmp_path / _FILENAME
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)
    else:
        path.mkdir()

    with pytest.raises(ValueError, match="symlink|regular|file"):
        _write(api, tmp_path, _sparse_composition())
    with pytest.raises(ValueError, match="symlink|regular|file"):
        api.load_operator_brief_composition_artifact(tmp_path)
