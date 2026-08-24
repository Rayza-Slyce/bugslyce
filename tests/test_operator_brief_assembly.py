"""RED contract for pure final Stage 5 Operator Brief assembly."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from hashlib import sha256
from inspect import Parameter, signature
import importlib
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from bugslyce.reports.operator_brief import (
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpComposition,
    OperatorBriefHttpCompositionInput,
    build_operator_brief_http_retained_body_observation,
    compose_operator_brief_http,
)
from bugslyce.reports.operator_brief_multi_family_assembly import (
    assemble_operator_brief_policy_subjects,
)
from bugslyce.reports.operator_brief_network import OperatorBriefNetworkComposition
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefEncodedArtifactInterpretation,
    OperatorBriefSourceNativeComposition,
    OperatorBriefSourceNativeFamily,
    OperatorBriefSourceNativeSubject,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadPolicyResult,
    OperatorBriefThreadSpecificity,
    apply_operator_brief_thread_policy,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefWebContextComposition,
)


_FUTURE_MODULE = "bugslyce.reports.operator_brief_assembly"
_ORIGIN = "https://assembly.example.test"


def _future_api() -> SimpleNamespace:
    module = importlib.import_module(_FUTURE_MODULE)
    names = ("OperatorBriefComposition", "assemble_operator_brief")
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


def _http(*, route: str = f"{_ORIGIN}/application") -> OperatorBriefHttpComposition:
    body = sha256(route.encode("utf-8")).hexdigest()
    observation = build_operator_brief_http_retained_body_observation(
        source_kind="retained_http_body",
        source_id=f"HTTP-{route}",
        endpoint=route,
        body_sha256=body,
        body_bytes=64,
        evidence_ids=("EVID-HTTP",),
        artefact_references=("http.json",),
    )
    return compose_operator_brief_http(
        OperatorBriefHttpCompositionInput(
            observations=(), exact_equivalences=(), retained_content=(observation,)
        )
    )


def _normalized_subjects(
    http: OperatorBriefHttpComposition,
    network: OperatorBriefNetworkComposition,
    web_context: OperatorBriefWebContextComposition,
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    return assemble_operator_brief_policy_subjects(
        http=http,
        network=network,
        web_context=web_context,
    )


def _native_policy(
    token: str,
    *,
    policy_key: str | None = None,
    semantic_subject_key: str | None = None,
    subject_kind: OperatorBriefSubjectKind = OperatorBriefSubjectKind.CONTENT_SURFACE,
    materiality: OperatorBriefThreadMateriality = OperatorBriefThreadMateriality.MATERIAL,
    independent: bool = True,
    associated_subject_reference: OperatorBriefThreadPolicySubjectReference | None = None,
    replaced_by_subject_reference: OperatorBriefThreadPolicySubjectReference | None = None,
) -> OperatorBriefThreadPolicySubject:
    return OperatorBriefThreadPolicySubject(
        policy_key=policy_key or f"POLICY-SOURCE-NATIVE-{token}",
        semantic_subject_key=semantic_subject_key or f"source-native:synthetic:{token}",
        subject_kind=subject_kind,
        materiality=materiality,
        specificity=OperatorBriefThreadSpecificity.SPECIFIC,
        evidence_basis=OperatorBriefThreadEvidenceBasis.LEGACY,
        independent=independent,
        associated_subject_reference=associated_subject_reference,
        replaced_by_subject_reference=replaced_by_subject_reference,
    )


def _native_subject(
    policy_subject: OperatorBriefThreadPolicySubject,
    *,
    endpoint: str | None = None,
) -> OperatorBriefSourceNativeSubject:
    endpoint = endpoint or f"{_ORIGIN}/native/{policy_subject.policy_key}"
    return OperatorBriefSourceNativeSubject(
        subject_id=f"SOURCE-NATIVE-{policy_subject.policy_key}",
        family=OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT,
        policy_subject=policy_subject,
        endpoints=(endpoint,),
        origins=(_ORIGIN,),
        evidence_ids=(f"EVID-{policy_subject.policy_key}",),
        artefact_references=("native-source.js",),
        source_references=(OperatorBriefSourceReference("synthetic", policy_subject.policy_key),),
        interpretation=OperatorBriefEncodedArtifactInterpretation(
            classification_category="likely_signal",
            source_url=endpoint,
            artefact_type="encoded_like_artifact",
            value_sha256=sha256(policy_subject.policy_key.encode("utf-8")).hexdigest(),
            value_length=32,
        ),
    )


def _source_native(
    *subjects: OperatorBriefThreadPolicySubject,
    endpoint: str | None = None,
) -> OperatorBriefSourceNativeComposition:
    return OperatorBriefSourceNativeComposition(
        subjects=tuple(_native_subject(subject, endpoint=endpoint) for subject in subjects)
    )


def _empty_source_native() -> OperatorBriefSourceNativeComposition:
    return OperatorBriefSourceNativeComposition(subjects=())


def _assemble(api: SimpleNamespace, **overrides: object):
    values = {
        "http": _empty_http(),
        "network": _empty_network(),
        "web_context": _empty_web(),
        "source_native": _empty_source_native(),
    }
    values.update(overrides)
    return api.assemble_operator_brief(**values)


# Existing-source controls: these must remain independent of the future module.


def test_source_control_closed_owners_accept_valid_mixed_union() -> None:
    http = _http()
    normalized = _normalized_subjects(http, _empty_network(), _empty_web())
    source_native = _source_native(_native_policy("CONTROL"))

    result = apply_operator_brief_thread_policy(
        tuple(sorted((*normalized, *source_native.policy_subjects), key=lambda item: item.policy_key))
    )

    assert len(result.subjects) == len(result.decisions) == 2


def test_source_control_closed_policy_accepts_valid_association() -> None:
    normalized = _normalized_subjects(_http(), _empty_network(), _empty_web())
    primary = normalized[0]
    associated = _native_policy(
        "ASSOCIATED",
        materiality=OperatorBriefThreadMateriality.CONTEXT,
        independent=False,
        associated_subject_reference=OperatorBriefThreadPolicySubjectReference(
            primary.subject_kind,
            primary.semantic_subject_key or "",
        ),
    )

    result = apply_operator_brief_thread_policy((primary, associated))

    decisions = {item.policy_key: item for item in result.decisions}
    assert decisions[associated.policy_key].thread_id == decisions[primary.policy_key].thread_id


def test_source_control_direct_attention_precedes_legacy_despite_storage_order() -> None:
    normalized = _normalized_subjects(_http(), _empty_network(), _empty_web())
    direct = normalized[0]
    legacy = _native_policy("ATTENTION", policy_key="AAA-LEGACY-STORAGE-FIRST")

    result = apply_operator_brief_thread_policy(
        tuple(sorted((direct, legacy), key=lambda item: item.policy_key))
    )
    decisions = {item.policy_key: item for item in result.decisions}

    assert result.subjects[0] is legacy
    assert decisions[direct.policy_key].rank == 1
    assert decisions[legacy.policy_key].rank == 2


# Future final-assembly contract.


def test_public_model_and_keyword_only_api_shape() -> None:
    api = _future_api()
    assert tuple(field.name for field in fields(api.OperatorBriefComposition)) == (
        "http",
        "network",
        "web_context",
        "source_native",
        "thread_policy_result",
    )
    hints = get_type_hints(api.OperatorBriefComposition)
    assert hints == {
        "http": OperatorBriefHttpComposition,
        "network": OperatorBriefNetworkComposition,
        "web_context": OperatorBriefWebContextComposition,
        "source_native": OperatorBriefSourceNativeComposition,
        "thread_policy_result": OperatorBriefThreadPolicyResult,
    }
    parameters = signature(api.assemble_operator_brief).parameters
    assert tuple(parameters) == ("http", "network", "web_context", "source_native")
    assert all(item.kind is Parameter.KEYWORD_ONLY for item in parameters.values())
    assert get_type_hints(api.assemble_operator_brief)["return"] is api.OperatorBriefComposition
    with pytest.raises(TypeError):
        api.assemble_operator_brief(_empty_http(), _empty_network(), _empty_web(), _empty_source_native())


def test_final_composition_is_frozen_and_has_no_duplicate_policy_or_decision_field() -> None:
    composition = _assemble(_future_api(), source_native=_source_native(_native_policy("FROZEN")))

    assert "policy_subjects" not in {field.name for field in fields(composition)}
    assert "decisions" not in {field.name for field in fields(composition)}
    assert isinstance(composition.thread_policy_result, OperatorBriefThreadPolicyResult)
    with pytest.raises(FrozenInstanceError):
        composition.source_native = _empty_source_native()
    with pytest.raises(FrozenInstanceError):
        composition.thread_policy_result = apply_operator_brief_thread_policy(())


def test_empty_assembly_retains_inputs_and_has_no_filler() -> None:
    api = _future_api()
    http, network, web_context, source_native = (
        _empty_http(),
        _empty_network(),
        _empty_web(),
        _empty_source_native(),
    )
    composition = _assemble(
        api,
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
    )

    assert (composition.http, composition.network, composition.web_context, composition.source_native) == (
        http,
        network,
        web_context,
        source_native,
    )
    assert composition.http is http
    assert composition.network is network
    assert composition.web_context is web_context
    assert composition.source_native is source_native
    assert composition.policy_subjects == ()
    assert composition.thread_policy_result.subjects == ()
    assert composition.thread_policy_result.decisions == ()


def test_normalized_only_delegates_to_closed_normalized_owner() -> None:
    api = _future_api()
    http = _http()
    network, web_context, source_native = _empty_network(), _empty_web(), _empty_source_native()
    expected = _normalized_subjects(http, network, web_context)
    composition = _assemble(
        api,
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
    )

    assert composition.http is http
    assert composition.network is network
    assert composition.web_context is web_context
    assert composition.source_native is source_native
    assert composition.policy_subjects == expected
    assert len(composition.thread_policy_result.decisions) == len(expected)


def test_source_native_only_retains_closed_source_native_projection() -> None:
    api = _future_api()
    source_native = _source_native(_native_policy("ONLY"))
    composition = _assemble(api, source_native=source_native)

    assert composition.source_native is source_native
    assert composition.policy_subjects == source_native.policy_subjects
    assert len(composition.thread_policy_result.decisions) == 1


def test_mixed_union_keeps_association_distinct_from_identity_merging() -> None:
    api = _future_api()
    http = _http()
    normalized = _normalized_subjects(http, _empty_network(), _empty_web())
    primary = normalized[0]
    associated = _native_policy(
        "CONTEXT",
        materiality=OperatorBriefThreadMateriality.CONTEXT,
        independent=False,
        associated_subject_reference=OperatorBriefThreadPolicySubjectReference(
            primary.subject_kind,
            primary.semantic_subject_key or "",
        ),
    )
    source_native = _source_native(associated)
    composition = _assemble(api, http=http, source_native=source_native)

    assert set(composition.policy_subjects) == {primary, associated}
    assert primary.semantic_subject_key != associated.semantic_subject_key
    decisions = {item.policy_key: item for item in composition.thread_policy_result.decisions}
    assert len(decisions) == 2
    assert decisions[associated.policy_key].thread_id == decisions[primary.policy_key].thread_id


def test_policy_subjects_are_derived_from_result_in_canonical_storage_order() -> None:
    api = _future_api()
    source_native = _source_native(_native_policy("Z"), _native_policy("A"))
    composition = _assemble(api, source_native=source_native)

    assert composition.policy_subjects is composition.thread_policy_result.subjects
    assert tuple(item.policy_key for item in composition.policy_subjects) == tuple(
        sorted(item.policy_key for item in composition.policy_subjects)
    )


def test_storage_order_is_distinct_from_closed_attention_rank() -> None:
    api = _future_api()
    direct_http = _http(route=f"{_ORIGIN}/z-direct")
    direct = _normalized_subjects(direct_http, _empty_network(), _empty_web())[0]
    legacy = _native_policy("ATTENTION", policy_key="AAA-LEGACY-STORAGE-FIRST")
    composition = _assemble(api, http=direct_http, source_native=_source_native(legacy))

    assert tuple(item.policy_key for item in composition.policy_subjects) == tuple(
        sorted(item.policy_key for item in composition.policy_subjects)
    )
    assert composition.policy_subjects[0] is legacy
    decisions = {item.policy_key: item for item in composition.thread_policy_result.decisions}
    assert decisions[direct.policy_key].rank == 1
    assert decisions[legacy.policy_key].rank == 2


def test_no_hard_cap_preserves_ten_independent_source_native_subjects() -> None:
    api = _future_api()
    source_native = _source_native(*(_native_policy(f"CAP-{index:02d}") for index in range(10)))
    composition = _assemble(api, source_native=source_native)

    assert len(composition.policy_subjects) == 10
    assert len(composition.thread_policy_result.decisions) == 10
    assert sorted(
        item.rank for item in composition.thread_policy_result.decisions if item.rank is not None
    ) == list(range(1, 11))


def test_cross_source_policy_key_collision_fails_closed() -> None:
    api = _future_api()
    http = _http()
    normalized = _normalized_subjects(http, _empty_network(), _empty_web())[0]
    source_native = _source_native(
        _native_policy("KEY-COLLISION", policy_key=normalized.policy_key)
    )

    with pytest.raises(ValueError, match="duplicate policy"):
        _assemble(api, http=http, source_native=source_native)


def test_cross_source_composite_semantic_identity_collision_fails_closed() -> None:
    api = _future_api()
    http = _http()
    normalized = _normalized_subjects(http, _empty_network(), _empty_web())[0]
    source_native = _source_native(
        _native_policy(
            "SEMANTIC-COLLISION",
            semantic_subject_key=normalized.semantic_subject_key,
            subject_kind=normalized.subject_kind,
        )
    )

    with pytest.raises(ValueError, match="duplicate semantic"):
        _assemble(api, http=http, source_native=source_native)


def test_distinct_namespaces_remain_distinct_subjects() -> None:
    api = _future_api()
    shared_route = f"{_ORIGIN}/shared"
    http = _http(route=shared_route)
    normalized = _normalized_subjects(http, _empty_network(), _empty_web())[0]
    assert normalized.facts[0].endpoints == (shared_route,)
    assert normalized.facts[0].origins == (_ORIGIN,)
    source_native = _source_native(
        _native_policy(
            "NAMESPACE",
            semantic_subject_key=f"source-native:{normalized.semantic_subject_key}",
        ),
        endpoint=shared_route,
    )
    composition = _assemble(api, http=http, source_native=source_native)

    source_subject = source_native.subjects[0]
    assert source_subject.endpoints == (shared_route,)
    assert source_subject.origins == (_ORIGIN,)
    assert source_subject.policy_subject.semantic_subject_key != normalized.semantic_subject_key
    assert len(composition.policy_subjects) == 2
    assert len(composition.thread_policy_result.decisions) == 2


def test_unresolved_association_propagates_closed_policy_rejection() -> None:
    api = _future_api()
    missing = OperatorBriefThreadPolicySubjectReference(
        OperatorBriefSubjectKind.APPLICATION,
        "http:missing-primary",
    )
    source_native = _source_native(
        _native_policy(
            "UNRESOLVED",
            materiality=OperatorBriefThreadMateriality.CONTEXT,
            independent=False,
            associated_subject_reference=missing,
        )
    )

    with pytest.raises(ValueError, match="association.*primary|reference.*primary"):
        _assemble(api, source_native=source_native)


def test_invalid_replacement_propagates_closed_policy_rejection() -> None:
    api = _future_api()
    missing = OperatorBriefThreadPolicySubjectReference(
        OperatorBriefSubjectKind.APPLICATION,
        "http:missing-replacement",
    )
    source_native = _source_native(
        _native_policy("REPLACEMENT", replaced_by_subject_reference=missing)
    )

    with pytest.raises(ValueError, match="replacement.*primary|reference.*primary"):
        _assemble(api, source_native=source_native)


@pytest.mark.parametrize("name", ("http", "network", "web_context", "source_native"))
def test_invalid_top_level_input_type_fails_closed(name: str) -> None:
    api = _future_api()
    values = {
        "http": _empty_http(),
        "network": _empty_network(),
        "web_context": _empty_web(),
        "source_native": _empty_source_native(),
    }
    values[name] = object()

    with pytest.raises(TypeError):
        api.assemble_operator_brief(**values)


def test_equivalent_owner_compositions_produce_equal_final_composition() -> None:
    api = _future_api()
    first = _assemble(
        api,
        http=_http(route=f"{_ORIGIN}/permutation"),
        source_native=_source_native(_native_policy("EQUIVALENT-B"), _native_policy("EQUIVALENT-A")),
    )
    second = _assemble(
        api,
        http=_http(route=f"{_ORIGIN}/permutation"),
        source_native=_source_native(_native_policy("EQUIVALENT-A"), _native_policy("EQUIVALENT-B")),
    )

    assert first == second
