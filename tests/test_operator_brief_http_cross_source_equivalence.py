from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha256
from inspect import Parameter, signature

from bugslyce.recon.deep_http_fingerprint_summary import EMPTY_BODY_SHA256
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.reports.operator_brief import (
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
)


_BODY = b"shared normalized response bytes"
_DIGEST = sha256(_BODY).hexdigest()


def _api():
    from bugslyce.reports.operator_brief_http import (
        OperatorBriefHttpCompositionInput,
        OperatorBriefHttpObservation,
        build_operator_brief_http_exact_equivalence,
        build_operator_brief_http_retained_body_observation,
        combine_operator_brief_http_inputs,
        compose_operator_brief_http,
        discover_operator_brief_http_cross_source_exact_equivalences,
    )

    return locals()


def _complete(
    api,
    observation_id: str = "HTTP-OBS-DEEP-1",
    endpoint: str = "https://example.test/deep",
    *,
    body_sha256: str = _DIGEST,
    body_bytes: int = len(_BODY),
    origin: HttpOrigin = HttpOrigin("https", "example.test", 443),
    evidence_id: str = "EVID-DEEP-1",
    artefact_reference: str = "deep_source_route_collection.json",
):
    return api["OperatorBriefHttpObservation"](
        observation_id=observation_id,
        source_fingerprint_id=f"FP-{observation_id}",
        endpoint=endpoint,
        final_url=endpoint,
        origin=origin,
        method="GET",
        status_code=200,
        status_bucket="2xx_success",
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        body_empty=body_bytes == 0,
        collection_stage="source_route_collection",
        evidence_ids=(evidence_id,),
        artefact_references=(artefact_reference,),
    )


def _retained(
    api,
    endpoint: str = "https://example.test/retained",
    *,
    source_id: str = "MANIFEST-HTML-1",
    body_sha256: str = _DIGEST,
    body_bytes: int = len(_BODY),
    evidence_id: str = "EVID-RETAINED-1",
    artefact_reference: str = "retained.html",
):
    return api["build_operator_brief_http_retained_body_observation"](
        source_kind="manifest_retained_html",
        source_id=source_id,
        endpoint=endpoint,
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        evidence_ids=(evidence_id,),
        artefact_references=(artefact_reference,),
    )


def _inputs(api, *, complete=(), retained=(), equivalences=()):
    return api["OperatorBriefHttpCompositionInput"](
        observations=tuple(complete),
        retained_content=tuple(retained),
        exact_equivalences=tuple(equivalences),
    )


def _equivalence(api, members, source_kind: str, source_id: str):
    return api["build_operator_brief_http_exact_equivalence"](
        body_sha256=members[0].body_sha256,
        observation_ids=tuple(item.observation_id for item in members),
        authority_references=(OperatorBriefSourceReference(source_kind, source_id),),
    )


def _discover(api, inputs):
    return api[
        "discover_operator_brief_http_cross_source_exact_equivalences"
    ](inputs)


def _mixed_equalities(inputs):
    return tuple(
        item
        for item in inputs.exact_equivalences
        if any(
            reference.source_kind == "cross_source_body_exact_hash"
            for reference in item.authority_references
        )
    )


def _response_equivalence_facts(composition):
    return tuple(
        item
        for item in composition.facts
        if item.kind is OperatorBriefFactKind.RESPONSE_EQUIVALENCE
    )


def test_cross_source_discovery_api_imports() -> None:
    api = _api()

    assert callable(
        api["discover_operator_brief_http_cross_source_exact_equivalences"]
    )


def test_cross_source_discovery_accepts_only_normalized_input() -> None:
    api = _api()
    function = api[
        "discover_operator_brief_http_cross_source_exact_equivalences"
    ]
    parameters = signature(function).parameters

    assert tuple(parameters) == ("inputs",)
    assert parameters["inputs"].kind is Parameter.POSITIONAL_OR_KEYWORD


def test_matching_complete_and_retained_members_create_one_mixed_equality() -> None:
    api = _api()
    complete = _complete(api)
    retained = _retained(api)

    discovered = _discover(
        api, _inputs(api, complete=(complete,), retained=(retained,))
    )

    assert len(_mixed_equalities(discovered)) == 1


def test_mixed_equality_uses_only_cross_source_hash_authority() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(api, complete=(_complete(api),), retained=(_retained(api),)),
    )
    authority_kinds = {
        reference.source_kind
        for reference in _mixed_equalities(discovered)[0].authority_references
    }

    assert authority_kinds == {"cross_source_body_exact_hash"}
    assert "deep_http_repeated_body_group" not in authority_kinds
    assert "retained_body_exact_hash" not in authority_kinds


def test_cross_source_authority_id_is_semantic_and_deterministic() -> None:
    api = _api()
    complete = _complete(api)
    retained = _retained(api)
    original = _discover(
        api, _inputs(api, complete=(complete,), retained=(retained,))
    )
    enriched_provenance = _discover(
        api,
        _inputs(
            api,
            complete=(
                replace(
                    complete,
                    evidence_ids=("EVID-OTHER",),
                    artefact_references=("other-deep.json",),
                ),
            ),
            retained=(
                replace(
                    retained,
                    evidence_ids=("EVID-OTHER-RETAINED",),
                    artefact_references=("other-retained.html",),
                ),
            ),
        ),
    )

    first = _mixed_equalities(original)[0].authority_references[0]
    second = _mixed_equalities(enriched_provenance)[0].authority_references[0]
    assert first == second
    assert first.source_id.strip()
    assert all(
        value not in first.source_id
        for value in ("EVID-OTHER", "other-deep.json", "other-retained.html")
    )


def test_cross_source_authority_id_changes_with_hash_group_semantics() -> None:
    api = _api()
    first = _discover(
        api,
        _inputs(api, complete=(_complete(api),), retained=(_retained(api),)),
    )
    other_body = b"other exact normalized bytes"
    other_digest = sha256(other_body).hexdigest()
    second = _discover(
        api,
        _inputs(
            api,
            complete=(
                _complete(
                    api,
                    "HTTP-OBS-DEEP-2",
                    "https://example.test/deep-other",
                    body_sha256=other_digest,
                    body_bytes=len(other_body),
                ),
            ),
            retained=(
                _retained(
                    api,
                    "https://example.test/retained-other",
                    source_id="MANIFEST-HTML-2",
                    body_sha256=other_digest,
                    body_bytes=len(other_body),
                ),
            ),
        ),
    )

    first_id = _mixed_equalities(first)[0].authority_references[0].source_id
    second_id = _mixed_equalities(second)[0].authority_references[0].source_id
    assert first_id != second_id


def test_mixed_equality_contains_both_semantic_member_ids() -> None:
    api = _api()
    complete = _complete(api)
    retained = _retained(api)
    equality = _mixed_equalities(
        _discover(api, _inputs(api, complete=(complete,), retained=(retained,)))
    )[0]

    assert equality.observation_ids == tuple(
        sorted((complete.observation_id, retained.observation_id))
    )


def test_same_digest_with_different_byte_count_creates_no_mixed_equality() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(_complete(api),),
            retained=(_retained(api, body_bytes=len(_BODY) + 1),),
        ),
    )

    assert _mixed_equalities(discovered) == ()


def test_different_digest_creates_no_mixed_equality() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(_complete(api),),
            retained=(_retained(api, body_sha256=sha256(b"other").hexdigest()),),
        ),
    )

    assert _mixed_equalities(discovered) == ()


def test_empty_complete_and_retained_members_create_no_mixed_equality() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(
                _complete(
                    api, body_sha256=EMPTY_BODY_SHA256, body_bytes=0
                ),
            ),
            retained=(
                _retained(
                    api, body_sha256=EMPTY_BODY_SHA256, body_bytes=0
                ),
            ),
        ),
    )

    assert _mixed_equalities(discovered) == ()


def test_complete_only_hash_group_creates_no_cross_source_equality() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )

    assert _mixed_equalities(_discover(api, _inputs(api, complete=complete))) == ()


def test_retained_only_hash_group_creates_no_cross_source_equality() -> None:
    api = _api()
    retained = (
        _retained(api, "https://example.test/a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/b", source_id="SOURCE-B"),
    )

    assert _mixed_equalities(_discover(api, _inputs(api, retained=retained))) == ()


def test_two_complete_and_one_retained_form_one_maximal_mixed_equality() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )
    retained = _retained(api)
    mixed = _mixed_equalities(
        _discover(api, _inputs(api, complete=complete, retained=(retained,)))
    )

    assert len(mixed) == 1
    assert set(mixed[0].observation_ids) == {
        *(item.observation_id for item in complete),
        retained.observation_id,
    }


def test_one_complete_and_two_retained_form_one_maximal_mixed_equality() -> None:
    api = _api()
    complete = _complete(api)
    retained = (
        _retained(api, "https://example.test/a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/b", source_id="SOURCE-B"),
    )
    mixed = _mixed_equalities(
        _discover(api, _inputs(api, complete=(complete,), retained=retained))
    )

    assert len(mixed) == 1
    assert set(mixed[0].observation_ids) == {
        complete.observation_id,
        *(item.observation_id for item in retained),
    }


def test_two_by_two_group_uses_one_maximal_relationship_not_pairwise_edges() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/deep-a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/deep-b"),
    )
    retained = (
        _retained(api, "https://example.test/retained-a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/retained-b", source_id="SOURCE-B"),
    )
    mixed = _mixed_equalities(
        _discover(api, _inputs(api, complete=complete, retained=retained))
    )

    assert len(mixed) == 1
    assert len(mixed[0].observation_ids) == 4


def test_existing_deep_only_equality_remains_unchanged() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )
    deep_equality = _equivalence(
        api, complete, "deep_http_repeated_body_group", "DEEP-GROUP-1"
    )
    retained = _retained(api)
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=complete,
            retained=(retained,),
            equivalences=(deep_equality,),
        ),
    )

    assert deep_equality in discovered.exact_equivalences
    assert len(discovered.exact_equivalences) == 2


def test_existing_retained_only_equality_remains_unchanged() -> None:
    api = _api()
    retained = (
        _retained(api, "https://example.test/a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/b", source_id="SOURCE-B"),
    )
    retained_equality = _equivalence(
        api, retained, "retained_body_exact_hash", "RETAINED-GROUP-1"
    )
    complete = _complete(api)
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(complete,),
            retained=retained,
            equivalences=(retained_equality,),
        ),
    )

    assert retained_equality in discovered.exact_equivalences
    assert len(discovered.exact_equivalences) == 2


def test_existing_same_core_mixed_equality_deduplicates() -> None:
    api = _api()
    members = (_complete(api), _retained(api))
    existing = _equivalence(
        api, members, "cross_source_body_exact_hash", "CROSS-EXACT-EXISTING"
    )
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(members[0],),
            retained=(members[1],),
            equivalences=(existing,),
        ),
    )

    assert len(_mixed_equalities(discovered)) == 1


def test_existing_same_core_mixed_equality_unions_compatible_authority() -> None:
    api = _api()
    members = (_complete(api), _retained(api))
    existing = _equivalence(
        api, members, "independent_normalized_hash", "INDEPENDENT-1"
    )
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(members[0],),
            retained=(members[1],),
            equivalences=(existing,),
        ),
    )
    same_core = tuple(
        item
        for item in discovered.exact_equivalences
        if item.equivalence_id == existing.equivalence_id
    )

    assert len(same_core) == 1
    assert {item.source_kind for item in same_core[0].authority_references} == {
        "cross_source_body_exact_hash",
        "independent_normalized_hash",
    }


def test_cross_source_discovery_is_idempotent() -> None:
    api = _api()
    inputs = _inputs(
        api, complete=(_complete(api),), retained=(_retained(api),)
    )
    once = _discover(api, inputs)

    assert _discover(api, once) == once


def test_complete_observation_order_is_deterministic() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )
    retained = (_retained(api),)

    assert _discover(
        api, _inputs(api, complete=complete, retained=retained)
    ) == _discover(api, _inputs(api, complete=reversed(complete), retained=retained))


def test_retained_observation_order_is_deterministic() -> None:
    api = _api()
    complete = (_complete(api),)
    retained = (
        _retained(api, "https://example.test/a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/b", source_id="SOURCE-B"),
    )

    assert _discover(
        api, _inputs(api, complete=complete, retained=retained)
    ) == _discover(api, _inputs(api, complete=complete, retained=reversed(retained)))


def test_existing_equality_order_is_deterministic() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )
    retained = (
        _retained(api, "https://example.test/c", source_id="SOURCE-C"),
        _retained(api, "https://example.test/d", source_id="SOURCE-D"),
    )
    equalities = (
        _equivalence(
            api, complete, "deep_http_repeated_body_group", "DEEP-GROUP-1"
        ),
        _equivalence(
            api, retained, "retained_body_exact_hash", "RETAINED-GROUP-1"
        ),
    )

    assert _discover(
        api,
        _inputs(
            api,
            complete=complete,
            retained=retained,
            equivalences=equalities,
        ),
    ) == _discover(
        api,
        _inputs(
            api,
            complete=complete,
            retained=retained,
            equivalences=reversed(equalities),
        ),
    )


def test_combined_adapter_input_order_is_deterministic() -> None:
    api = _api()
    deep = _inputs(api, complete=(_complete(api),))
    retained = _inputs(api, retained=(_retained(api),))
    combine = api["combine_operator_brief_http_inputs"]

    assert _discover(api, combine(deep, retained)) == _discover(
        api, combine(retained, deep)
    )


def test_cross_origin_and_different_endpoints_still_receive_relationship() -> None:
    api = _api()
    complete = _complete(
        api,
        endpoint="https://one.test/deep?view=full",
        origin=HttpOrigin("https", "one.test", 443),
    )
    retained = _retained(api, "http://two.test:8080/retained/")
    equality = _mixed_equalities(
        _discover(api, _inputs(api, complete=(complete,), retained=(retained,)))
    )[0]

    assert set(equality.observation_ids) == {
        complete.observation_id,
        retained.observation_id,
    }


def test_mixed_relationship_projects_only_derived_relationship_context() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(api, complete=(_complete(api),), retained=(_retained(api),)),
    )
    fact = _response_equivalence_facts(
        api["compose_operator_brief_http"](discovered)
    )[0]

    assert fact.kind is OperatorBriefFactKind.RESPONSE_EQUIVALENCE
    assert fact.semantic_class is OperatorBriefSemanticClass.DERIVED
    assert fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT


def test_mixed_relationship_does_not_merge_complete_and_retained_subjects() -> None:
    api = _api()
    discovered = _discover(
        api,
        _inputs(api, complete=(_complete(api),), retained=(_retained(api),)),
    )
    composition = api["compose_operator_brief_http"](discovered)

    assert len(composition.subjects) == 2


def test_deep_only_merge_survives_alongside_maximal_mixed_relationship() -> None:
    api = _api()
    complete = (
        _complete(api, "HTTP-OBS-DEEP-1", "https://example.test/a"),
        _complete(api, "HTTP-OBS-DEEP-2", "https://example.test/b"),
    )
    retained = _retained(api, "https://example.test/retained")
    deep_equality = _equivalence(
        api, complete, "deep_http_repeated_body_group", "DEEP-GROUP-1"
    )
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=complete,
            retained=(retained,),
            equivalences=(deep_equality,),
        ),
    )
    composition = api["compose_operator_brief_http"](discovered)
    complete_ids = {item.observation_id for item in complete}

    assert len(composition.subjects) == 2
    assert any(
        set(subject.observation_ids) == complete_ids
        for subject in composition.subjects
    )
    assert any(
        subject.observation_ids == (retained.observation_id,)
        for subject in composition.subjects
    )
    assert deep_equality in discovered.exact_equivalences
    assert len(_mixed_equalities(discovered)) == 1


def test_retained_only_equality_survives_when_mixed_relationship_is_added() -> None:
    api = _api()
    retained = (
        _retained(api, "https://example.test/a", source_id="SOURCE-A"),
        _retained(api, "https://example.test/b", source_id="SOURCE-B"),
    )
    retained_equality = _equivalence(
        api, retained, "retained_body_exact_hash", "RETAINED-GROUP-1"
    )
    discovered = _discover(
        api,
        _inputs(
            api,
            complete=(_complete(api),),
            retained=retained,
            equivalences=(retained_equality,),
        ),
    )

    assert retained_equality in discovered.exact_equivalences
    assert len(_mixed_equalities(discovered)) == 1


def test_mixed_equality_fact_closes_over_members_and_authority() -> None:
    api = _api()
    complete = _complete(api)
    retained = _retained(api)
    discovered = _discover(
        api, _inputs(api, complete=(complete,), retained=(retained,))
    )
    mixed = _mixed_equalities(discovered)[0]
    fact = _response_equivalence_facts(
        api["compose_operator_brief_http"](discovered)
    )[0]

    assert fact.evidence_ids == ("EVID-DEEP-1", "EVID-RETAINED-1")
    assert fact.artefact_references == (
        "deep_source_route_collection.json",
        "retained.html",
    )
    assert set(mixed.authority_references) <= set(fact.source_references)
    assert OperatorBriefSourceReference(
        "deep_http_fingerprint", complete.source_fingerprint_id
    ) in fact.source_references
    assert retained.source_references[0] in fact.source_references


def test_discovery_does_not_mutate_normalized_input() -> None:
    api = _api()
    inputs = _inputs(
        api, complete=(_complete(api),), retained=(_retained(api),)
    )
    original = replace(inputs)

    _discover(api, inputs)

    assert inputs == original


def test_discovery_requires_no_raw_body_or_storage_models() -> None:
    api = _api()
    function = api[
        "discover_operator_brief_http_cross_source_exact_equivalences"
    ]
    parameter_names = set(signature(function).parameters)
    forbidden_parameters = {
        "body",
        "body_bytes",
        "file",
        "path",
        "project_root",
        "manifest",
        "deep_summary",
        "project_state",
        "report",
    }
    forbidden_fields = {"body", "body_text", "response_body", "body_preview"}

    assert parameter_names == {"inputs"}
    assert forbidden_parameters.isdisjoint(parameter_names)
    assert forbidden_fields.isdisjoint(
        {item.name for item in fields(type(_complete(api)))}
    )
    assert forbidden_fields.isdisjoint(
        {item.name for item in fields(type(_retained(api)))}
    )
