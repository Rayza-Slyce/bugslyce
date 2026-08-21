from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha256
from inspect import signature

import pytest

from bugslyce.recon.deep_http_fingerprint_summary import (
    EMPTY_BODY_SHA256,
    DeepHttpFingerprintSummary,
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.recon.http_route_relationships import canonical_relationship_url
from bugslyce.reports.operator_brief import (
    OperatorBriefConflictKind,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
)


def _api():
    from bugslyce.reports.operator_brief_http import (
        OperatorBriefHttpComposition,
        OperatorBriefHttpCompositionInput,
        OperatorBriefHttpExactEquivalence,
        OperatorBriefHttpObservation,
        OperatorBriefHttpSubject,
        build_operator_brief_http_inputs_from_deep,
        compose_operator_brief_http,
    )

    return locals()


def _source_item(
    url: str,
    *,
    method: str = "GET",
    status_code: int = 200,
    body: bytes = b"retained application response",
    final_url: str | None = None,
    evidence_id: str | None = None,
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method=method,
        status_code=status_code,
        final_url=final_url or url,
        headers=(("Content-Type", "text/html; charset=utf-8"),),
        body_preview=body.decode("utf-8", errors="replace"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="exact retained source/route observation",
        evidence_ids=(
            evidence_id
            or "EVID-" + sha256(url.encode("utf-8")).hexdigest()[:12].upper(),
        ),
        body=body,
    )


def _summary(*items: DeepSourceRouteCollectedItem) -> DeepHttpFingerprintSummary:
    metadata = DeepMetadataCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )
    source = DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )
    return build_deep_http_fingerprint_summary(metadata, source)


def _compose(summary: DeepHttpFingerprintSummary):
    api = _api()
    inputs = api["build_operator_brief_http_inputs_from_deep"](summary)
    return api, inputs, api["compose_operator_brief_http"](inputs)


def _facts(composition, kind: OperatorBriefFactKind):
    return tuple(fact for fact in composition.facts if fact.kind is kind)


def _subject_for_endpoint(composition, endpoint: str):
    canonical = canonical_relationship_url(endpoint)
    return next(subject for subject in composition.subjects if canonical in subject.endpoints)


def test_deep_response_adapts_to_observed_direct_http_fact() -> None:
    item = _source_item(
        "https://example.test/admin",
        evidence_id="EVID-ADMIN-200",
    )

    _api_values, inputs, composition = _compose(_summary(item))

    assert len(inputs.observations) == 1
    observation = inputs.observations[0]
    assert observation.endpoint == "https://example.test/admin"
    assert observation.origin == HttpOrigin("https", "example.test", 443)
    assert observation.method == "GET"
    assert observation.status_code == 200
    assert observation.body_sha256 == item.body_sha256
    assert observation.evidence_ids == ("EVID-ADMIN-200",)
    assert observation.artefact_references == (
        DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    )

    fact = _facts(composition, OperatorBriefFactKind.HTTP_RESPONSE)[0]
    assert fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
    assert fact.http_method == "GET"
    assert fact.http_status_code == 200
    assert fact.endpoints == ("https://example.test/admin",)
    assert fact.body_sha256 == item.body_sha256
    assert fact.evidence_ids == ("EVID-ADMIN-200",)


def test_authoritative_exact_group_becomes_derived_relationship_fact() -> None:
    body = b"same retained page"
    summary = _summary(
        _source_item("https://example.test/", body=body, evidence_id="EVID-ROOT"),
        _source_item(
            "https://example.test/index.php",
            body=body,
            evidence_id="EVID-INDEX",
        ),
    )

    _api_values, inputs, composition = _compose(summary)

    assert len(summary.repeated_body_groups) == 1
    assert len(inputs.exact_equivalences) == 1
    fact = _facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)[0]
    assert fact.semantic_class is OperatorBriefSemanticClass.DERIVED
    assert fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT
    assert fact.body_sha256 == sha256(body).hexdigest()
    assert fact.endpoints == (
        "https://example.test/",
        "https://example.test/index.php",
    )
    assert fact.evidence_ids == ("EVID-INDEX", "EVID-ROOT")


def test_same_origin_method_status_and_exact_body_compose_one_subject() -> None:
    body = b"one exact successful response"
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/", body=body),
            _source_item("https://example.test/index", body=body),
        )
    )

    assert len(composition.subjects) == 1
    assert composition.subjects[0].endpoints == (
        "https://example.test/",
        "https://example.test/index",
    )
    assert len(composition.subjects[0].observation_ids) == 2


def test_alias_looking_paths_without_exact_proof_remain_separate() -> None:
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/", body=b"root"),
            _source_item("https://example.test/index", body=b"index"),
            _source_item("https://example.test/index.php", body=b"index php"),
        )
    )

    assert inputs.exact_equivalences == ()
    assert len(composition.subjects) == 3


def test_three_authoritatively_equal_members_compose_deterministically() -> None:
    body = b"three exact aliases"
    items = (
        _source_item("https://example.test/", body=body),
        _source_item("https://example.test/index", body=body),
        _source_item("https://example.test/index.php", body=body),
    )

    _api_values, _inputs, first = _compose(_summary(*items))
    _api_values, _inputs, second = _compose(_summary(*reversed(items)))

    assert first == second
    assert len(first.subjects) == 1
    assert first.subjects[0].endpoints == (
        "https://example.test/",
        "https://example.test/index",
        "https://example.test/index.php",
    )


def test_exact_repeated_client_error_body_does_not_compose_subjects() -> None:
    body = b"not found template"
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/missing-a", status_code=404, body=body),
            _source_item("https://example.test/missing-b", status_code=404, body=body),
        )
    )

    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2


def test_exact_repeated_server_error_body_does_not_compose_subjects() -> None:
    body = b"server error template"
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/error-a", status_code=500, body=body),
            _source_item("https://example.test/error-b", status_code=500, body=body),
        )
    )

    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2


def test_empty_body_equivalence_is_defensively_non_grouping() -> None:
    body = b"non-empty source relationship"
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/empty-a", body=body),
            _source_item("https://example.test/empty-b", body=body),
        )
    )
    empty_observations = tuple(
        replace(
            observation,
            body_sha256=EMPTY_BODY_SHA256,
            body_bytes=0,
            body_empty=True,
        )
        for observation in inputs.observations
    )
    empty_equivalence = replace(
        inputs.exact_equivalences[0],
        body_sha256=EMPTY_BODY_SHA256,
    )
    defensive_inputs = replace(
        inputs,
        observations=empty_observations,
        exact_equivalences=(empty_equivalence,),
    )

    composition = api["compose_operator_brief_http"](defensive_inputs)

    assert len(composition.subjects) == 2


def test_cross_origin_exact_equality_is_relationship_only() -> None:
    body = b"same bytes across origins"
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/", body=body),
            _source_item("https://other.test/", body=body),
        )
    )

    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2
    assert len(_facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)) == 1


def test_different_http_methods_do_not_merge() -> None:
    body = b"same bytes different method"
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/action", method="GET", body=body),
            _source_item("https://example.test/action", method="POST", body=body),
        )
    )

    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2


def test_different_successful_statuses_are_relationship_only() -> None:
    body = b"same bytes different successful status"
    _api_values, inputs, composition = _compose(
        _summary(
            _source_item("https://example.test/a", status_code=200, body=body),
            _source_item("https://example.test/b", status_code=201, body=body),
        )
    )

    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2
    assert len(_facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)) == 1


def test_same_endpoint_differing_statuses_create_one_neutral_conflict() -> None:
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item(
                "https://example.test/admin/",
                method="HEAD",
                status_code=404,
                body=b"not found",
                evidence_id="EVID-ADMIN-HEAD-404",
            ),
            _source_item(
                "https://example.test/admin/",
                method="GET",
                status_code=200,
                body=b"admin page",
                evidence_id="EVID-ADMIN-GET-200",
            ),
        )
    )

    assert len(composition.conflicts) == 1
    conflict = composition.conflicts[0]
    assert conflict.kind is OperatorBriefConflictKind.DIFFERING_HTTP_STATUS
    assert conflict.subject_endpoint == "https://example.test/admin/"
    assert tuple(item.status_code for item in conflict.observations) == (200, 404)


def test_status_conflict_preserves_each_observed_method() -> None:
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item(
                "https://example.test/admin/",
                method="HEAD",
                status_code=404,
                body=b"not found",
            ),
            _source_item(
                "https://example.test/admin/",
                method="GET",
                status_code=200,
                body=b"admin page",
            ),
        )
    )

    observations = composition.conflicts[0].observations
    assert {(item.method, item.status_code) for item in observations} == {
        ("GET", 200),
        ("HEAD", 404),
    }


def test_status_conflict_does_not_claim_chronology_or_change() -> None:
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item(
                "https://example.test/admin/",
                method="HEAD",
                status_code=404,
                body=b"not found",
            ),
            _source_item(
                "https://example.test/admin/",
                method="GET",
                status_code=200,
                body=b"admin page",
            ),
        )
    )

    summary = composition.conflicts[0].summary.casefold()
    assert not {"earlier", "later", "changed", "became", "now"}.intersection(
        summary.split()
    )
    assert "differing http status" in summary


def test_default_port_forms_share_canonical_origin_for_composition() -> None:
    body = b"same default-port response"
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item("http://example.test/", body=body),
            _source_item("http://example.test:80/index", body=body),
        )
    )

    assert len(composition.subjects) == 1
    assert composition.subjects[0].origins == ("http://example.test",)


def test_high_port_origin_remains_distinct() -> None:
    body = b"same bytes distinct port"
    _api_values, _inputs, composition = _compose(
        _summary(
            _source_item("http://example.test/", body=body),
            _source_item("http://example.test:8080/", body=body),
        )
    )

    assert len(composition.subjects) == 2
    assert {subject.origins for subject in composition.subjects} == {
        ("http://example.test",),
        ("http://example.test:8080",),
    }


def test_exact_endpoint_normalization_preserves_query_and_trailing_slash() -> None:
    expected = (
        "https://example.test/search",
        "https://example.test/search/",
        "https://example.test/search?tenant=alpha",
        "https://example.test/search?tenant=beta",
    )
    items = tuple(
        _source_item(endpoint, body=f"body-{index}".encode("ascii"))
        for index, endpoint in enumerate(expected)
    )

    _api_values, inputs, composition = _compose(_summary(*items))

    assert tuple(item.endpoint for item in inputs.observations) == expected
    assert tuple(subject.endpoints[0] for subject in composition.subjects) == expected


def test_input_permutation_produces_identical_composition() -> None:
    body = b"same permutation body"
    summary = _summary(
        _source_item("https://example.test/", body=body),
        _source_item("https://example.test/index", body=body),
        _source_item("https://example.test/other", body=b"other"),
    )
    api = _api()
    inputs = api["build_operator_brief_http_inputs_from_deep"](summary)
    permuted = replace(
        inputs,
        observations=tuple(reversed(inputs.observations)),
        exact_equivalences=tuple(reversed(inputs.exact_equivalences)),
    )

    assert api["compose_operator_brief_http"](inputs) == api[
        "compose_operator_brief_http"
    ](permuted)


def test_composed_subject_preserves_complete_member_provenance() -> None:
    body = b"same provenance body"
    summary = _summary(
        _source_item(
            "https://example.test/",
            body=body,
            evidence_id="EVID-ROOT",
        ),
        _source_item(
            "https://example.test/index",
            body=body,
            evidence_id="EVID-INDEX",
        ),
    )

    _api_values, inputs, composition = _compose(summary)

    subject = composition.subjects[0]
    assert subject.endpoints == (
        "https://example.test/",
        "https://example.test/index",
    )
    assert subject.origins == ("https://example.test",)
    assert subject.evidence_ids == ("EVID-INDEX", "EVID-ROOT")
    assert subject.artefact_references == (
        DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    )
    assert subject.observation_ids == tuple(
        item.observation_id for item in inputs.observations
    )
    source_ids = {
        reference.source_id
        for fact in composition.facts
        for reference in fact.source_references
    }
    assert {item.source_fingerprint_id for item in inputs.observations}.issubset(
        source_ids
    )


def test_http_composition_models_have_no_arbitrary_raw_body_fields() -> None:
    api = _api()

    for type_name in (
        "OperatorBriefHttpObservation",
        "OperatorBriefHttpExactEquivalence",
        "OperatorBriefHttpCompositionInput",
        "OperatorBriefHttpSubject",
        "OperatorBriefHttpComposition",
    ):
        field_names = {field.name for field in fields(api[type_name])}
        assert {"body", "response_body", "body_text"}.isdisjoint(field_names)


def test_sparse_single_deep_response_produces_one_subject() -> None:
    _api_values, inputs, composition = _compose(
        _summary(_source_item("https://example.test/only"))
    )

    assert len(inputs.observations) == 1
    assert inputs.exact_equivalences == ()
    assert len(composition.subjects) == 1


def test_ordinal_deep_ids_do_not_define_semantic_observation_or_subject_identity() -> None:
    stable_body = b"stable exact pair"
    stable_items = (
        _source_item("https://example.test/stable-a", body=stable_body),
        _source_item("https://example.test/stable-b", body=stable_body),
    )
    first_summary = _summary(*stable_items)
    second_summary = _summary(
        _source_item("https://example.test/aaa-1", body=b"other repeated"),
        _source_item("https://example.test/aaa-2", body=b"other repeated"),
        _source_item("https://example.test/aaa-3", body=b"other repeated"),
        *stable_items,
    )

    _api_values, first_inputs, first = _compose(first_summary)
    _api_values, second_inputs, second = _compose(second_summary)
    first_subject = _subject_for_endpoint(first, "https://example.test/stable-a")
    second_subject = _subject_for_endpoint(second, "https://example.test/stable-a")
    first_observations = tuple(
        item
        for item in first_inputs.observations
        if "/stable-" in item.endpoint
    )
    second_observations = tuple(
        item
        for item in second_inputs.observations
        if "/stable-" in item.endpoint
    )

    assert first_subject.subject_id == second_subject.subject_id
    assert tuple(item.observation_id for item in first_observations) == tuple(
        item.observation_id for item in second_observations
    )
    assert tuple(item.source_fingerprint_id for item in first_observations) != tuple(
        item.source_fingerprint_id for item in second_observations
    )
    assert first_inputs.exact_equivalences[0].source_repeated_body_group_id != (
        next(
            item.source_repeated_body_group_id
            for item in second_inputs.exact_equivalences
            if item.body_sha256 == sha256(stable_body).hexdigest()
        )
    )


def test_deep_input_adapter_requires_no_heuristic_similarity_review() -> None:
    api = _api()
    builder = api["build_operator_brief_http_inputs_from_deep"]

    assert tuple(signature(builder).parameters) == ("summary",)
    inputs = builder(_summary(_source_item("https://example.test/")))
    assert len(inputs.observations) == 1


def _metadata_item(
    url: str,
    *,
    method: str = "GET",
    status_code: int = 200,
    body: bytes = b"retained application response",
    final_url: str | None = None,
    evidence_id: str = "EVID-METADATA",
) -> DeepMetadataCollectedItem:
    return DeepMetadataCollectedItem(
        url=url,
        method=method,
        status_code=status_code,
        final_url=final_url or url,
        headers=(("Content-Type", "text/html; charset=utf-8"),),
        body_preview=body.decode("utf-8", errors="replace"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="metadata_collection",
        reason="exact retained metadata observation",
        evidence_ids=(evidence_id,),
    )


def _mixed_summary(
    metadata_items: tuple[DeepMetadataCollectedItem, ...],
    source_items: tuple[DeepSourceRouteCollectedItem, ...],
) -> DeepHttpFingerprintSummary:
    return build_deep_http_fingerprint_summary(
        DeepMetadataCollectionResult(
            collected=metadata_items,
            skipped=(),
            total_considered=len(metadata_items),
            total_collected=len(metadata_items),
            total_skipped=0,
        ),
        DeepSourceRouteCollectionResult(
            collected=source_items,
            skipped=(),
            total_considered=len(source_items),
            total_collected=len(source_items),
            total_skipped=0,
        ),
    )


def test_exact_equivalence_rejects_digest_mismatch() -> None:
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/a", body=b"same body"),
            _source_item("https://example.test/b", body=b"same body"),
        )
    )
    malformed = replace(
        inputs,
        exact_equivalences=(
            replace(inputs.exact_equivalences[0], body_sha256="f" * 64),
        ),
    )

    with pytest.raises(ValueError):
        api["compose_operator_brief_http"](malformed)


def test_exact_equivalence_rejects_one_member() -> None:
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/a", body=b"same body"),
            _source_item("https://example.test/b", body=b"same body"),
        )
    )
    malformed = replace(
        inputs,
        exact_equivalences=(
            replace(
                inputs.exact_equivalences[0],
                observation_ids=(inputs.observations[0].observation_id,),
            ),
        ),
    )

    with pytest.raises(ValueError):
        api["compose_operator_brief_http"](malformed)


def test_exact_equivalence_rejects_duplicate_member_identity() -> None:
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/a", body=b"same body"),
            _source_item("https://example.test/b", body=b"same body"),
        )
    )
    observation_id = inputs.observations[0].observation_id
    malformed = replace(
        inputs,
        exact_equivalences=(
            replace(
                inputs.exact_equivalences[0],
                observation_ids=(observation_id, observation_id),
            ),
        ),
    )

    with pytest.raises(ValueError):
        api["compose_operator_brief_http"](malformed)


def test_typed_404_cannot_merge_when_bucket_says_success() -> None:
    body = b"same retained error"
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/a", status_code=404, body=body),
            _source_item("https://example.test/b", status_code=404, body=body),
        )
    )
    inconsistent = replace(
        inputs,
        observations=tuple(
            replace(item, status_bucket="2xx_success")
            for item in inputs.observations
        ),
    )

    composition = api["compose_operator_brief_http"](inconsistent)

    assert len(composition.subjects) == 2


def test_typed_200_with_non_success_bucket_remains_non_merge() -> None:
    body = b"same retained success"
    api, inputs, _composition = _compose(
        _summary(
            _source_item("https://example.test/a", body=body),
            _source_item("https://example.test/b", body=body),
        )
    )
    inconsistent = replace(
        inputs,
        observations=tuple(
            replace(item, status_bucket="4xx_client_error")
            for item in inputs.observations
        ),
    )

    composition = api["compose_operator_brief_http"](inconsistent)

    assert len(composition.subjects) == 2


def test_cross_origin_subject_provenance_closes_over_referenced_facts() -> None:
    body = b"same body across origins"
    _api_values, _inputs, composition = _compose(
        _mixed_summary(
            (
                _metadata_item(
                    "https://one.test/", body=body, evidence_id="EVID-ONE"
                ),
            ),
            (
                _source_item(
                    "https://two.test/", body=body, evidence_id="EVID-TWO"
                ),
            ),
        )
    )
    facts = {item.fact_id: item for item in composition.facts}

    assert len(composition.subjects) == 2
    for subject in composition.subjects:
        referenced = tuple(facts[fact_id] for fact_id in subject.fact_ids)
        referenced_evidence = {
            value for fact in referenced for value in fact.evidence_ids
        }
        referenced_artefacts = {
            value for fact in referenced for value in fact.artefact_references
        }
        assert (
            referenced_evidence.difference(subject.evidence_ids),
            referenced_artefacts.difference(subject.artefact_references),
        ) == (set(), set())


def test_cross_subject_conflict_provenance_closes_over_referenced_conflict() -> None:
    _api_values, _inputs, composition = _compose(
        _mixed_summary(
            (
                _metadata_item(
                    "https://example.test/admin/",
                    method="GET",
                    status_code=200,
                    body=b"admin page",
                    evidence_id="EVID-GET-200",
                ),
            ),
            (
                _source_item(
                    "https://example.test/admin/",
                    method="HEAD",
                    status_code=404,
                    body=b"not found",
                    evidence_id="EVID-HEAD-404",
                ),
            ),
        )
    )
    conflicts = {item.conflict_id: item for item in composition.conflicts}

    assert len(composition.subjects) == 2
    for subject in composition.subjects:
        assert len(subject.conflict_ids) == 1
        referenced = conflicts[subject.conflict_ids[0]]
        referenced_evidence = {
            value
            for observation in referenced.observations
            for value in observation.evidence_ids
        }
        referenced_artefacts = {
            value
            for observation in referenced.observations
            for value in observation.artefact_references
        }
        assert (
            referenced_evidence.difference(subject.evidence_ids),
            referenced_artefacts.difference(subject.artefact_references),
        ) == (set(), set())


def test_cross_stage_equivalent_observations_keep_distinct_observation_ids() -> None:
    body = b"same response retained by two stages"
    summary = _mixed_summary(
        (_metadata_item("https://example.test/", body=body),),
        (_source_item("https://example.test/", body=body),),
    )
    api = _api()

    inputs = api["build_operator_brief_http_inputs_from_deep"](summary)

    assert len(inputs.observations) == 2
    assert len({item.observation_id for item in inputs.observations}) == 2
    assert {item.collection_stage for item in inputs.observations} == {
        "metadata_collection",
        "source_route_collection",
    }


def test_cross_stage_corroboration_preserves_subject_identity() -> None:
    body = b"same response retained by two stages"
    metadata = _metadata_item("https://example.test/", body=body)
    source = _source_item("https://example.test/", body=body)

    _api_values, _inputs, one_stage = _compose(_mixed_summary((metadata,), ()))
    _api_values, _inputs, two_stages = _compose(
        _mixed_summary((metadata,), (source,))
    )

    assert len(one_stage.subjects) == 1
    assert len(two_stages.subjects) == 1
    assert one_stage.subjects[0].subject_id == two_stages.subjects[0].subject_id


def test_non_merged_cross_stage_404_subject_ids_remain_unique() -> None:
    body = b"same retained missing response"
    _api_values, inputs, composition = _compose(
        _mixed_summary(
            (
                _metadata_item(
                    "https://example.test/missing",
                    status_code=404,
                    body=body,
                    evidence_id="EVID-METADATA-404",
                ),
            ),
            (
                _source_item(
                    "https://example.test/missing",
                    status_code=404,
                    body=body,
                    evidence_id="EVID-SOURCE-404",
                ),
            ),
        )
    )
    subject_ids = tuple(subject.subject_id for subject in composition.subjects)

    assert len(inputs.observations) == 2
    assert len({item.observation_id for item in inputs.observations}) == 2
    assert len(inputs.exact_equivalences) == 1
    assert len(composition.subjects) == 2
    assert len(set(subject_ids)) == len(composition.subjects), (
        subject_ids,
        tuple(item.observation_id for item in inputs.observations),
        tuple(item.collection_stage for item in inputs.observations),
        _subject_anchors(inputs),
        tuple(subject.endpoints for subject in composition.subjects),
    )


def test_non_merged_cross_stage_empty_subject_ids_remain_unique() -> None:
    _api_values, inputs, composition = _compose(
        _mixed_summary(
            (
                _metadata_item(
                    "https://example.test/empty",
                    body=b"",
                    evidence_id="EVID-METADATA-EMPTY",
                ),
            ),
            (
                _source_item(
                    "https://example.test/empty",
                    body=b"",
                    evidence_id="EVID-SOURCE-EMPTY",
                ),
            ),
        )
    )
    subject_ids = tuple(subject.subject_id for subject in composition.subjects)

    assert len(inputs.observations) == 2
    assert len({item.observation_id for item in inputs.observations}) == 2
    assert inputs.exact_equivalences == ()
    assert len(composition.subjects) == 2
    assert len(set(subject_ids)) == len(composition.subjects), (
        subject_ids,
        tuple(item.observation_id for item in inputs.observations),
        tuple(item.collection_stage for item in inputs.observations),
        _subject_anchors(inputs),
        tuple(subject.endpoints for subject in composition.subjects),
    )


def test_non_merged_collision_disambiguation_is_input_order_deterministic() -> None:
    body = b"same retained missing response"
    api = _api()
    inputs = api["build_operator_brief_http_inputs_from_deep"](
        _mixed_summary(
            (
                _metadata_item(
                    "https://example.test/missing",
                    status_code=404,
                    body=body,
                    evidence_id="EVID-METADATA-404",
                ),
            ),
            (
                _source_item(
                    "https://example.test/missing",
                    status_code=404,
                    body=body,
                    evidence_id="EVID-SOURCE-404",
                ),
            ),
        )
    )
    permuted = replace(
        inputs,
        observations=tuple(reversed(inputs.observations)),
        exact_equivalences=tuple(reversed(inputs.exact_equivalences)),
    )

    first = api["compose_operator_brief_http"](inputs)
    second = api["compose_operator_brief_http"](permuted)

    assert tuple(subject.subject_id for subject in first.subjects) == tuple(
        subject.subject_id for subject in second.subjects
    )


def _subject_anchors(inputs) -> tuple[str, ...]:
    from bugslyce.reports.operator_brief_http import _subject_anchor

    return tuple(_subject_anchor(item) for item in inputs.observations)
