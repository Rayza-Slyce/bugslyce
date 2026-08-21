from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha256
from inspect import Parameter, signature

import pytest

from bugslyce.recon.deep_http_fingerprint_summary import (
    EMPTY_BODY_SHA256,
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.reports.operator_brief import (
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
)


def _api():
    from bugslyce.reports.operator_brief_http import (
        OperatorBriefHttpCompositionInput,
        OperatorBriefHttpExactEquivalence,
        OperatorBriefHttpObservation,
        OperatorBriefHttpRetainedBodyObservation,
        build_operator_brief_http_exact_equivalence,
        build_operator_brief_http_inputs_from_deep,
        build_operator_brief_http_retained_body_observation,
        combine_operator_brief_http_inputs,
        compose_operator_brief_http,
    )

    return locals()


def _retained(
    api,
    endpoint: str = "https://example.test/app",
    *,
    body: bytes = b"retained initial content",
    body_sha256: str | None = None,
    body_bytes: int | None = None,
    source_kind: str = "manifest_retained_html",
    source_id: str = "INITIAL-HTML-SOURCE",
    evidence_id: str = "EVID-INITIAL",
    artefact_reference: str = "homepage-example.html",
):
    digest = body_sha256 or sha256(body).hexdigest()
    byte_count = len(body) if body_bytes is None else body_bytes
    return api["build_operator_brief_http_retained_body_observation"](
        source_kind=source_kind,
        source_id=source_id,
        endpoint=endpoint,
        body_sha256=digest,
        body_bytes=byte_count,
        evidence_ids=(evidence_id,),
        artefact_references=(artefact_reference,),
    )


def _complete(
    api,
    endpoint: str = "https://example.test/deep",
    *,
    body: bytes = b"retained initial content",
    evidence_id: str = "EVID-DEEP",
):
    return api["OperatorBriefHttpObservation"](
        observation_id="HTTP-OBS-DEEP",
        source_fingerprint_id="DEEP-HTTP-FP-0001",
        endpoint=endpoint,
        final_url=endpoint,
        origin=HttpOrigin("https", "example.test", 443),
        method="GET",
        status_code=200,
        status_bucket="2xx_success",
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        body_empty=not body,
        collection_stage="source_route_collection",
        evidence_ids=(evidence_id,),
        artefact_references=("deep_source_route_collection.json",),
    )


def _equivalence(api, members, *, source_kind="retained_body_sha256_group"):
    digest = members[0].body_sha256
    return api["build_operator_brief_http_exact_equivalence"](
        body_sha256=digest,
        observation_ids=tuple(item.observation_id for item in members),
        authority_references=(
            OperatorBriefSourceReference(source_kind, "EXACT-BYTES-001"),
        ),
    )


def _inputs(api, *, complete=(), retained=(), equivalences=()):
    return api["OperatorBriefHttpCompositionInput"](
        observations=tuple(complete),
        retained_content=tuple(retained),
        exact_equivalences=tuple(equivalences),
    )


def _facts(composition, kind: OperatorBriefFactKind):
    return tuple(item for item in composition.facts if item.kind is kind)


def _deep_summary(body: bytes = b"same deep bytes"):
    item = DeepSourceRouteCollectedItem(
        url="https://example.test/deep",
        method="GET",
        status_code=200,
        final_url="https://example.test/deep",
        headers=(("Content-Type", "text/html"),),
        body_preview=body.decode("ascii"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="retained source response",
        evidence_ids=("EVID-DEEP",),
        body=body,
    )
    return build_deep_http_fingerprint_summary(
        DeepMetadataCollectionResult((), (), 0, 0, 0),
        DeepSourceRouteCollectionResult((item,), (), 1, 1, 0),
    )


def test_partial_retained_body_model_is_distinct_from_complete_response_model() -> None:
    api = _api()

    assert api["OperatorBriefHttpRetainedBodyObservation"] is not api[
        "OperatorBriefHttpObservation"
    ]


def test_partial_retained_body_requires_no_complete_response_fields() -> None:
    api = _api()
    item = _retained(api)
    field_names = {field.name for field in fields(item)}

    assert {"method", "status_code", "status_bucket", "final_url"}.isdisjoint(
        field_names
    )


def test_partial_retained_body_projects_to_observed_direct_retained_content() -> None:
    api = _api()
    item = _retained(api)

    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=(item,))
    )

    fact = _facts(composition, OperatorBriefFactKind.RETAINED_CONTENT)[0]
    assert fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE


def test_partial_retained_body_does_not_emit_http_response() -> None:
    api = _api()
    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=(_retained(api),))
    )

    assert _facts(composition, OperatorBriefFactKind.HTTP_RESPONSE) == ()


def test_complete_response_model_keeps_required_complete_fields() -> None:
    from bugslyce.reports.operator_brief_http import OperatorBriefHttpObservation

    parameters = signature(OperatorBriefHttpObservation).parameters

    for name in ("final_url", "method", "status_code", "status_bucket"):
        assert parameters[name].default is Parameter.empty


def test_retained_content_fact_preserves_typed_semantics_and_provenance() -> None:
    api = _api()
    item = _retained(api)
    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=(item,))
    )

    fact = _facts(composition, OperatorBriefFactKind.RETAINED_CONTENT)[0]
    assert fact.endpoints == ("https://example.test/app",)
    assert fact.origins == ("https://example.test",)
    assert fact.body_sha256 == item.body_sha256
    assert fact.evidence_ids == ("EVID-INITIAL",)
    assert fact.artefact_references == ("homepage-example.html",)
    assert fact.source_references == (
        OperatorBriefSourceReference(
            "manifest_retained_html", "INITIAL-HTML-SOURCE"
        ),
    )


def test_retained_content_models_have_no_arbitrary_raw_body_fields() -> None:
    api = _api()

    for type_name in (
        "OperatorBriefHttpRetainedBodyObservation",
        "OperatorBriefHttpCompositionInput",
    ):
        field_names = {field.name for field in fields(api[type_name])}
        assert {
            "body",
            "response_body",
            "body_text",
            "body_preview",
            "content",
        }.isdisjoint(field_names)


def test_retained_content_identity_ignores_incidental_source_filename() -> None:
    api = _api()
    first = _retained(
        api,
        source_id="MANIFEST-FILE-001",
        artefact_reference="homepage-example-001.html",
    )
    second = _retained(
        api,
        source_id="MANIFEST-FILE-999",
        artefact_reference="homepage-example-999.html",
    )

    assert first.observation_id == second.observation_id


def test_retained_content_identity_changes_with_endpoint() -> None:
    api = _api()

    assert _retained(api).observation_id != _retained(
        api, endpoint="https://example.test/other"
    ).observation_id


def test_retained_content_identity_changes_with_digest() -> None:
    api = _api()

    assert _retained(api).observation_id != _retained(
        api, body=b"different retained content"
    ).observation_id


def test_retained_content_identity_changes_with_byte_count() -> None:
    api = _api()
    digest = sha256(b"same digest input").hexdigest()

    assert _retained(
        api, body_sha256=digest, body_bytes=16
    ).observation_id != _retained(
        api, body_sha256=digest, body_bytes=17
    ).observation_id


def test_retained_content_identity_changes_with_source_owner_category() -> None:
    api = _api()

    assert _retained(api).observation_id != _retained(
        api,
        source_kind="selective_body_fetch",
    ).observation_id


def test_generic_equality_supports_retained_members_without_deep_authority() -> None:
    api = _api()
    body = b"same retained bytes"
    members = (
        _retained(api, "https://example.test/a", body=body),
        _retained(api, "https://example.test/b", body=body),
    )
    equality = _equivalence(api, members)
    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=members, equivalences=(equality,))
    )

    fact = _facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)[0]
    assert equality.source_repeated_body_group_id is None
    assert all(
        item.source_kind != "deep_http_repeated_body_group"
        for item in fact.source_references
    )


def test_generic_equality_supports_retained_and_complete_members() -> None:
    api = _api()
    body = b"same mixed retained bytes"
    retained = _retained(api, body=body)
    complete = _complete(api, body=body)
    equality = _equivalence(api, (retained, complete))

    composition = api["compose_operator_brief_http"](
        _inputs(
            api,
            complete=(complete,),
            retained=(retained,),
            equivalences=(equality,),
        )
    )

    assert len(_facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)) == 1


def test_deep_equality_preserves_actual_repeated_body_authority() -> None:
    api = _api()
    body = b"same deep bytes"
    first = _deep_summary(body)
    second_item = replace(
        first.fingerprints[0],
        fingerprint_id="DEEP-HTTP-FP-0002",
        requested_url="https://example.test/deep-alias",
        final_url="https://example.test/deep-alias",
    )
    from bugslyce.recon.deep_http_fingerprint_summary import (
        DeepHttpFingerprintSummary,
        DeepHttpRepeatedBodyGroup,
    )

    summary = DeepHttpFingerprintSummary(
        fingerprints=(first.fingerprints[0], second_item),
        repeated_body_groups=(
            DeepHttpRepeatedBodyGroup(
                repeated_body_id="DEEP-HTTP-BODY-0001",
                body_sha256=sha256(body).hexdigest(),
                count=2,
                fingerprint_ids=("DEEP-HTTP-FP-0001", "DEEP-HTTP-FP-0002"),
                urls=(
                    "https://example.test/deep",
                    "https://example.test/deep-alias",
                ),
                collection_sections=("source_route_collection",),
                body_bytes=(len(body),),
                status_codes=(200,),
            ),
        ),
        summary_counts=first.summary_counts,
        safety_notes=first.safety_notes,
    )

    inputs = api["build_operator_brief_http_inputs_from_deep"](summary)
    equality = inputs.exact_equivalences[0]

    assert equality.source_repeated_body_group_id == "DEEP-HTTP-BODY-0001"
    assert OperatorBriefSourceReference(
        "deep_http_repeated_body_group", "DEEP-HTTP-BODY-0001"
    ) in equality.authority_references


def test_generic_equality_requires_multiple_distinct_members() -> None:
    api = _api()
    member = _retained(api)

    with pytest.raises(ValueError):
        api["build_operator_brief_http_exact_equivalence"](
            body_sha256=member.body_sha256,
            observation_ids=(member.observation_id,),
            authority_references=(
                OperatorBriefSourceReference("retained_body_sha256_group", "ONE"),
            ),
        )
    with pytest.raises(ValueError):
        api["build_operator_brief_http_exact_equivalence"](
            body_sha256=member.body_sha256,
            observation_ids=(member.observation_id, member.observation_id),
            authority_references=(
                OperatorBriefSourceReference("retained_body_sha256_group", "DUP"),
            ),
        )


def test_generic_equality_rejects_unknown_member() -> None:
    api = _api()
    member = _retained(api)
    equality = api["build_operator_brief_http_exact_equivalence"](
        body_sha256=member.body_sha256,
        observation_ids=(member.observation_id, "HTTP-RETAINED-UNKNOWN"),
        authority_references=(
            OperatorBriefSourceReference("retained_body_sha256_group", "UNKNOWN"),
        ),
    )

    with pytest.raises(ValueError):
        api["compose_operator_brief_http"](
            _inputs(api, retained=(member,), equivalences=(equality,))
        )


def test_generic_equality_rejects_member_digest_mismatch() -> None:
    api = _api()
    first = _retained(api, "https://example.test/a", body=b"first")
    second = _retained(api, "https://example.test/b", body=b"second")
    equality = api["build_operator_brief_http_exact_equivalence"](
        body_sha256=first.body_sha256,
        observation_ids=(first.observation_id, second.observation_id),
        authority_references=(
            OperatorBriefSourceReference("retained_body_sha256_group", "MISMATCH"),
        ),
    )

    with pytest.raises(ValueError):
        api["compose_operator_brief_http"](
            _inputs(api, retained=(first, second), equivalences=(equality,))
        )


def test_empty_retained_equality_is_structural_but_non_merging() -> None:
    api = _api()
    members = (
        _retained(
            api,
            "https://example.test/a",
            body=b"",
            body_sha256=EMPTY_BODY_SHA256,
            body_bytes=0,
        ),
        _retained(
            api,
            "https://example.test/b",
            body=b"",
            body_sha256=EMPTY_BODY_SHA256,
            body_bytes=0,
        ),
    )
    equality = _equivalence(api, members)

    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=members, equivalences=(equality,))
    )

    assert len(composition.subjects) == 2
    assert len(_facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)) == 1


@pytest.mark.parametrize("mixed", [False, True])
def test_partial_exact_equality_is_derived_relationship_context(mixed: bool) -> None:
    api = _api()
    body = b"same relationship bytes"
    retained = _retained(api, body=body)
    other = _complete(api, body=body) if mixed else _retained(
        api, "https://example.test/other", body=body
    )
    equality = _equivalence(api, (retained, other))
    composition = api["compose_operator_brief_http"](
        _inputs(
            api,
            complete=(other,) if mixed else (),
            retained=(retained,) if mixed else (retained, other),
            equivalences=(equality,),
        )
    )

    fact = _facts(composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE)[0]
    assert fact.semantic_class is OperatorBriefSemanticClass.DERIVED
    assert fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT


def test_partial_member_prevents_complete_response_merge_eligibility() -> None:
    api = _api()
    body = b"same origin exact successful-looking bytes"
    retained = _retained(api, body=body)
    complete = _complete(api, endpoint=retained.endpoint, body=body)
    equality = _equivalence(api, (retained, complete))

    composition = api["compose_operator_brief_http"](
        _inputs(
            api,
            complete=(complete,),
            retained=(retained,),
            equivalences=(equality,),
        )
    )

    assert len(composition.subjects) == 2


def test_sparse_retained_content_produces_one_existing_subject_type() -> None:
    api = _api()
    item = _retained(api)

    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=(item,))
    )

    assert len(composition.subjects) == 1
    subject = composition.subjects[0]
    assert type(subject).__name__ == "OperatorBriefHttpSubject"
    assert subject.observation_ids == (item.observation_id,)
    assert subject.endpoints == (item.endpoint,)
    assert subject.origins == (item.origin.origin_url,)


def test_sparse_retained_subject_preserves_provenance() -> None:
    api = _api()
    item = _retained(api)
    composition = api["compose_operator_brief_http"](
        _inputs(api, retained=(item,))
    )

    subject = composition.subjects[0]
    assert subject.evidence_ids == item.evidence_ids
    assert subject.artefact_references == item.artefact_references


def test_mixed_relationship_provenance_closes_over_both_member_types() -> None:
    api = _api()
    body = b"same mixed provenance bytes"
    retained = _retained(api, body=body)
    complete = _complete(api, body=body)
    equality = _equivalence(api, (retained, complete))
    composition = api["compose_operator_brief_http"](
        _inputs(
            api,
            complete=(complete,),
            retained=(retained,),
            equivalences=(equality,),
        )
    )
    equality_fact = _facts(
        composition, OperatorBriefFactKind.RESPONSE_EQUIVALENCE
    )[0]

    assert equality_fact.evidence_ids == ("EVID-DEEP", "EVID-INITIAL")
    assert equality_fact.artefact_references == (
        "deep_source_route_collection.json",
        "homepage-example.html",
    )
    assert equality.authority_references[0] in equality_fact.source_references
    for subject in composition.subjects:
        assert set(equality_fact.evidence_ids) <= set(subject.evidence_ids)
        assert set(equality_fact.artefact_references) <= set(
            subject.artefact_references
        )


def test_retained_composition_is_input_order_deterministic() -> None:
    api = _api()
    body = b"same deterministic retained bytes"
    members = (
        _retained(api, "https://example.test/a", body=body),
        _retained(api, "https://example.test/b", body=body),
    )
    equality = _equivalence(api, members)
    first = _inputs(api, retained=members, equivalences=(equality,))
    second = replace(
        first,
        retained_content=tuple(reversed(first.retained_content)),
        exact_equivalences=tuple(reversed(first.exact_equivalences)),
    )

    assert api["compose_operator_brief_http"](first) == api[
        "compose_operator_brief_http"
    ](second)


def test_deep_only_input_remains_supported_by_extended_composition_input() -> None:
    api = _api()
    inputs = api["build_operator_brief_http_inputs_from_deep"](_deep_summary())

    assert inputs.retained_content == ()
    composition = api["compose_operator_brief_http"](inputs)
    assert len(_facts(composition, OperatorBriefFactKind.HTTP_RESPONSE)) == 1


def test_pure_input_combiner_preserves_members_and_relationships_deterministically() -> None:
    api = _api()
    body = b"same combined retained bytes"
    deep_inputs = api["build_operator_brief_http_inputs_from_deep"](
        _deep_summary(body)
    )
    retained = _retained(api, body=body)
    retained_inputs = _inputs(api, retained=(retained,))
    equality = _equivalence(
        api, (retained, deep_inputs.observations[0]), source_kind="mixed_exact_bytes"
    )
    relationship_inputs = _inputs(api, equivalences=(equality,))

    first = api["combine_operator_brief_http_inputs"](
        deep_inputs, retained_inputs, relationship_inputs
    )
    second = api["combine_operator_brief_http_inputs"](
        relationship_inputs, retained_inputs, deep_inputs
    )

    assert first == second
    assert first.observations == deep_inputs.observations
    assert first.retained_content == (retained,)
    assert first.exact_equivalences == (equality,)


def test_combiner_rejects_conflicting_duplicate_semantic_ids() -> None:
    api = _api()
    first = _retained(api)
    conflicting = replace(
        first,
        observation_id=first.observation_id,
        endpoint="https://example.test/semantic-conflict",
    )

    with pytest.raises(ValueError):
        api["combine_operator_brief_http_inputs"](
            _inputs(api, retained=(first,)),
            _inputs(api, retained=(conflicting,)),
        )


def test_combiner_deduplicates_identical_normalized_members() -> None:
    api = _api()
    retained = _retained(api)
    inputs = _inputs(api, retained=(retained,))

    combined = api["combine_operator_brief_http_inputs"](inputs, inputs)

    assert combined.retained_content == (retained,)


def test_combiner_unions_provenance_only_retained_duplicates() -> None:
    api = _api()
    first = _retained(
        api,
        source_id="MANIFEST-FILE-001",
        evidence_id="EVID-INITIAL-A",
        artefact_reference="homepage-example-001.html",
    )
    second = _retained(
        api,
        source_id="MANIFEST-FILE-999",
        evidence_id="EVID-INITIAL-B",
        artefact_reference="homepage-example-999.html",
    )

    assert first.observation_id == second.observation_id
    combined = api["combine_operator_brief_http_inputs"](
        _inputs(api, retained=(first,)),
        _inputs(api, retained=(second,)),
    )

    assert len(combined.retained_content) == 1
    retained = combined.retained_content[0]
    assert retained.observation_id == first.observation_id
    assert retained.evidence_ids == ("EVID-INITIAL-A", "EVID-INITIAL-B")
    assert retained.artefact_references == (
        "homepage-example-001.html",
        "homepage-example-999.html",
    )
    assert retained.source_references == (
        OperatorBriefSourceReference("manifest_retained_html", "MANIFEST-FILE-001"),
        OperatorBriefSourceReference("manifest_retained_html", "MANIFEST-FILE-999"),
    )


def test_combiner_provenance_union_is_input_order_deterministic() -> None:
    api = _api()
    first = _retained(
        api,
        source_id="MANIFEST-FILE-001",
        evidence_id="EVID-INITIAL-A",
        artefact_reference="homepage-example-001.html",
    )
    second = _retained(
        api,
        source_id="MANIFEST-FILE-999",
        evidence_id="EVID-INITIAL-B",
        artefact_reference="homepage-example-999.html",
    )

    forward = api["combine_operator_brief_http_inputs"](
        _inputs(api, retained=(first,)),
        _inputs(api, retained=(second,)),
    )
    reverse = api["combine_operator_brief_http_inputs"](
        _inputs(api, retained=(second,)),
        _inputs(api, retained=(first,)),
    )

    assert forward == reverse


def test_combiner_unions_compatible_exact_equality_authorities() -> None:
    api = _api()
    body = b"same independently proven bytes"
    first = _deep_summary(body)
    second_fingerprint = replace(
        first.fingerprints[0],
        fingerprint_id="DEEP-HTTP-FP-0002",
        requested_url="https://example.test/deep-alias",
        final_url="https://example.test/deep-alias",
    )
    from bugslyce.recon.deep_http_fingerprint_summary import (
        DeepHttpFingerprintSummary,
        DeepHttpRepeatedBodyGroup,
    )

    summary = DeepHttpFingerprintSummary(
        fingerprints=(first.fingerprints[0], second_fingerprint),
        repeated_body_groups=(
            DeepHttpRepeatedBodyGroup(
                repeated_body_id="DEEP-HTTP-BODY-0001",
                body_sha256=sha256(body).hexdigest(),
                count=2,
                fingerprint_ids=("DEEP-HTTP-FP-0001", "DEEP-HTTP-FP-0002"),
                urls=(
                    "https://example.test/deep",
                    "https://example.test/deep-alias",
                ),
                collection_sections=("source_route_collection",),
                body_bytes=(len(body),),
                status_codes=(200,),
            ),
        ),
        summary_counts=first.summary_counts,
        safety_notes=first.safety_notes,
    )
    deep_inputs = api["build_operator_brief_http_inputs_from_deep"](summary)
    deep_equality = deep_inputs.exact_equivalences[0]
    generic_equality = api["build_operator_brief_http_exact_equivalence"](
        body_sha256=deep_equality.body_sha256,
        observation_ids=deep_equality.observation_ids,
        authority_references=(
            OperatorBriefSourceReference(
                "retained_body_exact_hash", "RETAINED-EXACT-001"
            ),
        ),
    )

    assert generic_equality.equivalence_id == deep_equality.equivalence_id
    combined = api["combine_operator_brief_http_inputs"](
        deep_inputs,
        _inputs(api, equivalences=(generic_equality,)),
    )

    assert len(combined.exact_equivalences) == 1
    equality = combined.exact_equivalences[0]
    assert equality.authority_references == (
        OperatorBriefSourceReference(
            "deep_http_repeated_body_group", "DEEP-HTTP-BODY-0001"
        ),
        OperatorBriefSourceReference(
            "retained_body_exact_hash", "RETAINED-EXACT-001"
        ),
    )
    assert equality.source_repeated_body_group_id == "DEEP-HTTP-BODY-0001"


def test_normalized_retained_content_requires_no_absolute_filesystem_path() -> None:
    api = _api()
    model_fields = {field.name for field in fields(api["OperatorBriefHttpRetainedBodyObservation"])}
    builder_parameters = set(
        signature(api["build_operator_brief_http_retained_body_observation"]).parameters
    )

    assert {
        "path",
        "absolute_path",
        "filesystem_path",
        "input_dir",
        "project_root",
    }.isdisjoint(model_fields | builder_parameters)
