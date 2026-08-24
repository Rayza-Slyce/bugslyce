"""RED contract for pure source-native Operator Brief composition."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from hashlib import sha256
import importlib
import json
from types import SimpleNamespace

import pytest

from bugslyce.core.models import HTTPArtifact
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpFingerprintSummaryCounts,
    DeepHttpHeaderObservation,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityGroup,
    DeepResponseSimilarityReview,
    DeepResponseSimilaritySummaryCounts,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
    DeepSourceRouteReviewLead,
)
from bugslyce.recon.deep_structured_body_review import analyse_deep_structured_body
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    directory_listing_title,
)
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    LIKELY_SIGNAL,
    POSSIBLE_SIGNAL,
    classify_encoded_artifact,
)
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadSpecificity,
    apply_operator_brief_thread_policy,
)
from bugslyce.triage.workflow_leads import (
    WorkflowAccountObservation,
    WorkflowAccountObservationKind,
    WorkflowAccountRetention,
    WorkflowLead,
    WorkflowObjectReferenceRetention,
)


_FUTURE_MODULE = "bugslyce.reports.operator_brief_source_native"
_ORIGIN = "https://app.example.test"
_CONFIG_URL = f"{_ORIGIN}/runtime.conf"
_JSON_URL = f"{_ORIGIN}/routes.json"
_LISTING_URL = f"{_ORIGIN}/public/"
_BOUNDARY_URL = f"{_ORIGIN}/admin"
_CREDENTIAL_URL = f"{_ORIGIN}/assets/config.js"
_ENCODED_URL = f"{_ORIGIN}/assets/data.js"
_SECRET = "R3B3L-CREDENTIAL-VALUE-DO-NOT-RETAIN"
_ENCODED_VALUE = "9fdafbd64c47471a8f54cd3fc64cd312"
_POSSIBLE_ENCODED_VALUE = "ObsJmP173N2X6dOrAgEAL0Vu"
_NOISE_ENCODED_VALUE = "ordinary"
_ENCODED_UNSAFE_URL = (
    "https://source-user:source-password@app.example.test/"
    "assets/data.js?token=QUERY-VALUE-DO-NOT-RETAIN#fragment"
)


def _future_api() -> SimpleNamespace:
    module = importlib.import_module(_FUTURE_MODULE)
    names = (
        "OperatorBriefSourceNativeFamily",
        "OperatorBriefSourceNativeSubject",
        "OperatorBriefSourceNativeComposition",
        "OperatorBriefStructuredDisclosureInterpretation",
        "OperatorBriefDirectoryListingInterpretation",
        "OperatorBriefAccessBoundaryInterpretation",
        "OperatorBriefCredentialInterpretation",
        "OperatorBriefAccountWorkflowInterpretation",
        "OperatorBriefObjectReferenceInterpretation",
        "OperatorBriefEncodedArtifactInterpretation",
        "compose_operator_brief_source_native",
    )
    return SimpleNamespace(**{name: getattr(module, name) for name in names})


def _empty_fingerprint_counts() -> DeepHttpFingerprintSummaryCounts:
    return DeepHttpFingerprintSummaryCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def _empty_similarity_counts() -> DeepResponseSimilaritySummaryCounts:
    return DeepResponseSimilaritySummaryCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def _source_review(*leads: DeepSourceRouteReviewLead) -> DeepSourceRouteCollectionReviewSummary:
    return DeepSourceRouteCollectionReviewSummary(
        total_collected=len(leads),
        total_skipped=0,
        status_buckets=(),
        body_signatures=(),
        skip_reasons=(),
        review_leads=tuple(leads),
        safety_notes=(),
    )


def _disclosure_lead(
    category: str,
    *,
    url: str,
    final_url: str | None = None,
    body_sha256: str,
    observed_values: tuple[str, ...] = (),
    excerpt: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = ("EVID-DISCLOSURE",),
) -> DeepSourceRouteReviewLead:
    return DeepSourceRouteReviewLead(
        lead_id=f"DEEP-SOURCE-{category}",
        category=category,
        title="presentation is not authority",
        urls=(url,),
        evidence_ids=evidence_ids,
        reason="presentation is not authority",
        observed_values=observed_values,
        evidence_excerpt=excerpt,
        source_body_sha256=body_sha256,
        final_urls=(final_url or url,),
    )


def _listing_review(
    *,
    url: str = _LISTING_URL,
    requested_urls: tuple[str, ...] | None = None,
    evidence_ids: tuple[str, ...] = ("EVID-LISTING",),
) -> SuccessfulDeepContentReview:
    body = b"<html><title>Index of /public/</title></html>"
    return SuccessfulDeepContentReview(
        review_id="DEEP-CONTENT-LISTING",
        canonical_url=url,
        requested_urls=requested_urls or (url,),
        status_code=200,
        content_type="text/html",
        body_bytes=len(body),
        body_sha256=sha256(body).hexdigest(),
        body_preview=body.decode(),
        evidence_ids=evidence_ids,
        artefact_references=("deep_source_route_collection.json",),
    )


def _fingerprint(
    *,
    fingerprint_id: str = "DEEP-HTTP-FP-BOUNDARY",
    url: str = _BOUNDARY_URL,
    status: int = 401,
    body_sha256: str = "boundary-body-sha",
) -> DeepHttpResponseFingerprint:
    return DeepHttpResponseFingerprint(
        fingerprint_id=fingerprint_id,
        collection_section="source_route_collection",
        requested_url=url,
        final_url=url,
        method="GET",
        status_code=status,
        status_bucket="4xx_client_error",
        title_observed_in_bounded_preview="Restricted",
        content_type="text/html",
        server="example",
        redirect_location=None,
        set_cookie_present=False,
        set_cookie_count=0,
        cookie_names=(),
        body_sha256=body_sha256,
        body_bytes=128,
        body_empty=False,
        interesting_headers=(
            DeepHttpHeaderObservation("WWW-Authenticate", 'Basic realm="admin"'),
        ),
        headers_not_observed=(),
        evidence_ids=("EVID-BOUNDARY",),
    )


def _fingerprint_summary(*items: DeepHttpResponseFingerprint) -> DeepHttpFingerprintSummary:
    return DeepHttpFingerprintSummary(tuple(items), (), _empty_fingerprint_counts(), ())


def _similarity_review(fingerprint: DeepHttpResponseFingerprint | None = None) -> DeepResponseSimilarityReview:
    groups = ()
    if fingerprint is not None:
        groups = (
            DeepResponseSimilarityGroup(
                group_id="DEEP-SIM-BOUNDARY",
                category="client_error_signature_group",
                title="presentation is not authority",
                reason="presentation is not authority",
                grouping_signature=("401", "www-authenticate"),
                fingerprint_ids=(fingerprint.fingerprint_id,),
                redirect_observation_ids=(),
                source_repeated_body_group_ids=(),
                requested_urls=(fingerprint.requested_url,),
                status_codes=(fingerprint.status_code,),
                collection_sections=(fingerprint.collection_section,),
                body_hashes=(fingerprint.body_sha256,),
                body_size_bands=("1-255",),
                titles_observed_in_bounded_previews=("Restricted",),
                content_types=("text/html",),
                server_families=("example",),
                redirect_origin_relationships=(),
                auth_path_transitions=(),
                evidence_ids=fingerprint.evidence_ids,
                interpretation="presentation is not authority",
                representative_fingerprint_id=fingerprint.fingerprint_id,
                representative_requested_url=fingerprint.requested_url,
                member_count=1,
                structural_signals=("www_authenticate",),
            ),
        )
    return DeepResponseSimilarityReview(groups, (), _empty_similarity_counts(), ())


def _credential_artifact(*, secret: str = _SECRET) -> HTTPArtifact:
    return HTTPArtifact(
        url=_CREDENTIAL_URL,
        artifact_type="html_comment",
        value=f"deployment note: api_key = {secret}",
        source_file="retained-config.js",
        evidence_ids=["EVID-CREDENTIAL"],
        tags=[],
    )


def _encoded_artifact(
    value: str = _ENCODED_VALUE,
    *,
    url: str = _ENCODED_URL,
    evidence_id: str = "EVID-ENCODED",
    source_file: str = "retained-data.js",
) -> HTTPArtifact:
    return HTTPArtifact(
        url=url,
        artifact_type="encoded_like_artifact",
        value=value,
        source_file=source_file,
        evidence_ids=[evidence_id],
        tags=["encoded_or_hidden_artifact"],
    )


def _account_workflow(
    *,
    observation: WorkflowAccountObservation | None = None,
    covered_urls: tuple[str, ...] = (f"{_ORIGIN}/login",),
    evidence_ids: tuple[str, ...] = ("EVID-ACCOUNT",),
) -> WorkflowLead:
    if observation is None:
        observation = WorkflowAccountObservation(
            kind=WorkflowAccountObservationKind.OBSERVED_FORM,
            url=f"{_ORIGIN}/login?next=private-value",
            evidence_ids=evidence_ids,
            methods=("post",),
            field_names=("password", "username"),
        )
    return WorkflowLead(
        title="presentation is not authority",
        priority="high",
        category="account_workflow",
        summary=f"must not be parsed: {_SECRET}",
        why_it_matters="presentation is not authority",
        suggested_manual_action="presentation is not authority",
        representative_urls=(f"{_ORIGIN}/login",),
        covered_urls=covered_urls,
        evidence_ids=evidence_ids,
        signal="presentation is not authority",
        retention=WorkflowAccountRetention(_ORIGIN, (observation,)),
    )


def _object_workflow(
    *,
    parameter_names: tuple[str, ...] = ("record", "user"),
    covered_urls: tuple[str, ...] = (
        f"{_ORIGIN}/records",
        f"{_ORIGIN}/users",
    ),
    evidence_ids: tuple[str, ...] = ("EVID-OBJECT",),
) -> WorkflowLead:
    return WorkflowLead(
        title="presentation is not authority",
        priority="medium",
        category="object_reference_surface",
        summary="must not be parsed: object=OBJECT-VALUE-DO-NOT-RETAIN",
        why_it_matters="presentation is not authority",
        suggested_manual_action="presentation is not authority",
        representative_urls=(f"{_ORIGIN}/records",),
        covered_urls=covered_urls,
        evidence_ids=evidence_ids,
        signal="presentation is not authority",
        retention=WorkflowObjectReferenceRetention(_ORIGIN, parameter_names),
    )


def _http_target(
    *,
    semantic_key: str = "http:application-one",
    route: str,
    body_sha256: str = "",
    status: int = 200,
    source_references: tuple[OperatorBriefSourceReference, ...] = (),
) -> OperatorBriefThreadPolicySubject:
    fact = OperatorBriefFact(
        fact_id=f"FACT-{semantic_key}",
        kind=OperatorBriefFactKind.HTTP_RESPONSE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="HTTP response",
        summary="direct retained response",
        endpoints=(route,),
        origins=(_ORIGIN,),
        source_references=source_references,
        route=route,
        body_sha256=body_sha256,
        http_method="GET",
        http_status_code=status,
    )
    return OperatorBriefThreadPolicySubject(
        policy_key=f"NORMALIZED-{semantic_key}",
        semantic_subject_key=semantic_key,
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
        materiality=OperatorBriefThreadMateriality.MATERIAL,
        specificity=OperatorBriefThreadSpecificity.SPECIFIC,
        evidence_basis=OperatorBriefThreadEvidenceBasis.DIRECT,
        independent=True,
        facts=(fact,),
    )


def _compose(api: SimpleNamespace, **overrides: object):
    fingerprint = overrides.pop("fingerprint", None)
    values = {
        "deep_source_route_review": _source_review(),
        "successful_content_reviews": (),
        "deep_http_fingerprints": _fingerprint_summary(
            *((fingerprint,) if fingerprint is not None else ())
        ),
        "deep_response_similarity": _similarity_review(fingerprint),
        "http_artifacts": (),
        "workflow_leads": (),
        "normalized_policy_subjects": (),
    }
    values.update(overrides)
    return api.compose_operator_brief_source_native(**values)


def _all_family_inputs() -> dict[str, object]:
    fingerprint = _fingerprint()
    return {
        "deep_source_route_review": _source_review(
            _disclosure_lead(
                "structured_configuration_body",
                url=_CONFIG_URL,
                body_sha256="config-body-sha",
                excerpt=("Listen 8443",),
            ),
            _disclosure_lead(
                "structured_json_routes",
                url=_JSON_URL,
                body_sha256="json-body-sha",
                observed_values=("/admin/reports",),
            ),
        ),
        "successful_content_reviews": (_listing_review(),),
        "fingerprint": fingerprint,
        "http_artifacts": (_credential_artifact(), _encoded_artifact()),
        "workflow_leads": (_account_workflow(), _object_workflow()),
    }


def _association_case(
    matcher: str,
) -> tuple[dict[str, object], OperatorBriefThreadPolicySubject, OperatorBriefThreadPolicySubject]:
    if matcher == "structured_disclosure":
        lead = _disclosure_lead(
            "structured_configuration_body",
            url=_CONFIG_URL,
            body_sha256="config-body-sha",
            excerpt=("Listen 8443",),
        )
        return (
            {"deep_source_route_review": _source_review(lead)},
            _http_target(route=_CONFIG_URL, body_sha256="config-body-sha"),
            _http_target(
                semantic_key="http:disclosure-nonmatch",
                route=_CONFIG_URL,
                body_sha256="wrong-body-sha",
            ),
        )
    if matcher == "directory_listing":
        review = _listing_review()
        return (
            {"successful_content_reviews": (review,)},
            _http_target(
                route=review.canonical_url,
                body_sha256=review.body_sha256,
                status=review.status_code,
            ),
            _http_target(
                semantic_key="http:listing-nonmatch",
                route=review.canonical_url,
                body_sha256=review.body_sha256,
                status=403,
            ),
        )
    if matcher == "access_boundary":
        fingerprint = _fingerprint()
        source_reference = OperatorBriefSourceReference(
            "deep_http_fingerprint",
            fingerprint.fingerprint_id,
        )
        return (
            {"fingerprint": fingerprint},
            _http_target(
                route="https://unrelated.example.test/other",
                source_references=(source_reference,),
            ),
            _http_target(
                semantic_key="http:access-nonmatch",
                route=fingerprint.requested_url,
            ),
        )
    if matcher == "credential":
        return (
            {"http_artifacts": (_credential_artifact(),)},
            _http_target(route=_CREDENTIAL_URL),
            _http_target(
                semantic_key="http:credential-nonmatch",
                route=f"{_ORIGIN}/other",
            ),
        )
    if matcher == "encoded":
        return (
            {"http_artifacts": (_encoded_artifact(),)},
            _http_target(route=_ENCODED_URL),
            _http_target(
                semantic_key="http:encoded-nonmatch",
                route=f"{_ORIGIN}/other",
            ),
        )
    raise AssertionError(f"Unknown association matcher: {matcher}")


# Existing-source controls: these do not import the absent future API.


def test_source_control_structured_configuration_disclosure() -> None:
    item = SimpleNamespace(
        final_url=_CONFIG_URL,
        headers=(("Content-Type", "text/plain"),),
        body_preview=(
            "Listen 8443\nDocumentRoot /srv/application\n"
            f"password = {_SECRET}\n"
        ),
        body_sha256="config-body-sha",
        evidence_ids=("EVID-CONFIG",),
    )
    disclosure = analyse_deep_structured_body(item, source_url=_CONFIG_URL)[0]

    assert disclosure.kind == "structured_configuration_body"
    assert disclosure.source_body_sha256 == "config-body-sha"
    assert _SECRET not in disclosure.excerpt_lines


def test_source_control_structured_json_route_disclosure() -> None:
    item = SimpleNamespace(
        final_url=_JSON_URL,
        headers=(("Content-Type", "application/json"),),
        body_preview='{"routes":["/admin/reports","/api/accounts"]}',
        body_sha256="json-body-sha",
        evidence_ids=("EVID-JSON",),
    )
    disclosure = analyse_deep_structured_body(item, source_url=_JSON_URL)[0]

    assert disclosure.kind == "structured_json_routes"
    assert disclosure.observed_values == ("/admin/reports", "/api/accounts")


def test_source_control_disclosure_retains_distinct_source_and_final_urls() -> None:
    final_url = f"{_ORIGIN}/canonical/runtime.conf"
    item = SimpleNamespace(
        final_url=final_url,
        headers=(("Content-Type", "text/plain"),),
        body_preview=(
            "Listen 8443\n"
            "ServerName app.example.test\n"
            "DocumentRoot /srv/application\n"
        ),
        body_sha256="redirected-config-body-sha",
        evidence_ids=("EVID-REDIRECTED-CONFIG",),
    )
    disclosure = analyse_deep_structured_body(item, source_url=_CONFIG_URL)[0]

    assert disclosure.source_url == _CONFIG_URL
    assert disclosure.source_final_url == final_url
    assert disclosure.source_body_sha256 == "redirected-config-body-sha"


def test_source_control_directory_listing_review() -> None:
    review = _listing_review()

    assert directory_listing_title(review) == "Index of /public/"
    assert review.artefact_references == ("deep_source_route_collection.json",)


def test_source_control_listing_retains_distinct_canonical_and_requested_urls() -> None:
    requested_url = f"{_ORIGIN}/public/index.html"
    review = _listing_review(requested_urls=(requested_url,))

    assert directory_listing_title(review) == "Index of /public/"
    assert review.canonical_url == _LISTING_URL
    assert review.requested_urls == (requested_url,)


def test_source_control_access_boundary_fingerprint_and_contrast() -> None:
    fingerprint = _fingerprint()
    review = _similarity_review(fingerprint)

    assert fingerprint.interesting_headers[0].name == "WWW-Authenticate"
    assert review.groups[0].fingerprint_ids == (fingerprint.fingerprint_id,)
    assert review.groups[0].structural_signals == ("www_authenticate",)


def test_source_control_credential_like_http_artefact() -> None:
    artifact = _credential_artifact()

    assert artifact.artifact_type == "html_comment"
    assert artifact.url == _CREDENTIAL_URL
    assert "api_key" in artifact.value


def test_source_control_account_workflow_typed_retention() -> None:
    lead = _account_workflow()

    assert isinstance(lead.retention, WorkflowAccountRetention)
    assert lead.retention.observations[0].field_names == ("password", "username")
    assert "private-value" not in lead.retention.observations[0].url


def test_source_control_object_reference_typed_retention() -> None:
    lead = _object_workflow()

    assert isinstance(lead.retention, WorkflowObjectReferenceRetention)
    assert lead.retention.parameter_names == ("record", "user")


def test_source_control_encoded_likely_signal_classifier() -> None:
    classification = classify_encoded_artifact(
        _encoded_artifact(url=_ENCODED_UNSAFE_URL)
    )

    assert classification.category == LIKELY_SIGNAL
    assert _ENCODED_VALUE not in classification.reason


def test_source_control_encoded_possible_signal_classifier() -> None:
    classification = classify_encoded_artifact(
        _encoded_artifact(_POSSIBLE_ENCODED_VALUE, url=f"{_ORIGIN}/possible")
    )

    assert classification.category == POSSIBLE_SIGNAL


def test_source_control_encoded_likely_noise_classifier() -> None:
    classification = classify_encoded_artifact(
        _encoded_artifact(_NOISE_ENCODED_VALUE, url=f"{_ORIGIN}/noise")
    )

    assert classification.category == LIKELY_NOISE


def test_source_control_all_no_hard_cap_values_are_likely_signal() -> None:
    classifications = tuple(
        classify_encoded_artifact(
            _encoded_artifact(
                f"{index:032x}",
                url=f"{_ORIGIN}/encoded/{index}",
                evidence_id=f"EVID-{index:02d}",
            )
        )
        for index in range(1, 11)
    )

    assert len(classifications) == 10
    assert all(item.category == LIKELY_SIGNAL for item in classifications)


def test_source_control_no_url_encoded_artefacts_remain_likely_signal() -> None:
    alpha = _encoded_artifact(url="", source_file="alpha.js")
    beta = _encoded_artifact(url="", source_file="beta.js")

    assert alpha.url == ""
    assert beta.url == ""
    assert classify_encoded_artifact(alpha).category == LIKELY_SIGNAL
    assert classify_encoded_artifact(beta).category == LIKELY_SIGNAL


# Future boundary contract: imports happen at test execution so all RED cases collect.


def test_future_api_is_keyword_only_and_composition_is_immutable() -> None:
    api = _future_api()
    composition = _compose(api)

    assert tuple(item.name for item in fields(api.OperatorBriefSourceNativeSubject)) == (
        "subject_id",
        "family",
        "policy_subject",
        "endpoints",
        "origins",
        "evidence_ids",
        "artefact_references",
        "source_references",
        "interpretation",
    )
    assert tuple(item.name for item in fields(api.OperatorBriefSourceNativeComposition)) == (
        "subjects",
    )
    with pytest.raises(TypeError):
        api.compose_operator_brief_source_native((), (), (), (), (), (), ())
    with pytest.raises(FrozenInstanceError):
        composition.subjects = ()


def test_empty_source_native_composition() -> None:
    composition = _compose(_future_api())

    assert composition.subjects == ()
    assert composition.policy_subjects == ()


def test_complete_family_subject_kind_and_independent_trait_map() -> None:
    api = _future_api()
    composition = _compose(api, **_all_family_inputs())
    expected_kinds = {
        api.OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW:
            OperatorBriefSubjectKind.ACCOUNT_WORKFLOW,
        api.OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
        api.OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT:
            OperatorBriefSubjectKind.CONTENT_SURFACE,
    }

    assert len(composition.subjects) == len(expected_kinds)
    assert {item.family for item in composition.subjects} == set(expected_kinds)
    for subject in composition.subjects:
        policy = subject.policy_subject
        assert subject.subject_id.startswith("SOURCE-NATIVE-")
        assert policy.semantic_subject_key.startswith("source-native:")
        assert policy.subject_kind is expected_kinds[subject.family]
        assert policy.materiality is OperatorBriefThreadMateriality.MATERIAL
        assert policy.specificity is OperatorBriefThreadSpecificity.SPECIFIC
        assert policy.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
        assert policy.independent is True
        assert policy.associated_subject_reference is None
        assert policy.facts == ()
        assert policy.conflicts == ()
        assert policy.coverage_limitations == ()
        assert policy.source_rankings == ()
        assert policy.source_lead_ids == ()
        assert policy.replaced_by_subject_reference is None


def test_source_native_subject_and_all_interpretation_variants_are_immutable() -> None:
    api = _future_api()
    composition = _compose(api, **_all_family_inputs())
    subject = composition.subjects[0]

    with pytest.raises(FrozenInstanceError):
        subject.endpoints = ()

    expected_types = {
        api.OperatorBriefStructuredDisclosureInterpretation,
        api.OperatorBriefDirectoryListingInterpretation,
        api.OperatorBriefAccessBoundaryInterpretation,
        api.OperatorBriefCredentialInterpretation,
        api.OperatorBriefAccountWorkflowInterpretation,
        api.OperatorBriefObjectReferenceInterpretation,
        api.OperatorBriefEncodedArtifactInterpretation,
    }
    interpretations = {
        type(item.interpretation): item.interpretation
        for item in composition.subjects
    }
    assert set(interpretations) == expected_types
    for interpretation in interpretations.values():
        first_field = fields(interpretation)[0].name
        with pytest.raises(FrozenInstanceError):
            setattr(
                interpretation,
                first_field,
                getattr(interpretation, first_field),
            )


def test_all_family_common_subject_fields_preserve_authoritative_provenance() -> None:
    api = _future_api()
    composition = _compose(api, **_all_family_inputs())
    by_family = {item.family: item for item in composition.subjects}

    configuration = by_family[
        api.OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY
    ]
    assert configuration.endpoints == (_CONFIG_URL,)
    assert configuration.origins == (_ORIGIN,)
    assert configuration.evidence_ids == ("EVID-DISCLOSURE",)

    json_routes = by_family[
        api.OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES
    ]
    assert json_routes.endpoints == (_JSON_URL,)
    assert json_routes.origins == (_ORIGIN,)
    assert json_routes.evidence_ids == ("EVID-DISCLOSURE",)

    listing = by_family[
        api.OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE
    ]
    assert listing.endpoints == (_LISTING_URL,)
    assert listing.origins == (_ORIGIN,)
    assert listing.evidence_ids == ("EVID-LISTING",)
    assert listing.artefact_references == ("deep_source_route_collection.json",)

    access = by_family[
        api.OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE
    ]
    assert access.endpoints == (_BOUNDARY_URL,)
    assert access.origins == (_ORIGIN,)
    assert access.evidence_ids == ("EVID-BOUNDARY",)
    assert access.source_references == (
        OperatorBriefSourceReference(
            "deep_http_fingerprint",
            "DEEP-HTTP-FP-BOUNDARY",
        ),
    )

    credential = by_family[
        api.OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW
    ]
    assert credential.endpoints == (_CREDENTIAL_URL,)
    assert credential.origins == (_ORIGIN,)
    assert credential.evidence_ids == ("EVID-CREDENTIAL",)
    assert credential.artefact_references == ("retained-config.js",)

    account = by_family[api.OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW]
    assert account.endpoints == (f"{_ORIGIN}/login",)
    assert account.origins == (_ORIGIN,)
    assert account.evidence_ids == ("EVID-ACCOUNT",)

    object_reference = by_family[
        api.OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE
    ]
    assert object_reference.endpoints == (
        f"{_ORIGIN}/records",
        f"{_ORIGIN}/users",
    )
    assert object_reference.origins == (_ORIGIN,)
    assert object_reference.evidence_ids == ("EVID-OBJECT",)

    encoded = by_family[
        api.OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
    ]
    assert encoded.endpoints == (_ENCODED_URL,)
    assert encoded.origins == (_ORIGIN,)
    assert encoded.evidence_ids == ("EVID-ENCODED",)
    assert encoded.artefact_references == ("retained-data.js",)


@pytest.mark.parametrize(
    ("category", "url", "body_sha", "values", "excerpt", "family_name"),
    (
        (
            "structured_configuration_body",
            _CONFIG_URL,
            "config-body-sha",
            (),
            ("Listen 8443", "DocumentRoot /srv/application"),
            "STRUCTURED_CONFIGURATION_BODY",
        ),
        (
            "structured_json_routes",
            _JSON_URL,
            "json-body-sha",
            ("/admin/reports", "/api/accounts"),
            (),
            "STRUCTURED_JSON_ROUTES",
        ),
    ),
)
def test_structured_disclosure_projection_retains_safe_interpretation(
    category: str,
    url: str,
    body_sha: str,
    values: tuple[str, ...],
    excerpt: tuple[str, ...],
    family_name: str,
) -> None:
    api = _future_api()
    lead = _disclosure_lead(
        category,
        url=url,
        body_sha256=body_sha,
        observed_values=values,
        excerpt=excerpt,
    )
    subject = _compose(api, deep_source_route_review=_source_review(lead)).subjects[0]

    assert subject.family is getattr(api.OperatorBriefSourceNativeFamily, family_name)
    assert isinstance(subject.interpretation, api.OperatorBriefStructuredDisclosureInterpretation)
    assert subject.interpretation.category == category
    assert subject.interpretation.source_url == url
    assert subject.interpretation.final_url == url
    assert subject.interpretation.body_sha256 == body_sha
    assert subject.interpretation.disclosed_routes == values
    assert subject.interpretation.redacted_excerpt_lines == excerpt


def test_directory_listing_projection_retains_typed_source_data() -> None:
    api = _future_api()
    review = _listing_review()
    subject = _compose(api, successful_content_reviews=(review,)).subjects[0]

    assert subject.family is api.OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE
    assert isinstance(subject.interpretation, api.OperatorBriefDirectoryListingInterpretation)
    assert subject.interpretation.canonical_url == review.canonical_url
    assert subject.interpretation.requested_urls == review.requested_urls
    assert subject.interpretation.status_code == 200
    assert subject.interpretation.content_type == "text/html"
    assert subject.interpretation.body_sha256 == review.body_sha256
    assert subject.interpretation.listing_path == "/public"


def test_access_boundary_projection_retains_response_and_contrast() -> None:
    api = _future_api()
    fingerprint = _fingerprint()
    subject = _compose(api, fingerprint=fingerprint).subjects[0]

    assert subject.family is api.OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE
    assert isinstance(subject.interpretation, api.OperatorBriefAccessBoundaryInterpretation)
    assert subject.interpretation.fingerprint_id == fingerprint.fingerprint_id
    assert subject.interpretation.requested_url == _BOUNDARY_URL
    assert subject.interpretation.final_url == _BOUNDARY_URL
    assert subject.interpretation.method == "GET"
    assert subject.interpretation.status_code == 401
    assert subject.interpretation.body_sha256 == "boundary-body-sha"
    assert tuple(item.value for item in subject.interpretation.signal_kinds) == (
        "www_authenticate",
    )
    assert subject.interpretation.contrast_category == "client_error_signature_group"
    assert subject.interpretation.comparison_endpoints == (_BOUNDARY_URL,)
    assert subject.interpretation.comparison_statuses == (401,)
    assert subject.interpretation.member_count == 1
    assert subject.source_references == (
        OperatorBriefSourceReference(
            source_kind="deep_http_fingerprint",
            source_id=fingerprint.fingerprint_id,
        ),
    )


def test_credential_projection_groups_by_url_and_drops_secret_values() -> None:
    api = _future_api()
    first = _credential_artifact()
    second = HTTPArtifact(
        url=_CREDENTIAL_URL,
        artifact_type="keyword_hit",
        value="secret",
        source_file="retained-config.js",
        evidence_ids=["EVID-KEYWORD"],
        tags=[],
    )
    subject = _compose(api, http_artifacts=(first, second)).subjects[0]

    assert subject.family is api.OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW
    assert isinstance(subject.interpretation, api.OperatorBriefCredentialInterpretation)
    assert subject.interpretation.source_url == _CREDENTIAL_URL
    assert subject.interpretation.artefact_types == ("html_comment", "keyword_hit")
    assert subject.interpretation.assignment_labels == ("api_key",)
    assert tuple(item.value for item in subject.interpretation.indicator_classes) == (
        "sensitive_assignment",
    )
    assert _SECRET not in subject.interpretation.assignment_labels


def test_account_workflow_projection_uses_retention_not_presentation() -> None:
    api = _future_api()
    lead = _account_workflow()
    subject = _compose(api, workflow_leads=(lead,)).subjects[0]

    assert subject.family is api.OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW
    assert isinstance(subject.interpretation, api.OperatorBriefAccountWorkflowInterpretation)
    assert subject.interpretation.origin == _ORIGIN
    assert subject.interpretation.covered_urls == lead.covered_urls
    assert subject.interpretation.observations == lead.retention.observations
    assert subject.policy_subject.subject_kind is OperatorBriefSubjectKind.ACCOUNT_WORKFLOW
    assert subject.policy_subject.associated_subject_reference is None
    assert all(
        _SECRET not in field_name
        for observation in subject.interpretation.observations
        for field_name in observation.field_names
    )
    assert all(
        "private-value" not in observation.url
        for observation in subject.interpretation.observations
    )


def test_object_reference_projection_uses_retention_not_presentation() -> None:
    api = _future_api()
    lead = _object_workflow()
    subject = _compose(api, workflow_leads=(lead,)).subjects[0]

    assert subject.family is api.OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE
    assert isinstance(subject.interpretation, api.OperatorBriefObjectReferenceInterpretation)
    assert subject.interpretation.origin == _ORIGIN
    assert subject.interpretation.covered_urls == lead.covered_urls
    assert subject.interpretation.parameter_names == ("record", "user")
    assert subject.policy_subject.subject_kind is OperatorBriefSubjectKind.CONTENT_SURFACE
    assert subject.policy_subject.associated_subject_reference is None
    assert "OBJECT-VALUE-DO-NOT-RETAIN" not in subject.interpretation.parameter_names


def test_encoded_classifier_admission_is_likely_signal_only() -> None:
    api = _future_api()
    likely = _encoded_artifact(url=_ENCODED_UNSAFE_URL)
    possible = _encoded_artifact(
        _POSSIBLE_ENCODED_VALUE,
        url=f"{_ORIGIN}/possible",
    )
    noise = _encoded_artifact(_NOISE_ENCODED_VALUE, url=f"{_ORIGIN}/noise")

    composition = _compose(api, http_artifacts=(noise, possible, likely))

    assert len(composition.subjects) == 1
    subject = composition.subjects[0]
    assert subject.family is api.OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
    assert isinstance(subject.interpretation, api.OperatorBriefEncodedArtifactInterpretation)
    assert subject.interpretation.classification_category == LIKELY_SIGNAL
    assert subject.interpretation.artefact_type == "encoded_like_artifact"
    assert subject.interpretation.value_sha256 == sha256(_ENCODED_VALUE.encode()).hexdigest()
    assert subject.interpretation.value_length == len(_ENCODED_VALUE)
    assert subject.interpretation.source_url == _ENCODED_URL
    assert "source-user" not in subject.interpretation.source_url
    assert "source-password" not in subject.interpretation.source_url
    assert "QUERY-VALUE-DO-NOT-RETAIN" not in subject.interpretation.source_url
    assert "#" not in subject.interpretation.source_url
    assert not hasattr(subject.interpretation, "value")


def test_encoded_no_url_source_file_is_the_fallback_semantic_locator() -> None:
    api = _future_api()
    alpha = _encoded_artifact(url="", source_file="alpha.js", evidence_id="EVID-A")
    beta = _encoded_artifact(url="", source_file="beta.js", evidence_id="EVID-B")

    composition = _compose(api, http_artifacts=(alpha, beta))

    assert len(composition.subjects) == 2
    assert {item.interpretation.source_url for item in composition.subjects} == {""}
    assert len({item.subject_id for item in composition.subjects}) == 2
    assert len({item.policy_subject.semantic_subject_key for item in composition.subjects}) == 2
    assert len({item.policy_subject.policy_key for item in composition.subjects}) == 2
    assert {item.artefact_references for item in composition.subjects} == {
        ("alpha.js",),
        ("beta.js",),
    }
    assert all(item.endpoints == () and item.origins == () for item in composition.subjects)


def test_encoded_same_file_no_url_duplicates_compose_evidence_deterministically() -> None:
    api = _future_api()
    first = _encoded_artifact(url="", source_file="same.js", evidence_id="EVID-B")
    second = _encoded_artifact(url="", source_file="same.js", evidence_id="EVID-A")

    forward = _compose(api, http_artifacts=(first, second))
    reverse = _compose(api, http_artifacts=(second, first))

    assert forward == reverse
    assert len(forward.subjects) == 1
    assert forward.subjects[0].evidence_ids == ("EVID-A", "EVID-B")
    assert forward.subjects[0].artefact_references == ("same.js",)


def test_encoded_url_present_identity_ignores_source_file_provenance() -> None:
    api = _future_api()
    alpha = _encoded_artifact(source_file="alpha.js")
    beta = _encoded_artifact(source_file="beta.js")

    first = _compose(api, http_artifacts=(alpha,)).subjects[0]
    second = _compose(api, http_artifacts=(beta,)).subjects[0]

    assert first.subject_id == second.subject_id
    assert first.policy_subject.semantic_subject_key == second.policy_subject.semantic_subject_key
    assert first.policy_subject.policy_key == second.policy_subject.policy_key


@pytest.mark.parametrize(
    "matcher",
    (
        "structured_disclosure",
        "directory_listing",
        "access_boundary",
        "credential",
        "encoded",
    ),
)
def test_each_http_matcher_freezes_zero_one_and_multiple_targets(
    matcher: str,
) -> None:
    api = _future_api()
    inputs, matching, nonmatching = _association_case(matcher)
    second_matching = replace(
        matching,
        policy_key=f"{matching.policy_key}-SECOND",
        semantic_subject_key=f"{matching.semantic_subject_key}-second",
        facts=tuple(
            replace(fact, fact_id=f"{fact.fact_id}-SECOND")
            for fact in matching.facts
        ),
    )

    zero = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(nonmatching,),
    ).policy_subjects[0]
    one = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(matching,),
    ).policy_subjects[0]
    multiple = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(second_matching, matching),
    ).policy_subjects[0]

    for subject in (zero, multiple):
        assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
        assert subject.specificity is OperatorBriefThreadSpecificity.SPECIFIC
        assert subject.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
        assert subject.independent is True
        assert subject.associated_subject_reference is None

    assert one.materiality is OperatorBriefThreadMateriality.CONTEXT
    assert one.specificity is OperatorBriefThreadSpecificity.SPECIFIC
    assert one.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
    assert one.independent is False
    assert one.associated_subject_reference.subject_kind is OperatorBriefSubjectKind.APPLICATION
    assert one.associated_subject_reference.semantic_subject_key == matching.semantic_subject_key


def test_disclosure_association_accepts_source_or_distinct_final_url() -> None:
    api = _future_api()
    final_url = f"{_ORIGIN}/canonical/runtime.conf"
    lead = _disclosure_lead(
        "structured_configuration_body",
        url=_CONFIG_URL,
        final_url=final_url,
        body_sha256="redirected-config-body-sha",
        excerpt=("Listen 8443",),
    )
    inputs = {"deep_source_route_review": _source_review(lead)}
    source_target = _http_target(
        semantic_key="http:disclosure-source",
        route=_CONFIG_URL,
        body_sha256="redirected-config-body-sha",
    )
    final_target = _http_target(
        semantic_key="http:disclosure-final",
        route=final_url,
        body_sha256="redirected-config-body-sha",
    )

    source_match = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(source_target,),
    ).policy_subjects[0]
    final_match = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(final_target,),
    ).policy_subjects[0]

    assert source_match.associated_subject_reference.semantic_subject_key == (
        source_target.semantic_subject_key
    )
    assert final_match.associated_subject_reference.semantic_subject_key == (
        final_target.semantic_subject_key
    )


def test_listing_association_accepts_canonical_or_distinct_requested_url() -> None:
    api = _future_api()
    requested_url = f"{_ORIGIN}/public/index.html"
    review = _listing_review(requested_urls=(requested_url,))
    inputs = {"successful_content_reviews": (review,)}
    canonical_target = _http_target(
        semantic_key="http:listing-canonical",
        route=review.canonical_url,
        body_sha256=review.body_sha256,
        status=review.status_code,
    )
    requested_target = _http_target(
        semantic_key="http:listing-requested",
        route=requested_url,
        body_sha256=review.body_sha256,
        status=review.status_code,
    )

    canonical_match = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(canonical_target,),
    ).policy_subjects[0]
    requested_match = _compose(
        api,
        **inputs,
        normalized_policy_subjects=(requested_target,),
    ).policy_subjects[0]

    assert canonical_match.associated_subject_reference.semantic_subject_key == (
        canonical_target.semantic_subject_key
    )
    assert requested_match.associated_subject_reference.semantic_subject_key == (
        requested_target.semantic_subject_key
    )


def test_encoded_association_uses_sanitized_locator_not_raw_unsafe_url() -> None:
    api = _future_api()
    artifact = _encoded_artifact(url=_ENCODED_UNSAFE_URL)
    safe_target = _http_target(
        semantic_key="http:encoded-safe",
        route=_ENCODED_URL,
    )

    subject = _compose(
        api,
        http_artifacts=(artifact,),
        normalized_policy_subjects=(safe_target,),
    ).subjects[0]

    assert subject.endpoints == (_ENCODED_URL,)
    assert subject.interpretation.source_url == _ENCODED_URL
    assert subject.policy_subject.associated_subject_reference.semantic_subject_key == (
        safe_target.semantic_subject_key
    )


def test_association_cardinality_counts_application_subjects_not_matching_facts() -> None:
    api = _future_api()
    review = _listing_review()
    application = _http_target(
        semantic_key="http:two-facts-one-application",
        route=review.canonical_url,
        body_sha256=review.body_sha256,
        status=review.status_code,
    )
    second_fact = replace(
        application.facts[0],
        fact_id="FACT-SECOND-MATCH-IN-SAME-APPLICATION",
    )
    application = replace(
        application,
        facts=(*application.facts, second_fact),
    )

    subject = _compose(
        api,
        successful_content_reviews=(review,),
        normalized_policy_subjects=(application,),
    ).policy_subjects[0]

    assert subject.materiality is OperatorBriefThreadMateriality.CONTEXT
    assert subject.independent is False
    assert subject.associated_subject_reference.semantic_subject_key == (
        application.semantic_subject_key
    )


def test_matching_fact_on_non_application_subject_is_not_an_association_target() -> None:
    api = _future_api()
    review = _listing_review()
    application_shaped = _http_target(
        semantic_key="web:not-an-application",
        route=review.canonical_url,
        body_sha256=review.body_sha256,
        status=review.status_code,
    )
    non_application = replace(
        application_shaped,
        subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
    )

    subject = _compose(
        api,
        successful_content_reviews=(review,),
        normalized_policy_subjects=(non_application,),
    ).policy_subjects[0]

    assert subject.materiality is OperatorBriefThreadMateriality.MATERIAL
    assert subject.independent is True
    assert subject.associated_subject_reference is None


def test_workflows_are_never_associated_by_shared_origin() -> None:
    api = _future_api()
    target = _http_target(route=f"{_ORIGIN}/login")
    composition = _compose(
        api,
        workflow_leads=(_account_workflow(), _object_workflow()),
        normalized_policy_subjects=(target,),
    )

    for item in composition.subjects:
        policy = item.policy_subject
        assert policy.materiality is OperatorBriefThreadMateriality.MATERIAL
        assert policy.specificity is OperatorBriefThreadSpecificity.SPECIFIC
        assert policy.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
        assert policy.independent is True
        assert policy.associated_subject_reference is None


def test_same_identity_account_workflows_compose_typed_unions_deterministically() -> None:
    api = _future_api()
    form = _account_workflow()
    redirect_observation = WorkflowAccountObservation(
        kind=WorkflowAccountObservationKind.AUTHENTICATION_REDIRECT,
        url=f"{_ORIGIN}/account",
        evidence_ids=("EVID-REDIRECT",),
        redirect_target_url=f"{_ORIGIN}/login?next=PRIVATE-REDIRECT-VALUE",
    )
    redirect = _account_workflow(
        observation=redirect_observation,
        covered_urls=(f"{_ORIGIN}/account",),
        evidence_ids=("EVID-REDIRECT",),
    )

    forward = _compose(api, workflow_leads=(form, redirect))
    reverse = _compose(api, workflow_leads=(redirect, form))
    baseline = _compose(api, workflow_leads=(form,)).subjects[0]

    assert forward == reverse
    assert len(forward.subjects) == 1
    subject = forward.subjects[0]
    assert subject.family is api.OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW
    assert subject.interpretation.origin == _ORIGIN
    assert subject.interpretation.covered_urls == (
        f"{_ORIGIN}/account",
        f"{_ORIGIN}/login",
    )
    assert subject.interpretation.observations == WorkflowAccountRetention(
        _ORIGIN,
        (*form.retention.observations, *redirect.retention.observations),
    ).observations
    assert subject.evidence_ids == ("EVID-ACCOUNT", "EVID-REDIRECT")
    retained_redirect = next(
        item
        for item in subject.interpretation.observations
        if item.kind is WorkflowAccountObservationKind.AUTHENTICATION_REDIRECT
    )
    assert retained_redirect.redirect_target_url == f"{_ORIGIN}/login"
    assert subject.subject_id == baseline.subject_id
    assert subject.policy_subject.semantic_subject_key == (
        baseline.policy_subject.semantic_subject_key
    )
    assert subject.policy_subject.policy_key == baseline.policy_subject.policy_key


def test_duplicate_account_observation_unions_evidence_without_identity_change() -> None:
    api = _future_api()
    first_observation = WorkflowAccountObservation(
        kind=WorkflowAccountObservationKind.OBSERVED_FORM,
        url=f"{_ORIGIN}/login",
        evidence_ids=("EVID-FORM-A",),
        methods=("POST",),
        field_names=("password", "username"),
    )
    second_observation = replace(
        first_observation,
        evidence_ids=("EVID-FORM-B",),
    )
    first = _account_workflow(
        observation=first_observation,
        evidence_ids=("EVID-FORM-A",),
    )
    second = _account_workflow(
        observation=second_observation,
        evidence_ids=("EVID-FORM-B",),
    )

    baseline = _compose(api, workflow_leads=(first,)).subjects[0]
    forward = _compose(api, workflow_leads=(first, second))
    reverse = _compose(api, workflow_leads=(second, first))

    assert forward == reverse
    assert len(forward.subjects) == 1
    subject = forward.subjects[0]
    assert subject.interpretation.observations == (
        replace(
            first_observation,
            evidence_ids=("EVID-FORM-A", "EVID-FORM-B"),
        ),
    )
    assert subject.evidence_ids == ("EVID-FORM-A", "EVID-FORM-B")
    assert subject.subject_id == baseline.subject_id
    assert subject.policy_subject.semantic_subject_key == (
        baseline.policy_subject.semantic_subject_key
    )
    assert subject.policy_subject.policy_key == baseline.policy_subject.policy_key


def test_same_identity_object_workflows_compose_typed_unions_deterministically() -> None:
    api = _future_api()
    first = _object_workflow(
        parameter_names=("record",),
        covered_urls=(f"{_ORIGIN}/records",),
        evidence_ids=("EVID-RECORD",),
    )
    second = _object_workflow(
        parameter_names=("document", "user"),
        covered_urls=(f"{_ORIGIN}/documents", f"{_ORIGIN}/users"),
        evidence_ids=("EVID-DOCUMENT", "EVID-USER"),
    )

    forward = _compose(api, workflow_leads=(first, second))
    reverse = _compose(api, workflow_leads=(second, first))
    baseline = _compose(api, workflow_leads=(first,)).subjects[0]

    assert forward == reverse
    assert len(forward.subjects) == 1
    subject = forward.subjects[0]
    assert subject.family is api.OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE
    assert subject.interpretation.parameter_names == ("document", "record", "user")
    assert subject.interpretation.covered_urls == (
        f"{_ORIGIN}/documents",
        f"{_ORIGIN}/records",
        f"{_ORIGIN}/users",
    )
    assert subject.evidence_ids == ("EVID-DOCUMENT", "EVID-RECORD", "EVID-USER")
    assert subject.subject_id == baseline.subject_id
    assert subject.policy_subject.semantic_subject_key == (
        baseline.policy_subject.semantic_subject_key
    )
    assert subject.policy_subject.policy_key == baseline.policy_subject.policy_key


def test_semantic_identity_and_policy_key_ignore_provenance_enrichment() -> None:
    api = _future_api()
    base = _disclosure_lead(
        "structured_json_routes",
        url=_JSON_URL,
        body_sha256="json-body-sha",
        observed_values=("/a",),
        evidence_ids=("EVID-A",),
    )
    enriched = replace(
        base,
        observed_values=("/a", "/b"),
        evidence_ids=("EVID-B", "EVID-A"),
        title="changed presentation",
    )
    before = _compose(api, deep_source_route_review=_source_review(base)).subjects[0]
    after = _compose(api, deep_source_route_review=_source_review(enriched)).subjects[0]

    assert before.subject_id == after.subject_id
    assert before.policy_subject.semantic_subject_key == after.policy_subject.semantic_subject_key
    assert before.policy_subject.policy_key == after.policy_subject.policy_key
    assert before.policy_subject.semantic_subject_key.startswith("source-native:")
    assert before.subject_id.startswith("SOURCE-NATIVE-")
    assert after.interpretation.disclosed_routes == ("/a", "/b")


def test_policy_key_is_canonical_composite_identity_hash() -> None:
    subject = _compose(
        _future_api(),
        workflow_leads=(_object_workflow(),),
    ).subjects[0]
    policy = subject.policy_subject
    payload = {
        "semantic_subject_key": policy.semantic_subject_key,
        "subject_kind": policy.subject_kind.value,
    }
    expected = "POLICY-" + sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16].upper()

    assert policy.policy_key == expected
    assert subject.subject_id != policy.policy_key


def test_common_provenance_is_canonical_and_safe_values_do_not_survive() -> None:
    api = _future_api()
    credential = _credential_artifact()
    encoded = _encoded_artifact()
    composition = _compose(api, http_artifacts=(encoded, credential))

    assert {item.evidence_ids for item in composition.subjects} == {
        ("EVID-CREDENTIAL",),
        ("EVID-ENCODED",),
    }
    assert all(item.artefact_references == ("retained-config.js",) or item.artefact_references == ("retained-data.js",) for item in composition.subjects)
    structured_values = [
        value
        for item in composition.subjects
        for field in fields(item.interpretation)
        for value in (getattr(item.interpretation, field.name),)
    ]
    assert all(_SECRET not in str(value) for value in structured_values)
    assert all(_ENCODED_VALUE not in str(value) for value in structured_values)
    assert all("private-value" not in endpoint for item in composition.subjects for endpoint in item.endpoints)


def test_input_permutation_and_duplicate_composition_are_deterministic() -> None:
    api = _future_api()
    encoded_a = _encoded_artifact(evidence_id="EVID-B")
    encoded_b = _encoded_artifact(evidence_id="EVID-A")
    forward = _compose(
        api,
        http_artifacts=(encoded_a, encoded_b),
        workflow_leads=(_object_workflow(), _account_workflow()),
    )
    reverse = _compose(
        api,
        http_artifacts=(encoded_b, encoded_a),
        workflow_leads=(_account_workflow(), _object_workflow()),
    )

    assert forward == reverse
    assert len(forward.subjects) == 3
    encoded_subject = next(
        item
        for item in forward.subjects
        if item.family is api.OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
    )
    assert encoded_subject.evidence_ids == ("EVID-A", "EVID-B")
    assert forward.policy_subjects == tuple(item.policy_subject for item in forward.subjects)
    assert tuple(item.policy_subject.policy_key for item in forward.subjects) == tuple(
        sorted(item.policy_subject.policy_key for item in forward.subjects)
    )


def test_no_hard_cap_and_direct_closed_policy_acceptance() -> None:
    api = _future_api()
    artifacts = tuple(
        _encoded_artifact(
            f"{index:032x}",
            url=f"{_ORIGIN}/encoded/{index}",
            evidence_id=f"EVID-{index:02d}",
        )
        for index in range(1, 11)
    )
    composition = _compose(api, http_artifacts=artifacts)
    result = apply_operator_brief_thread_policy(composition.policy_subjects)

    assert len(composition.subjects) == 10
    assert len(result.decisions) == 10
    assert all(item.rank is not None for item in result.decisions)


def test_policy_projection_has_no_fabricated_legacy_payload_fields() -> None:
    composition = _compose(
        _future_api(),
        workflow_leads=(_account_workflow(),),
    )
    policy = composition.policy_subjects[0]

    assert policy.evidence_basis is OperatorBriefThreadEvidenceBasis.LEGACY
    assert policy.facts == ()
    assert policy.conflicts == ()
    assert policy.coverage_limitations == ()
    assert policy.source_rankings == ()
    assert policy.source_lead_ids == ()
    assert policy.replaced_by_subject_reference is None


def test_normalized_and_source_native_composite_identities_remain_distinct() -> None:
    api = _future_api()
    normalized = _http_target(
        semantic_key="http:shared-raw-text",
        route=f"{_ORIGIN}/login",
    )
    source_native = _compose(
        api,
        workflow_leads=(_account_workflow(),),
        normalized_policy_subjects=(normalized,),
    ).policy_subjects[0]

    assert source_native.semantic_subject_key != normalized.semantic_subject_key
    assert source_native.policy_key != normalized.policy_key
    result = apply_operator_brief_thread_policy((normalized, source_native))
    assert len(result.decisions) == 2
