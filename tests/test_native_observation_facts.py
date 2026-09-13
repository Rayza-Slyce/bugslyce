"""RED contract for offline facts derived from native observation evidence."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
)
from bugslyce.recon.native_observation_store import (
    NativeCandidateObservation,
    NativeObservationStore,
    NativeReceivedExchange,
)


def _store(root: Path) -> NativeObservationStore:
    return NativeObservationStore(
        root,
        body_byte_allowance=100_000,
        metadata_byte_allowance=10_000_000,
    )


def _exchange(
    store: NativeObservationStore,
    *,
    url: str,
    status_code: int,
    headers: tuple[tuple[str, str], ...],
    body: bytes,
) -> NativeReceivedExchange:
    reference = store.commit_body(store.reserve_body_bytes(len(body)), body)
    return NativeReceivedExchange(
        request_url=url,
        status_code=status_code,
        headers=headers,
        capture_state="complete",
        captured_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body=reference,
    )


def _publish(
    store: NativeObservationStore,
    *,
    candidate_index: int,
    exchange: NativeReceivedExchange,
) -> None:
    store.publish_observation(
        NativeCandidateObservation(
            candidate_index=candidate_index,
            request_url=exchange.request_url,
            exchanges=(exchange,),
        ),
        store.reserve_candidate_metadata(candidate_index, maximum_redirect_hops=0),
    )


def _native_semantic_evidence(store: NativeObservationStore):
    """The narrow offline adapter Package 2 must provide.

    It receives only an already-published store.  It cannot execute HTTP,
    schedule candidates, promote a path, or claim Deep/documentation ownership.
    """

    module = importlib.import_module("bugslyce.recon.native_observation_facts")
    return module.build_native_observation_semantic_evidence(store)


def test_complete_uncertain_json_observation_becomes_direct_fact_without_path_promotion(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations")
    body = b'{"results": [], "count": 0}'
    exchange = _exchange(
        store,
        url="https://app.example.test/api/search/",
        status_code=200,
        headers=(("Content-Type", "application/json"),),
        body=body,
    )
    _publish(store, candidate_index=7, exchange=exchange)
    store.publish_index("complete")

    evidence = _native_semantic_evidence(store)

    assert len(evidence.structured_responses) == 1
    fact = evidence.structured_responses[0]
    assert fact.request_url == "https://app.example.test/api/search/"
    assert fact.status_code == 200
    assert fact.candidate_index == 7
    assert fact.exchange_index == 0
    assert fact.body_sha256 == hashlib.sha256(body).hexdigest()
    assert fact.direct_observation is True
    assert fact.confirmed_api is False


def test_complete_native_redirect_becomes_direct_relationship_without_destination_fetch(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations")
    exchange = _exchange(
        store,
        url="https://app.example.test/login",
        status_code=302,
        headers=(("Location", "//account.example.test/sign-in"),),
        body=b"",
    )
    _publish(store, candidate_index=3, exchange=exchange)
    store.publish_index("complete")

    evidence = _native_semantic_evidence(store)

    assert len(evidence.redirect_relationships) == 1
    relationship = evidence.redirect_relationships[0]
    assert relationship.source_url == "https://app.example.test/login"
    assert relationship.raw_location == "//account.example.test/sign-in"
    assert relationship.target_url == "https://account.example.test/sign-in"
    assert relationship.candidate_index == 3
    assert relationship.exchange_index == 0
    assert relationship.direct_observation is True
    assert relationship.destination_fetched is False

    composition_api = importlib.import_module(
        "bugslyce.recon.application_service_composition"
    )
    composition = composition_api.build_application_service_composition(
        native_observation_evidence=evidence,
    )
    assert len(composition.relations) == 1
    relation = composition.relations[0]
    assert relation.relation_kind.value == "redirects_to"
    assert len(relation.supports) == 1
    support = relation.supports[0]
    assert support.source_semantic.value == "native_http_redirect"
    assert support.source_reference.owner_kind.value == "native_observation_exchange"
    assert support.source_reference.source_id == "native-observation:3:0"
    assert support.artefact_references == ()
    assert support.raw_references == ()


def test_complete_android_assetlinks_observation_becomes_declared_application_fact(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations")
    body = (
        b'[{"relation":["delegate_permission/common.handle_all_urls"],'
        b'"target":{"namespace":"android_app",'
        b'"package_name":"com.example.mobile",'
        b'"sha256_cert_fingerprints":["AA:BB"]}}]'
    )
    exchange = _exchange(
        store,
        url="https://app.example.test/.well-known/assetlinks.json",
        status_code=200,
        headers=(("Content-Type", "application/json"),),
        body=body,
    )
    _publish(store, candidate_index=11, exchange=exchange)
    store.publish_index("complete")

    evidence = _native_semantic_evidence(store)

    assert len(evidence.mobile_association_declarations) == 1
    declaration = evidence.mobile_association_declarations[0]
    assert declaration.document_url == (
        "https://app.example.test/.well-known/assetlinks.json"
    )
    assert declaration.platform == "android"
    assert declaration.package_name == "com.example.mobile"
    assert declaration.candidate_index == 11
    assert declaration.exchange_index == 0
    assert declaration.body_sha256 == hashlib.sha256(body).hexdigest()
    assert declaration.direct_observation is True
    assert declaration.ownership_confirmed is False


def test_native_structured_response_fact_feeds_canonical_application_service_model(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations")
    body = b'{"results": [], "count": 0}'
    exchange = _exchange(
        store,
        url="https://app.example.test/api/search/",
        status_code=200,
        headers=(("Content-Type", "application/json"),),
        body=body,
    )
    _publish(store, candidate_index=7, exchange=exchange)
    store.publish_index("complete")

    evidence = _native_semantic_evidence(store)
    composition_api = importlib.import_module(
        "bugslyce.recon.application_service_composition"
    )
    application_composition = composition_api.build_application_service_composition(
        native_observation_evidence=evidence,
    )
    model_api = importlib.import_module("bugslyce.recon.application_service_model")
    model = model_api.build_application_service_model(
        application_composition=application_composition,
        documentation_assertions=DocumentationAssertionExtractionResult(
            assertions=(),
            skipped_sources=(),
            sources_considered=0,
            sources_eligible=0,
        ),
        native_observation_evidence=evidence,
    )

    assert len(model.native_observation_evidence.structured_responses) == 1
    fact = model.native_observation_evidence.structured_responses[0]
    assert fact.request_url == "https://app.example.test/api/search/"
    assert fact.candidate_index == 7
    assert fact.exchange_index == 0
    assert fact.body_sha256 == hashlib.sha256(body).hexdigest()
