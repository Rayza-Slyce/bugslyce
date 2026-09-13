"""WP5B canonical application/service model persistence and closure tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import runpy
import zipfile

import pytest

from bugslyce.recon.application_service_composition import (
    build_application_service_composition,
)
from bugslyce.recon.application_service_model import (
    ApplicationServiceModelRelationKind,
    build_application_service_model,
)
from bugslyce.recon.application_service_model_persistence import (
    APPLICATION_SERVICE_MODEL_FILENAME,
    application_service_model_from_dict,
    application_service_model_to_dict,
    load_application_service_model_artifact,
    write_application_service_model_artifact,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
    DocumentationAssertionKind,
    build_documentation_assertions,
)
from bugslyce.recon.evidence_pack_closure import (
    discover_evidence_pack_references,
    validate_evidence_pack_root,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge
from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    build_native_observation_semantic_evidence,
)
from bugslyce.recon.native_observation_store import (
    NATIVE_OBSERVATION_STORE_PROJECT_PATH,
    NativeCandidateObservation,
    NativeObservationStore,
    NativeReceivedExchange,
)


_ROOT = Path(__file__).resolve().parents[1]
_EXPORT_HELPERS = runpy.run_path(str(_ROOT / "tests/test_recon_export.py"))
_FIXED_TIME = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


def _item(body: bytes, *, url: str, evidence_id: str) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("content-type", "text/html"),),
        body_preview=body.decode()[:120],
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.125,
        source="recursive_evidence_feedback",
        reason="bounded_second_pass",
        evidence_ids=(evidence_id,),
        body=body,
    )


def _model(*, target_only: bool = False, reversed_inputs: bool = False):
    service = _item(
        b"<html><main><h2>API base URL</h2><pre>https://api.example.test/v1</pre></main></html>",
        url="https://docs.example.test/service",
        evidence_id="EVID-DOC",
    )
    realtime = _item(
        b"<html><main><h2>WebSocket endpoint</h2><pre>wss://stream.example.test/v1/public</pre></main></html>",
        url="https://docs.example.test/realtime",
        evidence_id="EVID-REALTIME",
    )
    unrelated = _item(
        b"<html><main><h2>HTTP operation</h2><pre>POST /v1/token</pre>"
        b"<table><tr><th>Header</th><th>Required</th></tr>"
        b"<tr><td>X-Client-Token</td><td>yes</td></tr></table>"
        b"<dl><dt>Authentication scheme</dt><dd>Bearer</dd>"
        b"<dt>OAuth scope</dt><dd>account:write</dd></dl></main></html>",
        url="https://docs.example.test/security",
        evidence_id="EVID-SECURITY",
    )
    items = (service, realtime, unrelated)
    if reversed_inputs:
        items = tuple(reversed(items))
    collection = DeepSourceRouteCollectionResult(
        collected=items,
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )
    documentation = build_documentation_assertions(collection)
    source = (
        "https://observed.example.test/start"
        if target_only
        else "https://api.example.test/start"
    )
    target = (
        "https://api.example.test/login"
        if target_only
        else "https://elsewhere.example.test/login"
    )
    edge = HttpRouteRelationshipEdge(
        edge_type="redirect",
        source_url=source,
        target_url=target,
        evidence_ids=("EVID-OBS",),
        artefact_references=("redirect.txt",),
        raw_references=(target,),
        status_code=302,
    )
    composition = build_application_service_composition(redirect_edges=(edge,))
    return build_application_service_model(
        application_composition=composition,
        documentation_assertions=documentation,
    )


def _native_model(root: Path):
    store = NativeObservationStore(
        root / NATIVE_OBSERVATION_STORE_PROJECT_PATH,
        100_000,
        metadata_byte_allowance=10_000_000,
    )

    json_body = b'{"results": [], "count": 0}'
    json_reference = store.commit_body(
        store.reserve_body_bytes(len(json_body)),
        json_body,
    )
    json_exchange = NativeReceivedExchange(
        request_url="https://app.example.test/api/search/",
        status_code=200,
        headers=(("Content-Type", "application/json"),),
        capture_state="complete",
        captured_bytes=len(json_body),
        body_sha256=sha256(json_body).hexdigest(),
        body=json_reference,
    )
    store.publish_observation(
        NativeCandidateObservation(
            candidate_index=7,
            request_url=json_exchange.request_url,
            exchanges=(json_exchange,),
        ),
        store.reserve_candidate_metadata(7, maximum_redirect_hops=0),
    )

    redirect_body = b""
    redirect_reference = store.commit_body(
        store.reserve_body_bytes(len(redirect_body)),
        redirect_body,
    )
    redirect_exchange = NativeReceivedExchange(
        request_url="https://app.example.test/login",
        status_code=302,
        headers=(("Location", "//account.example.test/sign-in"),),
        capture_state="complete",
        captured_bytes=0,
        body_sha256=sha256(redirect_body).hexdigest(),
        body=redirect_reference,
    )
    store.publish_observation(
        NativeCandidateObservation(
            candidate_index=3,
            request_url=redirect_exchange.request_url,
            exchanges=(redirect_exchange,),
        ),
        store.reserve_candidate_metadata(3, maximum_redirect_hops=0),
    )

    store.publish_index("complete")

    native_evidence = build_native_observation_semantic_evidence(store)
    composition = build_application_service_composition(
        native_observation_evidence=native_evidence,
    )
    model = build_application_service_model(
        application_composition=composition,
        documentation_assertions=DocumentationAssertionExtractionResult(
            assertions=(),
            skipped_sources=(),
            sources_considered=0,
            sources_eligible=0,
        ),
        native_observation_evidence=native_evidence,
    )
    return model, native_evidence, sha256(json_body).hexdigest()


def _project(tmp_path: Path, model) -> Path:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    (root / "redirect.txt").write_text("HTTP/1.1 302 Found\n", encoding="utf-8")
    (root / "docs.html").write_text("retained documentation\n", encoding="utf-8")
    (root / "realtime.html").write_text("retained realtime documentation\n", encoding="utf-8")
    (root / "security.html").write_text("retained security documentation\n", encoding="utf-8")
    evidence = [
        {"id": "EVID-OBS", "source_file": "redirect.txt"},
        {"id": "EVID-DOC", "source_file": "docs.html"},
        {"id": "EVID-REALTIME", "source_file": "realtime.html"},
        {"id": "EVID-SECURITY", "source_file": "security.html"},
    ]
    (root / "project_state.json").write_text(
        json.dumps({"project_state": {"processed_files": [item["source_file"] for item in evidence], "evidence": evidence}, "candidates": []}) + "\n",
        encoding="utf-8",
    )
    write_application_service_model_artifact(root, model)
    return root


def test_schema_one_self_contained_round_trip_preserves_lower_truth() -> None:
    model = _model()
    restored = application_service_model_from_dict(application_service_model_to_dict(model))
    assert restored == model
    assert {item.kind for item in restored.documentation_assertions.assertions} >= {
        DocumentationAssertionKind.HTTP_OPERATION,
        DocumentationAssertionKind.REQUIRED_HEADER,
        DocumentationAssertionKind.AUTHENTICATION_SCHEME,
        DocumentationAssertionKind.OAUTH_SCOPE,
    }


def test_schema_two_round_trip_preserves_native_observation_evidence(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-model"
    root.mkdir()

    model, native_evidence, _body_sha256 = _native_model(root)

    payload = application_service_model_to_dict(model)

    assert payload["schema_version"] == 2

    restored = application_service_model_from_dict(payload)

    assert restored == model
    assert restored.native_observation_evidence == native_evidence


def test_schema_one_without_native_evidence_loads_as_empty_native_evidence() -> None:
    payload = application_service_model_to_dict(_model())
    payload["schema_version"] = 1
    payload.pop("native_observation_evidence", None)

    restored = application_service_model_from_dict(payload)

    assert restored.native_observation_evidence == NativeObservationSemanticEvidence()


def test_schema_one_noncanonical_ordering_fails_closed() -> None:
    payload = application_service_model_to_dict(_model())
    payload["schema_version"] = 1
    payload.pop("native_observation_evidence", None)

    resources = payload["documentation_resources"]
    assert isinstance(resources, list)
    assert len(resources) > 1
    payload["documentation_resources"] = list(reversed(resources))

    with pytest.raises(ValueError, match="schema-1.*canonical"):
        application_service_model_from_dict(payload)


def test_schema_one_rejects_native_a1_vocabulary(tmp_path: Path) -> None:
    root = tmp_path / "schema-one-native"
    root.mkdir()
    model, _native_evidence, _body_sha256 = _native_model(root)

    payload = application_service_model_to_dict(model)
    payload["schema_version"] = 1
    payload.pop("native_observation_evidence", None)

    with pytest.raises(ValueError, match="schema-1.*native observation vocabulary"):
        application_service_model_from_dict(payload)


def test_canonical_serialization_is_deterministic_for_reversed_inputs(tmp_path: Path) -> None:
    first = write_application_service_model_artifact(tmp_path / "first", _model())
    second = write_application_service_model_artifact(tmp_path / "second", _model(reversed_inputs=True))
    assert first.read_bytes() == second.read_bytes()


@pytest.mark.parametrize("field,value", (("schema_version", 3), ("generated_by", "other")))
def test_unknown_schema_identity_fails_closed(field: str, value: object) -> None:
    payload = application_service_model_to_dict(_model())
    payload[field] = value
    with pytest.raises(ValueError):
        application_service_model_from_dict(payload)


def test_duplicate_json_member_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / APPLICATION_SERVICE_MODEL_FILENAME
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_application_service_model_artifact(tmp_path)


def test_malformed_relation_and_enum_fail_typed_reconstruction() -> None:
    payload = application_service_model_to_dict(_model())
    payload["relations"][0]["relation_kind"] = "requires_header"
    with pytest.raises(ValueError, match="unsupported"):
        application_service_model_from_dict(payload)


def test_source_side_correspondence_provenance_survives_round_trip() -> None:
    restored = application_service_model_from_dict(application_service_model_to_dict(_model()))
    relation = next(item for item in restored.relations if item.relation_kind is ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    support = relation.supports[0]
    assert support.documentation_support.source_reference.evidence_ids == ("EVID-DOC",)
    assert support.observation_support.evidence_ids == ("EVID-OBS",)


def test_target_only_redirect_does_not_gain_observation_through_persistence() -> None:
    restored = application_service_model_from_dict(application_service_model_to_dict(_model(target_only=True)))
    assert not any(item.relation_kind is ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN for item in restored.relations)


def test_documented_realtime_round_trips_as_non_http_non_executable_value() -> None:
    endpoint = application_service_model_from_dict(application_service_model_to_dict(_model())).documented_realtime_endpoints[0].value
    assert endpoint.canonical_url == "wss://stream.example.test/v1/public"
    assert not isinstance(endpoint, HttpOrigin)
    assert not any(hasattr(endpoint, name) for name in ("connect", "execute", "run"))


def test_optional_absence_returns_none_and_adds_no_closure_reference(tmp_path: Path) -> None:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    assert load_application_service_model_artifact(root) is None
    assert APPLICATION_SERVICE_MODEL_FILENAME not in {item.portable_path for item in discover_evidence_pack_references(root)}
    output = tmp_path / "older-compatible.zip"
    export_recon_evidence_pack(root, output, clock=lambda: _FIXED_TIME)
    extracted = tmp_path / "older-compatible"
    with zipfile.ZipFile(output) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_present_model_is_exported_loaded_and_validated(tmp_path: Path) -> None:
    root = _project(tmp_path, _model())
    output = tmp_path / "pack.zip"
    export_recon_evidence_pack(root, output, clock=lambda: _FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output) as archive:
        archive.extractall(extracted)
        assert APPLICATION_SERVICE_MODEL_FILENAME in archive.namelist()
    assert load_application_service_model_artifact(extracted) == _model()
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_closure_records_model_artifact_and_lower_provenance(tmp_path: Path) -> None:
    root = _project(tmp_path, _model())
    references = discover_evidence_pack_references(root)
    kinds = {item.owner_kind for item in references}
    assert {"application_service_model", "application_service_model_a1_relation_support", "application_service_model_a2_assertion_support"} <= kinds
    assert any(item.portable_path == "raw/redirect.txt" and item.evidence_ids == ("EVID-OBS",) for item in references)
    assert any(item.portable_path == "raw/docs.html" and item.evidence_ids == ("EVID-DOC",) for item in references)


def test_closure_binds_native_model_evidence_to_exact_store_members(
    tmp_path: Path,
) -> None:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    model, _native_evidence, body_sha256 = _native_model(root)
    write_application_service_model_artifact(root, model)

    references = discover_evidence_pack_references(root)

    fact_references = tuple(
        reference
        for reference in references
        if reference.owner_kind
        == "application_service_model_native_observation_evidence"
        and reference.owner_id == "native-observation:7:0"
    )
    assert any(
        reference.portable_path.endswith(
            "native-observations/observations/00000007.json"
        )
        for reference in fact_references
    )
    assert any(
        reference.portable_path.endswith(
            f"native-observations/bodies/sha256/{body_sha256}"
        )
        for reference in fact_references
    )

    redirect_references = tuple(
        reference
        for reference in references
        if reference.owner_kind == "application_service_model_a1_relation_support"
        and "native_observation_exchange" in reference.owner_id
    )
    assert any(
        reference.portable_path.endswith(
            "native-observations/observations/00000003.json"
        )
        for reference in redirect_references
    )


def test_broken_required_provenance_is_rejected(tmp_path: Path) -> None:
    root = _project(tmp_path, _model())
    (root / "redirect.txt").unlink()
    references = discover_evidence_pack_references(root)
    assert any(item.portable_path == "raw/redirect.txt" for item in references)
    output = tmp_path / "pack.zip"
    with pytest.raises(ValueError, match="not represented"):
        export_recon_evidence_pack(root, output, clock=lambda: _FIXED_TIME)


def test_unknown_embedded_evidence_id_fails_closure_discovery(tmp_path: Path) -> None:
    root = _project(tmp_path, _model())
    payload = json.loads((root / "project_state.json").read_text(encoding="utf-8"))
    payload["project_state"]["evidence"] = [item for item in payload["project_state"]["evidence"] if item["id"] != "EVID-DOC"]
    (root / "project_state.json").write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        discover_evidence_pack_references(root)
