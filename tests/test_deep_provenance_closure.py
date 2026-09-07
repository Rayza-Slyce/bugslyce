"""Retained Deep response ownership and portable relation correspondence."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import runpy
import zipfile

import pytest

from bugslyce.recon.deep_collection_provenance import item_response_identity
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectedItem, DeepMetadataCollectionResult
from bugslyce.recon.deep_metadata_collection_export import write_deep_metadata_collection_artifacts
from bugslyce.recon.deep_source_route_collection_export import write_deep_source_route_collection_artifacts
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_javascript_route_extraction import build_deep_javascript_route_extraction
from bugslyce.recon.deep_provenance_artifacts import EXTRACTION_JSON, extraction_to_dict
from bugslyce.recon.application_service_composition import build_application_service_composition
from bugslyce.recon.application_service_model import build_application_service_model
from bugslyce.recon.application_service_model_persistence import write_application_service_model_artifact
from bugslyce.recon.documentation_assertions import build_documentation_assertions
from bugslyce.recon.evidence_pack_closure import discover_evidence_pack_references, validate_evidence_pack_root
from bugslyce.recon.export import export_recon_evidence_pack

HELPERS = runpy.run_path(str(Path(__file__).with_name("test_application_service_model_persistence.py")))


def metadata_project(tmp_path):
    item = DeepMetadataCollectedItem(
        url="https://example.test/sitemap.xml", final_url="https://example.test/sitemap.xml",
        method="GET", status_code=200, headers=(), body_preview="bounded",
        body_sha256=sha256(b"sitemap response").hexdigest(), body_bytes=16,
        elapsed_seconds=0.1, source="metadata_coverage", reason="test", evidence_ids=(),
        sitemap_route_references=("https://example.test/account",),
    )
    identifier = item_response_identity("metadata", item)
    item = replace(item, evidence_ids=(identifier,))
    collection = DeepMetadataCollectionResult((item,), (), 1, 1, 0)
    model = build_application_service_model(
        application_composition=build_application_service_composition(metadata_collection=collection),
        documentation_assertions=build_documentation_assertions(DeepSourceRouteCollectionResult((), (), 0, 0, 0)),
    )
    root = HELPERS["_project"](tmp_path, model)
    write_deep_metadata_collection_artifacts(collection, root)
    return root, identifier


def test_metadata_response_absent_from_core_has_one_retained_owner_and_portable_pack(tmp_path):
    root, identifier = metadata_project(tmp_path)
    assert identifier not in (root / "project_state.json").read_text()
    references = discover_evidence_pack_references(root)
    assert {ref.portable_path for ref in references if identifier in ref.evidence_ids} == {"deep_metadata_collection.json"}
    archive_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(root, archive_path, clock=lambda: HELPERS["_FIXED_TIME"])
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    payload_path = extracted / "deep_metadata_collection.json"
    payload = json.loads(payload_path.read_text())
    payload["collected"][0]["body_sha256"] = "f" * 64
    payload_path.write_text(json.dumps(payload))
    assert validate_evidence_pack_root(extracted).validation_status == "incomplete"


@pytest.mark.parametrize("field,value", [
    ("body_sha256", "f" * 64), ("status_code", 404),
    ("url", "https://example.test/unrelated"), ("final_url", "https://example.test/other"),
    ("evidence_ids", ["DEEP-RESP-SHA256-" + "e" * 64]),
    ("evidence_ids", ["DEEP-RESP-SHA256-malformed"]),
])
def test_tampered_response_facts_or_claim_fail_closed(tmp_path, field, value):
    root, _ = metadata_project(tmp_path)
    path = root / "deep_metadata_collection.json"
    payload = json.loads(path.read_text())
    payload["collected"][0][field] = value
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        discover_evidence_pack_references(root)


@pytest.mark.parametrize("mutation", ["missing", "antecedent", "skipped", "producer", "schema", "core", "symlink"])
def test_unowned_or_untrusted_response_cannot_satisfy_relation(tmp_path, mutation):
    root, identifier = metadata_project(tmp_path)
    path = root / "deep_metadata_collection.json"
    payload = json.loads(path.read_text())
    if mutation == "missing":
        path.rename(root / "unrecognised_collection.json")
    elif mutation == "symlink":
        retained = tmp_path / "outside.json"
        path.rename(retained)
        path.symlink_to(retained)
    elif mutation == "core":
        state = root / "project_state.json"
        data = json.loads(state.read_text())
        data["project_state"]["evidence"].append({"id": identifier, "source_file": "docs.html"})
        state.write_text(json.dumps(data))
    else:
        if mutation == "antecedent":
            payload["collected"][0]["body_sha256"] = "0" * 64
        elif mutation == "skipped":
            payload["skipped"] = [{"url": "https://example.test/sitemap.xml", "method": "GET", "reason": "refused", "source": "metadata_coverage", "evidence_ids": [identifier]}]
            payload["collected"] = []
        elif mutation == "producer":
            payload["generated_by"] = "untrusted"
        elif mutation == "schema":
            payload["schema_version"] = 999
        path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        discover_evidence_pack_references(root)


@pytest.mark.parametrize("body", [b'<a href="/account">account</a>', b'fetch("/account");'])
def test_html_javascript_response_binding_survives_export_and_rejects_mismatch(tmp_path, body):
    item = HELPERS["_item"](body, url="https://example.test/index", evidence_id="unused")
    item = replace(item, headers=(("content-type", "text/html" if body.startswith(b"<") else "application/javascript"),))
    identifier = item_response_identity("source-route", item)
    item = replace(item, evidence_ids=(identifier,))
    collection = DeepSourceRouteCollectionResult((item,), (), 1, 1, 0)
    html = build_deep_html_route_extraction(collection)
    js = build_deep_javascript_route_extraction(collection)
    composition = build_application_service_composition(html_extraction=html, javascript_extraction=js)
    assert composition.relations
    model = build_application_service_model(application_composition=composition, documentation_assertions=build_documentation_assertions(collection))
    root = HELPERS["_project"](tmp_path, model)
    write_deep_source_route_collection_artifacts(collection, root)
    path = root / EXTRACTION_JSON
    path.write_text(json.dumps(extraction_to_dict(html, js)))
    references = discover_evidence_pack_references(root)
    assert any(ref.portable_path == EXTRACTION_JSON for ref in references)
    archive_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(root, archive_path, clock=lambda: HELPERS["_FIXED_TIME"])
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    payload = json.loads(path.read_text())
    record = payload["html"]["routes"][0] if html.routes else payload["javascript"]["candidates"][0]
    record["source_response_ids"] = ["DEEP-RESP-SHA256-" + "e" * 64]
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="binding"):
        discover_evidence_pack_references(root)


def test_duplicate_json_members_cannot_declare_response_ownership(tmp_path):
    root, _ = metadata_project(tmp_path)
    path = root / "deep_metadata_collection.json"
    text = path.read_text()
    path.write_text(text.replace('"schema_version": 1', '"schema_version": 99, "schema_version": 1'))
    with pytest.raises(ValueError, match="duplicate"):
        discover_evidence_pack_references(root)


def test_valid_response_cannot_be_swapped_onto_unrelated_sitemap_source(tmp_path):
    root, identifier = metadata_project(tmp_path)
    path = root / "deep_metadata_collection.json"
    payload = json.loads(path.read_text())
    # A second valid response at the SAME URL has a distinct body identity.
    from bugslyce.recon.deep_metadata_collection_export import deep_metadata_collection_result_from_dict
    second = replace(deep_metadata_collection_result_from_dict(payload).collected[0], body_sha256="a" * 64)
    second_id = item_response_identity("metadata", second)
    second_payload = dict(payload["collected"][0], body_sha256="a" * 64, evidence_ids=[second_id])
    payload["collected"].append(second_payload)
    payload["total_collected"] = payload["total_considered"] = 2
    path.write_text(json.dumps(payload))
    assert discover_evidence_pack_references(root)
    model_path = root / "application_service_model.json"
    model = json.loads(model_path.read_text())
    support = model["application_composition"]["relations"][0]["supports"][0]
    assert support["evidence_ids"] == [identifier]
    support["evidence_ids"] = [second_id]
    model_path.write_text(json.dumps(model))
    with pytest.raises(ValueError, match="correspondence"):
        discover_evidence_pack_references(root)


def test_duplicate_identical_observation_in_one_artifact_is_one_owner(tmp_path):
    root, identifier = metadata_project(tmp_path)
    path = root / "deep_metadata_collection.json"
    payload = json.loads(path.read_text())
    payload["collected"].append(dict(payload["collected"][0]))
    payload["total_collected"] = payload["total_considered"] = 2
    path.write_text(json.dumps(payload))
    refs = discover_evidence_pack_references(root)
    owners = [ref for ref in refs if ref.owner_kind == "deep_response" and ref.owner_id == identifier]
    assert len(owners) == 1


def test_real_deep_step_collects_persists_composes_and_exports_all_three_owners(tmp_path, monkeypatch):
    import bugslyce.project_pipeline as pipeline
    from bugslyce.recon.deep_collection_policy import DeepCollectionRequest, evaluate_deep_collection_requests
    from bugslyce.recon.deep_collection_request_plan import DeepCollectionRequestPlan
    from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
    from bugslyce.recon.evidence_pack_closure import _load_relationship_project_state

    root = HELPERS["_project"](tmp_path, HELPERS["_model"]())
    requests = tuple(DeepCollectionRequest(
        url="https://example.test" + path, method="GET", source=source,
        reason="bounded synthetic collection", origin="https://example.test",
        path=path, evidence_ids=(), tags=("route",),
    ) for path, source in (("/index", "source_route_coverage"), ("/sitemap.xml", "metadata_coverage")))
    plan = DeepCollectionRequestPlan(
        allowed_origins=("https://example.test",), proposed_requests=requests,
        policy_summary=evaluate_deep_collection_requests(requests, allowed_origins=("https://example.test",)),
        source_counts=(),
    )
    seen = []

    def fetch(request, bounds):
        seen.append(request.url)
        if request.url.endswith("/index"):
            body, media = b'<a href="/account">account</a><script>fetch("/api");</script>', "text/html"
        elif request.url.endswith("/sitemap.xml"):
            body, media = b'<urlset><url><loc>https://example.test/sitemap-route</loc></url></urlset>', "application/xml"
        else:
            body, media = b"bounded response", "text/plain"
        return DeepHTTPResponse(request.url, request.url, 200, (("content-type", media),), body, 0.1)

    monkeypatch.setattr(pipeline, "build_project_state", lambda path: _load_relationship_project_state(root))
    monkeypatch.setattr(pipeline, "build_deep_collection_request_plan_from_project_state", lambda state: plan)
    monkeypatch.setattr(pipeline, "build_deep_http_fetcher", lambda: fetch)
    context = dict(output_dir=root, scope_file=root / "scope.md", target="example.test",
                   project_file=root / "bugslyce_project.json", export_path=tmp_path / "pack.zip",
                   profile=pipeline.DEEP_PIPELINE_PROFILE, resume=False,
                   deep_outputs=pipeline.DeepPipelineOutputs(),
                   plan_dir=root / "plan", plan_path=root / "plan/content_discovery_plan.json")
    _, paths, _ = pipeline._step_runners(context, None)["PIPELINE-STEP-010D"]()
    outputs = context["deep_outputs"]
    assert len(outputs.source_collection.collected) == 1
    assert len(outputs.metadata_collection.collected) == 1
    assert outputs.shallow_followups.collected
    for owner, collection in (("metadata", outputs.metadata_collection), ("source-route", outputs.source_collection), ("shallow-followup", outputs.shallow_followups)):
        for item in collection.collected:
            assert item.evidence_ids.count(item_response_identity(owner, item)) == 1
    assert len(seen) == len(set(seen))
    refs = discover_evidence_pack_references(root)
    assert {ref.portable_path for ref in refs if ref.owner_kind == "deep_response"} == {
        "deep_metadata_collection.json", "deep_source_route_collection.json", "deep_shallow_route_followup_collection.json",
    }
    archive_path = tmp_path / "complete.zip"
    export_recon_evidence_pack(root, archive_path, clock=lambda: HELPERS["_FIXED_TIME"])
    extracted = tmp_path / "complete"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    assert len(paths) == 7


def test_antecedent_only_collection_is_retained_without_declaring_ownership(tmp_path):
    root = HELPERS["_project"](tmp_path, HELPERS["_model"]())
    item = HELPERS["_item"](b"response", url="https://example.test/index", evidence_id="unused")
    identifier = item_response_identity("source-route", item)
    item = replace(item, evidence_ids=(identifier,))
    write_deep_source_route_collection_artifacts(DeepSourceRouteCollectionResult((item,), (), 1, 1, 0), root)
    from bugslyce.recon.deep_metadata_collector import DeepMetadataSkippedItem
    metadata = DeepMetadataCollectionResult((), (
        DeepMetadataSkippedItem("https://example.test/sitemap.xml", "GET", "refused", "metadata_coverage", (identifier,)),
    ), 1, 0, 1)
    write_deep_metadata_collection_artifacts(metadata, root)
    refs = discover_evidence_pack_references(root)
    assert {ref.portable_path for ref in refs if ref.owner_kind == "deep_response"} == {"deep_source_route_collection.json"}
    assert any(ref.portable_path == "deep_metadata_collection.json" for ref in refs)
    path = tmp_path / "pack.zip"
    export_recon_evidence_pack(root, path, clock=lambda: HELPERS["_FIXED_TIME"])
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_pipeline_source_merge_gives_retained_response_its_own_identity(tmp_path):
    from types import SimpleNamespace
    from bugslyce.project_pipeline import _merge_recursive_source_collection

    initial_item = HELPERS["_item"](b"initial", url="https://example.test/index", evidence_id="unused")
    antecedent = item_response_identity("source-route", initial_item)
    initial_item = replace(initial_item, evidence_ids=(antecedent,))
    body = b'<html><h2>API base URL</h2><pre>https://api.example.test/v1</pre></html>'
    accepted = SimpleNamespace(
        request=SimpleNamespace(url="https://example.test/docs"), status_code=200,
        final_url="https://example.test/docs", headers=(("content-type", "text/html"),),
        body_sha256=sha256(body).hexdigest(), body_bytes=len(body), body=body,
        elapsed_seconds=0.1, evidence_ids=(antecedent,),
    )
    collection = _merge_recursive_source_collection(
        DeepSourceRouteCollectionResult((initial_item,), (), 1, 1, 0),
        SimpleNamespace(collected=(accepted,)),
    )
    item = collection.collected[-1]
    assert item.evidence_ids == (antecedent, item_response_identity("source-route", item))
    documentation = build_documentation_assertions(collection)
    assert documentation.assertions
    model = build_application_service_model(
        application_composition=build_application_service_composition(),
        documentation_assertions=documentation,
    )
    root = HELPERS["_project"](tmp_path, model)
    write_deep_source_route_collection_artifacts(collection, root)
    assert discover_evidence_pack_references(root)
    path = tmp_path / "pack.zip"
    export_recon_evidence_pack(root, path, clock=lambda: HELPERS["_FIXED_TIME"])
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
