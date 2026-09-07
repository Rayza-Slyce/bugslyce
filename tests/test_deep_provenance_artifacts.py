"""Persistence of bounded response facts and extraction observations."""
from dataclasses import replace
import json
from pathlib import Path
import runpy

import pytest

from bugslyce.recon.deep_provenance_artifacts import (
    SHALLOW_JSON, EXTRACTION_JSON, shallow_collection_to_dict,
    shallow_collection_from_dict, extraction_to_dict, extraction_from_dict,
    write_deep_provenance_artifacts, owned_responses,
)
from bugslyce.recon.deep_shallow_route_followup import (
    build_deep_shallow_route_followup_plan, collect_deep_shallow_route_followups,
)
from bugslyce.recon.deep_collection_provenance import item_response_identity
from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_to_dict, deep_source_route_collection_result_from_dict,
)
from bugslyce.recon.deep_metadata_collection_export import (
    deep_metadata_collection_result_to_dict, deep_metadata_collection_result_from_dict,
)

FIXTURE = runpy.run_path(str(Path(__file__).with_name("test_deep_fresh_response_provenance.py")))
METADATA = runpy.run_path(str(Path(__file__).with_name("test_deep_metadata_collector.py")))


def shallow_result():
    html = FIXTURE["_html_result_with_evidence"](())
    js = FIXTURE["_empty_javascript_result"]()
    plan = build_deep_shallow_route_followup_plan(html, js)
    return collect_deep_shallow_route_followups(
        plan, fetcher=lambda request, bounds: FIXTURE["_response"](request.url),
    ), html, js


def test_shallow_fresh_identity_and_bounded_summary_round_trip(tmp_path):
    result, html, js = shallow_result()
    paths = write_deep_provenance_artifacts(tmp_path, result, html, js)
    assert tuple(path.name for path in paths) == (SHALLOW_JSON, EXTRACTION_JSON)
    payload = json.loads(paths[0].read_text())
    assert "body" not in payload["result"]["collected"][0]
    loaded = shallow_collection_from_dict(payload)
    assert loaded == replace(result, collected=tuple(replace(item, body=b"") for item in result.collected))
    assert item_response_identity("shallow-followup", loaded.collected[0]) == result.collected[0].evidence_ids[-1]
    assert extraction_from_dict(json.loads(paths[1].read_text())) == (html, js)


@pytest.mark.parametrize("owner", ["metadata", "source-route"])
def test_fresh_and_historical_collection_evidence_round_trip_without_minting(owner):
    if owner == "source-route":
        request = FIXTURE["_source_route_request"](evidence_ids=())
        result = FIXTURE["collect_deep_source_routes_from_plan"](
            FIXTURE["_source_route_plan"](request),
            fetcher=lambda request, bounds: FIXTURE["_response"](request.url),
        )
        encode, decode = deep_source_route_collection_result_to_dict, deep_source_route_collection_result_from_dict
    else:
        request = METADATA["_request"]("https://app.example.test/sitemap.xml", source="metadata_coverage", evidence_ids=())
        result = METADATA["collect_deep_metadata_from_plan"](
            METADATA["_plan"]((request,), allowed_origins=("https://app.example.test",)),
            fetcher=METADATA["_fake_fetcher"]([], body=b"empty sitemap"),
        )
        encode, decode = deep_metadata_collection_result_to_dict, deep_metadata_collection_result_from_dict
    payload = encode(result)
    restored = decode(json.loads(json.dumps(payload)))
    assert restored.collected[0].evidence_ids == result.collected[0].evidence_ids
    assert item_response_identity(owner, restored.collected[0]) == result.collected[0].evidence_ids[-1]
    for evidence in ([], ["EVID-ANTECEDENT"]):
        payload["collected"][0]["evidence_ids"] = evidence
        historical = decode(payload)
        assert historical.collected[0].evidence_ids == tuple(evidence)
        assert owned_responses(owner, historical) == {}


@pytest.mark.parametrize("change", ["body", "status", "digest", "counts", "nan", "producer", "extra"])
def test_shallow_malformed_persistence_fails_closed(change):
    result, _, _ = shallow_result()
    payload = shallow_collection_to_dict(result)
    item = payload["result"]["collected"][0]
    if change == "body":
        item["body"] = "must not retain"
    elif change == "status":
        item["status_code"] = True
    elif change == "digest":
        item["body_sha256"] = "bad"
    elif change == "counts":
        payload["result"]["summary_counts"]["responses_collected"] = 99
    elif change == "nan":
        item["elapsed_seconds"] = float("nan")
    elif change == "producer":
        payload["generated_by"] = "other"
    else:
        payload["unknown"] = True
    with pytest.raises(ValueError):
        shallow_collection_from_dict(payload)


def test_shallow_legacy_empty_ids_are_not_upgraded():
    result, _, _ = shallow_result()
    payload = shallow_collection_to_dict(result)
    payload["result"]["collected"][0]["evidence_ids"] = []
    loaded = shallow_collection_from_dict(payload)
    assert loaded.collected[0].evidence_ids == ()
    assert owned_responses("shallow-followup", loaded) == {}


def test_provenance_writer_refuses_symlink_output(tmp_path):
    result, html, js = shallow_result()
    outside = tmp_path / "unrelated.txt"
    outside.write_text("unchanged")
    (tmp_path / SHALLOW_JSON).symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        write_deep_provenance_artifacts(tmp_path, result, html, js)
    assert outside.read_text() == "unchanged"
