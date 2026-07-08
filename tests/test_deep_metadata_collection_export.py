"""Tests for explicit Deep metadata collection artefact export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
    DEEP_METADATA_COLLECTION_MARKDOWN,
    deep_metadata_collection_result_from_dict,
    deep_metadata_collection_result_to_dict,
    load_deep_metadata_collection_result,
    write_deep_metadata_collection_artifacts,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
    DeepMetadataSkippedItem,
)


def test_result_to_dict_includes_expected_keys_without_full_body() -> None:
    result = _result()

    payload = deep_metadata_collection_result_to_dict(result)

    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "bugslyce.deep_metadata_collection"
    assert payload["total_considered"] == 2
    assert payload["total_collected"] == 1
    assert payload["total_skipped"] == 1
    assert payload["safety_notes"]
    assert payload["collected"] == [
        {
            "url": "http://example.test/robots.txt",
            "method": "GET",
            "status_code": 200,
            "final_url": "http://example.test/robots.txt",
            "headers": [["content-type", "text/plain"]],
            "body_preview": "preview only",
            "body_sha256": "abc123",
            "body_bytes": 2048,
            "elapsed_seconds": 0.12,
            "source": "metadata_coverage",
            "reason": "planned_uncollected_metadata",
            "evidence_ids": ["EVID-1", "EVID-2"],
        }
    ]
    assert payload["skipped"] == [
        {
            "url": "http://example.test/login.php",
            "method": "GET",
            "reason": "non_metadata_request",
            "source": "source_route_coverage",
            "evidence_ids": ["EVID-ROUTE"],
        }
    ]
    assert not _contains_key(payload, "body")
    assert "full response body" not in json.dumps(payload, sort_keys=True)


def test_write_artifacts_writes_only_expected_files_with_stable_json(
    tmp_path: Path,
) -> None:
    result = _result()
    before = sorted(path.name for path in tmp_path.iterdir())

    markdown_path, json_path = write_deep_metadata_collection_artifacts(result, tmp_path)

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == []
    assert after == [
        DEEP_METADATA_COLLECTION_JSON,
        DEEP_METADATA_COLLECTION_MARKDOWN,
    ]
    assert markdown_path == tmp_path / DEEP_METADATA_COLLECTION_MARKDOWN
    assert json_path == tmp_path / DEEP_METADATA_COLLECTION_JSON
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown.startswith("## Deep Metadata Collection Result")
    assert markdown.endswith("\n")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload == deep_metadata_collection_result_to_dict(result)
    assert not _contains_key(payload, "body")
    assert not (tmp_path / "deep_metadata_collection").exists()
    assert not (tmp_path / "deep").exists()


def test_write_artifacts_rejects_missing_or_file_output_dir(tmp_path: Path) -> None:
    result = _result()
    missing = tmp_path / "missing"
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("existing", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="output directory does not exist"):
        write_deep_metadata_collection_artifacts(result, missing)
    with pytest.raises(NotADirectoryError, match="output path is not a directory"):
        write_deep_metadata_collection_artifacts(result, output_file)

    assert not missing.exists()
    assert output_file.read_text(encoding="utf-8") == "existing"
    assert not (tmp_path / DEEP_METADATA_COLLECTION_MARKDOWN).exists()
    assert not (tmp_path / DEEP_METADATA_COLLECTION_JSON).exists()


def test_result_round_trips_from_dict_and_loader(tmp_path: Path) -> None:
    result = _result()
    payload = deep_metadata_collection_result_to_dict(result)
    path = tmp_path / DEEP_METADATA_COLLECTION_JSON
    path.write_text(json.dumps(payload), encoding="utf-8")

    rebuilt = deep_metadata_collection_result_from_dict(payload)
    loaded = load_deep_metadata_collection_result(path)

    for candidate in (rebuilt, loaded):
        assert candidate.total_considered == result.total_considered
        assert candidate.total_collected == result.total_collected
        assert candidate.total_skipped == result.total_skipped
        assert candidate.collected[0].headers == (("content-type", "text/plain"),)
        assert candidate.collected[0].evidence_ids == ("EVID-1", "EVID-2")
        assert candidate.skipped[0].evidence_ids == ("EVID-ROUTE",)
        assert not hasattr(candidate.collected[0], "body")


def test_result_from_dict_rejects_missing_or_unsupported_schema() -> None:
    payload = deep_metadata_collection_result_to_dict(_result())
    missing = dict(payload)
    missing.pop("schema_version")
    unsupported = dict(payload)
    unsupported["schema_version"] = 2
    boolean_schema = dict(payload)
    boolean_schema["schema_version"] = True

    with pytest.raises(ValueError, match="schema_version"):
        deep_metadata_collection_result_from_dict(missing)
    with pytest.raises(ValueError, match="schema_version"):
        deep_metadata_collection_result_from_dict(unsupported)
    with pytest.raises(ValueError, match="schema_version"):
        deep_metadata_collection_result_from_dict(boolean_schema)


def test_result_from_dict_rejects_boolean_numeric_fields() -> None:
    boolean_total = deep_metadata_collection_result_to_dict(_result())
    boolean_total["total_collected"] = True
    boolean_elapsed = deep_metadata_collection_result_to_dict(_result())
    boolean_elapsed["collected"][0]["elapsed_seconds"] = False

    with pytest.raises(ValueError, match="total_collected.*integer"):
        deep_metadata_collection_result_from_dict(boolean_total)
    with pytest.raises(ValueError, match="elapsed_seconds.*number"):
        deep_metadata_collection_result_from_dict(boolean_elapsed)


def test_result_from_dict_rejects_malformed_collected_and_skipped() -> None:
    payload = deep_metadata_collection_result_to_dict(_result())
    malformed_collected = dict(payload)
    malformed_collected["collected"] = ["not-an-object"]
    malformed_skipped = dict(payload)
    malformed_skipped["skipped"] = [{"url": "http://example.test/"}]
    with_body = deep_metadata_collection_result_to_dict(_result())
    with_body["collected"][0]["body"] = "full response body"

    with pytest.raises(ValueError, match="collected item"):
        deep_metadata_collection_result_from_dict(malformed_collected)
    with pytest.raises(ValueError, match="method"):
        deep_metadata_collection_result_from_dict(malformed_skipped)
    with pytest.raises(ValueError, match="full body"):
        deep_metadata_collection_result_from_dict(with_body)


def _result() -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=(
            DeepMetadataCollectedItem(
                url="http://example.test/robots.txt",
                method="GET",
                status_code=200,
                final_url="http://example.test/robots.txt",
                headers=(("content-type", "text/plain"),),
                body_preview="preview only",
                body_sha256="abc123",
                body_bytes=2048,
                elapsed_seconds=0.12,
                source="metadata_coverage",
                reason="planned_uncollected_metadata",
                evidence_ids=("EVID-1", "EVID-2"),
            ),
        ),
        skipped=(
            DeepMetadataSkippedItem(
                url="http://example.test/login.php",
                method="GET",
                reason="non_metadata_request",
                source="source_route_coverage",
                evidence_ids=("EVID-ROUTE",),
            ),
        ),
        total_considered=2,
        total_collected=1,
        total_skipped=1,
    )


def _contains_key(value, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False
