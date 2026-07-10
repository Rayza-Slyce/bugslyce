"""Tests for explicit Deep source/route collection artefact export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    deep_source_route_collection_result_to_dict,
    write_deep_source_route_collection_artifacts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)


def test_result_to_dict_includes_expected_keys_without_full_body() -> None:
    result = _result()

    payload = deep_source_route_collection_result_to_dict(result)

    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "bugslyce.deep_source_route_collection"
    assert payload["total_considered"] == 2
    assert payload["total_collected"] == 1
    assert payload["total_skipped"] == 1
    assert payload["safety_notes"]
    assert payload["collected"] == [
        {
            "url": "http://example.test/login.php",
            "method": "GET",
            "status_code": 200,
            "final_url": "http://example.test/login.php",
            "headers": [["content-type", "text/html"]],
            "body_preview": "preview only",
            "body_sha256": "abc123",
            "body_bytes": 2048,
            "elapsed_seconds": 0.12,
            "source": "source_route_coverage",
            "reason": "discovered_unfetched_auth_route",
            "evidence_ids": ["EVID-1", "EVID-2"],
        }
    ]
    assert payload["skipped"] == [
        {
            "url": "http://example.test/robots.txt",
            "method": "GET",
            "reason": "metadata_request",
            "source": "metadata_coverage",
            "evidence_ids": ["EVID-META"],
        }
    ]
    assert not _contains_key(payload, "body")
    assert "full response body" not in json.dumps(payload, sort_keys=True)


def test_write_artifacts_writes_only_expected_files_with_stable_json(
    tmp_path: Path,
) -> None:
    result = _result()
    before = sorted(path.name for path in tmp_path.iterdir())

    markdown_path, json_path = write_deep_source_route_collection_artifacts(
        result,
        tmp_path,
    )

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == []
    assert after == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON,
        DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    ]
    assert markdown_path == tmp_path / DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN
    assert json_path == tmp_path / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown.startswith("## Deep Source/Route Collection Result")
    assert markdown.endswith("\n")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload == deep_source_route_collection_result_to_dict(result)
    assert not _contains_key(payload, "body")
    assert not (tmp_path / "deep_source_route_collection").exists()
    assert not (tmp_path / "deep").exists()


def test_write_artifacts_rejects_missing_or_file_output_dir(tmp_path: Path) -> None:
    result = _result()
    missing = tmp_path / "missing"
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("existing", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="output directory does not exist"):
        write_deep_source_route_collection_artifacts(result, missing)
    with pytest.raises(NotADirectoryError, match="output path is not a directory"):
        write_deep_source_route_collection_artifacts(result, output_file)

    assert not missing.exists()
    assert output_file.read_text(encoding="utf-8") == "existing"
    assert not (tmp_path / DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN).exists()
    assert not (tmp_path / DEEP_SOURCE_ROUTE_COLLECTION_JSON).exists()


def _result() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(
            DeepSourceRouteCollectedItem(
                url="http://example.test/login.php",
                method="GET",
                status_code=200,
                final_url="http://example.test/login.php",
                headers=(("content-type", "text/html"),),
                body_preview="preview only",
                body_sha256="abc123",
                body_bytes=2048,
                elapsed_seconds=0.12,
                source="source_route_coverage",
                reason="discovered_unfetched_auth_route",
                evidence_ids=("EVID-1", "EVID-2"),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="http://example.test/robots.txt",
                method="GET",
                reason="metadata_request",
                source="metadata_coverage",
                evidence_ids=("EVID-META",),
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
