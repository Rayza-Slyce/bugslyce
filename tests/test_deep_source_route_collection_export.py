"""Tests for explicit Deep source/route collection artefact export."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    deep_source_route_collection_result_from_dict,
    deep_source_route_collection_result_to_dict,
    load_deep_source_route_collection_result,
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


def test_machine_readable_collection_retains_complete_set_cookie_header() -> None:
    result = _result()
    cookie_value = "session_id=target-secret; Path=/; HttpOnly"
    result = replace(
        result,
        collected=(
            replace(
                result.collected[0],
                headers=(("Set-Cookie", cookie_value),),
            ),
        ),
    )

    payload = deep_source_route_collection_result_to_dict(result)

    assert payload["collected"][0]["headers"] == [["Set-Cookie", cookie_value]]


def test_result_from_dict_round_trips_exported_payload(tmp_path: Path) -> None:
    result = _result()
    payload = deep_source_route_collection_result_to_dict(result)
    path = tmp_path / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    path.write_text(json.dumps(payload), encoding="utf-8")

    rebuilt = deep_source_route_collection_result_from_dict(payload)
    loaded = load_deep_source_route_collection_result(path)

    assert rebuilt == result
    assert loaded == result
    assert rebuilt.collected[0].headers == (("content-type", "text/html"),)
    assert rebuilt.collected[0].evidence_ids == ("EVID-1", "EVID-2")
    assert rebuilt.skipped[0].evidence_ids == ("EVID-META",)


def test_result_from_dict_rejects_bad_schema_generated_by_and_body() -> None:
    payload = deep_source_route_collection_result_to_dict(_result())

    bad_schema = dict(payload)
    bad_schema["schema_version"] = True
    with pytest.raises(ValueError, match="schema_version"):
        deep_source_route_collection_result_from_dict(bad_schema)

    bad_generated_by = dict(payload)
    bad_generated_by["generated_by"] = "bugslyce.other"
    with pytest.raises(ValueError, match="generated_by"):
        deep_source_route_collection_result_from_dict(bad_generated_by)

    with_body = deep_source_route_collection_result_to_dict(_result())
    with_body["collected"][0]["body"] = "full response body"
    with pytest.raises(ValueError, match="full body"):
        deep_source_route_collection_result_from_dict(with_body)


def test_result_from_dict_rejects_malformed_structures() -> None:
    payload = deep_source_route_collection_result_to_dict(_result())

    missing_list = dict(payload)
    missing_list["collected"] = {}
    with pytest.raises(ValueError, match="collected"):
        deep_source_route_collection_result_from_dict(missing_list)

    bad_headers = deep_source_route_collection_result_to_dict(_result())
    bad_headers["collected"][0]["headers"] = [["content-type"]]
    with pytest.raises(ValueError, match="headers"):
        deep_source_route_collection_result_from_dict(bad_headers)

    bad_elapsed = deep_source_route_collection_result_to_dict(_result())
    bad_elapsed["collected"][0]["elapsed_seconds"] = False
    with pytest.raises(ValueError, match="elapsed_seconds"):
        deep_source_route_collection_result_from_dict(bad_elapsed)


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


def test_export_omits_in_memory_full_body_and_loader_rebuilds_empty_body(
    tmp_path: Path,
) -> None:
    secret = "FULL_BODY_EXPORT_SECRET_NOT_ALLOWED"
    result = _result(body=f"<html>{secret}</html>".encode())

    payload = deep_source_route_collection_result_to_dict(result)
    markdown_path, json_path = write_deep_source_route_collection_artifacts(
        result,
        tmp_path,
    )
    json_text = json_path.read_text(encoding="utf-8")
    markdown_text = markdown_path.read_text(encoding="utf-8")
    loaded = load_deep_source_route_collection_result(json_path)

    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "bugslyce.deep_source_route_collection"
    assert not _contains_key(payload, "body")
    assert secret not in repr(payload)
    assert '"body"' not in json_text
    assert secret not in json_text
    assert secret not in markdown_text
    assert loaded.collected[0].body == b""

    with_body = deep_source_route_collection_result_to_dict(result)
    with_body["collected"][0]["body"] = secret
    with pytest.raises(ValueError, match="full body"):
        deep_source_route_collection_result_from_dict(with_body)


def test_retained_bounded_preview_is_not_silently_redacted() -> None:
    secret_line = "session_token = retained-target-secret-38172"
    result = _result(body=(secret_line + "\n").encode())
    result = replace(
        result,
        collected=(replace(result.collected[0], body_preview=secret_line),),
    )

    payload = deep_source_route_collection_result_to_dict(result)

    assert payload["collected"][0]["body_preview"] == secret_line
    assert "body" not in payload["collected"][0]


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


def _result(body: bytes = b"") -> DeepSourceRouteCollectionResult:
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
                body=body,
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
