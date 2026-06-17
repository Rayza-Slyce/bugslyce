"""Tests for recon manifest parsing and context precedence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.core.project import build_project_state
from bugslyce.parsers.manifest import parse_recon_manifest


def test_manifest_parser_loads_valid_manifest(tmp_path: Path) -> None:
    (tmp_path / "scan.txt").write_text("PORT STATE SERVICE\n8080/tcp open http\n", encoding="utf-8")
    manifest_path = _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "192.0.2.10",
            "created_by": "manual",
            "profile": "manual-import",
            "artifacts": [
                {
                    "type": "nmap",
                    "file": "scan.txt",
                    "host": "192.0.2.10",
                    "description": "Saved service output",
                    "tags": ["lab"],
                }
            ],
        },
    )

    manifest = parse_recon_manifest(manifest_path, tmp_path)

    assert manifest is not None
    assert manifest.schema_version == "1.0"
    assert manifest.target == "192.0.2.10"
    assert manifest.artifacts[0].description == "Saved service output"
    assert manifest.artifacts[0].tags == ["lab"]


def test_missing_manifest_is_not_an_error(tmp_path: Path) -> None:
    assert parse_recon_manifest(tmp_path / "recon_manifest.json", tmp_path) is None


def test_malformed_manifest_warns_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "recon_manifest.json"
    path.write_text("{bad json", encoding="utf-8")

    with pytest.warns(RuntimeWarning, match="Could not parse recon manifest"):
        assert parse_recon_manifest(path, tmp_path) is None


def test_project_state_records_malformed_manifest_warning(tmp_path: Path) -> None:
    (tmp_path / "recon_manifest.json").write_text("{bad json", encoding="utf-8")
    (tmp_path / "scope.md").write_text("# Scope\n\n## In Scope\n- 192.0.2.10\n", encoding="utf-8")

    state = build_project_state(tmp_path)

    assert state.recon_manifest is None
    assert any("Could not parse recon manifest" in warning for warning in state.warnings)
    assert any("subdomains.txt" in warning for warning in state.warnings)


def test_manifest_skips_unsafe_unknown_and_missing_artifacts(tmp_path: Path) -> None:
    path = _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "192.0.2.10",
            "artifacts": [
                {"type": "html", "file": "../../secret.html"},
                {"type": "future_scanner", "file": "future.txt"},
                {"type": "robots", "file": "missing.txt"},
            ],
        },
    )

    with pytest.warns(RuntimeWarning) as captured:
        manifest = parse_recon_manifest(path, tmp_path)

    messages = [str(item.message) for item in captured]
    assert manifest is not None
    assert manifest.artifacts == []
    assert any("unsafe manifest artefact path" in message for message in messages)
    assert any("unsupported manifest artefact type" in message for message in messages)
    assert any("missing manifest artefact file" in message for message in messages)


def test_manifest_led_project_suppresses_missing_legacy_input_warnings(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text("# Scope\n\n- 127.0.0.1\n", encoding="utf-8")
    (tmp_path / "curl-headers-127.0.0.1-8765.txt").write_text(
        "HTTP/1.0 200 OK\nServer: Test\nContent-Length: 123\n",
        encoding="utf-8",
    )
    _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "127.0.0.1",
            "scope_file": "scope.md",
            "artifacts": [
                {
                    "type": "http_headers",
                    "file": "curl-headers-127.0.0.1-8765.txt",
                    "url": "http://127.0.0.1:8765/",
                }
            ],
        },
    )

    state = build_project_state(tmp_path)

    assert state.recon_manifest is not None
    assert not any(
        filename in warning
        for warning in state.warnings
        for filename in ("subdomains.txt", "httpx.jsonl", "urls.txt", "notes.md")
    )


def test_valid_manifest_project_keeps_missing_artifact_warning(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text("# Scope\n\n- 127.0.0.1\n", encoding="utf-8")
    _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "127.0.0.1",
            "scope_file": "scope.md",
            "artifacts": [{"type": "http_headers", "file": "missing-headers.txt"}],
        },
    )

    state = build_project_state(tmp_path)

    assert state.recon_manifest is not None
    assert any("missing manifest artefact file" in warning for warning in state.warnings)
    assert not any("subdomains.txt" in warning for warning in state.warnings)


def test_valid_manifest_project_keeps_unknown_artifact_warning(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text("# Scope\n\n- 127.0.0.1\n", encoding="utf-8")
    _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "127.0.0.1",
            "scope_file": "scope.md",
            "artifacts": [{"type": "future_type", "file": "future.txt"}],
        },
    )

    state = build_project_state(tmp_path)

    assert state.recon_manifest is not None
    assert any("unsupported manifest artefact type" in warning for warning in state.warnings)
    assert not any("httpx.jsonl" in warning for warning in state.warnings)


def test_valid_manifest_is_authoritative_over_filename_discovery(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text("# Scope\n\n## In Scope\n- 192.0.2.10\n", encoding="utf-8")
    (tmp_path / "homepage-80.html").write_text("<title>Should be skipped</title>", encoding="utf-8")
    _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "192.0.2.10",
            "artifacts": [{"type": "future_scanner", "file": "homepage-80.html"}],
        },
    )

    state = build_project_state(tmp_path)

    assert state.http_artifacts == []
    assert any("unsupported manifest artefact type" in warning for warning in state.warnings)


def test_manifest_metadata_overrides_filename_hints(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "gobuster-80-root.txt").write_text(
        "admin (Status: 200) [Size: 42]\n",
        encoding="utf-8",
    )
    (tmp_path / "curl-headers-80.txt").write_text(
        "HTTP/1.1 404 Not Found\nServer: Example\nContent-Length: 12\n",
        encoding="utf-8",
    )
    (tmp_path / "homepage-80.html").write_text(
        "<html><head><title>Manifest Context</title></head></html>",
        encoding="utf-8",
    )
    _write_manifest(
        tmp_path,
        {
            "schema_version": "1.0",
            "target": "10.10.10.10",
            "artifacts": [
                {
                    "type": "gobuster",
                    "file": "gobuster-80-root.txt",
                    "base_url": "http://10.10.10.10:8088/",
                },
                {
                    "type": "http_headers",
                    "file": "curl-headers-80.txt",
                    "url": "http://10.10.10.10:9090/manual/",
                },
                {
                    "type": "html",
                    "file": "homepage-80.html",
                    "url": "http://10.10.10.10:7070/app/",
                },
            ],
        },
    )

    state = build_project_state(tmp_path)

    assert any(item.url == "http://10.10.10.10:8088/admin" for item in state.discovered_paths)
    assert any(item.url == "http://10.10.10.10:9090/manual/" for item in state.discovered_paths)
    assert any(
        item.url == "http://10.10.10.10:7070/app/" and item.artifact_type == "page_title"
        for item in state.http_artifacts
    )
    assert not any(item.url.startswith("http://10.10.10.10/admin") for item in state.discovered_paths)


def test_filename_hint_fallback_still_works_without_manifest(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "gobuster-8088-root.txt").write_text(
        "api (Status: 200) [Size: 64]\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert any(item.url == "http://10.10.10.10:8088/api" for item in state.discovered_paths)
    assert state.recon_manifest is None


def _write_manifest(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "recon_manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
