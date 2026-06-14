"""Tests for local-only BugSlyce evidence pack export."""

from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from bugslyce.cli import main
from bugslyce.recon.export import export_recon_evidence_pack


def test_export_refuses_missing_input_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        export_recon_evidence_pack(tmp_path / "missing", tmp_path / "pack.zip")


def test_export_refuses_missing_manifest(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="Recon manifest does not exist"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_refuses_non_zip_output(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="must end with .zip"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.tar")


def test_export_refuses_overwrite_without_force_and_allows_force(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"existing")

    with pytest.raises(ValueError, match="Re-run with --force"):
        export_recon_evidence_pack(input_dir, output_path)

    result = export_recon_evidence_pack(input_dir, output_path, force=True)

    assert result.output_path == str(output_path.resolve())
    assert zipfile.is_zipfile(output_path)


def test_export_contains_pack_metadata_scope_and_manifest_artifacts(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        readme = archive.read("BUGSLYCE_EXPORT_README.md").decode("utf-8")

    assert {
        "BUGSLYCE_EXPORT_README.md",
        "bugslyce_export_manifest.json",
        "report.md",
        "project_state.json",
        "recon_manifest.json",
        "recon_status.md",
        "recon_status.json",
        "scope.md",
        "metadata/recon_execution.md",
        "metadata/recon_execution.json",
        "metadata/recon_execution_content_run.md",
        "metadata/recon_execution_content_run.json",
        "metadata/content_discovery_execution.md",
        "metadata/content_discovery_execution.json",
        "raw/nmap-allports.txt",
        "raw/nested/homepage-target-80.html",
    }.issubset(names)
    assert result.files_included == export_manifest["files_included"]
    assert export_manifest["target"] == "10.10.10.10"
    assert export_manifest["raw_profile"] == "lab-tcp-full-plus-services"
    assert export_manifest["file_count"] == len(names)
    assert export_manifest["warning"] == "sensitive recon evidence"
    assert export_manifest["no_live_commands_executed"] is True
    assert "may contain sensitive recon evidence" in readme
    assert "No live commands were executed during export." in readme


def test_export_accepts_absolute_manifest_path_inside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(input_dir / "nmap-allports.txt")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        assert "raw/nmap-allports.txt" in archive.namelist()


def test_export_rejects_path_traversal_reference(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = "../outside.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_rejects_absolute_path_outside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(outside)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_records_missing_manifest_artifacts_without_failing(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {"type": "robots", "file": "missing-robots.txt", "url": "http://10.10.10.10/robots.txt"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        assert "raw/missing-robots.txt" not in archive.namelist()
    assert result.missing_files == ["missing-robots.txt"]
    assert export_manifest["missing_files"] == ["missing-robots.txt"]


def test_export_excludes_unrelated_and_cache_files(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / ".git").mkdir()
    (input_dir / ".git" / "config").write_text("private", encoding="utf-8")
    (input_dir / ".venv").mkdir()
    (input_dir / ".venv" / "secret").write_text("private", encoding="utf-8")
    (input_dir / "__pycache__").mkdir()
    (input_dir / "__pycache__" / "cache.pyc").write_bytes(b"cache")
    (input_dir / ".pytest_cache").mkdir()
    (input_dir / ".pytest_cache" / "state").write_text("cache", encoding="utf-8")
    (input_dir / "unrelated.txt").write_text("not evidence", encoding="utf-8")
    output_path = input_dir / "evidence-pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert not any(".git" in name for name in names)
    assert not any(".venv" in name for name in names)
    assert not any("__pycache__" in name for name in names)
    assert not any(".pytest_cache" in name for name in names)
    assert "unrelated.txt" not in names
    assert "evidence-pack.zip" not in names


def test_export_is_deterministic_for_unchanged_input(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    export_recon_evidence_pack(input_dir, first)
    export_recon_evidence_pack(input_dir, second)

    assert first.read_bytes() == second.read_bytes()


def test_cli_export_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "export", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon export" in captured.out
    assert "--input-dir" in captured.out
    assert "--output" in captured.out
    assert "--force" in captured.out


def test_cli_export_succeeds_without_live_activity(tmp_path: Path, capsys) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    exit_code = main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_path.is_file()
    assert "BugSlyce evidence pack export complete" in captured.out
    assert "No live commands were executed." in captured.out
    assert "No network requests were made." in captured.out


def test_export_module_has_no_command_or_network_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "export.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def _export_input(tmp_path: Path) -> Path:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    (input_dir / "nested").mkdir()
    files = {
        "report.md": "# BugSlyce Recon Pack\n",
        "project_state.json": '{"project_state": {}, "candidates": []}\n',
        "recon_status.md": "# BugSlyce Recon Status\n",
        "recon_status.json": '{"target": "10.10.10.10"}\n',
        "recon_execution.md": "# Latest execution\n",
        "recon_execution.json": '{"mode": "content-run"}\n',
        "recon_execution_content_run.md": "# Content discovery\n",
        "recon_execution_content_run.json": '{"mode": "content-run"}\n',
        "content_discovery_execution.md": "# Content discovery\n",
        "content_discovery_execution.json": '{"mode": "content-run"}\n',
        "scope.md": "## In Scope\n\n- 10.10.10.10\n",
        "nmap-allports.txt": "80/tcp open http\n",
        "nested/homepage-target-80.html": "<title>Home</title>\n",
    }
    for name, content in files.items():
        (input_dir / name).write_text(content, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "scope_file": "scope.md",
        "profile": "lab-tcp-full-plus-services",
        "artifacts": [
            {"type": "nmap", "file": "nmap-allports.txt"},
            {
                "type": "html",
                "file": "nested/homepage-target-80.html",
                "url": "http://10.10.10.10/",
            },
        ],
    }
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return input_dir
