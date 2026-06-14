"""Tests for guided, non-executing project next-step previews."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.cli import main
from bugslyce.project_session import build_project_next, initialize_project


def test_project_next_refuses_missing_project_file(tmp_path: Path, capsys) -> None:
    exit_code = main(
        ["project", "next", "--project", str(tmp_path / "missing.json")]
    )
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Project file does not exist" in captured.err
    assert "No commands were executed." in captured.err


def test_project_next_refuses_malformed_project_file(
    tmp_path: Path,
    capsys,
) -> None:
    project_file = tmp_path / "bugslyce_project.json"
    project_file.write_text("{bad", encoding="utf-8")

    exit_code = main(["project", "next", "--project", str(project_file)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Could not parse project file" in captured.err


def test_project_next_without_recon_pack_suggests_scoped_nmap_discovery(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)

    result = build_project_next(project_file)

    assert result.project.name == "guided-test"
    assert result.project.target == "10.10.10.10"
    assert result.recon_pack_exists is False
    assert result.recommended_action.id == "nmap-discover"
    assert "recon nmap-discover" in result.recommended_action.command_preview
    assert "--profile lab-tcp-full" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview
    assert not Path(f"{output_dir}-content-plan-tiny").exists()


def test_project_next_discovery_only_suggests_nmap_services(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "discovery")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "nmap-services"
    assert "recon nmap-services" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_services_with_http_suggests_http_metadata(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "services")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "http-metadata"
    assert "recon http-metadata" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_metadata_suggests_path_followup(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "metadata")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "path-followup"
    assert "recon path-followup" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_http_evidence_suggests_tiny_content_plan(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "path-followup")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "content-plan-tiny"
    assert "recon content-plan" in result.recommended_action.command_preview
    assert "lab-root-tiny" in result.recommended_action.command_preview
    assert f"{output_dir}-content-plan-tiny" in result.recommended_action.command_preview
    assert "--confirm" not in result.recommended_action.command_preview


def test_project_next_valid_tiny_plan_suggests_content_run(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "path-followup")
    plan_path = _write_content_plan(output_dir, "lab-root-tiny")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "content-run-tiny"
    assert str(plan_path) in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_rejects_untrusted_plan_as_runnable(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "path-followup")
    plan_path = _write_content_plan(output_dir, "lab-root-tiny")
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["created_by"] = "other-tool"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "content-plan-tiny"
    assert "content-run" not in result.recommended_action.command_preview


def test_project_next_gobuster_output_suggests_content_followup(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "gobuster")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "content-followup"
    assert "recon content-followup" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_followed_200_path_suggests_body_fetch(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "content-followup")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "body-fetch"
    assert "recon body-fetch" in result.recommended_action.command_preview
    assert "--confirm" in result.recommended_action.command_preview


def test_project_next_complete_pack_suggests_manual_review_and_export(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "complete")

    result = build_project_next(project_file)

    assert result.recommended_action.id == "manual-review"
    assert f"less {output_dir / 'report.md'}" in result.recommended_action.command_preview
    export = next(action for action in result.optional_actions if action.id == "export")
    assert "recon export" in export.command_preview
    assert f"{output_dir}-evidence-pack.zip" in export.command_preview


def test_project_next_tiny_completion_suggests_optional_light_plan(
    tmp_path: Path,
) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "complete", tiny=True)

    result = build_project_next(project_file)

    light = next(
        action for action in result.optional_actions if action.id == "content-plan-light"
    )
    assert "lab-root-light" in light.command_preview
    assert f"{output_dir}-content-plan-light" in light.command_preview
    assert "--confirm" not in light.command_preview


def test_project_next_cli_prints_guidance_and_safety_lines(
    tmp_path: Path,
    capsys,
) -> None:
    project_file, _output_dir = _project(tmp_path)

    exit_code = main(["project", "next", "--project", str(project_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce guided next step" in captured.out
    assert "Project name: guided-test" in captured.out
    assert "Target: 10.10.10.10" in captured.out
    assert "Suggested command preview:" in captured.out
    assert "Suggested commands are previews only." in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert "by Rayza Slyce" not in captured.out


def test_project_next_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "next", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce project next" in captured.out
    assert "--project" in captured.out


def test_project_next_does_not_mutate_recon_or_create_plan_dirs(tmp_path: Path) -> None:
    project_file, output_dir = _project(tmp_path)
    _write_pack(output_dir, "gobuster")
    before = _snapshot(tmp_path)

    build_project_next(project_file)

    assert _snapshot(tmp_path) == before
    assert not Path(f"{output_dir}-content-plan-tiny").exists()
    assert not Path(f"{output_dir}-content-plan-light").exists()


def test_project_next_module_has_no_execution_or_network_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "project_session.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def _project(tmp_path: Path) -> tuple[Path, Path]:
    scope = tmp_path / "scope.md"
    scope.write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"
    _project, project_file = initialize_project(
        "guided-test",
        "10.10.10.10",
        scope,
        output_dir,
    )
    return project_file, output_dir


def _write_pack(output_dir: Path, stage: str, tiny: bool = False) -> None:
    artifacts: list[dict[str, object]] = []
    _write(
        output_dir / "nmap-allports.txt",
        "Nmap scan report for 10.10.10.10\nPORT STATE SERVICE\n80/tcp open unknown\n",
    )
    artifacts.append({"type": "nmap", "file": "nmap-allports.txt"})
    if stage != "discovery":
        _write(
            output_dir / "nmap-services-all.txt",
            "Nmap scan report for 10.10.10.10\n"
            "PORT STATE SERVICE VERSION\n80/tcp open http nginx 1.24.0\n",
        )
        artifacts.append({"type": "nmap", "file": "nmap-services-all.txt"})
    if stage in {"metadata", "path-followup", "gobuster", "content-followup", "complete"}:
        _write(output_dir / "homepage-80.html", "<title>Home</title>")
        artifacts.append(
            {
                "type": "html",
                "file": "homepage-80.html",
                "url": "http://10.10.10.10/",
            }
        )
    if stage in {"path-followup", "gobuster", "content-followup", "complete"}:
        _write(
            output_dir / "curl-headers-followup-manual.txt",
            "HTTP/1.1 404 Not Found\n",
        )
        artifacts.append(
            {
                "type": "http_headers",
                "file": "curl-headers-followup-manual.txt",
                "url": "http://10.10.10.10/manual",
            }
        )
    if stage in {"gobuster", "content-followup", "complete"}:
        name = (
            "gobuster-tiny-10.10.10.10-80-root.txt"
            if tiny or stage == "complete"
            else "gobuster-10.10.10.10-80-root.txt"
        )
        _write(output_dir / name, "portal (Status: 200) [Size: 123]\n")
        artifacts.append(
            {
                "type": "gobuster",
                "file": name,
                "base_url": "http://10.10.10.10/",
            }
        )
    if stage in {"content-followup", "complete"}:
        name = "curl-headers-content-followup-10.10.10.10-80-portal.txt"
        _write(output_dir / name, "HTTP/1.1 200 OK\nContent-Type: text/html\n")
        artifacts.append(
            {
                "type": "http_headers",
                "file": name,
                "url": "http://10.10.10.10/portal",
            }
        )
    if stage == "complete":
        name = "body-fetch-10.10.10.10-80-portal.html"
        _write(output_dir / name, "<title>Portal</title>")
        artifacts.append(
            {
                "type": "html",
                "file": name,
                "url": "http://10.10.10.10/portal",
            }
        )
        _write(output_dir / "report.md", "# BugSlyce Recon Pack\n")
    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "scope_file": str((output_dir.parent / "scope.md").resolve()),
        "created_by": "test",
        "profile": "lab-tcp-full",
        "artifacts": artifacts,
    }
    _write(output_dir / "recon_manifest.json", json.dumps(manifest))


def _write_content_plan(output_dir: Path, profile: str) -> Path:
    suffix = "tiny" if profile == "lab-root-tiny" else "light"
    plan_dir = Path(f"{output_dir}-content-plan-{suffix}")
    plan_dir.mkdir()
    plan_path = plan_dir / "content_discovery_plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "created_by": "bugslyce-content-planner",
                "target": "10.10.10.10",
                "profile": profile,
                "input_dir": str(output_dir.resolve()),
                "scope_file": str((output_dir.parent / "scope.md").resolve()),
                "output_dir": str(plan_dir.resolve()),
                "origins": ["http://10.10.10.10/"],
                "steps": [{"id": "CONTENT-STEP-001"}],
            }
        ),
        encoding="utf-8",
    )
    return plan_path.resolve()


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
