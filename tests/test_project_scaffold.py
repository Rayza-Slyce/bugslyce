"""Tests for conservative local project scaffolding."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.cli import main
from bugslyce.project_session import (
    PROJECT_FILENAME,
    SCAFFOLD_SCOPE_FILENAME,
    scaffold_project,
)


def test_scaffold_creates_scope_and_project_files(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"

    result = scaffold_project("scaffold-test", "10.10.10.10", projects_dir)
    project_dir = projects_dir / "scaffold-test"
    scope_file = project_dir / SCAFFOLD_SCOPE_FILENAME
    project_file = project_dir / PROJECT_FILENAME
    scope = scope_file.read_text(encoding="utf-8")
    payload = json.loads(project_file.read_text(encoding="utf-8"))

    assert project_dir.is_dir()
    assert result.project_directory == str(project_dir.resolve())
    assert scope_file.is_file()
    assert project_file.is_file()
    assert "## In Scope\n\n* 10.10.10.10" in scope
    assert "Review and confirm authorisation before running recon." in scope
    assert "* Any other IP or domain" in scope
    assert "* UDP scans" in scope
    assert "* NSE scripts" in scope
    assert "* Brute force" in scope
    assert "* Exploitation" in scope
    assert "* Recursive discovery unless explicitly authorised" in scope
    assert payload["name"] == "scaffold-test"
    assert payload["target"] == "10.10.10.10"
    assert payload["scope_file"] == str(scope_file.resolve())
    assert payload["output_dir"] == str(project_dir.resolve())
    assert payload["created_by"] == "bugslyce"
    assert payload["default_profiles"]["content_discovery_smoke"] == "lab-root-tiny"
    assert payload["notes"] == []


@pytest.mark.parametrize("name", ["../escape", "bad/name", "bad name", "", "."])
def test_scaffold_rejects_unsafe_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="Project name"):
        scaffold_project(name, "10.10.10.10", tmp_path / "projects")


@pytest.mark.parametrize("target", ["not a host", "http://example.com", "10.0.0.0/24"])
def test_scaffold_rejects_invalid_single_target(tmp_path: Path, target: str) -> None:
    with pytest.raises(ValueError, match="plain IP address or hostname"):
        scaffold_project("test", target, tmp_path / "projects")


def test_scaffold_refuses_existing_nonempty_directory_without_force(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    scaffold_project("test", "10.10.10.10", projects_dir)

    with pytest.raises(ValueError, match="not empty"):
        scaffold_project("test", "10.10.10.10", projects_dir)


def test_scaffold_force_replaces_only_owned_files(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"
    scaffold_project("test", "10.10.10.10", projects_dir)
    project_dir = projects_dir / "test"
    scope_file = project_dir / SCAFFOLD_SCOPE_FILENAME
    scope_file.write_text("old scope\n", encoding="utf-8")

    result = scaffold_project(
        "test",
        "app.example.test",
        projects_dir,
        force=True,
    )

    assert result.project.target == "app.example.test"
    assert "* app.example.test" in scope_file.read_text(encoding="utf-8")


def test_scaffold_refuses_recon_or_unrelated_files_even_with_force(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    project_dir = projects_dir / "test"
    project_dir.mkdir(parents=True)
    evidence = project_dir / "recon_manifest.json"
    evidence.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="will not be modified"):
        scaffold_project("test", "10.10.10.10", projects_dir, force=True)

    assert evidence.read_text(encoding="utf-8") == "{}\n"
    assert not (project_dir / SCAFFOLD_SCOPE_FILENAME).exists()
    assert not (project_dir / PROJECT_FILENAME).exists()


def test_cli_scaffold_prints_safe_summary_and_next_preview(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    def fail_subprocess(*args, **kwargs):
        raise AssertionError("project scaffold must not call subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    projects_dir = tmp_path / "projects"

    exit_code = main(
        [
            "project",
            "scaffold",
            "--name",
            "cli-scaffold",
            "--target",
            "10.10.10.10",
            "--projects-dir",
            str(projects_dir),
        ]
    )
    captured = capsys.readouterr()
    project_file = projects_dir / "cli-scaffold" / PROJECT_FILENAME

    assert exit_code == 0
    assert "BugSlyce project scaffold created" in captured.out
    assert "Review scope.md before running recon." in captured.out
    assert "Suggested command preview:" in captured.out
    assert f"bugslyce project next --project {project_file.resolve()}" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out


def test_project_scaffold_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "scaffold", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce project scaffold" in captured.out
    assert "--name" in captured.out
    assert "--target" in captured.out
    assert "--projects-dir" in captured.out
    assert "--force" in captured.out
