"""Tests for read-only local project inventory."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.cli import main
from bugslyce.project_session import (
    PROJECT_FILENAME,
    list_projects,
    render_project_inventory,
    scaffold_project,
)


def test_project_list_refuses_missing_or_file_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        list_projects(tmp_path / "missing")

    file_path = tmp_path / "projects"
    file_path.write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        list_projects(file_path)


def test_project_list_zero_projects_is_clean_and_suggests_scaffold(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()

    rendered = render_project_inventory(list_projects(projects_dir))

    assert "Projects found: 0" in rendered
    assert "No BugSlyce project files were found." in rendered
    assert "bugslyce project scaffold --name NAME --target TARGET" in rendered
    assert "No commands were executed." in rendered
    assert "No network requests were made." in rendered


def test_project_list_finds_sorts_and_summarises_projects(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"
    beta = scaffold_project("beta", "beta.example.test", projects_dir)
    alpha = scaffold_project("alpha", "10.10.10.10", projects_dir)
    (Path(beta.project.output_dir) / "recon_manifest.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    result = list_projects(projects_dir)
    rendered = render_project_inventory(result)

    assert [entry.name for entry in result.entries] == ["alpha", "beta"]
    assert result.entries[0].target == "10.10.10.10"
    assert result.entries[0].recon_pack_exists is False
    assert result.entries[1].target == "beta.example.test"
    assert result.entries[1].recon_pack_exists is True
    assert result.entries[0].created_at is not None
    assert str(Path(alpha.project_file).resolve()) in rendered
    assert "Projects found: 2" in rendered
    assert "alpha" in rendered
    assert "beta" in rendered
    assert "yes" in rendered
    assert "no" in rendered


def test_project_list_handles_missing_created_at(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"
    result = scaffold_project("legacy", "10.10.10.10", projects_dir)
    project_file = Path(result.project_file)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload.pop("created_at")
    project_file.write_text(json.dumps(payload), encoding="utf-8")

    inventory = list_projects(projects_dir)
    rendered = render_project_inventory(inventory)

    assert inventory.entries[0].created_at is None
    assert "not recorded" in rendered


def test_malformed_project_is_reported_without_hiding_valid_projects(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    scaffold_project("valid", "10.10.10.10", projects_dir)
    invalid_dir = projects_dir / "broken"
    invalid_dir.mkdir()
    invalid_file = invalid_dir / PROJECT_FILENAME
    invalid_file.write_text("{bad", encoding="utf-8")

    result = list_projects(projects_dir)
    rendered = render_project_inventory(result)

    assert [entry.name for entry in result.entries] == ["broken", "valid"]
    assert result.entries[0].error is not None
    assert "Projects found: 2" in rendered
    assert "Invalid project file" in rendered
    assert str(invalid_file.resolve()) in rendered
    assert "valid" in rendered


def test_project_list_checks_only_immediate_child_directories(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    nested_parent = projects_dir / "group"
    scaffold_project("nested", "10.10.10.10", nested_parent)

    result = list_projects(projects_dir)

    assert result.entries == []


def test_cli_project_list_is_read_only_and_does_not_call_subprocess(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    projects_dir = tmp_path / "projects"
    scaffold_project("local", "10.10.10.10", projects_dir)
    before = _snapshot(projects_dir)

    def fail_subprocess(*args, **kwargs):
        raise AssertionError("project list must not call subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    exit_code = main(
        ["project", "list", "--projects-dir", str(projects_dir)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce projects" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert _snapshot(projects_dir) == before


def test_project_list_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "list", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce project list" in captured.out
    assert "--projects-dir" in captured.out


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
