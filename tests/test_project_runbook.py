"""Tests for generated local project runbooks."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess

import pytest

from bugslyce.cli import main
from bugslyce.project_session import (
    PROJECT_RUNBOOK_FILENAME,
    build_project_runbook,
    scaffold_project,
    write_project_runbook,
)


FIXED_TIME = datetime(2026, 6, 15, 9, 30, 0, tzinfo=timezone.utc)


def test_runbook_writes_inside_project_with_no_recon_next_step(
    tmp_path: Path,
) -> None:
    scaffold = scaffold_project(
        "runbook-test",
        "10.10.10.10",
        tmp_path / "projects",
    )
    project_file = Path(scaffold.project_file)
    scope_file = Path(scaffold.scope_file)
    scope_before = scope_file.read_bytes()

    result = build_project_runbook(project_file, clock=lambda: FIXED_TIME)
    runbook_path = write_project_runbook(result)
    content = runbook_path.read_text(encoding="utf-8")

    assert runbook_path == Path(scaffold.project.output_dir) / PROJECT_RUNBOOK_FILENAME
    assert "# BugSlyce Project Runbook" in content
    assert "Generated at: `2026-06-15T09:30:00Z`" in content
    assert "* Name: runbook-test" in content
    assert "* Target: 10.10.10.10" in content
    assert f"* Scope file: `{scope_file.resolve()}`" in content
    assert "This runbook does not grant authorisation." in content
    assert "* Recon pack exists: false" in content
    assert "Start with scoped full TCP discovery." in content
    assert "recon nmap-discover" in content
    assert "--confirm" in content
    assert "No commands were executed during runbook generation." in content
    assert "No network requests were made." in content
    assert scope_file.read_bytes() == scope_before


def test_runbook_regeneration_is_deterministic_with_fixed_clock(
    tmp_path: Path,
) -> None:
    scaffold = scaffold_project("repeat", "10.10.10.10", tmp_path / "projects")
    project_file = Path(scaffold.project_file)

    first = build_project_runbook(project_file, clock=lambda: FIXED_TIME)
    write_project_runbook(first)
    first_content = Path(first.runbook_path).read_text(encoding="utf-8")

    second = build_project_runbook(project_file, clock=lambda: FIXED_TIME)
    write_project_runbook(second)

    assert second.content == first_content
    assert Path(second.runbook_path).read_text(encoding="utf-8") == first_content


def test_completed_project_runbook_includes_manual_review_and_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scaffold = scaffold_project("complete", "10.10.10.10", tmp_path / "projects")
    project_file = Path(scaffold.project_file)

    from bugslyce import project_session

    original = project_session.build_project_next(project_file)
    manual = project_session.GuidedProjectAction(
        id="manual-review",
        title="Review the Operator Summary and raw evidence manually.",
        command_preview=f"less {scaffold.project.output_dir}/report.md",
    )
    export = project_session.GuidedProjectAction(
        id="export",
        title="Optionally create a portable evidence pack after review.",
        command_preview=(
            ".venv/bin/bugslyce recon export "
            f"--input-dir {scaffold.project.output_dir} "
            f"--output {scaffold.project.output_dir}-evidence-pack.zip"
        ),
        optional=True,
    )
    monkeypatch.setattr(
        project_session,
        "build_project_next",
        lambda path: project_session.ProjectNextResult(
            project=original.project,
            project_file=original.project_file,
            recon_pack_exists=True,
            status_summary="Detected phases: 14/14.",
            recommended_action=manual,
            optional_actions=[export],
        ),
    )

    result = build_project_runbook(project_file, clock=lambda: FIXED_TIME)

    assert "* Recon pack exists: true" in result.content
    assert "Review the Operator Summary and raw evidence manually." in result.content
    assert "less " in result.content
    assert "recon export" in result.content


@pytest.mark.parametrize("payload", [None, "{bad"])
def test_cli_runbook_refuses_missing_or_malformed_project(
    tmp_path: Path,
    payload: str | None,
    capsys,
) -> None:
    project_file = tmp_path / "bugslyce_project.json"
    if payload is not None:
        project_file.write_text(payload, encoding="utf-8")

    exit_code = main(["project", "runbook", "--project", str(project_file)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Error:" in captured.err
    assert "No commands were executed." in captured.err
    assert not (tmp_path / PROJECT_RUNBOOK_FILENAME).exists()


def test_cli_runbook_only_writes_runbook_and_does_not_call_subprocess(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scaffold = scaffold_project("cli-runbook", "10.10.10.10", tmp_path / "projects")
    project_dir = Path(scaffold.project.output_dir)
    before = _snapshot(project_dir)

    def fail_subprocess(*args, **kwargs):
        raise AssertionError("project runbook must not call subprocess")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    exit_code = main(
        ["project", "runbook", "--project", scaffold.project_file]
    )
    captured = capsys.readouterr()
    after = _snapshot(project_dir)

    assert exit_code == 0
    assert "BugSlyce project runbook written" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert set(after) == set(before) | {PROJECT_RUNBOOK_FILENAME}
    for path, content in before.items():
        assert after[path] == content


def test_runbook_refuses_symlink_path_outside_project(tmp_path: Path) -> None:
    scaffold = scaffold_project("symlink", "10.10.10.10", tmp_path / "projects")
    project_dir = Path(scaffold.project.output_dir)
    outside = tmp_path / "outside.md"
    outside.write_text("keep\n", encoding="utf-8")
    (project_dir / PROJECT_RUNBOOK_FILENAME).symlink_to(outside)

    with pytest.raises(ValueError, match="inside the project output directory"):
        build_project_runbook(Path(scaffold.project_file))

    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_project_runbook_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "runbook", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce project runbook" in captured.out
    assert "--project" in captured.out


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
