"""Tests for the dry-run-only recon executor scaffold."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from bugslyce.recon.executor import (
    build_execution_preview,
    load_recon_plan,
    render_execution_preview_markdown,
    write_execution_preview,
)
from bugslyce.recon.planner import build_recon_plan, write_recon_plan


def test_load_valid_recon_plan(tmp_path: Path) -> None:
    plan_path = _write_lab_plan(tmp_path)

    plan = load_recon_plan(plan_path)

    assert plan.target == "10.10.10.10"
    assert plan.profile == "lab-full"
    assert len(plan.steps) == 8


def test_build_execution_preview_counts_only_command_steps(tmp_path: Path) -> None:
    plan_path = _write_lab_plan(tmp_path)
    plan = load_recon_plan(plan_path)

    preview = build_execution_preview(plan, plan_path)

    assert preview.step_count == 8
    assert preview.command_count == 7
    assert preview.steps[0].would_execute is False
    assert all(step.would_execute for step in preview.steps[1:])
    assert preview.no_commands_executed is True
    assert "No commands were executed." in preview.warnings


def test_empty_command_preview_is_not_counted(tmp_path: Path) -> None:
    plan_path = _write_lab_plan(tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["steps"][1]["command_preview"] = "   "
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    preview = build_execution_preview(load_recon_plan(plan_path), plan_path)

    assert preview.command_count == 6
    assert preview.steps[1].command_preview is None
    assert preview.steps[1].would_execute is False


def test_write_execution_preview_creates_valid_json_and_markdown(tmp_path: Path) -> None:
    plan_path = _write_lab_plan(tmp_path)
    preview = build_execution_preview(load_recon_plan(plan_path), plan_path)

    json_path, markdown_path = write_execution_preview(preview, plan_path.parent)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert payload["no_commands_executed"] is True
    assert payload["command_count"] == 7
    assert "No commands were executed." in markdown
    assert render_execution_preview_markdown(preview) == markdown


def test_load_missing_plan_fails_gracefully(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_recon_plan(tmp_path / "missing.json")


def test_load_invalid_json_fails_gracefully(tmp_path: Path) -> None:
    path = tmp_path / "recon_plan.json"
    path.write_text("{bad json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        load_recon_plan(path)


def test_load_non_bugslyce_plan_fails_gracefully(tmp_path: Path) -> None:
    path = tmp_path / "recon_plan.json"
    path.write_text(
        json.dumps(
            {
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-full",
                "output_dir": str(tmp_path),
                "created_by": "other-tool",
                "steps": [{"id": "STEP-001"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not look like a BugSlyce recon plan"):
        load_recon_plan(path)


def test_load_zero_step_plan_fails_gracefully(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    plan = build_recon_plan("10.10.10.10", scope, tmp_path / "output", "lab-full")
    empty_plan = replace(plan, steps=[])
    plan_path, _markdown_path = write_recon_plan(empty_plan)

    with pytest.raises(ValueError, match="at least one step"):
        load_recon_plan(plan_path)


def test_executor_source_contains_no_command_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "recon" / "executor.py"
    ).read_text(encoding="utf-8")

    forbidden = ("subprocess", "os.system", "popen", "pexpect")
    assert all(value not in source.casefold() for value in forbidden)


def _write_lab_plan(tmp_path: Path) -> Path:
    scope = _scope_file(tmp_path)
    plan = build_recon_plan("10.10.10.10", scope, tmp_path / "output", "lab-full")
    plan_path, _markdown_path = write_recon_plan(plan)
    return plan_path


def _scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.md"
    path.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    return path
