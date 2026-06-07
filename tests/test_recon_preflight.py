"""Tests for local recon-plan safety preflight."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.recon.planner import build_recon_plan, write_recon_plan
from bugslyce.recon.preflight import (
    render_preflight_markdown,
    run_preflight,
    write_preflight_result,
)


def test_lab_full_preflight_passes_with_tools_and_safe_output(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    result = run_preflight(plan_path)

    assert result.passed is True
    assert not result.errors
    assert all(check.status == "pass" for check in result.checks)
    assert result.no_commands_executed is True


def test_missing_required_tool_fails_active_profile(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    monkeypatch.setattr(
        "bugslyce.recon.preflight.shutil.which",
        lambda tool: None if tool == "gobuster" else f"/usr/bin/{tool}",
    )

    result = run_preflight(plan_path)

    assert result.passed is False
    assert any(
        check.name == "Tool availability: gobuster" and check.status == "fail"
        for check in result.checks
    )


def test_missing_tools_do_not_fail_passive_only(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "passive-only")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda _tool: None)

    result = run_preflight(plan_path)

    assert result.passed is True
    assert any(
        check.name == "Tool availability" and check.status == "pass"
        for check in result.checks
    )


def test_unsafe_output_directory_fails(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    _mutate_plan(plan_path, output_dir=str(Path.cwd() / "tests"))
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    result = run_preflight(plan_path)

    assert result.passed is False
    assert any(
        check.name == "Output directory safety" and check.status == "fail"
        for check in result.checks
    )


def test_active_profile_target_missing_from_scope_fails(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    (tmp_path / "scope.md").write_text("# Scope\n\n- 192.0.2.20\n", encoding="utf-8")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    result = run_preflight(plan_path)

    assert result.passed is False
    assert any(check.name == "Scope alignment" and check.status == "fail" for check in result.checks)


def test_passive_only_target_missing_from_scope_warns_and_passes(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "passive-only")
    (tmp_path / "scope.md").write_text("# Scope\n\n- 192.0.2.20\n", encoding="utf-8")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda _tool: None)

    result = run_preflight(plan_path)

    assert result.passed is True
    assert any(check.name == "Scope alignment" and check.status == "warn" for check in result.checks)
    assert result.warnings


def test_forbidden_command_preview_token_fails(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["steps"][1]["command_preview"] = "nmap --script vuln 10.10.10.10"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    result = run_preflight(plan_path)

    assert result.passed is False
    assert any(
        check.name == "Command-preview guardrails" and check.status == "fail"
        for check in result.checks
    )


def test_wrong_plan_provenance_fails(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "lab-full")
    _mutate_plan(plan_path, created_by="other-planner")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    result = run_preflight(plan_path)

    assert result.passed is False
    assert any(check.name == "Plan provenance" and check.status == "fail" for check in result.checks)


def test_preflight_outputs_are_valid_json_and_markdown(tmp_path: Path, monkeypatch) -> None:
    plan_path = _write_plan(tmp_path, "passive-only")
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda _tool: None)
    result = run_preflight(plan_path)

    json_path, markdown_path = write_preflight_result(result, plan_path.parent)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert payload["passed"] is True
    assert payload["no_commands_executed"] is True
    assert "No commands were executed." in markdown
    assert render_preflight_markdown(result) == markdown


def test_preflight_source_contains_no_command_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "recon" / "preflight.py"
    ).read_text(encoding="utf-8")

    forbidden = ("subprocess", "os.system", "popen", "pexpect")
    assert all(value not in source.casefold() for value in forbidden)


def _write_plan(tmp_path: Path, profile: str) -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / profile
    plan = build_recon_plan("10.10.10.10", scope, output, profile)
    plan_path, _markdown_path = write_recon_plan(plan)
    return plan_path


def _mutate_plan(plan_path: Path, **updates: object) -> None:
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload.update(updates)
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
