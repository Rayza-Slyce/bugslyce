"""Tests for planning-only recon profiles and serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.recon.planner import build_recon_plan, render_recon_plan, write_recon_plan


def test_lab_full_plan_contains_expected_steps_and_artifacts(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, "10.10.10.10")

    plan = build_recon_plan("10.10.10.10", scope, tmp_path / "output", "lab-full")

    step_names = [step.name for step in plan.steps]
    artifact_files = [artifact.file for artifact in plan.planned_artifacts]
    assert step_names == [
        "Confirm target scope",
        "Full TCP port discovery",
        "Service and version discovery",
        "HTTP probing and response header checks",
        "Robots and sitemap checks",
        "Root content discovery",
        "Limited recursive content discovery",
        "Saved HTML metadata collection",
    ]
    assert "nmap-allports.txt" in artifact_files
    assert "curl-headers-<http-port>.txt" in artifact_files
    assert "gobuster-<http-port>-root.txt" in artifact_files
    assert all("No commands were executed." != (step.command_preview or "") for step in plan.steps)


def test_bug_bounty_standard_plan_is_conservative(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, "app.example-bounty.test")

    plan = build_recon_plan(
        "app.example-bounty.test",
        scope,
        tmp_path / "output",
        "bug-bounty-standard",
    )

    assert any(step.name == "Conservative content discovery" for step in plan.steps)
    assert all(step.name != "Limited recursive content discovery" for step in plan.steps)
    assert any("rate limits" in note for note in plan.safety_notes)
    assert any("aggressive fuzzing" in note for note in plan.safety_notes)


def test_passive_only_plan_has_no_live_command_previews(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, "different.example-bounty.test")

    plan = build_recon_plan(
        "app.example-bounty.test",
        scope,
        tmp_path / "output",
        "passive-only",
    )

    assert all(step.command_preview is None for step in plan.steps)
    assert plan.planned_artifacts == []
    assert plan.warnings
    assert "no live recon is included" in plan.warnings[0]


def test_unsupported_profile_fails_gracefully(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, "10.10.10.10")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope, tmp_path / "output", "aggressive")


def test_deep_bounded_contract_is_not_an_executable_planner_profile(
    tmp_path: Path,
) -> None:
    scope = _scope_file(tmp_path, "10.10.10.10")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope, tmp_path / "output", "deep-bounded")


def test_missing_scope_file_fails_gracefully(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Scope file does not exist"):
        build_recon_plan(
            "10.10.10.10",
            tmp_path / "missing-scope.md",
            tmp_path / "output",
            "lab-full",
        )


@pytest.mark.parametrize("profile", ["lab-full", "bug-bounty-standard"])
def test_active_profiles_refuse_target_absent_from_scope(tmp_path: Path, profile: str) -> None:
    scope = _scope_file(tmp_path, "192.0.2.20")

    with pytest.raises(ValueError, match="Refusing to plan live recon activity"):
        build_recon_plan("10.10.10.10", scope, tmp_path / "output", profile)


def test_recon_plan_outputs_are_valid_and_state_no_execution(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, "10.10.10.10")
    output = tmp_path / "output"
    plan = build_recon_plan("10.10.10.10", scope, output, "lab-full")

    json_path, markdown_path = write_recon_plan(plan)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert payload["target"] == "10.10.10.10"
    assert payload["steps"]
    assert payload["planned_artifacts"]
    assert "No commands were executed." in markdown
    assert render_recon_plan(plan) == markdown


def _scope_file(tmp_path: Path, target: str) -> Path:
    path = tmp_path / "scope.md"
    path.write_text(f"# Test Scope\n\n## In Scope\n\n- {target}\n", encoding="utf-8")
    return path
