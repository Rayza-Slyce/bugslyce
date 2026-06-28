"""Tests for the static Deep Recon readiness summary renderer."""

from __future__ import annotations

import pytest

from bugslyce.project_pipeline import run_project_pipeline
from bugslyce.recon.deep_outputs import get_deep_recon_planned_outputs
from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline
from bugslyce.recon.deep_preflight import get_deep_recon_preflight_requirements
from bugslyce.recon.deep_readiness import render_deep_recon_readiness_summary
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)
from bugslyce.recon.planner import build_recon_plan


def test_deep_readiness_summary_is_deterministic_markdown() -> None:
    first = render_deep_recon_readiness_summary()
    second = render_deep_recon_readiness_summary()

    assert first == second
    assert first.startswith("# Deep Recon Readiness Summary\n")
    for heading in (
        "## Current Status",
        "## Profile Contract",
        "## Bounds",
        "## Planned Pipeline",
        "## Planned Outputs",
        "## Preflight Gates",
        "## Validation Status",
        "## Non-Executable Guarantees",
    ):
        assert heading in first


def test_deep_readiness_summary_contains_required_status_wording() -> None:
    markdown = render_deep_recon_readiness_summary()

    assert "Deep Recon is planned and unavailable." in markdown
    assert "`deep-bounded` is a planned profile contract, not an executable profile." in markdown
    assert "This summary is static contract rendering only." in markdown
    assert "No runtime collection is performed." in markdown
    assert "No project files are read or written." in markdown
    assert "No commands are executed." in markdown
    assert "Quick Recon remains mapped to lab-safe-tiny." in markdown
    assert "Standard Recon remains mapped to standard-bounded." in markdown


def test_deep_readiness_summary_includes_all_bounds() -> None:
    markdown = render_deep_recon_readiness_summary()
    expected_bounds = {
        "max_total_requests": "1500",
        "max_requests_per_service": "400",
        "max_second_pass_directories": "8",
        "max_second_pass_requests_per_directory": "100",
        "max_crawl_depth": "1",
        "max_crawl_pages": "50",
        "max_js_files": "50",
        "max_source_files": "80",
        "max_source_map_files": "10",
        "max_body_bytes": "1000000",
        "max_redirects": "5",
        "request_timeout_seconds": "10",
        "rate_limit_delay_seconds": "0.1",
    }

    for name, value in expected_bounds.items():
        assert f"- `{name}`: `{value}`" in markdown


def test_deep_readiness_summary_includes_planned_step_counts_and_rows() -> None:
    markdown = render_deep_recon_readiness_summary()
    steps = get_deep_recon_planned_pipeline()

    assert "- Total planned steps: 24" in markdown
    assert "- Active collection steps: 12" in markdown
    assert "- Offline/correlation/reporting steps: 12" in markdown
    assert "- First step: `deep-01-scope-validation` - Environment and scope validation" in markdown
    assert "- Final step: `deep-24-evidence-pack-export` - Evidence pack export" in markdown
    for step in steps:
        active_label = "active" if step.active_collection else "passive"
        assert (
            f"| `{step.step_id}` | {step.name} | {active_label} | "
            f"{step.method_class} |"
        ) in markdown


def test_deep_readiness_summary_includes_outputs_and_preflight_counts() -> None:
    markdown = render_deep_recon_readiness_summary()
    outputs = get_deep_recon_planned_outputs()
    requirements = get_deep_recon_preflight_requirements()

    assert "- Total planned outputs: 25" in markdown
    assert "Output kinds used: correlation, evidence, export_manifest, index, queue, report_section, runbook_section" in markdown
    assert "- Sensitivity levels used: high, medium" in markdown
    assert "- Final output: `deep-output-evidence-pack-manifest` - Deep Evidence Pack Manifest" in markdown
    for output in outputs:
        assert (
            f"| `{output.output_id}` | {output.name} | {output.output_kind} | "
            f"{output.sensitivity} | `{output.producer_step_id}` |"
        ) in markdown

    assert "- Total preflight requirements: 22" in markdown
    assert "Categories used: authorisation, bounds, data_handling, engagement_context, method_safety, operator_confirmation, scope, target_control" in markdown
    assert "- Severity levels used: critical, high" in markdown
    assert "- Blocking requirements: 22" in markdown
    for requirement in requirements:
        assert (
            f"| `{requirement.requirement_id}` | {requirement.name} | "
            f"{requirement.category} | {requirement.severity} | yes |"
        ) in markdown


def test_deep_readiness_summary_reports_validation_statuses_as_valid() -> None:
    markdown = render_deep_recon_readiness_summary()

    assert "- Planned pipeline contract: valid" in markdown
    assert "- Planned output taxonomy: valid" in markdown
    assert "- Preflight contract: valid" in markdown


def test_deep_readiness_summary_has_non_executable_guarantees() -> None:
    markdown = render_deep_recon_readiness_summary()

    assert "This renderer does not enable Deep Recon." in markdown
    assert "This renderer does not make `deep-bounded` executable." in markdown
    assert "This renderer does not perform runtime preflight checks." in markdown
    assert "This renderer does not read or write project files." in markdown
    assert "This renderer does not create reports, evidence packs, or output files." in markdown
    assert "This renderer does not execute commands or make network requests." in markdown
    assert "Quick and Standard mappings remain unchanged." in markdown
    assert "argv" not in markdown
    assert "command_preview" not in markdown
    assert "`execute`" not in markdown
    assert "| execute |" not in markdown


def test_deep_bounded_remains_non_executable_in_planner_and_pipeline(
    tmp_path,
) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope_file, tmp_path / "output", "deep-bounded")

    project_file = tmp_path / "bugslyce_project.json"
    project_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported project pipeline profile"):
        run_project_pipeline(project_file, "deep-bounded")


def test_deep_remains_unavailable_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False

    with pytest.raises(ReconModeUnavailable):
        resolve_executable_profile("deep")
