"""Tests for the static Deep Recon readiness summary renderer."""

from __future__ import annotations

import json

import pytest

from bugslyce.project_pipeline import run_project_pipeline
from bugslyce.recon.deep_outputs import get_deep_recon_planned_outputs
from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline
from bugslyce.recon.deep_preflight import get_deep_recon_preflight_requirements
from bugslyce.recon.deep_readiness import (
    build_deep_recon_readiness_snapshot,
    render_deep_recon_readiness_summary,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)
from bugslyce.recon.planner import build_recon_plan


def _walk_keys(value: object) -> tuple[str, ...]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.extend(_walk_keys(nested))
    return tuple(keys)


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


def test_deep_readiness_snapshot_is_deterministic_json_serialisable_data() -> None:
    first = build_deep_recon_readiness_snapshot()
    second = build_deep_recon_readiness_snapshot()

    assert first == second
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert tuple(first) == (
        "schema_version",
        "status",
        "mode_mappings",
        "profile_contract",
        "bounds",
        "counts",
        "planned_pipeline",
        "planned_outputs",
        "preflight_requirements",
        "validation",
        "non_executable_guarantees",
    )


def test_deep_readiness_snapshot_status_mappings_counts_and_validation() -> None:
    snapshot = build_deep_recon_readiness_snapshot()

    assert snapshot["schema_version"] == 1
    assert snapshot["status"] == {
        "deep_available": True,
        "deep_executable": True,
        "deep_status": "implemented",
        "summary": "Deep Recon is available as bounded deep-bounded.",
    }
    assert snapshot["mode_mappings"] == {
        "quick": "lab-safe-tiny",
        "standard": "standard-bounded",
        "deep": "deep-bounded",
    }
    assert snapshot["counts"] == {
        "planned_steps": 24,
        "active_collection_steps": 12,
        "offline_correlation_reporting_steps": 12,
        "planned_outputs": 25,
        "preflight_requirements": 22,
        "blocking_preflight_requirements": 22,
    }
    assert snapshot["validation"] == {
        "planned_pipeline_valid": True,
        "planned_pipeline_errors": [],
        "planned_outputs_valid": True,
        "planned_outputs_errors": [],
        "preflight_contract_valid": True,
        "preflight_contract_errors": [],
    }


def test_deep_readiness_snapshot_includes_bounds_pipeline_outputs_and_preflight() -> None:
    snapshot = build_deep_recon_readiness_snapshot()

    assert snapshot["bounds"] == {
        "max_total_requests": 1500,
        "max_requests_per_service": 400,
        "max_second_pass_directories": 8,
        "max_second_pass_requests_per_directory": 100,
        "max_crawl_depth": 1,
        "max_crawl_pages": 50,
        "max_js_files": 50,
        "max_source_files": 80,
        "max_source_map_files": 10,
        "max_body_bytes": 1_000_000,
        "max_redirects": 5,
        "request_timeout_seconds": 10,
        "rate_limit_delay_seconds": 0.1,
    }
    assert len(snapshot["planned_pipeline"]) == 24
    assert snapshot["planned_pipeline"][0] == {
        "step_id": "deep-01-scope-validation",
        "name": "Environment and scope validation",
        "active_collection": False,
        "method_class": "local validation",
        "uses_bounds": [],
        "planned_outputs": ["deep-output-scope-safety-summary"],
    }
    assert len(snapshot["planned_outputs"]) == 25
    assert snapshot["planned_outputs"][-1] == {
        "output_id": "deep-output-evidence-pack-manifest",
        "name": "Deep Evidence Pack Manifest",
        "output_kind": "export_manifest",
        "sensitivity": "high",
        "producer_step_id": "deep-24-evidence-pack-export",
        "contains_target_data": True,
    }
    assert len(snapshot["preflight_requirements"]) == 22
    assert snapshot["preflight_requirements"][0] == {
        "requirement_id": "deep-preflight-authorisation-declared",
        "name": "Explicit authorisation declared",
        "category": "authorisation",
        "severity": "critical",
        "blocking": True,
        "related_deep_step_ids": ["deep-01-scope-validation"],
        "related_output_ids": ["deep-output-scope-safety-summary"],
    }


def test_deep_readiness_snapshot_has_non_executable_guarantees_and_no_command_shape() -> None:
    snapshot = build_deep_recon_readiness_snapshot()

    assert snapshot["non_executable_guarantees"] == [
        "Deep Recon is available only through the bounded deep-bounded profile.",
        "`deep-bounded` remains bounded and scope-conscious.",
        "This readiness renderer performs no runtime collection.",
        "No project files are read or written.",
        "No commands are executed.",
        "No output files are created.",
        "Quick and Standard mappings remain unchanged.",
    ]
    keys = set(_walk_keys(snapshot))
    assert "argv" not in keys
    assert "command_preview" not in keys
    assert "execute" not in keys


def test_deep_readiness_summary_contains_required_status_wording() -> None:
    markdown = render_deep_recon_readiness_summary()

    assert "Deep Recon is available as bounded deep-bounded." in markdown
    assert "`deep-bounded` is the bounded executable Deep profile." in markdown
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


def test_deep_readiness_summary_has_renderer_safety_guarantees() -> None:
    markdown = render_deep_recon_readiness_summary()

    assert "This renderer does not run Deep Recon." in markdown
    assert "`deep-bounded` remains bounded and scope-conscious." in markdown
    assert "This renderer does not perform runtime preflight checks." in markdown
    assert "This renderer does not read or write project files." in markdown
    assert "This renderer does not create reports, evidence packs, or output files." in markdown
    assert "This renderer does not execute commands or make network requests." in markdown
    assert "Quick and Standard mappings remain unchanged." in markdown
    assert "argv" not in markdown
    assert "command_preview" not in markdown
    assert "`execute`" not in markdown
    assert "| execute |" not in markdown


def test_deep_bounded_remains_unsupported_by_static_recon_planner(
    tmp_path,
) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope_file, tmp_path / "output", "deep-bounded")


def test_deep_is_available_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert resolve_executable_profile("deep") == "deep-bounded"
