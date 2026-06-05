"""Tests for deterministic report and JSON export generation."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.reports.markdown import (
    export_project_state_json,
    format_evidence_ids,
    render_markdown_report,
    write_project_outputs,
)
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def _basic_saas_report() -> tuple[str, object, object]:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    return render_markdown_report(state, candidates), state, candidates


def test_markdown_report_renders_for_basic_saas() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert report.startswith("# BugSlyce Triage Report")
    assert "basic_saas" in report


def test_markdown_report_includes_required_sections() -> None:
    report, _state, _candidates = _basic_saas_report()

    required_sections = [
        "## Scope Summary",
        "## Input Files Processed",
        "## Asset Inventory",
        "## Live HTTP Services",
        "## Interesting Surface Areas",
        "## Priority Manual Testing Queue",
        "## Evidence Table",
        "## Safe Next Steps",
        "## Kill-switch / Rabbit-hole Warnings",
        "## Unknowns / Needs Manual Validation",
    ]

    for section in required_sections:
        assert section in report


def test_markdown_report_includes_candidate_and_evidence_ids() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert "CAND-0001" in report
    assert "EVID-HOST-0001" in report
    assert "EVID-URL-0001" in report


def test_markdown_report_includes_priority_queue_and_kill_switch_warnings() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert "### high" in report
    assert "### medium" in report
    assert "### low" in report
    assert "### kill_switch" in report
    assert "Kill-switch guidance" in report


def test_project_state_json_export_is_valid_and_complete() -> None:
    _report, state, candidates = _basic_saas_report()

    exported = json.loads(export_project_state_json(state, candidates))

    assert "project_state" in exported
    assert "candidates" in exported
    assert exported["project_state"]["assets"]
    assert exported["project_state"]["endpoints"]
    assert exported["project_state"]["evidence"]
    assert exported["candidates"]
    assert exported["candidates"][0]["id"].startswith("CAND-")


def test_write_project_outputs_to_temp_directory(tmp_path: Path) -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    report_path, json_path = write_project_outputs(state, candidates, tmp_path / "bugslyce-output")

    assert report_path == tmp_path / "bugslyce-output" / "report.md"
    assert json_path == tmp_path / "bugslyce-output" / "project_state.json"
    assert report_path.exists()
    assert json_path.exists()
    assert "# BugSlyce Triage Report" in report_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["candidates"]


def test_long_evidence_lists_are_compacted_in_markdown_tables() -> None:
    report, state, _candidates = _basic_saas_report()
    app_asset = next(asset for asset in state.assets if asset.hostname == "app.example-bounty.test")
    expected_compact = format_evidence_ids(app_asset.evidence_ids)

    assert len(app_asset.evidence_ids) > 4
    assert "... +" in expected_compact
    assert expected_compact in report


def test_json_export_preserves_full_evidence_ids() -> None:
    _report, state, candidates = _basic_saas_report()
    app_asset = next(asset for asset in state.assets if asset.hostname == "app.example-bounty.test")
    exported = json.loads(export_project_state_json(state, candidates))
    exported_app = next(
        asset
        for asset in exported["project_state"]["assets"]
        if asset["hostname"] == "app.example-bounty.test"
    )

    assert exported_app["evidence_ids"] == app_asset.evidence_ids
    assert len(exported_app["evidence_ids"]) > 4
