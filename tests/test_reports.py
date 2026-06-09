"""Tests for deterministic report and JSON export generation."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.reports.markdown import (
    export_project_state_json,
    format_endpoint_list,
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

    assert report.startswith("# BugSlyce Recon Pack")
    assert "basic_saas" in report


def test_markdown_report_includes_required_sections() -> None:
    report, _state, _candidates = _basic_saas_report()

    required_sections = [
        "## Scope Summary",
        "## Input Files Processed",
        "## Asset Inventory",
        "## Live HTTP Services",
        "## Attack Surface Summary",
        "## Manual Review Queue",
        "## Evidence Summary",
        "### Raw Evidence References",
        "## Operator Notes / Context",
        "## Safe Next Steps",
        "## Kill-switch / Rabbit-hole Warnings",
        "## Unknowns / Requires Manual Validation",
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
    assert "# BugSlyce Recon Pack" in report_path.read_text(encoding="utf-8")
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


def test_report_candidate_endpoint_lists_are_compacted_but_json_preserves_full_detail() -> None:
    report, _state, candidates = _basic_saas_report()
    auth_candidate = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "auth_surface"
        and candidate.affected_assets == ["app.example-bounty.test"]
    )
    expected_compact = format_endpoint_list(auth_candidate.affected_endpoints)
    exported = json.loads(export_project_state_json(_state, candidates))
    exported_auth = next(
        candidate
        for candidate in exported["candidates"]
        if candidate["id"] == auth_candidate.id
    )

    assert len(auth_candidate.affected_endpoints) > 4
    assert "... +" in expected_compact
    assert expected_compact in report
    assert exported_auth["affected_endpoints"] == auth_candidate.affected_endpoints


def test_report_renders_ip_assets() -> None:
    state = build_project_state(FIXTURES_ROOT / "local_lab_ip")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "10.10.10.10" in report
    assert "http://10.10.10.10/login" in report
    assert "CAND-" in report


def test_scope_policy_text_is_not_rendered_as_assets_or_candidates(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "\n".join(
            [
                "# Scope Policy Check",
                "",
                "## In Scope",
                "",
                "* 127.0.0.1",
                "",
                "## Out of Scope",
                "",
                "* Scanners",
                "* Content discovery",
                "* Brute force",
                "* Exploitation",
            ]
        ),
        encoding="utf-8",
    )
    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    asset_inventory = report.split("## Asset Inventory", 1)[1].split("## Live HTTP Services", 1)[0]
    manual_queue = report.split("## Manual Review Queue", 1)[1].split("## Evidence Summary", 1)[0]

    assert "127.0.0.1" in asset_inventory
    assert "scanners" not in asset_inventory.lower()
    assert "exploitation" not in asset_inventory.lower()
    assert "scope review before testing scanners" not in manual_queue.lower()
    assert "scope review before testing exploitation" not in manual_queue.lower()


def test_operator_notes_are_context_not_queue_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "## Operator Notes / Context" in report
    assert "Notes are context only" in report
    assert "manual_note_review" not in report
    assert all(candidate.candidate_type != "manual_note_review" for candidate in candidates)


def test_lab_recon_pack_report_uses_evidence_first_sections() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "# BugSlyce Recon Pack" in report
    assert "## Attack Surface Summary" in report
    assert "## Manual Review Queue" in report
    assert "High-port HTTP services" in report
    assert "Robots artifacts" in report


def test_raw_recon_pack_report_includes_structured_evidence_sections() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "# BugSlyce Recon Pack" in report
    assert "## Recon Manifest" in report
    assert "Schema version: `1.0`" in report
    assert "Artifact count: 14" in report
    assert "### Port Services" in report
    assert "### Discovered Paths" in report
    assert "### HTTP Artifacts" in report
    assert "### Raw Evidence References" in report


def test_raw_recon_pack_json_preserves_manifest_metadata() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    exported = json.loads(export_project_state_json(state, candidates))

    manifest = exported["project_state"]["recon_manifest"]
    assert manifest["schema_version"] == "1.0"
    assert manifest["target"] == "10.10.10.10"
    assert manifest["created_by"] == "manual"
    assert manifest["profile"] == "manual-import"
    assert len(manifest["artifacts"]) == 14
