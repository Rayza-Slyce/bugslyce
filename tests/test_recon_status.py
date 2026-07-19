"""Tests for read-only recon status and next-step advice."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import shutil

import pytest

from bugslyce.cli import main
from bugslyce.recon.status import (
    build_recon_status,
    render_recon_status_markdown,
    write_recon_status,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "demo_recon"
    / "lab_raw_recon_pack"
)
FIXED_TIME = datetime(2026, 6, 14, 13, 45, 12, tzinfo=timezone.utc)


def test_status_refuses_missing_input_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        build_recon_status(tmp_path / "missing")


def test_status_refuses_missing_manifest(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="Recon manifest does not exist"):
        build_recon_status(input_dir)


def test_status_refuses_malformed_manifest(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    (input_dir / "recon_manifest.json").write_text("{bad", encoding="utf-8")

    with pytest.raises(ValueError, match="Could not parse recon manifest"):
        build_recon_status(input_dir)


def test_status_detects_fixture_phases_and_counts(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    shutil.copytree(FIXTURE, input_dir)

    result = build_recon_status(input_dir, input_dir / "scope.md")
    phases = {phase.id: phase.status for phase in result.phases}

    assert result.target == "10.10.10.10"
    assert result.input_dir == str(input_dir.resolve())
    assert result.scope_status == "in scope"
    assert phases["nmap_full"] == "detected"
    assert phases["nmap_services"] == "detected"
    assert phases["http_metadata"] == "detected"
    assert phases["content_light"] == "detected"
    assert result.artifact_overview["open_ports"] == 3
    assert result.artifact_overview["http_services"] == 2
    assert result.artifact_overview["gobuster_outputs"] == 3


def test_status_writes_generated_at_and_source_input_dir(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path)

    result = build_recon_status(input_dir, clock=lambda: FIXED_TIME)
    json_path, markdown_path = write_recon_status(result, input_dir)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert result.generated_at == "2026-06-14T13:45:12Z"
    assert payload["generated_at"] == "2026-06-14T13:45:12Z"
    assert payload["source_input_dir"] == str(input_dir.resolve())
    assert "Generated at: `2026-06-14T13:45:12Z`" in markdown


def test_status_cleans_profile_display_and_reports_raw_unique_duplicate_paths(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["profile"] = (
        "lab-tcp-full-plus-services-plus-http-metadata-plus-path-followup-"
        "plus-content-discovery-plus-content-followup-plus-body-fetch-"
        "plus-content-discovery"
    )
    tiny_file = input_dir / "gobuster-tiny-10.10.10.10-80-root.txt"
    tiny_file.write_text("portal (Status: 200) [Size: 321]\n", encoding="utf-8")
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": tiny_file.name,
            "base_url": "http://10.10.10.10/",
            "description": "Approved lab-root-tiny root discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.manifest_profile == manifest["profile"]
    assert result.workflow_summary.base_discovery_profile == "lab-tcp-full"
    assert result.workflow_summary.content_discovery_profiles == [
        "lab-root-tiny",
        "lab-root-light",
    ]
    assert result.workflow_summary.raw_discovered_path_rows == 3
    assert result.workflow_summary.unique_discovered_paths == 2
    assert result.workflow_summary.duplicate_discovered_path_rows == 1
    assert result.artifact_overview["raw_discovered_path_evidence_rows"] == 3
    assert result.artifact_overview["unique_discovered_paths"] == 2
    assert result.artifact_overview["duplicate_discovered_path_evidence_rows"] == 1
    workflow_section = rendered.split("## Workflow / Provenance Summary", 1)[1].split(
        "## Completed Phases Detected",
        1,
    )[0]
    assert "lab-root-tiny" in workflow_section
    assert "lab-root-light" in workflow_section
    assert "plus-content-discovery-plus-content-discovery" not in workflow_section


def test_status_detects_standard_bounded_core_content_profile(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        artifact
        for artifact in manifest["artifacts"]
        if not artifact.get("file", "").startswith("gobuster-")
    ]
    bounded_file = input_dir / "gobuster-standard-bounded-core-10.10.10.10-80-root.txt"
    bounded_file.write_text("login.php (Status: 200) [Size: 456]\n", encoding="utf-8")
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": bounded_file.name,
            "base_url": "http://10.10.10.10/",
            "description": "Bounded Standard content discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.workflow_summary.content_discovery_profiles == ["standard-bounded-core"]
    assert "standard-bounded-core" in rendered
    assert "lab-root-light" not in result.workflow_summary.content_discovery_profiles


def test_status_detects_deep_bounded_core_content_profile(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        artifact
        for artifact in manifest["artifacts"]
        if not artifact.get("file", "").startswith("gobuster-")
    ]
    deep_file = input_dir / "gobuster-deep-bounded-core-10.10.10.10-80-root.txt"
    deep_file.write_text("sitemap (Status: 301) [--> /sitemap/]\n", encoding="utf-8")
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": deep_file.name,
            "base_url": "http://10.10.10.10/",
            "description": "Bounded Deep content discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.workflow_summary.content_discovery_profiles == ["deep-bounded-core"]
    assert "deep-bounded-core" in rendered
    assert "lab-root-light" not in result.workflow_summary.content_discovery_profiles


def test_status_detects_content_profile_from_execution_metadata(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="services")
    (input_dir / "recon_execution_content_run.json").write_text(
        json.dumps({"mode": "content-run", "profile": "lab-root-tiny"}),
        encoding="utf-8",
    )

    result = build_recon_status(input_dir)

    assert result.workflow_summary.content_discovery_profiles == ["lab-root-tiny"]


def test_status_detects_followup_body_report_and_execution_metadata(
    tmp_path: Path,
) -> None:
    input_dir, scope = _status_input(tmp_path, include_body=True)
    (input_dir / "report.md").write_text(
        "# BugSlyce Recon Pack\n\n"
        "## Operator Summary\n\n"
        "### Encoded Artefact Classification\n",
        encoding="utf-8",
    )
    latest = {
        "mode": "content-run",
        "profile": "lab-root-tiny",
        "commands_started": 1,
        "commands_completed": 1,
        "commands_timed_out": 0,
        "selected_step_id": "CONTENT-STEP-001",
        "selected_origin": "http://10.10.10.10/",
        "artifact_paths": ["gobuster-tiny-10.10.10.10-80-root.txt"],
    }
    (input_dir / "recon_execution.json").write_text(json.dumps(latest), encoding="utf-8")
    (input_dir / "recon_execution.md").write_text(
        "# BugSlyce Content Discovery Execution\n",
        encoding="utf-8",
    )
    (input_dir / "recon_execution_content_run.json").write_text(
        json.dumps(latest),
        encoding="utf-8",
    )
    (input_dir / "recon_execution_content_run.md").write_text(
        "# BugSlyce Content Discovery Execution\n",
        encoding="utf-8",
    )

    result = build_recon_status(input_dir, scope)
    phases = {phase.id: phase.status for phase in result.phases}

    assert phases["content_followup"] == "detected"
    assert phases["body_fetch"] == "detected"
    assert phases["operator_summary"] == "detected"
    assert phases["encoded_classification"] == "detected"
    assert phases["latest_execution"] == "detected"
    assert phases["content_run_metadata"] == "detected"
    assert result.latest_execution
    assert result.latest_execution["mode"] == "content-run"
    assert result.latest_execution["commands_completed"] == 1
    assert result.latest_execution["heading"] == "BugSlyce Content Discovery Execution"
    assert "recon_execution_content_run.json" in result.phase_specific_metadata


def test_status_advises_nmap_services_after_discovery_only(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="discovery")

    result = build_recon_status(input_dir)

    assert "`bugslyce recon nmap-services`" in result.next_actions[0]


def test_status_advises_http_metadata_after_service_detection(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="services")

    result = build_recon_status(input_dir)

    assert "`bugslyce recon http-metadata`" in result.next_actions[0]


def test_status_advises_content_plan_when_metadata_has_no_eligible_paths(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="metadata")

    result = build_recon_status(input_dir)

    assert "`bugslyce recon path-followup`" not in result.next_actions[0]
    assert "`bugslyce recon content-plan`" in result.next_actions[0]


def test_status_advises_content_plan_after_http_path_metadata(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="path-followup")

    result = build_recon_status(input_dir)

    assert "`lab-root-tiny`" in result.next_actions[0]
    assert "`bugslyce recon content-plan`" in result.next_actions[0]


def test_status_advises_content_followup_for_pending_gobuster_path(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")

    result = build_recon_status(input_dir)

    assert "`bugslyce recon content-followup`" in result.next_actions[0]
    assert "1 eligible URL" in result.next_actions[0]


def test_status_advises_body_fetch_for_followed_200_path(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="content-followup")

    result = build_recon_status(input_dir)

    assert "`bugslyce recon body-fetch`" in result.next_actions[0]


def test_status_reports_no_pending_automation_when_body_already_saved(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)

    result = build_recon_status(input_dir)

    assert "No eligible automated follow-up appears pending" in result.next_actions[0]


def test_status_suggests_optional_light_profile_after_tiny_only(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True, tiny=True)

    result = build_recon_status(input_dir)

    assert any("Optional broader root discovery" in action for action in result.next_actions)


def test_status_scope_warning_is_nonfatal(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path)
    other_scope = tmp_path / "other-scope.md"
    other_scope.write_text("## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    result = build_recon_status(input_dir, other_scope)

    assert result.scope_status.startswith("warning:")
    assert result.target == "10.10.10.10"


def test_status_writes_only_status_outputs_and_renders_safety_notes(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    report_path = input_dir / "report.md"
    execution_path = input_dir / "recon_execution.md"
    report_path.write_text("# Existing report\n", encoding="utf-8")
    execution_path.write_text("# Existing execution\n", encoding="utf-8")
    result = build_recon_status(input_dir)

    json_path, markdown_path = write_recon_status(result, input_dir)
    rendered = render_recon_status_markdown(result)

    assert json.loads(json_path.read_text(encoding="utf-8"))["target"] == "10.10.10.10"
    assert markdown_path.read_text(encoding="utf-8") == rendered
    assert "# BugSlyce Recon Status" in rendered
    assert "No commands were executed." in rendered
    assert "No network requests were made." in rendered
    assert report_path.read_text(encoding="utf-8") == "# Existing report\n"
    assert execution_path.read_text(encoding="utf-8") == "# Existing execution\n"


def test_status_reports_completed_deep_pipeline_profile_and_phases(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="completed",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
        },
    )
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.latest_execution
    assert result.latest_execution["pipeline_profile"] == "deep-bounded"
    assert result.artifact_overview["deep_pipeline_phases_detected"] == 2
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2
    assert "- Pipeline profile: `deep-bounded`" in rendered
    assert "- Deep pipeline phases: 2/2" in rendered


def test_completed_deep_review_is_primary_and_remaining_collection_is_optional(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")
    (input_dir / "report.md").write_text(
        "# Report\n\n## Operator Summary\n",
        encoding="utf-8",
    )
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="completed",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
        },
    )
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)

    assert "review the Operator Summary" in result.next_actions[0]
    assert "`report.md`" in result.next_actions[0]
    assert "Optional additional bounded collection" in result.next_actions[1]
    assert "`bugslyce recon content-followup`" in result.next_actions[1]


def test_incomplete_deep_review_keeps_collection_recovery_first(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, stage="gobuster")
    (input_dir / "report.md").write_text(
        "# Report\n\n## Operator Summary\n",
        encoding="utf-8",
    )
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="running",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "pending",
        },
    )
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)

    assert "`bugslyce recon content-followup`" in result.next_actions[0]
    assert "Optional additional bounded collection" not in result.next_actions[0]


def test_status_counts_skipped_existing_steps_as_satisfied_pipeline_work(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="completed",
        step_statuses={
            "PIPELINE-STEP-010": "completed",
            "PIPELINE-STEP-011": "skipped_existing",
            "PIPELINE-STEP-012": "noop",
            "PIPELINE-STEP-013": "failed",
        },
    )

    result = build_recon_status(input_dir)

    assert result.artifact_overview["pipeline_steps_satisfied"] == 3
    assert result.artifact_overview["pipeline_steps_total"] == 4


def test_status_reports_deep_phases_from_running_pipeline_checkpoint(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="running",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
        },
    )
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.latest_execution
    assert result.latest_execution["pipeline_profile"] == "deep-bounded"
    assert result.artifact_overview["deep_pipeline_phases_detected"] == 2
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2
    assert "- Pipeline profile: `deep-bounded`" in rendered
    assert "- Deep pipeline phases: 2/2" in rendered


@pytest.mark.parametrize(
    ("step_statuses", "expected_detected"),
    (
        (
            {
                "PIPELINE-STEP-010D": "running",
                "PIPELINE-STEP-011D": "completed",
            },
            1,
        ),
        (
            {
                "PIPELINE-STEP-010D": "failed",
                "PIPELINE-STEP-011D": "completed",
            },
            1,
        ),
        (
            {
                "PIPELINE-STEP-010D": "completed",
                "PIPELINE-STEP-011D": "running",
            },
            1,
        ),
        (
            {
                "PIPELINE-STEP-010D": "completed",
                "PIPELINE-STEP-011D": "failed",
            },
            1,
        ),
    ),
)
def test_status_counts_only_completed_deep_pipeline_steps(
    tmp_path: Path,
    step_statuses: dict[str, str],
    expected_detected: int,
) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="running",
        step_statuses=step_statuses,
    )
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == expected_detected
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2


def test_status_reports_partial_deep_artifacts_without_full_completion(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="failed",
        step_statuses={
            "PIPELINE-STEP-010D": "failed",
            "PIPELINE-STEP-011D": "failed",
        },
    )
    (input_dir / "deep_source_route_collection.md").write_text("source\n", encoding="utf-8")

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2
    assert "- Deep pipeline phases: 0/2" in rendered


def test_status_reports_one_verified_deep_phase_when_orchestration_pending(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="running",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "pending",
        },
    )
    for name in ("deep_source_route_collection.md", "deep_source_route_collection.json"):
        (input_dir / name).write_text(f"{name}\n", encoding="utf-8")
    for name in ("deep_recon_review.md", "deep_recon_runbook.md", "deep_recon_orchestration.json"):
        (input_dir / name).write_text(f"{name}\n", encoding="utf-8")

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 1
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2
    assert "- Pipeline profile: `deep-bounded`" in rendered
    assert "- Deep pipeline phases: 1/2" in rendered


def test_status_does_not_verify_deep_files_without_pipeline_metadata(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_artifacts(input_dir)

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert result.artifact_overview["deep_pipeline_phases_total"] == 2
    assert "- Pipeline profile: `deep-bounded`" not in rendered
    assert "- Deep pipeline phases: 0/2" in rendered


def test_status_rejects_mismatched_pipeline_metadata_for_deep_verification(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_artifacts(input_dir)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="completed",
        target="other.test",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
        },
    )

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert "- Pipeline profile: `deep-bounded`" not in rendered
    assert result.latest_execution
    assert "pipeline_metadata_warning" in result.latest_execution


def test_status_rejects_mismatched_pipeline_output_dir_for_deep_verification(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_artifacts(input_dir)
    _write_deep_pipeline_metadata(
        input_dir,
        final_status="completed",
        output_dir=tmp_path / "elsewhere",
        step_statuses={
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
        },
    )

    result = build_recon_status(input_dir)
    rendered = render_recon_status_markdown(result)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert "- Pipeline profile: `deep-bounded`" not in rendered


def test_status_ignores_malformed_pipeline_metadata_without_crashing(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_artifacts(input_dir)
    (input_dir / "project_pipeline.json").write_text("{bad", encoding="utf-8")

    result = build_recon_status(input_dir)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert result.latest_execution
    assert "pipeline_metadata_warning" in result.latest_execution


def test_status_ignores_non_object_pipeline_metadata_without_crashing(tmp_path: Path) -> None:
    input_dir, _scope = _status_input(tmp_path, include_body=True)
    _write_deep_artifacts(input_dir)
    (input_dir / "project_pipeline.json").write_text("[]", encoding="utf-8")

    result = build_recon_status(input_dir)

    assert result.artifact_overview["deep_pipeline_phases_detected"] == 0
    assert result.latest_execution
    assert "pipeline_metadata_warning" in result.latest_execution


def test_cli_status_writes_outputs_and_prints_local_only_summary(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir, scope = _status_input(tmp_path, include_body=True)

    exit_code = main(
        [
            "recon",
            "status",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce recon status complete" in captured.out
    assert "Target: 10.10.10.10" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert "by Rayza Slyce" not in captured.out
    assert (input_dir / "recon_status.json").is_file()
    assert (input_dir / "recon_status.md").is_file()


def test_status_module_does_not_use_command_or_network_execution() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "status.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "os.system" not in source
    assert "Popen" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def _status_input(
    tmp_path: Path,
    stage: str = "gobuster",
    include_body: bool = False,
    tiny: bool = False,
) -> tuple[Path, Path]:
    if include_body:
        stage = "content-followup"
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    scope = input_dir / "scope.md"
    scope.write_text("## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    artifacts: list[dict[str, object]] = []

    if stage in {"discovery", "services", "metadata", "path-followup", "gobuster", "content-followup"}:
        discovery_name = "nmap-allports.txt"
        (input_dir / discovery_name).write_text(
            "Nmap scan report for 10.10.10.10\n"
            "PORT   STATE SERVICE\n"
            "80/tcp open  unknown\n",
            encoding="utf-8",
        )
        artifacts.append({"type": "nmap", "file": discovery_name})

    if stage in {"services", "metadata", "path-followup", "gobuster", "content-followup"}:
        service_name = "nmap-services-all.txt"
        (input_dir / service_name).write_text(
            "Nmap scan report for 10.10.10.10\n"
            "PORT   STATE SERVICE VERSION\n"
            "80/tcp open  http    nginx 1.24.0\n",
            encoding="utf-8",
        )
        artifacts.append({"type": "nmap", "file": service_name})

    if stage in {"metadata", "path-followup", "gobuster", "content-followup"}:
        (input_dir / "homepage-10.10.10.10-80.html").write_text(
            "<html><title>Home</title></html>",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "html",
                "file": "homepage-10.10.10.10-80.html",
                "url": "http://10.10.10.10/",
            }
        )
        if stage != "metadata":
            (input_dir / "curl-headers-followup-10.10.10.10-80-manual.txt").write_text(
                "HTTP/1.1 404 Not Found\n",
                encoding="utf-8",
            )
            artifacts.append(
                {
                    "type": "http_headers",
                    "file": "curl-headers-followup-10.10.10.10-80-manual.txt",
                    "url": "http://10.10.10.10/manual",
                }
            )

    if stage in {"gobuster", "content-followup"}:
        gobuster_name = (
            "gobuster-tiny-10.10.10.10-80-root.txt"
            if tiny
            else "gobuster-10.10.10.10-80-root.txt"
        )
        (input_dir / gobuster_name).write_text(
            "portal (Status: 200) [Size: 321]\n",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "gobuster",
                "file": gobuster_name,
                "base_url": "http://10.10.10.10/",
            }
        )

    if stage == "content-followup":
        followup_name = "curl-headers-content-followup-10.10.10.10-80-portal.txt"
        (input_dir / followup_name).write_text(
            "HTTP/1.1 200 OK\nContent-Type: text/html\n",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "http_headers",
                "file": followup_name,
                "url": "http://10.10.10.10/portal",
            }
        )

    if include_body:
        body_name = "body-fetch-10.10.10.10-80-portal.html"
        (input_dir / body_name).write_text(
            "<html><title>Portal</title></html>",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "html",
                "file": body_name,
                "url": "http://10.10.10.10/portal",
            }
        )

    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "scope_file": "scope.md",
        "created_by": "test",
        "profile": "test-profile",
        "artifacts": artifacts,
    }
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return input_dir, scope


def _write_deep_pipeline_metadata(
    input_dir: Path,
    *,
    final_status: str,
    target: str = "10.10.10.10",
    output_dir: Path | None = None,
    step_statuses: dict[str, str] | None = None,
) -> None:
    payload = {
        "schema_version": "1.0",
        "target": target,
        "project_file": str(input_dir / "bugslyce_project.json"),
        "output_dir": str(output_dir or input_dir),
        "profile": "deep-bounded",
        "final_status": final_status,
        "steps": [
            {"step_id": step_id, "status": status}
            for step_id, status in (step_statuses or {}).items()
        ],
    }
    (input_dir / "project_pipeline.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _write_deep_artifacts(input_dir: Path) -> None:
    for name in (
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
    ):
        (input_dir / name).write_text(f"{name}\n", encoding="utf-8")
