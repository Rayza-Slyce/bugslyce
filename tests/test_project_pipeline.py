"""Tests for the confirmed, fixed-profile project pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce.cli import main
from bugslyce.doctor import DoctorReport
from bugslyce.project_pipeline import (
    PIPELINE_JSON_FILENAME,
    PIPELINE_MARKDOWN_FILENAME,
    PIPELINE_PROFILE,
    ProjectPipelineFailed,
    run_project_pipeline,
)
from bugslyce.project_session import scaffold_project
from bugslyce.recon.body_fetch import BodyFetchNoWork
from bugslyce.recon.content_followup import ContentFollowupNoWork


FIXED_TIME = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_project_run_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "run", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce project run" in captured.out
    assert "--project" in captured.out
    assert "--profile" in captured.out
    assert "--confirm" in captured.out


def test_cli_project_run_requires_confirm(tmp_path: Path, monkeypatch, capsys) -> None:
    project_file, _output_dir = _fresh_project(tmp_path)

    def fail_pipeline(*args, **kwargs):
        raise AssertionError("pipeline must not start without confirmation")

    monkeypatch.setattr("bugslyce.cli.run_project_pipeline", fail_pipeline)
    exit_code = main(
        [
            "project",
            "run",
            "--project",
            str(project_file),
            "--profile",
            PIPELINE_PROFILE,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "requires explicit --confirm" in captured.err
    assert "No pipeline phase was executed." in captured.err


def test_pipeline_rejects_unsupported_profile_and_invalid_project(
    tmp_path: Path,
) -> None:
    project_file, _output_dir = _fresh_project(tmp_path)
    with pytest.raises(ValueError, match="Unsupported project pipeline profile"):
        run_project_pipeline(project_file, "other-profile")

    with pytest.raises(ValueError, match="Project file does not exist"):
        run_project_pipeline(tmp_path / "missing.json", PIPELINE_PROFILE)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not parse project file"):
        run_project_pipeline(malformed, PIPELINE_PROFILE)


def test_pipeline_rejects_scope_readiness_and_existing_outputs_before_live_phases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_discovery_workflow",
        lambda *args, **kwargs: pytest.fail("live phase should not start"),
    )

    scope = output_dir / "scope.md"
    scope.write_text(
        "# Scope\n\n## In Scope\n\n* 192.0.2.20\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not explicitly listed"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)

    scope.write_text(
        "# Scope\n\n## In Scope\n\n* 10.10.10.10\n",
        encoding="utf-8",
    )
    (output_dir / "recon_manifest.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Existing recon pack detected"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)
    (output_dir / "recon_manifest.json").unlink()

    export_path = Path(f"{output_dir}-evidence-pack.zip")
    export_path.write_bytes(b"existing")
    with pytest.raises(ValueError, match="Evidence pack output already exists"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)


def test_pipeline_rejects_missing_scope_and_existing_plan_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_discovery_workflow",
        lambda *args, **kwargs: pytest.fail("live phase should not start"),
    )

    scope = output_dir / "scope.md"
    scope.unlink()
    with pytest.raises(ValueError, match="scope file does not exist"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)

    scope.write_text(
        "# Scope\n\n## In Scope\n\n* 10.10.10.10\n",
        encoding="utf-8",
    )
    plan_dir = Path(f"{output_dir}-content-plan-tiny")
    plan_dir.mkdir()
    with pytest.raises(ValueError, match="Content plan directory already exists"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)


@pytest.mark.parametrize(
    ("doctor_kwargs", "message"),
    [
        ({"gobuster": None}, "Required pipeline tools"),
        ({"bundled": False}, "Bundled lab-root-tiny"),
    ],
)
def test_pipeline_stops_on_missing_required_readiness(
    tmp_path: Path,
    monkeypatch,
    doctor_kwargs: dict[str, object],
    message: str,
) -> None:
    project_file, _output_dir = _fresh_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(**doctor_kwargs),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_discovery_workflow",
        lambda *args, **kwargs: pytest.fail("live phase should not start"),
    )

    with pytest.raises(ValueError, match=message):
        run_project_pipeline(project_file, PIPELINE_PROFILE)


def test_fresh_pipeline_runs_all_steps_in_order_and_writes_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    progress: list[str] = []

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        clock=lambda: FIXED_TIME,
        progress_callback=progress.append,
    )

    assert calls == [
        "nmap-discover",
        "nmap-discover-write",
        "nmap-services",
        "nmap-services-write",
        "http-metadata",
        "http-metadata-write",
        "path-followup",
        "path-followup-write",
        "content-plan",
        "content-plan-write",
        "content-run",
        "content-run-write",
        "content-followup",
        "content-followup-write",
        "body-fetch",
        "body-fetch-write",
        "status",
        "status-write",
        "runbook",
        "runbook-write",
        "export",
    ]
    assert result.final_status == "completed"
    assert [step.status for step in result.steps] == ["completed"] * 12
    assert result.report_path == str(output_dir / "report.md")
    assert result.runbook_path == str(output_dir / "runbook.md")
    assert result.export_path == f"{output_dir}-evidence-pack.zip"
    assert "[1/12] environment and project validation starting..." in progress
    assert "[12/12] evidence pack export complete" in progress

    json_path = output_dir / PIPELINE_JSON_FILENAME
    markdown_path = output_dir / PIPELINE_MARKDOWN_FILENAME
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert markdown_path.is_file()
    assert payload["profile"] == PIPELINE_PROFILE
    assert payload["target"] == "10.10.10.10"
    assert payload["final_status"] == "completed"
    assert payload["no_unapproved_actions"] is True
    assert len(payload["steps"]) == 12
    assert "No NSE scripts, UDP scans, brute force" in markdown_path.read_text(
        encoding="utf-8"
    )


def test_pipeline_records_noop_followups_and_continues(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_content_followup_workflow",
        lambda *args, **kwargs: (_ for _ in ()).throw(ContentFollowupNoWork(4)),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_body_fetch_workflow",
        lambda *args, **kwargs: (_ for _ in ()).throw(BodyFetchNoWork(2)),
    )

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        clock=lambda: FIXED_TIME,
    )

    assert result.steps[7].status == "noop"
    assert result.steps[8].status == "noop"
    assert result.steps[9].status == "completed"
    assert result.steps[11].status == "completed"
    assert "content-followup-write" not in calls
    assert "body-fetch-write" not in calls
    assert "export" in calls


def test_pipeline_stops_on_required_failure_and_records_pending_later_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)

    def fail_http(*args, **kwargs):
        calls.append("http-metadata")
        raise ValueError("mocked HTTP failure")

    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_http_metadata_workflow",
        fail_http,
    )

    with pytest.raises(ProjectPipelineFailed) as exc_info:
        run_project_pipeline(
            project_file,
            PIPELINE_PROFILE,
            clock=lambda: FIXED_TIME,
        )

    result = exc_info.value.result
    assert result.final_status == "failed"
    assert result.steps[3].status == "failed"
    assert result.steps[4].status == "pending"
    assert "path-followup" not in calls
    assert "export" not in calls
    payload = json.loads(
        (output_dir / PIPELINE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert payload["steps"][3]["message"] == "mocked HTTP failure"
    assert payload["steps"][4]["status"] == "pending"


def test_project_pipeline_module_has_no_direct_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "project_pipeline.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "shell=True" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source


def _fresh_project(tmp_path: Path) -> tuple[Path, Path]:
    scaffold = scaffold_project("pipeline-test", "10.10.10.10", tmp_path / "projects")
    return Path(scaffold.project_file), Path(scaffold.project.output_dir)


def _doctor(
    *,
    nmap: str | None = "/usr/bin/nmap",
    curl: str | None = "/usr/bin/curl",
    gobuster: str | None = "/usr/bin/gobuster",
    bundled: bool = True,
) -> DoctorReport:
    return DoctorReport(
        bugslyce_version="0.1.0",
        python_version="3.12.3",
        python_supported=True,
        virtual_environment=True,
        platform_summary="Linux",
        current_working_directory="/tmp",
        tool_paths={"nmap": nmap, "curl": curl, "gobuster": gobuster},
        bundled_wordlist_available=bundled,
        bundled_wordlist_path="/package/lab-root-tiny.txt" if bundled else None,
        dirbuster_wordlist_available=False,
        dirbuster_wordlist_path="/usr/share/wordlists/dirbuster/small.txt",
        project_commands_available=True,
        readiness="ready",
        warnings=(),
    )


def _patch_successful_pipeline(
    monkeypatch,
    output_dir: Path,
    calls: list[str],
) -> None:
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )

    def phase(name: str, **attributes):
        def run(*args, **kwargs):
            calls.append(name)
            return SimpleNamespace(**attributes)

        return run

    def writer(name: str):
        def write(*args, **kwargs):
            calls.append(name)
            return output_dir / f"{name}.json", output_dir / f"{name}.md"

        return write

    report = str(output_dir / "report.md")
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_discovery_workflow",
        phase(
            "nmap-discover",
            nmap_output_path=str(output_dir / "nmap-allports.txt"),
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_nmap_discovery_execution_result",
        writer("nmap-discover-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_service_workflow",
        phase(
            "nmap-services",
            nmap_output_path=str(output_dir / "nmap-services-all.txt"),
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_nmap_service_execution_result",
        writer("nmap-services-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_http_metadata_workflow",
        phase(
            "http-metadata",
            artifact_paths=[str(output_dir / "homepage.html")],
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_http_metadata_execution_result",
        writer("http-metadata-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_path_followup_workflow",
        phase(
            "path-followup",
            artifact_paths=[str(output_dir / "followup.txt")],
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_path_followup_execution_result",
        writer("path-followup-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_content_discovery_plan",
        phase("content-plan"),
    )

    def write_plan(*args, **kwargs):
        calls.append("content-plan-write")
        plan_dir = Path(f"{output_dir}-content-plan-tiny")
        plan_dir.mkdir(parents=True, exist_ok=True)
        json_path = plan_dir / "content_discovery_plan.json"
        markdown_path = plan_dir / "content_discovery_plan.md"
        json_path.write_text("{}\n", encoding="utf-8")
        markdown_path.write_text("# Plan\n", encoding="utf-8")
        return json_path, markdown_path

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_content_discovery_plan",
        write_plan,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_content_discovery_workflow",
        phase(
            "content-run",
            artifact_paths=[str(output_dir / "gobuster.txt")],
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_content_discovery_execution_result",
        writer("content-run-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_content_followup_workflow",
        phase(
            "content-followup",
            artifact_paths=[str(output_dir / "content-followup.txt")],
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_content_followup_execution_result",
        writer("content-followup-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_body_fetch_workflow",
        phase(
            "body-fetch",
            artifact_paths=[str(output_dir / "body.html")],
            report_path=report,
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_body_fetch_execution_result",
        writer("body-fetch-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_recon_status",
        phase("status"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_recon_status",
        writer("status-write"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_runbook",
        phase("runbook"),
    )

    def write_runbook(*args, **kwargs):
        calls.append("runbook-write")
        path = output_dir / "runbook.md"
        path.write_text("# Runbook\n", encoding="utf-8")
        return path

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_project_runbook",
        write_runbook,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.export_recon_evidence_pack",
        phase("export", output_path=f"{output_dir}-evidence-pack.zip"),
    )
