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
    STANDARD_PIPELINE_PROFILE,
    run_project_pipeline,
)
from bugslyce.project_session import scaffold_project
from bugslyce.recon.body_fetch import BodyFetchNoWork
from bugslyce.recon.content_followup import ContentFollowupNoWork
from bugslyce.recon.path_followup import PathFollowupNoWork


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
    assert "--resume" in captured.out


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


def test_cli_project_run_forwards_resume(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    received: dict[str, object] = {}

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace(
            project_name="pipeline-test",
            target="10.10.10.10",
            profile=PIPELINE_PROFILE,
            project_file=str(project_file),
            output_dir=str(output_dir),
            resume_requested=True,
            completed_steps=3,
            skipped_steps=9,
            no_op_steps=0,
            final_status="completed",
            steps=[
                SimpleNamespace(
                    step_id=f"PIPELINE-STEP-{index:03d}",
                    status="completed" if index == 10 else "skipped_existing",
                )
                for index in range(1, 11)
            ],
            report_path=str(output_dir / "report.md"),
            runbook_path=str(output_dir / "runbook.md"),
            export_path=f"{output_dir}-evidence-pack.zip",
        )

    monkeypatch.setattr("bugslyce.cli.run_project_pipeline", fake_pipeline)
    exit_code = main(
        [
            "project",
            "run",
            "--project",
            str(project_file),
            "--profile",
            PIPELINE_PROFILE,
            "--confirm",
            "--resume",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert received["resume"] is True
    assert received["project_file"] == project_file
    assert "Resume: true" in captured.out
    assert "Step summary:" in captured.out
    assert "* Completed: 3" in captured.out
    assert "* Skipped existing: 9" in captured.out
    assert "* No-op: 0" in captured.out
    assert "Final outputs:" in captured.out
    assert f"less {output_dir / 'report.md'}" in captured.out


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
    runbook_sections: list[str | None] = []

    def fake_build_project_runbook(
        project_file_arg,
        clock=None,
        standard_investigation_workflow_markdown=None,
    ):
        calls.append("runbook")
        runbook_sections.append(standard_investigation_workflow_markdown)
        return SimpleNamespace(
            runbook_path=str(output_dir / "runbook.md"),
            content=standard_investigation_workflow_markdown or "",
        )

    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_runbook",
        fake_build_project_runbook,
    )

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
    assert runbook_sections == [None]
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
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "## Summary" in markdown
    assert "- Completed steps: `12`" in markdown
    assert "- Skipped existing steps: `0`" in markdown
    assert "## Final Outputs" in markdown
    assert f"- Recon status: `{output_dir / 'recon_status.md'}`" in markdown
    assert f"- Pipeline metadata JSON: `{json_path}`" in markdown
    assert f"- Pipeline metadata Markdown: `{markdown_path}`" in markdown
    assert "## Suggested Review Commands" in markdown
    assert f"less {output_dir / 'report.md'}" in markdown
    assert "No NSE scripts, UDP scans, brute force" in markdown


def test_standard_pipeline_reuses_bounded_steps_and_writes_manual_review_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)

    project_state = SimpleNamespace(project_name="pipeline-test")
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_state",
        lambda path: project_state,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.generate_candidates",
        lambda state: [],
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.assemble_standard_interpretation_from_project_state",
        lambda state: SimpleNamespace(
            manual_review_leads_markdown="\n".join(
                [
                    "## Manual Review Leads",
                    "",
                    (
                        "These leads are derived from collected evidence and "
                        "should be treated as manual review prompts, not proof "
                        "of vulnerability."
                    ),
                    "",
                    "### LEAD-0001: Possible hash candidate detected.",
                ]
            ),
            review_leads=(),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_investigation_threads",
        lambda state, candidates, review_leads: (),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_investigation_threads_markdown",
        lambda threads, **kwargs: "",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_standard_investigation_workflow_runbook_section",
        lambda threads, **kwargs: "## Standard Investigation Workflow\n\n### THREAD-0001: High-port HTTP application review\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_route_source_review",
        lambda state, sources: (),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_route_source_review_markdown",
        lambda leads, **kwargs: "## Offline Route/Source Review\n\nNo offline route/source review leads were generated from the collected evidence.\n",
    )
    runbook_sections: list[str | None] = []
    route_sections: list[str | None] = []

    def fake_build_project_runbook(
        project_file_arg,
        clock=None,
        standard_investigation_workflow_markdown=None,
    ):
        calls.append("runbook")
        runbook_sections.append(standard_investigation_workflow_markdown)
        return SimpleNamespace(
            runbook_path=str(output_dir / "runbook.md"),
            content=standard_investigation_workflow_markdown or "",
        )

    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_runbook",
        fake_build_project_runbook,
    )

    def fake_write_project_outputs(
        state,
        candidates,
        output_path,
        *,
        manual_review_leads_markdown=None,
        investigation_threads_markdown=None,
        route_source_review_markdown=None,
    ):
        calls.append("standard-report-write")
        route_sections.append(route_source_review_markdown)
        report_path = output_path / "report.md"
        json_path = output_path / "project_state.json"
        report_path.write_text(
            "# Report\n\n"
            "## Operator Summary\n\n"
            f"{manual_review_leads_markdown}\n\n"
            f"{route_source_review_markdown}\n\n"
            "## Scope Summary\n",
            encoding="utf-8",
        )
        json_path.write_text("{}\n", encoding="utf-8")
        return report_path, json_path

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_project_outputs",
        fake_write_project_outputs,
    )

    result = run_project_pipeline(
        project_file,
        STANDARD_PIPELINE_PROFILE,
        clock=lambda: FIXED_TIME,
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
        "standard-report-write",
        "status",
        "status-write",
        "runbook",
        "runbook-write",
        "export",
    ]
    assert result.profile == STANDARD_PIPELINE_PROFILE
    assert result.report_path == str(output_dir / "report.md")
    assert [step.status for step in result.steps] == ["completed"] * 12
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    assert "## Manual Review Leads" in report
    assert report.index("## Operator Summary") < report.index("## Manual Review Leads")
    assert report.index("## Manual Review Leads") < report.index("## Scope Summary")
    assert "not proof of vulnerability" in report
    assert runbook_sections == [
        "## Standard Investigation Workflow\n\n### THREAD-0001: High-port HTTP application review\n"
    ]
    assert route_sections == [
        "## Offline Route/Source Review\n\nNo offline route/source review leads were generated from the collected evidence.\n"
    ]
    payload = json.loads((output_dir / PIPELINE_JSON_FILENAME).read_text(encoding="utf-8"))
    assert payload["profile"] == STANDARD_PIPELINE_PROFILE


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


def test_pipeline_records_path_followup_noop_and_continues_to_content_plan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_path_followup_workflow",
        lambda *args, **kwargs: (_ for _ in ()).throw(PathFollowupNoWork(5)),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_path_followup_execution_result",
        lambda *args, **kwargs: pytest.fail("no-op should not write path-followup metadata"),
    )
    progress: list[str] = []

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        clock=lambda: FIXED_TIME,
        progress_callback=progress.append,
    )

    assert result.final_status == "completed"
    assert result.steps[4].status == "noop"
    assert result.no_op_steps == 1
    assert "path-followup-write" not in calls
    assert "content-plan" in calls
    assert calls.index("content-plan") < calls.index("content-run")
    assert "[5/12] discovered-path follow-up no-op" in progress
    assert "export" in calls


def test_resume_skips_existing_prefix_and_runs_next_missing_phase(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_resume_evidence(
        output_dir,
        [
            "nmap-allports.txt",
            "nmap-services-all.txt",
            "curl-headers-10.10.10.10-80.txt",
        ],
    )
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_path_followup_workflow",
        lambda *args, **kwargs: (_ for _ in ()).throw(PathFollowupNoWork(4)),
    )
    progress: list[str] = []

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        resume=True,
        clock=lambda: FIXED_TIME,
        progress_callback=progress.append,
    )

    assert "nmap-discover" not in calls
    assert "nmap-services" not in calls
    assert "http-metadata" not in calls
    assert "path-followup" not in calls
    assert calls[0] == "content-plan"
    assert [step.status for step in result.steps[:4]] == [
        "completed",
        "skipped_existing",
        "skipped_existing",
        "skipped_existing",
    ]
    assert result.steps[4].status == "noop"
    assert result.resume_requested is True
    assert result.reused_existing_evidence is True
    assert result.skipped_steps == 3
    assert result.no_op_steps == 1
    assert "Resume: true" in progress[0]
    assert (
        "[2/12] nmap full TCP discovery skipped.\n"
        "Existing nmap discovery evidence detected; phase skipped during resume."
        in progress
    )
    assert (
        "[3/12] nmap service/version scan skipped.\n"
        "Existing service/version evidence detected; phase skipped during resume."
        in progress
    )
    assert (
        "[4/12] HTTP metadata collection skipped.\n"
        "Existing HTTP metadata evidence detected; phase skipped during resume."
        in progress
    )
    assert "[5/12] discovered-path follow-up no-op" in progress
    payload = json.loads(
        (output_dir / PIPELINE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert payload["resume_requested"] is True
    assert payload["reused_existing_evidence"] is True
    assert payload["skipped_steps"] == 3
    assert "Resume requested: `true`" in (
        output_dir / PIPELINE_MARKDOWN_FILENAME
    ).read_text(encoding="utf-8")


def test_resume_uses_valid_tiny_plan_and_skips_content_plan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_resume_evidence(
        output_dir,
        [
            "nmap-allports.txt",
            "nmap-services-all.txt",
            "curl-headers-10.10.10.10-80.txt",
            "curl-headers-followup-10.10.10.10-80-manual.txt",
        ],
    )
    plan_path = _write_plan_file(output_dir)
    _patch_plan_loader(monkeypatch, project_file, output_dir, plan_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        resume=True,
        clock=lambda: FIXED_TIME,
    )

    assert result.steps[5].status == "skipped_existing"
    assert "content-plan" not in calls
    assert "content-run" in calls


def test_resume_records_followup_noops_and_continues(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_resume_evidence(
        output_dir,
        [
            "nmap-allports.txt",
            "nmap-services-all.txt",
            "curl-headers-10.10.10.10-80.txt",
            "curl-headers-followup-10.10.10.10-80-manual.txt",
            "gobuster-tiny-10.10.10.10-80-root.txt",
        ],
    )
    plan_path = _write_plan_file(output_dir)
    _patch_plan_loader(monkeypatch, project_file, output_dir, plan_path)
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
        resume=True,
        clock=lambda: FIXED_TIME,
    )

    assert result.steps[7].status == "noop"
    assert result.steps[8].status == "noop"
    assert result.no_op_steps == 2
    assert result.steps[9].status == "completed"
    assert result.steps[10].status == "completed"
    assert result.steps[11].status == "completed"


def test_resume_refuses_target_and_content_plan_mismatches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_resume_evidence(output_dir, ["nmap-allports.txt"], target="192.0.2.10")
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    with pytest.raises(ValueError, match="does not match the existing recon manifest"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)

    _write_resume_evidence(
        output_dir,
        [
            "nmap-allports.txt",
            "nmap-services-all.txt",
            "curl-headers-10.10.10.10-80.txt",
            "curl-headers-followup-10.10.10.10-80-manual.txt",
        ],
    )
    plan_path = _write_plan_file(output_dir)
    project = json.loads(project_file.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        "bugslyce.project_pipeline.load_content_discovery_plan",
        lambda path: SimpleNamespace(
            target="192.0.2.10",
            profile="lab-root-tiny",
            input_dir=str(output_dir),
            output_dir=str(plan_path.parent),
            scope_file=project["scope_file"],
        ),
    )
    with pytest.raises(ValueError, match="Existing content plan does not match"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)


def test_resume_refuses_prior_pipeline_profile_mismatch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    _write_prior_pipeline(project_file, output_dir, export_path)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )

    with pytest.raises(
        ValueError,
        match="Prior pipeline metadata profile does not match this run",
    ):
        run_project_pipeline(
            project_file,
            STANDARD_PIPELINE_PROFILE,
            resume=True,
        )


def test_resume_refuses_incoherent_or_missing_manifest_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    _write_resume_evidence(output_dir, ["nmap-services-all.txt"])
    with pytest.raises(ValueError, match="not a coherent pipeline prefix"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)

    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "artifacts": [{"type": "nmap", "file": "nmap-allports.txt"}],
    }
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="references missing artifact"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)


def test_resume_rejects_manifest_artifact_path_escape(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("not project evidence\n", encoding="utf-8")
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "artifacts": [{"type": "nmap", "file": "../outside.txt"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )

    with pytest.raises(ValueError, match="escapes the project output directory"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)


def test_resume_export_requires_verified_completion_and_can_be_skipped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    export_path.write_bytes(b"existing")
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    with pytest.raises(ValueError, match="completed prior pipeline cannot be verified"):
        run_project_pipeline(project_file, PIPELINE_PROFILE, resume=True)

    artifact_names = [
        "nmap-allports.txt",
        "nmap-services-all.txt",
        "curl-headers-10.10.10.10-80.txt",
        "curl-headers-followup-10.10.10.10-80-manual.txt",
        "gobuster-tiny-10.10.10.10-80-root.txt",
        "curl-headers-content-followup-10.10.10.10-80-admin.txt",
        "body-fetch-10.10.10.10-80-admin.html",
    ]
    _write_resume_evidence(output_dir, artifact_names)
    plan_path = _write_plan_file(output_dir)
    _patch_plan_loader(monkeypatch, project_file, output_dir, plan_path)
    _write_prior_pipeline(project_file, output_dir, export_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    progress: list[str] = []

    result = run_project_pipeline(
        project_file,
        PIPELINE_PROFILE,
        resume=True,
        clock=lambda: FIXED_TIME,
        progress_callback=progress.append,
    )

    assert calls == ["status", "status-write", "runbook", "runbook-write"]
    assert result.steps[11].status == "skipped_existing"
    assert result.steps[11].message == (
        "Existing completed evidence pack detected; export skipped during resume."
    )
    assert result.export_path == str(export_path)
    assert result.final_status == "completed"
    assert (
        "[12/12] evidence pack export skipped.\n"
        "Existing completed evidence pack detected; export skipped during resume."
        in progress
    )
    assert result.steps[4].message.startswith(
            "Existing evidence-derived path follow-up artefacts"
    )
    assert result.steps[5].message.startswith(
        "Existing lab-root-tiny content plan"
    )
    assert result.steps[6].message.startswith(
        "Existing lab-root-tiny content discovery output"
    )
    assert result.steps[7].message.startswith(
        "Existing content-result follow-up artefacts"
    )
    assert result.steps[8].message.startswith(
        "Existing selective body-fetch artefacts"
    )


def test_resumed_required_failure_stops_later_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_resume_evidence(output_dir, ["nmap-allports.txt"])
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)

    def fail_services(*args, **kwargs):
        calls.append("nmap-services")
        raise ValueError("mocked resumed service failure")

    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_service_workflow",
        fail_services,
    )

    with pytest.raises(ProjectPipelineFailed) as exc_info:
        run_project_pipeline(
            project_file,
            PIPELINE_PROFILE,
            resume=True,
            clock=lambda: FIXED_TIME,
        )

    result = exc_info.value.result
    assert result.steps[1].status == "skipped_existing"
    assert result.steps[2].status == "failed"
    assert result.failed_step == "PIPELINE-STEP-003"
    assert result.steps[3].status == "pending"
    assert "http-metadata" not in calls


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
        bugslyce_version="0.3.0",
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


def _write_resume_evidence(
    output_dir: Path,
    names: list[str],
    *,
    target: str = "10.10.10.10",
) -> None:
    artifacts = []
    for name in names:
        (output_dir / name).write_text("local fixture evidence\n", encoding="utf-8")
        artifact_type = "nmap" if name.startswith("nmap-") else "http_headers"
        if name.startswith("gobuster"):
            artifact_type = "gobuster"
        elif name.startswith("body-fetch-"):
            artifact_type = "html"
        artifacts.append({"type": artifact_type, "file": name})
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": target,
                "profile": "lab-tcp-full",
                "artifacts": artifacts,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_plan_file(output_dir: Path) -> Path:
    plan_dir = Path(f"{output_dir}-content-plan-tiny")
    plan_dir.mkdir(parents=True, exist_ok=True)
    plan_path = plan_dir / "content_discovery_plan.json"
    plan_path.write_text("{}\n", encoding="utf-8")
    return plan_path


def _patch_plan_loader(
    monkeypatch,
    project_file: Path,
    output_dir: Path,
    plan_path: Path,
) -> None:
    project = json.loads(project_file.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        "bugslyce.project_pipeline.load_content_discovery_plan",
        lambda path: SimpleNamespace(
            target="10.10.10.10",
            profile="lab-root-tiny",
            input_dir=str(output_dir),
            output_dir=str(plan_path.parent),
            scope_file=project["scope_file"],
        ),
    )


def _write_prior_pipeline(
    project_file: Path,
    output_dir: Path,
    export_path: Path,
) -> None:
    (output_dir / PIPELINE_JSON_FILENAME).write_text(
        json.dumps(
            {
                "target": "10.10.10.10",
                "profile": PIPELINE_PROFILE,
                "project_file": str(project_file.resolve()),
                "output_dir": str(output_dir.resolve()),
                "final_status": "completed",
                "export_path": str(export_path.resolve()),
                "steps": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
