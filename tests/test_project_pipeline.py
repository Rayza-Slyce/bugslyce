"""Tests for the confirmed, fixed-profile project pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from typing import get_type_hints
import zipfile

import pytest

from bugslyce.cli import main
from bugslyce.doctor import DoctorReport
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    DeepPipelineOutputs,
    PIPELINE_JSON_FILENAME,
    PIPELINE_MARKDOWN_FILENAME,
    PARTIAL_DEEP_RESUME_MESSAGE,
    PIPELINE_PROFILE,
    ProjectPipelineFailed,
    STANDARD_PIPELINE_PROFILE,
    run_project_pipeline,
)
from bugslyce.project_session import scaffold_project
from bugslyce.recon.body_fetch import BodyFetchNoWork
from bugslyce.recon.content_followup import ContentFollowupNoWork
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_TINY_PROFILE,
    STANDARD_BOUNDED_CORE_PROFILE,
)
from bugslyce.recon.path_followup import PathFollowupNoWork
from bugslyce.recon.status import build_recon_status, render_recon_status_markdown


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
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_human_triage_brief",
        lambda state, candidates, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_human_triage_brief_markdown",
        lambda brief: "## Human Triage Brief\n\nNo high-confidence manual triage leads were identified from the collected evidence.\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_readable_evidence_cards_markdown",
        lambda brief: "## Readable Evidence Cards\n\nNo high-value evidence cards were generated from the collected evidence.\n",
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
        human_triage_brief_markdown=None,
        manual_review_leads_markdown=None,
        investigation_threads_markdown=None,
        route_source_review_markdown=None,
        readable_evidence_cards_markdown=None,
    ):
        calls.append("standard-report-write")
        route_sections.append(route_source_review_markdown)
        report_path = output_path / "report.md"
        json_path = output_path / "project_state.json"
        report_path.write_text(
            "# Report\n\n"
            "## Operator Summary\n\n"
            f"{human_triage_brief_markdown}\n\n"
            f"{manual_review_leads_markdown}\n\n"
            f"{route_source_review_markdown}\n\n"
            f"{readable_evidence_cards_markdown}\n\n"
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
    assert "## Human Triage Brief" in report
    assert "## Manual Review Leads" in report
    assert "## Readable Evidence Cards" in report
    assert report.index("## Operator Summary") < report.index("## Human Triage Brief")
    assert report.index("## Human Triage Brief") < report.index("## Manual Review Leads")
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


def test_project_pipeline_selects_standard_bounded_core_content_profile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_project, quick_output = _fresh_project(tmp_path / "quick")
    standard_project, standard_output = _fresh_project(tmp_path / "standard")
    observed: list[tuple[str, str]] = []

    def fake_build_content_plan(*, input_dir, scope_file, profile, output_dir):
        observed.append((Path(input_dir).name, profile))
        return SimpleNamespace(profile=profile)

    for project_file, output_dir, profile in (
        (quick_project, quick_output, PIPELINE_PROFILE),
        (standard_project, standard_output, STANDARD_PIPELINE_PROFILE),
    ):
        calls: list[str] = []
        _patch_successful_pipeline(monkeypatch, output_dir, calls)
        monkeypatch.setattr(
            "bugslyce.project_pipeline.build_content_discovery_plan",
            fake_build_content_plan,
        )
        if profile == STANDARD_PIPELINE_PROFILE:
            monkeypatch.setattr(
                "bugslyce.project_pipeline.build_project_state",
                lambda path: SimpleNamespace(project_name="pipeline-test"),
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.generate_candidates",
                lambda state: [],
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.assemble_standard_interpretation_from_project_state",
                lambda state: SimpleNamespace(
                    manual_review_leads_markdown="## Manual Review Leads\n",
                    review_leads=(),
                    sources=(),
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
                "bugslyce.project_pipeline.build_route_source_review",
                lambda state, sources: (),
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.render_route_source_review_markdown",
                lambda leads, **kwargs: "",
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.build_human_triage_brief",
                lambda state, candidates, **kwargs: SimpleNamespace(),
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.render_human_triage_brief_markdown",
                lambda brief: "",
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.render_readable_evidence_cards_markdown",
                lambda brief: "",
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.render_standard_investigation_workflow_runbook_section",
                lambda threads, **kwargs: "",
            )
            monkeypatch.setattr(
                "bugslyce.project_pipeline.write_project_outputs",
                lambda state, candidates, output_path, **kwargs: (
                    output_path / "report.md",
                    output_path / "project_state.json",
                ),
            )

        run_project_pipeline(project_file, profile, clock=lambda: FIXED_TIME)

    assert observed == [
        (quick_output.name, CONTENT_DISCOVERY_TINY_PROFILE),
        (standard_output.name, STANDARD_BOUNDED_CORE_PROFILE),
    ]
    assert STANDARD_PIPELINE_PROFILE == "standard-bounded"


def test_deep_pipeline_runs_bounded_collectors_and_threads_phase_93_seams(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)

    source_collection = SimpleNamespace(kind="source-collection")
    shallow_followups = SimpleNamespace(kind="shallow-followups")
    orchestration = SimpleNamespace(
        deep_recon_markdown="## Deep Collection Review\n\nDeep report block.\n",
        deep_recon_runbook_markdown="## Deep Recon Review Guide\n\nDeep runbook block.\n",
    )
    identities: dict[str, object] = {}
    captured_report: list[str | None] = []
    captured_runbook: list[str | None] = []
    captured_evidence_paths: list[tuple[Path, ...] | None] = []
    checkpoint_seen: list[dict[str, str]] = []

    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_state",
        lambda path: SimpleNamespace(project_name="pipeline-test"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_collection_request_plan_from_project_state",
        lambda state: calls.append("deep-plan") or SimpleNamespace(kind="deep-plan"),
    )

    def fake_collect_source(plan, *, fetcher):
        calls.append("deep-source-collect")
        identities["source_fetcher"] = fetcher
        return source_collection

    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_source_routes_from_plan",
        fake_collect_source,
    )

    def fake_write_source(result, output_path):
        calls.append("deep-source-write")
        assert result is source_collection
        markdown_path = output_path / "deep_source_route_collection.md"
        json_path = output_path / "deep_source_route_collection.json"
        markdown_path.write_text("# Deep Source\n", encoding="utf-8")
        json_path.write_text("{}\n", encoding="utf-8")
        return markdown_path, json_path

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_source_route_collection_artifacts",
        fake_write_source,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_html_route_extraction",
        lambda result: calls.append("deep-html-routes") or SimpleNamespace(kind="html"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_javascript_route_extraction",
        lambda result: calls.append("deep-js-routes") or SimpleNamespace(kind="js"),
    )

    def fake_build_followup_plan(html_routes, javascript_routes):
        calls.append("deep-shallow-plan")
        return SimpleNamespace(kind="shallow-plan")

    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_shallow_route_followup_plan",
        fake_build_followup_plan,
    )

    def fake_collect_shallow(plan, *, fetcher):
        calls.append("deep-shallow-collect")
        identities["shallow_fetcher"] = fetcher
        return shallow_followups

    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_shallow_route_followups",
        fake_collect_shallow,
    )

    def fake_orchestrate(source_arg, shallow_arg):
        calls.append("deep-orchestrate")
        identities["orchestration_source"] = source_arg
        identities["orchestration_shallow"] = shallow_arg
        return orchestration

    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_recon_orchestration",
        fake_orchestrate,
    )

    def fake_write_orchestration(result, output_path, *, force=False):
        calls.append("deep-orchestration-write")
        assert result is orchestration
        paths = (
            output_path / "deep_recon_review.md",
            output_path / "deep_recon_runbook.md",
            output_path / "deep_recon_orchestration.json",
        )
        for path in paths:
            path.write_text(path.name + "\n", encoding="utf-8")
        return paths

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_recon_orchestration_artifacts",
        fake_write_orchestration,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.assemble_standard_interpretation_from_project_state",
        lambda state: SimpleNamespace(
            manual_review_leads_markdown="## Manual Review Leads\n\nStandard leads.\n",
            review_leads=(),
            sources=(),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_investigation_threads",
        lambda state, candidates, review_leads: (),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_investigation_threads_markdown",
        lambda threads, **kwargs: "## Investigation Threads\n\nStandard threads.\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_route_source_review",
        lambda state, sources: (),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_route_source_review_markdown",
        lambda leads, **kwargs: "## Offline Route/Source Review\n\nStandard route review.\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_human_triage_brief",
        lambda state, candidates, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_human_triage_brief_markdown",
        lambda brief: "## Human Triage Brief\n\nStandard triage.\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_readable_evidence_cards_markdown",
        lambda brief: "## Readable Evidence Cards\n\nStandard cards.\n",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_standard_investigation_workflow_runbook_section",
        lambda threads, **kwargs: "## Standard Investigation Workflow\n\nStandard guidance.\n",
    )
    monkeypatch.setattr("bugslyce.project_pipeline.generate_candidates", lambda state: [])

    def fake_build_status(input_dir, scope_file=None, clock=None):
        calls.append("status-build")
        payload = json.loads((output_dir / PIPELINE_JSON_FILENAME).read_text(encoding="utf-8"))
        statuses = {
            step["step_id"]: step["status"]
            for step in payload["steps"]
        }
        assert payload["profile"] == DEEP_PIPELINE_PROFILE
        assert payload["final_status"] == "running"
        assert payload["target"] == "10.10.10.10"
        assert Path(payload["output_dir"]).resolve() == output_dir
        assert statuses["PIPELINE-STEP-010D"] == "completed"
        assert statuses["PIPELINE-STEP-011D"] == "completed"
        checkpoint_seen.append(statuses)
        return SimpleNamespace(
            artifact_overview={
                "deep_pipeline_phases_detected": 2,
                "deep_pipeline_phases_total": 2,
            }
        )

    def fake_write_status(result, output_path):
        calls.append("status-write")
        json_path = output_path / "recon_status.json"
        markdown_path = output_path / "recon_status.md"
        json_path.write_text(
            json.dumps({"artifact_overview": result.artifact_overview}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        markdown_path.write_text(
            "# BugSlyce Recon Status\n\n"
            "- Pipeline profile: `deep-bounded`\n"
            "- Deep pipeline phases: 2/2\n",
            encoding="utf-8",
        )
        return json_path, markdown_path

    monkeypatch.setattr("bugslyce.project_pipeline.build_recon_status", fake_build_status)
    monkeypatch.setattr("bugslyce.project_pipeline.write_recon_status", fake_write_status)

    def fake_write_outputs(
        state,
        candidates,
        output_path,
        *,
        deep_recon_markdown=None,
        **kwargs,
    ):
        calls.append("deep-report-write")
        captured_report.append(deep_recon_markdown)
        report_path = output_path / "report.md"
        json_path = output_path / "project_state.json"
        report_path.write_text(deep_recon_markdown or "", encoding="utf-8")
        json_path.write_text("{}\n", encoding="utf-8")
        return report_path, json_path

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_project_outputs",
        fake_write_outputs,
    )

    def fake_runbook(project_file_arg, **kwargs):
        calls.append("runbook")
        captured_runbook.append(kwargs.get("deep_recon_runbook_markdown"))
        identities["runbook_standard"] = kwargs.get(
            "standard_investigation_workflow_markdown"
        )
        return SimpleNamespace(
            runbook_path=str(output_dir / "runbook.md"),
            content=kwargs.get("deep_recon_runbook_markdown") or "",
        )

    monkeypatch.setattr("bugslyce.project_pipeline.build_project_runbook", fake_runbook)

    def fake_export(input_dir, output_path, **kwargs):
        calls.append("export")
        captured_evidence_paths.append(kwargs.get("deep_evidence_paths"))
        with zipfile.ZipFile(output_path, "w") as archive:
            archive.write(input_dir / "recon_status.md", "recon_status.md")
            archive.write(input_dir / "recon_status.json", "recon_status.json")
        return SimpleNamespace(output_path=str(output_path))

    monkeypatch.setattr("bugslyce.project_pipeline.export_recon_evidence_pack", fake_export)

    result = run_project_pipeline(
        project_file,
        DEEP_PIPELINE_PROFILE,
        clock=lambda: FIXED_TIME,
    )

    step_ids = [step.step_id for step in result.steps]
    assert step_ids == [
        "PIPELINE-STEP-001",
        "PIPELINE-STEP-002",
        "PIPELINE-STEP-003",
        "PIPELINE-STEP-004",
        "PIPELINE-STEP-005",
        "PIPELINE-STEP-006",
        "PIPELINE-STEP-007",
        "PIPELINE-STEP-008",
        "PIPELINE-STEP-009",
        "PIPELINE-STEP-010D",
        "PIPELINE-STEP-011D",
        "PIPELINE-STEP-010",
        "PIPELINE-STEP-011",
        "PIPELINE-STEP-012",
    ]
    assert result.profile == "deep-bounded"
    assert result.final_status == "completed"
    assert result.completed_steps == 14
    assert calls.count("deep-source-collect") == 1
    assert calls.count("deep-shallow-collect") == 1
    assert calls.count("deep-orchestrate") == 1
    assert calls.count("deep-orchestration-write") == 1
    assert identities["orchestration_source"] is source_collection
    assert identities["orchestration_shallow"] is shallow_followups
    assert identities["source_fetcher"] is identities["shallow_fetcher"]
    assert captured_report == [orchestration.deep_recon_markdown]
    assert captured_runbook == [orchestration.deep_recon_runbook_markdown]
    assert checkpoint_seen
    assert identities["runbook_standard"] == (
        "## Standard Investigation Workflow\n\nStandard guidance.\n"
    )
    assert captured_evidence_paths == [
        (
            output_dir / "deep_source_route_collection.md",
            output_dir / "deep_source_route_collection.json",
            output_dir / "deep_recon_review.md",
            output_dir / "deep_recon_runbook.md",
            output_dir / "deep_recon_orchestration.json",
        )
    ]
    assert calls.index("body-fetch") < calls.index("deep-source-collect")
    assert calls.index("deep-shallow-collect") < calls.index("deep-orchestrate")
    assert calls.index("deep-orchestration-write") < calls.index("deep-report-write")
    assert calls.index("deep-orchestration-write") < calls.index("export")
    assert "- Deep pipeline phases: 2/2" in (output_dir / "recon_status.md").read_text(
        encoding="utf-8"
    )
    status_payload = json.loads((output_dir / "recon_status.json").read_text(encoding="utf-8"))
    assert status_payload["artifact_overview"]["deep_pipeline_phases_detected"] == 2
    with zipfile.ZipFile(f"{output_dir}-evidence-pack.zip") as archive:
        assert "- Deep pipeline phases: 2/2" in archive.read("recon_status.md").decode(
            "utf-8"
        )
        packed_status = json.loads(archive.read("recon_status.json").decode("utf-8"))
    assert packed_status["artifact_overview"]["deep_pipeline_phases_detected"] == 2


def test_deep_pipeline_selects_standard_bounded_core_content_profile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    observed: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_content_discovery_plan",
        lambda **kwargs: observed.append(kwargs["profile"]) or SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_state",
        lambda path: SimpleNamespace(project_name="pipeline-test"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_collection_request_plan_from_project_state",
        lambda state: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_source_routes_from_plan",
        lambda plan, *, fetcher: SimpleNamespace(),
    )

    def fake_write_source_for_profile(result, output_path):
        paths = (
            output_path / "deep_source_route_collection.md",
            output_path / "deep_source_route_collection.json",
        )
        for path in paths:
            path.write_text(path.name + "\n", encoding="utf-8")
        return paths

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_source_route_collection_artifacts",
        fake_write_source_for_profile,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_html_route_extraction",
        lambda result: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_javascript_route_extraction",
        lambda result: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_shallow_route_followup_plan",
        lambda html, js: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_shallow_route_followups",
        lambda plan, *, fetcher: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_recon_orchestration",
        lambda source, shallow: SimpleNamespace(
            deep_recon_markdown="## Deep\n",
            deep_recon_runbook_markdown="## Guide\n",
        ),
    )

    def fake_write_orchestration_for_profile(result, output_path, **kwargs):
        paths = (
            output_path / "deep_recon_review.md",
            output_path / "deep_recon_runbook.md",
            output_path / "deep_recon_orchestration.json",
        )
        for path in paths:
            path.write_text(path.name + "\n", encoding="utf-8")
        return paths

    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_recon_orchestration_artifacts",
        fake_write_orchestration_for_profile,
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.assemble_standard_interpretation_from_project_state",
        lambda state: SimpleNamespace(
            manual_review_leads_markdown="## Manual Review Leads\n",
            review_leads=(),
            sources=(),
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
        "bugslyce.project_pipeline.build_route_source_review",
        lambda state, sources: (),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_route_source_review_markdown",
        lambda leads, **kwargs: "",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_human_triage_brief",
        lambda state, candidates, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_human_triage_brief_markdown",
        lambda brief: "",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_readable_evidence_cards_markdown",
        lambda brief: "",
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.render_standard_investigation_workflow_runbook_section",
        lambda threads, **kwargs: "",
    )
    monkeypatch.setattr("bugslyce.project_pipeline.generate_candidates", lambda state: [])
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_project_outputs",
        lambda state, candidates, output_path, **kwargs: (
            output_path / "report.md",
            output_path / "project_state.json",
        ),
    )

    run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE, clock=lambda: FIXED_TIME)

    assert observed == [STANDARD_BOUNDED_CORE_PROFILE]


def test_deep_pipeline_outputs_uses_concrete_result_types() -> None:
    hints = get_type_hints(DeepPipelineOutputs)

    assert "DeepSourceRouteCollectionResult" in str(hints["source_collection"])
    assert "DeepShallowRouteFollowupResult" in str(hints["shallow_followups"])
    assert "DeepReconOrchestrationResult" in str(hints["orchestration"])


@pytest.mark.parametrize(
    "deep_statuses",
    (
        {"PIPELINE-STEP-010D": "running"},
        {"PIPELINE-STEP-010D": "completed"},
        {"PIPELINE-STEP-010D": "completed", "PIPELINE-STEP-011D": "failed"},
    ),
)
def test_deep_partial_resume_rejects_before_live_calls(
    tmp_path: Path,
    monkeypatch,
    deep_statuses: dict[str, str],
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    _write_prior_pipeline(
        project_file,
        output_dir,
        Path(f"{output_dir}-evidence-pack.zip"),
        profile=DEEP_PIPELINE_PROFILE,
        final_status="failed",
        step_statuses=deep_statuses,
    )
    _patch_live_calls_to_fail(monkeypatch)

    with pytest.raises(ValueError, match="Partial Deep pipeline state"):
        run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE, resume=True)


@pytest.mark.parametrize(
    "artefact_name",
    (
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
    ),
)
def test_deep_resume_rejects_existing_deep_artefact_without_completed_metadata(
    tmp_path: Path,
    monkeypatch,
    artefact_name: str,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    (output_dir / artefact_name).write_text("partial\n", encoding="utf-8")
    _patch_live_calls_to_fail(monkeypatch)

    with pytest.raises(ValueError, match="Partial Deep pipeline state"):
        run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE, resume=True)


def test_deep_completed_resume_skips_deep_tail_and_preserves_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    _write_completed_deep_resume_state(project_file, output_dir, export_path)
    _patch_plan_loader_for_profile(
        monkeypatch,
        project_file,
        output_dir,
        _write_plan_file(output_dir, profile=STANDARD_BOUNDED_CORE_PROFILE),
        STANDARD_BOUNDED_CORE_PROFILE,
    )
    _patch_live_calls_to_fail(monkeypatch)
    for dotted_name in (
        "build_recon_status",
        "write_recon_status",
        "build_project_runbook",
        "write_project_runbook",
    ):
        monkeypatch.setattr(
            f"bugslyce.project_pipeline.{dotted_name}",
            lambda *args, _name=dotted_name, **kwargs: pytest.fail(
                f"{_name} must not be called"
            ),
        )
    canonical_paths = (
        output_dir / PIPELINE_JSON_FILENAME,
        output_dir / PIPELINE_MARKDOWN_FILENAME,
        output_dir / "report.md",
        output_dir / "recon_status.md",
        output_dir / "recon_status.json",
        output_dir / "runbook.md",
        export_path,
    )
    before = {path: path.read_bytes() for path in canonical_paths}

    result = run_project_pipeline(
        project_file,
        DEEP_PIPELINE_PROFILE,
        resume=True,
        clock=lambda: FIXED_TIME,
    )

    statuses = {step.step_id: step.status for step in result.steps}
    assert statuses["PIPELINE-STEP-009"] == "skipped_existing"
    assert statuses["PIPELINE-STEP-010D"] == "skipped_existing"
    assert statuses["PIPELINE-STEP-011D"] == "skipped_existing"
    assert statuses["PIPELINE-STEP-010"] == "skipped_existing"
    assert statuses["PIPELINE-STEP-011"] == "skipped_existing"
    assert statuses["PIPELINE-STEP-012"] == "skipped_existing"
    assert result.report_path == str(output_dir / "report.md")
    assert result.runbook_path == str(output_dir / "runbook.md")
    assert result.export_path == str(export_path)
    assert result.completed_steps == 1
    assert result.skipped_steps == 13
    markdown = (output_dir / PIPELINE_MARKDOWN_FILENAME).read_text(encoding="utf-8")
    assert f"- Report: `{output_dir / 'report.md'}`" in markdown
    assert f"- Recon status: `{output_dir / 'recon_status.md'}`" in markdown
    assert f"- Runbook: `{output_dir / 'runbook.md'}`" in markdown
    assert f"- Evidence pack: `{export_path}`" in markdown
    assert {path: path.read_bytes() for path in canonical_paths} == before
    prior_payload = json.loads((output_dir / PIPELINE_JSON_FILENAME).read_text(encoding="utf-8"))
    prior_statuses = {
        step["step_id"]: step["status"]
        for step in prior_payload["steps"]
    }
    assert prior_statuses["PIPELINE-STEP-009"] == "noop"
    assert prior_statuses["PIPELINE-STEP-010D"] == "completed"
    assert prior_statuses["PIPELINE-STEP-011D"] == "completed"
    assert prior_statuses["PIPELINE-STEP-010"] == "completed"
    assert prior_statuses["PIPELINE-STEP-011"] == "completed"
    assert prior_statuses["PIPELINE-STEP-012"] == "completed"
    rendered_status = render_recon_status_markdown(build_recon_status(output_dir))
    assert "- Pipeline profile: `deep-bounded`" in rendered_status
    assert "- Deep pipeline phases: 2/2" in rendered_status

    second_result = run_project_pipeline(
        project_file,
        DEEP_PIPELINE_PROFILE,
        resume=True,
        clock=lambda: FIXED_TIME,
    )

    assert second_result.completed_steps == 1
    assert second_result.skipped_steps == 13
    assert {path: path.read_bytes() for path in canonical_paths} == before


def test_deep_completed_resume_requires_all_fixed_artefacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    _write_completed_deep_resume_state(project_file, output_dir, export_path)
    (output_dir / "deep_recon_orchestration.json").unlink()
    _patch_live_calls_to_fail(monkeypatch)

    with pytest.raises(ValueError, match="Partial Deep pipeline state"):
        run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE, resume=True)


def test_deep_completed_resume_rejects_mismatched_recorded_export_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    _write_completed_deep_resume_state(project_file, output_dir, export_path)
    _write_prior_pipeline(
        project_file,
        output_dir,
        tmp_path / "other-evidence-pack.zip",
        profile=DEEP_PIPELINE_PROFILE,
        final_status="completed",
        step_statuses={
            "PIPELINE-STEP-002": "completed",
            "PIPELINE-STEP-003": "completed",
            "PIPELINE-STEP-004": "completed",
            "PIPELINE-STEP-005": "completed",
            "PIPELINE-STEP-006": "completed",
            "PIPELINE-STEP-007": "completed",
            "PIPELINE-STEP-008": "completed",
            "PIPELINE-STEP-009": "noop",
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
            "PIPELINE-STEP-010": "completed",
            "PIPELINE-STEP-011": "completed",
            "PIPELINE-STEP-012": "completed",
        },
    )
    _patch_live_calls_to_fail(monkeypatch)

    with pytest.raises(ValueError, match="Partial Deep pipeline state"):
        run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE, resume=True)


@pytest.mark.parametrize(
    "artefact_name",
    (
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
    ),
)
def test_deep_fresh_run_rejects_existing_fixed_artefact_before_live_calls(
    tmp_path: Path,
    monkeypatch,
    artefact_name: str,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    (output_dir / artefact_name).write_text("existing\n", encoding="utf-8")
    _patch_live_calls_to_fail(monkeypatch)

    with pytest.raises(ValueError, match="Existing Deep artefact detected"):
        run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE)


def test_deep_report_requires_orchestration(
    tmp_path: Path,
) -> None:
    from bugslyce import project_pipeline

    with pytest.raises(ValueError, match="Deep orchestration is required"):
        project_pipeline._write_interpretation_report_if_needed(
            DEEP_PIPELINE_PROFILE,
            tmp_path,
            {"deep_outputs": DeepPipelineOutputs()},
        )


def test_deep_export_requires_existing_five_path_tuple(tmp_path: Path) -> None:
    from bugslyce import project_pipeline

    outputs = DeepPipelineOutputs(
        deep_artifact_paths=(
            tmp_path / "deep_source_route_collection.md",
            tmp_path / "deep_source_route_collection.json",
        )
    )
    with pytest.raises(ValueError, match="Deep evidence artefacts are incomplete"):
        project_pipeline._deep_evidence_paths_required(
            DEEP_PIPELINE_PROFILE,
            {"deep_outputs": outputs},
        )


def test_deep_source_writer_oserror_records_collection_step_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    _patch_minimal_deep_collection(monkeypatch, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_source_route_collection_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.export_recon_evidence_pack",
        lambda *args, **kwargs: pytest.fail("export must not run after Deep failure"),
    )

    with pytest.raises(ProjectPipelineFailed) as exc_info:
        run_project_pipeline(
            project_file,
            DEEP_PIPELINE_PROFILE,
            clock=lambda: FIXED_TIME,
        )

    result = exc_info.value.result
    assert result.failed_step == "PIPELINE-STEP-010D"
    assert result.steps[9].status == "failed"
    assert result.steps[10].status == "pending"
    assert result.steps[13].status == "pending"


def test_deep_orchestration_writer_oserror_records_orchestration_step_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file, output_dir = _fresh_project(tmp_path)
    calls: list[str] = []
    _patch_successful_pipeline(monkeypatch, output_dir, calls)
    _patch_minimal_deep_collection(monkeypatch, calls)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_source_route_collection_artifacts",
        lambda result, output_path: _write_named_files(
            output_path,
            ("deep_source_route_collection.md", "deep_source_route_collection.json"),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_deep_recon_orchestration_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.export_recon_evidence_pack",
        lambda *args, **kwargs: pytest.fail("export must not run after Deep failure"),
    )

    with pytest.raises(ProjectPipelineFailed) as exc_info:
        run_project_pipeline(
            project_file,
            DEEP_PIPELINE_PROFILE,
            clock=lambda: FIXED_TIME,
        )

    result = exc_info.value.result
    assert result.failed_step == "PIPELINE-STEP-011D"
    assert result.steps[9].status == "completed"
    assert result.steps[10].status == "failed"
    assert result.steps[13].status == "pending"


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
        "Existing bounded content plan"
    )
    assert result.steps[6].message.startswith(
        "Existing bounded content discovery output"
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


def _write_plan_file(
    output_dir: Path,
    *,
    profile: str = CONTENT_DISCOVERY_TINY_PROFILE,
) -> Path:
    suffix = "tiny" if profile == CONTENT_DISCOVERY_TINY_PROFILE else "standard-bounded-core"
    plan_dir = Path(f"{output_dir}-content-plan-{suffix}")
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
    _patch_plan_loader_for_profile(
        monkeypatch,
        project_file,
        output_dir,
        plan_path,
        CONTENT_DISCOVERY_TINY_PROFILE,
    )


def _patch_plan_loader_for_profile(
    monkeypatch,
    project_file: Path,
    output_dir: Path,
    plan_path: Path,
    profile: str,
) -> None:
    project = json.loads(project_file.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        "bugslyce.project_pipeline.load_content_discovery_plan",
        lambda path: SimpleNamespace(
            target="10.10.10.10",
            profile=profile,
            input_dir=str(output_dir),
            output_dir=str(plan_path.parent),
            scope_file=project["scope_file"],
        ),
    )


def _write_prior_pipeline(
    project_file: Path,
    output_dir: Path,
    export_path: Path,
    *,
    profile: str = PIPELINE_PROFILE,
    final_status: str = "completed",
    step_statuses: dict[str, str] | None = None,
) -> None:
    payload = {
        "target": "10.10.10.10",
        "profile": profile,
        "project_file": str(project_file.resolve()),
        "output_dir": str(output_dir.resolve()),
        "final_status": final_status,
        "export_path": str(export_path.resolve()),
        "steps": [
            {"step_id": step_id, "status": status}
            for step_id, status in (step_statuses or {}).items()
        ],
    }
    (output_dir / PIPELINE_JSON_FILENAME).write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )
    (output_dir / PIPELINE_MARKDOWN_FILENAME).write_text(
        "# Prior Pipeline\n\n"
        f"- Profile: `{profile}`\n"
        f"- Final status: `{final_status}`\n"
        f"- Report: `{output_dir / 'report.md'}`\n"
        f"- Recon status: `{output_dir / 'recon_status.md'}`\n"
        f"- Runbook: `{output_dir / 'runbook.md'}`\n"
        f"- Evidence pack: `{export_path}`\n",
        encoding="utf-8",
    )


def _write_named_files(output_dir: Path, names: tuple[str, ...]) -> tuple[Path, ...]:
    paths = tuple(output_dir / name for name in names)
    for path in paths:
        path.write_text(path.name + "\n", encoding="utf-8")
    return paths


def _write_completed_deep_resume_state(
    project_file: Path,
    output_dir: Path,
    export_path: Path,
) -> None:
    _write_resume_evidence(
        output_dir,
        [
            "nmap-allports.txt",
            "nmap-services-all.txt",
            "curl-headers-10.10.10.10-80.txt",
            "curl-headers-followup-10.10.10.10-80-manual.txt",
            "gobuster-tiny-10.10.10.10-80-root.txt",
            "curl-headers-content-followup-10.10.10.10-80-admin.txt",
            "body-fetch-10.10.10.10-80-admin.html",
        ],
    )
    _write_named_files(
        output_dir,
        (
            "report.md",
            "recon_status.md",
            "recon_status.json",
            "runbook.md",
            "deep_source_route_collection.md",
            "deep_source_route_collection.json",
            "deep_recon_review.md",
            "deep_recon_runbook.md",
            "deep_recon_orchestration.json",
        ),
    )
    export_path.write_bytes(b"zip")
    _write_prior_pipeline(
        project_file,
        output_dir,
        export_path,
        profile=DEEP_PIPELINE_PROFILE,
        final_status="completed",
        step_statuses={
            "PIPELINE-STEP-002": "completed",
            "PIPELINE-STEP-003": "completed",
            "PIPELINE-STEP-004": "completed",
            "PIPELINE-STEP-005": "completed",
            "PIPELINE-STEP-006": "completed",
            "PIPELINE-STEP-007": "completed",
            "PIPELINE-STEP-008": "completed",
            "PIPELINE-STEP-009": "noop",
            "PIPELINE-STEP-010D": "completed",
            "PIPELINE-STEP-011D": "completed",
            "PIPELINE-STEP-010": "completed",
            "PIPELINE-STEP-011": "completed",
            "PIPELINE-STEP-012": "completed",
        },
    )


def _patch_live_calls_to_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_doctor_report",
        lambda: _doctor(),
    )
    for dotted_name in (
        "run_nmap_discovery_workflow",
        "run_nmap_service_workflow",
        "run_http_metadata_workflow",
        "run_path_followup_workflow",
        "run_content_discovery_workflow",
        "run_content_followup_workflow",
        "run_body_fetch_workflow",
        "collect_deep_source_routes_from_plan",
        "collect_deep_shallow_route_followups",
        "build_deep_recon_orchestration",
        "export_recon_evidence_pack",
    ):
        monkeypatch.setattr(
            f"bugslyce.project_pipeline.{dotted_name}",
            lambda *args, _name=dotted_name, **kwargs: pytest.fail(
                f"{_name} must not be called"
            ),
        )


def _patch_minimal_deep_collection(monkeypatch, calls: list[str]) -> None:
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_state",
        lambda path: SimpleNamespace(
            project_name="pipeline-test",
            http_artifacts=(),
            evidence=(),
            engagement_context="unknown",
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_collection_request_plan_from_project_state",
        lambda state: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_source_routes_from_plan",
        lambda plan, *, fetcher: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_html_route_extraction",
        lambda result: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_javascript_route_extraction",
        lambda result: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_shallow_route_followup_plan",
        lambda html, js: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.collect_deep_shallow_route_followups",
        lambda plan, *, fetcher: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_deep_recon_orchestration",
        lambda source, shallow: SimpleNamespace(
            deep_recon_markdown="## Deep\n",
            deep_recon_runbook_markdown="## Guide\n",
        ),
    )
