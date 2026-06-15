"""Plan-driven orchestration for one approved BugSlyce project pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable

from bugslyce.doctor import DoctorReport, build_doctor_report
from bugslyce.project_session import (
    build_project_runbook,
    load_project,
    write_project_runbook,
)
from bugslyce.recon.body_fetch import (
    BodyFetchExecutionIncomplete,
    BodyFetchNoWork,
    run_body_fetch_workflow,
    write_body_fetch_execution_result,
)
from bugslyce.recon.content_followup import (
    ContentFollowupExecutionIncomplete,
    ContentFollowupNoWork,
    run_content_followup_workflow,
    write_content_followup_execution_result,
)
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_TINY_PROFILE,
    build_content_discovery_plan,
    write_content_discovery_plan,
)
from bugslyce.recon.content_run import (
    ContentDiscoveryExecutionIncomplete,
    run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.http_metadata import (
    run_http_metadata_workflow,
    write_http_metadata_execution_result,
)
from bugslyce.recon.nmap_discover import (
    run_nmap_discovery_workflow,
    write_nmap_discovery_execution_result,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.nmap_services import (
    run_nmap_service_workflow,
    write_nmap_service_execution_result,
)
from bugslyce.recon.path_followup import (
    run_path_followup_workflow,
    write_path_followup_execution_result,
)
from bugslyce.recon.status import build_recon_status, write_recon_status
from bugslyce.time_utils import Clock, utc_now_iso


PIPELINE_PROFILE = "lab-safe-tiny"
PIPELINE_JSON_FILENAME = "project_pipeline.json"
PIPELINE_MARKDOWN_FILENAME = "project_pipeline.md"


@dataclass(frozen=True)
class PipelineStep:
    """One recorded project pipeline stage."""

    step_id: str
    name: str
    command_kind: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    message: str = ""
    output_paths: list[str] | None = None


@dataclass(frozen=True)
class PipelineResult:
    """Serializable result for one project pipeline execution."""

    project_name: str
    target: str
    profile: str
    project_file: str
    scope_file: str
    output_dir: str
    started_at: str
    completed_at: str | None
    final_status: str
    steps: list[PipelineStep]
    report_path: str | None
    runbook_path: str | None
    export_path: str | None
    no_unapproved_actions: bool


class ProjectPipelineFailed(ValueError):
    """Raised after a started pipeline records one failed required step."""

    def __init__(self, message: str, result: PipelineResult) -> None:
        super().__init__(message)
        self.result = result


def run_project_pipeline(
    project_file: Path,
    profile: str,
    *,
    clock: Clock | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> PipelineResult:
    """Run the fixed approved lab-safe-tiny project chain."""

    if profile != PIPELINE_PROFILE:
        raise ValueError(
            f"Unsupported project pipeline profile '{profile}'. "
            f"Supported profile: {PIPELINE_PROFILE}."
        )

    project_file = project_file.expanduser().resolve()
    project = load_project(project_file)
    output_dir = Path(project.output_dir).expanduser().resolve()
    scope_file = Path(project.scope_file).expanduser().resolve()
    plan_dir = Path(f"{output_dir}-content-plan-tiny")
    plan_path = plan_dir / "content_discovery_plan.json"
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    _validate_fresh_pipeline(
        project.target,
        scope_file,
        output_dir,
        plan_dir,
        export_path,
        build_doctor_report(),
    )

    steps = _pending_steps()
    result = PipelineResult(
        project_name=project.name,
        target=project.target,
        profile=profile,
        project_file=str(project_file),
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        started_at=utc_now_iso(clock),
        completed_at=None,
        final_status="running",
        steps=steps,
        report_path=None,
        runbook_path=None,
        export_path=None,
        no_unapproved_actions=True,
    )
    _emit(
        progress_callback,
        "\n".join(
            [
                "BugSlyce project pipeline starting",
                f"Project: {project.name}",
                f"Target: {project.target}",
                f"Profile: {profile}",
                "This pipeline performs bounded live recon against the project target.",
                "Review scope before running.",
            ]
        ),
    )

    context: dict[str, object] = {
        "project_file": project_file,
        "scope_file": scope_file,
        "output_dir": output_dir,
        "plan_dir": plan_dir,
        "plan_path": plan_path,
        "export_path": export_path,
        "target": project.target,
    }
    step_runners = _step_runners(context, clock)
    for index, step in enumerate(result.steps):
        position = index + 1
        _emit(progress_callback, f"[{position}/12] {step.name} starting...")
        started_step = replace(step, status="running", started_at=utc_now_iso(clock))
        result = _replace_step(result, index, started_step)
        try:
            message, output_paths, updates = step_runners[step.step_id]()
        except (ContentFollowupNoWork, BodyFetchNoWork) as outcome:
            completed_step = replace(
                started_step,
                status="noop",
                completed_at=utc_now_iso(clock),
                message=str(outcome),
                output_paths=[],
            )
            result = _replace_step(result, index, completed_step)
            _emit(progress_callback, f"[{position}/12] {step.name} no-op")
            continue
        except (
            ContentDiscoveryExecutionIncomplete,
            ContentFollowupExecutionIncomplete,
            BodyFetchExecutionIncomplete,
        ) as exc:
            _write_incomplete_phase_metadata(exc, output_dir, plan_dir)
            result = _failed_result(
                result,
                index,
                started_step,
                str(exc),
                clock,
            )
            write_project_pipeline_result(result)
            _emit(progress_callback, f"[{position}/12] {step.name} failed")
            raise ProjectPipelineFailed(str(exc), result) from exc
        except ValueError as exc:
            result = _failed_result(
                result,
                index,
                started_step,
                str(exc),
                clock,
            )
            write_project_pipeline_result(result)
            _emit(progress_callback, f"[{position}/12] {step.name} failed")
            raise ProjectPipelineFailed(str(exc), result) from exc

        completed_step = replace(
            started_step,
            status="completed",
            completed_at=utc_now_iso(clock),
            message=message,
            output_paths=output_paths,
        )
        result = _replace_step(result, index, completed_step)
        result = replace(result, **updates)
        _emit(progress_callback, f"[{position}/12] {step.name} complete")

    result = replace(
        result,
        completed_at=utc_now_iso(clock),
        final_status="completed",
    )
    write_project_pipeline_result(result)
    return result


def write_project_pipeline_result(result: PipelineResult) -> tuple[Path, Path]:
    """Write project pipeline JSON and Markdown inside its output directory."""

    output_dir = Path(result.output_dir).expanduser().resolve()
    json_path = output_dir / PIPELINE_JSON_FILENAME
    markdown_path = output_dir / PIPELINE_MARKDOWN_FILENAME
    json_path.write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_project_pipeline_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_project_pipeline_markdown(result: PipelineResult) -> str:
    """Render detailed pipeline execution metadata."""

    lines = [
        "# BugSlyce Project Pipeline",
        "",
        f"- Project: `{result.project_name}`",
        f"- Target: `{result.target}`",
        f"- Profile: `{result.profile}`",
        f"- Project file: `{result.project_file}`",
        f"- Scope file: `{result.scope_file}`",
        f"- Output directory: `{result.output_dir}`",
        f"- Started at: `{result.started_at}`",
        f"- Completed at: `{result.completed_at or 'not completed'}`",
        f"- Final status: `{result.final_status}`",
        f"- No unapproved actions: `{str(result.no_unapproved_actions).lower()}`",
        "",
        "## Steps",
        "",
    ]
    for step in result.steps:
        lines.extend(
            [
                f"### {step.step_id}: {step.name}",
                "",
                f"- Kind: `{step.command_kind}`",
                f"- Status: `{step.status}`",
                f"- Started at: `{step.started_at or 'not started'}`",
                f"- Completed at: `{step.completed_at or 'not completed'}`",
                f"- Message: {step.message or 'none'}",
                (
                    "- Output paths: "
                    + (
                        ", ".join(f"`{path}`" for path in step.output_paths)
                        if step.output_paths
                        else "none"
                    )
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## Final Outputs",
            "",
            f"- Report: `{result.report_path or 'not written'}`",
            f"- Runbook: `{result.runbook_path or 'not written'}`",
            f"- Evidence pack: `{result.export_path or 'not written'}`",
            "",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
            "",
        ]
    )
    return "\n".join(lines)


def render_project_pipeline_summary(result: PipelineResult) -> str:
    """Render a concise final pipeline summary."""

    return "\n".join(
        [
            "BugSlyce project pipeline complete",
            f"Project: {result.project_name}",
            f"Target: {result.target}",
            f"Profile: {result.profile}",
            f"Final status: {result.final_status}",
            f"Report path: {result.report_path or 'not written'}",
            f"Runbook path: {result.runbook_path or 'not written'}",
            f"Evidence pack path: {result.export_path or 'not written'}",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
        ]
    )


def _validate_fresh_pipeline(
    target: str,
    scope_file: Path,
    output_dir: Path,
    plan_dir: Path,
    export_path: Path,
    doctor: DoctorReport,
) -> None:
    if not output_dir.is_dir():
        raise ValueError(f"Project output directory does not exist: {output_dir}")
    validate_explicit_nmap_target_scope(target, scope_file)
    if (output_dir / "recon_manifest.json").exists():
        raise ValueError(
            "Existing recon pack detected. Use project status/next or start with "
            "a clean project directory."
        )
    if plan_dir.exists():
        raise ValueError(f"Content plan directory already exists: {plan_dir}")
    if export_path.exists():
        raise ValueError(f"Evidence pack output already exists: {export_path}")
    if not doctor.python_supported or not doctor.project_commands_available:
        raise ValueError("BugSlyce doctor reports required runtime checks are not ready.")
    if not doctor.bundled_wordlist_available:
        raise ValueError("Bundled lab-root-tiny wordlist is unavailable.")
    missing_tools = [
        tool for tool in ("nmap", "curl", "gobuster") if not doctor.tool_paths.get(tool)
    ]
    if missing_tools:
        raise ValueError(
            "Required pipeline tools are not available on PATH: "
            + ", ".join(missing_tools)
            + "."
        )


def _pending_steps() -> list[PipelineStep]:
    definitions = [
        ("PIPELINE-STEP-001", "environment and project validation", "local-validation"),
        ("PIPELINE-STEP-002", "nmap full TCP discovery", "nmap-discover"),
        ("PIPELINE-STEP-003", "nmap service/version scan", "nmap-services"),
        ("PIPELINE-STEP-004", "HTTP metadata collection", "http-metadata"),
        ("PIPELINE-STEP-005", "discovered-path follow-up", "path-followup"),
        ("PIPELINE-STEP-006", "tiny content discovery planning", "content-plan"),
        ("PIPELINE-STEP-007", "tiny content discovery execution", "content-run"),
        ("PIPELINE-STEP-008", "content-result follow-up", "content-followup"),
        ("PIPELINE-STEP-009", "selective body fetch", "body-fetch"),
        ("PIPELINE-STEP-010", "recon status", "status"),
        ("PIPELINE-STEP-011", "project runbook", "runbook"),
        ("PIPELINE-STEP-012", "evidence pack export", "export"),
    ]
    return [
        PipelineStep(
            step_id=step_id,
            name=name,
            command_kind=kind,
            status="pending",
            output_paths=[],
        )
        for step_id, name, kind in definitions
    ]


def _step_runners(
    context: dict[str, object],
    clock: Clock | None,
) -> dict[str, Callable[[], tuple[str, list[str], dict[str, str | None]]]]:
    output_dir = context["output_dir"]
    scope_file = context["scope_file"]
    plan_dir = context["plan_dir"]
    plan_path = context["plan_path"]
    export_path = context["export_path"]
    target = context["target"]
    project_file = context["project_file"]
    assert isinstance(output_dir, Path)
    assert isinstance(scope_file, Path)
    assert isinstance(plan_dir, Path)
    assert isinstance(plan_path, Path)
    assert isinstance(export_path, Path)
    assert isinstance(target, str)
    assert isinstance(project_file, Path)

    def validation():
        return "Local readiness, fresh output, and exact scope checks passed.", [], {}

    def nmap_discover():
        result = run_nmap_discovery_workflow(
            target=target,
            scope_file=scope_file,
            output_dir=output_dir,
            profile_name="lab-tcp-full",
        )
        metadata = write_nmap_discovery_execution_result(result, output_dir)
        return (
            "One approved lab-tcp-full discovery completed.",
            [result.nmap_output_path, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def nmap_services():
        result = run_nmap_service_workflow(output_dir, scope_file)
        metadata = write_nmap_service_execution_result(result, output_dir)
        return (
            "Service/version detection completed on discovered open TCP ports.",
            [result.nmap_output_path, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def http_metadata():
        result = run_http_metadata_workflow(output_dir, scope_file)
        metadata = write_http_metadata_execution_result(result, output_dir)
        return (
            "HTTP metadata collection completed for discovered services.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def path_followup():
        result = run_path_followup_workflow(output_dir, scope_file)
        metadata = write_path_followup_execution_result(result, output_dir)
        return (
            "Evidence-derived same-origin path follow-up completed.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def content_plan():
        plan = build_content_discovery_plan(
            input_dir=output_dir,
            scope_file=scope_file,
            profile=CONTENT_DISCOVERY_TINY_PROFILE,
            output_dir=plan_dir,
        )
        json_path, markdown_path = write_content_discovery_plan(plan, plan_dir)
        return (
            "Approved lab-root-tiny content plan created.",
            [str(json_path), str(markdown_path)],
            {},
        )

    def content_run():
        result = run_content_discovery_workflow(plan_path, scope_file)
        metadata = write_content_discovery_execution_result(result, plan_dir)
        return (
            "Approved lab-root-tiny content discovery completed.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def content_followup():
        result = run_content_followup_workflow(output_dir, scope_file)
        metadata = write_content_followup_execution_result(result, output_dir)
        return (
            "Content-discovery result follow-up completed.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def body_fetch():
        result = run_body_fetch_workflow(output_dir, scope_file)
        metadata = write_body_fetch_execution_result(result, output_dir)
        return (
            "Selective body fetch completed.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def status():
        result = build_recon_status(output_dir, scope_file, clock=clock)
        json_path, markdown_path = write_recon_status(result, output_dir)
        return (
            "Local recon status generated.",
            [str(json_path), str(markdown_path)],
            {},
        )

    def runbook():
        result = build_project_runbook(project_file, clock=clock)
        runbook_path = write_project_runbook(result)
        return (
            "Project runbook generated.",
            [str(runbook_path)],
            {"runbook_path": str(runbook_path)},
        )

    def export():
        result = export_recon_evidence_pack(
            output_dir,
            export_path,
            clock=clock,
        )
        return (
            "Portable evidence pack exported.",
            [result.output_path],
            {"export_path": result.output_path},
        )

    return {
        "PIPELINE-STEP-001": validation,
        "PIPELINE-STEP-002": nmap_discover,
        "PIPELINE-STEP-003": nmap_services,
        "PIPELINE-STEP-004": http_metadata,
        "PIPELINE-STEP-005": path_followup,
        "PIPELINE-STEP-006": content_plan,
        "PIPELINE-STEP-007": content_run,
        "PIPELINE-STEP-008": content_followup,
        "PIPELINE-STEP-009": body_fetch,
        "PIPELINE-STEP-010": status,
        "PIPELINE-STEP-011": runbook,
        "PIPELINE-STEP-012": export,
    }


def _failed_result(
    result: PipelineResult,
    index: int,
    started_step: PipelineStep,
    message: str,
    clock: Clock | None,
) -> PipelineResult:
    failed_step = replace(
        started_step,
        status="failed",
        completed_at=utc_now_iso(clock),
        message=message,
        output_paths=[],
    )
    return replace(
        _replace_step(result, index, failed_step),
        completed_at=utc_now_iso(clock),
        final_status="failed",
    )


def _replace_step(
    result: PipelineResult,
    index: int,
    step: PipelineStep,
) -> PipelineResult:
    steps = list(result.steps)
    steps[index] = step
    return replace(result, steps=steps)


def _write_incomplete_phase_metadata(exc, output_dir: Path, plan_dir: Path) -> None:
    if isinstance(exc, ContentDiscoveryExecutionIncomplete):
        write_content_discovery_execution_result(exc.result, plan_dir)
    elif isinstance(exc, ContentFollowupExecutionIncomplete):
        write_content_followup_execution_result(exc.result, output_dir)
    elif isinstance(exc, BodyFetchExecutionIncomplete):
        write_body_fetch_execution_result(exc.result, output_dir)


def _emit(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)
