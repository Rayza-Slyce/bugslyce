"""Plan-driven orchestration for one approved BugSlyce project pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable

from bugslyce.doctor import DoctorReport, build_doctor_report
from bugslyce.core.project import build_project_state
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
    load_content_discovery_plan,
    run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.http_metadata import (
    run_http_metadata_workflow,
    write_http_metadata_execution_result,
)
from bugslyce.recon.investigation_threads import (
    build_investigation_threads,
    render_investigation_threads_markdown,
    render_standard_investigation_workflow_runbook_section,
)
from bugslyce.recon.modes import QUICK_RECON_PROFILE, STANDARD_RECON_PROFILE
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
    PathFollowupNoWork,
    run_path_followup_workflow,
    write_path_followup_execution_result,
)
from bugslyce.recon.route_source_review import (
    build_route_source_review,
    render_route_source_review_markdown,
)
from bugslyce.recon.status import build_recon_status, write_recon_status
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.time_utils import Clock, utc_now_iso
from bugslyce.triage.candidates import generate_candidates


PIPELINE_PROFILE = QUICK_RECON_PROFILE
STANDARD_PIPELINE_PROFILE = STANDARD_RECON_PROFILE
SUPPORTED_PIPELINE_PROFILES = (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE)
PIPELINE_JSON_FILENAME = "project_pipeline.json"
PIPELINE_MARKDOWN_FILENAME = "project_pipeline.md"
SKIPPED_STEP_MESSAGES = {
    "PIPELINE-STEP-002": (
        "Existing nmap discovery evidence detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-003": (
        "Existing service/version evidence detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-004": (
        "Existing HTTP metadata evidence detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-005": (
        "Existing evidence-derived path follow-up artefacts detected; "
        "phase skipped during resume."
    ),
    "PIPELINE-STEP-006": (
        "Existing lab-root-tiny content plan detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-007": (
        "Existing lab-root-tiny content discovery output detected; "
        "phase skipped during resume."
    ),
    "PIPELINE-STEP-008": (
        "Existing content-result follow-up artefacts detected; "
        "phase skipped during resume."
    ),
    "PIPELINE-STEP-009": (
        "Existing selective body-fetch artefacts detected; "
        "phase skipped during resume."
    ),
    "PIPELINE-STEP-012": (
        "Existing completed evidence pack detected; export skipped during resume."
    ),
}


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
    resume_requested: bool
    reused_existing_evidence: bool
    skipped_steps: int
    no_op_steps: int
    completed_steps: int
    failed_step: str | None
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


@dataclass(frozen=True)
class ResumeAssessment:
    """Validated existing state that can be reused by a resumed pipeline."""

    skipped_step_ids: frozenset[str]
    prior_pipeline: dict[str, object] | None


def run_project_pipeline(
    project_file: Path,
    profile: str,
    *,
    resume: bool = False,
    clock: Clock | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> PipelineResult:
    """Run the fixed approved project chain."""

    if profile not in SUPPORTED_PIPELINE_PROFILES:
        raise ValueError(
            f"Unsupported project pipeline profile '{profile}'. "
            f"Supported profiles: {', '.join(SUPPORTED_PIPELINE_PROFILES)}."
        )

    project_file = project_file.expanduser().resolve()
    project = load_project(project_file)
    output_dir = Path(project.output_dir).expanduser().resolve()
    scope_file = Path(project.scope_file).expanduser().resolve()
    plan_dir = Path(f"{output_dir}-content-plan-tiny")
    plan_path = plan_dir / "content_discovery_plan.json"
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    assessment = _validate_pipeline(
        project.target,
        project_file,
        scope_file,
        output_dir,
        plan_dir,
        plan_path,
        export_path,
        build_doctor_report(),
        profile=profile,
        resume=resume,
    )

    steps = _pending_steps()
    for index, step in enumerate(steps):
        if step.step_id in assessment.skipped_step_ids:
            steps[index] = replace(
                step,
                status="skipped_existing",
                message=SKIPPED_STEP_MESSAGES[step.step_id],
            )
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
        resume_requested=resume,
        reused_existing_evidence=bool(assessment.skipped_step_ids),
        skipped_steps=len(assessment.skipped_step_ids),
        no_op_steps=0,
        completed_steps=0,
        failed_step=None,
        steps=steps,
        report_path=(
            str(output_dir / "report.md")
            if (output_dir / "report.md").is_file()
            else None
        ),
        runbook_path=None,
        export_path=(
            str(export_path)
            if "PIPELINE-STEP-012" in assessment.skipped_step_ids
            else None
        ),
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
                f"Resume: {str(resume).lower()}",
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
        "resume": resume,
        "profile": profile,
    }
    step_runners = _step_runners(context, clock)
    for index, step in enumerate(result.steps):
        position = index + 1
        if step.status == "skipped_existing":
            _emit(
                progress_callback,
                f"[{position}/12] {step.name} skipped.\n{step.message}",
            )
            continue
        _emit(progress_callback, f"[{position}/12] {step.name} starting...")
        started_step = replace(step, status="running", started_at=utc_now_iso(clock))
        result = _replace_step(result, index, started_step)
        try:
            message, output_paths, updates = step_runners[step.step_id]()
        except (PathFollowupNoWork, ContentFollowupNoWork, BodyFetchNoWork) as outcome:
            completed_step = replace(
                started_step,
                status="noop",
                completed_at=utc_now_iso(clock),
                message=str(outcome),
                output_paths=[],
            )
            result = _replace_step(result, index, completed_step)
            result = _refresh_result_counts(result)
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
        result = _refresh_result_counts(result)
        _emit(progress_callback, f"[{position}/12] {step.name} complete")

    result = replace(
        _refresh_result_counts(result),
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

    outputs = _final_output_paths(result)
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
        "",
        "## Summary",
        "",
        f"- Resume requested: `{str(result.resume_requested).lower()}`",
        f"- Reused existing evidence: `{str(result.reused_existing_evidence).lower()}`",
        f"- Completed steps: `{result.completed_steps}`",
        f"- Skipped existing steps: `{result.skipped_steps}`",
        f"- No-op steps: `{result.no_op_steps}`",
        f"- Failed step: `{result.failed_step or 'none'}`",
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
            f"- Report: `{outputs['report']}`",
            f"- Recon status: `{outputs['status']}`",
            f"- Runbook: `{outputs['runbook']}`",
            f"- Pipeline metadata JSON: `{outputs['pipeline_json']}`",
            f"- Pipeline metadata Markdown: `{outputs['pipeline_markdown']}`",
            f"- Evidence pack: `{outputs['export']}`",
            "",
            "## Suggested Review Commands",
            "",
            "```bash",
            f"less {outputs['report']}",
            f".venv/bin/bugslyce project next --project {result.project_file}",
            f".venv/bin/bugslyce project status --project {result.project_file}",
            "```",
            "",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
            "",
        ]
    )
    return "\n".join(lines)


def render_project_pipeline_summary(result: PipelineResult) -> str:
    """Render a clear final pipeline and operator review summary."""

    outputs = _final_output_paths(result)
    failed_count = sum(step.status == "failed" for step in result.steps)
    return "\n".join(
        [
            "BugSlyce project pipeline complete",
            f"Project: {result.project_name}",
            f"Target: {result.target}",
            f"Profile: {result.profile}",
            f"Resume: {str(result.resume_requested).lower()}",
            f"Final status: {result.final_status}",
            "",
            "Step summary:",
            f"* Completed: {result.completed_steps}",
            f"* Skipped existing: {result.skipped_steps}",
            f"* No-op: {result.no_op_steps}",
            f"* Failed: {failed_count}",
            "",
            "Final outputs:",
            f"* Report: {outputs['report']}",
            f"* Status: {outputs['status']}",
            f"* Runbook: {outputs['runbook']}",
            f"* Pipeline metadata: {outputs['pipeline_markdown']}",
            f"* Evidence pack: {outputs['export']}",
            "",
            "Recommended next action:",
            "* Review the Operator Summary:",
            f"  less {outputs['report']}",
            "",
            "Optional:",
            "* Preview next safe action:",
            f"  .venv/bin/bugslyce project next --project {result.project_file}",
            "",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
        ]
    )


def _final_output_paths(result: PipelineResult) -> dict[str, str]:
    output_dir = Path(result.output_dir)
    status_generated = any(
        step.step_id == "PIPELINE-STEP-010" and step.status == "completed"
        for step in result.steps
    )
    return {
        "report": result.report_path or "not generated",
        "status": (
            str(output_dir / "recon_status.md")
            if status_generated
            else "not generated"
        ),
        "runbook": result.runbook_path or "not generated",
        "pipeline_json": str(output_dir / PIPELINE_JSON_FILENAME),
        "pipeline_markdown": str(output_dir / PIPELINE_MARKDOWN_FILENAME),
        "export": result.export_path or "not generated",
    }


def _validate_pipeline(
    target: str,
    project_file: Path,
    scope_file: Path,
    output_dir: Path,
    plan_dir: Path,
    plan_path: Path,
    export_path: Path,
    doctor: DoctorReport,
    *,
    profile: str,
    resume: bool,
) -> ResumeAssessment:
    if not output_dir.is_dir():
        raise ValueError(f"Project output directory does not exist: {output_dir}")
    validate_explicit_nmap_target_scope(target, scope_file)
    _validate_readiness(doctor)
    if not resume:
        if (output_dir / "recon_manifest.json").exists():
            raise ValueError(
                "Existing recon pack detected. Use project status/next or start with "
                "a clean project directory."
            )
        if plan_dir.exists():
            raise ValueError(f"Content plan directory already exists: {plan_dir}")
        if export_path.exists():
            raise ValueError(f"Evidence pack output already exists: {export_path}")
        return ResumeAssessment(frozenset(), None)

    return _assess_resume_state(
        target=target,
        project_file=project_file,
        scope_file=scope_file,
        output_dir=output_dir,
        plan_dir=plan_dir,
        plan_path=plan_path,
        export_path=export_path,
        profile=profile,
    )


def _validate_readiness(doctor: DoctorReport) -> None:
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


def _assess_resume_state(
    *,
    target: str,
    project_file: Path,
    scope_file: Path,
    output_dir: Path,
    plan_dir: Path,
    plan_path: Path,
    export_path: Path,
    profile: str,
) -> ResumeAssessment:
    manifest_path = output_dir / "recon_manifest.json"
    manifest = (
        _load_json_object(manifest_path, "recon manifest")
        if manifest_path.exists()
        else None
    )
    artifact_names: set[str] = set()
    if manifest is not None:
        manifest_target = _required_json_text(manifest, "target", "Recon manifest")
        if manifest_target.lower().rstrip(".") != target.lower().rstrip("."):
            raise ValueError(
                "Project target does not match the existing recon manifest target."
            )
        artifact_names = _validated_manifest_artifact_names(manifest, output_dir)

    prior_pipeline_path = output_dir / PIPELINE_JSON_FILENAME
    prior_pipeline = (
        _load_json_object(prior_pipeline_path, "project pipeline metadata")
        if prior_pipeline_path.exists()
        else None
    )
    if prior_pipeline is not None:
        _validate_prior_pipeline(
            prior_pipeline,
            target=target,
            project_file=project_file,
            output_dir=output_dir,
            profile=profile,
        )

    if plan_dir.exists() and not plan_dir.is_dir():
        raise ValueError(f"Content plan path is not a directory: {plan_dir}")
    if plan_dir.exists() and not plan_path.is_file():
        raise ValueError(
            "Content plan directory exists without content_discovery_plan.json; "
            "resume state is ambiguous."
        )
    plan_complete = False
    if plan_path.is_file():
        plan = load_content_discovery_plan(plan_path)
        if (
            plan.target.lower().rstrip(".") != target.lower().rstrip(".")
            or plan.profile != CONTENT_DISCOVERY_TINY_PROFILE
            or Path(plan.input_dir).expanduser().resolve() != output_dir
            or Path(plan.output_dir).expanduser().resolve() != plan_dir
            or Path(plan.scope_file).expanduser().resolve() != scope_file
        ):
            raise ValueError(
                "Existing content plan does not match this project target, profile, "
                "scope, or output paths."
            )
        plan_complete = True

    prior_statuses = _prior_step_statuses(prior_pipeline)
    detected = {
        "PIPELINE-STEP-002": "nmap-allports.txt" in artifact_names,
        "PIPELINE-STEP-003": any(
            name.startswith("nmap-services") for name in artifact_names
        ),
        "PIPELINE-STEP-004": any(
            name.startswith(("homepage-", "robots-", "curl-headers-"))
            and not name.startswith(
                ("curl-headers-followup-", "curl-headers-content-followup-")
            )
            for name in artifact_names
        ),
        "PIPELINE-STEP-005": any(
            name.startswith("curl-headers-followup-") for name in artifact_names
        ),
        "PIPELINE-STEP-006": plan_complete,
        "PIPELINE-STEP-007": any(
            name.startswith("gobuster-tiny-") for name in artifact_names
        ),
        "PIPELINE-STEP-008": any(
            name.startswith("curl-headers-content-followup-")
            for name in artifact_names
        )
        or prior_statuses.get("PIPELINE-STEP-008") == "noop",
        "PIPELINE-STEP-009": any(
            name.startswith("body-fetch-") for name in artifact_names
        )
        or prior_statuses.get("PIPELINE-STEP-009") == "noop",
    }
    _validate_resume_phase_order(detected)

    skipped = {step_id for step_id, complete in detected.items() if complete}
    if export_path.exists():
        if not export_path.is_file():
            raise ValueError(f"Evidence pack output is not a file: {export_path}")
        if prior_pipeline is None or prior_pipeline.get("final_status") != "completed":
            raise ValueError(
                "Evidence pack output exists but a completed prior pipeline cannot "
                "be verified; refusing resume before live phases."
            )
        recorded_export = prior_pipeline.get("export_path")
        if not isinstance(recorded_export, str) or (
            Path(recorded_export).expanduser().resolve() != export_path
        ):
            raise ValueError(
                "Existing evidence pack path does not match completed pipeline metadata."
            )
        skipped.add("PIPELINE-STEP-012")

    return ResumeAssessment(frozenset(skipped), prior_pipeline)


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse {label} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label.capitalize()} must contain a JSON object.")
    return payload


def _required_json_text(
    payload: dict[str, object],
    key: str,
    label: str,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} does not contain a valid {key}.")
    return value.strip()


def _validated_manifest_artifact_names(
    manifest: dict[str, object],
    output_dir: Path,
) -> set[str]:
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise ValueError("Recon manifest artefacts must be a list.")
    names: set[str] = set()
    for index, artifact in enumerate(raw_artifacts, start=1):
        if not isinstance(artifact, dict):
            raise ValueError(f"Recon manifest artifact {index} must be an object.")
        raw_file = artifact.get("file")
        if not isinstance(raw_file, str) or not raw_file.strip():
            raise ValueError(f"Recon manifest artifact {index} has no valid file path.")
        candidate = Path(raw_file).expanduser()
        resolved = (
            candidate.resolve()
            if candidate.is_absolute()
            else (output_dir / candidate).resolve()
        )
        try:
            resolved.relative_to(output_dir)
        except ValueError as exc:
            raise ValueError(
                f"Recon manifest artifact escapes the project output directory: {raw_file}"
            ) from exc
        if not resolved.is_file():
            raise ValueError(
                f"Recon manifest references missing artifact; resume is ambiguous: {raw_file}"
            )
        names.add(resolved.name)
    return names


def _validate_prior_pipeline(
    payload: dict[str, object],
    *,
    target: str,
    project_file: Path,
    output_dir: Path,
    profile: str,
) -> None:
    if _required_json_text(payload, "target", "Project pipeline metadata").lower().rstrip(
        "."
    ) != target.lower().rstrip("."):
        raise ValueError("Prior pipeline metadata target does not match this project.")
    existing_profile = payload.get("profile")
    if existing_profile not in SUPPORTED_PIPELINE_PROFILES:
        raise ValueError("Prior pipeline metadata uses an unsupported project profile.")
    if existing_profile != profile:
        raise ValueError("Prior pipeline metadata profile does not match this run.")
    for key, expected in (("project_file", project_file), ("output_dir", output_dir)):
        value = payload.get(key)
        if not isinstance(value, str) or Path(value).expanduser().resolve() != expected:
            raise ValueError(
                f"Prior pipeline metadata {key} does not match this project."
            )


def _prior_step_statuses(
    payload: dict[str, object] | None,
) -> dict[str, str]:
    if payload is None:
        return {}
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list):
        return {}
    statuses: dict[str, str] = {}
    for step in raw_steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("step_id")
        status = step.get("status")
        if isinstance(step_id, str) and isinstance(status, str):
            statuses[step_id] = status
    return statuses


def _validate_resume_phase_order(detected: dict[str, bool]) -> None:
    missing_seen = False
    for step_id in (
        "PIPELINE-STEP-002",
        "PIPELINE-STEP-003",
        "PIPELINE-STEP-004",
        "PIPELINE-STEP-005",
        "PIPELINE-STEP-006",
        "PIPELINE-STEP-007",
        "PIPELINE-STEP-008",
        "PIPELINE-STEP-009",
    ):
        if not detected[step_id]:
            missing_seen = True
        elif missing_seen:
            raise ValueError(
                "Existing resume evidence is not a coherent pipeline prefix; "
                f"{step_id} is present after an earlier missing phase."
            )


def _refresh_result_counts(result: PipelineResult) -> PipelineResult:
    return replace(
        result,
        skipped_steps=sum(step.status == "skipped_existing" for step in result.steps),
        no_op_steps=sum(step.status == "noop" for step in result.steps),
        completed_steps=sum(step.status == "completed" for step in result.steps),
        failed_step=next(
            (step.step_id for step in result.steps if step.status == "failed"),
            None,
        ),
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
    resume = context["resume"]
    profile = context["profile"]
    assert isinstance(output_dir, Path)
    assert isinstance(scope_file, Path)
    assert isinstance(plan_dir, Path)
    assert isinstance(plan_path, Path)
    assert isinstance(export_path, Path)
    assert isinstance(target, str)
    assert isinstance(project_file, Path)
    assert isinstance(resume, bool)
    assert isinstance(profile, str)

    def validation():
        state = "resume provenance" if resume else "fresh output"
        return f"Local readiness, {state}, and exact scope checks passed.", [], {}

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
        standard_paths = _write_standard_interpretation_report_if_needed(
            profile,
            output_dir,
        )
        result = build_recon_status(output_dir, scope_file, clock=clock)
        json_path, markdown_path = write_recon_status(result, output_dir)
        output_paths = [*standard_paths, str(json_path), str(markdown_path)]
        updates = (
            {"report_path": standard_paths[0]}
            if standard_paths
            else {}
        )
        return (
            "Local recon status generated.",
            output_paths,
            updates,
        )

    def runbook():
        result = build_project_runbook(
            project_file,
            clock=clock,
            standard_investigation_workflow_markdown=(
                _build_standard_investigation_runbook_section_if_needed(
                    profile,
                    output_dir,
                )
            ),
        )
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


def _write_standard_interpretation_report_if_needed(
    profile: str,
    output_dir: Path,
) -> list[str]:
    if profile != STANDARD_PIPELINE_PROFILE:
        return []
    project_state = build_project_state(output_dir)
    candidates = generate_candidates(project_state)
    assembly = assemble_standard_interpretation_from_project_state(project_state)
    engagement_context = getattr(project_state, "engagement_context", "unknown")
    threads = build_investigation_threads(
        project_state,
        candidates,
        assembly.review_leads,
    )
    route_source_leads = build_route_source_review(
        project_state,
        getattr(assembly, "sources", ()),
    )
    report_path, json_path = write_project_outputs(
        project_state,
        candidates,
        output_dir,
        manual_review_leads_markdown=assembly.manual_review_leads_markdown,
        investigation_threads_markdown=render_investigation_threads_markdown(
            threads,
            engagement_context=engagement_context,
        ),
        route_source_review_markdown=render_route_source_review_markdown(
            route_source_leads,
            engagement_context=engagement_context,
        ),
    )
    return [str(report_path), str(json_path)]


def _build_standard_investigation_runbook_section_if_needed(
    profile: str,
    output_dir: Path,
) -> str | None:
    if profile != STANDARD_PIPELINE_PROFILE:
        return None
    project_state = build_project_state(output_dir)
    candidates = generate_candidates(project_state)
    assembly = assemble_standard_interpretation_from_project_state(project_state)
    engagement_context = getattr(project_state, "engagement_context", "unknown")
    threads = build_investigation_threads(
        project_state,
        candidates,
        assembly.review_leads,
    )
    return render_standard_investigation_workflow_runbook_section(
        threads,
        engagement_context=engagement_context,
    )


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
        _refresh_result_counts(_replace_step(result, index, failed_step)),
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
