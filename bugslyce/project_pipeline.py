"""Plan-driven orchestration for one approved BugSlyce project pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable

from bugslyce.doctor import DoctorReport, build_doctor_report, mode_readiness_failures
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
    DEEP_BOUNDED_CORE_PROFILE,
    STANDARD_BOUNDED_CORE_PROFILE,
    STANDARD_AUTH_CORE_PROFILE,
    build_content_discovery_plan,
    write_content_discovery_plan,
)
from bugslyce.recon.content_run import (
    ContentDiscoveryExecutionIncomplete,
    load_content_discovery_plan,
    run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.deep_collection_request_plan import (
    build_deep_collection_request_plan_from_project_state,
)
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_http_fetcher import urllib_deep_http_fetcher
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_orchestration import (
    DEEP_RECON_ORCHESTRATION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
    DeepReconOrchestrationResult,
    build_deep_recon_orchestration,
    write_deep_recon_orchestration_artifacts,
)
from bugslyce.recon.deep_successful_content import (
    render_successful_deep_content_runbook,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupResult,
    build_deep_shallow_route_followup_plan,
    collect_deep_shallow_route_followups,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    write_deep_source_route_collection_artifacts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectionResult,
    collect_deep_source_routes_from_plan,
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
from bugslyce.recon.modes import DEEP_RECON_PROFILE, QUICK_RECON_PROFILE, STANDARD_RECON_PROFILE
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
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
    render_readable_evidence_cards_markdown,
)
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.reports.operator_summary import OperatorSummaryLead
from bugslyce.time_utils import Clock, utc_now_iso
from bugslyce.triage.candidates import generate_candidates
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


PIPELINE_PROFILE = QUICK_RECON_PROFILE
STANDARD_PIPELINE_PROFILE = STANDARD_RECON_PROFILE
DEEP_PIPELINE_PROFILE = DEEP_RECON_PROFILE
SUPPORTED_PIPELINE_PROFILES = (
    PIPELINE_PROFILE,
    STANDARD_PIPELINE_PROFILE,
    DEEP_PIPELINE_PROFILE,
)
PIPELINE_JSON_FILENAME = "project_pipeline.json"
PIPELINE_MARKDOWN_FILENAME = "project_pipeline.md"
PARTIAL_DEEP_RESUME_MESSAGE = (
    "Partial Deep pipeline state cannot be resumed safely because the full "
    "in-memory collection results are not persisted. Start a clean Deep run "
    "rather than repeating bounded network collection."
)
DEEP_FIXED_ARTEFACT_FILENAMES = (
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
    DEEP_RECON_ORCHESTRATION_JSON,
)
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
        "Existing bounded content plan detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-007": (
        "Existing bounded content discovery output detected; "
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
    "PIPELINE-STEP-010D": (
        "Existing completed Deep collection detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-011D": (
        "Existing completed Deep orchestration artefacts detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-010": (
        "Existing completed recon status detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-011": (
        "Existing completed project runbook detected; phase skipped during resume."
    ),
    "PIPELINE-STEP-012": (
        "Existing completed evidence pack detected; export skipped during resume."
    ),
}


@dataclass(frozen=True)
class DeepPipelineOutputs:
    """In-memory Deep pipeline outputs shared between adjacent steps."""

    source_collection: DeepSourceRouteCollectionResult | None = None
    shallow_followups: DeepShallowRouteFollowupResult | None = None
    orchestration: DeepReconOrchestrationResult | None = None
    deep_artifact_paths: tuple[Path, ...] = ()


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


def format_exception_diagnostic(exc: BaseException) -> str:
    """Render an exception and its ordered notes without relying on a traceback."""

    primary = str(exc).strip() or type(exc).__name__
    notes = getattr(exc, "__notes__", ())
    rendered_notes: list[str] = []
    seen: set[str] = set()
    primary_folded = primary.casefold()
    for raw_note in notes:
        note = str(raw_note).strip()
        if not note:
            continue
        normalised = note.rstrip().rstrip(".")
        fingerprint = normalised.casefold()
        if not normalised or fingerprint in seen or fingerprint in primary_folded:
            continue
        seen.add(fingerprint)
        if fingerprint.startswith(("cleanup warning:", "reconciliation warning:")):
            rendered_notes.append(_as_diagnostic_sentence(normalised))
        elif "cleanup" in fingerprint:
            rendered_notes.append(
                _as_diagnostic_sentence(f"Cleanup warning: {normalised}")
            )
        elif "reconcil" in fingerprint:
            rendered_notes.append(
                _as_diagnostic_sentence(f"Reconciliation warning: {normalised}")
            )
        else:
            rendered_notes.append(
                _as_diagnostic_sentence(f"Pipeline warning: {normalised}")
            )
    if not rendered_notes:
        return primary
    return " ".join((_as_diagnostic_sentence(primary), *rendered_notes))


def _as_diagnostic_sentence(value: str) -> str:
    value = value.rstrip()
    if value.endswith((".", "!", "?")):
        return value
    return value + "."


def render_project_pipeline_failure_guidance(result: PipelineResult) -> tuple[str, ...]:
    """Return truthful operator guidance for an unsuccessful pipeline execution."""

    failed_step = result.failed_step
    if failed_step is None:
        failed = next((step for step in result.steps if step.status == "failed"), None)
        failed_step = failed.step_id if failed is not None else "unknown"
    if failed_step == "PIPELINE-FINALISE":
        return (
            "The bounded collection pipeline steps had completed, but final output "
            "reconciliation or evidence-pack publication failed.",
            "The run is classified as failed.",
            "No successful final evidence pack is being advertised.",
            "Review local artefacts and pipeline diagnostics.",
        )
    return (
        f"Pipeline stopped at step {failed_step}.",
        "No later steps were executed.",
        "Review the error and local evidence.",
    )


@dataclass(frozen=True)
class ResumeAssessment:
    """Validated existing state that can be reused by a resumed pipeline."""

    skipped_step_ids: frozenset[str]
    prior_pipeline: dict[str, object] | None
    preserve_canonical_pipeline_metadata: bool = False


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
    content_profile = _content_discovery_profile_for_pipeline(profile)
    plan_dir = Path(f"{output_dir}-content-plan-{_content_plan_suffix(content_profile)}")
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
    preserve_canonical_pipeline_metadata = assessment.preserve_canonical_pipeline_metadata

    steps = _pending_steps(profile)
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
        runbook_path=(
            str(output_dir / "runbook.md")
            if (output_dir / "runbook.md").is_file()
            and "PIPELINE-STEP-011" in assessment.skipped_step_ids
            else None
        ),
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
        "published_export_path": None,
        "target": project.target,
        "resume": resume,
        "profile": profile,
        "deep_outputs": DeepPipelineOutputs(),
    }
    step_runners = _step_runners(context, clock)
    total_steps = len(result.steps)
    for index, step in enumerate(result.steps):
        position = index + 1
        if step.status == "skipped_existing":
            _emit(
                progress_callback,
                f"[{position}/{total_steps}] {step.name} skipped.\n{step.message}",
            )
            continue
        _emit(progress_callback, f"[{position}/{total_steps}] {step.name} starting...")
        started_step = replace(step, status="running", started_at=utc_now_iso(clock))
        result = _replace_step(result, index, started_step)
        _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
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
            _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
            _emit(progress_callback, f"[{position}/{total_steps}] {step.name} no-op")
            continue
        except (
            ContentDiscoveryExecutionIncomplete,
            ContentFollowupExecutionIncomplete,
            BodyFetchExecutionIncomplete,
        ) as exc:
            diagnostic = format_exception_diagnostic(exc)
            _write_incomplete_phase_metadata(exc, output_dir, plan_dir)
            result = _failed_result(
                result,
                index,
                started_step,
                diagnostic,
                clock,
            )
            _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
            result = _reconcile_failed_pipeline_outputs(
                result,
                project_file,
                scope_file,
                context,
                clock,
                preserve_canonical_pipeline_metadata,
            )
            _emit(progress_callback, f"[{position}/{total_steps}] {step.name} failed")
            raise ProjectPipelineFailed(diagnostic, result) from exc
        except (ValueError, OSError) as exc:
            diagnostic = format_exception_diagnostic(exc)
            result = _failed_result(
                result,
                index,
                started_step,
                diagnostic,
                clock,
            )
            _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
            result = _reconcile_failed_pipeline_outputs(
                result,
                project_file,
                scope_file,
                context,
                clock,
                preserve_canonical_pipeline_metadata,
            )
            _emit(progress_callback, f"[{position}/{total_steps}] {step.name} failed")
            raise ProjectPipelineFailed(diagnostic, result) from exc

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
        _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
        _emit(progress_callback, f"[{position}/{total_steps}] {step.name} complete")

    result = replace(
        _refresh_result_counts(result),
        completed_at=utc_now_iso(clock),
        final_status="completed",
    )
    _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
    if not preserve_canonical_pipeline_metadata:
        try:
            _refresh_final_pipeline_outputs(result, project_file, scope_file, context, clock)
        except (ValueError, OSError) as exc:
            diagnostic = format_exception_diagnostic(exc)
            result = replace(
                result,
                final_status="failed",
                failed_step="PIPELINE-FINALISE",
                completed_at=utc_now_iso(clock),
            )
            warning_index = len(result.steps) - 1
            warning_step = result.steps[warning_index]
            result = _replace_step(
                result,
                warning_index,
                replace(
                    warning_step,
                    message=(
                        f"{warning_step.message} Finalisation failed: {diagnostic}"
                    ).strip(),
                ),
            )
            _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
            cleanup_errors = _remove_owned_export_after_finalisation_failure(context)
            if isinstance(context.get("published_export_path"), Path):
                result = replace(result, export_path=None)
                _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
            result = _reconcile_failed_pipeline_outputs(
                result,
                project_file,
                scope_file,
                context,
                clock,
                preserve_canonical_pipeline_metadata,
                cleanup_errors,
            )
            raise ProjectPipelineFailed(diagnostic, result) from exc
    return result


def _write_project_pipeline_checkpoint(
    result: PipelineResult,
    preserve_canonical_pipeline_metadata: bool,
) -> tuple[Path, Path] | None:
    if preserve_canonical_pipeline_metadata:
        return None
    return write_project_pipeline_result(result)


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
            f"bugslyce project next --project {result.project_file}",
            f"bugslyce project status --project {result.project_file}",
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
            f"  bugslyce project next --project {result.project_file}",
            "",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
        ]
    )


def _final_output_paths(result: PipelineResult) -> dict[str, str]:
    output_dir = Path(result.output_dir)
    status_generated = any(
        step.step_id == "PIPELINE-STEP-010" and step.status == "completed"
        for step in result.steps
    ) or any(
        step.step_id == "PIPELINE-STEP-010"
        and step.status == "skipped_existing"
        and (output_dir / "recon_status.md").is_file()
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
    _validate_readiness(doctor, profile)
    if not resume:
        if (output_dir / "recon_manifest.json").exists():
            raise ValueError(
                "Existing recon pack detected. Use project status/next or start with "
                "a clean project directory."
            )
        if profile == DEEP_PIPELINE_PROFILE:
            _reject_existing_deep_fixed_artefacts(output_dir)
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


def _validate_readiness(doctor: DoctorReport, profile: str) -> None:
    failures = mode_readiness_failures(doctor, _doctor_mode_for_pipeline_profile(profile))
    if failures:
        raise ValueError(" ".join(failures))


def _doctor_mode_for_pipeline_profile(profile: str) -> str:
    if profile == PIPELINE_PROFILE:
        return "quick"
    if profile == STANDARD_PIPELINE_PROFILE:
        return "standard"
    if profile == DEEP_PIPELINE_PROFILE:
        return "deep"
    raise ValueError(f"Unsupported project pipeline profile '{profile}'.")


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
        expected_content_profile = _content_discovery_profile_for_pipeline(profile)
        if (
            plan.target.lower().rstrip(".") != target.lower().rstrip(".")
            or plan.profile != expected_content_profile
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
    if profile == DEEP_PIPELINE_PROFILE:
        if _deep_completed_resume_verified(
            output_dir=output_dir,
            export_path=export_path,
            prior_pipeline=prior_pipeline,
            prior_statuses=prior_statuses,
        ):
            return ResumeAssessment(
                frozenset(_completed_deep_resume_skipped_steps(prior_statuses)),
                prior_pipeline,
                preserve_canonical_pipeline_metadata=True,
            )
        _validate_deep_resume_state(
            output_dir=output_dir,
            export_path=export_path,
            prior_pipeline=prior_pipeline,
            prior_statuses=prior_statuses,
        )
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
        if profile == DEEP_PIPELINE_PROFILE and _deep_completed_resume_verified(
            output_dir=output_dir,
            export_path=export_path,
            prior_pipeline=prior_pipeline,
            prior_statuses=prior_statuses,
        ):
            skipped.update(
                {
                    "PIPELINE-STEP-010D",
                    "PIPELINE-STEP-011D",
                    "PIPELINE-STEP-010",
                    "PIPELINE-STEP-011",
                }
            )
        skipped.add("PIPELINE-STEP-012")

    return ResumeAssessment(frozenset(skipped), prior_pipeline)


def _reject_existing_deep_fixed_artefacts(output_dir: Path) -> None:
    existing = [name for name in DEEP_FIXED_ARTEFACT_FILENAMES if (output_dir / name).exists()]
    if existing:
        raise ValueError(
            "Existing Deep artefact detected before a fresh Deep run: "
            + ", ".join(existing)
            + ". Start with a clean project directory."
        )


def _validate_deep_resume_state(
    *,
    output_dir: Path,
    export_path: Path,
    prior_pipeline: dict[str, object] | None,
    prior_statuses: dict[str, str],
) -> None:
    if _deep_completed_resume_verified(
        output_dir=output_dir,
        export_path=export_path,
        prior_pipeline=prior_pipeline,
        prior_statuses=prior_statuses,
    ):
        return
    deep_status_touched = any(
        prior_statuses.get(step_id) in {"running", "completed", "failed"}
        for step_id in ("PIPELINE-STEP-010D", "PIPELINE-STEP-011D")
    )
    deep_artefact_touched = any(
        (output_dir / name).exists() for name in DEEP_FIXED_ARTEFACT_FILENAMES
    )
    if deep_status_touched or deep_artefact_touched:
        raise ValueError(PARTIAL_DEEP_RESUME_MESSAGE)


def _deep_completed_resume_verified(
    *,
    output_dir: Path,
    export_path: Path,
    prior_pipeline: dict[str, object] | None,
    prior_statuses: dict[str, str],
) -> bool:
    if prior_pipeline is None:
        return False
    if prior_pipeline.get("profile") != DEEP_PIPELINE_PROFILE:
        return False
    if prior_pipeline.get("final_status") != "completed":
        return False
    if not all(
        prior_statuses.get(step_id) == "completed"
        for step_id in (
            "PIPELINE-STEP-010D",
            "PIPELINE-STEP-011D",
            "PIPELINE-STEP-010",
            "PIPELINE-STEP-011",
            "PIPELINE-STEP-012",
        )
    ):
        return False
    recorded_export = prior_pipeline.get("export_path")
    if not isinstance(recorded_export, str):
        return False
    if Path(recorded_export).expanduser().resolve() != export_path:
        return False
    required = (
        output_dir / "report.md",
        output_dir / "recon_status.md",
        output_dir / "recon_status.json",
        output_dir / "runbook.md",
        *(output_dir / name for name in DEEP_FIXED_ARTEFACT_FILENAMES),
        export_path,
    )
    return all(path.is_file() for path in required)


def _completed_deep_resume_skipped_steps(
    prior_statuses: dict[str, str],
) -> tuple[str, ...]:
    reusable = {"completed", "noop"}
    return tuple(
        step_id
        for step_id in (
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
        )
        if prior_statuses.get(step_id) in reusable
    )


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


def _content_discovery_profile_for_pipeline(profile: str) -> str:
    if profile == STANDARD_PIPELINE_PROFILE:
        return STANDARD_BOUNDED_CORE_PROFILE
    if profile == DEEP_PIPELINE_PROFILE:
        return DEEP_BOUNDED_CORE_PROFILE
    return CONTENT_DISCOVERY_TINY_PROFILE


def _content_plan_suffix(content_profile: str) -> str:
    if content_profile == CONTENT_DISCOVERY_TINY_PROFILE:
        return "tiny"
    if content_profile == STANDARD_BOUNDED_CORE_PROFILE:
        return "standard-bounded-core"
    if content_profile == DEEP_BOUNDED_CORE_PROFILE:
        return "deep-bounded-core"
    if content_profile == STANDARD_AUTH_CORE_PROFILE:
        return "standard-auth-core"
    return content_profile.replace("/", "-")


def _pending_steps(profile: str) -> list[PipelineStep]:
    definitions = [
        ("PIPELINE-STEP-001", "environment and project validation", "local-validation"),
        ("PIPELINE-STEP-002", "nmap full TCP discovery", "nmap-discover"),
        ("PIPELINE-STEP-003", "nmap service/version scan", "nmap-services"),
        ("PIPELINE-STEP-004", "HTTP metadata collection", "http-metadata"),
        ("PIPELINE-STEP-005", "discovered-path follow-up", "path-followup"),
        ("PIPELINE-STEP-006", "bounded content discovery planning", "content-plan"),
        ("PIPELINE-STEP-007", "bounded content discovery execution", "content-run"),
        ("PIPELINE-STEP-008", "content-result follow-up", "content-followup"),
        ("PIPELINE-STEP-009", "selective body fetch", "body-fetch"),
    ]
    if profile == DEEP_PIPELINE_PROFILE:
        definitions.extend(
            [
                (
                    "PIPELINE-STEP-010D",
                    "Deep bounded collection",
                    "deep-collection",
                ),
                (
                    "PIPELINE-STEP-011D",
                    "Deep offline review orchestration",
                    "deep-orchestration",
                ),
            ]
        )
    definitions.extend(
        [
            ("PIPELINE-STEP-010", "recon status", "status"),
            ("PIPELINE-STEP-011", "project runbook", "runbook"),
            ("PIPELINE-STEP-012", "evidence pack export", "export"),
        ]
    )
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
) -> dict[str, Callable[[], tuple[str, list[str], dict[str, object]]]]:
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
            profile=_content_discovery_profile_for_pipeline(profile),
            output_dir=plan_dir,
        )
        json_path, markdown_path = write_content_discovery_plan(plan, plan_dir)
        plan_profile = getattr(plan, "profile", _content_discovery_profile_for_pipeline(profile))
        return (
            f"Approved {plan_profile} content plan created.",
            [str(json_path), str(markdown_path)],
            {},
        )

    def content_run():
        result = run_content_discovery_workflow(plan_path, scope_file)
        metadata = write_content_discovery_execution_result(result, plan_dir)
        result_profile = getattr(result, "profile", _content_discovery_profile_for_pipeline(profile))
        return (
            f"Approved {result_profile} content discovery completed.",
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

    def deep_collection():
        project_state = build_project_state(output_dir)
        plan = build_deep_collection_request_plan_from_project_state(project_state)
        source_collection = collect_deep_source_routes_from_plan(
            plan,
            fetcher=urllib_deep_http_fetcher,
        )
        source_paths = write_deep_source_route_collection_artifacts(
            source_collection,
            output_dir,
        )
        html_routes = build_deep_html_route_extraction(source_collection)
        javascript_routes = build_deep_javascript_route_extraction(source_collection)
        followup_plan = build_deep_shallow_route_followup_plan(
            html_routes,
            javascript_routes,
        )
        shallow_followups = collect_deep_shallow_route_followups(
            followup_plan,
            fetcher=urllib_deep_http_fetcher,
        )
        current = _deep_outputs_from_context(context)
        context["deep_outputs"] = replace(
            current,
            source_collection=source_collection,
            shallow_followups=shallow_followups,
            deep_artifact_paths=_dedupe_paths(tuple(source_paths)),
        )
        return (
            "Deep bounded source-route collection and shallow same-origin follow-up completed.",
            [str(path) for path in source_paths],
            {},
        )

    def deep_orchestration():
        current = _deep_outputs_from_context(context)
        if current.source_collection is None or current.shallow_followups is None:
            raise ValueError("Deep collection results are required before orchestration.")
        orchestration = build_deep_recon_orchestration(
            current.source_collection,
            current.shallow_followups,
            deep_profile_selected=profile == DEEP_PIPELINE_PROFILE,
            deep_collection_completed=profile == DEEP_PIPELINE_PROFILE,
        )
        artifact_paths = write_deep_recon_orchestration_artifacts(
            orchestration,
            output_dir,
            force=resume,
        )
        context["deep_outputs"] = replace(
            current,
            orchestration=orchestration,
            deep_artifact_paths=_dedupe_paths(
                (*current.deep_artifact_paths, *artifact_paths),
            ),
        )
        return (
            "Deep offline review orchestration completed.",
            [str(path) for path in artifact_paths],
            {},
        )

    def status():
        report_paths = _write_interpretation_report_if_needed(
            profile,
            output_dir,
            context,
        )
        result = build_recon_status(output_dir, scope_file, clock=clock)
        json_path, markdown_path = write_recon_status(result, output_dir)
        output_paths = [*report_paths, str(json_path), str(markdown_path)]
        updates = (
            {"report_path": report_paths[0]}
            if report_paths
            else {}
        )
        return (
            "Local recon status generated.",
            output_paths,
            updates,
        )

    def runbook():
        runbook_kwargs: dict[str, object] = {
            "clock": clock,
            "standard_investigation_workflow_markdown": (
                _build_standard_investigation_runbook_section_if_needed(
                    profile,
                    output_dir,
                    context,
                )
            ),
        }
        deep_runbook_markdown = _deep_runbook_markdown_required(profile, context)
        if deep_runbook_markdown is not None:
            runbook_kwargs["deep_recon_runbook_markdown"] = deep_runbook_markdown
        result = build_project_runbook(
            project_file,
            **runbook_kwargs,
        )
        runbook_path = write_project_runbook(result)
        return (
            "Project runbook generated.",
            [str(runbook_path)],
            {"runbook_path": str(runbook_path)},
        )

    def export():
        deep_evidence_paths = _deep_evidence_paths_required(profile, context)
        if deep_evidence_paths is None:
            result = export_recon_evidence_pack(
                output_dir,
                export_path,
                clock=clock,
            )
        else:
            result = export_recon_evidence_pack(
                output_dir,
                export_path,
                clock=clock,
                deep_evidence_paths=deep_evidence_paths,
            )
        context["published_export_path"] = Path(result.output_path)
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
        "PIPELINE-STEP-010D": deep_collection,
        "PIPELINE-STEP-011D": deep_orchestration,
        "PIPELINE-STEP-010": status,
        "PIPELINE-STEP-011": runbook,
        "PIPELINE-STEP-012": export,
    }


def _deep_outputs_from_context(context: dict[str, object]) -> DeepPipelineOutputs:
    outputs = context.get("deep_outputs")
    if not isinstance(outputs, DeepPipelineOutputs):
        raise ValueError("Deep pipeline outputs are not initialised.")
    return outputs


def _deep_runbook_markdown_required(
    profile: str,
    context: dict[str, object],
) -> str | None:
    if profile != DEEP_PIPELINE_PROFILE:
        return None
    orchestration = _deep_outputs_from_context(context).orchestration
    if orchestration is None:
        raise ValueError("Deep orchestration is required before runbook generation.")
    return orchestration.deep_recon_runbook_markdown


def _deep_evidence_paths_required(
    profile: str,
    context: dict[str, object],
) -> tuple[Path, ...] | None:
    if profile != DEEP_PIPELINE_PROFILE:
        return None
    paths = _deep_outputs_from_context(context).deep_artifact_paths
    deduped = _dedupe_paths(paths)
    expected_names = tuple(path.name for path in deduped)
    if expected_names != DEEP_FIXED_ARTEFACT_FILENAMES:
        raise ValueError(
            "Deep evidence artefacts are incomplete; expected explicit paths for "
            + ", ".join(DEEP_FIXED_ARTEFACT_FILENAMES)
            + "."
        )
    missing = [str(path) for path in deduped if not path.is_file()]
    if missing:
        raise ValueError("Deep evidence artefact is missing: " + ", ".join(missing))
    return deduped


def _dedupe_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in paths:
        resolved = path.expanduser().resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return tuple(deduped)


def _write_interpretation_report_if_needed(
    profile: str,
    output_dir: Path,
    context: dict[str, object],
) -> list[str]:
    if profile not in {STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE}:
        return []
    deep_recon_markdown = None
    orchestration: DeepReconOrchestrationResult | None = None
    operator_summary_leads: tuple[OperatorSummaryLead, ...] = ()
    if profile == DEEP_PIPELINE_PROFILE:
        orchestration = _deep_outputs_from_context(context).orchestration
        if orchestration is None:
            raise ValueError("Deep orchestration is required before report generation.")
        deep_recon_markdown = _render_deep_report_index(orchestration)
        operator_summary_leads = _deep_operator_summary_leads(orchestration)
    project_state = build_project_state(output_dir)
    candidates = generate_candidates(project_state)
    workflow_leads = build_grouped_workflow_leads(project_state, orchestration)
    assembly = (
        assemble_standard_interpretation_from_project_state(
            project_state,
            referenced_direct_lead_count=len(operator_summary_leads),
        )
        if operator_summary_leads
        else assemble_standard_interpretation_from_project_state(project_state)
    )
    engagement_context = getattr(project_state, "engagement_context", "unknown")
    threads = build_investigation_threads(
        project_state,
        candidates,
        assembly.review_leads,
        workflow_leads=workflow_leads,
    )
    route_source_leads = build_route_source_review(
        project_state,
        getattr(assembly, "sources", ()),
    )
    human_triage_brief = build_human_triage_brief(
        project_state,
        candidates,
        engagement_context=engagement_context,
        deep_orchestration=orchestration,
        workflow_leads=workflow_leads,
    )
    report_kwargs: dict[str, object] = {
        "human_triage_brief_markdown": render_human_triage_brief_markdown(
            human_triage_brief,
        ),
        "manual_review_leads_markdown": assembly.manual_review_leads_markdown,
        "investigation_threads_markdown": render_investigation_threads_markdown(
            threads,
            engagement_context=engagement_context,
        ),
        "route_source_review_markdown": render_route_source_review_markdown(
            route_source_leads,
            engagement_context=engagement_context,
        ),
        "readable_evidence_cards_markdown": render_readable_evidence_cards_markdown(
            human_triage_brief,
        ),
    }
    if deep_recon_markdown is not None:
        report_kwargs["deep_recon_markdown"] = deep_recon_markdown
        report_kwargs["operator_summary_leads"] = operator_summary_leads
    report_path, json_path = write_project_outputs(
        project_state,
        candidates,
        output_dir,
        **report_kwargs,
    )
    return [str(report_path), str(json_path)]


def _refresh_final_pipeline_outputs(
    result: PipelineResult,
    project_file: Path,
    scope_file: Path,
    context: dict[str, object],
    clock: Clock | None,
) -> None:
    output_dir = Path(result.output_dir).expanduser().resolve()
    if not _step_satisfied(result, "PIPELINE-STEP-010"):
        return
    status_result = build_recon_status(output_dir, scope_file, clock=clock)
    write_recon_status(status_result, output_dir)
    runbook_kwargs: dict[str, object] = {
        "clock": clock,
        "standard_investigation_workflow_markdown": (
            _build_standard_investigation_runbook_section_if_needed(
                result.profile,
                output_dir,
                context,
            )
        ),
    }
    deep_runbook_markdown = _deep_runbook_markdown_required(result.profile, context)
    if deep_runbook_markdown is not None:
        runbook_kwargs["deep_recon_runbook_markdown"] = deep_runbook_markdown
    write_project_runbook(build_project_runbook(project_file, **runbook_kwargs))
    if result.export_path and _step_completed(result, "PIPELINE-STEP-012"):
        export_kwargs: dict[str, object] = {"force": True, "clock": clock}
        deep_paths = _deep_evidence_paths_for_final_export(result.profile, output_dir)
        if deep_paths is not None:
            export_kwargs["deep_evidence_paths"] = deep_paths
        export_recon_evidence_pack(
            output_dir,
            Path(result.export_path),
            **export_kwargs,
        )


def _reconcile_failed_pipeline_outputs(
    result: PipelineResult,
    project_file: Path,
    scope_file: Path,
    context: dict[str, object],
    clock: Clock | None,
    preserve_canonical_pipeline_metadata: bool,
    initial_cleanup_errors: list[str] | None = None,
) -> PipelineResult:
    if preserve_canonical_pipeline_metadata:
        return result
    cleanup_errors: list[str] = list(initial_cleanup_errors or [])
    try:
        _refresh_recon_status_after_failure(result, scope_file, clock)
    except (ValueError, OSError) as exc:
        cleanup_errors.append(
            f"recon status refresh failed: {format_exception_diagnostic(exc)}"
        )
    try:
        _refresh_runbook_after_failure(result, project_file, context, clock)
    except (ValueError, OSError) as exc:
        cleanup_errors.append(f"runbook refresh failed: {format_exception_diagnostic(exc)}")
    if not cleanup_errors:
        return result
    failed_index = next(
        (index for index, step in enumerate(result.steps) if step.status == "failed"),
        None,
    )
    if failed_index is None:
        warning_index = len(result.steps) - 1
        warning_step = result.steps[warning_index]
        message = _append_reconciliation_warnings(warning_step.message, cleanup_errors)
        reconciled = _replace_step(
            result,
            warning_index,
            replace(warning_step, message=message),
        )
        _write_project_pipeline_checkpoint(reconciled, preserve_canonical_pipeline_metadata)
        return reconciled
    failed_step = result.steps[failed_index]
    message = _append_reconciliation_warnings(failed_step.message, cleanup_errors)
    reconciled = _replace_step(result, failed_index, replace(failed_step, message=message))
    reconciled = _refresh_result_counts(reconciled)
    _write_project_pipeline_checkpoint(reconciled, preserve_canonical_pipeline_metadata)
    return reconciled


def _append_reconciliation_warnings(message: str, warnings: list[str]) -> str:
    retained: list[str] = []
    seen: set[str] = set()
    message_folded = message.casefold()
    for warning in warnings:
        normalised = warning.strip().rstrip(".")
        fingerprint = normalised.casefold()
        if not normalised or fingerprint in seen or fingerprint in message_folded:
            continue
        seen.add(fingerprint)
        retained.append(normalised)
    if not retained:
        return message
    return (
        f"{message.rstrip()} Reconciliation warning: {'; '.join(retained)}."
    ).strip()


def _refresh_recon_status_after_failure(
    result: PipelineResult,
    scope_file: Path,
    clock: Clock | None,
) -> None:
    output_dir = Path(result.output_dir).expanduser().resolve()
    status = next((step.status for step in result.steps if step.step_id == "PIPELINE-STEP-010"), None)
    if status in {"failed", "running"}:
        _quarantine_previous_status_files(output_dir)
        return
    if not _status_refresh_allowed_after_failure(result, output_dir):
        return
    status_result = build_recon_status(output_dir, scope_file, clock=clock)
    write_recon_status(status_result, output_dir)


def _status_refresh_allowed_after_failure(result: PipelineResult, output_dir: Path) -> bool:
    status = next((step.status for step in result.steps if step.step_id == "PIPELINE-STEP-010"), None)
    if status == "completed":
        return True
    if status in {"failed", "running"}:
        return False
    return (output_dir / "recon_status.json").is_file() and (output_dir / "recon_status.md").is_file()


def _quarantine_previous_status_files(output_dir: Path) -> None:
    for name in ("recon_status.json", "recon_status.md"):
        source = output_dir / name
        if not source.exists():
            continue
        destination = output_dir / name.replace("recon_status", "recon_status.previous")
        if destination.exists():
            destination.unlink()
        source.replace(destination)


def _step_satisfied(result: PipelineResult, step_id: str) -> bool:
    return any(
        step.step_id == step_id and step.status in {"completed", "noop", "skipped_existing"}
        for step in result.steps
    )


def _step_completed(result: PipelineResult, step_id: str) -> bool:
    return any(step.step_id == step_id and step.status == "completed" for step in result.steps)


def _refresh_runbook_after_failure(
    result: PipelineResult,
    project_file: Path,
    context: dict[str, object],
    clock: Clock | None,
) -> None:
    output_dir = Path(result.output_dir).expanduser().resolve()
    if not (output_dir / "runbook.md").is_file():
        return
    runbook_kwargs: dict[str, object] = {
        "clock": clock,
        "standard_investigation_workflow_markdown": (
            _build_standard_investigation_runbook_section_if_needed(
                result.profile,
                output_dir,
                context,
            )
        ),
    }
    deep_runbook_markdown = _deep_runbook_markdown_required(result.profile, context)
    if deep_runbook_markdown is not None:
        runbook_kwargs["deep_recon_runbook_markdown"] = deep_runbook_markdown
    write_project_runbook(build_project_runbook(project_file, **runbook_kwargs))


def _deep_evidence_paths_for_final_export(profile: str, output_dir: Path) -> tuple[Path, ...] | None:
    if profile != DEEP_PIPELINE_PROFILE:
        return None
    deep_paths = tuple(output_dir / name for name in DEEP_FIXED_ARTEFACT_FILENAMES)
    if not all(path.is_file() for path in deep_paths):
        raise ValueError("Deep evidence artefacts are incomplete before final export refresh.")
    return deep_paths


def _remove_owned_export_after_finalisation_failure(context: dict[str, object]) -> list[str]:
    published = context.get("published_export_path")
    if not isinstance(published, Path):
        return []
    try:
        if published.is_symlink():
            return [
                f"owned evidence pack cleanup refused symlink path: {published}; stale path remains: {published}"
            ]
        if published.is_file():
            published.unlink()
    except OSError as exc:
        return [f"owned evidence pack cleanup failed: {exc}; stale path remains: {published}"]
    return []


def _render_deep_report_index(orchestration: DeepReconOrchestrationResult) -> str:
    lines = [
        "## Deep Recon Review",
        "",
        "Detailed Deep review output is retained in `deep_recon_review.md`; this primary report lists the completed Deep stages and bounded counts for navigation.",
        "",
        "### Completed Deep Stages",
        "",
    ]
    for index, stage_id in enumerate(getattr(orchestration, "stage_order", ()), start=1):
        lines.append(f"{index}. `{stage_id}`")
    lines.extend(["", "### Deep Stage Counts", ""])
    for stage_id, count in getattr(orchestration, "stage_counts", ()):
        lines.append(f"- `{stage_id}`: {count}")
    lines.extend(
        [
            "",
            "### Deep Detail Artefact",
            "",
            "- Exhaustive Deep tables and inventories: `deep_recon_review.md`",
            "- Compact Deep operator guide: `deep_recon_runbook.md`",
            "- Bounded metadata index: `deep_recon_orchestration.json`",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _deep_operator_summary_leads(
    orchestration: DeepReconOrchestrationResult,
) -> tuple[OperatorSummaryLead, ...]:
    leads: list[OperatorSummaryLead] = []
    source_review = getattr(orchestration, "source_route_collection_review", None)
    for lead in getattr(source_review, "review_leads", ()):
        source_urls = tuple(getattr(lead, "urls", ()))
        final_urls = tuple(getattr(lead, "final_urls", ()))
        differing_final_urls = tuple(
            url for url in final_urls if url not in source_urls
        )
        provenance = ""
        if differing_final_urls:
            provenance = (
                " The request began at "
                + ", ".join(f"`{url}`" for url in source_urls)
                + " and the retained body came from final response URL "
                + ", ".join(f"`{url}`" for url in differing_final_urls)
                + "."
            )
        if lead.category == "structured_configuration_body":
            excerpt = "; ".join(lead.evidence_excerpt[:3])
            why = (
                "Collected plaintext contains coherent operational configuration "
                f"structure. Bounded excerpt: `{excerpt}`.{provenance}"
            )
            title = "Structured operational configuration observed"
            score = 97
        elif lead.category == "structured_json_routes":
            routes = ", ".join(f"`{value}`" for value in lead.observed_values[:6])
            why = (
                "A valid collected JSON response directly discloses relative route "
                f"strings: {routes}. No request was generated from these values."
                f"{provenance}"
            )
            title = "Routes disclosed by structured JSON response"
            score = 94
        else:
            continue
        leads.append(
            OperatorSummaryLead(
                title=title,
                why=why,
                endpoints=list(differing_final_urls or source_urls),
                evidence_ids=list(lead.evidence_ids),
                next_action=(
                    "Inspect the saved response and correlate the direct values with "
                    "existing route and service evidence. Do not treat the disclosure "
                    "as a vulnerability or request uncollected routes automatically."
                ),
                signal="high",
                score=score,
            )
        )
    successful_content_reviews = tuple(
        getattr(orchestration, "successful_content_reviews", ())
    )
    if successful_content_reviews:
        endpoints = sorted(
            {
                review.canonical_url
                for review in successful_content_reviews
                if review.canonical_url
            }
        )
        evidence_ids = sorted(
            {
                evidence_id
                for review in successful_content_reviews
                for evidence_id in review.evidence_ids
                if evidence_id
            }
        )
        artefact_references = sorted(
            {
                reference
                for review in successful_content_reviews
                for reference in review.artefact_references
                if reference
            }
        )
        response_count = len(successful_content_reviews)
        leads.append(
            OperatorSummaryLead(
                title="Successfully collected Deep content available offline",
                why=(
                    f"{response_count} successfully retained Deep "
                    f"response{'s' if response_count != 1 else ''} are available "
                    "for offline review in "
                    + ", ".join(
                        f"`{reference}`" for reference in artefact_references
                    )
                    + "."
                ),
                endpoints=endpoints,
                evidence_ids=evidence_ids,
                next_action=(
                    "Use the detailed Human Triage and runbook entries for per-response "
                    "offline review. Do not re-fetch these URLs or treat successful "
                    "collection as a confirmed finding."
                ),
                signal="direct retained response",
                score=72,
            )
        )
    return tuple(leads)


def _build_standard_investigation_runbook_section_if_needed(
    profile: str,
    output_dir: Path,
    context: dict[str, object] | None = None,
) -> str | None:
    if profile not in {STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE}:
        return None
    project_state = build_project_state(output_dir)
    candidates = generate_candidates(project_state)
    assembly = assemble_standard_interpretation_from_project_state(project_state)
    orchestration = None
    if profile == DEEP_PIPELINE_PROFILE and context is not None:
        outputs = context.get("deep_outputs")
        if isinstance(outputs, DeepPipelineOutputs):
            orchestration = outputs.orchestration
    workflow_leads = build_grouped_workflow_leads(project_state, orchestration)
    engagement_context = getattr(project_state, "engagement_context", "unknown")
    threads = build_investigation_threads(
        project_state,
        candidates,
        assembly.review_leads,
        workflow_leads=workflow_leads,
    )
    investigation_section = render_standard_investigation_workflow_runbook_section(
        threads,
        engagement_context=engagement_context,
    )
    successful_content_section = render_successful_deep_content_runbook(
        tuple(getattr(orchestration, "successful_content_reviews", ()))
    )
    if not successful_content_section:
        return investigation_section
    return "\n\n".join(
        section.strip()
        for section in (investigation_section, successful_content_section)
        if section and section.strip()
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
