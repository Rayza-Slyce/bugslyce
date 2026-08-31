"""Plan-driven orchestration for one approved BugSlyce project pipeline."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field, replace
import json
from pathlib import Path
import textwrap
from typing import Callable

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.engagement_policy import READINESS_FUTURE_ENFORCEMENT
from bugslyce.core.models import ProjectState
from bugslyce.core.project import build_project_state
from bugslyce.doctor import DoctorReport, build_doctor_report, mode_readiness_failures
from bugslyce.project_session import (
    build_project_runbook,
    load_project_engagement_policy,
    load_project,
    write_project_runbook,
)
from bugslyce.recon.project_runtime import (
    BugBountyProjectRuntime,
    build_bug_bounty_project_runtime,
)
from bugslyce.recon.runner import (
    ContentDiscoveryProgressEvent,
    render_content_discovery_progress,
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
from bugslyce.recon.collection_confidence import (
    CollectionConfidenceNotice,
    build_collection_confidence_notices_from_project,
    render_collection_confidence_markdown,
    render_collection_confidence_runbook,
)
from bugslyce.recon.deep_collection_request_plan import (
    DeepCollectionRequestPlan,
    build_deep_collection_request_plan_from_project_state,
)
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_http_fetcher import build_deep_http_fetcher
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    build_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
    DEEP_METADATA_COLLECTION_MARKDOWN,
    write_deep_metadata_collection_artifacts,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectionResult,
    collect_deep_metadata_from_plan,
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
    MAX_BODY_PREVIEW_CHARS,
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    collect_deep_source_routes_from_plan,
)
from bugslyce.recon.evidence_pack_closure import (
    EvidencePackReference,
    evidence_pack_references_from_deep_models,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.http_metadata import (
    run_http_metadata_workflow,
    write_http_metadata_execution_result,
)
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    build_http_route_relationship_clusters,
    render_http_route_relationship_clusters_markdown,
    render_http_route_relationship_clusters_runbook,
)
from bugslyce.recon.investigation_threads import (
    build_investigation_threads,
    render_investigation_threads_markdown,
    render_standard_investigation_workflow_runbook_section,
)
from bugslyce.recon.reasoning_relationships import build_route_reasoning_review
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
from bugslyce.recon.native_content_discovery import (
    NativeContentDiscoveryLimits,
    NativeContentDiscoveryPlan,
    NativeContentDiscoveryResult,
    build_native_content_discovery_plan,
    run_native_content_discovery,
)
from bugslyce.recon.programme_orchestration import (
    ProgrammeOrchestrationPlan,
    build_programme_orchestration_plan,
)
from bugslyce.recon.recursive_evidence_feedback import (
    RecursiveEvidenceFeedbackCollectedResponse,
    RecursiveEvidenceFeedbackLimits,
    RecursiveEvidenceFeedbackPlan,
    RecursiveEvidenceFeedbackResult,
    build_recursive_evidence_feedback_plan,
    run_recursive_evidence_feedback,
)
from bugslyce.recon.smb_collection import (
    SMBEnumerationNoWork,
    collect_smb_share_evidence,
    write_smb_share_execution_result,
)
from bugslyce.recon.route_source_review import (
    build_route_source_review,
    render_route_source_review_markdown,
)
from bugslyce.recon.status import build_recon_status, write_recon_status
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    coverage_evidence_from_deep_javascript_routes,
    coverage_evidence_from_deep_parameter_inventory,
    coverage_evidence_from_initial_retained_javascript_routes,
    coverage_evidence_from_post_followup_javascript_routes,
)
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
    render_readable_evidence_cards_markdown,
)
from bugslyce.reports.html import write_project_html_report
from bugslyce.reports.investigation_context import InvestigationContextSources
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.reports.operator_brief import build_operator_brief_view
from bugslyce.reports.operator_brief_composition_persistence import (
    OPERATOR_BRIEF_COMPOSITION_FILENAME,
    load_operator_brief_composition_artifact,
    write_operator_brief_composition_artifact,
)
from bugslyce.reports.operator_brief_project import (
    build_project_operator_brief_composition,
)
from bugslyce.reports.operator_report_view import (
    OperatorReportView,
    build_operator_report_view,
)
from bugslyce.reports.operator_summary import (
    OperatorSummary,
    OperatorSummaryLead,
    build_deep_operator_summary_leads,
    build_operator_summary,
    count_direct_structured_disclosure_leads,
)
from bugslyce.time_utils import Clock, utc_now_iso
from bugslyce.triage.candidates import generate_candidates
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


PIPELINE_PROFILE = QUICK_RECON_PROFILE
LEGACY_QUICK_PIPELINE_PROFILE = PIPELINE_PROFILE
STANDARD_PIPELINE_PROFILE = STANDARD_RECON_PROFILE
DEEP_PIPELINE_PROFILE = DEEP_RECON_PROFILE
NORMAL_PIPELINE_PROFILE = DEEP_PIPELINE_PROFILE
SUPPORTED_PIPELINE_PROFILES = (NORMAL_PIPELINE_PROFILE,)
PIPELINE_JSON_FILENAME = "project_pipeline.json"
PIPELINE_MARKDOWN_FILENAME = "project_pipeline.md"
PARTIAL_DEEP_RESUME_MESSAGE = (
    "Partial Deep pipeline state cannot be resumed safely because the full "
    "in-memory collection results are not persisted. Start a clean Deep run "
    "rather than repeating bounded network collection."
)
LEGACY_DEEP_FIXED_ARTEFACT_FILENAMES = (
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
    DEEP_RECON_ORCHESTRATION_JSON,
)
DEEP_FIXED_ARTEFACT_FILENAMES = (
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_METADATA_COLLECTION_MARKDOWN,
    DEEP_METADATA_COLLECTION_JSON,
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
    "PIPELINE-STEP-003S": (
        "Existing bounded SMB share-enumeration outcome detected; "
        "phase skipped during resume."
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
DEEP_CONTENT_FAILURE_DEPENDENT_STEP_IDS = (
    "PIPELINE-STEP-008",
    "PIPELINE-STEP-009",
)


@dataclass(frozen=True)
class DeepPipelineOutputs:
    """In-memory Deep pipeline outputs shared between adjacent steps."""

    source_collection: DeepSourceRouteCollectionResult | None = None
    metadata_collection: DeepMetadataCollectionResult | None = None
    shallow_followups: DeepShallowRouteFollowupResult | None = None
    recursive_feedback_plan: RecursiveEvidenceFeedbackPlan | None = None
    recursive_feedback_result: RecursiveEvidenceFeedbackResult | None = None
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


class ServiceVersionNoWork(ValueError):
    """Signal a policy-approved service/version no-op without producing traffic."""


class TCPDiscoveryNoWork(ValueError):
    """Signal a policy-approved TCP-discovery no-op without producing traffic."""


class SMBPipelinePolicyNoWork(ValueError):
    """Signal an SMB policy no-op without producing traffic."""


@dataclass(frozen=True)
class PipelineCompletionSummary:
    """Structured report models retained only for terminal completion output."""

    collection_confidence_notices: tuple[CollectionConfidenceNotice, ...]
    operator_summary: OperatorSummary
    operator_report_view: OperatorReportView | None = None


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
    completion_summary: PipelineCompletionSummary | None = field(
        default=None,
        compare=False,
        repr=False,
    )


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
    if any(step.status == "skipped_dependency" for step in result.steps):
        return (
            f"Pipeline recorded a failure at step {failed_step}.",
            "Dependent stages were skipped; execution continued only while "
            "remaining stage prerequisites were satisfied.",
            "The run remains classified as failed.",
            "Review the failed and dependency-skipped step diagnostics and retained local evidence.",
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


def enforce_project_execution_policy(
    project: object,
    profile: str | None = None,
) -> BugBountyProjectRuntime | None:
    """Build the strict runtime for supported bug-bounty project profiles."""

    if getattr(project, "engagement_context", None) != BUG_BOUNTY_CONTEXT:
        return None
    if profile != NORMAL_PIPELINE_PROFILE:
        raise ValueError(
            "Bug-bounty live execution is supported only through the policy-aware "
            "Reconnaissance project pipeline."
        )
    return build_bug_bounty_project_runtime(project, profile)


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
    project_runtime = enforce_project_execution_policy(project, profile)
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
        project_runtime=project_runtime,
    )
    preserve_canonical_pipeline_metadata = assessment.preserve_canonical_pipeline_metadata

    steps = _pending_steps(profile)
    for index, step in enumerate(steps):
        if step.step_id in assessment.skipped_step_ids:
            steps[index] = replace(
                step,
                status="skipped_existing",
                message=_skipped_step_message(step.step_id, assessment.prior_pipeline),
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
        "project_runtime": project_runtime,
    }
    total_steps = len(result.steps)
    content_step_position = next(
        index
        for index, step in enumerate(result.steps, start=1)
        if step.step_id == "PIPELINE-STEP-007"
    )
    content_step_name = result.steps[content_step_position - 1].name
    comparator_progress_callback = (
        lambda message: _emit(
            progress_callback,
            f"[{content_step_position}/{total_steps}] {content_step_name}: {message}",
        )
        if progress_callback is not None
        else None
    )
    gobuster_indeterminate_origins: set[str] = set()

    def _forward_gobuster_progress(event) -> None:
        if event.trusted:
            gobuster_indeterminate_origins.discard(event.origin)
        elif event.origin in gobuster_indeterminate_origins:
            return
        else:
            gobuster_indeterminate_origins.add(event.origin)

        _emit(
            progress_callback,
            (
                f"[{content_step_position}/{total_steps}] {content_step_name}: "
                + render_content_discovery_progress(
                    origin=event.origin,
                    completed=event.completed,
                    total=event.total,
                    elapsed_seconds=event.elapsed_seconds,
                    trusted=event.trusted,
                )
            ),
        )

    gobuster_progress_callback = (
        _forward_gobuster_progress
        if progress_callback is not None
        else None
    )
    step_runners = _step_runners(
        context,
        clock,
        comparator_progress_callback=comparator_progress_callback,
        gobuster_progress_callback=gobuster_progress_callback,
    )
    deferred_failure_diagnostic: str | None = None
    for index in range(len(result.steps)):
        step = result.steps[index]
        position = index + 1
        if step.status == "skipped_existing":
            _emit(
                progress_callback,
                f"[{position}/{total_steps}] {step.name} skipped.\n{step.message}",
            )
            continue
        if step.status == "skipped_dependency":
            _emit(
                progress_callback,
                f"[{position}/{total_steps}] {step.name} dependency-skipped.\n{step.message}",
            )
            continue
        _emit(progress_callback, f"[{position}/{total_steps}] {step.name} starting...")
        started_step = replace(step, status="running", started_at=utc_now_iso(clock))
        result = _replace_step(result, index, started_step)
        _write_project_pipeline_checkpoint(result, preserve_canonical_pipeline_metadata)
        try:
            message, output_paths, updates = step_runners[step.step_id]()
        except (
            TCPDiscoveryNoWork,
            ServiceVersionNoWork,
            SMBEnumerationNoWork,
            SMBPipelinePolicyNoWork,
            PathFollowupNoWork,
            ContentFollowupNoWork,
            BodyFetchNoWork,
        ) as outcome:
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
            if _may_continue_after_deep_content_failure(profile, step.step_id):
                result = _mark_deep_content_dependent_steps_skipped(result)
                _write_project_pipeline_checkpoint(
                    result,
                    preserve_canonical_pipeline_metadata,
                )
                deferred_failure_diagnostic = diagnostic
                continue
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
            if _may_continue_after_deep_content_failure(profile, step.step_id):
                result = _mark_deep_content_dependent_steps_skipped(result)
                _write_project_pipeline_checkpoint(
                    result,
                    preserve_canonical_pipeline_metadata,
                )
                deferred_failure_diagnostic = diagnostic
                continue
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
        final_status=(
            "failed" if deferred_failure_diagnostic is not None else "completed"
        ),
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
    completion_summary = context.get("completion_summary")
    if isinstance(completion_summary, PipelineCompletionSummary):
        result = replace(result, completion_summary=completion_summary)
    if deferred_failure_diagnostic is not None:
        raise ProjectPipelineFailed(deferred_failure_diagnostic, result)
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
    payload = asdict(result)
    payload.pop("completion_summary", None)
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
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
        f"- Dependency-skipped steps: `{_dependency_skipped_count(result)}`",
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
    final_outputs = []
    review_commands = []
    if outputs["html_report"] != "not generated":
        final_outputs.append(f"- HTML report: `{outputs['html_report']}`")
        review_commands.append(f"xdg-open {outputs['html_report']}")
    final_outputs.extend(
        [
            f"- Markdown report: `{outputs['report']}`",
            f"- Recon status: `{outputs['status']}`",
            f"- Runbook: `{outputs['runbook']}`",
            f"- Pipeline metadata JSON: `{outputs['pipeline_json']}`",
            f"- Pipeline metadata Markdown: `{outputs['pipeline_markdown']}`",
            f"- Evidence pack: `{outputs['export']}`",
        ]
    )
    review_commands.append(f"less {outputs['report']}")
    lines.extend(
        [
            "## Final Outputs",
            "",
            *final_outputs,
            "",
            "## Suggested Review Commands",
            "",
            "```bash",
            *review_commands,
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
    lines = [
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
        f"* Dependency-skipped: {_dependency_skipped_count(result)}",
        f"* No-op: {result.no_op_steps}",
        f"* Failed: {failed_count}",
        "",
    ]
    completion_summary = getattr(result, "completion_summary", None)
    compact_summary = _render_compact_run_summary(completion_summary)
    if compact_summary is not None:
        lines.extend([*compact_summary, ""])
    final_outputs = []
    if outputs["html_report"] != "not generated":
        final_outputs.append(f"* HTML report: {outputs['html_report']}")
    final_outputs.extend(
        [
            f"* Markdown report: {outputs['report']}",
            f"* Status: {outputs['status']}",
            f"* Runbook: {outputs['runbook']}",
            f"* Pipeline metadata: {outputs['pipeline_markdown']}",
            f"* Evidence pack: {outputs['export']}",
        ]
    )
    review_guidance = []
    if outputs["html_report"] != "not generated":
        review_guidance.extend(
            [
                "* Open the HTML Operator Report:",
                f"  xdg-open {outputs['html_report']}",
                "",
                "Text fallback:",
            ]
        )
    review_guidance.extend(
        [
            "* Review the Markdown report:",
            f"  less {outputs['report']}",
        ]
    )
    lines.extend(
        [
            "Final outputs:",
            *final_outputs,
            "",
            "Recommended next action:",
            *review_guidance,
            "",
            "Optional:",
            "* Preview next safe action:",
            f"  bugslyce project next --project {result.project_file}",
            "",
            "No NSE scripts, UDP scans, brute force, exploitation, recursive discovery, form submission, authentication testing, or arbitrary commands were run.",
        ]
    )
    return "\n".join(lines)


def _render_compact_run_summary(
    summary: object,
) -> tuple[str, ...] | None:
    notices = getattr(summary, "collection_confidence_notices", None)
    operator_summary = getattr(summary, "operator_summary", None)
    if not isinstance(notices, tuple) or not isinstance(
        operator_summary,
        OperatorSummary,
    ):
        return None
    if not all(isinstance(notice, CollectionConfidenceNotice) for notice in notices):
        return None
    if not all(
        isinstance(lead, OperatorSummaryLead)
        for lead in operator_summary.ranked_leads
    ):
        return None

    lines = ["BugSlyce Run Summary", "", "Collection confidence:"]
    if notices:
        for notice in notices[:5]:
            lines.extend(_terminal_bullet(f"{notice.title}: {notice.direct_fact}"))
        remaining = len(notices) - 5
        if remaining > 0:
            noun = "notice" if remaining == 1 else "notices"
            lines.append(
                f"... and {remaining} more confidence {noun} in the full report."
            )
    else:
        lines.extend(
            _terminal_bullet(
                "No material collection-confidence notice was recorded. "
                "This does not prove exhaustive coverage."
            )
        )

    lines.extend(["", "Review first:"])
    review_first = operator_summary.ranked_leads
    if review_first:
        for lead in review_first[:5]:
            lines.extend(
                _terminal_bullet(
                    f"{lead.rank}. [{lead.lead_id}] {lead.title}: {lead.rationale}"
                )
            )
        remaining = len(review_first) - 5
        if remaining > 0:
            noun = "item" if remaining == 1 else "items"
            lines.append(
                f"... and {remaining} more prioritised {noun} in the full report."
            )
    else:
        lines.extend(
            _terminal_bullet(
                "No prioritised review item was produced. Review the full report and "
                "retained evidence."
            )
        )

    lines.extend(
        [
            "",
            "This is a compact overview. The full report contains complete evidence "
            "and provenance.",
        ]
    )
    return tuple(lines)


def _terminal_bullet(text: str) -> tuple[str, ...]:
    return tuple(
        textwrap.wrap(
            text,
            width=88,
            initial_indent="* ",
            subsequent_indent="  ",
            break_long_words=False,
            break_on_hyphens=False,
        )
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
        "html_report": (
            str(output_dir / "report.html")
            if (output_dir / "report.html").is_file()
            and not (output_dir / "report.html").is_symlink()
            else "not generated"
        ),
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
    project_runtime: BugBountyProjectRuntime | None = None,
) -> ResumeAssessment:
    if not output_dir.is_dir():
        raise ValueError(f"Project output directory does not exist: {output_dir}")
    validate_explicit_nmap_target_scope(target, scope_file)
    _validate_readiness(doctor, profile, project_runtime=project_runtime)
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


def _validate_readiness(
    doctor: DoctorReport,
    profile: str,
    *,
    project_runtime: BugBountyProjectRuntime | None = None,
) -> None:
    failures = mode_readiness_failures(
        doctor,
        _doctor_mode_for_pipeline_profile(profile),
        nmap_required=not (
            project_runtime is not None and project_runtime.tcp_discovery_skipped
        ),
    )
    if failures:
        raise ValueError(" ".join(failures))


def _doctor_mode_for_pipeline_profile(profile: str) -> str:
    if profile == LEGACY_QUICK_PIPELINE_PROFILE:
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
    canonical_resume = _validate_canonical_operator_brief_resume_state(
        prior_pipeline,
        output_dir,
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
    legacy_smb_resume = (
        prior_pipeline is None
        or "PIPELINE-STEP-003S" not in prior_statuses
    )
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
        "PIPELINE-STEP-002": "nmap-allports.txt" in artifact_names
        or prior_statuses.get("PIPELINE-STEP-002") == "noop",
        "PIPELINE-STEP-003": any(
            name.startswith("nmap-services") for name in artifact_names
        ) or prior_statuses.get("PIPELINE-STEP-003") == "noop",
        "PIPELINE-STEP-003S": (
            (
                legacy_smb_resume
                and (
                    any(
                        name.startswith("nmap-services")
                        for name in artifact_names
                    )
                    or prior_statuses.get("PIPELINE-STEP-003") == "noop"
                )
            )
            or any(name.startswith("smb-shares-") for name in artifact_names)
            or prior_statuses.get("PIPELINE-STEP-003S")
            in {"completed", "noop", "skipped_existing"}
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
            name.startswith(
                ("gobuster-tiny-", "content-discovery-internal-")
            )
            for name in artifact_names
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
    if (
        canonical_resume
        and prior_pipeline is not None
        and prior_pipeline.get("final_status") == "completed"
        and all(
            prior_statuses.get(step_id) == "completed"
            for step_id in ("PIPELINE-STEP-010", "PIPELINE-STEP-011")
        )
    ):
        skipped.update({"PIPELINE-STEP-010", "PIPELINE-STEP-011"})
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


def _validate_canonical_operator_brief_resume_state(
    prior_pipeline: dict[str, object] | None,
    output_dir: Path,
) -> bool:
    """Validate the canonical snapshot declared by current pipeline metadata."""

    canonical_path = output_dir / OPERATOR_BRIEF_COMPOSITION_FILENAME
    expected = canonical_path.resolve(strict=False)
    declared = False
    raw_steps = prior_pipeline.get("steps") if prior_pipeline is not None else None
    if isinstance(raw_steps, list):
        for step in raw_steps:
            if not isinstance(step, dict) or step.get("step_id") != "PIPELINE-STEP-010":
                continue
            output_paths = step.get("output_paths")
            if not isinstance(output_paths, list):
                break
            for raw_path in output_paths:
                if not isinstance(raw_path, str):
                    continue
                candidate = Path(raw_path).expanduser()
                if candidate.name != OPERATOR_BRIEF_COMPOSITION_FILENAME:
                    continue
                if candidate.resolve(strict=False) != expected:
                    raise ValueError(
                        "Stage 010 declares a noncanonical Operator Brief "
                        "composition path."
                    )
                declared = True
            break

    if declared:
        if load_operator_brief_composition_artifact(output_dir) is None:
            raise ValueError("Declared canonical Operator Brief composition is missing.")
        return True
    if canonical_path.exists() or canonical_path.is_symlink():
        raise ValueError(
            "Canonical Operator Brief composition exists without a Stage 010 "
            "declaration; resume state is ambiguous."
        )
    return False


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
    required_deep_names = _completed_deep_artefact_names(prior_pipeline)
    if required_deep_names == LEGACY_DEEP_FIXED_ARTEFACT_FILENAMES and any(
        (output_dir / name).exists()
        for name in (
            DEEP_METADATA_COLLECTION_MARKDOWN,
            DEEP_METADATA_COLLECTION_JSON,
        )
    ):
        return False
    required = (
        output_dir / "report.md",
        output_dir / "recon_status.md",
        output_dir / "recon_status.json",
        output_dir / "runbook.md",
        *(output_dir / name for name in required_deep_names),
        export_path,
    )
    return all(path.is_file() for path in required)


def _completed_deep_artefact_names(
    prior_pipeline: dict[str, object],
) -> tuple[str, ...]:
    raw_steps = prior_pipeline.get("steps")
    if not isinstance(raw_steps, list):
        return DEEP_FIXED_ARTEFACT_FILENAMES
    for step in raw_steps:
        if not isinstance(step, dict) or step.get("step_id") != "PIPELINE-STEP-010D":
            continue
        output_paths = step.get("output_paths")
        if not isinstance(output_paths, list):
            break
        recorded_names = {
            Path(path).name for path in output_paths if isinstance(path, str)
        }
        if {
            DEEP_METADATA_COLLECTION_MARKDOWN,
            DEEP_METADATA_COLLECTION_JSON,
        } & recorded_names:
            return DEEP_FIXED_ARTEFACT_FILENAMES
        return LEGACY_DEEP_FIXED_ARTEFACT_FILENAMES
    return LEGACY_DEEP_FIXED_ARTEFACT_FILENAMES


def _completed_deep_resume_skipped_steps(
    prior_statuses: dict[str, str],
) -> tuple[str, ...]:
    reusable = {"completed", "noop"}
    return tuple(
        step_id
        for step_id in (
            "PIPELINE-STEP-002",
            "PIPELINE-STEP-003",
            "PIPELINE-STEP-003S",
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
        if (
            prior_statuses.get(step_id) in reusable
            or (
                step_id == "PIPELINE-STEP-003S"
                and step_id not in prior_statuses
            )
        )
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
        "PIPELINE-STEP-003S",
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


def _skipped_step_message(
    step_id: str,
    prior_pipeline: dict[str, object] | None,
) -> str:
    prior_statuses = _prior_step_statuses(prior_pipeline)
    if step_id == "PIPELINE-STEP-002" and prior_statuses.get(step_id) == "noop":
        return (
            "Prior engagement-policy TCP-discovery no-op verified; phase skipped "
            "during resume."
        )
    if step_id == "PIPELINE-STEP-003" and prior_statuses.get(step_id) == "noop":
        return (
            "Prior policy-approved service/version no-op verified; phase skipped "
            "during resume."
        )
    if step_id == "PIPELINE-STEP-003S" and step_id not in prior_statuses:
        return (
            "Legacy pipeline metadata predates SMB share enumeration; SMB phase "
            "skipped during resume to avoid introducing new live network traffic."
        )
    return SKIPPED_STEP_MESSAGES[step_id]


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


def _dependency_skipped_count(result: PipelineResult) -> int:
    return sum(step.status == "skipped_dependency" for step in result.steps)


def _may_continue_after_deep_content_failure(profile: str, step_id: str) -> bool:
    return profile == DEEP_PIPELINE_PROFILE and step_id == "PIPELINE-STEP-007"


def _mark_deep_content_dependent_steps_skipped(
    result: PipelineResult,
) -> PipelineResult:
    steps = list(result.steps)
    for index, step in enumerate(steps):
        if step.step_id not in DEEP_CONTENT_FAILURE_DEPENDENT_STEP_IDS:
            continue
        steps[index] = replace(
            step,
            status="skipped_dependency",
            message=(
                "Skipped because PIPELINE-STEP-007 bounded content discovery "
                "execution failed."
            ),
            output_paths=[],
        )
    return replace(result, steps=steps)


def _content_discovery_profile_for_pipeline(profile: str) -> str:
    if profile == STANDARD_PIPELINE_PROFILE:
        return STANDARD_BOUNDED_CORE_PROFILE
    if profile == DEEP_PIPELINE_PROFILE:
        return DEEP_BOUNDED_CORE_PROFILE
    return CONTENT_DISCOVERY_TINY_PROFILE


_NATIVE_TOTAL_CANDIDATE_REQUEST_LIMIT = 4096
_NATIVE_PER_ORIGIN_LIMIT_BY_CONTENT_PROFILE = {
    CONTENT_DISCOVERY_TINY_PROFILE: 25,
    STANDARD_BOUNDED_CORE_PROFILE: 220,
    DEEP_BOUNDED_CORE_PROFILE: 1753,
}


def _native_content_discovery_limits_for_pipeline(
    profile: str,
) -> NativeContentDiscoveryLimits:
    content_profile = _content_discovery_profile_for_pipeline(profile)
    try:
        per_origin = _NATIVE_PER_ORIGIN_LIMIT_BY_CONTENT_PROFILE[content_profile]
    except KeyError as exc:
        raise ValueError("Pipeline content profile has no native request limit.") from exc
    return NativeContentDiscoveryLimits(
        maximum_total_candidate_requests=_NATIVE_TOTAL_CANDIDATE_REQUEST_LIMIT,
        maximum_candidate_requests_per_origin=per_origin,
    )


def _recursive_evidence_feedback_limits() -> RecursiveEvidenceFeedbackLimits:
    return RecursiveEvidenceFeedbackLimits(
        maximum_total_candidate_requests=800,
        maximum_candidate_requests_per_origin=100,
        maximum_depth=1,
    )


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
        (
            "PIPELINE-STEP-003S",
            "bounded anonymous SMB share enumeration",
            "smb-share-list",
        ),
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
    *,
    comparator_progress_callback: Callable[[str], None] | None = None,
    gobuster_progress_callback: (
        Callable[[ContentDiscoveryProgressEvent], None] | None
    ) = None,
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
    project_runtime = context.get("project_runtime")
    assert isinstance(output_dir, Path)
    assert isinstance(scope_file, Path)
    assert isinstance(plan_dir, Path)
    assert isinstance(plan_path, Path)
    assert isinstance(export_path, Path)
    assert isinstance(target, str)
    assert isinstance(project_file, Path)
    assert isinstance(resume, bool)
    assert isinstance(profile, str)
    if project_runtime is not None and not isinstance(project_runtime, BugBountyProjectRuntime):
        raise ValueError("Project runtime is invalid.")

    def validation():
        state = "resume provenance" if resume else "fresh output"
        return f"Local readiness, {state}, and exact scope checks passed.", [], {}

    def nmap_discover():
        if project_runtime is not None and project_runtime.tcp_discovery_skipped:
            raise TCPDiscoveryNoWork(
                "TCP discovery was intentionally skipped by the engagement policy."
            )
        result = (
            run_nmap_discovery_workflow(
                target=target,
                scope_file=scope_file,
                output_dir=output_dir,
                profile_name="lab-tcp-full",
                runner=project_runtime.nmap_discovery_runner(),
                project_runtime=project_runtime,
            )
            if project_runtime
            else run_nmap_discovery_workflow(
                target=target,
                scope_file=scope_file,
                output_dir=output_dir,
                profile_name="lab-tcp-full",
            )
        )
        metadata = write_nmap_discovery_execution_result(result, output_dir)
        return (
            (
                "Strict policy-authorised TCP discovery completed."
                if project_runtime
                else "One approved lab-tcp-full discovery completed."
            ),
            [result.nmap_output_path, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def nmap_services():
        if project_runtime is not None and project_runtime.tcp_discovery_skipped:
            raise ServiceVersionNoWork(
                "Nmap service/version enrichment was intentionally skipped because "
                "TCP discovery produced no trusted open-port observations."
            )
        if project_runtime is not None and not project_runtime.service_version_permitted:
            raise ServiceVersionNoWork(
                "Nmap service/version enrichment was intentionally skipped because "
                "the engagement policy does not permit it."
            )
        result = (
            run_nmap_service_workflow(
                output_dir,
                scope_file,
                runner=project_runtime.nmap_service_runner(),
                project_runtime=project_runtime,
            )
            if project_runtime
            else run_nmap_service_workflow(output_dir, scope_file)
        )
        metadata = write_nmap_service_execution_result(result, output_dir)
        return (
            "Service/version detection completed on discovered open TCP ports.",
            [result.nmap_output_path, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def smb_shares():
        if project_runtime is not None:
            raise SMBPipelinePolicyNoWork(
                "Bounded SMB share enumeration is intentionally disabled for "
                "live bug-bounty project pipelines."
            )

        result = collect_smb_share_evidence(
            output_dir,
            scope_file,
        )
        metadata = write_smb_share_execution_result(
            result,
            output_dir,
        )
        successful_outputs = list(
            dict.fromkeys(
                item.output_file
                for item in result.command_results
                if item.exit_code == 0 and item.error is None
            )
        )
        return (
            (
                "Bounded anonymous SMB share enumeration completed: "
                f"{result.commands_succeeded} succeeded, "
                f"{result.commands_unsuccessful} unsuccessful, "
                f"{result.commands_timed_out} timed out."
            ),
            [
                *successful_outputs,
                *(str(path) for path in metadata),
            ],
            {},
        )

    def http_metadata():
        programme_scope_seed_origins = None
        if project_runtime is not None:
            if project_runtime.tcp_discovery_skipped:
                programme_scope_seed_origins = project_runtime.initial_http_origins
                project_runtime.bind_http_origins(programme_scope_seed_origins)
            else:
                state = build_project_state(output_dir)
                from bugslyce.recon.http_metadata import discover_http_origins
                project_runtime.bind_http_origins(
                    tuple(discover_http_origins(state, target))
                )
        result = (
            run_http_metadata_workflow(
                output_dir,
                scope_file,
                runner=project_runtime.curl_runner(),
                project_runtime=project_runtime,
                programme_scope_seed_origins=programme_scope_seed_origins,
            )
            if project_runtime
            else run_http_metadata_workflow(output_dir, scope_file)
        )
        metadata = write_http_metadata_execution_result(result, output_dir)
        return (
            "HTTP metadata collection completed for discovered services.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def path_followup():
        result = (
            run_path_followup_workflow(
                output_dir,
                scope_file,
                runner=project_runtime.curl_runner(),
                project_runtime=project_runtime,
            )
            if project_runtime
            else run_path_followup_workflow(output_dir, scope_file)
        )
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
        def legacy_content_run():
            result = (
                run_content_discovery_workflow(
                    plan_path,
                    scope_file,
                    comparator_progress_callback=comparator_progress_callback,
                    gobuster_progress_callback=gobuster_progress_callback,
                    runner=project_runtime.gobuster_runner(),
                    http_executor=project_runtime.http_executor,
                    project_runtime=project_runtime,
                )
                if project_runtime is not None
                else run_content_discovery_workflow(
                    plan_path,
                    scope_file,
                    comparator_progress_callback=comparator_progress_callback,
                    gobuster_progress_callback=gobuster_progress_callback,
                )
            )
            metadata = write_content_discovery_execution_result(result, plan_dir)
            result_profile = getattr(
                result,
                "profile",
                _content_discovery_profile_for_pipeline(profile),
            )
            return (
                f"Approved {result_profile} content discovery completed.",
                [*result.artifact_paths, *(str(path) for path in metadata)],
                {"report_path": result.report_path},
            )

        if project_runtime is None:
            return legacy_content_run()
        project_state = build_project_state(output_dir)
        if not isinstance(project_state, ProjectState):
            return legacy_content_run()
        programme_orchestration = build_programme_orchestration_plan(
            project_runtime,
            project_state,
        )
        root_plan = build_native_content_discovery_plan(
            project_runtime,
            project_state,
            programme_orchestration,
            profile=_content_discovery_profile_for_pipeline(profile),
            limits=_native_content_discovery_limits_for_pipeline(profile),
        )
        native_result = run_native_content_discovery(
            project_runtime,
            project_state,
            programme_orchestration,
            root_plan,
            output_dir=output_dir,
        )
        artifact_paths = _register_native_content_discovery_artifacts(
            output_dir,
            native_result,
        )
        context["wp4_root_plan"] = root_plan
        context["wp4_root_result"] = native_result
        context["wp4_programme_orchestration"] = programme_orchestration
        return (
            f"BugSlyce-native {root_plan.profile} content discovery completed.",
            [str(path) for path in artifact_paths],
            {},
        )

    def content_followup():
        result = (
            run_content_followup_workflow(
                output_dir,
                scope_file,
                runner=project_runtime.curl_runner(),
                project_runtime=project_runtime,
            )
            if project_runtime
            else run_content_followup_workflow(output_dir, scope_file)
        )
        metadata = write_content_followup_execution_result(result, output_dir)
        return (
            "Content-discovery result follow-up completed.",
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )

    def body_fetch():
        result = (
            run_body_fetch_workflow(
                output_dir,
                scope_file,
                runner=project_runtime.curl_runner(),
                project_runtime=project_runtime,
            )
            if project_runtime
            else run_body_fetch_workflow(output_dir, scope_file)
        )
        metadata = write_body_fetch_execution_result(result, output_dir)
        failed_transfers = getattr(result, "failed_transfers", 0)
        partial_bodies_retained = getattr(result, "partial_bodies_retained", 0)
        if failed_transfers:
            message = _body_fetch_warning_message(
                failed_transfers,
                partial_bodies_retained,
            )
        else:
            message = "Selective body fetch completed."
        return (
            message,
            [*result.artifact_paths, *(str(path) for path in metadata)],
            {"report_path": result.report_path},
        )
    def deep_collection():
        project_state = build_project_state(output_dir)
        plan = (
            build_deep_collection_request_plan_from_project_state(
                project_state,
                programme_scope_policy=project_runtime.programme_scope_policy,
            )
            if project_runtime
            else build_deep_collection_request_plan_from_project_state(project_state)
        )
        fetcher = (
            build_deep_http_fetcher(executor=project_runtime.http_executor)
            if project_runtime
            else build_deep_http_fetcher()
        )
        initial_source_collection = collect_deep_source_routes_from_plan(
            plan,
            fetcher=fetcher,
        )
        metadata_plan = _deep_plan_for_source(plan, "metadata_coverage")
        metadata_collection = collect_deep_metadata_from_plan(
            metadata_plan,
            fetcher=fetcher,
        )
        metadata_paths = write_deep_metadata_collection_artifacts(
            metadata_collection,
            output_dir,
        )
        html_routes = build_deep_html_route_extraction(initial_source_collection)
        javascript_routes = build_deep_javascript_route_extraction(
            initial_source_collection
        )
        followup_plan = (
            build_deep_shallow_route_followup_plan(
                html_routes,
                javascript_routes,
                programme_scope_policy=project_runtime.programme_scope_policy,
            )
            if project_runtime
            else build_deep_shallow_route_followup_plan(html_routes, javascript_routes)
        )
        shallow_followups = collect_deep_shallow_route_followups(
            followup_plan,
            fetcher=fetcher,
        )
        source_collection = initial_source_collection
        recursive_plan = None
        recursive_result = None
        if project_runtime is not None:
            root_plan = context.get("wp4_root_plan")
            programme_orchestration = context.get("wp4_programme_orchestration")
            if root_plan is not None or programme_orchestration is not None:
                if not isinstance(root_plan, NativeContentDiscoveryPlan):
                    raise ValueError(
                        "Deep recursive feedback requires the exact native root plan."
                    )
                if not isinstance(
                    programme_orchestration,
                    ProgrammeOrchestrationPlan,
                ):
                    raise ValueError(
                        "Deep recursive feedback requires programme orchestration."
                    )
                recursive_plan = build_recursive_evidence_feedback_plan(
                    project_runtime,
                    project_state,
                    programme_orchestration,
                    root_plan=root_plan,
                    metadata_collection=metadata_collection,
                    html_extraction=html_routes,
                    javascript_extraction=javascript_routes,
                    source_depth=0,
                    limits=_recursive_evidence_feedback_limits(),
                )
                recursive_result = run_recursive_evidence_feedback(
                    project_runtime,
                    project_state,
                    programme_orchestration,
                    recursive_plan,
                    root_plan=root_plan,
                    metadata_collection=metadata_collection,
                    html_extraction=html_routes,
                    javascript_extraction=javascript_routes,
                )
                source_collection = _merge_recursive_source_collection(
                    initial_source_collection,
                    recursive_result,
                )
        source_paths = write_deep_source_route_collection_artifacts(
            source_collection,
            output_dir,
        )
        current = _deep_outputs_from_context(context)
        context["deep_outputs"] = replace(
            current,
            source_collection=source_collection,
            metadata_collection=metadata_collection,
            shallow_followups=shallow_followups,
            recursive_feedback_plan=recursive_plan,
            recursive_feedback_result=recursive_result,
            deep_artifact_paths=_dedupe_paths((*source_paths, *metadata_paths)),
        )
        return (
            "Deep bounded source-route and metadata collection, with shallow same-origin follow-up, completed.",
            [str(path) for path in (*source_paths, *metadata_paths)],
            {},
        )

    def deep_orchestration():
        current = _deep_outputs_from_context(context)
        if (
            current.source_collection is None
            or current.metadata_collection is None
            or current.shallow_followups is None
        ):
            raise ValueError("Deep collection results are required before orchestration.")
        initial_retained_javascript_routes = (
            build_deep_initial_retained_javascript_route_extraction(
                build_project_state(output_dir),
                current.source_collection,
            )
        )
        orchestration = build_deep_recon_orchestration(
            current.source_collection,
            current.shallow_followups,
            metadata_collection=current.metadata_collection,
            initial_retained_javascript_route_extraction=(
                initial_retained_javascript_routes
            ),
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
        project_state = build_project_state(output_dir)
        deep_source_collection = None
        deep_orchestration_result = None
        if profile == DEEP_PIPELINE_PROFILE:
            deep_outputs = _deep_outputs_from_context(context)
            deep_source_collection = deep_outputs.source_collection
            deep_orchestration_result = deep_outputs.orchestration
        operator_brief_composition = build_project_operator_brief_composition(
            project_root=output_dir,
            project_state=project_state,
            profile=profile,
            deep_source_collection=deep_source_collection,
            deep_orchestration=deep_orchestration_result,
        )
        operator_brief_composition_path = write_operator_brief_composition_artifact(
            output_dir,
            operator_brief_composition,
        )
        report_paths = _write_interpretation_report_if_needed(
            profile,
            output_dir,
            context,
        )
        if "completion_summary" not in context:
            completion_summary = _build_completion_summary_from_project(output_dir)
            if completion_summary is not None:
                context["completion_summary"] = completion_summary
        result = build_recon_status(output_dir, scope_file, clock=clock)
        json_path, markdown_path = write_recon_status(result, output_dir)
        output_paths = [
            str(operator_brief_composition_path),
            *report_paths,
            str(json_path),
            str(markdown_path),
        ]
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
        reference_requirements = _evidence_pack_reference_requirements(
            profile,
            output_dir,
            context,
        )
        write_project_html_report(output_dir)
        if deep_evidence_paths is None:
            result = export_recon_evidence_pack(
                output_dir,
                export_path,
                clock=clock,
                reference_requirements=reference_requirements,
            )
        else:
            result = export_recon_evidence_pack(
                output_dir,
                export_path,
                clock=clock,
                deep_evidence_paths=deep_evidence_paths,
                reference_requirements=reference_requirements,
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
        "PIPELINE-STEP-003S": smb_shares,
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


def _body_fetch_warning_message(
    failed_transfers: int,
    partial_bodies_retained: int,
) -> str:
    transfer_noun = "transfer" if failed_transfers == 1 else "transfers"
    body_noun = "body" if partial_bodies_retained == 1 else "bodies"
    return (
        "Selective body fetch completed with warnings: "
        f"{failed_transfers} {transfer_noun} failed; "
        f"{partial_bodies_retained} partial {body_noun} retained."
    )


def _register_native_content_discovery_artifacts(
    output_dir: Path,
    result: NativeContentDiscoveryResult,
) -> tuple[Path, ...]:
    manifest_path = output_dir / "recon_manifest.json"
    manifest = _load_json_object(manifest_path, "recon manifest")
    existing = manifest.get("artifacts")
    if not isinstance(existing, list):
        raise ValueError("Recon manifest artefacts must be a list.")

    artifacts = list(existing)
    registered_paths: list[Path] = []
    output_root = output_dir.resolve()
    for artifact in result.artifacts:
        artifact_path = artifact.path.resolve(strict=True)
        try:
            artifact_path.relative_to(output_root)
        except ValueError as exc:
            raise ValueError(
                "Native content discovery artefact escapes the project output directory."
            ) from exc
        if not artifact_path.is_file() or artifact_path.is_symlink():
            raise ValueError("Native content discovery artefact is not a regular file.")
        artifacts.append(
            {
                "type": artifact.artifact_type,
                "file": artifact_path.name,
                "base_url": artifact.canonical_origin,
                "description": "BugSlyce-native bounded root content discovery",
                "tags": [artifact.selection_reason, "wp4a_native"],
            }
        )
        registered_paths.append(artifact_path)

    if registered_paths:
        payload = dict(manifest)
        payload["artifacts"] = artifacts
        manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return tuple(registered_paths)


def _recursive_response_to_deep_source_item(
    response: RecursiveEvidenceFeedbackCollectedResponse,
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=response.request.url,
        method="GET",
        status_code=response.status_code,
        final_url=response.final_url,
        headers=response.headers,
        body_preview=response.body.decode("utf-8", errors="replace")[
            :MAX_BODY_PREVIEW_CHARS
        ],
        body_sha256=response.body_sha256,
        body_bytes=response.body_bytes,
        elapsed_seconds=response.elapsed_seconds,
        source="recursive_evidence_feedback",
        reason="bounded_second_pass",
        evidence_ids=response.evidence_ids,
        body=response.body,
    )


def _merge_recursive_source_collection(
    initial: DeepSourceRouteCollectionResult,
    recursive_result: RecursiveEvidenceFeedbackResult,
) -> DeepSourceRouteCollectionResult:
    collected = list(initial.collected)
    seen = {(item.method.upper(), item.url) for item in collected}
    for response in recursive_result.collected:
        item = _recursive_response_to_deep_source_item(response)
        key = (item.method.upper(), item.url)
        if key in seen:
            continue
        seen.add(key)
        collected.append(item)
    added = len(collected) - len(initial.collected)
    return DeepSourceRouteCollectionResult(
        collected=tuple(collected),
        skipped=initial.skipped,
        total_considered=initial.total_considered + added,
        total_collected=initial.total_collected + added,
        total_skipped=initial.total_skipped,
    )


def _deep_outputs_from_context(context: dict[str, object]) -> DeepPipelineOutputs:
    outputs = context.get("deep_outputs")
    if not isinstance(outputs, DeepPipelineOutputs):
        raise ValueError("Deep pipeline outputs are not initialised.")
    return outputs


def _deep_plan_for_source(
    plan: DeepCollectionRequestPlan,
    source: str,
) -> DeepCollectionRequestPlan:
    """Project an evaluated plan without re-evaluating its policy decisions."""

    requests = tuple(
        request for request in plan.proposed_requests if request.source == source
    )
    request_keys = {(request.method.upper(), request.url) for request in requests}
    decisions = tuple(
        decision
        for decision in plan.policy_summary.decisions
        if (decision.method.upper(), decision.url) in request_keys
    )
    blocked_reasons = Counter(
        decision.reason for decision in decisions if not decision.allowed
    )
    policy_summary = replace(
        plan.policy_summary,
        decisions=decisions,
        allowed_count=sum(decision.allowed for decision in decisions),
        blocked_count=sum(not decision.allowed for decision in decisions),
        blocked_reasons=tuple(sorted(blocked_reasons.items())),
    )
    source_counts = tuple(
        count for count in plan.source_counts if count.source == source
    )
    return replace(
        plan,
        proposed_requests=requests,
        policy_summary=policy_summary,
        source_counts=source_counts,
    )


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
    confidence_notices = build_collection_confidence_notices_from_project(
        project_state,
        output_dir,
        source_collection=_deep_source_collection_if_available(profile, context),
        metadata_collection=_deep_metadata_collection_if_available(profile, context),
    )
    candidates = generate_candidates(project_state)
    workflow_leads = build_grouped_workflow_leads(project_state, orchestration)
    assembly = (
        assemble_standard_interpretation_from_project_state(
            project_state,
            referenced_direct_lead_count=count_direct_structured_disclosure_leads(
                operator_summary_leads
            ),
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
    relationship_clusters = _http_route_relationship_clusters_if_available(
        profile,
        project_state,
        context,
    )
    route_reasoning_review = build_route_reasoning_review(
        project_state,
        successful_reviews=tuple(
            getattr(orchestration, "successful_content_reviews", ())
        ),
        relationship_clusters=relationship_clusters,
        response_similarity_review=(
            getattr(orchestration, "response_similarity_review", None)
            if orchestration is not None
            else None
        ),
    )
    operator_summary = (
        build_operator_summary(
            project_state,
            candidates,
            additional_leads=operator_summary_leads,
            response_similarity_review=(
                getattr(orchestration, "response_similarity_review", None)
                if orchestration is not None
                else None
            ),
            route_reasoning_review=route_reasoning_review,
        )
        if isinstance(project_state, ProjectState)
        else None
    )
    triage_kwargs: dict[str, object] = {}
    if operator_summary is not None:
        triage_kwargs["ranked_leads"] = operator_summary.ranked_leads
    human_triage_brief = build_human_triage_brief(
        project_state,
        candidates,
        engagement_context=engagement_context,
        deep_orchestration=orchestration,
        workflow_leads=workflow_leads,
        **triage_kwargs,
    )
    coverage_evidence = (
        _report_coverage_evidence(orchestration)
        if orchestration is not None
        else ()
    )
    operator_report_view = (
        build_operator_report_view(
            operator_summary,
            investigation_sources=InvestigationContextSources(
                evidence=tuple(project_state.evidence),
                route_reasoning=route_reasoning_review,
                successful_content=tuple(
                    getattr(orchestration, "successful_content_reviews", ())
                ),
                route_relationships=relationship_clusters,
                forms=(orchestration.form_inventory.forms if orchestration else ()),
                parameters=(
                    orchestration.parameter_inventory.parameters
                    if orchestration
                    else ()
                ),
                workflow_leads=tuple(workflow_leads),
            ),
            coverage_evidence=coverage_evidence,
        )
        if operator_summary is not None
        else None
    )
    relationship_markdown = render_http_route_relationship_clusters_markdown(
        relationship_clusters
    )
    report_kwargs: dict[str, object] = {
        "human_triage_brief_markdown": render_human_triage_brief_markdown(
            human_triage_brief,
            include_ranked_leads=False,
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
    if operator_summary is not None:
        report_kwargs["operator_summary"] = operator_summary
        report_kwargs["operator_brief"] = build_operator_brief_view(
            operator_summary,
        )
        if operator_report_view is not None:
            report_kwargs["operator_report_view"] = operator_report_view
    confidence_markdown = render_collection_confidence_markdown(confidence_notices)
    if confidence_markdown:
        report_kwargs["collection_confidence_markdown"] = confidence_markdown
    if relationship_markdown:
        report_kwargs["http_route_relationships_markdown"] = relationship_markdown
    if deep_recon_markdown is not None:
        report_kwargs["deep_recon_markdown"] = deep_recon_markdown
        report_kwargs["operator_summary_leads"] = operator_summary_leads
        report_kwargs["analysis_coverage_evidence"] = coverage_evidence
    report_path, json_path = write_project_outputs(
        project_state,
        candidates,
        output_dir,
        **report_kwargs,
    )
    if operator_summary is not None and operator_report_view is not None:
        context["completion_summary"] = PipelineCompletionSummary(
            collection_confidence_notices=confidence_notices,
            operator_summary=operator_summary,
            operator_report_view=operator_report_view,
        )
    return [str(report_path), str(json_path)]


def _build_completion_summary_from_project(
    output_dir: Path,
) -> PipelineCompletionSummary | None:
    """Build terminal-only models from final local state without rerendering output."""

    try:
        project_state = build_project_state(output_dir)
    except (OSError, ValueError):
        return None
    if not isinstance(project_state, ProjectState):
        return None
    candidates = generate_candidates(project_state)
    operator_summary = build_operator_summary(project_state, candidates)
    return PipelineCompletionSummary(
        collection_confidence_notices=build_collection_confidence_notices_from_project(
            project_state,
            output_dir,
        ),
        operator_summary=operator_summary,
        operator_report_view=build_operator_report_view(
            operator_summary,
            investigation_sources=InvestigationContextSources(
                evidence=tuple(project_state.evidence),
                workflow_leads=tuple(build_grouped_workflow_leads(project_state)),
            ),
        ),
    )


def _report_coverage_evidence(
    orchestration: DeepReconOrchestrationResult | None,
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    if orchestration is None:
        return ()
    return (
        *coverage_evidence_from_deep_javascript_routes(
            orchestration.javascript_route_extraction
        ),
        *coverage_evidence_from_initial_retained_javascript_routes(
            orchestration.initial_retained_javascript_route_extraction
        ),
        *coverage_evidence_from_post_followup_javascript_routes(
            orchestration.post_followup_javascript_route_extraction
        ),
        *coverage_evidence_from_deep_parameter_inventory(
            orchestration.parameter_inventory
        ),
    )


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
        export_kwargs["reference_requirements"] = (
            _evidence_pack_reference_requirements(
                result.profile,
                output_dir,
                context,
            )
        )
        export_recon_evidence_pack(
            output_dir,
            Path(result.export_path),
            **export_kwargs,
        )
    write_project_pipeline_result(result)


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
    source_review = getattr(orchestration, "source_route_collection_review", None)
    return build_deep_operator_summary_leads(
        tuple(getattr(source_review, "review_leads", ())),
        tuple(getattr(orchestration, "successful_content_reviews", ())),
        http_fingerprint_summary=getattr(
            orchestration,
            "http_fingerprint_summary",
            None,
        ),
        response_similarity_review=getattr(
            orchestration,
            "response_similarity_review",
            None,
        ),
    )


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
    relationship_section = render_http_route_relationship_clusters_runbook(
        _http_route_relationship_clusters_if_available(
            profile,
            project_state,
            context,
        )
    )
    confidence_section = render_collection_confidence_runbook(
        build_collection_confidence_notices_from_project(
            project_state,
            output_dir,
            source_collection=_deep_source_collection_if_available(profile, context),
            metadata_collection=_deep_metadata_collection_if_available(profile, context),
        )
    )
    if (
        not relationship_section
        and not successful_content_section
        and not confidence_section
    ):
        return investigation_section
    return "\n\n".join(
        section.strip()
        for section in (
            investigation_section,
            confidence_section,
            relationship_section,
            successful_content_section,
        )
        if section and section.strip()
    )


def _deep_source_collection_if_available(
    profile: str,
    context: dict[str, object] | None,
) -> object | None:
    if profile != DEEP_PIPELINE_PROFILE or context is None:
        return None
    outputs = context.get("deep_outputs")
    return outputs.source_collection if isinstance(outputs, DeepPipelineOutputs) else None


def _deep_metadata_collection_if_available(
    profile: str,
    context: dict[str, object] | None,
) -> object | None:
    if profile != DEEP_PIPELINE_PROFILE or context is None:
        return None
    outputs = context.get("deep_outputs")
    return outputs.metadata_collection if isinstance(outputs, DeepPipelineOutputs) else None


def _http_route_relationship_clusters_if_available(
    profile: str,
    project_state: ProjectState,
    context: dict[str, object] | None,
) -> tuple[HttpRouteRelationshipCluster, ...]:
    if profile != DEEP_PIPELINE_PROFILE or context is None:
        return ()
    outputs = context.get("deep_outputs")
    if not isinstance(outputs, DeepPipelineOutputs):
        return ()
    orchestration = outputs.orchestration
    if not isinstance(outputs.source_collection, DeepSourceRouteCollectionResult):
        return ()
    if not isinstance(orchestration, DeepReconOrchestrationResult):
        return ()
    return build_http_route_relationship_clusters(
        project_state,
        source_collection=outputs.source_collection,
        successful_reviews=orchestration.successful_content_reviews,
    )


def _evidence_pack_reference_requirements(
    profile: str,
    output_dir: Path,
    context: dict[str, object] | None,
) -> tuple[EvidencePackReference, ...]:
    if profile != DEEP_PIPELINE_PROFILE or context is None:
        return ()
    outputs = context.get("deep_outputs")
    if not isinstance(outputs, DeepPipelineOutputs):
        return ()
    orchestration = outputs.orchestration
    if orchestration is None:
        return ()
    project_state = build_project_state(output_dir)
    return evidence_pack_references_from_deep_models(
        tuple(getattr(orchestration, "successful_content_reviews", ())),
        _http_route_relationship_clusters_if_available(
            profile,
            project_state,
            context,
        ),
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
