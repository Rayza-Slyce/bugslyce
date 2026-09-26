"""Offline dashboard projection, never a semantic, priority or authority owner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bugslyce.core.models import Evidence
from bugslyce.core.engagement_policy import (
    EngagementPolicyAssessment,
    assess_engagement_policy,
)
from bugslyce.core.programme_scope import ACTION_EXCLUDE, ACTION_INCLUDE
from bugslyce.project_session import (
    BugSlyceProject,
    PROJECT_FILENAME,
    load_project,
    load_project_engagement_policy,
    load_project_programme_scope_policy,
)
from bugslyce.recon.application_service_model import ApplicationServiceModel
from bugslyce.recon.application_service_model_persistence import (
    load_application_service_model_artifact,
)
from bugslyce.recon.collection_confidence import (
    CollectionConfidenceNotice,
    build_collection_confidence_notices_from_project,
)
from bugslyce.recon.investigation_thread_persistence import (
    load_investigation_threads_artifact,
)
from bugslyce.recon.investigation_threads import (
    InvestigationThread,
    primary_investigation_threads,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    build_analysis_coverage,
    load_analysis_coverage_artifact,
)
from bugslyce.reports.html_model import load_report_project_state
from bugslyce.reports.investigation_context import (
    InvestigationContextSources,
    build_primary_investigation_contexts_for_threads,
)
from bugslyce.reports.operator_report_view import OperatorReportView


@dataclass(frozen=True)
class DashboardProjectIdentity:
    """Identity/context only; targets are not authorisation decisions."""

    name: str
    target: str | None
    engagement_context: str


@dataclass(frozen=True)
class DashboardAuthoritySummary:
    """Private-owner assessment/counts, not permission to execute on any asset.

    None means the corresponding private policy is absent. No policy objects,
    rule values/notes/source wording, identification values or project notes
    escape into this projection. Readiness is not a destination-scope decision.
    """

    engagement_assessment: EngagementPolicyAssessment | None
    programme_include_rule_count: int | None
    programme_exclude_rule_count: int | None


@dataclass(frozen=True)
class DashboardReadModel:
    """Canonical snapshots and read-side navigation, with honest absence.

    None differs from an authoritative empty thread/coverage tuple. Confidence
    notices are diagnostic only: an empty tuple never proves exhaustive or clean
    collection. This model does not replay semantic composition or validate an
    entire evidence pack's closure. Native/application provenance remains owned
    by the loaded canonical objects; generic evidence navigation uses the
    existing report context interface without inventing another namespace.
    """

    project: DashboardProjectIdentity
    investigation_threads: tuple[InvestigationThread, ...] | None
    primary_investigation_threads: tuple[InvestigationThread, ...] | None
    application_service_model: ApplicationServiceModel | None
    operator_report_view: OperatorReportView
    analysis_coverage_evidence: tuple[AnalysisCoverageExecutionEvidence, ...] | None
    confidence_notices: tuple[CollectionConfidenceNotice, ...]
    authority: DashboardAuthoritySummary
    generic_evidence: tuple[Evidence, ...] | None = None


def build_dashboard_read_model(project: BugSlyceProject | Path) -> DashboardReadModel:
    """Read a project object, project file or artifact root without execution.

    Portable artifact roots need not contain private authority or project-session
    metadata. Missing optional snapshots remain absent; malformed ones propagate
    the existing owner's refusal rather than triggering reconstruction.
    """

    session = project if isinstance(project, BugSlyceProject) else None
    if session is None:
        root = Path(project).expanduser()
        if root.is_file():
            session = load_project(root)
        elif (root / PROJECT_FILENAME).exists():
            session = load_project(root / PROJECT_FILENAME)
    if session is not None:
        root = Path(session.output_dir).expanduser()
    if not root.is_dir():
        raise ValueError("Dashboard project root must be an existing directory")
    root = root.resolve()

    state = load_report_project_state(root)
    threads = load_investigation_threads_artifact(root)
    primary = None if threads is None else primary_investigation_threads(threads)
    application = load_application_service_model_artifact(root)
    coverage = load_analysis_coverage_artifact(root)
    view = OperatorReportView(
        investigation_context=build_primary_investigation_contexts_for_threads(
            primary if primary is not None else (),
            InvestigationContextSources(evidence=tuple(state.evidence) if state else ()),
        ),
        analysis_coverage=build_analysis_coverage(coverage if coverage is not None else ()),
    )
    if session is not None:
        # Respect project-owned references, including refusal of a missing
        # referenced policy. Do not adopt an unrelated/stale private file.
        policy = load_project_engagement_policy(session)
        scope = load_project_programme_scope_policy(session)
    else:
        # A portable artefact root has no project-session authority binding.
        policy = None
        scope = None
    return DashboardReadModel(
        project=DashboardProjectIdentity(
            name=session.name if session else state.project_name if state else root.name,
            target=session.target if session else None,
            engagement_context=(
                session.engagement_context if session
                else state.engagement_context if state else "unknown"
            ),
        ),
        investigation_threads=threads,
        primary_investigation_threads=primary,
        application_service_model=application,
        operator_report_view=view,
        analysis_coverage_evidence=coverage,
        confidence_notices=(
            build_collection_confidence_notices_from_project(state, root)
            if state is not None else ()
        ),
        authority=DashboardAuthoritySummary(
            engagement_assessment=assess_engagement_policy(policy) if policy else None,
            programme_include_rule_count=(
                sum(rule.action == ACTION_INCLUDE for rule in scope.rules)
                if scope is not None else None
            ),
            programme_exclude_rule_count=(
                sum(rule.action == ACTION_EXCLUDE for rule in scope.rules)
                if scope is not None else None
            ),
        ),
        generic_evidence=tuple(state.evidence) if state is not None else None,
    )
