"""Project-source adaptation for canonical Operator Brief composition."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from bugslyce.core.models import HTTPArtifact, ProjectState
from bugslyce.recon.deep_collection_review_bundle import (
    empty_deep_source_route_collection_review_summary,
)
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpFingerprintSummaryCounts,
)
from bugslyce.recon.deep_orchestration import DeepReconOrchestrationResult
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    DeepResponseSimilaritySummaryCounts,
)
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult
from bugslyce.recon.http_route_relationships import (
    build_http_route_relationship_clusters,
)
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
)
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.operator_brief_assembly import (
    OperatorBriefComposition,
    assemble_operator_brief,
)
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpCompositionInput,
    build_operator_brief_http_inputs_from_deep,
    combine_operator_brief_http_inputs,
    compose_operator_brief_http,
)
from bugslyce.reports.operator_brief_http_retained_manifest import (
    build_operator_brief_http_inputs_from_retained_manifest_html,
)
from bugslyce.reports.operator_brief_multi_family_assembly import (
    assemble_operator_brief_policy_subjects,
)
from bugslyce.reports.operator_brief_network import (
    build_operator_brief_network_inputs_from_project_state,
    compose_operator_brief_network,
)
from bugslyce.reports.operator_brief_source_native import (
    compose_operator_brief_source_native,
)
from bugslyce.reports.operator_brief_web_context import (
    build_operator_brief_web_context_inputs_from_project_state,
    compose_operator_brief_web_context,
)
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


_MAXIMUM_RETAINED_BODY_BYTES = 1_000_000
_SUPPORTED_PROFILES = frozenset(
    {QUICK_RECON_PROFILE, STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE}
)


def _empty_http_fingerprints() -> DeepHttpFingerprintSummary:
    return DeepHttpFingerprintSummary(
        fingerprints=(),
        repeated_body_groups=(),
        summary_counts=DeepHttpFingerprintSummaryCounts(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ),
        safety_notes=(),
    )


def _empty_response_similarity() -> DeepResponseSimilarityReview:
    return DeepResponseSimilarityReview(
        groups=(),
        unique_success_responses=(),
        summary_counts=DeepResponseSimilaritySummaryCounts(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ),
        safety_notes=(),
    )


def _project_relative_source_file(project_root: Path, source_file: str) -> str:
    if not isinstance(source_file, str):
        raise TypeError("HTTP artefact source_file must be a string.")
    if not source_file:
        return ""
    if "\x00" in source_file:
        raise ValueError("HTTP artefact source_file is unsafe.")
    if "\\" in source_file:
        raise ValueError("HTTP artefact source_file is unsafe.")

    source_path = Path(source_file)
    candidate = source_path if source_path.is_absolute() else project_root / source_path
    try:
        resolved = candidate.resolve(strict=False)
        relative = resolved.relative_to(project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            "HTTP artefact source_file must remain inside the project root."
        ) from exc
    if not relative.parts:
        raise ValueError("HTTP artefact source_file must identify a project file.")
    return relative.as_posix()


def _adapt_http_artifacts(
    project_root: Path,
    artifacts: list[HTTPArtifact],
) -> tuple[HTTPArtifact, ...]:
    return tuple(
        replace(
            artifact,
            source_file=_project_relative_source_file(
                project_root,
                artifact.source_file,
            ),
        )
        for artifact in artifacts
    )


def build_project_operator_brief_composition(
    *,
    project_root: Path,
    project_state: ProjectState,
    profile: str,
    deep_source_collection: DeepSourceRouteCollectionResult | None,
    deep_orchestration: DeepReconOrchestrationResult | None,
) -> OperatorBriefComposition:
    """Build one final Operator Brief composition from authoritative project sources."""

    if not isinstance(project_root, Path):
        raise TypeError("project_root must be a Path.")
    if not isinstance(project_state, ProjectState):
        raise TypeError("project_state must be a ProjectState.")
    if not isinstance(profile, str) or profile not in _SUPPORTED_PROFILES:
        raise ValueError("Operator Brief project profile is unsupported.")

    root = project_root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("project_root must identify an existing directory.")

    if profile == DEEP_RECON_PROFILE:
        if not isinstance(deep_source_collection, DeepSourceRouteCollectionResult):
            raise ValueError("Deep source collection is required for the Deep profile.")
        if not isinstance(deep_orchestration, DeepReconOrchestrationResult):
            raise ValueError("Deep orchestration is required for the Deep profile.")
        source_route_review = deep_orchestration.source_route_collection_review
        successful_content_reviews = deep_orchestration.successful_content_reviews
        http_fingerprints = deep_orchestration.http_fingerprint_summary
        response_similarity = deep_orchestration.response_similarity_review
    else:
        if deep_source_collection is not None or deep_orchestration is not None:
            raise ValueError("Non-Deep profiles cannot consume Deep authority.")
        source_route_review = empty_deep_source_route_collection_review_summary()
        successful_content_reviews = ()
        http_fingerprints = _empty_http_fingerprints()
        response_similarity = _empty_response_similarity()

    http_inputs = OperatorBriefHttpCompositionInput(
        observations=(),
        exact_equivalences=(),
    )
    if project_state.recon_manifest is not None:
        retained = build_operator_brief_http_inputs_from_retained_manifest_html(
            project_state.recon_manifest,
            root,
            maximum_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES,
        )
        http_inputs = retained.inputs
    if profile == DEEP_RECON_PROFILE:
        http_inputs = combine_operator_brief_http_inputs(
            http_inputs,
            build_operator_brief_http_inputs_from_deep(http_fingerprints),
        )
    http = compose_operator_brief_http(http_inputs)

    network = compose_operator_brief_network(
        build_operator_brief_network_inputs_from_project_state(project_state)
    )

    standard = assemble_standard_interpretation_from_project_state(
        project_state,
        render_markdown=False,
    )
    relationship_clusters = build_http_route_relationship_clusters(
        project_state,
        source_collection=deep_source_collection,
        successful_reviews=successful_content_reviews,
    )
    web_context = compose_operator_brief_web_context(
        build_operator_brief_web_context_inputs_from_project_state(
            project_state,
            robots_analyses=standard.collection.robots_analyses,
            relationship_clusters=relationship_clusters,
        )
    )

    normalized_policy_subjects = assemble_operator_brief_policy_subjects(
        http=http,
        network=network,
        web_context=web_context,
    )
    source_native = compose_operator_brief_source_native(
        deep_source_route_review=source_route_review,
        successful_content_reviews=successful_content_reviews,
        deep_http_fingerprints=http_fingerprints,
        deep_response_similarity=response_similarity,
        http_artifacts=_adapt_http_artifacts(root, project_state.http_artifacts),
        workflow_leads=build_grouped_workflow_leads(
            project_state,
            deep_orchestration,
        ),
        normalized_policy_subjects=normalized_policy_subjects,
    )

    return assemble_operator_brief(
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
    )
