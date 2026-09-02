"""Offline programme graph adaptation above one strict project runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

from bugslyce.core.models import ProjectState
from bugslyce.core.programme_graph import (
    RELATIONSHIP_CONFIGURED_SEED,
    RELATIONSHIP_OBSERVED_REDIRECT,
    RELATIONSHIP_OBSERVED_REFERENCE,
    ProgrammeGraph,
    ProgrammeHTTPWorkItem,
    ProgrammeRelationshipEvidence,
    build_programme_graph,
    build_programme_http_work_items,
    build_programme_relationship_evidence,
)
from bugslyce.core.programme_scope import ScopeDecision
from bugslyce.recon.http_enforcement import (
    InternalHTTPExecutor,
    build_internal_http_executor_view,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.project_runtime import BugBountyProjectRuntime


CONFIGURED_SEED_PROVENANCE = (
    "bug_bounty_project_runtime.approved_http_origins",
)
REFERENCE_ARTEFACT_TYPES = frozenset({"link", "form", "script_or_asset"})


@dataclass(frozen=True)
class ProgrammeRuntimeBinding:
    """Stable strict-runtime facts to which one programme plan belongs."""

    project_name: str
    project_target: str
    project_output_directory: str
    project_scope_file: str
    profile: str
    target_decision: ScopeDecision
    initial_http_origins: tuple[str, ...]
    approved_http_origins: tuple[str, ...]


@dataclass(frozen=True)
class ProgrammeOrchestrationPlan:
    """Immutable offline programme topology and exact future HTTP work."""

    runtime_binding: ProgrammeRuntimeBinding = field(repr=False)
    programme_graph: ProgrammeGraph
    http_work_items: tuple[ProgrammeHTTPWorkItem, ...]


def build_programme_orchestration_plan(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
) -> ProgrammeOrchestrationPlan:
    """Adapt retained project evidence under the runtime's programme authority."""

    binding = _runtime_binding(runtime)
    graph = _build_expected_programme_graph(
        runtime,
        project_state,
        binding=binding,
    )
    plan = ProgrammeOrchestrationPlan(
        runtime_binding=binding,
        programme_graph=graph,
        http_work_items=build_programme_http_work_items(graph),
    )
    return require_programme_orchestration_plan_binding(
        runtime,
        plan,
        project_state=project_state,
    )


def require_programme_orchestration_plan_binding(
    runtime: BugBountyProjectRuntime,
    plan: ProgrammeOrchestrationPlan,
    *,
    project_state: ProjectState | None = None,
) -> ProgrammeOrchestrationPlan:
    """Fail closed unless a plan is canonical for this exact strict runtime."""

    if not isinstance(runtime, BugBountyProjectRuntime):
        raise ValueError("Programme plan requires a canonical project runtime.")
    if not isinstance(plan, ProgrammeOrchestrationPlan):
        raise ValueError("Programme orchestration plan is not canonical.")
    if not isinstance(plan.programme_graph, ProgrammeGraph):
        raise ValueError("Programme orchestration graph is not canonical.")

    expected_binding = _runtime_binding(runtime)
    if plan.runtime_binding != expected_binding:
        raise ValueError("Programme orchestration runtime binding is not canonical.")
    if plan.programme_graph.programme_scope_policy != runtime.programme_scope_policy:
        raise ValueError("Programme orchestration policy does not match the runtime.")

    try:
        canonical_work_items = build_programme_http_work_items(
            plan.programme_graph
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Programme orchestration graph is not canonical.") from None
    if plan.http_work_items != canonical_work_items:
        raise ValueError("Programme orchestration work-item plan is not canonical.")

    actual_seed_origins = _canonical_graph_seed_origins(plan.programme_graph)
    if actual_seed_origins != expected_binding.approved_http_origins:
        raise ValueError("Programme orchestration configured origins are not canonical.")

    has_non_seed_relationships = any(
        relationship.relationship_type != RELATIONSHIP_CONFIGURED_SEED
        for relationship in plan.programme_graph.relationships
    )
    if project_state is None:
        if has_non_seed_relationships:
            raise ValueError(
                "Programme orchestration relationship evidence requires project state."
            )
        return plan

    expected_graph = _build_expected_programme_graph(
        runtime,
        project_state,
        binding=expected_binding,
    )
    if plan.programme_graph != expected_graph:
        raise ValueError(
            "Programme orchestration relationship evidence is not backed by project state."
        )
    expected_work_items = build_programme_http_work_items(expected_graph)
    if plan.http_work_items != expected_work_items:
        raise ValueError("Programme orchestration work-item plan is not canonical.")
    return plan


def build_programme_orchestration_http_executor(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    plan: ProgrammeOrchestrationPlan,
) -> InternalHTTPExecutor:
    """Build an exact-origin executor view from canonical authorised work."""

    bound_plan = require_programme_orchestration_plan_binding(
        runtime,
        plan,
        project_state=project_state,
    )
    origins = tuple(item.canonical_origin for item in bound_plan.http_work_items)
    if not origins:
        raise ValueError("Programme execution requires authorised HTTP work items.")
    source_executor = runtime.http_executor
    if not isinstance(source_executor, InternalHTTPExecutor):
        raise ValueError("Programme execution requires a bound HTTP runtime.")
    return build_internal_http_executor_view(
        source_executor,
        approved_origins=origins,
    )


def _build_expected_programme_graph(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    *,
    binding: ProgrammeRuntimeBinding,
) -> ProgrammeGraph:
    """Build the complete graph attributable to one runtime and retained state."""

    _require_project_state_binding(runtime, project_state)
    relationship_evidence = (
        *_configured_seed_evidence(binding.approved_http_origins),
        *_redirect_evidence(project_state),
        *_reference_evidence(project_state),
    )
    return build_programme_graph(
        runtime.programme_scope_policy,
        relationship_evidence=relationship_evidence,
    )


def _runtime_binding(runtime: object) -> ProgrammeRuntimeBinding:
    if not isinstance(runtime, BugBountyProjectRuntime):
        raise ValueError("Programme plan requires a canonical project runtime.")
    try:
        project = runtime.project
        name = _binding_text(project.name)
        target = _binding_text(project.target)
        output_directory = _binding_path(project.output_dir)
        scope_file = _binding_path(project.scope_file)
        profile = _binding_text(runtime.profile)
        target_decision = runtime.target_decision
        if not isinstance(target_decision, ScopeDecision):
            raise ValueError
        initial_origins = _canonical_origin_tuple(runtime.initial_http_origins)
        approved_origins = _canonical_origin_tuple(runtime.approved_http_origins)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("Programme plan requires a canonical project runtime.") from None
    return ProgrammeRuntimeBinding(
        project_name=name,
        project_target=target,
        project_output_directory=output_directory,
        project_scope_file=scope_file,
        profile=profile,
        target_decision=target_decision,
        initial_http_origins=initial_origins,
        approved_http_origins=approved_origins,
    )


def _require_project_state_binding(
    runtime: BugBountyProjectRuntime,
    project_state: object,
) -> None:
    if not isinstance(project_state, ProjectState):
        raise ValueError("Programme planning requires canonical project state.")
    try:
        state_input = _binding_path(project_state.input_dir)
        runtime_output = _binding_path(runtime.project.output_dir)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("Programme planning project state is not canonical.") from None
    if (
        project_state.project_name != runtime.project.name
        or state_input != runtime_output
    ):
        raise ValueError("Programme planning project state does not match the runtime.")


def _configured_seed_evidence(
    approved_origins: tuple[str, ...],
) -> tuple[ProgrammeRelationshipEvidence, ...]:
    return tuple(
        build_programme_relationship_evidence(
            relationship_type=RELATIONSHIP_CONFIGURED_SEED,
            source_origin=None,
            destination_origin=origin,
            evidence_ids=(),
            provenance_sources=CONFIGURED_SEED_PROVENANCE,
        )
        for origin in approved_origins
    )


def _redirect_evidence(
    project_state: ProjectState,
) -> tuple[ProgrammeRelationshipEvidence, ...]:
    relationships: list[ProgrammeRelationshipEvidence] = []
    for path in project_state.discovered_paths:
        location = path.redirect_location
        if not isinstance(location, str) or not location.strip():
            continue
        relationship = _resolved_relationship(
            relationship_type=RELATIONSHIP_OBSERVED_REDIRECT,
            source_url=path.url,
            raw_reference=location,
            evidence_ids=path.evidence_ids,
            provenance_source=path.source,
        )
        if relationship is not None:
            relationships.append(relationship)
    return tuple(relationships)


def _reference_evidence(
    project_state: ProjectState,
) -> tuple[ProgrammeRelationshipEvidence, ...]:
    relationships: list[ProgrammeRelationshipEvidence] = []
    for artefact in project_state.http_artifacts:
        if artefact.artifact_type not in REFERENCE_ARTEFACT_TYPES:
            continue
        relationship = _resolved_relationship(
            relationship_type=RELATIONSHIP_OBSERVED_REFERENCE,
            source_url=artefact.url,
            raw_reference=artefact.value,
            evidence_ids=artefact.evidence_ids,
            provenance_source=artefact.source_file,
        )
        if relationship is not None:
            relationships.append(relationship)
    return tuple(relationships)


def _resolved_relationship(
    *,
    relationship_type: str,
    source_url: object,
    raw_reference: object,
    evidence_ids: object,
    provenance_source: object,
) -> ProgrammeRelationshipEvidence | None:
    if (
        not isinstance(source_url, str)
        or not isinstance(raw_reference, str)
        or not raw_reference.strip()
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in raw_reference
        )
        or not isinstance(evidence_ids, (list, tuple))
        or not isinstance(provenance_source, str)
        or not provenance_source.strip()
    ):
        return None
    source_origin = http_origin_from_url(source_url)
    if source_origin is None:
        return None
    try:
        resolved_url = urljoin(source_url, raw_reference.strip())
    except (TypeError, ValueError):
        return None
    destination_origin = http_origin_from_url(resolved_url)
    if destination_origin is None or destination_origin == source_origin:
        return None
    try:
        return build_programme_relationship_evidence(
            relationship_type=relationship_type,
            source_origin=source_origin.origin_url,
            destination_origin=destination_origin.origin_url,
            evidence_ids=tuple(evidence_ids),
            provenance_sources=(provenance_source,),
        )
    except (TypeError, ValueError):
        return None


def _canonical_graph_seed_origins(graph: ProgrammeGraph) -> tuple[str, ...]:
    seeds: list[str] = []
    for relationship in graph.relationships:
        if relationship.relationship_type != RELATIONSHIP_CONFIGURED_SEED:
            continue
        if (
            relationship.source_origin is not None
            or relationship.evidence_ids
            or relationship.provenance_sources != CONFIGURED_SEED_PROVENANCE
        ):
            raise ValueError("Programme orchestration configured origins are invalid.")
        seeds.append(relationship.destination_origin)
    if len(seeds) != len(set(seeds)):
        raise ValueError("Programme orchestration configured origins are invalid.")
    return tuple(sorted(seeds, key=_origin_sort_key))


def _canonical_origin_tuple(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError
    canonical: list[str] = []
    for value in values:
        evidence = build_programme_relationship_evidence(
            relationship_type=RELATIONSHIP_CONFIGURED_SEED,
            source_origin=None,
            destination_origin=value,
            evidence_ids=(),
            provenance_sources=CONFIGURED_SEED_PROVENANCE,
        )
        canonical.append(evidence.destination_origin)
    if len(canonical) != len(set(canonical)):
        raise ValueError
    return tuple(sorted(canonical, key=_origin_sort_key))


def _origin_sort_key(value: str) -> tuple[str, str, int]:
    origin = http_origin_from_url(value)
    if origin is None:
        raise ValueError
    return origin.scheme, origin.hostname, origin.effective_port


def _binding_text(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError
    return value


def _binding_path(value: object) -> str:
    text = _binding_text(value)
    return str(Path(text).resolve(strict=False))
