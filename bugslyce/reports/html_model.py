"""Structured adapter for the offline HTML evidence report."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

from bugslyce.core.models import (
    Asset,
    Candidate,
    DiscoveredPath,
    Endpoint,
    Evidence,
    HTTPArtifact,
    HTTPService,
    PortService,
    ProjectState,
    SMBShare,
    ReconManifest,
    ReconManifestArtifact,
    ReconPackSummary,
)
from bugslyce.recon.collection_confidence import (
    CollectionConfidenceNotice,
    build_collection_confidence_notices_from_project,
)
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteExtractionResult,
    build_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
    load_deep_metadata_collection_result,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_redirect_auth_flow_review import (
    DeepRedirectAuthFlowReview,
    build_deep_redirect_auth_flow_review,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    build_deep_response_similarity_review,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    load_deep_source_route_collection_result,
)
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    build_successful_deep_content_reviews,
)
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    build_http_route_relationship_clusters,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.reasoning_relationships import build_route_reasoning_review
from bugslyce.recon.review_occurrence_grouping import ReviewOccurrenceGroup
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.analysis_coverage import (
    coverage_evidence_from_initial_retained_javascript_routes,
    load_analysis_coverage_artifact,
)
from bugslyce.reports.human_triage import (
    HumanTriageBrief,
    build_human_triage_brief,
)
from bugslyce.reports.investigation_context import InvestigationContextSources
from bugslyce.reports.operator_brief import (
    OperatorBriefView,
    build_operator_brief_view,
    load_operator_brief_artifact,
)
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_composition_persistence import (
    load_operator_brief_composition_artifact,
)
from bugslyce.reports.operator_report_view import (
    OperatorReportView,
    build_operator_report_view,
)
from bugslyce.reports.operator_summary import (
    OperatorSummary,
    build_deep_operator_summary_leads,
    build_operator_summary,
)
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


_T = TypeVar("_T")


@dataclass(frozen=True)
class PersistedDeepDisclosure:
    """One existing Deep interpretation retained by orchestration metadata."""

    category: str
    title: str
    urls: tuple[str, ...]
    final_urls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    observed_values: tuple[str, ...]
    evidence_excerpt: tuple[str, ...]
    source_body_sha256: str


@dataclass(frozen=True)
class HtmlRouteObservation:
    """One unchanged endpoint or discovered-path observation."""

    record_kind: str
    path: str
    status_code: int | None
    redirect_location: str | None
    query_params: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class HtmlRouteGroup:
    """Presentation-only grouping for one exact URL string."""

    url: str
    origin_group: str
    observations: tuple[HtmlRouteObservation, ...]

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    evidence_id
                    for observation in self.observations
                    for evidence_id in observation.evidence_ids
                }
            )
        )


@dataclass(frozen=True)
class HtmlReportModel:
    """Immutable report input assembled from local structured artefacts."""

    project_state: ProjectState
    candidates: tuple[Candidate, ...]
    operator_summary: OperatorSummary
    operator_brief: OperatorBriefView
    human_triage_brief: HumanTriageBrief
    confidence_notices: tuple[CollectionConfidenceNotice, ...]
    http_fingerprints: DeepHttpFingerprintSummary
    redirect_review: DeepRedirectAuthFlowReview
    similarity_review: DeepResponseSimilarityReview
    metadata_collection: DeepMetadataCollectionResult
    source_collection: DeepSourceRouteCollectionResult
    successful_content: tuple[SuccessfulDeepContentReview, ...]
    relationship_clusters: tuple[HttpRouteRelationshipCluster, ...]
    deep_disclosures: tuple[PersistedDeepDisclosure, ...]
    deep_summary_complete: bool
    operator_summary_fallback: str | None
    missing_deep_summary_inputs: tuple[str, ...]
    assessed_origins: tuple[HttpOrigin, ...]
    route_groups: tuple[HtmlRouteGroup, ...]
    review_leads: tuple[ReviewLead, ...]
    review_occurrence_groups: tuple[ReviewOccurrenceGroup, ...]
    available_artefacts: tuple[str, ...]
    operator_report_view: OperatorReportView
    initial_retained_javascript_routes: (
        DeepInitialRetainedJavaScriptRouteExtractionResult | None
    ) = None
    operator_brief_composition: OperatorBriefComposition | None = None


def build_html_report_model(input_dir: Path) -> HtmlReportModel:
    """Load current local artefacts and reconstruct existing deterministic models."""

    root = input_dir.expanduser()
    if not root.exists():
        raise ValueError(f"input directory does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"input path is not a directory: {root}")
    root = root.resolve()

    operator_brief_composition = load_operator_brief_composition_artifact(root)
    payload = _read_json_object(root, "project_state.json", required=True)
    project_state, candidates = _project_state_from_payload(payload, root)
    _validate_optional_structured_objects(root)
    persisted_operator_brief = load_operator_brief_artifact(root)

    source_collection = _load_source_collection(root)
    metadata_collection = _load_metadata_collection(root)
    fingerprints = build_deep_http_fingerprint_summary(
        metadata_collection,
        source_collection,
    )
    redirects = build_deep_redirect_auth_flow_review(fingerprints)
    similarities = build_deep_response_similarity_review(fingerprints, redirects)
    successful_content = build_successful_deep_content_reviews(source_collection)
    deep_disclosures, deep_mode_enabled = _load_deep_disclosures(root)
    deep_summary_complete, summary_fallback, missing_deep_inputs = (
        _deep_summary_input_status(root, project_state, deep_mode_enabled)
    )
    deep_summary_leads = build_deep_operator_summary_leads(
        deep_disclosures,
        successful_content,
        http_fingerprint_summary=fingerprints,
        response_similarity_review=similarities,
    )
    relationships = build_http_route_relationship_clusters(
        project_state,
        source_collection=source_collection,
        successful_reviews=successful_content,
    )
    route_reasoning = build_route_reasoning_review(
        project_state,
        successful_reviews=successful_content,
        relationship_clusters=relationships,
        response_similarity_review=similarities,
    )
    notices = build_collection_confidence_notices_from_project(
        project_state,
        root,
        source_collection=source_collection,
    )
    operator_summary = build_operator_summary(
        project_state,
        candidates,
        additional_leads=deep_summary_leads,
        response_similarity_review=similarities,
        route_reasoning_review=route_reasoning,
    )
    operator_brief = (
        persisted_operator_brief
        if persisted_operator_brief is not None
        else build_operator_brief_view(operator_summary)
    )
    human_triage_brief = build_human_triage_brief(
        project_state,
        candidates,
        engagement_context=getattr(project_state, "engagement_context", "unknown"),
        ranked_leads=operator_summary.ranked_leads,
    )
    workflow_leads = build_grouped_workflow_leads(project_state)
    initial_retained_routes = (
        build_deep_initial_retained_javascript_route_extraction(
            project_state,
            source_collection,
        )
        if _deep_report_inputs_available(root, project_state, deep_mode_enabled)
        else None
    )
    persisted_coverage_evidence = load_analysis_coverage_artifact(root)
    coverage_evidence = (
        persisted_coverage_evidence
        if persisted_coverage_evidence is not None
        else (
            coverage_evidence_from_initial_retained_javascript_routes(
                initial_retained_routes
            )
            if initial_retained_routes is not None
            else ()
        )
    )
    operator_report_view = build_operator_report_view(
        operator_summary,
        investigation_sources=InvestigationContextSources(
            evidence=tuple(project_state.evidence),
            route_reasoning=route_reasoning,
            successful_content=successful_content,
            route_relationships=relationships,
            workflow_leads=tuple(workflow_leads),
        ),
        coverage_evidence=coverage_evidence,
    )
    interpretation = assemble_standard_interpretation_from_project_state(
        project_state,
        render_markdown=False,
    )
    return HtmlReportModel(
        project_state=project_state,
        candidates=tuple(candidates),
        operator_summary=operator_summary,
        operator_brief=operator_brief,
        human_triage_brief=human_triage_brief,
        confidence_notices=notices,
        http_fingerprints=fingerprints,
        redirect_review=redirects,
        similarity_review=similarities,
        metadata_collection=metadata_collection,
        source_collection=source_collection,
        successful_content=successful_content,
        relationship_clusters=relationships,
        deep_disclosures=deep_disclosures,
        deep_summary_complete=deep_summary_complete,
        operator_summary_fallback=summary_fallback,
        missing_deep_summary_inputs=missing_deep_inputs,
        assessed_origins=_assessed_origins(project_state),
        route_groups=_route_groups(project_state),
        review_leads=interpretation.review_leads,
        review_occurrence_groups=interpretation.collection.review_occurrence_groups,
        available_artefacts=tuple(
            path.name
            for path in sorted(root.iterdir(), key=lambda value: value.name)
            if path.is_file() and not path.is_symlink()
        ),
        operator_report_view=operator_report_view,
        initial_retained_javascript_routes=initial_retained_routes,
        operator_brief_composition=operator_brief_composition,
    )


def _deep_report_inputs_available(
    root: Path,
    project_state: ProjectState,
    deep_mode_enabled: bool,
) -> bool:
    """Return the existing persisted-state policy for Deep report applicability."""

    profile = (
        project_state.recon_manifest.profile
        if project_state.recon_manifest is not None
        else None
    )
    return (
        profile == "deep-bounded"
        or _deep_pipeline_profile(root) == "deep-bounded"
        or deep_mode_enabled
        or (root / DEEP_SOURCE_ROUTE_COLLECTION_JSON).is_file()
    )


def _load_deep_disclosures(
    root: Path,
) -> tuple[tuple[PersistedDeepDisclosure, ...], bool]:
    path = root / "deep_recon_orchestration.json"
    if not path.exists():
        return (), False
    payload = _read_json_object(root, path.name, required=True)
    if payload.get("schema_version") != "1.0":
        raise ValueError("deep_recon_orchestration.json has an unsupported schema_version")
    raw_disclosures = payload.get("structured_body_disclosures")
    if not isinstance(raw_disclosures, list):
        raise ValueError(
            "deep_recon_orchestration.json field 'structured_body_disclosures' must be a list"
        )
    deep_mode_enabled = payload.get("deep_mode_enabled") is True
    disclosures = tuple(
        _persisted_deep_disclosure(item, index)
        for index, item in enumerate(raw_disclosures)
    )
    return disclosures, deep_mode_enabled


def _deep_summary_input_status(
    root: Path,
    project_state: ProjectState,
    deep_mode_enabled: bool,
) -> tuple[bool, str | None, tuple[str, ...]]:
    """Describe whether persisted Deep inputs can reproduce the production summary."""

    orchestration = root / "deep_recon_orchestration.json"
    source_collection = root / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    if not _deep_report_inputs_available(root, project_state, deep_mode_enabled):
        return False, None, ()
    missing = tuple(
        name
        for name, path in (
            ("deep_recon_orchestration.json", orchestration),
            (DEEP_SOURCE_ROUTE_COLLECTION_JSON, source_collection),
        )
        if not path.is_file() or path.is_symlink()
    )
    if not missing:
        return True, None, ()
    return (
        False,
        "Operator summary reconstructed from available structured inputs. "
        "Some Deep summary inputs were unavailable, so this view may be incomplete.",
        missing,
    )


def _deep_pipeline_profile(root: Path) -> str | None:
    """Read the existing local run profile when status metadata is available."""

    path = root / "recon_status.json"
    if not path.exists():
        return None
    payload = _read_json_object(root, path.name, required=False)
    latest = payload.get("latest_execution")
    if not isinstance(latest, dict):
        return None
    profile = latest.get("pipeline_profile")
    return profile if isinstance(profile, str) else None


def _persisted_deep_disclosure(value: object, index: int) -> PersistedDeepDisclosure:
    label = f"deep_recon_orchestration.structured_body_disclosures[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return PersistedDeepDisclosure(
        category=_required_string(value, "category", label),
        title=_required_string(value, "title", label),
        urls=tuple(_string_list(value, "source_urls", label)),
        final_urls=tuple(_string_list(value, "final_response_urls", label)),
        evidence_ids=tuple(_string_list(value, "evidence_ids", label)),
        observed_values=tuple(_string_list(value, "observed_values", label)),
        evidence_excerpt=tuple(_string_list(value, "evidence_excerpt", label)),
        source_body_sha256=_required_string(value, "source_body_sha256", label),
    )


def _assessed_origins(project_state: ProjectState) -> tuple[HttpOrigin, ...]:
    return tuple(
        sorted(
            {
                origin
                for service in project_state.http_services
                if (origin := http_origin_from_url(service.url)) is not None
            }
        )
    )


def _route_groups(project_state: ProjectState) -> tuple[HtmlRouteGroup, ...]:
    observations: dict[str, list[HtmlRouteObservation]] = {}
    for endpoint in project_state.endpoints:
        observations.setdefault(endpoint.url, []).append(
            HtmlRouteObservation(
                record_kind="endpoint",
                path=endpoint.path,
                status_code=None,
                redirect_location=None,
                query_params=tuple(endpoint.query_params),
                evidence_ids=tuple(endpoint.evidence_ids),
                source="project_state.json",
            )
        )
    for route in project_state.discovered_paths:
        observations.setdefault(route.url, []).append(
            HtmlRouteObservation(
                record_kind="discovered_path",
                path=_url_path(route.url),
                status_code=route.status_code,
                redirect_location=route.redirect_location,
                query_params=(),
                evidence_ids=tuple(route.evidence_ids),
                source=route.source,
            )
        )
    assessed = set(_assessed_origins(project_state))
    groups = []
    for url in sorted(observations):
        origin = http_origin_from_url(url)
        origin_group = (
            "assessed"
            if origin in assessed
            else "external"
            if assessed and origin is not None
            else "relative"
        )
        groups.append(
            HtmlRouteGroup(
                url=url,
                origin_group=origin_group,
                observations=tuple(
                    sorted(
                        observations[url],
                        key=lambda item: (
                            item.record_kind,
                            item.status_code if item.status_code is not None else -1,
                            item.redirect_location or "",
                            item.source,
                            item.evidence_ids,
                        ),
                    )
                ),
            )
        )
    return tuple(groups)


def _url_path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return ""


def _project_state_from_payload(
    payload: dict[str, Any],
    root: Path,
) -> tuple[ProjectState, list[Candidate]]:
    raw_state = payload.get("project_state")
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_state, dict):
        raise ValueError("project_state.json field 'project_state' must be an object")
    if not isinstance(raw_candidates, list):
        raise ValueError("project_state.json field 'candidates' must be a list")
    try:
        manifest_raw = raw_state.get("recon_manifest")
        manifest = None
        if manifest_raw is not None:
            if not isinstance(manifest_raw, dict):
                raise ValueError("project_state.recon_manifest must be an object or null")
            artifacts = _dataclass_list(
                ReconManifestArtifact,
                manifest_raw.get("artifacts"),
                "project_state.recon_manifest.artifacts",
            )
            manifest = ReconManifest(
                **{**manifest_raw, "artifacts": artifacts, "source_file": "recon_manifest.json"}
            )
        summary_raw = raw_state.get("recon_summary")
        summary = None
        if summary_raw is not None:
            if not isinstance(summary_raw, dict):
                raise ValueError("project_state.recon_summary must be an object or null")
            summary = ReconPackSummary(**summary_raw)
        state = ProjectState(
            project_name=_required_string(raw_state, "project_name", "project_state"),
            input_dir=str(root),
            processed_files=_string_list(raw_state, "processed_files", "project_state"),
            scope_summary=_required_string(raw_state, "scope_summary", "project_state"),
            assets=_dataclass_list(Asset, raw_state.get("assets"), "project_state.assets"),
            http_services=_dataclass_list(
                HTTPService, raw_state.get("http_services"), "project_state.http_services"
            ),
            endpoints=_dataclass_list(
                Endpoint, raw_state.get("endpoints"), "project_state.endpoints"
            ),
            port_services=_dataclass_list(
                PortService, raw_state.get("port_services"), "project_state.port_services"
            ),
            smb_shares=_dataclass_list(
                SMBShare,
                raw_state.get("smb_shares", []),
                "project_state.smb_shares",
            ),
            http_artifacts=_dataclass_list(
                HTTPArtifact, raw_state.get("http_artifacts"), "project_state.http_artifacts"
            ),
            discovered_paths=_dataclass_list(
                DiscoveredPath,
                raw_state.get("discovered_paths"),
                "project_state.discovered_paths",
            ),
            recon_summary=summary,
            recon_manifest=manifest,
            evidence=_dataclass_list(
                Evidence, raw_state.get("evidence"), "project_state.evidence"
            ),
            warnings=_string_list(raw_state, "warnings", "project_state"),
            generated_at=_required_string(raw_state, "generated_at", "project_state"),
            engagement_context=_optional_string(raw_state, "engagement_context") or "unknown",
        )
        candidates = _dataclass_list(Candidate, raw_candidates, "candidates")
    except (KeyError, TypeError) as exc:
        raise ValueError(f"project_state.json has an invalid current structure: {exc}") from exc
    return state, candidates


def _dataclass_list(cls: type[_T], value: object, label: str) -> list[_T]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    result: list[_T] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{index}] must be an object")
        try:
            result.append(cls(**item))
        except TypeError as exc:
            raise ValueError(f"{label}[{index}] is invalid: {exc}") from exc
    return result


def _required_string(payload: dict[str, Any], key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{label}.{key} must be a string")
    return value


def _optional_string(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _string_list(payload: dict[str, Any], key: str, label: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label}.{key} must be a list of strings")
    return value


def _read_json_object(root: Path, name: str, *, required: bool) -> dict[str, Any]:
    path = root / name
    if not path.exists():
        if required:
            raise ValueError(f"required artefact is missing: {name}")
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"structured artefact must be a regular file: {name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not parse {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload


def _validate_optional_structured_objects(root: Path) -> None:
    for name in ("recon_manifest.json", "project_pipeline.json"):
        if (root / name).exists():
            _read_json_object(root, name, required=False)
    for path in sorted(root.glob("recon_execution*.json")):
        _read_json_object(root, path.name, required=False)


def _load_source_collection(root: Path) -> DeepSourceRouteCollectionResult:
    path = root / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    if not path.exists():
        return DeepSourceRouteCollectionResult((), (), 0, 0, 0)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"structured artefact must be a regular file: {path.name}")
    try:
        return load_deep_source_route_collection_result(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"could not load {path.name}: {exc}") from exc


def _load_metadata_collection(root: Path) -> DeepMetadataCollectionResult:
    path = root / DEEP_METADATA_COLLECTION_JSON
    if not path.exists():
        return DeepMetadataCollectionResult((), (), 0, 0, 0)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"structured artefact must be a regular file: {path.name}")
    try:
        return load_deep_metadata_collection_result(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"could not load {path.name}: {exc}") from exc
