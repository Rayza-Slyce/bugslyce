"""Structured adapter for the offline HTML evidence report."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, TypeVar

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
from bugslyce.reports.operator_summary import OperatorSummary, build_operator_summary


_T = TypeVar("_T")


@dataclass(frozen=True)
class HtmlReportModel:
    """Immutable report input assembled from local structured artefacts."""

    project_state: ProjectState
    candidates: tuple[Candidate, ...]
    operator_summary: OperatorSummary
    confidence_notices: tuple[CollectionConfidenceNotice, ...]
    http_fingerprints: DeepHttpFingerprintSummary
    redirect_review: DeepRedirectAuthFlowReview
    similarity_review: DeepResponseSimilarityReview
    metadata_collection: DeepMetadataCollectionResult
    source_collection: DeepSourceRouteCollectionResult
    successful_content: tuple[SuccessfulDeepContentReview, ...]
    relationship_clusters: tuple[HttpRouteRelationshipCluster, ...]
    available_artefacts: tuple[str, ...]


def build_html_report_model(input_dir: Path) -> HtmlReportModel:
    """Load current local artefacts and reconstruct existing deterministic models."""

    root = input_dir.expanduser()
    if not root.exists():
        raise ValueError(f"input directory does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"input path is not a directory: {root}")
    root = root.resolve()

    payload = _read_json_object(root, "project_state.json", required=True)
    project_state, candidates = _project_state_from_payload(payload, root)
    _validate_optional_structured_objects(root)

    source_collection = _load_source_collection(root)
    metadata_collection = _load_metadata_collection(root)
    fingerprints = build_deep_http_fingerprint_summary(
        metadata_collection,
        source_collection,
    )
    redirects = build_deep_redirect_auth_flow_review(fingerprints)
    similarities = build_deep_response_similarity_review(fingerprints, redirects)
    successful_content = build_successful_deep_content_reviews(source_collection)
    relationships = build_http_route_relationship_clusters(
        project_state,
        source_collection=source_collection,
        successful_reviews=successful_content,
    )
    notices = build_collection_confidence_notices_from_project(
        project_state,
        root,
        source_collection=source_collection,
    )
    return HtmlReportModel(
        project_state=project_state,
        candidates=tuple(candidates),
        operator_summary=build_operator_summary(project_state, candidates),
        confidence_notices=notices,
        http_fingerprints=fingerprints,
        redirect_review=redirects,
        similarity_review=similarities,
        metadata_collection=metadata_collection,
        source_collection=source_collection,
        successful_content=successful_content,
        relationship_clusters=relationships,
        available_artefacts=tuple(
            path.name
            for path in sorted(root.iterdir(), key=lambda value: value.name)
            if path.is_file() and not path.is_symlink()
        ),
    )


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
