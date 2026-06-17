"""Parse and validate BugSlyce recon manifests."""

from __future__ import annotations

import json
from pathlib import Path
import warnings

from bugslyce.core.models import ReconManifest, ReconManifestArtifact


SUPPORTED_ARTIFACT_TYPES = {"nmap", "gobuster", "http_headers", "robots", "html"}


def parse_recon_manifest(path: Path, input_dir: Path | None = None) -> ReconManifest | None:
    """Parse a manifest, skipping invalid artifact entries with warnings."""

    if not path.exists():
        return None

    root = (input_dir or path.parent).resolve()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        warnings.warn(f"Could not parse recon manifest {path}: {exc}", RuntimeWarning, stacklevel=2)
        return None

    if not isinstance(payload, dict):
        warnings.warn(f"Recon manifest must contain a JSON object: {path}", RuntimeWarning, stacklevel=2)
        return None

    schema_version = _required_text(payload, "schema_version", path)
    target = _required_text(payload, "target", path)
    raw_artifacts = payload.get("artifacts")
    if schema_version is None or target is None or not isinstance(raw_artifacts, list):
        if not isinstance(raw_artifacts, list):
            warnings.warn(
                f"Recon manifest field 'artifacts' must be a list: {path}",
                RuntimeWarning,
                stacklevel=2,
            )
        return None

    scope_file = _optional_text(payload, "scope_file")
    if scope_file and not _is_safe_relative_path(root, scope_file):
        warnings.warn(
            f"Skipping unsafe manifest scope_file outside input directory: {scope_file}",
            RuntimeWarning,
            stacklevel=2,
        )
        scope_file = None

    artifacts: list[ReconManifestArtifact] = []
    for index, raw_artifact in enumerate(raw_artifacts, start=1):
        artifact = _parse_artifact(raw_artifact, index, root, path)
        if artifact is not None:
            artifacts.append(artifact)

    return ReconManifest(
        schema_version=schema_version,
        target=target,
        artifacts=artifacts,
        scope_file=scope_file,
        created_by=_optional_text(payload, "created_by"),
        profile=_optional_text(payload, "profile"),
        notes=_optional_text(payload, "notes"),
        source_file=str(path),
    )


def _parse_artifact(
    value: object,
    index: int,
    root: Path,
    manifest_path: Path,
) -> ReconManifestArtifact | None:
    if not isinstance(value, dict):
        warnings.warn(
            f"Skipping non-object manifest artefact #{index}: {manifest_path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None

    artifact_type_value = _optional_text(value, "type")
    artifact_type = artifact_type_value.lower() if artifact_type_value else None
    artifact_file = _optional_text(value, "file")
    if not artifact_type or not artifact_file:
        warnings.warn(
            f"Skipping manifest artefact #{index} without required type/file: {manifest_path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None
    if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
        warnings.warn(
            f"Skipping unsupported manifest artefact type '{artifact_type}': {artifact_file}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None
    if not _is_safe_relative_path(root, artifact_file):
        warnings.warn(
            f"Skipping unsafe manifest artefact path outside input directory: {artifact_file}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None

    artifact_path = (root / artifact_file).resolve()
    if not artifact_path.is_file():
        warnings.warn(
            f"Skipping missing manifest artefact file: {artifact_file}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None

    port = value.get("port")
    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
        warnings.warn(
            f"Ignoring invalid port for manifest artefact: {artifact_file}",
            RuntimeWarning,
            stacklevel=2,
        )
        port = None

    raw_tags = value.get("tags", [])
    tags = [item for item in raw_tags if isinstance(item, str) and item.strip()] if isinstance(raw_tags, list) else []

    return ReconManifestArtifact(
        type=artifact_type,
        file=artifact_file,
        url=_optional_text(value, "url"),
        base_url=_optional_text(value, "base_url"),
        host=_optional_text(value, "host"),
        port=port,
        protocol=_optional_text(value, "protocol"),
        description=_optional_text(value, "description"),
        tags=tags,
    )


def _required_text(payload: dict[str, object], key: str, path: Path) -> str | None:
    value = _optional_text(payload, key)
    if value is None:
        warnings.warn(
            f"Recon manifest field '{key}' is required: {path}",
            RuntimeWarning,
            stacklevel=2,
        )
    return value


def _optional_text(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _is_safe_relative_path(root: Path, value: str) -> bool:
    candidate = Path(value)
    if candidate.is_absolute():
        return False
    try:
        (root / candidate).resolve().relative_to(root)
    except ValueError:
        return False
    return True
