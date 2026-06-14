"""Deterministic workflow provenance and path-count summaries."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from bugslyce.core.models import ProjectState


@dataclass(frozen=True)
class WorkflowProvenance:
    """Human-facing workflow summary derived from retained local evidence."""

    raw_manifest_profile: str | None
    base_discovery_profile: str
    enrichment_phases: list[str]
    content_discovery_profiles: list[str]
    followup_phases: list[str]
    raw_discovered_path_rows: int
    unique_discovered_paths: int
    duplicate_discovered_path_rows: int


def build_workflow_provenance(project_state: ProjectState) -> WorkflowProvenance:
    """Build a clean workflow summary without changing raw evidence."""

    manifest = project_state.recon_manifest
    raw_profile = manifest.profile if manifest else None
    artifacts = manifest.artifacts if manifest else []
    filenames = [Path(artifact.file).name for artifact in artifacts]
    descriptions = [(artifact.description or "").lower() for artifact in artifacts]
    metadata_profiles = _execution_profiles(Path(project_state.input_dir))

    enrichment: list[str] = []
    if any(name.startswith("nmap-services") for name in filenames):
        enrichment.append("services")
    if any(
        name.startswith(("homepage-", "robots-", "curl-headers-"))
        and not name.startswith(
            ("curl-headers-followup-", "curl-headers-content-followup-")
        )
        for name in filenames
    ):
        enrichment.append("HTTP metadata")
    if any(name.startswith("curl-headers-followup-") for name in filenames):
        enrichment.append("path follow-up")

    content_profiles: list[str] = []
    if any(name.startswith("gobuster-tiny-") for name in filenames) or any(
        "lab-root-tiny" in description for description in descriptions
    ) or "lab-root-tiny" in metadata_profiles:
        content_profiles.append("lab-root-tiny")
    if any(
        name.startswith("gobuster-") and not name.startswith("gobuster-tiny-")
        for name in filenames
    ) or any(
        "lab-root-light" in description for description in descriptions
    ) or "lab-root-light" in metadata_profiles:
        content_profiles.append("lab-root-light")

    followup: list[str] = []
    if any(name.startswith("curl-headers-content-followup-") for name in filenames):
        followup.append("content-result follow-up")
    if any(name.startswith("body-fetch-") for name in filenames):
        followup.append("selective body fetch")

    unique_paths = {
        record.url.strip()
        for record in project_state.discovered_paths
        if record.url.strip()
    }
    raw_path_count = len(project_state.discovered_paths)
    unique_path_count = len(unique_paths)

    return WorkflowProvenance(
        raw_manifest_profile=raw_profile,
        base_discovery_profile=_base_profile(raw_profile),
        enrichment_phases=enrichment,
        content_discovery_profiles=content_profiles,
        followup_phases=followup,
        raw_discovered_path_rows=raw_path_count,
        unique_discovered_paths=unique_path_count,
        duplicate_discovered_path_rows=raw_path_count - unique_path_count,
    )


def _base_profile(raw_profile: str | None) -> str:
    if not raw_profile:
        return "not recorded"
    for profile in (
        "lab-tcp-full",
        "lab-tcp-top",
        "passive-only",
        "curl-headers-only",
        "manual-import",
    ):
        if raw_profile == profile or raw_profile.startswith(f"{profile}-plus-"):
            return profile
    return raw_profile.split("-plus-", 1)[0]


def _execution_profiles(input_dir: Path) -> set[str]:
    profiles: set[str] = set()
    paths = [input_dir / "recon_execution.json", *input_dir.glob("recon_execution_*.json")]
    for path in paths:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            profile = payload.get("profile")
            if isinstance(profile, str) and profile.strip():
                profiles.add(profile.strip())
    return profiles
