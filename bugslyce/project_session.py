"""Local JSON project/session management for BugSlyce."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re

from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.status import (
    ReconStatusResult,
    build_recon_status,
    render_recon_status_summary,
    write_recon_status,
)


PROJECT_FILENAME = "bugslyce_project.json"
PROJECT_SCHEMA_VERSION = "1.0"
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
DEFAULT_PROFILES = {
    "tcp_discovery": "lab-tcp-full",
    "content_discovery_smoke": "lab-root-tiny",
    "content_discovery_broader": "lab-root-light",
}


@dataclass(frozen=True)
class BugSlyceProject:
    """Portable local project/session metadata."""

    schema_version: str
    name: str
    target: str
    scope_file: str
    output_dir: str
    created_by: str
    default_profiles: dict[str, str]
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProjectStatusResult:
    """Project-level status, with optional recon-pack status."""

    project: BugSlyceProject
    project_file: str
    recon_pack_exists: bool
    recon_status: ReconStatusResult | None
    status_json_path: str | None
    status_markdown_path: str | None
    next_action: str


def initialize_project(
    name: str,
    target: str,
    scope_file: Path,
    output_dir: Path,
    force: bool = False,
) -> tuple[BugSlyceProject, Path]:
    """Validate and write one local project file."""

    normalized_name = name.strip()
    if not SAFE_PROJECT_NAME.fullmatch(normalized_name):
        raise ValueError(
            "Project name may contain only letters, numbers, dash, and underscore."
        )
    normalized_target = _validate_target(target)
    scope_file = scope_file.expanduser().resolve()
    if not scope_file.is_file():
        raise ValueError(f"Scope file does not exist: {scope_file}")

    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"Output path is not a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    project_path = output_dir / PROJECT_FILENAME
    if project_path.exists() and not force:
        raise ValueError(
            f"Project file already exists: {project_path}. "
            "Re-run with --force to overwrite it."
        )

    project = BugSlyceProject(
        schema_version=PROJECT_SCHEMA_VERSION,
        name=normalized_name,
        target=normalized_target,
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        created_by="bugslyce",
        default_profiles=dict(DEFAULT_PROFILES),
        notes=[],
    )
    project_path.write_text(
        json.dumps(asdict(project), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return project, project_path


def load_project(project_file: Path) -> BugSlyceProject:
    """Load and validate a BugSlyce project file."""

    project_file = project_file.expanduser().resolve()
    if not project_file.is_file():
        raise ValueError(f"Project file does not exist: {project_file}")
    try:
        payload = json.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse project file {project_file}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Project file must contain a JSON object: {project_file}")

    schema_version = _required_text(payload, "schema_version")
    if schema_version != PROJECT_SCHEMA_VERSION:
        raise ValueError(f"Unsupported project schema version: {schema_version}")
    name = _required_text(payload, "name")
    if not SAFE_PROJECT_NAME.fullmatch(name):
        raise ValueError("Project file contains an unsafe project name.")
    target = _validate_target(_required_text(payload, "target"))
    scope_file = Path(_required_text(payload, "scope_file")).expanduser().resolve()
    output_dir = Path(_required_text(payload, "output_dir")).expanduser().resolve()
    if not scope_file.is_file():
        raise ValueError(f"Project scope file does not exist: {scope_file}")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"Project output path is not a directory: {output_dir}")

    raw_profiles = payload.get("default_profiles", DEFAULT_PROFILES)
    if not isinstance(raw_profiles, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in raw_profiles.items()
    ):
        raise ValueError("Project default_profiles must be a JSON object of strings.")
    raw_notes = payload.get("notes", [])
    if not isinstance(raw_notes, list) or not all(isinstance(note, str) for note in raw_notes):
        raise ValueError("Project notes must be a list of strings.")

    return BugSlyceProject(
        schema_version=schema_version,
        name=name,
        target=target,
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        created_by=_required_text(payload, "created_by"),
        default_profiles=dict(raw_profiles),
        notes=list(raw_notes),
    )


def inspect_project_status(project_file: Path) -> ProjectStatusResult:
    """Inspect a project's output directory without executing recon."""

    project_file = project_file.expanduser().resolve()
    project = load_project(project_file)
    output_dir = Path(project.output_dir)
    manifest_path = output_dir / "recon_manifest.json"
    if not manifest_path.is_file():
        return ProjectStatusResult(
            project=project,
            project_file=str(project_file),
            recon_pack_exists=False,
            recon_status=None,
            status_json_path=None,
            status_markdown_path=None,
            next_action=(
                "No recon pack exists yet. Recommended first safe action: create a "
                "scoped recon plan or run an existing narrowly scoped discovery command."
            ),
        )

    status = build_recon_status(output_dir, Path(project.scope_file))
    json_path, markdown_path = write_recon_status(status, output_dir)
    return ProjectStatusResult(
        project=project,
        project_file=str(project_file),
        recon_pack_exists=True,
        recon_status=status,
        status_json_path=str(json_path),
        status_markdown_path=str(markdown_path),
        next_action=status.next_actions[0],
    )


def render_project_init_summary(project: BugSlyceProject, project_path: Path) -> str:
    """Render project creation output."""

    return "\n".join(
        [
            "BugSlyce project initialized",
            f"Name: {project.name}",
            f"Target: {project.target}",
            f"Scope file: {project.scope_file}",
            f"Output directory: {project.output_dir}",
            f"Project file path: {project_path}",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )


def render_project_show(project: BugSlyceProject, project_file: Path) -> str:
    """Render project metadata without inspecting recon state."""

    profiles = ", ".join(
        f"{key}={value}" for key, value in sorted(project.default_profiles.items())
    )
    return "\n".join(
        [
            "BugSlyce project",
            f"Project file: {project_file.expanduser().resolve()}",
            f"Schema version: {project.schema_version}",
            f"Name: {project.name}",
            f"Target: {project.target}",
            f"Scope file: {project.scope_file}",
            f"Output directory: {project.output_dir}",
            f"Created by: {project.created_by}",
            f"Default profiles: {profiles}",
            f"Notes: {len(project.notes)}",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )


def render_project_status(result: ProjectStatusResult) -> str:
    """Render project resume/status output."""

    lines = [
        "BugSlyce project status",
        f"Name: {result.project.name}",
        f"Target: {result.project.target}",
        f"Project file: {result.project_file}",
        f"Scope file: {result.project.scope_file}",
        f"Output directory: {result.project.output_dir}",
        f"Recon pack exists: {str(result.recon_pack_exists).lower()}",
    ]
    if result.recon_status is not None:
        lines.extend(
            [
                "",
                render_recon_status_summary(
                    result.recon_status,
                    Path(result.status_json_path or ""),
                    Path(result.status_markdown_path or ""),
                ),
            ]
        )
    else:
        lines.extend(
            [
                f"Next action: {result.next_action}",
                "No commands were executed.",
                "No network requests were made.",
            ]
        )
    return "\n".join(lines)


def _validate_target(target: str) -> str:
    value = target.strip().lower().rstrip(".")
    if (
        not value
        or value.startswith("*.")
        or "/" in value
        or "://" in value
        or scope_entry_target(value) != value
    ):
        raise ValueError("Target must be one plain IP address or hostname.")
    return value


def _required_text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Project field '{key}' is required.")
    return value.strip()
