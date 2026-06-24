"""Local JSON project/session management for BugSlyce."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlparse

from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.status import (
    ReconStatusResult,
    build_recon_status,
    render_recon_status_summary,
    write_recon_status,
)
from bugslyce.time_utils import Clock, utc_now_iso


PROJECT_FILENAME = "bugslyce_project.json"
PROJECT_RUNBOOK_FILENAME = "runbook.md"
PROJECT_SCHEMA_VERSION = "1.0"
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DEFAULT_PROFILES = {
    "tcp_discovery": "lab-tcp-full",
    "content_discovery_smoke": "lab-root-tiny",
    "content_discovery_broader": "lab-root-light",
}
SCAFFOLD_SCOPE_FILENAME = "scope.md"
SCAFFOLD_OWNED_FILENAMES = {PROJECT_FILENAME, SCAFFOLD_SCOPE_FILENAME}


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
    created_at: str | None
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


@dataclass(frozen=True)
class GuidedProjectAction:
    """One deterministic, non-executing project guidance item."""

    id: str
    title: str
    command_preview: str
    optional: bool = False


@dataclass(frozen=True)
class ProjectNextResult:
    """Read-only guided next-step result for a saved project."""

    project: BugSlyceProject
    project_file: str
    recon_pack_exists: bool
    status_summary: str
    recommended_action: GuidedProjectAction
    optional_actions: list[GuidedProjectAction]


@dataclass(frozen=True)
class ProjectScaffoldResult:
    """Files created for a new local project scaffold."""

    project: BugSlyceProject
    project_directory: str
    scope_file: str
    project_file: str


@dataclass(frozen=True)
class ProjectInventoryEntry:
    """One valid or invalid immediate-child project inventory entry."""

    name: str
    target: str
    recon_pack_exists: bool | None
    created_at: str | None
    project_file: str
    error: str | None = None


@dataclass(frozen=True)
class ProjectInventoryResult:
    """Read-only inventory of projects beneath one local directory."""

    projects_directory: str
    entries: list[ProjectInventoryEntry]


@dataclass(frozen=True)
class ProjectRunbookResult:
    """Generated local project runbook metadata."""

    project: BugSlyceProject
    project_file: str
    runbook_path: str
    generated_at: str
    content: str


def initialize_project(
    name: str,
    target: str,
    scope_file: Path,
    output_dir: Path,
    force: bool = False,
    clock: Clock | None = None,
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
        created_at=utc_now_iso(clock),
        notes=[],
    )
    project_path.write_text(
        json.dumps(asdict(project), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return project, project_path


def scaffold_project(
    name: str,
    target: str,
    projects_dir: Path,
    force: bool = False,
    clock: Clock | None = None,
) -> ProjectScaffoldResult:
    """Create a conservative scope template and matching project file."""

    normalized_name = name.strip()
    if not SAFE_PROJECT_NAME.fullmatch(normalized_name):
        raise ValueError(
            "Project name may contain only letters, numbers, dash, and underscore."
        )
    normalized_target = _validate_target(target)
    projects_dir = projects_dir.expanduser().resolve()
    if projects_dir.exists() and not projects_dir.is_dir():
        raise ValueError(f"Projects path is not a directory: {projects_dir}")

    project_dir = projects_dir / normalized_name
    if project_dir.exists() and not project_dir.is_dir():
        raise ValueError(f"Project path is not a directory: {project_dir}")
    if project_dir.is_dir():
        entries = list(project_dir.iterdir())
        unsafe_entries = [
            entry for entry in entries if entry.name not in SCAFFOLD_OWNED_FILENAMES
        ]
        if unsafe_entries:
            names = ", ".join(sorted(entry.name for entry in unsafe_entries))
            raise ValueError(
                "Project directory contains existing non-scaffold files and will "
                f"not be modified: {names}"
            )
        non_file_entries = [entry for entry in entries if not entry.is_file()]
        if non_file_entries:
            names = ", ".join(sorted(entry.name for entry in non_file_entries))
            raise ValueError(
                "Project directory contains unsafe scaffold paths and will not "
                f"be modified: {names}"
            )
        if entries and not force:
            raise ValueError(
                f"Project directory is not empty: {project_dir}. "
                "Re-run with --force to replace scaffold-owned files."
            )

    project_dir.mkdir(parents=True, exist_ok=True)
    scope_file = project_dir / SCAFFOLD_SCOPE_FILENAME
    scope_file.write_text(_render_scope_template(normalized_target), encoding="utf-8")
    project, project_file = initialize_project(
        name=normalized_name,
        target=normalized_target,
        scope_file=scope_file,
        output_dir=project_dir,
        force=force,
        clock=clock,
    )
    return ProjectScaffoldResult(
        project=project,
        project_directory=str(project_dir),
        scope_file=str(scope_file),
        project_file=str(project_file),
    )


def list_projects(projects_dir: Path) -> ProjectInventoryResult:
    """List immediate-child BugSlyce projects without mutating project state."""

    projects_dir = projects_dir.expanduser().resolve()
    if not projects_dir.exists():
        raise ValueError(f"Projects directory does not exist: {projects_dir}")
    if not projects_dir.is_dir():
        raise ValueError(f"Projects path is not a directory: {projects_dir}")

    entries: list[ProjectInventoryEntry] = []
    project_files = sorted(
        (
            child / PROJECT_FILENAME
            for child in projects_dir.iterdir()
            if child.is_dir() and (child / PROJECT_FILENAME).is_file()
        ),
        key=lambda path: (path.parent.name.lower(), path.parent.name),
    )
    for project_file in project_files:
        try:
            project = load_project(project_file)
        except ValueError as exc:
            entries.append(
                ProjectInventoryEntry(
                    name=project_file.parent.name,
                    target="invalid",
                    recon_pack_exists=None,
                    created_at=None,
                    project_file=str(project_file.resolve()),
                    error=str(exc),
                )
            )
            continue
        entries.append(
            ProjectInventoryEntry(
                name=project.name,
                target=project.target,
                recon_pack_exists=(
                    Path(project.output_dir) / "recon_manifest.json"
                ).is_file(),
                created_at=project.created_at,
                project_file=str(project_file.resolve()),
            )
        )

    entries.sort(key=lambda entry: (entry.name.lower(), entry.name, entry.project_file))
    return ProjectInventoryResult(
        projects_directory=str(projects_dir),
        entries=entries,
    )


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
        created_at=_optional_text(payload.get("created_at")),
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


def build_project_next(project_file: Path) -> ProjectNextResult:
    """Build safe command previews from a project and its local evidence."""

    project_file = project_file.expanduser().resolve()
    project = load_project(project_file)
    output_dir = Path(project.output_dir)
    scope_file = Path(project.scope_file)
    manifest_path = output_dir / "recon_manifest.json"
    if not manifest_path.is_file():
        return ProjectNextResult(
            project=project,
            project_file=str(project_file),
            recon_pack_exists=False,
            status_summary="No recon pack exists yet.",
            recommended_action=_nmap_discovery_action(project),
            optional_actions=[],
        )

    status = build_recon_status(output_dir, scope_file)
    if status.target != project.target:
        raise ValueError(
            "Project target does not match the target in recon_manifest.json."
        )
    phase_status = {phase.id: phase.status for phase in status.phases}
    detected = lambda phase_id: phase_status.get(phase_id) == "detected"
    artifact_names = _manifest_artifact_names(manifest_path)
    has_discovery = any(
        name in {"nmap-allports.txt", "nmap-top1000.txt"}
        for name in artifact_names
    )
    has_gobuster = any(name.startswith("gobuster-") for name in artifact_names)
    status_summary = (
        f"Detected phases: {sum(value == 'detected' for value in phase_status.values())}/"
        f"{len(phase_status)}; HTTP services: "
        f"{status.artifact_overview.get('http_services', 0)}; unique discovered paths: "
        f"{status.artifact_overview.get('unique_discovered_paths', 0)}."
    )

    if has_discovery and not detected("nmap_services"):
        recommended = _live_action(
            "nmap-services",
            "Run service/version detection on already discovered open TCP ports.",
            [
                ".venv/bin/bugslyce",
                "recon",
                "nmap-services",
                "--input-dir",
                project.output_dir,
                "--scope",
                project.scope_file,
                "--confirm",
            ],
        )
    elif (
        detected("nmap_services")
        and status.artifact_overview.get("http_services", 0) > 0
        and not detected("http_metadata")
    ):
        recommended = _live_action(
            "http-metadata",
            "Collect bounded metadata from the discovered HTTP services.",
            _input_scope_confirm_argv("http-metadata", project),
        )
    elif (
        detected("http_metadata")
        and not detected("path_followup")
        and not has_gobuster
        and status.next_actions[0].find("path-followup") != -1
    ):
        recommended = _live_action(
            "path-followup",
            "Check same-origin paths already present in collected HTTP evidence.",
            _input_scope_confirm_argv("path-followup", project),
        )
    elif status.next_actions[0].find("content-followup") != -1:
        recommended = _live_action(
            "content-followup",
            "Follow up eligible paths already found by content discovery.",
            _input_scope_confirm_argv("content-followup", project),
        )
    elif status.next_actions[0].find("body-fetch") != -1:
        recommended = _live_action(
            "body-fetch",
            "Fetch bounded bodies for eligible high-signal followed paths.",
            _input_scope_confirm_argv("body-fetch", project),
        )
    elif status.artifact_overview.get("http_services", 0) > 0 and not has_gobuster:
        tiny_plan = _validated_plan_path(project, "lab-root-tiny")
        if tiny_plan is not None:
            recommended = _live_action(
                "content-run-tiny",
                "Run the reviewed lab-root-tiny content discovery plan.",
                [
                    ".venv/bin/bugslyce",
                    "recon",
                    "content-run",
                    "--plan",
                    str(tiny_plan),
                    "--scope",
                    project.scope_file,
                    "--confirm",
                ],
            )
        else:
            recommended = _content_plan_action(project, "lab-root-tiny")
    else:
        recommended = GuidedProjectAction(
            id="manual-review",
            title="Review the Operator Summary and raw evidence manually.",
            command_preview=_format_command(
                ["less", str(output_dir / "report.md")]
            ),
        )

    optional_actions: list[GuidedProjectAction] = []
    profiles = status.workflow_summary.content_discovery_profiles
    if "lab-root-tiny" in profiles and "lab-root-light" not in profiles:
        light_plan = _validated_plan_path(project, "lab-root-light")
        if light_plan is not None:
            optional_actions.append(
                GuidedProjectAction(
                    id="content-run-light",
                    title=(
                        "Optional broader root discovery: inspect the saved "
                        "lab-root-light plan, then run one immutable step at a time."
                    ),
                    command_preview=_format_command(
                        [
                            ".venv/bin/bugslyce",
                            "recon",
                            "content-run",
                            "--plan",
                            str(light_plan),
                            "--scope",
                            project.scope_file,
                            "--step-id",
                            "CONTENT-STEP-001",
                            "--confirm",
                        ]
                    ),
                    optional=True,
                )
            )
        else:
            optional_actions.append(_content_plan_action(project, "lab-root-light", optional=True))
    if recommended.id == "manual-review":
        optional_actions.append(
            GuidedProjectAction(
                id="export",
                title="Optionally create a portable evidence pack after review.",
                command_preview=_format_command(
                    [
                        ".venv/bin/bugslyce",
                        "recon",
                        "export",
                        "--input-dir",
                        project.output_dir,
                        "--output",
                        f"{project.output_dir}-evidence-pack.zip",
                    ]
                ),
                optional=True,
            )
        )

    return ProjectNextResult(
        project=project,
        project_file=str(project_file),
        recon_pack_exists=True,
        status_summary=status_summary,
        recommended_action=recommended,
        optional_actions=optional_actions,
    )


def build_project_runbook(
    project_file: Path,
    clock: Clock | None = None,
    standard_investigation_workflow_markdown: str | None = None,
) -> ProjectRunbookResult:
    """Build a local Markdown runbook from project next-step guidance."""

    project_file = project_file.expanduser().resolve()
    next_result = build_project_next(project_file)
    output_dir = Path(next_result.project.output_dir).expanduser().resolve()
    if not output_dir.is_dir():
        raise ValueError(f"Project output directory does not exist: {output_dir}")

    runbook_path = output_dir / PROJECT_RUNBOOK_FILENAME
    resolved_runbook = runbook_path.resolve(strict=False)
    if resolved_runbook.parent != output_dir:
        raise ValueError("Runbook path must remain inside the project output directory.")

    generated_at = utc_now_iso(clock)
    content = _render_project_runbook(
        next_result,
        project_file=project_file,
        generated_at=generated_at,
        standard_investigation_workflow_markdown=standard_investigation_workflow_markdown,
    )
    return ProjectRunbookResult(
        project=next_result.project,
        project_file=str(project_file),
        runbook_path=str(resolved_runbook),
        generated_at=generated_at,
        content=content,
    )


def write_project_runbook(result: ProjectRunbookResult) -> Path:
    """Write only the generated runbook file inside the project output directory."""

    output_dir = Path(result.project.output_dir).expanduser().resolve()
    runbook_path = Path(result.runbook_path)
    if runbook_path.parent != output_dir or runbook_path.name != PROJECT_RUNBOOK_FILENAME:
        raise ValueError("Runbook path must remain inside the project output directory.")
    if runbook_path.exists() and not runbook_path.is_file():
        raise ValueError(f"Runbook path is not a regular file: {runbook_path}")
    runbook_path.write_text(result.content, encoding="utf-8")
    return runbook_path


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
            f"Created at: {project.created_at or 'not recorded'}",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )


def render_project_scaffold_summary(
    result: ProjectScaffoldResult,
    *,
    include_next_preview: bool = True,
    include_safety_footer: bool = True,
) -> str:
    """Render project scaffold creation output and next-step preview."""

    lines = [
        "BugSlyce project scaffold created",
        f"Name: {result.project.name}",
        f"Target: {result.project.target}",
        f"Project directory: {result.project_directory}",
        f"Scope file: {result.scope_file}",
        f"Project file: {result.project_file}",
    ]
    if include_next_preview:
        lines.extend(
            [
                "Review scope.md before running recon.",
                "Suggested command preview:",
                f"bugslyce project next --project {shlex.quote(result.project_file)}",
            ]
        )
    if include_safety_footer:
        lines.extend(
            [
                "No commands were executed.",
                "No network requests were made.",
            ]
        )
    return "\n".join(lines)


def render_project_inventory(result: ProjectInventoryResult) -> str:
    """Render a deterministic local project inventory."""

    lines = [
        "BugSlyce projects",
        "",
        f"Projects directory: {result.projects_directory}",
        f"Projects found: {len(result.entries)}",
    ]
    if not result.entries:
        lines.extend(
            [
                "",
                "No BugSlyce project files were found.",
                "Create one with:",
                "bugslyce project scaffold --name NAME --target TARGET "
                f"--projects-dir {shlex.quote(result.projects_directory)}",
            ]
        )
    else:
        rows = [
            (
                entry.name,
                entry.target,
                _inventory_recon_pack_label(entry.recon_pack_exists),
                entry.created_at or "not recorded",
                entry.project_file,
            )
            for entry in result.entries
        ]
        headers = ("Name", "Target", "Recon Pack", "Created At", "Path")
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in rows))
            for index in range(len(headers))
        ]
        lines.extend(
            [
                "",
                _format_inventory_row(headers, widths),
                _format_inventory_row(
                    tuple("-" * width for width in widths),
                    widths,
                ),
            ]
        )
        lines.extend(_format_inventory_row(row, widths) for row in rows)

        invalid_entries = [entry for entry in result.entries if entry.error]
        if invalid_entries:
            lines.extend(["", "Warnings:"])
            lines.extend(
                f"* Invalid project file {entry.project_file}: {entry.error}"
                for entry in invalid_entries
            )

    lines.extend(
        [
            "",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )
    return "\n".join(lines)


def render_project_runbook_summary(result: ProjectRunbookResult) -> str:
    """Render local runbook write confirmation."""

    return "\n".join(
        [
            "BugSlyce project runbook written",
            f"Project name: {result.project.name}",
            f"Target: {result.project.target}",
            f"Runbook path: {result.runbook_path}",
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
            f"Created at: {project.created_at or 'not recorded'}",
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


def render_project_next(result: ProjectNextResult) -> str:
    """Render guided command previews without executing them."""

    lines = [
        "BugSlyce guided next step",
        f"Project name: {result.project.name}",
        f"Target: {result.project.target}",
        f"Recon pack exists: {str(result.recon_pack_exists).lower()}",
        f"Current status summary: {result.status_summary}",
        "",
        "Recommended next safe action:",
        f"- {result.recommended_action.title}",
        "",
        "Suggested command preview:",
        result.recommended_action.command_preview,
    ]
    for action in result.optional_actions:
        lines.extend(
            [
                "",
                "Optional safe action:",
                f"- {action.title}",
                "",
                "Suggested command preview:",
                action.command_preview,
            ]
        )
    lines.extend(
        [
            "",
            "Safety reminder: review current scope and command details before running anything.",
            "Suggested commands are previews only.",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )
    return "\n".join(lines)


def _nmap_discovery_action(project: BugSlyceProject) -> GuidedProjectAction:
    profile = project.default_profiles.get("tcp_discovery", "lab-tcp-full")
    return _live_action(
        "nmap-discover",
        "Start with scoped full TCP discovery.",
        [
            ".venv/bin/bugslyce",
            "recon",
            "nmap-discover",
            "--target",
            project.target,
            "--scope",
            project.scope_file,
            "--profile",
            profile,
            "--output",
            project.output_dir,
            "--confirm",
        ],
    )


def _content_plan_action(
    project: BugSlyceProject,
    profile: str,
    optional: bool = False,
) -> GuidedProjectAction:
    suffix = "tiny" if profile == "lab-root-tiny" else "light"
    title = (
        "Create a reviewed lab-root-tiny content discovery plan."
        if profile == "lab-root-tiny"
        else (
            "Optional broader root discovery: create a lab-root-light plan and "
            "run selected steps one origin at a time."
        )
    )
    return GuidedProjectAction(
        id=f"content-plan-{suffix}",
        title=title,
        command_preview=_format_command(
            [
                ".venv/bin/bugslyce",
                "recon",
                "content-plan",
                "--input-dir",
                project.output_dir,
                "--scope",
                project.scope_file,
                "--profile",
                profile,
                "--output",
                f"{project.output_dir}-content-plan-{suffix}",
            ]
        ),
        optional=optional,
    )


def _live_action(action_id: str, title: str, argv: list[str]) -> GuidedProjectAction:
    if "--confirm" not in argv:
        raise ValueError(f"Live command preview '{action_id}' must include --confirm.")
    return GuidedProjectAction(
        id=action_id,
        title=title,
        command_preview=_format_command(argv),
    )


def _input_scope_confirm_argv(command: str, project: BugSlyceProject) -> list[str]:
    return [
        ".venv/bin/bugslyce",
        "recon",
        command,
        "--input-dir",
        project.output_dir,
        "--scope",
        project.scope_file,
        "--confirm",
    ]


def _validated_plan_path(
    project: BugSlyceProject,
    profile: str,
) -> Path | None:
    suffix = "tiny" if profile == "lab-root-tiny" else "light"
    plan_path = Path(f"{project.output_dir}-content-plan-{suffix}") / "content_discovery_plan.json"
    if not plan_path.is_file():
        return None
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if (
        payload.get("created_by") != "bugslyce-content-planner"
        or payload.get("target") != project.target
        or payload.get("profile") != profile
    ):
        return None
    steps = payload.get("steps")
    if not isinstance(steps, list) or not steps:
        return None
    if profile == "lab-root-light" and not any(
        isinstance(step, dict) and step.get("id") == "CONTENT-STEP-001"
        for step in steps
    ):
        return None
    input_dir = payload.get("input_dir")
    if not isinstance(input_dir, str):
        return None
    if Path(input_dir).expanduser().resolve() != Path(project.output_dir):
        return None
    return plan_path.resolve()


def _manifest_artifact_names(manifest_path: Path) -> list[str]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse recon manifest {manifest_path}: {exc}") from exc
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(artifacts, list):
        raise ValueError("Recon manifest field 'artifacts' must be a list.")
    return [
        Path(str(artifact.get("file", ""))).name
        for artifact in artifacts
        if isinstance(artifact, dict)
    ]


def _format_command(argv: list[str]) -> str:
    quoted = [shlex.quote(value) for value in argv]
    if len(quoted) <= 3:
        return " ".join(quoted)
    groups = [" ".join(quoted[:3])]
    index = 3
    while index < len(quoted):
        current = quoted[index]
        if (
            current.startswith("--")
            and index + 1 < len(quoted)
            and not quoted[index + 1].startswith("--")
        ):
            groups.append(f"{current} {quoted[index + 1]}")
            index += 2
        else:
            groups.append(current)
            index += 1
    return " \\\n  ".join(groups)


def _validate_target(target: str) -> str:
    value = target.strip().lower()
    if not value or any(character.isspace() for character in value):
        raise ValueError(_target_validation_message())

    if "://" in value:
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.params
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError(_target_validation_message())
        value = parsed.hostname.lower()

    value = value.rstrip(".")
    if not _is_valid_ipv4(value) and not _is_valid_hostname(value):
        raise ValueError(_target_validation_message())
    if scope_entry_target(value) != value:
        raise ValueError(_target_validation_message())
    return value


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _is_valid_hostname(value: str) -> bool:
    if not value or value.startswith("*.") or value.startswith(".") or value.endswith("."):
        return False
    if set(value) <= set("0123456789."):
        return False
    labels = value.split(".")
    return all(label and HOSTNAME_LABEL.fullmatch(label) for label in labels)


def _target_validation_message() -> str:
    return (
        "Target must be a plain IPv4 address, hostname, or simple http/https URL. "
        "Do not include paths, queries, fragments, credentials, malformed IP-like "
        "values, or non-http schemes."
    )


def _render_scope_template(target: str) -> str:
    return "\n".join(
        [
            "# BugSlyce Scope",
            "",
            "Starter scope template generated by BugSlyce.",
            "",
            "Review and confirm authorisation before running recon.",
            "",
            "## In Scope",
            "",
            f"* {target}",
            "",
            "## Out of Scope",
            "",
            "* Any other IP or domain",
            "* UDP scans",
            "* NSE scripts",
            "* Brute force",
            "* Exploitation",
            "* Recursive discovery unless explicitly authorised",
            "* Form submission unless explicitly authorised",
            "* Authentication testing unless explicitly authorised",
            "",
            "## Notes",
            "",
            "* This file is a local operator template.",
            "* Edit it to match the actual programme/lab scope before running commands.",
            "* BugSlyce scope checks use target entries and policy notes as safety context.",
            "",
        ]
    )


def _render_project_runbook(
    result: ProjectNextResult,
    *,
    project_file: Path,
    generated_at: str,
    standard_investigation_workflow_markdown: str | None = None,
) -> str:
    project = result.project
    output_dir = Path(project.output_dir)
    lines = [
        "# BugSlyce Project Runbook",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "## Project",
        "",
        f"* Name: {project.name}",
        f"* Target: {project.target}",
        f"* Scope file: `{project.scope_file}`",
        f"* Output directory: `{project.output_dir}`",
        f"* Project file: `{project_file}`",
        "",
        "## Scope Reminder",
        "",
        "Review `scope.md` before running recon.",
        "This runbook does not grant authorisation.",
        "Only test targets you are authorised to assess.",
        "",
        "## Current Status",
        "",
        f"* Recon pack exists: {str(result.recon_pack_exists).lower()}",
        f"* Status summary: {result.status_summary}",
        (
            "* Current recommended next safe action: "
            f"{result.recommended_action.title}"
        ),
        "",
        "## Suggested Next Command",
        "",
        "```bash",
        result.recommended_action.command_preview,
        "```",
    ]
    if standard_investigation_workflow_markdown:
        section = standard_investigation_workflow_markdown.strip()
        if section:
            lines.extend(["", section])
    if result.optional_actions:
        lines.extend(["", "## Optional Safe Commands"])
        for action in result.optional_actions:
            lines.extend(
                [
                    "",
                    f"### {action.title}",
                    "",
                    "```bash",
                    action.command_preview,
                    "```",
                ]
            )

    project_arg = shlex.quote(str(project_file))
    output_arg = shlex.quote(project.output_dir)
    report_arg = shlex.quote(str(output_dir / "report.md"))
    export_arg = shlex.quote(f"{project.output_dir}-evidence-pack.zip")
    lines.extend(
        [
            "",
            "## Typical Safe Workflow",
            "",
            "1. Run doctor:",
            "   `bugslyce doctor`",
            "",
            "2. Check project status:",
            f"   `bugslyce project status --project {project_arg}`",
            "",
            "3. Preview the next action:",
            f"   `bugslyce project next --project {project_arg}`",
            "",
            "4. Run reviewed commands manually.",
            "",
            "5. Review the report:",
            f"   `less {report_arg}`",
            "",
            "6. Export an evidence pack:",
            (
                "   `bugslyce recon export "
                f"--input-dir {output_arg} --output {export_arg}`"
            ),
            "",
            "## Safety Notes",
            "",
            "* This runbook is generated from local project metadata and local evidence.",
            "* Suggested commands are previews only.",
            "* No commands were executed during runbook generation.",
            "* No network requests were made.",
            "* Manual validation is required before claiming any finding.",
            "* Absence of evidence is not proof of safety.",
            "* Do not run recon outside authorised scope.",
            "",
        ]
    )
    return "\n".join(lines)


def _inventory_recon_pack_label(value: bool | None) -> str:
    if value is None:
        return "invalid"
    return "yes" if value else "no"


def _format_inventory_row(
    values: tuple[str, ...],
    widths: list[int],
) -> str:
    return "  ".join(
        value.ljust(widths[index]) for index, value in enumerate(values)
    ).rstrip()


def _required_text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Project field '{key}' is required.")
    return value.strip()


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
