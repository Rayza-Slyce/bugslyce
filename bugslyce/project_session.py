"""Local JSON project/session management for BugSlyce."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
import shlex

from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.status import (
    ReconStatusResult,
    build_recon_status,
    render_recon_status_summary,
    write_recon_status,
)
from bugslyce.time_utils import Clock, utc_now_iso


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


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
