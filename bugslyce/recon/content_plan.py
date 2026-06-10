"""Build reviewed content discovery plans without executing commands."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import (
    ContentDiscoveryPlan,
    ContentDiscoveryStep,
    ProjectState,
    ReconPlannedArtifact,
)
from bugslyce.core.project import build_project_state
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope


CONTENT_DISCOVERY_PROFILE = "lab-root-light"
DEFAULT_WORDLIST = Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
MAX_CONTENT_PLAN_ORIGINS = 5
CONTENT_PLAN_THREADS = 10
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")
NO_EXECUTION_NOTE = "No commands were executed."


def build_content_discovery_plan(
    input_dir: Path,
    scope_file: Path,
    profile: str,
    output_dir: Path,
) -> ContentDiscoveryPlan:
    """Build a bounded root-discovery plan from existing HTTP services."""

    input_dir = input_dir.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")
    if not scope_file.exists():
        raise ValueError(f"Scope file does not exist: {scope_file}")
    if not scope_file.is_file():
        raise ValueError(f"Scope path is not a file: {scope_file}")
    if profile != CONTENT_DISCOVERY_PROFILE:
        raise ValueError(
            f"Unsupported content discovery profile '{profile}'. "
            f"Supported profile: {CONTENT_DISCOVERY_PROFILE}."
        )
    if not _safe_output_dir(output_dir):
        raise ValueError(
            "Content plan output must be under /tmp, private_recon/, raw-recon/, "
            "or bugslyce-output/."
        )

    project_state = build_project_state(input_dir)
    manifest = project_state.recon_manifest
    if manifest is None or not manifest.target.strip():
        raise ValueError("Content planning requires recon_manifest.json with a target.")
    target = validate_explicit_nmap_target_scope(manifest.target.strip().lower(), scope_file)
    all_origins = discover_content_plan_origins(
        project_state,
        target,
        max_origins=max(MAX_CONTENT_PLAN_ORIGINS, len(project_state.http_services)),
    )
    if not all_origins:
        raise ValueError("No discovered HTTP service origins are available for content planning.")
    origins = all_origins[:MAX_CONTENT_PLAN_ORIGINS]

    warnings: list[str] = []
    if len(all_origins) > MAX_CONTENT_PLAN_ORIGINS:
        warnings.append(f"Content discovery plan capped at {MAX_CONTENT_PLAN_ORIGINS} origins.")
    if not DEFAULT_WORDLIST.is_file():
        warnings.append(
            f"Future approved wordlist was not found locally: {DEFAULT_WORDLIST}. "
            "Planning continues without using it."
        )

    steps = [
        _build_step(index, origin, output_dir)
        for index, origin in enumerate(origins, start=1)
    ]
    return ContentDiscoveryPlan(
        target=target,
        profile=CONTENT_DISCOVERY_PROFILE,
        input_dir=str(input_dir),
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        origins=origins,
        steps=steps,
        warnings=warnings,
        safety_notes=[
            NO_EXECUTION_NOTE,
            "This plan requires operator review before any future content discovery.",
            "Only discovered HTTP service roots are included.",
            "The profile proposes no recursion, extensions, arbitrary paths, or user-supplied flags.",
            "Future execution must require explicit confirmation and remain in scope.",
        ],
        no_commands_executed=True,
    )


def discover_content_plan_origins(
    project_state: ProjectState,
    target: str,
    max_origins: int = MAX_CONTENT_PLAN_ORIGINS,
) -> list[str]:
    """Return deterministic root origins from structured HTTP services."""

    origins: set[str] = set()
    for service in project_state.http_services:
        parsed = urlparse(service.url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            continue
        origins.add(urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")))
    return sorted(origins, key=_origin_sort_key)[:max_origins]


def write_content_discovery_plan(
    plan: ContentDiscoveryPlan,
    output_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Write JSON and Markdown content discovery plans."""

    destination = (output_dir or Path(plan.output_dir)).expanduser().resolve()
    if not _safe_output_dir(destination):
        raise ValueError(
            "Content plan output must be under /tmp, private_recon/, raw-recon/, "
            "or bugslyce-output/."
        )
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "content_discovery_plan.json"
    markdown_path = destination / "content_discovery_plan.md"
    json_path.write_text(json.dumps(asdict(plan), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_content_discovery_plan(plan), encoding="utf-8")
    return json_path, markdown_path


def render_content_discovery_plan(plan: ContentDiscoveryPlan) -> str:
    """Render a human-readable non-executing content discovery plan."""

    lines = [
        "# BugSlyce Content Discovery Plan",
        "",
        f"- Target: `{plan.target}`",
        f"- Profile: `{plan.profile}`",
        f"- Input directory: `{plan.input_dir}`",
        f"- Scope file: `{plan.scope_file}`",
        f"- Output directory: `{plan.output_dir}`",
        f"- HTTP origins planned: {len(plan.origins)}",
        "",
        "## Safety",
        "",
        *[f"- {note}" for note in plan.safety_notes],
    ]
    if plan.warnings:
        lines.extend(["", "## Warnings", "", *[f"- {warning}" for warning in plan.warnings]])
    lines.extend(["", "## Planned Root Discovery Steps", ""])
    for step in plan.steps:
        lines.extend(
            [
                f"### {step.step_id}: {step.origin}",
                "",
                f"- Allowed tool: `{step.allowed_tool}`",
                f"- Risk level: `{step.risk_level}`",
                f"- Requires confirmation: `{str(step.requires_confirmation).lower()}`",
                f"- Scope sensitive: `{str(step.scope_sensitive).lower()}`",
                f"- Command preview: `{shlex.join(step.command_preview)}`",
                f"- Expected artifact: `{step.expected_artifact.file}`",
                "- Recursive discovery: `false`",
                "- Ready for execution: `false`",
                "",
            ]
        )
    lines.extend([NO_EXECUTION_NOTE, ""])
    return "\n".join(lines)


def render_content_discovery_plan_summary(
    plan: ContentDiscoveryPlan,
    json_path: Path,
    markdown_path: Path,
) -> str:
    """Render concise CLI output for content planning."""

    lines = [
        "BugSlyce content discovery plan created",
        f"Target: {plan.target}",
        f"Profile: {plan.profile}",
        f"Input directory: {plan.input_dir}",
        f"Output directory: {plan.output_dir}",
        f"HTTP origins planned: {len(plan.origins)}",
        f"Planned commands: {len(plan.steps)}",
        f"JSON path: {json_path}",
        f"Markdown path: {markdown_path}",
    ]
    lines.extend(f"Warning: {warning}" for warning in plan.warnings)
    lines.append(NO_EXECUTION_NOTE)
    return "\n".join(lines)


def _build_step(index: int, origin: str, output_dir: Path) -> ContentDiscoveryStep:
    parsed = urlparse(origin)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    safe_host = _safe_component(parsed.hostname or "host")
    filename = f"gobuster-{safe_host}-{port}-root.txt"
    argv = [
        "gobuster",
        "dir",
        "-u",
        origin,
        "-w",
        str(DEFAULT_WORDLIST),
        "-t",
        str(CONTENT_PLAN_THREADS),
        "-o",
        str(output_dir / filename),
    ]
    _validate_preview(argv, origin, output_dir / filename)
    return ContentDiscoveryStep(
        step_id=f"CONTENT-STEP-{index:03d}",
        origin=origin,
        command_preview=argv,
        expected_artifact=ReconPlannedArtifact(
            type="gobuster",
            file=filename,
            base_url=origin,
            description="Future bounded root content discovery output",
        ),
        risk_level="moderate",
        requires_confirmation=True,
        scope_sensitive=True,
        allowed_tool="gobuster",
        no_commands_executed=True,
    )


def _validate_preview(argv: list[str], origin: str, output_file: Path) -> None:
    expected = [
        "gobuster",
        "dir",
        "-u",
        origin,
        "-w",
        str(DEFAULT_WORDLIST),
        "-t",
        str(CONTENT_PLAN_THREADS),
        "-o",
        str(output_file),
    ]
    if argv != expected:
        raise ValueError("Content discovery preview does not match the approved fixed shape.")
    if any(token in value for value in argv for token in SHELL_METACHARACTERS):
        raise ValueError("Content discovery preview contains a shell metacharacter.")


def _safe_output_dir(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    if _is_relative_to(resolved, Path("/tmp")):
        return True
    return any(part in {"private_recon", "raw-recon", "bugslyce-output"} for part in resolved.parts)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _origin_sort_key(origin: str) -> tuple[str, int, str]:
    parsed = urlparse(origin)
    return parsed.scheme, parsed.port or (443 if parsed.scheme == "https" else 80), origin


def _safe_component(value: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", value.lower()).strip(".-") or "host"
