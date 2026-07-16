"""Read-only local readiness checks for BugSlyce."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.resources
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Callable

from bugslyce import __version__
from bugslyce.project_session import initialize_project, inspect_project_status
from bugslyce.recon.content_plan import (
    STANDARD_BOUNDED_CORE_PROFILE,
    TINY_WORDLIST,
    STANDARD_BOUNDED_CORE_WORDLIST,
)


DIRBUSTER_SMALL_WORDLIST = Path(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
)
SUPPORTED_PYTHON = (3, 11)
REQUIRED_EXTERNAL_TOOLS = (
    ("nmap", "TCP discovery and service/version detection", ("quick", "standard", "deep")),
    ("curl", "bounded HTTP metadata, follow-up, and body-fetch requests", ("quick", "standard", "deep")),
    ("gobuster", "bounded content discovery with approved wordlists", ("quick", "standard", "deep")),
)
MANUAL_MODE_ID = "manual_setup"
MODE_LABELS = {
    MANUAL_MODE_ID: "Manual Setup Only",
    "quick": "Quick Recon",
    "standard": "Standard Recon",
    "deep": "Deep Recon",
}


@dataclass(frozen=True)
class ResourceRequirement:
    """Authoritative bundled resource required by executable workflows."""

    name: str
    path: Path
    workflows: tuple[str, ...]


REQUIRED_BUNDLED_RESOURCES = (
    ResourceRequirement(
        name="lab-root-tiny",
        path=TINY_WORDLIST,
        workflows=("quick",),
    ),
    ResourceRequirement(
        name=STANDARD_BOUNDED_CORE_PROFILE,
        path=STANDARD_BOUNDED_CORE_WORDLIST,
        workflows=("standard", "deep"),
    ),
)


@dataclass(frozen=True)
class ToolReadiness:
    """Readiness for one external local command."""

    name: str
    found: bool
    path: str | None
    executable: bool
    ready: bool
    purpose: str
    blocked_workflows: tuple[str, ...]
    problem: str | None = None


@dataclass(frozen=True)
class ResourceReadiness:
    """Readiness for one package-local resource."""

    name: str
    path: str
    exists: bool
    regular_file: bool
    readable: bool
    non_empty: bool
    inside_package: bool
    ready: bool
    blocked_workflows: tuple[str, ...]
    problem: str | None = None


@dataclass(frozen=True)
class ModeReadiness:
    """Readiness for one operator-facing mode."""

    mode: str
    display_name: str
    status: str
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True)
class DoctorReport:
    """Structured result of local, non-executing readiness checks."""

    bugslyce_version: str
    python_version: str
    python_supported: bool
    virtual_environment: bool
    platform_summary: str
    current_working_directory: str
    tool_paths: dict[str, str | None]
    bundled_wordlist_available: bool
    bundled_wordlist_path: str | None
    dirbuster_wordlist_available: bool
    dirbuster_wordlist_path: str
    project_commands_available: bool
    readiness: str
    warnings: tuple[str, ...]
    minimum_python_version: str = "3.11"
    python_executable: str | None = None
    package_import_ready: bool = True
    core_ready: bool = True
    recon_ready: bool = True
    overall_ready: bool = True
    tools: tuple[ToolReadiness, ...] = ()
    resources: tuple[ResourceReadiness, ...] = ()
    modes: tuple[ModeReadiness, ...] = ()
    recommended_fixes: tuple[str, ...] = ()


def build_doctor_report(
    *,
    which: Callable[[str], str | None] | None = None,
    path_exists: Callable[[Path], bool] | None = None,
    bundled_wordlist_probe: Callable[[], tuple[bool, str | None]] | None = None,
    python_version_info: tuple[int, int, int] | None = None,
    path_is_file: Callable[[Path], bool] | None = None,
    path_is_dir: Callable[[Path], bool] | None = None,
    path_is_symlink: Callable[[Path], bool] | None = None,
    path_is_readable: Callable[[Path], bool] | None = None,
    path_is_executable: Callable[[Path], bool] | None = None,
    path_size: Callable[[Path], int] | None = None,
) -> DoctorReport:
    """Inspect local Python, tools, and package resources without execution."""

    which = which or shutil.which
    path_exists = path_exists or Path.exists
    path_is_file = path_is_file or Path.is_file
    path_is_dir = path_is_dir or Path.is_dir
    path_is_symlink = path_is_symlink or Path.is_symlink
    path_is_readable = path_is_readable or (lambda path: os.access(path, os.R_OK))
    path_is_executable = path_is_executable or (lambda path: os.access(path, os.X_OK))
    path_size = path_size or (lambda path: path.stat().st_size)

    version_info = python_version_info or sys.version_info[:3]
    python_supported = version_info >= SUPPORTED_PYTHON
    project_commands_available = callable(initialize_project) and callable(inspect_project_status)
    package_import_ready = bool(__version__)
    core_ready = python_supported and project_commands_available and package_import_ready

    tools = tuple(
        _build_tool_readiness(
            name,
            purpose,
            workflows,
            which=which,
            path_is_file=path_is_file,
            path_is_dir=path_is_dir,
            path_is_executable=path_is_executable,
        )
        for name, purpose, workflows in REQUIRED_EXTERNAL_TOOLS
    )
    tool_paths = {tool.name: tool.path for tool in tools}

    resources = tuple(
        _build_resource_readiness(
            name=requirement.name,
            path=requirement.path,
            workflows=requirement.workflows,
            package_root=_package_root(),
            path_exists=path_exists,
            path_is_file=path_is_file,
            path_is_symlink=path_is_symlink,
            path_is_readable=path_is_readable,
            path_size=path_size,
        )
        for requirement in REQUIRED_BUNDLED_RESOURCES
    )

    bundled_wordlist_probe = bundled_wordlist_probe or _probe_bundled_wordlist
    legacy_bundled_available, legacy_bundled_path = bundled_wordlist_probe()
    tiny_resource = next(resource for resource in resources if resource.name == "lab-root-tiny")
    bundled_available = legacy_bundled_available and tiny_resource.ready
    bundled_path = legacy_bundled_path or tiny_resource.path

    dirbuster_available = path_exists(DIRBUSTER_SMALL_WORDLIST) and path_is_file(DIRBUSTER_SMALL_WORDLIST)
    mode_entries = _build_mode_readiness(
        core_ready=core_ready,
        tools=tools,
        resources=resources,
    )
    recon_ready = all(
        mode.status == "ready" for mode in mode_entries if mode.mode != MANUAL_MODE_ID
    )
    overall_ready = core_ready and recon_ready

    warnings = tuple(_build_warnings(tools, resources, dirbuster_available))
    recommended_fixes = tuple(_build_recommended_fixes(core_ready, python_supported, project_commands_available, package_import_ready, tools, resources))
    readiness = "ready" if overall_ready else "not ready"

    return DoctorReport(
        bugslyce_version=__version__,
        python_version=platform.python_version(),
        python_supported=python_supported,
        virtual_environment=_in_virtual_environment(),
        platform_summary=platform.platform(),
        current_working_directory=str(Path.cwd()),
        tool_paths=tool_paths,
        bundled_wordlist_available=bundled_available,
        bundled_wordlist_path=bundled_path if bundled_available else None,
        dirbuster_wordlist_available=dirbuster_available,
        dirbuster_wordlist_path=str(DIRBUSTER_SMALL_WORDLIST),
        project_commands_available=project_commands_available,
        readiness=readiness,
        warnings=warnings,
        minimum_python_version=_format_version(SUPPORTED_PYTHON),
        python_executable=sys.executable,
        package_import_ready=package_import_ready,
        core_ready=core_ready,
        recon_ready=recon_ready,
        overall_ready=overall_ready,
        tools=tools,
        resources=resources,
        modes=mode_entries,
        recommended_fixes=recommended_fixes,
    )


def render_doctor_text(report: DoctorReport) -> str:
    """Render a human-readable readiness report."""

    lines = [
        "BugSlyce doctor",
        "",
        "Runtime",
        f"* Python version: {report.python_version}",
        f"* Minimum supported Python: {report.minimum_python_version}",
        f"* Python executable: {report.python_executable or 'not recorded'}",
        f"* Supported runtime: {_ready_blocked(report.python_supported)}",
        f"* Virtual environment: {_yes_no(report.virtual_environment)}",
        f"* Platform: {report.platform_summary}",
        "",
        "Application",
        f"* BugSlyce version: {report.bugslyce_version}",
        f"* Package import: {_ready_blocked(report.package_import_ready)}",
        f"* Project/CLI command surface: {_ready_blocked(report.project_commands_available)}",
        f"* Current working directory: {report.current_working_directory}",
        f"* Core readiness: {_ready_blocked(report.core_ready)}",
        "",
        "External tools",
    ]
    tools = report.tools or _legacy_tools(report)
    for tool in tools:
        path = tool.path if tool.path else "not found"
        status = "ready" if tool.ready else "blocked"
        lines.append(f"* {tool.name}: {status} ({path}) - {tool.purpose}")
        if tool.problem:
            lines.append(f"  - Problem: {tool.problem}")
        if tool.blocked_workflows:
            lines.append(f"  - Blocks: {_display_modes(tool.blocked_workflows)}")

    lines.extend(["", "Bundled resources"])
    resources = report.resources or _legacy_resources(report)
    for resource in resources:
        status = "ready" if resource.ready else "blocked"
        lines.append(f"* {resource.name}: {status} ({resource.path})")
        if resource.problem:
            lines.append(f"  - Problem: {resource.problem}")
        if resource.blocked_workflows:
            lines.append(f"  - Blocks: {_display_modes(resource.blocked_workflows)}")
    lines.append(
        "* dirbuster small: "
        + (f"found at {report.dirbuster_wordlist_path}" if report.dirbuster_wordlist_available else f"not found at {report.dirbuster_wordlist_path}")
        + " (optional legacy lab-root-light profile)"
    )

    lines.extend(["", "Mode readiness"])
    for mode in report.modes or _legacy_modes(report):
        lines.append(f"* {mode.display_name}: {mode.status}")
        for blocker in mode.blockers:
            lines.append(f"  - Blocked by: {blocker}")

    lines.extend(
        [
            "",
            "Overall result",
            f"* Core ready: {_yes_no(report.core_ready)}",
            f"* Recon ready: {_yes_no(report.recon_ready)}",
            f"* Overall ready: {_yes_no(report.overall_ready)}",
            f"* Ready for controlled lab recon: {report.readiness}",
            "",
            "Recommended fixes",
        ]
    )
    fixes = report.recommended_fixes or report.warnings
    if fixes:
        lines.extend(f"* {fix}" for fix in fixes)
    else:
        lines.append("* No fixes required for executable v1 recon modes.")

    lines.extend(
        [
            "",
            "Safety",
            "* No commands were executed.",
            "* No recon commands were executed.",
            "* No network requests were made.",
            "* Checks used local filesystem, import, and PATH inspection only.",
        ]
    )
    return "\n".join(lines)


def doctor_exit_code(report: DoctorReport) -> int:
    """Return non-zero when executable v1 recon readiness is blocked."""

    try:
        mode_failures = tuple(
            mode_readiness_failures(report, mode)
            for mode in ("quick", "standard", "deep")
        )
    except ValueError:
        return 2
    blocked = any(mode_failures)
    expected_recon_ready = not blocked
    expected_overall_ready = report.core_ready and expected_recon_ready
    if report.recon_ready != expected_recon_ready:
        return 2
    if report.overall_ready != expected_overall_ready:
        return 2
    return 2 if blocked else 0


def recon_readiness_failures(report: DoctorReport) -> tuple[str, ...]:
    """Return deterministic failures that block executable recon pipelines."""

    failures: list[str] = []
    for mode in ("quick", "standard", "deep"):
        failures.extend(mode_readiness_failures(report, mode))
    return tuple(dict.fromkeys(failures))


def mode_readiness_failures(report: DoctorReport, mode: str) -> tuple[str, ...]:
    """Return deterministic failures that block one executable recon mode."""

    if mode not in {"quick", "standard", "deep"}:
        raise ValueError(f"Unknown doctor mode readiness identifier: {mode}")
    display_name = MODE_LABELS[mode]
    failures: list[str] = []
    failures.extend(_core_readiness_failures(report, display_name))
    failures.extend(_tool_readiness_failures(report, mode, display_name))
    failures.extend(_resource_readiness_failures(report, mode, display_name))
    return tuple(failures)


def _core_readiness_failures(report: DoctorReport, display_name: str) -> tuple[str, ...]:
    component_ready = (
        report.python_supported
        and report.project_commands_available
        and report.package_import_ready
    )
    if report.core_ready and not component_ready:
        return (
            f"{display_name} is blocked: core readiness fields are internally inconsistent.",
        )
    if report.core_ready:
        return ()
    if not report.python_supported:
        return (f"{display_name} is blocked: supported Python runtime is unavailable.",)
    if not report.project_commands_available or not report.package_import_ready:
        return (
            f"{display_name} is blocked: BugSlyce project/CLI command surface is unavailable.",
        )
    return (f"{display_name} is blocked: core application readiness is not ready.",)


def _tool_readiness_failures(
    report: DoctorReport,
    mode: str,
    display_name: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    for name, _purpose, workflows in REQUIRED_EXTERNAL_TOOLS:
        if mode not in workflows:
            continue
        if report.tools:
            matches = [tool for tool in report.tools if tool.name == name]
            if not matches:
                failures.append(
                    f"{display_name} is blocked: required readiness record for pipeline tool `{name}` is missing."
                )
                continue
            if len(matches) > 1:
                failures.append(
                    f"{display_name} is blocked: duplicate readiness records exist for pipeline tool `{name}`."
                )
                continue
            tool = matches[0]
            if mode not in tool.blocked_workflows:
                failures.append(
                    f"{display_name} is blocked: readiness record for pipeline tool `{name}` does not declare `{mode}`."
                )
                continue
            if tool.ready and (not tool.found or not tool.executable):
                failures.append(
                    f"{display_name} is blocked: readiness record for `{name}` is internally inconsistent."
                )
                continue
            if not tool.ready:
                failures.append(
                    f"{display_name} is blocked: required pipeline tool `{name}` is unavailable: {tool.problem or 'not ready'}."
                )
            continue
        if not report.tool_paths.get(name):
            failures.append(
                f"{display_name} is blocked: required pipeline tool `{name}` is unavailable: not found on PATH."
            )
    return tuple(failures)


def _resource_readiness_failures(
    report: DoctorReport,
    mode: str,
    display_name: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    for requirement in REQUIRED_BUNDLED_RESOURCES:
        if mode not in requirement.workflows:
            continue
        if report.resources:
            matches = [resource for resource in report.resources if resource.name == requirement.name]
            if not matches:
                failures.append(
                    f"{display_name} is blocked: required readiness record for bundled resource `{requirement.name}` is missing."
                )
                continue
            if len(matches) > 1:
                failures.append(
                    f"{display_name} is blocked: duplicate readiness records exist for bundled resource `{requirement.name}`."
                )
                continue
            resource = matches[0]
            if mode not in resource.blocked_workflows:
                failures.append(
                    f"{display_name} is blocked: readiness record for bundled resource `{requirement.name}` does not declare `{mode}`."
                )
                continue
            if resource.ready and not (
                resource.exists
                and resource.regular_file
                and resource.readable
                and resource.non_empty
                and resource.inside_package
            ):
                failures.append(
                    f"{display_name} is blocked: readiness record for bundled resource `{requirement.name}` is internally inconsistent."
                )
                continue
            if not resource.ready:
                failures.append(
                    f"{display_name} is blocked: required bundled resource `{requirement.name}` is unavailable: {resource.problem or 'not ready'}."
                )
            continue
        if mode == "quick" and not report.bundled_wordlist_available:
            failures.append(
                f"{display_name} is blocked: required bundled resource `lab-root-tiny` is unavailable: resource file is missing."
            )
        else:
            failures.append(
                f"{display_name} is blocked: required readiness record for bundled resource `{requirement.name}` is missing."
            )
    return tuple(failures)


def _build_tool_readiness(
    name: str,
    purpose: str,
    workflows: tuple[str, ...],
    *,
    which: Callable[[str], str | None],
    path_is_file: Callable[[Path], bool],
    path_is_dir: Callable[[Path], bool],
    path_is_executable: Callable[[Path], bool],
) -> ToolReadiness:
    raw_path = which(name)
    if not raw_path:
        return ToolReadiness(name, False, None, False, False, purpose, workflows, "not found on PATH")
    path = Path(raw_path)
    if path_is_dir(path):
        return ToolReadiness(name, True, raw_path, False, False, purpose, workflows, "resolved path is a directory")
    if not path_is_file(path):
        return ToolReadiness(name, True, raw_path, False, False, purpose, workflows, "resolved path is not an executable file")
    executable = path_is_executable(path)
    return ToolReadiness(
        name,
        True,
        raw_path,
        executable,
        executable,
        purpose,
        workflows,
        None if executable else "resolved path is not executable",
    )


def _build_resource_readiness(
    *,
    name: str,
    path: Path,
    workflows: tuple[str, ...],
    package_root: Path,
    path_exists: Callable[[Path], bool],
    path_is_file: Callable[[Path], bool],
    path_is_symlink: Callable[[Path], bool],
    path_is_readable: Callable[[Path], bool],
    path_size: Callable[[Path], int],
) -> ResourceReadiness:
    resolved = path.expanduser().resolve(strict=False)
    inside_package = _is_relative_to(resolved, package_root)
    exists = path_exists(path)
    regular = exists and path_is_file(path)
    readable = regular and path_is_readable(path)
    try:
        non_empty = readable and path_size(path) > 0
    except OSError:
        non_empty = False
    symlink_escape = path_is_symlink(path) and not inside_package
    problem = None
    if not inside_package or symlink_escape:
        problem = "resource path escapes the BugSlyce package boundary"
    elif not exists:
        problem = "resource file is missing"
    elif not regular:
        problem = "resource path is not a regular file"
    elif not readable:
        problem = "resource file is not readable"
    elif not non_empty:
        problem = "resource file is empty"
    ready = problem is None
    return ResourceReadiness(
        name=name,
        path=str(path),
        exists=exists,
        regular_file=regular,
        readable=readable,
        non_empty=non_empty,
        inside_package=inside_package and not symlink_escape,
        ready=ready,
        blocked_workflows=workflows,
        problem=problem,
    )


def _build_mode_readiness(
    *,
    core_ready: bool,
    tools: tuple[ToolReadiness, ...],
    resources: tuple[ResourceReadiness, ...],
) -> tuple[ModeReadiness, ...]:
    modes: list[ModeReadiness] = []
    core_blockers = () if core_ready else ("core application readiness",)
    modes.append(
        ModeReadiness(
            mode=MANUAL_MODE_ID,
            display_name=MODE_LABELS[MANUAL_MODE_ID],
            status="ready" if core_ready else "blocked",
            blockers=core_blockers,
        )
    )
    for mode in ("quick", "standard", "deep"):
        blockers = list(core_blockers)
        blockers.extend(f"tool:{tool.name}" for tool in tools if mode in tool.blocked_workflows and not tool.ready)
        blockers.extend(f"resource:{resource.name}" for resource in resources if mode in resource.blocked_workflows and not resource.ready)
        modes.append(
            ModeReadiness(
                mode=mode,
                display_name=MODE_LABELS[mode],
                status="blocked" if blockers else "ready",
                blockers=tuple(blockers),
            )
        )
    return tuple(modes)


def _build_warnings(
    tools: tuple[ToolReadiness, ...],
    resources: tuple[ResourceReadiness, ...],
    dirbuster_available: bool,
) -> list[str]:
    warnings = [
        f"Required tool `{tool.name}` is unavailable: {tool.problem}." for tool in tools if not tool.ready
    ]
    warnings.extend(
        f"Required bundled resource `{resource.name}` is unavailable: {resource.problem}." for resource in resources if not resource.ready
    )
    if not dirbuster_available:
        warnings.append("The optional legacy lab-root-light profile is unavailable without the dirbuster small wordlist.")
    return warnings


def _build_recommended_fixes(
    core_ready: bool,
    python_supported: bool,
    project_commands_available: bool,
    package_import_ready: bool,
    tools: tuple[ToolReadiness, ...],
    resources: tuple[ResourceReadiness, ...],
) -> list[str]:
    fixes: list[str] = []
    if not python_supported:
        fixes.append(f"Install or run BugSlyce with Python {_format_version(SUPPORTED_PYTHON)} or newer, then run `bugslyce doctor` again.")
    if not package_import_ready or not project_commands_available:
        fixes.append("Reinstall the BugSlyce package in this Python environment, then run `bugslyce doctor` again.")
    for tool in tools:
        if not tool.ready:
            fixes.append(f"Install `{tool.name}` or place an executable `{tool.name}` on PATH; blocked workflows: {_display_modes(tool.blocked_workflows)}.")
    for resource in resources:
        if not resource.ready:
            fixes.append(f"Restore bundled resource `{resource.name}` at `{resource.path}` from the BugSlyce installation package.")
    return fixes


def _probe_bundled_wordlist() -> tuple[bool, str | None]:
    try:
        wordlist = importlib.resources.files("bugslyce").joinpath(
            "wordlists", "lab-root-tiny.txt"
        )
        return wordlist.is_file(), str(wordlist)
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        return False, None


def _package_root() -> Path:
    return Path(__file__).resolve().parent


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _legacy_tools(report: DoctorReport) -> tuple[ToolReadiness, ...]:
    return tuple(
        ToolReadiness(
            name=tool,
            found=bool(path),
            path=path,
            executable=bool(path),
            ready=bool(path),
            purpose=purpose,
            blocked_workflows=workflows,
            problem=None if path else "not found on PATH",
        )
        for tool, purpose, workflows in REQUIRED_EXTERNAL_TOOLS
        for path in (report.tool_paths.get(tool),)
    )


def _legacy_resources(report: DoctorReport) -> tuple[ResourceReadiness, ...]:
    return (
        ResourceReadiness(
            name="lab-root-tiny",
            path=report.bundled_wordlist_path or "not resolved",
            exists=report.bundled_wordlist_available,
            regular_file=report.bundled_wordlist_available,
            readable=report.bundled_wordlist_available,
            non_empty=report.bundled_wordlist_available,
            inside_package=report.bundled_wordlist_available,
            ready=report.bundled_wordlist_available,
            blocked_workflows=("quick",),
            problem=None if report.bundled_wordlist_available else "resource file is missing",
        ),
    )


def _legacy_modes(report: DoctorReport) -> tuple[ModeReadiness, ...]:
    core_ready = report.python_supported and report.project_commands_available
    recon_ready = core_ready and report.bundled_wordlist_available and all(report.tool_paths.get(tool) for tool in ("nmap", "curl", "gobuster"))
    return (
        ModeReadiness(MANUAL_MODE_ID, MODE_LABELS[MANUAL_MODE_ID], "ready" if core_ready else "blocked"),
        ModeReadiness("quick", MODE_LABELS["quick"], "ready" if recon_ready else "blocked"),
        ModeReadiness("standard", MODE_LABELS["standard"], "ready" if recon_ready else "blocked"),
        ModeReadiness("deep", MODE_LABELS["deep"], "ready" if recon_ready else "blocked"),
    )


def _in_virtual_environment() -> bool:
    return sys.prefix != sys.base_prefix or hasattr(sys, "real_prefix")


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _ready_blocked(value: bool) -> str:
    return "ready" if value else "blocked"


def _format_version(version: tuple[int, int] | tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version[:2])


def _display_modes(modes: tuple[str, ...]) -> str:
    return ", ".join(MODE_LABELS.get(mode, mode) for mode in modes)
