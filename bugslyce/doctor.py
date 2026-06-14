"""Read-only local readiness checks for BugSlyce."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.resources
from pathlib import Path
import platform
import shutil
import sys
from typing import Callable

from bugslyce import __version__
from bugslyce.project_session import initialize_project, inspect_project_status


DIRBUSTER_SMALL_WORDLIST = Path(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
)
SUPPORTED_PYTHON = (3, 11)


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


def build_doctor_report(
    *,
    which: Callable[[str], str | None] | None = None,
    path_exists: Callable[[Path], bool] | None = None,
    bundled_wordlist_probe: Callable[[], tuple[bool, str | None]] | None = None,
) -> DoctorReport:
    """Inspect local Python, tools, and package resources without execution."""

    which = which or shutil.which
    path_exists = path_exists or Path.exists
    bundled_wordlist_probe = bundled_wordlist_probe or _probe_bundled_wordlist

    python_supported = sys.version_info >= SUPPORTED_PYTHON
    bundled_available, bundled_path = bundled_wordlist_probe()
    project_commands_available = callable(initialize_project) and callable(
        inspect_project_status
    )
    tool_paths = {tool: which(tool) for tool in ("nmap", "curl", "gobuster")}
    dirbuster_available = path_exists(DIRBUSTER_SMALL_WORDLIST)

    warnings: list[str] = []
    missing_tools = [tool for tool, path in tool_paths.items() if path is None]
    if missing_tools:
        warnings.append(
            "Recommended live recon tools not found: " + ", ".join(missing_tools) + "."
        )
    if tool_paths["gobuster"] is None:
        warnings.append(
            "Content discovery execution is unavailable until gobuster is installed."
        )
    if not dirbuster_available:
        warnings.append(
            "The optional lab-root-light profile is unavailable without the "
            "dirbuster small wordlist."
        )

    required_checks_pass = (
        python_supported and bundled_available and project_commands_available
    )
    if not required_checks_pass:
        readiness = "not ready"
    elif warnings:
        readiness = "ready with warnings"
    else:
        readiness = "ready"

    return DoctorReport(
        bugslyce_version=__version__,
        python_version=platform.python_version(),
        python_supported=python_supported,
        virtual_environment=_in_virtual_environment(),
        platform_summary=platform.platform(),
        current_working_directory=str(Path.cwd()),
        tool_paths=tool_paths,
        bundled_wordlist_available=bundled_available,
        bundled_wordlist_path=bundled_path,
        dirbuster_wordlist_available=dirbuster_available,
        dirbuster_wordlist_path=str(DIRBUSTER_SMALL_WORDLIST),
        project_commands_available=project_commands_available,
        readiness=readiness,
        warnings=tuple(warnings),
    )


def render_doctor_text(report: DoctorReport) -> str:
    """Render a human-readable readiness report."""

    lines = [
        "BugSlyce doctor",
        "",
        "Environment:",
        f"* BugSlyce version: {report.bugslyce_version}",
        f"* Python: {report.python_version}",
        f"* Supported Python: {_yes_no(report.python_supported)}",
        f"* Virtual environment: {_yes_no(report.virtual_environment)}",
        f"* Platform: {report.platform_summary}",
        f"* Current working directory: {report.current_working_directory}",
        f"* Project commands: {'available' if report.project_commands_available else 'unavailable'}",
        "",
        "Local tools:",
    ]
    for tool in ("nmap", "curl", "gobuster"):
        path = report.tool_paths[tool]
        lines.append(f"* {tool}: {'found at ' + path if path else 'not found'}")

    lines.extend(
        [
            "",
            "Wordlists:",
            "* bundled lab-root-tiny: "
            + (
                f"found at {report.bundled_wordlist_path}"
                if report.bundled_wordlist_available
                else "missing"
            ),
            "* dirbuster small: "
            + (
                f"found at {report.dirbuster_wordlist_path}"
                if report.dirbuster_wordlist_available
                else f"not found at {report.dirbuster_wordlist_path}"
            ),
            "",
            "Overall:",
            f"* Ready for controlled lab recon: {report.readiness}",
        ]
    )

    if report.warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"* {warning}" for warning in report.warnings)

    lines.extend(
        [
            "",
            "Safety:",
            "* No commands were executed.",
            "* No network requests were made.",
            "* Checks used local filesystem, import, and PATH inspection only.",
        ]
    )
    return "\n".join(lines)


def doctor_exit_code(report: DoctorReport) -> int:
    """Return non-zero only when a required local check fails."""

    return 2 if report.readiness == "not ready" else 0


def _probe_bundled_wordlist() -> tuple[bool, str | None]:
    try:
        wordlist = importlib.resources.files("bugslyce").joinpath(
            "wordlists", "lab-root-tiny.txt"
        )
        return wordlist.is_file(), str(wordlist)
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        return False, None


def _in_virtual_environment() -> bool:
    return sys.prefix != sys.base_prefix or hasattr(sys, "real_prefix")


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
