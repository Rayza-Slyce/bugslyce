"""Build and validate structured future recon commands without execution."""

from __future__ import annotations

from pathlib import Path
import re

from bugslyce.core.models import (
    ReconCommand,
    ReconCommandValidationResult,
    ReconPlan,
    ReconPlanStep,
)


ALLOWED_TOOLS = {"nmap", "curl", "gobuster"}
FORBIDDEN_TOKENS = {
    "hydra",
    "medusa",
    "sqlmap",
    "nuclei",
    "masscan",
    "wfuzz",
    "nikto",
    "brute",
    "password",
    "exploit",
    "payload",
}
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")
MAX_TIMEOUT_SECONDS = 3600
PLACEHOLDER_PATTERN = re.compile(r"\{[^{}]+\}")


def build_recon_commands(plan: ReconPlan) -> tuple[list[ReconCommand], list[str]]:
    """Convert known active-plan steps into structured argv templates."""

    commands: list[ReconCommand] = []
    warnings: list[str] = []
    output_dir = Path(plan.output_dir)
    for step in plan.steps:
        command = _command_for_step(step, plan.target, output_dir)
        if command is not None:
            commands.append(command)
        elif step.command_preview:
            warnings.append(
                f"Step {step.id} ({step.name}) has a preview but no structured command builder."
            )
    return commands, warnings


def validate_recon_command(
    command: ReconCommand,
    planned_output_dir: Path,
) -> ReconCommandValidationResult:
    """Validate one command against local structural safety guardrails."""

    errors: list[str] = []
    warnings: list[str] = []
    tool = command.tool.strip().lower() if isinstance(command.tool, str) else ""
    argv = command.argv

    if tool not in ALLOWED_TOOLS:
        errors.append(f"Tool '{command.tool}' is not allowlisted.")
    if not isinstance(argv, list) or any(not isinstance(value, str) for value in argv):
        errors.append("argv must be a list of strings.")
        argv_values: list[str] = []
    else:
        argv_values = argv
        if not argv_values:
            errors.append("argv must not be empty.")
        elif argv_values[0] != tool:
            errors.append("argv[0] must match the command tool.")

    for value in argv_values:
        lower_value = value.casefold()
        matched_meta = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched_meta:
            errors.append(f"argv contains forbidden shell metacharacter token '{matched_meta}'.")
        matched_forbidden = next((token for token in FORBIDDEN_TOKENS if token in lower_value), None)
        if matched_forbidden:
            errors.append(f"argv contains forbidden token '{matched_forbidden}'.")

    if not command.ready_for_execution or command.placeholders:
        errors.append("Command contains unresolved placeholders and is not ready for execution.")
    if not isinstance(command.timeout_seconds, int) or isinstance(command.timeout_seconds, bool):
        errors.append("timeout_seconds must be an integer.")
    elif not 1 <= command.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        errors.append(
            f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}."
        )

    if not _output_is_inside(command.output_file, planned_output_dir):
        errors.append("output_file must stay inside the planned output directory.")

    if command.risk_level not in {"low", "moderate", "high"}:
        warnings.append(f"Unrecognised risk level '{command.risk_level}'.")
    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=_dedupe(errors),
        warnings=_dedupe(warnings),
    )


def _command_for_step(
    step: ReconPlanStep,
    target: str,
    output_dir: Path,
) -> ReconCommand | None:
    builders = {
        "Full TCP port discovery": _nmap_all_ports,
        "Controlled port discovery": _nmap_controlled_ports,
        "Service and version discovery": _nmap_services,
        "HTTP probing and response header checks": _curl_headers,
        "Robots and sitemap checks": _curl_robots,
        "Root content discovery": _gobuster_root,
        "Conservative content discovery": _gobuster_root,
        "Limited recursive content discovery": _gobuster_recursive,
        "Saved HTML metadata collection": _curl_html,
    }
    builder = builders.get(step.name)
    return builder(step, target, output_dir) if builder else None


def _nmap_all_ports(step: ReconPlanStep, target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "nmap-allports.txt"
    return _command(
        step,
        "nmap",
        ["nmap", "-p-", "--min-rate", "{bounded-rate}", "-oN", str(output), target],
        output,
        ["bounded-rate"],
    )


def _nmap_controlled_ports(step: ReconPlanStep, target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "nmap-allports.txt"
    return _command(
        step,
        "nmap",
        ["nmap", "--top-ports", "{approved-count}", "-oN", str(output), target],
        output,
        ["approved-count"],
    )


def _nmap_services(step: ReconPlanStep, target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "nmap-services-all.txt"
    return _command(
        step,
        "nmap",
        ["nmap", "-sV", "-p", "{discovered-ports}", "-oN", str(output), target],
        output,
        ["discovered-ports"],
    )


def _curl_headers(step: ReconPlanStep, _target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "curl-headers-{http-port}.txt"
    return _command(
        step,
        "curl",
        [
            "curl",
            "-I",
            "--max-time",
            "{timeout}",
            "{discovered-http-url}",
            "--output",
            str(output),
        ],
        output,
        ["timeout", "discovered-http-url", "http-port"],
    )


def _curl_robots(step: ReconPlanStep, _target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "robots-{http-port}.txt"
    return _command(
        step,
        "curl",
        [
            "curl",
            "--max-time",
            "{timeout}",
            "{http-origin}/robots.txt",
            "--output",
            str(output),
        ],
        output,
        ["timeout", "http-origin", "http-port"],
    )


def _gobuster_root(step: ReconPlanStep, _target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "gobuster-{http-port}-root.txt"
    return _command(
        step,
        "gobuster",
        [
            "gobuster",
            "dir",
            "-u",
            "{http-origin}/",
            "-w",
            "{approved-wordlist}",
            "-o",
            str(output),
        ],
        output,
        ["http-origin", "approved-wordlist", "http-port"],
    )


def _gobuster_recursive(step: ReconPlanStep, _target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "gobuster-{http-port}-{path}.txt"
    return _command(
        step,
        "gobuster",
        [
            "gobuster",
            "dir",
            "-u",
            "{approved-discovered-url}",
            "-w",
            "{approved-wordlist}",
            "-o",
            str(output),
        ],
        output,
        ["approved-discovered-url", "approved-wordlist", "http-port", "path"],
    )


def _curl_html(step: ReconPlanStep, _target: str, output_dir: Path) -> ReconCommand:
    output = output_dir / "homepage-{http-port}.html"
    return _command(
        step,
        "curl",
        [
            "curl",
            "--max-time",
            "{timeout}",
            "{selected-http-url}",
            "--output",
            str(output),
        ],
        output,
        ["timeout", "selected-http-url", "http-port"],
    )


def _command(
    step: ReconPlanStep,
    tool: str,
    argv: list[str],
    output_file: Path,
    placeholders: list[str],
) -> ReconCommand:
    detected = sorted(
        {
            match.group(0)[1:-1]
            for value in argv
            for match in PLACEHOLDER_PATTERN.finditer(value)
        }
    )
    placeholders = sorted(set(placeholders) | set(detected))
    return ReconCommand(
        id=f"CMD-{step.id.removeprefix('STEP-')}",
        tool=tool,
        argv=argv,
        output_file=str(output_file),
        timeout_seconds=300,
        phase=step.phase,
        risk_level=step.risk_level,
        requires_confirmation=step.requires_confirmation,
        scope_sensitive=step.scope_sensitive,
        description=step.description,
        ready_for_execution=not placeholders,
        placeholders=placeholders,
    )


def _output_is_inside(output_file: str, output_dir: Path) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False
    return output != root


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
