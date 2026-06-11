"""Build and validate the one approved live root content discovery shape."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import (
    ContentDiscoveryPlan,
    ContentDiscoveryStep,
    ReconCommand,
    ReconCommandValidationResult,
)
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_PROFILE,
    SHELL_METACHARACTERS,
    get_content_discovery_profile,
)


CONTENT_DISCOVERY_TIMEOUT_SECONDS = 900


def build_live_content_discovery_command(
    step: ContentDiscoveryStep,
    plan: ContentDiscoveryPlan,
) -> ReconCommand:
    """Convert one fully validated plan step into an executable command model."""

    profile = get_content_discovery_profile(plan.profile)
    output_file = Path(plan.output_dir).resolve() / step.expected_artifact.file
    command = ReconCommand(
        id=step.step_id,
        tool="gobuster",
        argv=list(step.command_preview),
        output_file=str(output_file),
        timeout_seconds=profile.timeout_seconds,
        phase="content-discovery-root",
        risk_level=step.risk_level,
        requires_confirmation=step.requires_confirmation,
        scope_sensitive=step.scope_sensitive,
        description="Approved bounded root content discovery from a BugSlyce plan.",
        ready_for_execution=True,
        placeholders=[],
    )
    validation = validate_live_content_discovery_command(
        command,
        Path(plan.output_dir),
        plan.target,
        {item.origin for item in plan.steps},
        plan.profile,
    )
    if not validation.valid:
        raise ValueError("; ".join(validation.errors))
    return command


def validate_live_content_discovery_command(
    command: ReconCommand,
    output_dir: Path,
    target: str,
    allowed_origins: set[str],
    profile_name: str = CONTENT_DISCOVERY_PROFILE,
) -> ReconCommandValidationResult:
    """Validate one exact gobuster root-discovery argv list."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    if command.tool != "gobuster":
        errors.append("Content discovery execution is restricted to gobuster.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(
                f"Gobuster argv contains forbidden shell metacharacter token '{matched}'."
            )

    try:
        profile = get_content_discovery_profile(profile_name)
    except ValueError as exc:
        profile = None
        errors.append(str(exc))

    if len(argv) != 10 or profile is None:
        errors.append("Gobuster command must match the approved content profile argv shape.")
    else:
        origin = argv[3]
        output_file = argv[9]
        expected = [
            "gobuster",
            "dir",
            "-u",
            origin,
            "-w",
            str(profile.wordlist),
            "-t",
            str(profile.threads),
            "-o",
            output_file,
        ]
        if argv != expected:
            errors.append("Gobuster command must match the approved content profile argv shape.")
        parsed = urlparse(origin)
        normalized_origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname != target
            or origin != normalized_origin
        ):
            errors.append("Gobuster URL must be a discovered root origin for the target.")
        if origin not in allowed_origins:
            errors.append("Gobuster URL must be present in the approved content plan.")
        if output_file != command.output_file:
            errors.append("Gobuster -o path must match command output_file.")
        if not _output_is_inside(command.output_file, output_dir):
            errors.append("output_file must stay inside the planned output directory.")
        if Path(output_file).name != _expected_filename(origin, profile.output_prefix):
            errors.append(
                "Gobuster output must use deterministic filename "
                f"{_expected_filename(origin, profile.output_prefix)}."
            )

    expected_timeout = profile.timeout_seconds if profile is not None else None
    if expected_timeout is not None and command.timeout_seconds != expected_timeout:
        errors.append(
            f"Content discovery profile '{profile_name}' requires "
            f"timeout_seconds={expected_timeout}."
        )
    if not command.ready_for_execution:
        errors.append("Live content discovery command must be marked ready for execution.")
    if command.placeholders:
        errors.append("Live content discovery command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("Live content discovery requires explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Live content discovery commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def _expected_filename(origin: str, output_prefix: str) -> str:
    parsed = urlparse(origin)
    safe_host = "".join(
        character if character.isalnum() or character in ".-" else "-"
        for character in (parsed.hostname or "host").lower()
    ).strip(".-") or "host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{output_prefix}-{safe_host}-{port}-root.txt"


def _output_is_inside(output_file: str, output_dir: Path) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False
    return output != root
