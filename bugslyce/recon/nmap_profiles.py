"""Approved nmap command models and non-executing plan output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import ipaddress
import json
from pathlib import Path
import shlex

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult
from bugslyce.core.scope import parse_scope, scope_entry_target


@dataclass(frozen=True)
class NmapCommandProfile:
    """Metadata for one approved future nmap command shape."""

    name: str
    description: str
    risk_level: str
    requires_confirmation: bool
    allowed_flags: list[str]
    forbidden_flags: list[str]
    default_timeout_seconds: int
    expected_output_file: str
    planned_artifact_type: str


COMMON_FORBIDDEN_FLAGS = [
    "-A",
    "-O",
    "--script",
    "--script=*",
    "-sU",
    "-T5",
    "--decoy",
    "-D",
    "-S",
]
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")

NMAP_PROFILES = {
    "lab-tcp-top": NmapCommandProfile(
        name="lab-tcp-top",
        description="Conservative TCP discovery across nmap's top 1000 ports for one authorised lab target.",
        risk_level="moderate",
        requires_confirmation=True,
        allowed_flags=["-sS", "-Pn", "--top-ports", "-oN"],
        forbidden_flags=COMMON_FORBIDDEN_FLAGS,
        default_timeout_seconds=900,
        expected_output_file="nmap-top1000.txt",
        planned_artifact_type="nmap",
    ),
    "lab-tcp-full": NmapCommandProfile(
        name="lab-tcp-full",
        description="Full TCP discovery for one authorised lab target using a fixed planned rate.",
        risk_level="moderate",
        requires_confirmation=True,
        allowed_flags=["-sS", "-Pn", "-p-", "--min-rate", "-oN"],
        forbidden_flags=COMMON_FORBIDDEN_FLAGS,
        default_timeout_seconds=1800,
        expected_output_file="nmap-allports.txt",
        planned_artifact_type="nmap",
    ),
    "lab-service-scan": NmapCommandProfile(
        name="lab-service-scan",
        description="Service and version detection for an explicit set of previously discovered TCP ports.",
        risk_level="moderate",
        requires_confirmation=True,
        allowed_flags=["-sV", "-Pn", "-p", "-oN"],
        forbidden_flags=[*COMMON_FORBIDDEN_FLAGS, "-sC"],
        default_timeout_seconds=1200,
        expected_output_file="nmap-services-all.txt",
        planned_artifact_type="nmap",
    ),
}


def nmap_profile_names() -> tuple[str, ...]:
    """Return supported non-executing nmap profile names."""

    return tuple(NMAP_PROFILES)


def get_nmap_profile(name: str) -> NmapCommandProfile:
    """Return one approved nmap profile."""

    try:
        return NMAP_PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported nmap profile '{name}'. Supported profiles: {', '.join(nmap_profile_names())}."
        ) from exc


def build_nmap_top_ports_command(target: str, output_dir: Path) -> ReconCommand:
    """Build the approved top-1000 TCP discovery command model."""

    return _build_command(
        profile_name="lab-tcp-top",
        target=target,
        output_dir=output_dir,
        argv_before_output=["nmap", "-sS", "-Pn", "--top-ports", "1000"],
    )


def build_live_nmap_top_ports_command(target: str, output_dir: Path) -> ReconCommand:
    """Build the top-1000 nmap command permitted for live execution."""

    return replace(
        build_nmap_top_ports_command(target, output_dir),
        id="CMD-NMAP-DISCOVER-0001",
        ready_for_execution=True,
    )


def build_nmap_full_tcp_command(target: str, output_dir: Path) -> ReconCommand:
    """Build the approved full TCP discovery command model."""

    return _build_command(
        profile_name="lab-tcp-full",
        target=target,
        output_dir=output_dir,
        argv_before_output=["nmap", "-sS", "-Pn", "-p-", "--min-rate", "5000"],
    )


def build_live_nmap_full_tcp_command(target: str, output_dir: Path) -> ReconCommand:
    """Build the full TCP nmap command permitted for live execution."""

    return replace(
        build_nmap_full_tcp_command(target, output_dir),
        id="CMD-NMAP-DISCOVER-0001",
        ready_for_execution=True,
    )


def build_nmap_service_scan_command(
    target: str,
    ports: str | list[int] | list[str],
    output_dir: Path,
) -> ReconCommand:
    """Build service/version detection for validated explicit TCP ports."""

    port_value = normalise_nmap_ports(ports)
    return _build_command(
        profile_name="lab-service-scan",
        target=target,
        output_dir=output_dir,
        argv_before_output=["nmap", "-sV", "-Pn", "-p", port_value],
    )


def normalise_nmap_ports(ports: str | list[int] | list[str]) -> str:
    """Validate and normalize an explicit comma-separated TCP port set."""

    values = ports.split(",") if isinstance(ports, str) else list(ports)
    if not values:
        raise ValueError("At least one TCP port is required for lab-service-scan.")

    normalized: list[str] = []
    for raw_value in values:
        value = str(raw_value).strip()
        if not value.isdigit():
            raise ValueError(f"Invalid TCP port '{value}'; ports must be numeric.")
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port '{value}'; expected a value from 1 to 65535.")
        text = str(port)
        if text not in normalized:
            normalized.append(text)
    return ",".join(normalized)


def validate_nmap_command(
    command: ReconCommand,
    planned_output_dir: Path,
) -> ReconCommandValidationResult:
    """Validate that an nmap command exactly matches one approved profile."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        errors.append("argv must be a list of strings.")
        argv: list[str] = []
    else:
        argv = command.argv
    profile = _profile_for_argv(argv)

    if command.tool != "nmap":
        errors.append("Nmap validation requires tool 'nmap'.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Nmap argv contains forbidden shell metacharacter token '{matched}'.")
    if any(
        value == forbidden or value.startswith(f"{forbidden}=")
        for value in argv
        for forbidden in ("-A", "-O", "--script", "-sC", "-sU", "-T5", "--decoy", "-D", "-S")
    ):
        errors.append("Nmap argv contains an explicitly forbidden flag.")
    if profile is None:
        errors.append("Nmap argv does not match an approved command profile.")
    if command.placeholders:
        errors.append("Nmap command contains unresolved placeholders.")
    if command.ready_for_execution:
        errors.append("Nmap execution is not implemented; command must remain planning-only.")
    if not command.requires_confirmation:
        errors.append("Future nmap commands must require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Future nmap commands must be scope sensitive.")
    if not _output_is_inside(command.output_file, planned_output_dir):
        errors.append("output_file must stay inside the planned output directory.")

    if profile is not None:
        if command.timeout_seconds != profile.default_timeout_seconds:
            errors.append(
                f"Nmap profile '{profile.name}' requires timeout_seconds={profile.default_timeout_seconds}."
            )
        output_index = argv.index("-oN") + 1
        if argv[output_index] != command.output_file:
            errors.append("Nmap -oN path must match command output_file.")
        try:
            expected_output = Path(planned_output_dir).expanduser().resolve() / profile.expected_output_file
            if Path(command.output_file).expanduser().resolve() != expected_output:
                errors.append(
                    f"Nmap profile '{profile.name}' must write {profile.expected_output_file}."
                )
        except OSError:
            errors.append("Nmap output path could not be resolved.")
        target = argv[-1]
        if not _valid_single_target(target):
            errors.append("Nmap command must contain one valid hostname or IP target.")
        if profile.name == "lab-service-scan":
            try:
                normalise_nmap_ports(argv[argv.index("-p") + 1])
            except ValueError as exc:
                errors.append(str(exc))

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=["Nmap command is validated for planning only; execution is not implemented."]
        if not errors
        else [],
    )


def validate_live_nmap_top_ports_command(
    command: ReconCommand,
    planned_output_dir: Path,
) -> ReconCommandValidationResult:
    """Validate the exact lab-tcp-top shape permitted for live execution."""

    return _validate_live_nmap_discovery_command(
        command,
        planned_output_dir,
        allowed_profiles=("lab-tcp-top",),
    )


def validate_live_nmap_discovery_command(
    command: ReconCommand,
    planned_output_dir: Path,
) -> ReconCommandValidationResult:
    """Validate either approved live nmap discovery command shape."""

    return _validate_live_nmap_discovery_command(
        command,
        planned_output_dir,
        allowed_profiles=("lab-tcp-top", "lab-tcp-full"),
    )


def _validate_live_nmap_discovery_command(
    command: ReconCommand,
    planned_output_dir: Path,
    allowed_profiles: tuple[str, ...],
) -> ReconCommandValidationResult:
    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    profile = _profile_for_argv(argv)
    if profile is not None and profile.name not in allowed_profiles:
        profile = None

    if command.tool != "nmap":
        errors.append("Live nmap execution is restricted to the nmap tool.")
    if profile is None:
        labels = " or ".join(allowed_profiles)
        errors.append(f"Live nmap command must match the approved {labels} argv shape.")
    else:
        output_index = argv.index("-oN") + 1
        expected_output = (
            planned_output_dir.expanduser().resolve() / profile.expected_output_file
        )
        if argv[output_index] != command.output_file:
            errors.append("Nmap -oN path must match command output_file.")
        if Path(argv[output_index]).expanduser().resolve() != expected_output:
            errors.append(
                f"Live nmap output must be {profile.expected_output_file} "
                "inside the selected output directory."
            )
        if not _valid_single_target(argv[-1]):
            errors.append("Live nmap command must contain one valid hostname or IP target.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Nmap argv contains forbidden shell metacharacter token '{matched}'.")
    if command.output_file and not _output_is_inside(command.output_file, planned_output_dir):
        errors.append("output_file must stay inside the planned output directory.")
    if profile is not None and command.timeout_seconds != profile.default_timeout_seconds:
        errors.append(
            f"Live {profile.name} requires timeout_seconds={profile.default_timeout_seconds}."
        )
    if not command.ready_for_execution:
        errors.append("Live nmap command must be explicitly marked ready for execution.")
    if command.placeholders:
        errors.append("Live nmap command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("Live nmap commands require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Live nmap commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def build_nmap_command_plan(
    target: str,
    scope_file: Path,
    profile_name: str,
    output_dir: Path,
    ports: str | None = None,
) -> tuple[NmapCommandProfile, ReconCommand]:
    """Build one scoped, non-executing nmap command plan."""

    target = _normalise_target(target)
    if not scope_file.exists() or not scope_file.is_file():
        raise ValueError(f"Scope file does not exist or is not a file: {scope_file}")
    parsed_scope = parse_scope(scope_file)
    if not any(_scope_target_matches(target, value) for value in parsed_scope.in_scope):
        raise ValueError(f"Target '{target}' is not present in the supplied in-scope target entries.")

    profile = get_nmap_profile(profile_name)
    if profile.name == "lab-tcp-top":
        if ports:
            raise ValueError("--ports is only supported with lab-service-scan.")
        command = build_nmap_top_ports_command(target, output_dir)
    elif profile.name == "lab-tcp-full":
        if ports:
            raise ValueError("--ports is only supported with lab-service-scan.")
        command = build_nmap_full_tcp_command(target, output_dir)
    else:
        if not ports:
            raise ValueError("--ports is required with lab-service-scan.")
        command = build_nmap_service_scan_command(target, ports, output_dir)
    return profile, command


def validate_explicit_nmap_target_scope(target: str, scope_file: Path) -> str:
    """Validate one live target against an explicit target-like in-scope entry."""

    target = _normalise_target(target)
    if not scope_file.exists() or not scope_file.is_file():
        raise ValueError(f"Scope file does not exist or is not a file: {scope_file}")
    parsed_scope = parse_scope(scope_file)
    for value in parsed_scope.in_scope:
        stripped = value.strip().strip("`").strip()
        if stripped.startswith("*.") or "/" in stripped:
            continue
        if scope_entry_target(value) == target:
            return target
    raise ValueError(f"Target '{target}' is not explicitly listed in the supplied in-scope target entries.")


def write_nmap_command_plan(
    profile: NmapCommandProfile,
    command: ReconCommand,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown for a planning-only nmap command."""

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "nmap_command_plan.json"
    markdown_path = output_dir / "nmap_command_plan.md"
    payload = {
        "profile": asdict(profile),
        "command": asdict(command),
        "no_commands_executed": True,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_nmap_command_plan(profile, command), encoding="utf-8")
    return json_path, markdown_path


def render_nmap_command_plan(profile: NmapCommandProfile, command: ReconCommand) -> str:
    """Render one readable, explicitly non-executing nmap plan."""

    return "\n".join(
        [
            "# BugSlyce Nmap Command Plan",
            "",
            f"- Target: `{command.argv[-1]}`",
            f"- Profile: `{profile.name}`",
            f"- Description: {profile.description}",
            f"- Risk level: `{profile.risk_level}`",
            f"- Requires confirmation: `{str(profile.requires_confirmation).lower()}`",
            f"- Planned command: `{shlex.join(command.argv)}`",
            f"- Expected output: `{command.output_file}`",
            "",
            "This command is a structured planning model and is not enabled for execution.",
            "",
            "No commands were executed.",
            "",
        ]
    )


def render_nmap_command_plan_summary(
    profile: NmapCommandProfile,
    command: ReconCommand,
    output_dir: Path,
    json_path: Path,
    markdown_path: Path,
) -> str:
    """Render CLI output for a completed nmap planning operation."""

    return "\n".join(
        [
            "BugSlyce nmap command plan created",
            f"Target: {command.argv[-1]}",
            f"Profile: {profile.name}",
            f"Output directory: {output_dir}",
            f"Planned command: {shlex.join(command.argv)}",
            f"JSON path: {json_path}",
            f"Markdown path: {markdown_path}",
            "No commands were executed.",
        ]
    )


def _build_command(
    profile_name: str,
    target: str,
    output_dir: Path,
    argv_before_output: list[str],
) -> ReconCommand:
    profile = get_nmap_profile(profile_name)
    target = _normalise_target(target)
    output_dir = output_dir.expanduser().resolve()
    output_file = output_dir / profile.expected_output_file
    return ReconCommand(
        id=f"CMD-NMAP-{profile.name.upper().replace('-', '_')}",
        tool="nmap",
        argv=[*argv_before_output, "-oN", str(output_file), target],
        output_file=str(output_file),
        timeout_seconds=profile.default_timeout_seconds,
        phase="service-discovery" if profile.name != "lab-service-scan" else "service-enumeration",
        risk_level=profile.risk_level,
        requires_confirmation=True,
        scope_sensitive=True,
        description=profile.description,
        ready_for_execution=False,
        placeholders=[],
    )


def _profile_for_argv(argv: list[str]) -> NmapCommandProfile | None:
    if len(argv) == 8 and argv[:5] == ["nmap", "-sS", "-Pn", "--top-ports", "1000"] and argv[5] == "-oN":
        return NMAP_PROFILES["lab-tcp-top"]
    if (
        len(argv) == 9
        and argv[:6] == ["nmap", "-sS", "-Pn", "-p-", "--min-rate", "5000"]
        and argv[6] == "-oN"
    ):
        return NMAP_PROFILES["lab-tcp-full"]
    if len(argv) == 8 and argv[:4] == ["nmap", "-sV", "-Pn", "-p"] and argv[5] == "-oN":
        return NMAP_PROFILES["lab-service-scan"]
    return None


def _normalise_target(target: str) -> str:
    target = target.strip()
    if not _valid_single_target(target):
        raise ValueError("Target must be one hostname or IP address, without a URL, CIDR, or extra arguments.")
    return target.lower()


def _valid_single_target(target: str) -> bool:
    if not target or any(character.isspace() for character in target) or "/" in target:
        return False
    normalized = scope_entry_target(target)
    return normalized == target.lower().rstrip(".")


def _scope_target_matches(target: str, scope_value: str) -> bool:
    scope_target = scope_entry_target(scope_value)
    if not scope_target:
        return False
    try:
        return ipaddress.ip_address(target) in ipaddress.ip_network(scope_target, strict=False)
    except ValueError:
        return target == scope_target or target.endswith(f".{scope_target}")


def _output_is_inside(output_file: str, output_dir: Path) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False
    return output != root
