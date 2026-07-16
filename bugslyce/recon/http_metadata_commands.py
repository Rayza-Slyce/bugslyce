"""Build and validate fixed curl commands for discovered HTTP metadata."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urljoin, urlparse, urlunparse

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult
from bugslyce.recon.argv_safety import argv_control_character_errors


HTTP_METADATA_TIMEOUT_SECONDS = 10
MAX_HTTP_METADATA_SERVICES = 10
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")


def build_http_metadata_commands(
    origins: list[str],
    target: str,
    output_dir: Path,
) -> list[ReconCommand]:
    """Build three fixed metadata commands for each discovered HTTP origin."""

    output_dir = output_dir.expanduser().resolve()
    commands: list[ReconCommand] = []
    for service_index, origin in enumerate(origins, start=1):
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            raise ValueError(f"Discovered HTTP origin is not valid for target '{target}': {origin}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        safe_host = _safe_host(parsed.hostname)
        normalized_origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        commands.extend(
            [
                _metadata_command(
                    command_id=f"CMD-HTTP-METADATA-{service_index:02d}-HEADERS",
                    phase="http-headers",
                    description="Bounded header request for a discovered HTTP service.",
                    argv=[
                        "curl",
                        "-I",
                        "--max-time",
                        str(HTTP_METADATA_TIMEOUT_SECONDS),
                        "--silent",
                        "--show-error",
                        "--output",
                        str(output_dir / f"curl-headers-{safe_host}-{port}.txt"),
                        normalized_origin,
                    ],
                    output_file=output_dir / f"curl-headers-{safe_host}-{port}.txt",
                ),
                _metadata_command(
                    command_id=f"CMD-HTTP-METADATA-{service_index:02d}-ROBOTS",
                    phase="http-robots",
                    description="Bounded robots.txt request for a discovered HTTP service.",
                    argv=[
                        "curl",
                        "--max-time",
                        str(HTTP_METADATA_TIMEOUT_SECONDS),
                        "--silent",
                        "--show-error",
                        "--output",
                        str(output_dir / f"robots-{safe_host}-{port}.txt"),
                        urljoin(normalized_origin, "robots.txt"),
                    ],
                    output_file=output_dir / f"robots-{safe_host}-{port}.txt",
                ),
                _metadata_command(
                    command_id=f"CMD-HTTP-METADATA-{service_index:02d}-HOMEPAGE",
                    phase="http-homepage",
                    description="Bounded homepage HTML request for a discovered HTTP service.",
                    argv=[
                        "curl",
                        "--max-time",
                        str(HTTP_METADATA_TIMEOUT_SECONDS),
                        "--silent",
                        "--show-error",
                        "--output",
                        str(output_dir / f"homepage-{safe_host}-{port}.html"),
                        normalized_origin,
                    ],
                    output_file=output_dir / f"homepage-{safe_host}-{port}.html",
                ),
            ]
        )
    return commands


def validate_live_http_metadata_command(
    command: ReconCommand,
    output_dir: Path,
    target: str,
    allowed_origins: set[str],
) -> ReconCommandValidationResult:
    """Validate one exact curl metadata command against discovered origins."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    if command.tool != "curl":
        errors.append("HTTP metadata execution is restricted to curl.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Curl argv contains forbidden shell metacharacter token '{matched}'.")
    errors.extend(argv_control_character_errors(argv, label="Curl"))

    shape = _command_shape(argv)
    if shape is None:
        errors.append("Curl command must match an approved HTTP metadata argv shape.")
    else:
        output_index, url_index, artifact_type = shape
        if argv[output_index] != command.output_file:
            errors.append("Curl --output path must match command output_file.")
        if not _output_is_inside(command.output_file, output_dir):
            errors.append("output_file must stay inside the selected input directory.")
        parsed = urlparse(argv[url_index])
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            errors.append("Curl metadata URL must use the discovered target host.")
        origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        if origin not in allowed_origins:
            errors.append("Curl metadata URL must belong to a discovered HTTP service.")
        expected_url = urljoin(origin, "robots.txt") if artifact_type == "robots" else origin
        if argv[url_index] != expected_url:
            errors.append("Curl metadata URL path is not approved for this artefact type.")
        expected_name = _expected_filename(parsed, artifact_type)
        if Path(command.output_file).name != expected_name:
            errors.append(f"Curl metadata output must use deterministic filename {expected_name}.")

    if command.timeout_seconds != HTTP_METADATA_TIMEOUT_SECONDS:
        errors.append(
            f"HTTP metadata commands require timeout_seconds={HTTP_METADATA_TIMEOUT_SECONDS}."
        )
    if not command.ready_for_execution:
        errors.append("HTTP metadata command must be marked ready for execution.")
    if command.placeholders:
        errors.append("HTTP metadata command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("HTTP metadata commands require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("HTTP metadata commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def _metadata_command(
    command_id: str,
    phase: str,
    description: str,
    argv: list[str],
    output_file: Path,
) -> ReconCommand:
    return ReconCommand(
        id=command_id,
        tool="curl",
        argv=argv,
        output_file=str(output_file),
        timeout_seconds=HTTP_METADATA_TIMEOUT_SECONDS,
        phase=phase,
        risk_level="low",
        requires_confirmation=True,
        scope_sensitive=True,
        description=description,
        ready_for_execution=True,
        placeholders=[],
    )


def _command_shape(argv: list[str]) -> tuple[int, int, str] | None:
    get_prefix = [
        "curl",
        "--max-time",
        str(HTTP_METADATA_TIMEOUT_SECONDS),
        "--silent",
        "--show-error",
        "--output",
    ]
    header_prefix = [
        "curl",
        "-I",
        "--max-time",
        str(HTTP_METADATA_TIMEOUT_SECONDS),
        "--silent",
        "--show-error",
        "--output",
    ]
    if len(argv) == 9 and argv[:7] == header_prefix:
        return 7, 8, "headers"
    if len(argv) == 8 and argv[:6] == get_prefix:
        artifact_type = "robots" if Path(argv[6]).name.startswith("robots-") else "homepage"
        return 6, 7, artifact_type
    return None


def _expected_filename(parsed_url, artifact_type: str) -> str:
    safe_host = _safe_host(parsed_url.hostname or "")
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    if artifact_type == "headers":
        return f"curl-headers-{safe_host}-{port}.txt"
    if artifact_type == "robots":
        return f"robots-{safe_host}-{port}.txt"
    return f"homepage-{safe_host}-{port}.html"


def _safe_host(hostname: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", hostname.lower()).strip(".-") or "host"


def _output_is_inside(output_file: str, output_dir: Path) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False
    return output != root
