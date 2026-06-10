"""Build and validate fixed curl HEAD commands for discovered paths."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult


PATH_FOLLOWUP_TIMEOUT_SECONDS = 10
MAX_PATH_FOLLOWUPS = 20
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")


def build_path_followup_commands(
    urls: list[str],
    target: str,
    output_dir: Path,
) -> list[ReconCommand]:
    """Build one fixed HEAD command for each evidence-derived URL."""

    output_dir = output_dir.expanduser().resolve()
    commands: list[ReconCommand] = []
    for index, url in enumerate(urls, start=1):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            raise ValueError(f"Discovered follow-up URL is not valid for target '{target}': {url}")
        output_file = output_dir / _expected_filename(url)
        commands.append(
            ReconCommand(
                id=f"CMD-PATH-FOLLOWUP-{index:03d}",
                tool="curl",
                argv=[
                    "curl",
                    "-I",
                    "--max-time",
                    str(PATH_FOLLOWUP_TIMEOUT_SECONDS),
                    "--silent",
                    "--show-error",
                    "--output",
                    str(output_file),
                    url,
                ],
                output_file=str(output_file),
                timeout_seconds=PATH_FOLLOWUP_TIMEOUT_SECONDS,
                phase="path-followup-headers",
                risk_level="low",
                requires_confirmation=True,
                scope_sensitive=True,
                description="Bounded header request for a discovered same-origin path.",
                ready_for_execution=True,
                placeholders=[],
            )
        )
    return commands


def validate_live_path_followup_command(
    command: ReconCommand,
    output_dir: Path,
    target: str,
    allowed_origins: set[str],
    allowed_urls: set[str],
) -> ReconCommandValidationResult:
    """Validate one exact curl HEAD command against evidence-derived URLs."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    if command.tool != "curl":
        errors.append("Discovered-path follow-up execution is restricted to curl.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Curl argv contains forbidden shell metacharacter token '{matched}'.")

    prefix = [
        "curl",
        "-I",
        "--max-time",
        str(PATH_FOLLOWUP_TIMEOUT_SECONDS),
        "--silent",
        "--show-error",
        "--output",
    ]
    if len(argv) != 9 or argv[:7] != prefix:
        errors.append("Curl command must match the approved discovered-path HEAD argv shape.")
    else:
        output_file = argv[7]
        url = argv[8]
        if output_file != command.output_file:
            errors.append("Curl --output path must match command output_file.")
        if not _output_is_inside(command.output_file, output_dir):
            errors.append("output_file must stay inside the selected input directory.")

        parsed = urlparse(url)
        origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            errors.append("Curl follow-up URL must use the discovered target host.")
        if origin not in allowed_origins:
            errors.append("Curl follow-up URL must belong to a discovered HTTP service origin.")
        if url not in allowed_urls:
            errors.append("Curl follow-up URL must already exist in structured BugSlyce evidence.")
        if Path(command.output_file).name != _expected_filename(url):
            errors.append(
                f"Curl follow-up output must use deterministic filename {_expected_filename(url)}."
            )

    if command.timeout_seconds != PATH_FOLLOWUP_TIMEOUT_SECONDS:
        errors.append(
            f"Path follow-up commands require timeout_seconds={PATH_FOLLOWUP_TIMEOUT_SECONDS}."
        )
    if not command.ready_for_execution:
        errors.append("Path follow-up command must be marked ready for execution.")
    if command.placeholders:
        errors.append("Path follow-up command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("Path follow-up commands require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Path follow-up commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def _expected_filename(url: str) -> str:
    parsed = urlparse(url)
    safe_host = _safe_component(parsed.hostname or "host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path_value = parsed.path.strip("/") or "root"
    if parsed.query:
        path_value = f"{path_value}-{parsed.query}"
    safe_path = _safe_component(path_value)[:120] or "path"
    return f"curl-headers-followup-{safe_host}-{port}-{safe_path}.txt"


def _safe_component(value: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", value.lower()).strip(".-")


def _output_is_inside(output_file: str, output_dir: Path) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False
    return output != root
