"""Build and validate fixed curl HEAD commands for content results."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult
from bugslyce.recon.argv_safety import argv_control_character_errors


CONTENT_FOLLOWUP_TIMEOUT_SECONDS = 10
MAX_CONTENT_FOLLOWUPS = 20
MAX_CONTENT_FOLLOWUPS_PER_ORIGIN = 10
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")


def build_content_followup_commands(
    urls: list[str],
    target: str,
    output_dir: Path,
) -> list[ReconCommand]:
    """Build one fixed HEAD command for each selected discovered URL."""

    output_dir = output_dir.expanduser().resolve()
    commands: list[ReconCommand] = []
    for index, url in enumerate(urls, start=1):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            raise ValueError(f"Selected content follow-up URL is invalid for target '{target}': {url}")
        output_file = output_dir / content_followup_filename(url)
        commands.append(
            ReconCommand(
                id=f"CMD-CONTENT-FOLLOWUP-{index:03d}",
                tool="curl",
                argv=[
                    "curl",
                    "-I",
                    "--max-time",
                    str(CONTENT_FOLLOWUP_TIMEOUT_SECONDS),
                    "--silent",
                    "--show-error",
                    "--output",
                    str(output_file),
                    url,
                ],
                output_file=str(output_file),
                timeout_seconds=CONTENT_FOLLOWUP_TIMEOUT_SECONDS,
                phase="content-result-followup",
                risk_level="low",
                requires_confirmation=True,
                scope_sensitive=True,
                description="Bounded header request for a content-discovery result.",
                ready_for_execution=True,
                placeholders=[],
            )
        )
    return commands


def validate_live_content_followup_command(
    command: ReconCommand,
    output_dir: Path,
    target: str,
    allowed_origins: set[str],
    allowed_urls: set[str],
) -> ReconCommandValidationResult:
    """Validate one exact curl HEAD command against selected content results."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    if command.tool != "curl":
        errors.append("Content-result follow-up execution is restricted to curl.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Curl argv contains forbidden shell metacharacter token '{matched}'.")
    errors.extend(argv_control_character_errors(argv, label="Curl"))

    prefix = [
        "curl",
        "-I",
        "--max-time",
        str(CONTENT_FOLLOWUP_TIMEOUT_SECONDS),
        "--silent",
        "--show-error",
        "--output",
    ]
    if len(argv) != 9 or argv[:7] != prefix:
        errors.append("Curl command must match the approved content-result HEAD argv shape.")
    else:
        output_file, url = argv[7], argv[8]
        if output_file != command.output_file:
            errors.append("Curl --output path must match command output_file.")
        if not _output_is_inside(command.output_file, output_dir):
            errors.append("output_file must stay inside the selected input directory.")
        parsed = urlparse(url)
        origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            errors.append("Curl content-followup URL must use the discovered target host.")
        if origin not in allowed_origins:
            errors.append("Curl content-followup URL must belong to a discovered HTTP origin.")
        if url not in allowed_urls:
            errors.append("Curl content-followup URL must be selected from discovered-path evidence.")
        if Path(command.output_file).name != content_followup_filename(url):
            errors.append(
                "Curl content-followup output must use deterministic filename "
                f"{content_followup_filename(url)}."
            )

    if command.timeout_seconds != CONTENT_FOLLOWUP_TIMEOUT_SECONDS:
        errors.append(
            f"Content follow-up commands require timeout_seconds={CONTENT_FOLLOWUP_TIMEOUT_SECONDS}."
        )
    if not command.ready_for_execution:
        errors.append("Content follow-up command must be marked ready for execution.")
    if command.placeholders:
        errors.append("Content follow-up command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("Content follow-up commands require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Content follow-up commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def content_followup_filename(url: str) -> str:
    """Return a deterministic safe header filename for one selected URL."""

    parsed = urlparse(url)
    safe_host = _safe_component(parsed.hostname or "host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path_value = parsed.path.strip("/") or "root"
    if parsed.query:
        path_value = f"{path_value}-{parsed.query}"
    safe_path = _safe_component(path_value)[:120] or "path"
    return f"curl-headers-content-followup-{safe_host}-{port}-{safe_path}.txt"


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
