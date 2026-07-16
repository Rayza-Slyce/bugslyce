"""Build and validate fixed curl GET commands for selective body fetches."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult
from bugslyce.recon.argv_safety import argv_control_character_errors


BODY_FETCH_TIMEOUT_SECONDS = 10
MAX_BODY_FETCHES = 10
MAX_BODY_FETCHES_PER_ORIGIN = 5
SHELL_METACHARACTERS = (";", "&&", "||", "|", "`", "$(", ">", "<")


def build_body_fetch_commands(
    urls: list[str],
    target: str,
    output_dir: Path,
) -> list[ReconCommand]:
    """Build one fixed GET command for each selected prior-evidence URL."""

    output_dir = output_dir.expanduser().resolve()
    commands: list[ReconCommand] = []
    for index, url in enumerate(urls, start=1):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            raise ValueError(f"Selected body-fetch URL is invalid for target '{target}': {url}")
        output_file = output_dir / body_fetch_filename(url)
        commands.append(
            ReconCommand(
                id=f"CMD-BODY-FETCH-{index:03d}",
                tool="curl",
                argv=[
                    "curl",
                    "--max-time",
                    str(BODY_FETCH_TIMEOUT_SECONDS),
                    "--silent",
                    "--show-error",
                    "--output",
                    str(output_file),
                    url,
                ],
                output_file=str(output_file),
                timeout_seconds=BODY_FETCH_TIMEOUT_SECONDS,
                phase="selective-body-fetch",
                risk_level="low",
                requires_confirmation=True,
                scope_sensitive=True,
                description="Bounded body request for a selected followed path.",
                ready_for_execution=True,
                placeholders=[],
            )
        )
    return commands


def validate_live_body_fetch_command(
    command: ReconCommand,
    output_dir: Path,
    target: str,
    allowed_origins: set[str],
    allowed_urls: set[str],
) -> ReconCommandValidationResult:
    """Validate one exact curl GET command against selected prior evidence."""

    errors: list[str] = []
    if not isinstance(command.argv, list) or any(not isinstance(value, str) for value in command.argv):
        argv: list[str] = []
        errors.append("argv must be a list of strings.")
    else:
        argv = command.argv

    if command.tool != "curl":
        errors.append("Selective body fetch execution is restricted to curl.")
    for value in argv:
        matched = next((token for token in SHELL_METACHARACTERS if token in value), None)
        if matched:
            errors.append(f"Curl argv contains forbidden shell metacharacter token '{matched}'.")
    errors.extend(argv_control_character_errors(argv, label="Curl"))

    prefix = [
        "curl",
        "--max-time",
        str(BODY_FETCH_TIMEOUT_SECONDS),
        "--silent",
        "--show-error",
        "--output",
    ]
    if len(argv) != 8 or argv[:6] != prefix:
        errors.append("Curl command must match the approved selective body-fetch GET argv shape.")
    else:
        output_file, url = argv[6], argv[7]
        if output_file != command.output_file:
            errors.append("Curl --output path must match command output_file.")
        if not _output_is_inside(command.output_file, output_dir):
            errors.append("output_file must stay inside the selected input directory.")
        parsed = urlparse(url)
        origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            errors.append("Curl body-fetch URL must use the discovered target host.")
        if origin not in allowed_origins:
            errors.append("Curl body-fetch URL must belong to a discovered HTTP origin.")
        if url not in allowed_urls:
            errors.append("Curl body-fetch URL must be selected from prior followed-path evidence.")
        if Path(command.output_file).name != body_fetch_filename(url):
            errors.append(
                "Curl body-fetch output must use deterministic filename "
                f"{body_fetch_filename(url)}."
            )

    if command.timeout_seconds != BODY_FETCH_TIMEOUT_SECONDS:
        errors.append(
            f"Body-fetch commands require timeout_seconds={BODY_FETCH_TIMEOUT_SECONDS}."
        )
    if not command.ready_for_execution:
        errors.append("Body-fetch command must be marked ready for execution.")
    if command.placeholders:
        errors.append("Body-fetch command must not contain placeholders.")
    if not command.requires_confirmation:
        errors.append("Body-fetch commands require explicit confirmation.")
    if not command.scope_sensitive:
        errors.append("Body-fetch commands must be scope sensitive.")

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def body_fetch_filename(url: str) -> str:
    """Return a deterministic safe HTML filename for one selected URL."""

    parsed = urlparse(url)
    safe_host = _safe_component(parsed.hostname or "host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path_value = parsed.path.strip("/") or "root"
    if parsed.query:
        path_value = f"{path_value}-{parsed.query}"
    safe_path = _safe_component(path_value)[:120] or "path"
    return f"body-fetch-{safe_host}-{port}-{safe_path}.html"


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
