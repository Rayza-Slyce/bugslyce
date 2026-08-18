"""Build and validate the bounded anonymous SMB share-list command."""

from __future__ import annotations

from pathlib import Path
import re

from bugslyce.core.models import ReconCommand, ReconCommandValidationResult
from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.argv_safety import argv_control_character_errors
from bugslyce.recon.smb_eligibility import SMBEnumerationTarget


SMB_REQUEST_TIMEOUT_SECONDS = 10
SMB_PROCESS_TIMEOUT_SECONDS = 30
SMB_SERVICE_NAMES = frozenset({"microsoft-ds", "netbios-ssn"})


def build_live_smb_share_list_command(
    target: SMBEnumerationTarget,
    output_dir: Path,
) -> ReconCommand:
    """Build one non-interactive no-credential SMB share-list command."""

    host = _normalise_target_host(target.host)
    port = _validated_port(target.port)

    if not any(
        name.casefold() in SMB_SERVICE_NAMES
        for name in target.service_names
    ):
        raise ValueError(
            "SMB enumeration target lacks retained SMB service evidence."
        )
    if not target.evidence_ids:
        raise ValueError(
            "SMB enumeration target lacks retained evidence IDs."
        )

    output_dir = output_dir.expanduser().resolve()
    output_file = (
        output_dir
        / f"smb-shares-{_safe_host(host)}-{port}.txt"
    )

    return ReconCommand(
        id=f"CMD-SMB-SHARES-{_safe_host(host)}-{port}",
        tool="smbclient",
        argv=_approved_argv(host, port),
        output_file=str(output_file),
        timeout_seconds=SMB_PROCESS_TIMEOUT_SECONDS,
        phase="smb-share-list",
        risk_level="low",
        requires_confirmation=True,
        scope_sensitive=True,
        description=(
            "Single bounded anonymous SMB share-listing request."
        ),
        ready_for_execution=True,
        placeholders=[],
    )


def validate_live_smb_share_list_command(
    command: ReconCommand,
    output_dir: Path,
    target: SMBEnumerationTarget,
) -> ReconCommandValidationResult:
    """Validate the exact SMB share-list argv and evidence-derived endpoint."""

    errors: list[str] = []

    if not isinstance(command.argv, list) or any(
        not isinstance(value, str)
        for value in command.argv
    ):
        errors.append("SMB argv must be a list of strings.")
        argv: list[str] = []
    else:
        argv = command.argv
        errors.extend(
            argv_control_character_errors(argv, label="SMB")
        )

    try:
        expected = build_live_smb_share_list_command(
            target,
            output_dir,
        )
    except ValueError as exc:
        errors.append(str(exc))
        expected = None

    if expected is not None and command != expected:
        errors.append(
            "SMB command must match the approved anonymous "
            "share-list argv shape."
        )

    output_path = Path(command.output_file).expanduser()
    if output_path.is_symlink():
        errors.append(
            "SMB output_file must not be a symbolic link."
        )
    elif output_path.exists() and not output_path.is_file():
        errors.append(
            "SMB output_file must be a regular file when it already exists."
        )

    if not _output_is_inside(
        command.output_file,
        output_dir,
    ):
        errors.append(
            "SMB output_file must stay inside the selected "
            "output directory."
        )

    return ReconCommandValidationResult(
        command_id=command.id,
        valid=not errors,
        errors=list(dict.fromkeys(errors)),
        warnings=[],
    )


def _approved_argv(host: str, port: int) -> list[str]:
    return [
        "smbclient",
        "--configfile=/dev/null",
        f"--list={host}",
        "--grepable",
        "--stderr",
        "--no-pass",
        "--user=%",
        "--use-kerberos=off",
        "--name-resolve=host",
        f"--port={port}",
        f"--timeout={SMB_REQUEST_TIMEOUT_SECONDS}",
    ]


def _normalise_target_host(host: str) -> str:
    if not isinstance(host, str):
        raise ValueError(
            "SMB enumeration target host is invalid."
        )

    value = host.strip().lower().rstrip(".")
    if (
        not value
        or any(character.isspace() for character in value)
        or "/" in value
    ):
        raise ValueError(
            "SMB enumeration target host is invalid."
        )

    canonical = scope_entry_target(value)
    if canonical != value:
        raise ValueError(
            "SMB enumeration target host is invalid."
        )

    return value


def _validated_port(port: int) -> int:
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError(
            "SMB enumeration target port is invalid."
        )
    return port


def _safe_host(host: str) -> str:
    return (
        re.sub(r"[^a-z0-9.-]+", "-", host.lower())
        .strip(".-")
        or "host"
    )


def _output_is_inside(
    output_file: str,
    output_dir: Path,
) -> bool:
    try:
        output = Path(output_file).expanduser().resolve()
        root = output_dir.expanduser().resolve()
        output.relative_to(root)
    except (OSError, ValueError):
        return False

    return output != root
