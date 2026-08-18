"""Bounded orchestration for evidence-backed anonymous SMB share enumeration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable

from bugslyce.core.engagement_policy import enforce_r0b2_bug_bounty_live_block
from bugslyce.core.models import ReconCommandResult, SMBShare
from bugslyce.core.project import build_project_state
from bugslyce.parsers.smbclient import parse_smbclient_share_list
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.smb_commands import (
    SMB_AUTH_GUEST,
    build_live_smb_share_list_command,
)
from bugslyce.recon.smb_eligibility import (
    SMBEnumerationTarget,
    select_smb_enumeration_targets,
)


class SMBEnumerationNoWork(Exception):
    """Clean outcome when retained evidence contains no eligible SMB endpoint."""

    def __init__(self, considered: int) -> None:
        super().__init__(
            "No evidence-backed SMB endpoints are eligible for "
            "anonymous share enumeration."
        )
        self.considered = considered


@dataclass(frozen=True)
class SMBShareCollectionResult:
    """Result of one bounded SMB share-enumeration collection stage."""

    input_dir: str
    scope_file: str
    execution_count: int
    commands_succeeded: int
    commands_unsuccessful: int
    commands_timed_out: int
    command_results: tuple[ReconCommandResult, ...]
    shares: tuple[SMBShare, ...]
    warnings: tuple[str, ...]


def collect_smb_share_evidence(
    input_dir: Path,
    scope_file: Path,
    *,
    runner_factory: Callable[[SMBEnumerationTarget], object] | None = None,
) -> SMBShareCollectionResult:
    """Enumerate shares only for retained, explicitly scoped SMB endpoints."""

    input_dir = input_dir.expanduser().resolve()
    scope_file = scope_file.expanduser().resolve()

    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    initial_state = build_project_state(input_dir)

    manifest = getattr(initial_state, "recon_manifest", None)
    if manifest is not None:
        authoritative_scope = (
            input_dir / (manifest.scope_file or "scope.md")
        ).resolve()
        if scope_file != authoritative_scope:
            raise ValueError(
                "SMB collection scope_file must match the "
                "authoritative project scope."
            )
        scope_file = authoritative_scope

    # Direct/modular bug-bounty SMB traffic is not yet policy-authorised.
    enforce_r0b2_bug_bounty_live_block(initial_state.engagement_context)

    targets = select_smb_enumeration_targets(
        initial_state.port_services,
        initial_state.evidence,
    )
    if not targets:
        raise SMBEnumerationNoWork(0)

    validated_targets: list[SMBEnumerationTarget] = []
    for target in targets:
        validated_host = validate_explicit_nmap_target_scope(
            target.host,
            scope_file,
        )
        validated_targets.append(
            replace(target, host=validated_host)
            if validated_host != target.host
            else target
        )
    targets = tuple(validated_targets)

    command_results: list[ReconCommandResult] = []
    shares: list[SMBShare] = []
    successful_artifacts: list[
        tuple[SMBEnumerationTarget, ReconCommandResult]
    ] = []
    commands_succeeded = 0
    commands_unsuccessful = 0
    commands_timed_out = 0

    for target in targets:
        command = build_live_smb_share_list_command(
            target,
            input_dir,
        )

        if runner_factory is None:
            from bugslyce.recon.runner import LiveSMBShareListRunner

            runner = LiveSMBShareListRunner(
                input_dir,
                target,
            )
        else:
            runner = runner_factory(target)

        results_for_target = [runner.run(command)]

        if _smb_session_setup_rejected(results_for_target[0]):
            guest_command = build_live_smb_share_list_command(
                target,
                input_dir,
                auth_mode=SMB_AUTH_GUEST,
            )
            results_for_target.append(
                runner.run(guest_command)
            )

        for result in results_for_target:
            command_results.append(result)

            if result.exit_code == 0 and result.error is None:
                commands_succeeded += 1
                successful_artifacts.append((target, result))
                shares.extend(
                    parse_smbclient_share_list(
                        Path(result.output_file),
                        target,
                    )
                )
            elif result.executed and result.exit_code is None:
                _retire_previous_smb_artifact(
                    input_dir,
                    result.output_file,
                    remove_output=True,
                )
                commands_timed_out += 1
            else:
                if result.executed:
                    _retire_previous_smb_artifact(
                        input_dir,
                        result.output_file,
                        remove_output=False,
                    )
                commands_unsuccessful += 1

    if successful_artifacts:
        _register_successful_smb_artifacts(
            input_dir,
            successful_artifacts,
        )

    return SMBShareCollectionResult(
        input_dir=str(input_dir),
        scope_file=str(scope_file),
        execution_count=len(command_results),
        commands_succeeded=commands_succeeded,
        commands_unsuccessful=commands_unsuccessful,
        commands_timed_out=commands_timed_out,
        command_results=tuple(command_results),
        shares=tuple(shares),
        warnings=tuple(initial_state.warnings),
    )

def _smb_session_setup_rejected(
    result: ReconCommandResult,
) -> bool:
    """Return whether a null-identity attempt reached and failed SMB session setup."""

    if (
        not result.executed
        or result.exit_code in {0, None}
        or not result.stderr_path
    ):
        return False

    path = Path(result.stderr_path)
    if not path.is_file() or path.is_symlink():
        return False

    try:
        stderr = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return False

    return "session setup failed:" in stderr.casefold()


def write_smb_share_execution_result(
    result: SMBShareCollectionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write generic and durable phase-specific SMB execution metadata."""

    input_dir = input_dir.expanduser().resolve()
    input_dir.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(
        asdict(result),
        indent=2,
        sort_keys=True,
    ) + "\n"
    markdown = render_smb_share_execution_markdown(result)

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    phase_json_path = input_dir / "recon_execution_smb_shares.json"
    phase_markdown_path = input_dir / "recon_execution_smb_shares.md"

    for path in (json_path, phase_json_path):
        path.write_text(payload, encoding="utf-8")
    for path in (markdown_path, phase_markdown_path):
        path.write_text(markdown, encoding="utf-8")

    return json_path, markdown_path


def render_smb_share_execution_markdown(
    result: SMBShareCollectionResult,
) -> str:
    """Render bounded anonymous SMB share-list execution metadata."""

    return "\n".join(
        [
            "# BugSlyce SMB Share Enumeration Execution",
            "",
            f"- Input/output directory: `{result.input_dir}`",
            f"- Scope file: `{result.scope_file}`",
            f"- Commands attempted: {result.execution_count}",
            f"- Commands succeeded: {result.commands_succeeded}",
            f"- Commands unsuccessful: {result.commands_unsuccessful}",
            f"- Commands timed out: {result.commands_timed_out}",
            f"- Shares observed: {len(result.shares)}",
            "",
            (
                "Bounded anonymous SMB share-listing commands were attempted "
                "only for evidence-backed, explicitly scoped SMB endpoints."
            ),
            (
                "No share traversal, file listing, download, upload, writeability "
                "testing, credential guessing, vulnerability scripts, or "
                "exploitation were performed."
            ),
            "",
        ]
    )


def _retire_previous_smb_artifact(
    input_dir: Path,
    output_file: str,
    *,
    remove_output: bool,
) -> None:
    """Retire stale authoritative SMB evidence after an executed failed refresh."""

    manifest_path = input_dir / "recon_manifest.json"
    output_path = Path(output_file)

    if manifest_path.is_file():
        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(
                "Could not update recon manifest for SMB collection: "
                f"{exc}"
            ) from exc

        if not isinstance(manifest, dict):
            raise ValueError(
                "Recon manifest must contain a JSON object."
            )

        existing = manifest.get("artifacts")
        if not isinstance(existing, list):
            raise ValueError(
                "Recon manifest field 'artifacts' must be a list."
            )

        output_name = output_path.name
        artifacts = [
            artifact
            for artifact in existing
            if not (
                isinstance(artifact, dict)
                and artifact.get("type") == "smb_shares"
                and artifact.get("file") == output_name
            )
        ]

        if artifacts != existing:
            manifest["artifacts"] = artifacts
            manifest_path.write_text(
                json.dumps(
                    manifest,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

    if (
        remove_output
        and output_path.exists()
        and output_path.is_file()
        and not output_path.is_symlink()
    ):
        output_path.unlink()


def _register_successful_smb_artifacts(
    input_dir: Path,
    successful_artifacts: list[
        tuple[SMBEnumerationTarget, ReconCommandResult]
    ],
) -> None:
    """Register successful raw SMB listings for deterministic rebuild."""

    manifest_path = input_dir / "recon_manifest.json"

    # Preserve the existing modular collector behaviour used by tests and
    # legacy local inputs. Normal BugSlyce project workflows own a manifest.
    if not manifest_path.is_file():
        return

    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "Could not update recon manifest for SMB collection: "
            f"{exc}"
        ) from exc

    if not isinstance(manifest, dict):
        raise ValueError(
            "Recon manifest must contain a JSON object."
        )

    existing = manifest.get("artifacts")
    if not isinstance(existing, list):
        raise ValueError(
            "Recon manifest field 'artifacts' must be a list."
        )

    refreshed_endpoints = {
        (
            target.host.casefold(),
            target.port,
            "tcp",
        )
        for target, _result in successful_artifacts
    }

    artifacts = [
        artifact
        for artifact in existing
        if not (
            isinstance(artifact, dict)
            and artifact.get("type") == "smb_shares"
            and (
                str(artifact.get("host") or "").casefold(),
                artifact.get("port"),
                str(artifact.get("protocol") or "").casefold(),
            )
            in refreshed_endpoints
        )
    ]

    for target, result in successful_artifacts:
        artifacts.append(
            {
                "type": "smb_shares",
                "file": Path(result.output_file).name,
                "host": target.host,
                "port": target.port,
                "protocol": "tcp",
                "description": (
                    "Bounded anonymous SMB share listing for "
                    "evidence-backed SMB endpoint"
                ),
            }
        )

    manifest["artifacts"] = artifacts

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

