"""Simulated recon runner for testing structured command flow only."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import subprocess

from bugslyce.core.models import ReconCommand, ReconCommandResult
from bugslyce.recon.commands import (
    validate_live_curl_header_command,
    validate_recon_command,
)
from bugslyce.recon.body_fetch_commands import validate_live_body_fetch_command
from bugslyce.recon.content_commands import validate_live_content_discovery_command
from bugslyce.recon.content_followup_commands import validate_live_content_followup_command
from bugslyce.recon.http_metadata_commands import validate_live_http_metadata_command
from bugslyce.recon.path_followup_commands import validate_live_path_followup_command
from bugslyce.recon.nmap_profiles import (
    validate_live_nmap_discovery_command,
    validate_live_nmap_service_scan_command,
)
from bugslyce.time_utils import format_utc_iso, utc_now


class SimulatedReconRunner:
    """Validate commands and return simulated results without execution."""

    def __init__(self, planned_output_dir: Path) -> None:
        self.planned_output_dir = planned_output_dir

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Simulate one command result without invoking any external process."""

        started = utc_now()
        validation = validate_recon_command(command, self.planned_output_dir)
        ended = utc_now()
        error = "; ".join(validation.errors) if validation.errors else None
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=0 if validation.valid else None,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at=format_utc_iso(started),
            ended_at=format_utc_iso(ended),
            duration_seconds=max(0.0, (ended - started).total_seconds()),
            executed=False,
            simulated=True,
            error=error,
        )


class LiveCurlHeaderRunner:
    """Execute one validated, bounded curl header request."""

    def __init__(self, planned_output_dir: Path) -> None:
        self.planned_output_dir = planned_output_dir

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run only the approved curl header argv shape."""

        started = utc_now()
        validation = validate_live_curl_header_command(command, self.planned_output_dir)
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Curl header request exceeded {command.timeout_seconds} seconds.",
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Curl header request could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Curl exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LiveNmapDiscoveryRunner:
    """Execute only approved nmap discovery command shapes."""

    def __init__(self, planned_output_dir: Path) -> None:
        self.planned_output_dir = planned_output_dir

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated nmap TCP discovery command."""

        started = utc_now()
        validation = validate_live_nmap_discovery_command(command, self.planned_output_dir)
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Nmap discovery exceeded {command.timeout_seconds} seconds.",
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Nmap discovery could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Nmap exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


# Backwards-compatible internal alias from the first live nmap phase.
LiveNmapTopPortsRunner = LiveNmapDiscoveryRunner


class LiveNmapServiceRunner:
    """Execute only the approved nmap service/version command shape."""

    def __init__(self, planned_output_dir: Path) -> None:
        self.planned_output_dir = planned_output_dir

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated nmap service/version command."""

        started = utc_now()
        validation = validate_live_nmap_service_scan_command(
            command,
            self.planned_output_dir,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Nmap service scan exceeded {command.timeout_seconds} seconds.",
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Nmap service scan could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Nmap exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LiveHTTPMetadataRunner:
    """Execute only approved curl metadata commands for discovered origins."""

    def __init__(
        self,
        output_dir: Path,
        target: str,
        allowed_origins: set[str],
    ) -> None:
        self.output_dir = output_dir
        self.target = target
        self.allowed_origins = allowed_origins

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated curl metadata request."""

        started = utc_now()
        validation = validate_live_http_metadata_command(
            command,
            self.output_dir,
            self.target,
            self.allowed_origins,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"HTTP metadata request exceeded {command.timeout_seconds} seconds.",
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"HTTP metadata request could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Curl exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LivePathFollowupRunner:
    """Execute only approved curl HEAD checks for evidence-derived paths."""

    def __init__(
        self,
        output_dir: Path,
        target: str,
        allowed_origins: set[str],
        allowed_urls: set[str],
    ) -> None:
        self.output_dir = output_dir
        self.target = target
        self.allowed_origins = allowed_origins
        self.allowed_urls = allowed_urls

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated discovered-path HEAD request."""

        started = utc_now()
        validation = validate_live_path_followup_command(
            command,
            self.output_dir,
            self.target,
            self.allowed_origins,
            self.allowed_urls,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Discovered-path follow-up exceeded {command.timeout_seconds} seconds.",
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Discovered-path follow-up could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Curl exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LiveContentDiscoveryRunner:
    """Execute only approved gobuster commands from a validated content plan."""

    def __init__(
        self,
        output_dir: Path,
        target: str,
        allowed_origins: set[str],
        profile: str = "lab-root-light",
    ) -> None:
        self.output_dir = output_dir
        self.target = target
        self.allowed_origins = allowed_origins
        self.profile = profile

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated lab-root-light gobuster command."""

        started = utc_now()
        validation = validate_live_content_discovery_command(
            command,
            self.output_dir,
            self.target,
            self.allowed_origins,
            self.profile,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=(
                    f"Content discovery command {command.id} for {command.argv[3]} "
                    f"started and exceeded {command.timeout_seconds} seconds."
                ),
                executed=True,
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Content discovery could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Gobuster exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LiveContentFollowupRunner:
    """Execute only approved curl HEAD checks for selected content results."""

    def __init__(
        self,
        output_dir: Path,
        target: str,
        allowed_origins: set[str],
        allowed_urls: set[str],
    ) -> None:
        self.output_dir = output_dir
        self.target = target
        self.allowed_origins = allowed_origins
        self.allowed_urls = allowed_urls

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated content-result HEAD request."""

        started = utc_now()
        validation = validate_live_content_followup_command(
            command,
            self.output_dir,
            self.target,
            self.allowed_origins,
            self.allowed_urls,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Content-result follow-up exceeded {command.timeout_seconds} seconds.",
                executed=True,
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Content-result follow-up could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Curl exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


class LiveBodyFetchRunner:
    """Execute only approved curl GET requests for selected followed paths."""

    def __init__(
        self,
        output_dir: Path,
        target: str,
        allowed_origins: set[str],
        allowed_urls: set[str],
    ) -> None:
        self.output_dir = output_dir
        self.target = target
        self.allowed_origins = allowed_origins
        self.allowed_urls = allowed_urls

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated selective body-fetch request."""

        started = utc_now()
        validation = validate_live_body_fetch_command(
            command,
            self.output_dir,
            self.target,
            self.allowed_origins,
            self.allowed_urls,
        )
        if not validation.valid:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error="; ".join(validation.errors),
            )

        output_path = Path(command.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
        try:
            completed = subprocess.run(
                command.argv,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Selective body fetch exceeded {command.timeout_seconds} seconds.",
                executed=True,
            )
        except OSError as exc:
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Selective body fetch could not start: {exc}",
            )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(completed.stderr, encoding="utf-8")
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if completed.returncode == 0 else f"Curl exited with code {completed.returncode}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=completed.returncode,
            stderr_path=stderr_file,
            error=error,
        )


def _live_result(
    command: ReconCommand,
    started: datetime,
    ended: datetime,
    exit_code: int | None,
    stderr_path: str | None,
    error: str | None,
    executed: bool | None = None,
) -> ReconCommandResult:
    return ReconCommandResult(
        command_id=command.id,
        tool=command.tool,
        exit_code=exit_code,
        stdout_path=None,
        stderr_path=stderr_path,
        output_file=command.output_file,
        started_at=format_utc_iso(started),
        ended_at=format_utc_iso(ended),
        duration_seconds=max(0.0, (ended - started).total_seconds()),
        executed=exit_code is not None if executed is None else executed,
        simulated=False,
        error=error,
    )
