"""Simulated recon runner for testing structured command flow only."""

from __future__ import annotations

from collections.abc import Callable
import codecs
from dataclasses import dataclass
from datetime import datetime
import errno
from pathlib import Path
import os
import pty
import re
import select
import subprocess
import time

from bugslyce.core.models import ReconCommand, ReconCommandResult
from bugslyce.recon.commands import (
    validate_live_curl_header_command,
    validate_recon_command,
)
from bugslyce.recon.body_fetch_commands import validate_live_body_fetch_command
from bugslyce.recon.content_commands import (
    gobuster_candidate_count,
    validate_live_content_discovery_command,
)
from bugslyce.recon.content_followup_commands import validate_live_content_followup_command
from bugslyce.recon.http_metadata_commands import validate_live_http_metadata_command
from bugslyce.recon.path_followup_commands import validate_live_path_followup_command
from bugslyce.recon.smb_commands import validate_live_smb_share_list_command
from bugslyce.recon.smb_eligibility import SMBEnumerationTarget
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


class LiveSMBShareListRunner:
    """Execute only the approved bounded anonymous SMB share-list command."""

    def __init__(
        self,
        output_dir: Path,
        target: SMBEnumerationTarget,
    ) -> None:
        self.output_dir = output_dir
        self.target = target

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Run one validated non-interactive SMB share-list command."""

        started = utc_now()
        validation = validate_live_smb_share_list_command(
            command,
            self.output_dir,
            self.target,
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
        stderr_path = output_path.with_suffix(
            output_path.suffix + ".stderr.log"
        )

        environment = os.environ.copy()
        for name in (
            "USER",
            "LOGNAME",
            "PASSWD",
            "PASSWD_FD",
            "PASSWD_FILE",
        ):
            environment.pop(name, None)

        try:
            completed = subprocess.run(
                command.argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
                shell=False,
                env=environment,
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
                    "SMB share listing exceeded "
                    f"{command.timeout_seconds} seconds."
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
                error=f"SMB share listing could not start: {exc}",
            )

        stdout_text = completed.stdout or ""
        authoritative_output = stdout_text

        if (
            completed.returncode == 0
            and not stdout_text.strip()
            and completed.stderr
        ):
            authoritative_output = completed.stderr

        output_path.write_text(
            authoritative_output,
            encoding="utf-8",
        )

        stderr_file: str | None = None
        if completed.stderr:
            stderr_path.write_text(
                completed.stderr,
                encoding="utf-8",
            )
            stderr_file = str(stderr_path)

        ended = utc_now()
        error = (
            None
            if completed.returncode == 0
            else f"smbclient exited with code {completed.returncode}."
        )

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
            http_status_code=(
                _parse_http_status_code(completed.stdout)
                if command.phase == "http-robots"
                else None
            ),
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


GOBUSTER_TERMINATION_GRACE_SECONDS = 2.0
GOBUSTER_PROGRESS_POLL_SECONDS = 0.25
_GOBUSTER_PROGRESS_RE = re.compile(
    r"Progress:\s*(\d+)\s*/\s*(\d+)(?:\s*\([^)]*\))?"
)


@dataclass(frozen=True)
class GobusterParsedProgress:
    """Candidate counts parsed from one observed Gobuster terminal frame."""

    completed: int
    reported_total: int


@dataclass(frozen=True)
class GobusterProgressState:
    """Trusted determinate state, or a fail-safe indeterminate state."""

    completed: int | None
    total: int | None
    trusted: bool
    trust_lost: bool = False


@dataclass(frozen=True)
class ContentDiscoveryProgressEvent:
    """Direct progress facts emitted while a content child is supervised."""

    origin: str
    completed: int | None
    total: int | None
    elapsed_seconds: float
    trusted: bool


def parse_gobuster_progress(value: str) -> GobusterParsedProgress | None:
    """Parse the observed Gobuster 3.8 progress counter from terminal text."""

    if not isinstance(value, str):
        return None
    match = _GOBUSTER_PROGRESS_RE.search(value)
    if match is None:
        return None
    try:
        completed = int(match.group(1))
        reported_total = int(match.group(2))
    except ValueError:
        return None
    if completed < 0 or reported_total <= 0:
        return None
    return GobusterParsedProgress(completed, reported_total)


def observe_gobuster_progress(
    value: str,
    *,
    expected_total: int,
    previous: GobusterProgressState | None,
) -> GobusterProgressState:
    """Validate parsed progress against known work and latch trust loss."""

    if (
        not isinstance(expected_total, int)
        or isinstance(expected_total, bool)
        or expected_total <= 0
    ):
        raise ValueError("Expected Gobuster candidate total must be positive.")
    if previous is not None and previous.trust_lost:
        return previous

    parsed = parse_gobuster_progress(value)
    if parsed is None:
        return previous or GobusterProgressState(None, None, False)
    valid = (
        parsed.reported_total == expected_total
        and 0 <= parsed.completed <= expected_total
    )
    if previous is not None and previous.trusted:
        if not valid or parsed.completed < (previous.completed or 0):
            return GobusterProgressState(None, None, False, trust_lost=True)
        return GobusterProgressState(parsed.completed, expected_total, True)
    if valid:
        return GobusterProgressState(parsed.completed, expected_total, True)
    return GobusterProgressState(None, None, False)


def render_content_discovery_progress(
    *,
    origin: str,
    completed: int | None,
    total: int | None,
    elapsed_seconds: float,
    trusted: bool,
) -> str:
    """Render a compact determinate or indeterminate terminal progress line."""

    elapsed = max(0, int(elapsed_seconds))
    minutes, seconds = divmod(elapsed, 60)
    clock = f"{minutes:02d}:{seconds:02d}"
    if trusted and completed is not None and total is not None and total > 0:
        percentage = min(100, max(0, completed * 100 // total))
        filled = min(20, percentage * 20 // 100)
        bar = "#" * filled + "-" * (20 - filled)
        return (
            f"Content discovery [{bar}] {percentage}% "
            f"{completed}/{total} {clock} {origin}"
        )
    return f"Content discovery [active] {clock} {origin}"


class _GobusterTerminalBuffer:
    """Decode arbitrary PTY reads and emit complete CR/LF terminal frames."""

    def __init__(self, consumer: Callable[[str], None]) -> None:
        self._consumer = consumer
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._buffer = ""

    def feed(self, chunk: bytes) -> None:
        self._buffer += self._decoder.decode(chunk)
        self._emit_complete_frames()

    def finish(self) -> None:
        self._buffer += self._decoder.decode(b"", final=True)
        self._emit_complete_frames()
        if self._buffer:
            self._consumer(self._buffer)
            self._buffer = ""

    def _emit_complete_frames(self) -> None:
        while True:
            positions = [
                position
                for marker in ("\r", "\n")
                if (position := self._buffer.find(marker)) >= 0
            ]
            if not positions:
                return
            position = min(positions)
            frame = self._buffer[:position]
            self._buffer = self._buffer[position + 1 :]
            while self._buffer.startswith(("\r", "\n")):
                self._buffer = self._buffer[1:]
            if frame:
                self._consumer(frame)


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

    def run(
        self,
        command: ReconCommand,
        progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None = None,
    ) -> ReconCommandResult:
        """Run one validated Gobuster command without a normal process deadline."""

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
        master_fd: int | None = None
        slave_fd: int | None = None
        process = None
        terminal_output = bytearray()
        expected_total: int
        try:
            expected_total = gobuster_candidate_count(Path(command.argv[5]))
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                command.argv,
                stdin=subprocess.DEVNULL,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                shell=False,
            )
            os.close(slave_fd)
            slave_fd = None
            progress_state: GobusterProgressState | None = None
            monotonic_started = time.monotonic()

            if progress_callback is not None:
                progress_callback(
                    ContentDiscoveryProgressEvent(
                        origin=command.argv[3],
                        completed=None,
                        total=None,
                        elapsed_seconds=0.0,
                        trusted=False,
                    )
                )

            def consume_frame(frame: str) -> None:
                nonlocal progress_state
                parsed = parse_gobuster_progress(frame)
                progress_state = observe_gobuster_progress(
                    frame,
                    expected_total=expected_total,
                    previous=progress_state,
                )
                if progress_callback is None:
                    return
                if parsed is None and progress_state.trusted:
                    return
                progress_callback(
                    ContentDiscoveryProgressEvent(
                        origin=command.argv[3],
                        completed=progress_state.completed,
                        total=progress_state.total,
                        elapsed_seconds=max(0.0, time.monotonic() - monotonic_started),
                        trusted=progress_state.trusted,
                    )
                )

            terminal_buffer = _GobusterTerminalBuffer(consume_frame)
            while True:
                assert master_fd is not None
                child_exited = process.poll() is not None
                readable, _writable, _exceptional = select.select(
                    [master_fd],
                    [],
                    [],
                    0.0 if child_exited else GOBUSTER_PROGRESS_POLL_SECONDS,
                )
                if readable:
                    try:
                        chunk = os.read(master_fd, 65536)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    terminal_output.extend(chunk)
                    terminal_buffer.feed(chunk)
                    continue
                if child_exited:
                    break
            terminal_buffer.finish()
            return_code = process.wait()
        except OSError as exc:
            if process is not None and process.poll() is None:
                _terminate_gobuster_process(process)
            ended = utc_now()
            return _live_result(
                command,
                started,
                ended,
                exit_code=None,
                stderr_path=None,
                error=f"Content discovery could not start: {exc}",
            )
        except BaseException:
            if process is not None and process.poll() is None:
                _terminate_gobuster_process(process)
            raise
        finally:
            if slave_fd is not None:
                _close_file_descriptor(slave_fd)
            if master_fd is not None:
                _close_file_descriptor(master_fd)

        stderr_file: str | None = None
        if terminal_output:
            stderr_path.write_bytes(bytes(terminal_output))
            stderr_file = str(stderr_path)
        ended = utc_now()
        error = None if return_code == 0 else f"Gobuster exited with code {return_code}."
        return _live_result(
            command,
            started,
            ended,
            exit_code=return_code,
            stderr_path=stderr_file,
            error=error,
        )


def _terminate_gobuster_process(process) -> None:
    """Stop and reap the directly launched child after cancellation or error."""

    try:
        process.terminate()
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=GOBUSTER_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _close_file_descriptor(file_descriptor: int) -> None:
    try:
        os.close(file_descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise


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
    http_status_code: int | None = None,
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
        http_status_code=http_status_code,
    )


def _parse_http_status_code(value: str) -> int | None:
    compact = value.strip()
    if len(compact) != 3 or not compact.isdigit():
        return None
    status_code = int(compact)
    return status_code if 100 <= status_code <= 599 else None
