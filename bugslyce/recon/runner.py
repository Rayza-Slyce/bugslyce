"""Simulated recon runner for testing structured command flow only."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from bugslyce.core.models import ReconCommand, ReconCommandResult
from bugslyce.recon.commands import validate_recon_command


class SimulatedReconRunner:
    """Validate commands and return simulated results without execution."""

    def __init__(self, planned_output_dir: Path) -> None:
        self.planned_output_dir = planned_output_dir

    def run(self, command: ReconCommand) -> ReconCommandResult:
        """Simulate one command result without invoking any external process."""

        started = datetime.now(timezone.utc)
        validation = validate_recon_command(command, self.planned_output_dir)
        ended = datetime.now(timezone.utc)
        error = "; ".join(validation.errors) if validation.errors else None
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=0 if validation.valid else None,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            duration_seconds=max(0.0, (ended - started).total_seconds()),
            executed=False,
            simulated=True,
            error=error,
        )
