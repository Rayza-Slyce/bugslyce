"""Internal recon mode registry.

Mode names describe recon depth and evidence coverage. They do not grant
permission to run recon.
"""

from __future__ import annotations

from dataclasses import dataclass


QUICK_MODE_ID = "quick"
STANDARD_MODE_ID = "standard"
DEEP_MODE_ID = "deep"
QUICK_RECON_PROFILE = "lab-safe-tiny"
STANDARD_RECON_PROFILE = "standard-bounded"
DEEP_RECON_PROFILE = "deep-correlation"


class ReconModeUnavailable(ValueError):
    """Raised when a planned recon mode has no executable profile."""


@dataclass(frozen=True)
class ReconMode:
    """Stable metadata for a user-facing recon mode."""

    mode_id: str
    display_name: str
    internal_profile: str
    status: str
    purpose: str

    @property
    def is_available(self) -> bool:
        """Return whether this mode has implemented executable behaviour."""

        return self.status == "implemented"

    @property
    def unavailable_message(self) -> str:
        """Return deterministic user-facing wording for unavailable modes."""

        return f"{self.display_name} is planned but not implemented yet."


RECON_MODES: tuple[ReconMode, ...] = (
    ReconMode(
        mode_id=QUICK_MODE_ID,
        display_name="Quick Recon",
        internal_profile=QUICK_RECON_PROFILE,
        status="implemented",
        purpose="fast first-pass signal finding",
    ),
    ReconMode(
        mode_id=STANDARD_MODE_ID,
        display_name="Standard Recon",
        internal_profile=STANDARD_RECON_PROFILE,
        status="implemented",
        purpose=(
            "bounded evidence collection with offline interpretation of "
            "already-collected artefacts"
        ),
    ),
    ReconMode(
        mode_id=DEEP_MODE_ID,
        display_name="Deep Recon",
        internal_profile=DEEP_RECON_PROFILE,
        status="planned",
        purpose="slower evidence expansion, correlation, and review preparation",
    ),
)

_RECON_MODES_BY_ID = {mode.mode_id: mode for mode in RECON_MODES}


def list_recon_modes() -> tuple[ReconMode, ...]:
    """Return recon modes in deterministic display order."""

    return RECON_MODES


def get_recon_mode(mode_id: str) -> ReconMode:
    """Look up a recon mode by stable ID."""

    try:
        return _RECON_MODES_BY_ID[mode_id]
    except KeyError as exc:
        raise ValueError(f"Unknown recon mode: {mode_id}") from exc


def is_recon_mode_available(mode_id: str) -> bool:
    """Return whether a mode has executable behaviour."""

    return get_recon_mode(mode_id).is_available


def resolve_executable_profile(mode_id: str) -> str:
    """Resolve an executable internal profile for implemented modes only."""

    mode = get_recon_mode(mode_id)
    if not mode.is_available:
        raise ReconModeUnavailable(mode.unavailable_message)
    return mode.internal_profile
