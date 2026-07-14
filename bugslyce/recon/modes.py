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
DEEP_RECON_PROFILE = "deep-bounded"


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


@dataclass(frozen=True)
class DeepReconBounds:
    """Explicit Deep Recon hard limits for the bounded enabled profile."""

    max_total_requests: int
    max_requests_per_service: int
    max_second_pass_directories: int
    max_second_pass_requests_per_directory: int
    max_crawl_depth: int
    max_crawl_pages: int
    max_js_files: int
    max_source_files: int
    max_source_map_files: int
    max_body_bytes: int
    max_redirects: int
    request_timeout_seconds: int
    rate_limit_delay_seconds: float


@dataclass(frozen=True)
class DeepReconProfileContract:
    """Deep Recon profile contract for bounded executable behaviour."""

    mode_name: str
    internal_profile: str
    availability: str
    purpose: str
    bounds: DeepReconBounds
    allowed_method_class: str
    default_behaviour_status: str
    capability_categories: tuple[str, ...]


DEEP_RECON_BOUNDS = DeepReconBounds(
    max_total_requests=1500,
    max_requests_per_service=400,
    max_second_pass_directories=8,
    max_second_pass_requests_per_directory=100,
    max_crawl_depth=1,
    max_crawl_pages=50,
    max_js_files=50,
    max_source_files=80,
    max_source_map_files=10,
    max_body_bytes=1_000_000,
    max_redirects=5,
    request_timeout_seconds=10,
    rate_limit_delay_seconds=0.1,
)


DEEP_RECON_CAPABILITY_CATEGORIES: tuple[str, ...] = (
    "expanded content discovery",
    "strong-signal second-pass discovery",
    "common metadata discovery",
    "shallow same-origin crawl",
    "selected body/source fetch",
    "JavaScript/source text collection",
    "static route extraction",
    "parameter inventory",
    "form inventory without submission",
    "source map detection",
    "backup/config/source exposure checks",
    "service/route/source correlation",
    "deep investigation threads",
    "deep manual review queue",
    "deep report/runbook output",
)


DEEP_RECON_PROFILE_CONTRACT = DeepReconProfileContract(
    mode_name="Deep Recon",
    internal_profile=DEEP_RECON_PROFILE,
    availability="implemented",
    purpose=(
        "aggressive evidence discovery inside strict authorisation, scope, "
        "method, and rate limits"
    ),
    bounds=DEEP_RECON_BOUNDS,
    allowed_method_class="GET/HEAD-style recon only",
    default_behaviour_status="implemented, bounded, non-exploitative",
    capability_categories=DEEP_RECON_CAPABILITY_CATEGORIES,
)


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
        status="implemented",
        purpose=(
            "aggressive evidence discovery inside strict authorisation, scope, "
            "method, and rate limits"
        ),
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


def get_deep_recon_profile_contract() -> DeepReconProfileContract:
    """Return the bounded Deep Recon profile contract."""

    return DEEP_RECON_PROFILE_CONTRACT
