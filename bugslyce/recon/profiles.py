"""Recon profile definitions used by the planning-only workflow."""

from __future__ import annotations

from bugslyce.core.models import ReconProfile


PROFILES = {
    "lab-full": ReconProfile(
        name="lab-full",
        description="Broad planning profile for an explicitly authorised private lab target.",
        allows_live_commands=True,
        safety_notes=[
            "Confirm the target and all planned activity are authorised before future execution.",
            "Stop if scope changes or the target no longer matches the supplied scope.",
            "Use bounded timeouts and preserve all raw outputs locally.",
        ],
    ),
    "bug-bounty-standard": ReconProfile(
        name="bug-bounty-standard",
        description="Conservative planning profile for explicitly authorised programme scope.",
        allows_live_commands=True,
        safety_notes=[
            "Review programme scope, exclusions, rate limits, and testing windows before future execution.",
            "Use conservative request rates, bounded timeouts, and limited content discovery.",
            "Do not add aggressive fuzzing or recursive discovery without explicit authorisation.",
        ],
    ),
    "passive-only": ReconProfile(
        name="passive-only",
        description="Offline import and recon-pack planning with no live network activity.",
        allows_live_commands=False,
        safety_notes=[
            "No live network commands are included in this profile.",
            "Only supplied local artifacts should be parsed and assembled.",
            "Use this profile when scope is unclear, sensitive, or limited to existing evidence.",
        ],
    ),
}


def get_recon_profile(name: str) -> ReconProfile:
    """Return a supported profile or raise a clear validation error."""

    normalised = name.strip().lower()
    try:
        return PROFILES[normalised]
    except KeyError as exc:
        supported = ", ".join(PROFILES)
        raise ValueError(f"Unsupported recon profile '{name}'. Supported profiles: {supported}.") from exc


def recon_profile_names() -> tuple[str, ...]:
    """Return supported profile names in stable display order."""

    return tuple(PROFILES)
