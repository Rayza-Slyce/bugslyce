"""Engagement context labels and normalisation."""

from __future__ import annotations


UNKNOWN_CONTEXT = "unknown"
CTF_LAB_CONTEXT = "ctf_lab"
BUG_BOUNTY_CONTEXT = "bug_bounty"
INTERNAL_AUTHORISED_CONTEXT = "internal_authorised"

ENGAGEMENT_CONTEXT_LABELS = {
    UNKNOWN_CONTEXT: "Unknown / not specified",
    CTF_LAB_CONTEXT: "CTF / lab / TryHackMe",
    BUG_BOUNTY_CONTEXT: "Bug bounty",
    INTERNAL_AUTHORISED_CONTEXT: "Internal authorised assessment",
}
ALLOWED_ENGAGEMENT_CONTEXTS = tuple(ENGAGEMENT_CONTEXT_LABELS)


def normalise_engagement_context(value: str | None) -> str:
    """Return a supported engagement context, falling back to unknown."""

    if not isinstance(value, str):
        return UNKNOWN_CONTEXT
    normalised = value.strip().lower().replace("-", "_")
    return normalised if normalised in ENGAGEMENT_CONTEXT_LABELS else UNKNOWN_CONTEXT


def engagement_context_label(value: str | None) -> str:
    """Return the user-facing engagement context label."""

    return ENGAGEMENT_CONTEXT_LABELS[normalise_engagement_context(value)]
