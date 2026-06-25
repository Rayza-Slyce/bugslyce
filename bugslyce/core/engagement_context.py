"""Engagement context labels and normalisation."""

from __future__ import annotations


UNKNOWN_CONTEXT = "unknown"
CTF_LAB_CONTEXT = "ctf_lab"
BUG_BOUNTY_CONTEXT = "bug_bounty"
INTERNAL_AUTHORISED_CONTEXT = "internal_authorised"

ENGAGEMENT_CONTEXT_LABELS = {
    UNKNOWN_CONTEXT: "Unknown / not specified",
    CTF_LAB_CONTEXT: "CTF / learning lab",
    BUG_BOUNTY_CONTEXT: "Bug bounty",
    INTERNAL_AUTHORISED_CONTEXT: "Internal authorised assessment",
}
ALLOWED_ENGAGEMENT_CONTEXTS = tuple(ENGAGEMENT_CONTEXT_LABELS)
ENGAGEMENT_CONTEXT_CHOICE_ALIASES = {
    "": UNKNOWN_CONTEXT,
    "1": UNKNOWN_CONTEXT,
    "unknown": UNKNOWN_CONTEXT,
    "unspecified": UNKNOWN_CONTEXT,
    "not specified": UNKNOWN_CONTEXT,
    "default": UNKNOWN_CONTEXT,
    "2": CTF_LAB_CONTEXT,
    "ctf": CTF_LAB_CONTEXT,
    "lab": CTF_LAB_CONTEXT,
    "ctf_lab": CTF_LAB_CONTEXT,
    "ctf-lab": CTF_LAB_CONTEXT,
    "tryhackme": CTF_LAB_CONTEXT,
    "thm": CTF_LAB_CONTEXT,
    "3": BUG_BOUNTY_CONTEXT,
    "bug": BUG_BOUNTY_CONTEXT,
    "bounty": BUG_BOUNTY_CONTEXT,
    "bug bounty": BUG_BOUNTY_CONTEXT,
    "bug_bounty": BUG_BOUNTY_CONTEXT,
    "bug-bounty": BUG_BOUNTY_CONTEXT,
    "bb": BUG_BOUNTY_CONTEXT,
    "4": INTERNAL_AUTHORISED_CONTEXT,
    "internal": INTERNAL_AUTHORISED_CONTEXT,
    "internal authorised": INTERNAL_AUTHORISED_CONTEXT,
    "internal authorized": INTERNAL_AUTHORISED_CONTEXT,
    "internal_authorised": INTERNAL_AUTHORISED_CONTEXT,
    "internal_authorized": INTERNAL_AUTHORISED_CONTEXT,
    "authorised": INTERNAL_AUTHORISED_CONTEXT,
    "authorized": INTERNAL_AUTHORISED_CONTEXT,
}


def normalise_engagement_context(value: str | None) -> str:
    """Return a supported engagement context, falling back to unknown."""

    if not isinstance(value, str):
        return UNKNOWN_CONTEXT
    normalised = value.strip().lower().replace("-", "_")
    return normalised if normalised in ENGAGEMENT_CONTEXT_LABELS else UNKNOWN_CONTEXT


def engagement_context_label(value: str | None) -> str:
    """Return the user-facing engagement context label."""

    return ENGAGEMENT_CONTEXT_LABELS[normalise_engagement_context(value)]


def parse_engagement_context_choice(value: str | None) -> str | None:
    """Parse an interactive context choice, returning None for invalid input."""

    if value is None:
        return UNKNOWN_CONTEXT
    cleaned = " ".join(value.strip().lower().split())
    if cleaned in ENGAGEMENT_CONTEXT_CHOICE_ALIASES:
        return ENGAGEMENT_CONTEXT_CHOICE_ALIASES[cleaned]
    underscored = cleaned.replace("-", "_")
    return ENGAGEMENT_CONTEXT_CHOICE_ALIASES.get(underscored)
