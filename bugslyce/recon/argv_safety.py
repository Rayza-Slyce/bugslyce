"""Shared argv safety checks for fixed recon command validators."""

from __future__ import annotations


def contains_ascii_control(value: str) -> bool:
    """Return True when a command argument contains a C0 control or DEL."""

    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def argv_control_character_errors(argv: list[str], *, label: str) -> list[str]:
    """Return deterministic validation errors for unsafe control characters."""

    if any(contains_ascii_control(value) for value in argv):
        return [f"{label} argv contains an unsafe control character."]
    return []
