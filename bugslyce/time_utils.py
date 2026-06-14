"""Central UTC timestamp helpers for BugSlyce metadata."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone


Clock = Callable[[], datetime]


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def utc_now_iso(clock: Clock | None = None) -> str:
    """Return a seconds-precision ISO-8601 UTC timestamp with trailing Z."""

    return format_utc_iso((clock or utc_now)())


def format_utc_iso(value: datetime) -> str:
    """Normalize a datetime to seconds-precision UTC with trailing Z."""

    if value.tzinfo is None:
        raise ValueError("Timestamp datetime must be timezone-aware.")
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")
