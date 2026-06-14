"""Tests for centralized UTC metadata timestamps."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bugslyce.time_utils import format_utc_iso, utc_now_iso


FIXED_UTC = datetime(2026, 6, 14, 13, 45, 12, 987654, tzinfo=timezone.utc)


def test_utc_now_iso_uses_injected_clock_and_trailing_z() -> None:
    assert utc_now_iso(lambda: FIXED_UTC) == "2026-06-14T13:45:12Z"


def test_format_utc_iso_normalizes_offset_and_drops_fractional_seconds() -> None:
    offset_value = datetime(
        2026,
        6,
        14,
        14,
        45,
        12,
        111222,
        tzinfo=timezone(timedelta(hours=1)),
    )

    assert format_utc_iso(offset_value) == "2026-06-14T13:45:12Z"


def test_format_utc_iso_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_utc_iso(datetime(2026, 6, 14, 13, 45, 12))
