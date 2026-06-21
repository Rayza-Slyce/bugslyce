"""Tests for the internal recon mode registry."""

from __future__ import annotations

import pytest

from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    list_recon_modes,
    resolve_executable_profile,
)


def test_recon_mode_registry_has_deterministic_order() -> None:
    modes = list_recon_modes()

    assert [mode.mode_id for mode in modes] == ["quick", "standard", "deep"]
    assert [mode.display_name for mode in modes] == [
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
    ]


def test_quick_recon_is_available_and_maps_to_lab_safe_tiny() -> None:
    quick = get_recon_mode("quick")

    assert quick.mode_id == "quick"
    assert quick.display_name == "Quick Recon"
    assert quick.internal_profile == QUICK_RECON_PROFILE
    assert quick.internal_profile == "lab-safe-tiny"
    assert quick.status == "implemented"
    assert quick.is_available is True
    assert is_recon_mode_available("quick") is True
    assert resolve_executable_profile("quick") == "lab-safe-tiny"


def test_standard_recon_is_available_and_maps_to_standard_bounded() -> None:
    standard = get_recon_mode("standard")

    assert standard.mode_id == "standard"
    assert standard.display_name == "Standard Recon"
    assert standard.internal_profile == STANDARD_RECON_PROFILE
    assert standard.internal_profile == "standard-bounded"
    assert standard.status == "implemented"
    assert standard.is_available is True
    assert is_recon_mode_available("standard") is True
    assert "already-collected artefacts" in standard.purpose
    assert resolve_executable_profile("standard") == "standard-bounded"


def test_deep_recon_is_planned_and_unavailable() -> None:
    deep = get_recon_mode("deep")

    assert deep.mode_id == "deep"
    assert deep.display_name == "Deep Recon"
    assert deep.internal_profile == DEEP_RECON_PROFILE
    assert deep.internal_profile == "deep-correlation"
    assert deep.status == "planned"
    assert deep.is_available is False
    assert is_recon_mode_available("deep") is False

    with pytest.raises(
        ReconModeUnavailable,
        match="Deep Recon is planned but not implemented yet",
    ):
        resolve_executable_profile("deep")


def test_planned_modes_do_not_fall_back_to_quick() -> None:
    for mode_id in ("deep",):
        mode = get_recon_mode(mode_id)
        assert mode.internal_profile != QUICK_RECON_PROFILE
        with pytest.raises(ReconModeUnavailable):
            resolve_executable_profile(mode_id)


def test_standard_does_not_fall_back_to_quick() -> None:
    standard = get_recon_mode("standard")

    assert standard.internal_profile == STANDARD_RECON_PROFILE
    assert standard.internal_profile != QUICK_RECON_PROFILE
    assert resolve_executable_profile("standard") == STANDARD_RECON_PROFILE
