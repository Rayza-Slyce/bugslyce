"""Tests for the internal recon mode registry."""

from __future__ import annotations

import pytest

from bugslyce.recon.modes import (
    DEEP_RECON_CAPABILITY_CATEGORIES,
    DEEP_RECON_PROFILE_CONTRACT,
    DEEP_RECON_PROFILE,
    DEEP_RECON_BOUNDS,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_deep_recon_profile_contract,
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


def test_deep_recon_is_available_and_maps_to_deep_bounded() -> None:
    deep = get_recon_mode("deep")

    assert deep.mode_id == "deep"
    assert deep.display_name == "Deep Recon"
    assert deep.internal_profile == DEEP_RECON_PROFILE
    assert deep.internal_profile == "deep-bounded"
    assert deep.status == "implemented"
    assert deep.is_available is True
    assert is_recon_mode_available("deep") is True
    assert "strict authorisation, scope, method, and rate limits" in deep.purpose
    assert resolve_executable_profile("deep") == "deep-bounded"


def test_deep_mode_does_not_fall_back_to_quick() -> None:
    mode = get_recon_mode("deep")
    assert mode.internal_profile != QUICK_RECON_PROFILE
    assert resolve_executable_profile("deep") == DEEP_RECON_PROFILE


def test_standard_does_not_fall_back_to_quick() -> None:
    standard = get_recon_mode("standard")

    assert standard.internal_profile == STANDARD_RECON_PROFILE
    assert standard.internal_profile != QUICK_RECON_PROFILE
    assert resolve_executable_profile("standard") == STANDARD_RECON_PROFILE


def test_deep_recon_profile_contract_is_bounded_and_executable() -> None:
    contract = get_deep_recon_profile_contract()

    assert contract is DEEP_RECON_PROFILE_CONTRACT
    assert contract.mode_name == "Deep Recon"
    assert contract.internal_profile == "deep-bounded"
    assert contract.availability == "implemented"
    assert contract.default_behaviour_status == "implemented, bounded, non-exploitative"
    assert contract.allowed_method_class == "GET/HEAD-style recon only"
    assert "aggressive evidence discovery" in contract.purpose
    assert contract.bounds is DEEP_RECON_BOUNDS
    assert contract.bounds.max_total_requests == 1500
    assert contract.bounds.max_requests_per_service == 400
    assert contract.bounds.max_second_pass_directories == 8
    assert contract.bounds.max_second_pass_requests_per_directory == 100
    assert contract.bounds.max_crawl_depth == 1
    assert contract.bounds.max_crawl_pages == 50
    assert contract.bounds.max_js_files == 50
    assert contract.bounds.max_source_files == 80
    assert contract.bounds.max_source_map_files == 10
    assert contract.bounds.max_body_bytes == 1_000_000
    assert contract.bounds.max_redirects == 5
    assert contract.bounds.request_timeout_seconds == 10
    assert contract.bounds.rate_limit_delay_seconds == 0.1
    assert contract.capability_categories == DEEP_RECON_CAPABILITY_CATEGORIES
    assert "expanded content discovery" in contract.capability_categories
    assert "strong-signal second-pass discovery" in contract.capability_categories
    assert "common metadata discovery" in contract.capability_categories
    assert "shallow same-origin crawl" in contract.capability_categories
    assert "selected body/source fetch" in contract.capability_categories
    assert "JavaScript/source text collection" in contract.capability_categories
    assert "static route extraction" in contract.capability_categories
    assert "parameter inventory" in contract.capability_categories
    assert "form inventory without submission" in contract.capability_categories
    assert "source map detection" in contract.capability_categories
    assert "backup/config/source exposure checks" in contract.capability_categories
    assert "service/route/source correlation" in contract.capability_categories
    assert "deep investigation threads" in contract.capability_categories
    assert "deep manual review queue" in contract.capability_categories
    assert "deep report/runbook output" in contract.capability_categories
    assert is_recon_mode_available("deep") is True
    assert resolve_executable_profile("deep") == DEEP_RECON_PROFILE
