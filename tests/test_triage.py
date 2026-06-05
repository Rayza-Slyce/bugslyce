"""Tests for deterministic triage candidate generation."""

from __future__ import annotations

from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_generate_candidates_basic_saas() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    assert candidates
    assert len(candidates) < 25
    assert candidates[0].id == "CAND-0001"
    assert {candidate.candidate_type for candidate in candidates} >= {
        "auth_surface",
        "admin_surface",
        "environment_surface",
        "api_surface",
        "file_or_content_surface",
        "object_reference_review",
        "redirect_parameter_review",
        "technology_review",
        "manual_note_review",
        "low_signal_static",
    }


def test_auth_endpoints_create_auth_review_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    auth_candidates = [candidate for candidate in candidates if candidate.candidate_type == "auth_surface"]
    app_auth_candidates = [
        candidate for candidate in auth_candidates if candidate.affected_assets == ["app.example-bounty.test"]
    ]

    assert auth_candidates
    assert len(app_auth_candidates) == 1
    assert len(app_auth_candidates[0].affected_endpoints) > 1
    assert any("/login" in endpoint for endpoint in app_auth_candidates[0].affected_endpoints)
    assert any("/account" in endpoint for endpoint in app_auth_candidates[0].affected_endpoints)
    assert "manual review" in app_auth_candidates[0].title.lower()
    assert len(app_auth_candidates[0].evidence_ids) == len(app_auth_candidates[0].affected_endpoints)


def test_api_account_resource_path_does_not_create_auth_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    api_resource_url = "https://api.example-bounty.test/v1/accounts/1001/orders?order_id=5001"

    assert any(
        api_resource_url in endpoint
        for candidate in candidates
        if candidate.candidate_type == "object_reference_review"
        for endpoint in candidate.affected_endpoints
    )
    assert not any(
        api_resource_url in endpoint
        for candidate in candidates
        if candidate.candidate_type == "auth_surface"
        for endpoint in candidate.affected_endpoints
    )


def test_api_object_like_params_create_object_reference_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    object_candidates = [
        candidate for candidate in candidates if candidate.candidate_type == "object_reference_review"
    ]

    assert object_candidates
    assert any("tenant_id" in endpoint for candidate in object_candidates for endpoint in candidate.affected_endpoints)
    assert all("object reference" in candidate.title.lower() for candidate in object_candidates)


def test_redirect_like_params_create_redirect_parameter_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    redirect_candidates = [
        candidate for candidate in candidates if candidate.candidate_type == "redirect_parameter_review"
    ]

    assert redirect_candidates
    assert any("next=" in endpoint for candidate in redirect_candidates for endpoint in candidate.affected_endpoints)
    assert all("redirect-parameter" in candidate.title.lower() for candidate in redirect_candidates)


def test_static_cdn_assets_are_low_or_kill_switch() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    static_candidates = [candidate for candidate in candidates if candidate.candidate_type == "low_signal_static"]

    assert static_candidates
    assert all(candidate.priority in {"low", "kill_switch"} for candidate in static_candidates)
    assert any("static" in (candidate.kill_switch_guidance or "").lower() for candidate in static_candidates)


def test_grouped_endpoint_candidates_preserve_endpoints_and_evidence() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    grouped = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "object_reference_review"
        and candidate.affected_assets == ["app.example-bounty.test"]
    )

    assert len(grouped.affected_endpoints) == 3
    assert len(grouped.evidence_ids) == 3
    assert all(endpoint.startswith("https://app.example-bounty.test/") for endpoint in grouped.affected_endpoints)


def test_every_candidate_has_evidence_ids() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    evidence_ids = {item.id for item in state.evidence}

    assert all(candidate.evidence_ids for candidate in candidates)
    assert all(evidence_id in evidence_ids for candidate in candidates for evidence_id in candidate.evidence_ids)


def test_candidate_ids_are_stable_and_ordered() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    first = generate_candidates(state)
    second = generate_candidates(state)

    assert [candidate.id for candidate in first] == [f"CAND-{index:04d}" for index in range(1, len(first) + 1)]
    assert [candidate.id for candidate in first] == [candidate.id for candidate in second]
    assert [candidate.candidate_type for candidate in first] == [candidate.candidate_type for candidate in second]


def test_low_signal_demo_only_produces_low_or_kill_switch_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "boring_low_signal")
    candidates = generate_candidates(state)

    assert candidates
    assert all(candidate.priority in {"low", "kill_switch"} for candidate in candidates)
    assert not any(candidate.priority in {"high", "medium"} for candidate in candidates)


def test_duplicate_heavy_url_file_does_not_explode_candidates(tmp_path: Path) -> None:
    (tmp_path / "urls.txt").write_text(
        "\n".join(["https://app.example-bounty.test/account?user_id=1001"] * 25),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)

    assert len(state.endpoints) == 1
    assert len(candidates) == 2
    assert {candidate.candidate_type for candidate in candidates} == {
        "auth_surface",
        "object_reference_review",
    }


def test_generic_technology_review_candidates_are_low_priority() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    technology_candidates = [candidate for candidate in candidates if candidate.candidate_type == "technology_review"]

    assert technology_candidates
    assert all(candidate.priority == "low" for candidate in technology_candidates)
