"""Tests for the static Deep Recon preflight contract."""

from __future__ import annotations

import pytest

from bugslyce.project_pipeline import run_project_pipeline
from bugslyce.recon.deep_outputs import get_deep_recon_planned_outputs
from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline
from bugslyce.recon.deep_preflight import (
    PREFLIGHT_CATEGORIES,
    DeepReconPreflightRequirement,
    get_deep_recon_preflight_requirements,
    get_deep_recon_preflight_requirements_by_category,
    validate_deep_recon_preflight_requirements,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)
from bugslyce.recon.planner import build_recon_plan


def test_deep_preflight_requirements_are_static_deterministic_data() -> None:
    requirements = get_deep_recon_preflight_requirements()

    assert len(requirements) == 22
    assert [requirement.requirement_id for requirement in requirements] == [
        "deep-preflight-authorisation-declared",
        "deep-preflight-engagement-context-explicit",
        "deep-preflight-engagement-context-supported",
        "deep-preflight-target-in-scope",
        "deep-preflight-scope-rules-present",
        "deep-preflight-no-inferred-scope",
        "deep-preflight-target-control-confirmed",
        "deep-preflight-bounds-present",
        "deep-preflight-plan-valid",
        "deep-preflight-outputs-valid",
        "deep-preflight-method-classes-supported",
        "deep-preflight-no-form-submission",
        "deep-preflight-no-auth-testing",
        "deep-preflight-no-brute-force",
        "deep-preflight-no-browser-automation",
        "deep-preflight-no-javascript-execution",
        "deep-preflight-no-payload-injection",
        "deep-preflight-no-external-reporting",
        "deep-preflight-local-retention-warning",
        "deep-preflight-operator-confirmation",
        "deep-preflight-stop-on-ambiguous-authorisation",
        "deep-preflight-preserve-quick-standard",
    ]
    assert len({requirement.requirement_id for requirement in requirements}) == len(requirements)
    assert validate_deep_recon_preflight_requirements(requirements) == ()


def test_deep_preflight_covers_categories_and_severities() -> None:
    requirements = get_deep_recon_preflight_requirements()

    assert {requirement.category for requirement in requirements} == set(PREFLIGHT_CATEGORIES)
    assert {requirement.severity for requirement in requirements} == {
        "critical",
        "high",
    }
    assert all(requirement.blocking for requirement in requirements if requirement.severity == "critical")
    assert all(requirement.failure_message for requirement in requirements if requirement.blocking)
    assert all(requirement.safety_notes for requirement in requirements)


def test_deep_preflight_references_existing_steps_and_outputs() -> None:
    requirements = get_deep_recon_preflight_requirements()
    step_ids = {step.step_id for step in get_deep_recon_planned_pipeline()}
    output_ids = {output.output_id for output in get_deep_recon_planned_outputs()}

    assert any(
        "deep-01-scope-validation" in requirement.related_deep_step_ids
        for requirement in requirements
    )
    assert any(
        "deep-output-scope-safety-summary" in requirement.related_output_ids
        for requirement in requirements
    )
    for requirement in requirements:
        assert set(requirement.related_deep_step_ids).issubset(step_ids)
        assert set(requirement.related_output_ids).issubset(output_ids)


def test_deep_preflight_grouping_by_category_is_deterministic() -> None:
    grouped = get_deep_recon_preflight_requirements_by_category()

    assert tuple(grouped) == tuple(sorted(PREFLIGHT_CATEGORIES))
    assert grouped["authorisation"][0].requirement_id == (
        "deep-preflight-authorisation-declared"
    )
    assert {
        requirement.requirement_id
        for requirement in grouped["method_safety"]
    } == {
        "deep-preflight-method-classes-supported",
        "deep-preflight-no-form-submission",
        "deep-preflight-no-auth-testing",
        "deep-preflight-no-brute-force",
        "deep-preflight-no-browser-automation",
        "deep-preflight-no-javascript-execution",
        "deep-preflight-no-payload-injection",
    }


def test_deep_preflight_has_no_executable_command_shape_or_allowed_attack_claims() -> None:
    requirements = get_deep_recon_preflight_requirements()
    forbidden = (
        "deep is executable",
        "deep recon is executable",
        "deep-bounded is executable",
        "allows exploitation",
        "allows authentication testing",
        "allows brute force",
        "allows form submission",
        "allows browser automation",
        "allows JavaScript execution",
        "allows payload injection",
        "allows sqlmap",
        "allows hydra",
        "allows nuclei",
        "allows masscan",
        "allows password spraying",
        "allows credential stuffing",
        "allows external reporting",
        "permits exploitation",
        "permits authentication testing",
        "permits brute force",
        "permits form submission",
        "permits browser automation",
        "permits JavaScript execution",
        "permits payload injection",
        "permits external reporting",
    )

    for requirement in requirements:
        assert isinstance(requirement, DeepReconPreflightRequirement)
        assert not hasattr(requirement, "argv")
        assert not hasattr(requirement, "command")
        assert not hasattr(requirement, "command_preview")
        assert not hasattr(requirement, "execute")
        text = " ".join(
            (
                requirement.description,
                requirement.failure_message,
                *requirement.safety_notes,
            )
        ).casefold()
        assert all(term.casefold() not in text for term in forbidden)


def test_deep_preflight_validation_reports_contract_errors() -> None:
    broken = (
        DeepReconPreflightRequirement(
            requirement_id="deep-preflight-broken",
            name="Broken requirement",
            description="Synthetic invalid requirement claiming Deep is executable.",
            category="unknown",
            blocking=False,
            severity="critical",
            expected_evidence=(),
            failure_message="",
            related_deep_step_ids=("missing-step",),
            related_output_ids=("missing-output",),
            safety_notes=(),
        ),
    )

    errors = validate_deep_recon_preflight_requirements(broken)

    assert any("unknown category" in error for error in errors)
    assert any("critical but not blocking" in error for error in errors)
    assert any("has no safety notes" in error for error in errors)
    assert any("unknown Deep step" in error for error in errors)
    assert any("unknown Deep output" in error for error in errors)
    assert any("forbidden wording" in error for error in errors)
    assert any("missing preflight category" in error for error in errors)
    assert any("no requirement protects deep-01-scope-validation" in error for error in errors)
    assert any(
        "no requirement protects deep-output-scope-safety-summary" in error
        for error in errors
    )


def test_deep_bounded_remains_non_executable_in_planner_and_pipeline(
    tmp_path,
) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope_file, tmp_path / "output", "deep-bounded")

    project_file = tmp_path / "bugslyce_project.json"
    project_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported project pipeline profile"):
        run_project_pipeline(project_file, "deep-bounded")


def test_deep_remains_unavailable_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False

    with pytest.raises(ReconModeUnavailable):
        resolve_executable_profile("deep")
