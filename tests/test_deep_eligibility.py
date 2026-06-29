"""Tests for pure Deep Recon eligibility evaluation."""

from __future__ import annotations

from dataclasses import asdict, replace

import pytest

from bugslyce.cli import main
from bugslyce.project_pipeline import run_project_pipeline
from bugslyce.recon.deep_eligibility import (
    SUPPORTED_DEEP_ENGAGEMENT_CONTEXTS,
    DeepReconEligibilityDecision,
    build_confirmed_deep_eligibility_input,
    build_default_blocked_deep_eligibility_input,
    evaluate_deep_recon_eligibility,
)
from bugslyce.recon.deep_preflight import get_deep_recon_preflight_requirements
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)
from bugslyce.recon.planner import build_recon_plan


def _reason_ids(decision: DeepReconEligibilityDecision) -> tuple[str, ...]:
    return tuple(reason.requirement_id for reason in decision.blocking_reasons)


def _walk_keys(value: object) -> tuple[str, ...]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys.extend(_walk_keys(nested))
    return tuple(keys)


def test_default_deep_eligibility_input_is_blocked() -> None:
    decision = evaluate_deep_recon_eligibility(
        build_default_blocked_deep_eligibility_input()
    )

    assert decision.eligible is False
    assert decision.status == "blocked"
    assert decision.warnings == ()
    assert "deep-preflight-authorisation-declared" in _reason_ids(decision)
    assert "deep-preflight-target-in-scope" in _reason_ids(decision)
    assert "deep-preflight-no-form-submission" in _reason_ids(decision)
    assert "deep-preflight-operator-confirmation" in _reason_ids(decision)


def test_confirmed_deep_eligibility_input_is_eligible() -> None:
    decision = evaluate_deep_recon_eligibility(
        build_confirmed_deep_eligibility_input(engagement_context="bug_bounty")
    )

    assert decision.eligible is True
    assert decision.status == "eligible"
    assert decision.blocking_reasons == ()
    assert decision.warnings == ()
    assert decision.checked_requirements == tuple(
        requirement.requirement_id
        for requirement in get_deep_recon_preflight_requirements()
    )


@pytest.mark.parametrize("context", ("", "unknown"))
def test_empty_or_unknown_engagement_context_blocks(context: str) -> None:
    decision = evaluate_deep_recon_eligibility(
        replace(build_confirmed_deep_eligibility_input(), engagement_context=context)
    )

    assert decision.eligible is False
    assert _reason_ids(decision) == ("deep-preflight-engagement-context-explicit",)


def test_unsupported_engagement_context_blocks() -> None:
    decision = evaluate_deep_recon_eligibility(
        replace(build_confirmed_deep_eligibility_input(), engagement_context="external_red_team")
    )

    assert decision.eligible is False
    assert _reason_ids(decision) == ("deep-preflight-engagement-context-supported",)


@pytest.mark.parametrize(
    ("field_name", "unsafe_value", "requirement_id"),
    (
        ("form_submission_required", True, "deep-preflight-no-form-submission"),
        ("authentication_testing_required", True, "deep-preflight-no-auth-testing"),
        ("brute_force_required", True, "deep-preflight-no-brute-force"),
        ("browser_automation_required", True, "deep-preflight-no-browser-automation"),
        ("javascript_execution_required", True, "deep-preflight-no-javascript-execution"),
        ("payload_injection_required", True, "deep-preflight-no-payload-injection"),
        (
            "automatic_external_reporting_required",
            True,
            "deep-preflight-no-external-reporting",
        ),
        ("scope_is_inferred", True, "deep-preflight-no-inferred-scope"),
        ("target_in_scope", False, "deep-preflight-target-in-scope"),
        ("scope_rules_present", False, "deep-preflight-scope-rules-present"),
        ("operator_confirmed_deep_intent", False, "deep-preflight-operator-confirmation"),
        ("local_retention_acknowledged", False, "deep-preflight-local-retention-warning"),
        ("planned_pipeline_valid", False, "deep-preflight-plan-valid"),
        ("planned_outputs_valid", False, "deep-preflight-outputs-valid"),
        ("method_classes_supported", False, "deep-preflight-method-classes-supported"),
        ("bounds_acknowledged", False, "deep-preflight-bounds-present"),
        ("target_control_confirmed", False, "deep-preflight-target-control-confirmed"),
        ("authorisation_declared", False, "deep-preflight-authorisation-declared"),
    ),
)
def test_deep_eligibility_blocks_individual_failed_facts(
    field_name: str,
    unsafe_value: bool,
    requirement_id: str,
) -> None:
    decision = evaluate_deep_recon_eligibility(
        replace(build_confirmed_deep_eligibility_input(), **{field_name: unsafe_value})
    )

    assert decision.eligible is False
    assert _reason_ids(decision) == (requirement_id,)


def test_deep_eligibility_exposes_supported_contexts() -> None:
    assert SUPPORTED_DEEP_ENGAGEMENT_CONTEXTS == (
        "ctf_lab",
        "bug_bounty",
        "internal_authorised",
    )
    for context in SUPPORTED_DEEP_ENGAGEMENT_CONTEXTS:
        decision = evaluate_deep_recon_eligibility(
            build_confirmed_deep_eligibility_input(engagement_context=context)
        )
        assert decision.eligible is True


def test_deep_eligibility_decision_is_deterministic_and_non_executable() -> None:
    first = evaluate_deep_recon_eligibility(build_default_blocked_deep_eligibility_input())
    second = evaluate_deep_recon_eligibility(build_default_blocked_deep_eligibility_input())

    assert first == second
    payload = asdict(first)
    assert payload["non_executable_guarantees"] == (
        "Deep Recon remains unavailable.",
        "`deep-bounded` is not an executable profile.",
        "No runtime collection is performed.",
        "No project files are read or written.",
        "No commands are executed.",
        "No output files are created.",
        "Quick and Standard mappings remain unchanged.",
    )
    keys = set(_walk_keys(payload))
    assert "argv" not in keys
    assert "command_preview" not in keys
    assert "execute" not in keys


def test_deep_eligibility_does_not_create_project_files(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    decision = evaluate_deep_recon_eligibility(
        build_confirmed_deep_eligibility_input()
    )

    assert decision.eligible is True
    assert list(tmp_path.iterdir()) == []


def test_deep_eligibility_has_no_cli_exposure(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-eligibility"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "invalid choice" in captured.err


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
