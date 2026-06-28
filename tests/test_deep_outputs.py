"""Tests for the static Deep Recon planned output taxonomy."""

from __future__ import annotations

from bugslyce.recon.deep_outputs import (
    DeepReconPlannedOutput,
    get_deep_recon_planned_outputs,
    get_deep_recon_planned_outputs_by_step,
    validate_deep_recon_planned_outputs,
)
from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)


def test_deep_planned_outputs_are_static_deterministic_data() -> None:
    outputs = get_deep_recon_planned_outputs()

    assert len(outputs) == 25
    assert [output.output_id for output in outputs] == [
        "deep-output-scope-safety-summary",
        "deep-output-service-inventory",
        "deep-output-service-version-context",
        "deep-output-http-service-matrix",
        "deep-output-http-metadata",
        "deep-output-common-metadata",
        "deep-output-baseline-content-discovery",
        "deep-output-discovered-path-context",
        "deep-output-strong-signal-directory-set",
        "deep-output-second-pass-content-discovery",
        "deep-output-shallow-crawl-routes",
        "deep-output-selected-body-text",
        "deep-output-js-source-reference-inventory",
        "deep-output-js-source-text",
        "deep-output-static-route-inventory",
        "deep-output-source-map-context",
        "deep-output-parameter-inventory",
        "deep-output-form-inventory",
        "deep-output-backup-config-source-checks",
        "deep-output-route-source-service-correlation",
        "deep-output-investigation-threads",
        "deep-output-manual-review-queue",
        "deep-output-report-section-set",
        "deep-output-runbook-section-set",
        "deep-output-evidence-pack-manifest",
    ]
    assert len({output.output_id for output in outputs}) == len(outputs)
    assert validate_deep_recon_planned_outputs(outputs) == ()


def test_deep_outputs_cover_every_planned_pipeline_step() -> None:
    steps = get_deep_recon_planned_pipeline()
    outputs = get_deep_recon_planned_outputs()
    output_ids = {output.output_id for output in outputs}
    produced_by_step = {output.producer_step_id for output in outputs}

    assert {step.step_id for step in steps} == produced_by_step
    for step in steps:
        assert step.planned_outputs
        assert set(step.planned_outputs).issubset(output_ids)
    assert output_ids == {
        output_id
        for step in steps
        for output_id in step.planned_outputs
    }


def test_deep_output_producers_and_consumers_are_valid_and_forward_only() -> None:
    steps = get_deep_recon_planned_pipeline()
    outputs = get_deep_recon_planned_outputs()
    step_order = {step.step_id: index for index, step in enumerate(steps)}

    for output in outputs:
        assert output.producer_step_id in step_order
        producer_order = step_order[output.producer_step_id]
        for consumer_step_id in output.consumed_by_step_ids:
            assert consumer_step_id in step_order
            assert step_order[consumer_step_id] > producer_order

    evidence_pack = next(
        output
        for output in outputs
        if output.output_id == "deep-output-evidence-pack-manifest"
    )
    assert evidence_pack.output_kind == "export_manifest"
    assert evidence_pack.consumed_by_step_ids == ()


def test_deep_output_kinds_sensitivity_and_retention_are_explicit() -> None:
    outputs = get_deep_recon_planned_outputs()

    assert {output.output_kind for output in outputs} == {
        "evidence",
        "index",
        "correlation",
        "queue",
        "report_section",
        "runbook_section",
        "export_manifest",
    }
    assert {output.sensitivity for output in outputs} == {"medium", "high"}
    assert all(output.retention_note for output in outputs if output.contains_target_data)
    assert all(output.safety_notes for output in outputs if output.sensitivity == "high")


def test_deep_outputs_do_not_claim_confirmed_or_executable_behaviour() -> None:
    outputs = get_deep_recon_planned_outputs()
    forbidden = (
        "confirmed vulnerability",
        "confirmed vulnerabilities",
        "performs exploitation",
        "performs authentication testing",
        "performs brute force",
        "performs form submission",
        "performs browser automation",
        "performs JavaScript execution",
        "performs payload injection",
        "performs external reporting",
        "runs sqlmap",
        "runs hydra",
        "runs nuclei",
        "runs masscan",
    )

    for output in outputs:
        assert isinstance(output, DeepReconPlannedOutput)
        assert not hasattr(output, "argv")
        assert not hasattr(output, "command")
        assert not hasattr(output, "command_preview")
        assert not hasattr(output, "execute")
        text = " ".join((output.description, *output.safety_notes)).casefold()
        assert all(term.casefold() not in text for term in forbidden)


def test_deep_outputs_group_by_producer_step() -> None:
    grouped = get_deep_recon_planned_outputs_by_step()

    assert grouped["deep-02-tcp-service-discovery"][0].output_id == (
        "deep-output-service-inventory"
    )
    assert {
        output.output_id
        for output in grouped["deep-23-deep-report-runbook-generation"]
    } == {
        "deep-output-report-section-set",
        "deep-output-runbook-section-set",
    }
    assert grouped["deep-24-evidence-pack-export"][0].output_id == (
        "deep-output-evidence-pack-manifest"
    )


def test_deep_output_validation_reports_contract_errors() -> None:
    broken = (
        DeepReconPlannedOutput(
            output_id="deep-output-broken",
            name="Broken output",
            description="Synthetic invalid output with confirmed vulnerability wording.",
            output_kind="unknown",
            producer_step_id="missing-producer",
            consumed_by_step_ids=("missing-consumer",),
            sensitivity="unknown",
            contains_target_data=True,
            retention_note="",
            safety_notes=(),
        ),
    )

    errors = validate_deep_recon_planned_outputs(broken)

    assert any("unknown output kind" in error for error in errors)
    assert any("unknown sensitivity" in error for error in errors)
    assert any("unknown producer step" in error for error in errors)
    assert any("unknown consumer step" in error for error in errors)
    assert any("without retention note" in error for error in errors)
    assert any("forbidden claim" in error for error in errors)
    assert any("planned pipeline step has no output" in error for error in errors)


def test_deep_remains_unavailable_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False

    try:
        resolve_executable_profile("deep")
    except ReconModeUnavailable:
        pass
    else:
        raise AssertionError("Deep Recon must remain unavailable")
