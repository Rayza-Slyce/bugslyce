"""Tests for the static Deep Recon planned pipeline contract."""

from __future__ import annotations

from bugslyce.recon.deep_plan import (
    DeepReconPlannedStep,
    get_deep_recon_planned_pipeline,
    validate_deep_recon_planned_pipeline,
)
from bugslyce.recon.modes import (
    DEEP_RECON_CAPABILITY_CATEGORIES,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    ReconModeUnavailable,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
)


def test_deep_planned_pipeline_has_24_deterministic_steps() -> None:
    steps = get_deep_recon_planned_pipeline()

    assert len(steps) == 24
    assert [step.step_id for step in steps] == [
        "deep-01-scope-validation",
        "deep-02-tcp-service-discovery",
        "deep-03-service-version-enrichment",
        "deep-04-http-service-matrix",
        "deep-05-http-metadata-collection",
        "deep-06-common-metadata-discovery",
        "deep-07-baseline-content-discovery",
        "deep-08-discovered-path-follow-up",
        "deep-09-strong-signal-directory-selection",
        "deep-10-bounded-second-pass-content-discovery",
        "deep-11-shallow-same-origin-crawl",
        "deep-12-selected-html-body-fetch",
        "deep-13-same-origin-js-source-discovery",
        "deep-14-same-origin-js-source-text-collection",
        "deep-15-static-route-extraction",
        "deep-16-source-map-detection-collection",
        "deep-17-parameter-inventory",
        "deep-18-html-form-inventory",
        "deep-19-backup-config-source-exposure-checks",
        "deep-20-route-source-service-correlation",
        "deep-21-deep-investigation-threads",
        "deep-22-deep-manual-review-queue",
        "deep-23-deep-report-runbook-generation",
        "deep-24-evidence-pack-export",
    ]
    assert len({step.step_id for step in steps}) == 24
    assert validate_deep_recon_planned_pipeline(steps) == ()


def test_deep_planned_pipeline_marks_active_steps_as_bounded() -> None:
    steps = get_deep_recon_planned_pipeline()
    active_steps = [step for step in steps if step.active_collection]
    passive_steps = [step for step in steps if not step.active_collection]

    assert len(active_steps) == 12
    assert len(passive_steps) == 12
    assert all(step.uses_bounds for step in active_steps)
    assert all(step.safety_notes for step in active_steps)
    assert all(not step.uses_bounds for step in passive_steps)
    assert {
        "max_second_pass_directories",
        "max_second_pass_requests_per_directory",
        "max_requests_per_service",
        "request_timeout_seconds",
        "rate_limit_delay_seconds",
    }.issubset(
        set(
            next(
                step
                for step in active_steps
                if step.step_id == "deep-10-bounded-second-pass-content-discovery"
            ).uses_bounds
        )
    )
    assert {
        "max_crawl_depth",
        "max_crawl_pages",
        "max_redirects",
        "max_body_bytes",
        "request_timeout_seconds",
        "rate_limit_delay_seconds",
    }.issubset(
        set(
            next(
                step
                for step in active_steps
                if step.step_id == "deep-11-shallow-same-origin-crawl"
            ).uses_bounds
        )
    )


def test_deep_planned_pipeline_dependencies_and_categories_are_valid() -> None:
    steps = get_deep_recon_planned_pipeline()
    category_set = set(DEEP_RECON_CAPABILITY_CATEGORIES)
    seen: set[str] = set()

    for step in steps:
        assert step.capability_category in category_set
        assert all(dependency in seen for dependency in step.depends_on)
        seen.add(step.step_id)


def test_deep_planned_pipeline_has_no_executable_command_shape() -> None:
    steps = get_deep_recon_planned_pipeline()
    forbidden_method_terms = (
        "exploit",
        "authentication testing",
        "form submission",
        "browser automation",
        "javascript execution",
        "arbitrary command",
    )

    assert all(isinstance(step, DeepReconPlannedStep) for step in steps)
    for step in steps:
        assert not hasattr(step, "argv")
        assert not hasattr(step, "command")
        assert not hasattr(step, "command_preview")
        assert not hasattr(step, "execute")
        lowered_method = step.method_class.lower()
        assert all(term not in lowered_method for term in forbidden_method_terms)


def test_deep_pipeline_validation_reports_contract_errors() -> None:
    broken = (
        DeepReconPlannedStep(
            step_id="deep-99-broken",
            name="Broken active step",
            purpose="Synthetic invalid step for validation.",
            capability_category="unknown category",
            active_collection=True,
            method_class="local",
            uses_bounds=("not_a_bound",),
            planned_outputs=(),
            depends_on=("missing-step",),
            safety_notes=(),
        ),
    )

    errors = validate_deep_recon_planned_pipeline(broken)

    assert any("expected 24 steps" in error for error in errors)
    assert any("unknown capability category" in error for error in errors)
    assert any("unknown bound" in error for error in errors)
    assert any("active collection without safety notes" in error for error in errors)
    assert any("depends on unknown step" in error for error in errors)


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
