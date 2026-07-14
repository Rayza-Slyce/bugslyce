"""Static Deep Recon scope and safety preflight contract.

The requirements in this module are descriptive contract data only. They do
not inspect projects, read files, write files, create outputs, run commands, or
make network requests.
"""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_outputs import get_deep_recon_planned_outputs
from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline


PREFLIGHT_CATEGORIES = (
    "authorisation",
    "scope",
    "engagement_context",
    "bounds",
    "target_control",
    "method_safety",
    "data_handling",
    "operator_confirmation",
)
PREFLIGHT_SEVERITIES = ("critical", "high", "medium")
CONTRACT_ONLY_NOTE = "Preflight contract only; Deep Recon remains bounded."


@dataclass(frozen=True)
class DeepReconPreflightRequirement:
    """One future Deep Recon preflight requirement as static contract data."""

    requirement_id: str
    name: str
    description: str
    category: str
    blocking: bool
    severity: str
    expected_evidence: tuple[str, ...]
    failure_message: str
    related_deep_step_ids: tuple[str, ...]
    related_output_ids: tuple[str, ...]
    safety_notes: tuple[str, ...]


DEEP_RECON_PREFLIGHT_REQUIREMENTS: tuple[DeepReconPreflightRequirement, ...] = (
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-authorisation-declared",
        name="Explicit authorisation declared",
        description="Future Deep execution must require an explicit authorised engagement declaration before any Deep collection.",
        category="authorisation",
        blocking=True,
        severity="critical",
        expected_evidence=("explicit authorised engagement context",),
        failure_message="Deep Recon requires explicit authorisation before it can proceed.",
        related_deep_step_ids=("deep-01-scope-validation",),
        related_output_ids=("deep-output-scope-safety-summary",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Stop if authorisation is ambiguous."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-engagement-context-explicit",
        name="Engagement context is explicit",
        description="Future Deep execution must not proceed when the engagement context is unknown.",
        category="engagement_context",
        blocking=True,
        severity="critical",
        expected_evidence=("engagement_context is ctf_lab, bug_bounty, or internal_authorised",),
        failure_message="Choose an explicit engagement context before Deep Recon.",
        related_deep_step_ids=("deep-01-scope-validation",),
        related_output_ids=("deep-output-scope-safety-summary",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Unknown context is insufficient for Deep Recon."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-engagement-context-supported",
        name="Engagement context is supported",
        description="Future Deep execution must be limited to supported authorised contexts.",
        category="engagement_context",
        blocking=True,
        severity="high",
        expected_evidence=("ctf_lab", "bug_bounty", "internal_authorised"),
        failure_message="Deep Recon requires CTF/lab, bug bounty, or internal authorised context.",
        related_deep_step_ids=("deep-01-scope-validation",),
        related_output_ids=("deep-output-scope-safety-summary",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not infer engagement type from target appearance."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-target-in-scope",
        name="Target explicitly in scope",
        description="Future Deep execution must require the requested target to be explicitly listed inside approved scope.",
        category="scope",
        blocking=True,
        severity="critical",
        expected_evidence=("target listed in approved scope",),
        failure_message="Deep Recon must stop because the target is not explicitly in scope.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-02-tcp-service-discovery"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-service-inventory"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Stop on out-of-scope targets."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-scope-rules-present",
        name="Scope rules available",
        description="A future runtime preflight must require local scope rules before any Deep collection.",
        category="scope",
        blocking=True,
        severity="critical",
        expected_evidence=("approved scope file or equivalent local scope rules",),
        failure_message="Deep Recon requires explicit local scope rules.",
        related_deep_step_ids=("deep-01-scope-validation",),
        related_output_ids=("deep-output-scope-safety-summary",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Scope rules must be reviewed before Deep planning."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-inferred-scope",
        name="No inferred scope",
        description="Future Deep execution must not rely on inferred scope from hostnames, banners, certificates, or redirects.",
        category="scope",
        blocking=True,
        severity="critical",
        expected_evidence=("explicit scope match rather than inferred scope",),
        failure_message="Deep Recon must stop when scope would be inferred rather than explicit.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-04-http-service-matrix"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-http-service-matrix"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not expand scope from observed metadata alone."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-target-control-confirmed",
        name="Target control boundary understood",
        description="Future Deep execution must require operator confirmation that target ownership or testing permission is understood.",
        category="target_control",
        blocking=True,
        severity="high",
        expected_evidence=("approved target ownership or permission context",),
        failure_message="Deep Recon requires target control or permission context before proceeding.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-05-http-metadata-collection"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-http-metadata"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not treat reachable services as authorised by default."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-bounds-present",
        name="Deep bounds loaded",
        description="Future Deep execution must require explicit finite request, timeout, crawl, redirect, and body-size bounds.",
        category="bounds",
        blocking=True,
        severity="critical",
        expected_evidence=("DeepReconBounds contract loaded",),
        failure_message="Deep Recon requires explicit DeepReconBounds before it can proceed.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-10-bounded-second-pass-content-discovery", "deep-11-shallow-same-origin-crawl"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-second-pass-content-discovery", "deep-output-shallow-crawl-routes"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Bounds must be finite and reviewed before future execution."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-plan-valid",
        name="Deep planned pipeline validates",
        description="Future Deep execution must require the planned 24-step pipeline contract to validate cleanly.",
        category="bounds",
        blocking=True,
        severity="critical",
        expected_evidence=("validate_deep_recon_planned_pipeline returns no errors",),
        failure_message="Deep Recon planned pipeline contract did not validate.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-23-deep-report-runbook-generation"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-report-section-set"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not run Deep from an invalid planned-pipeline contract."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-outputs-valid",
        name="Deep planned outputs validate",
        description="Future Deep execution must require the planned output and artefact taxonomy to validate cleanly.",
        category="bounds",
        blocking=True,
        severity="critical",
        expected_evidence=("validate_deep_recon_planned_outputs returns no errors",),
        failure_message="Deep Recon planned output taxonomy did not validate.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-24-evidence-pack-export"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-evidence-pack-manifest"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not create Deep outputs from an invalid taxonomy."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-method-classes-supported",
        name="Method classes are supported",
        description="Future Deep execution must reject unsupported method classes before collection.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("local validation, bounded service recon, GET/HEAD-style recon, offline correlation, or reporting only",),
        failure_message="Deep Recon planned method classes are outside the supported safety contract.",
        related_deep_step_ids=("deep-02-tcp-service-discovery", "deep-05-http-metadata-collection", "deep-20-route-source-service-correlation"),
        related_output_ids=("deep-output-service-inventory", "deep-output-http-metadata", "deep-output-route-source-service-correlation"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Only documented non-interactive method classes are allowed."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-form-submission",
        name="No form submission",
        description="Future Deep execution must keep HTML form handling to inventory only.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("form inventory without submission",),
        failure_message="Deep Recon must stop if form submission would be required.",
        related_deep_step_ids=("deep-18-html-form-inventory",),
        related_output_ids=("deep-output-form-inventory",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Forms may be inventoried only; do not submit them."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-auth-testing",
        name="No authentication testing",
        description="Future Deep execution must not attempt login, session, or authentication testing.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("manual-review-only auth-related observations",),
        failure_message="Deep Recon must stop if authentication testing would be required.",
        related_deep_step_ids=("deep-18-html-form-inventory", "deep-22-deep-manual-review-queue"),
        related_output_ids=("deep-output-form-inventory", "deep-output-manual-review-queue"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not attempt login, session, or authentication workflows."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-brute-force",
        name="No brute force",
        description="Future Deep execution must not include brute force, password spraying, credential stuffing, or unbounded guessing.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("bounded deterministic recon only",),
        failure_message="Deep Recon must stop if brute-force style behaviour would be required.",
        related_deep_step_ids=("deep-07-baseline-content-discovery", "deep-10-bounded-second-pass-content-discovery"),
        related_output_ids=("deep-output-baseline-content-discovery", "deep-output-second-pass-content-discovery"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not perform guessing or credential attacks."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-browser-automation",
        name="No browser automation",
        description="Future Deep execution must not use browser automation or application interaction.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("text-only same-origin source collection",),
        failure_message="Deep Recon must stop if browser automation would be required.",
        related_deep_step_ids=("deep-11-shallow-same-origin-crawl", "deep-14-same-origin-js-source-text-collection"),
        related_output_ids=("deep-output-shallow-crawl-routes", "deep-output-js-source-text"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Collect text only; do not drive a browser."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-javascript-execution",
        name="No JavaScript execution",
        description="Future Deep execution must collect JavaScript/source text only and must not execute client-side code.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("JavaScript/source text collection as text only",),
        failure_message="Deep Recon must stop if JavaScript execution would be required.",
        related_deep_step_ids=("deep-14-same-origin-js-source-text-collection", "deep-15-static-route-extraction"),
        related_output_ids=("deep-output-js-source-text", "deep-output-static-route-inventory"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not execute collected scripts."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-payload-injection",
        name="No payload injection",
        description="Future Deep execution must not inject payloads or perform write actions.",
        category="method_safety",
        blocking=True,
        severity="critical",
        expected_evidence=("GET/HEAD-style recon only",),
        failure_message="Deep Recon must stop if payload injection or write actions would be required.",
        related_deep_step_ids=("deep-19-backup-config-source-exposure-checks",),
        related_output_ids=("deep-output-backup-config-source-checks",),
        safety_notes=(CONTRACT_ONLY_NOTE, "No write actions or payload injection are allowed."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-no-external-reporting",
        name="No automatic external reporting",
        description="Future Deep execution must keep reporting local unless an operator manually shares output.",
        category="data_handling",
        blocking=True,
        severity="high",
        expected_evidence=("local-only report and evidence-pack handling",),
        failure_message="Deep Recon must not automatically report to third parties.",
        related_deep_step_ids=("deep-23-deep-report-runbook-generation", "deep-24-evidence-pack-export"),
        related_output_ids=("deep-output-report-section-set", "deep-output-evidence-pack-manifest"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Automatic external reporting must remain out of scope."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-local-retention-warning",
        name="Local retention warning acknowledged",
        description="Future Deep execution must require acknowledgement that Deep artefacts can contain sensitive target context.",
        category="data_handling",
        blocking=True,
        severity="high",
        expected_evidence=("operator acknowledges local retention warning",),
        failure_message="Acknowledge local retention and sharing cautions before Deep Recon.",
        related_deep_step_ids=("deep-12-selected-html-body-fetch", "deep-24-evidence-pack-export"),
        related_output_ids=("deep-output-selected-body-text", "deep-output-evidence-pack-manifest"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Keep Deep artefacts local and review before sharing."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-operator-confirmation",
        name="Operator confirms Deep intent",
        description="Future Deep execution must require explicit operator confirmation that Deep mode is intended.",
        category="operator_confirmation",
        blocking=True,
        severity="critical",
        expected_evidence=("operator explicitly confirms Deep mode intent",),
        failure_message="Confirm Deep mode intent before any future Deep execution.",
        related_deep_step_ids=("deep-01-scope-validation",),
        related_output_ids=("deep-output-scope-safety-summary",),
        safety_notes=(CONTRACT_ONLY_NOTE, "Do not start Deep from accidental mode selection."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-stop-on-ambiguous-authorisation",
        name="Stop on ambiguous authorisation",
        description="Future Deep execution must stop when authorisation, scope, or method permission is ambiguous.",
        category="authorisation",
        blocking=True,
        severity="critical",
        expected_evidence=("clear authorisation and method permission",),
        failure_message="Deep Recon must stop because authorisation or method permission is ambiguous.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-22-deep-manual-review-queue"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-manual-review-queue"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Ambiguity must fail closed."),
    ),
    DeepReconPreflightRequirement(
        requirement_id="deep-preflight-preserve-quick-standard",
        name="Preserve Quick and Standard behaviour",
        description="Future Deep work must not make Quick or Standard more aggressive.",
        category="operator_confirmation",
        blocking=True,
        severity="high",
        expected_evidence=("tests proving Quick and Standard behaviour remain unchanged",),
        failure_message="Deep changes must not alter Quick or Standard behaviour.",
        related_deep_step_ids=("deep-01-scope-validation", "deep-23-deep-report-runbook-generation"),
        related_output_ids=("deep-output-scope-safety-summary", "deep-output-report-section-set"),
        safety_notes=(CONTRACT_ONLY_NOTE, "Deep gates must preserve existing mode boundaries."),
    ),
)


def get_deep_recon_preflight_requirements() -> tuple[DeepReconPreflightRequirement, ...]:
    """Return static Deep Recon preflight requirement contract data."""

    return DEEP_RECON_PREFLIGHT_REQUIREMENTS


def get_deep_recon_preflight_requirements_by_category() -> dict[str, tuple[DeepReconPreflightRequirement, ...]]:
    """Group planned Deep preflight requirements by category."""

    grouped: dict[str, list[DeepReconPreflightRequirement]] = {}
    for requirement in DEEP_RECON_PREFLIGHT_REQUIREMENTS:
        grouped.setdefault(requirement.category, []).append(requirement)
    return {
        category: tuple(requirements)
        for category, requirements in sorted(grouped.items())
    }


def validate_deep_recon_preflight_requirements(
    requirements: tuple[DeepReconPreflightRequirement, ...],
) -> tuple[str, ...]:
    """Validate Deep preflight contract data without inspecting a project."""

    errors: list[str] = []
    pipeline_step_ids = {step.step_id for step in get_deep_recon_planned_pipeline()}
    output_ids = {output.output_id for output in get_deep_recon_planned_outputs()}
    seen: set[str] = set()
    covered_categories: set[str] = set()
    forbidden_executable_claims = (
        "deep is executable",
        "deep recon is executable",
        "deep-bounded is executable",
    )
    forbidden_allowed_behaviours = (
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
        if requirement.requirement_id in seen:
            errors.append(f"duplicate requirement id: {requirement.requirement_id}")
        seen.add(requirement.requirement_id)

        if requirement.category not in PREFLIGHT_CATEGORIES:
            errors.append(
                f"{requirement.requirement_id} has unknown category: "
                f"{requirement.category}"
            )
        else:
            covered_categories.add(requirement.category)

        if requirement.severity not in PREFLIGHT_SEVERITIES:
            errors.append(
                f"{requirement.requirement_id} has unknown severity: "
                f"{requirement.severity}"
            )
        if requirement.severity == "critical" and not requirement.blocking:
            errors.append(f"{requirement.requirement_id} is critical but not blocking")
        if requirement.blocking and not requirement.failure_message.strip():
            errors.append(f"{requirement.requirement_id} is blocking without failure message")
        if not requirement.safety_notes:
            errors.append(f"{requirement.requirement_id} has no safety notes")

        for step_id in requirement.related_deep_step_ids:
            if step_id not in pipeline_step_ids:
                errors.append(f"{requirement.requirement_id} references unknown Deep step: {step_id}")
        for output_id in requirement.related_output_ids:
            if output_id not in output_ids:
                errors.append(f"{requirement.requirement_id} references unknown Deep output: {output_id}")

        text = " ".join(
            (
                requirement.description,
                requirement.failure_message,
                *requirement.safety_notes,
            )
        ).casefold()
        for forbidden in (*forbidden_executable_claims, *forbidden_allowed_behaviours):
            if forbidden.casefold() in text:
                errors.append(
                    f"{requirement.requirement_id} contains forbidden wording: "
                    f"{forbidden}"
                )

    missing_categories = set(PREFLIGHT_CATEGORIES) - covered_categories
    for category in sorted(missing_categories):
        errors.append(f"missing preflight category: {category}")

    if not any(
        "deep-01-scope-validation" in requirement.related_deep_step_ids
        for requirement in requirements
    ):
        errors.append("no requirement protects deep-01-scope-validation")
    if not any(
        "deep-output-scope-safety-summary" in requirement.related_output_ids
        for requirement in requirements
    ):
        errors.append("no requirement protects deep-output-scope-safety-summary")

    return tuple(errors)
