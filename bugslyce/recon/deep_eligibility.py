"""Pure Deep Recon eligibility evaluation from explicit operator facts.

This module does not inspect projects, read files, write files, run commands,
create outputs, call the runtime planner, or make network requests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from bugslyce.core.engagement_context import (
    BUG_BOUNTY_CONTEXT,
    CTF_LAB_CONTEXT,
    INTERNAL_AUTHORISED_CONTEXT,
    UNKNOWN_CONTEXT,
    normalise_engagement_context,
)
from bugslyce.recon.deep_preflight import (
    DeepReconPreflightRequirement,
    get_deep_recon_preflight_requirements,
)


SUPPORTED_DEEP_ENGAGEMENT_CONTEXTS = (
    CTF_LAB_CONTEXT,
    BUG_BOUNTY_CONTEXT,
    INTERNAL_AUTHORISED_CONTEXT,
)
DEEP_ELIGIBILITY_GUARANTEES = (
    "Deep Recon is available only through the bounded deep-bounded profile.",
    "`deep-bounded` remains bounded and scope-conscious.",
    "This eligibility renderer performs no runtime collection.",
    "No project files are read or written.",
    "No commands are executed.",
    "No output files are created.",
    "Quick and Standard mappings remain unchanged.",
)


@dataclass(frozen=True)
class DeepReconEligibilityInput:
    """Explicit operator-provided facts for future Deep gating."""

    authorisation_declared: bool
    engagement_context: str
    target_in_scope: bool
    scope_rules_present: bool
    scope_is_inferred: bool
    target_control_confirmed: bool
    bounds_acknowledged: bool
    planned_pipeline_valid: bool
    planned_outputs_valid: bool
    method_classes_supported: bool
    form_submission_required: bool
    authentication_testing_required: bool
    brute_force_required: bool
    browser_automation_required: bool
    javascript_execution_required: bool
    payload_injection_required: bool
    automatic_external_reporting_required: bool
    local_retention_acknowledged: bool
    operator_confirmed_deep_intent: bool


@dataclass(frozen=True)
class DeepReconEligibilityReason:
    """One eligibility blocker or warning tied to a preflight requirement."""

    requirement_id: str
    name: str
    severity: str
    message: str


@dataclass(frozen=True)
class DeepReconEligibilityDecision:
    """Deterministic Deep eligibility decision."""

    eligible: bool
    status: str
    blocking_reasons: tuple[DeepReconEligibilityReason, ...]
    warnings: tuple[DeepReconEligibilityReason, ...]
    checked_requirements: tuple[str, ...]
    non_executable_guarantees: tuple[str, ...]


def build_default_blocked_deep_eligibility_input() -> DeepReconEligibilityInput:
    """Return a conservative all-fail Deep eligibility input."""

    return DeepReconEligibilityInput(
        authorisation_declared=False,
        engagement_context=UNKNOWN_CONTEXT,
        target_in_scope=False,
        scope_rules_present=False,
        scope_is_inferred=True,
        target_control_confirmed=False,
        bounds_acknowledged=False,
        planned_pipeline_valid=False,
        planned_outputs_valid=False,
        method_classes_supported=False,
        form_submission_required=True,
        authentication_testing_required=True,
        brute_force_required=True,
        browser_automation_required=True,
        javascript_execution_required=True,
        payload_injection_required=True,
        automatic_external_reporting_required=True,
        local_retention_acknowledged=False,
        operator_confirmed_deep_intent=False,
    )


def build_confirmed_deep_eligibility_input(
    *,
    engagement_context: str = CTF_LAB_CONTEXT,
) -> DeepReconEligibilityInput:
    """Return an explicit positive Deep eligibility input for tests and future callers."""

    return DeepReconEligibilityInput(
        authorisation_declared=True,
        engagement_context=engagement_context,
        target_in_scope=True,
        scope_rules_present=True,
        scope_is_inferred=False,
        target_control_confirmed=True,
        bounds_acknowledged=True,
        planned_pipeline_valid=True,
        planned_outputs_valid=True,
        method_classes_supported=True,
        form_submission_required=False,
        authentication_testing_required=False,
        brute_force_required=False,
        browser_automation_required=False,
        javascript_execution_required=False,
        payload_injection_required=False,
        automatic_external_reporting_required=False,
        local_retention_acknowledged=True,
        operator_confirmed_deep_intent=True,
    )


def evaluate_deep_recon_eligibility(
    input_data: DeepReconEligibilityInput,
) -> DeepReconEligibilityDecision:
    """Evaluate explicit Deep eligibility facts without runtime inspection."""

    requirements = get_deep_recon_preflight_requirements()
    requirement_by_id = {
        requirement.requirement_id: requirement
        for requirement in requirements
    }
    blocking: list[DeepReconEligibilityReason] = []

    def add(requirement_id: str) -> None:
        blocking.append(_reason(requirement_by_id[requirement_id]))

    if not input_data.authorisation_declared:
        add("deep-preflight-authorisation-declared")

    cleaned_context = input_data.engagement_context.strip() if isinstance(input_data.engagement_context, str) else ""
    canonical_input_context = cleaned_context.lower().replace("-", "_")
    context = normalise_engagement_context(cleaned_context)
    if not cleaned_context or canonical_input_context == UNKNOWN_CONTEXT:
        add("deep-preflight-engagement-context-explicit")
    elif context not in SUPPORTED_DEEP_ENGAGEMENT_CONTEXTS:
        add("deep-preflight-engagement-context-supported")

    if not input_data.target_in_scope:
        add("deep-preflight-target-in-scope")
    if not input_data.scope_rules_present:
        add("deep-preflight-scope-rules-present")
    if input_data.scope_is_inferred:
        add("deep-preflight-no-inferred-scope")
    if not input_data.target_control_confirmed:
        add("deep-preflight-target-control-confirmed")
    if not input_data.bounds_acknowledged:
        add("deep-preflight-bounds-present")
    if not input_data.planned_pipeline_valid:
        add("deep-preflight-plan-valid")
    if not input_data.planned_outputs_valid:
        add("deep-preflight-outputs-valid")
    if not input_data.method_classes_supported:
        add("deep-preflight-method-classes-supported")
    if input_data.form_submission_required:
        add("deep-preflight-no-form-submission")
    if input_data.authentication_testing_required:
        add("deep-preflight-no-auth-testing")
    if input_data.brute_force_required:
        add("deep-preflight-no-brute-force")
    if input_data.browser_automation_required:
        add("deep-preflight-no-browser-automation")
    if input_data.javascript_execution_required:
        add("deep-preflight-no-javascript-execution")
    if input_data.payload_injection_required:
        add("deep-preflight-no-payload-injection")
    if input_data.automatic_external_reporting_required:
        add("deep-preflight-no-external-reporting")
    if not input_data.local_retention_acknowledged:
        add("deep-preflight-local-retention-warning")
    if not input_data.operator_confirmed_deep_intent:
        add("deep-preflight-operator-confirmation")

    eligible = not blocking
    return DeepReconEligibilityDecision(
        eligible=eligible,
        status="eligible" if eligible else "blocked",
        blocking_reasons=tuple(blocking),
        warnings=(),
        checked_requirements=tuple(requirement.requirement_id for requirement in requirements),
        non_executable_guarantees=DEEP_ELIGIBILITY_GUARANTEES,
    )


def render_deep_recon_eligibility_markdown(
    decision: DeepReconEligibilityDecision,
) -> str:
    """Render a deterministic Markdown Deep eligibility decision."""

    lines = [
        "# Deep Recon Eligibility",
        "",
        f"- Status: `{decision.status}`",
        f"- Eligible: `{str(decision.eligible).lower()}`",
        f"- Blocking reasons: {len(decision.blocking_reasons)}",
        f"- Warnings: {len(decision.warnings)}",
        "",
        "## Blocking Reasons",
        "",
    ]
    if not decision.blocking_reasons:
        lines.append("- None.")
    else:
        for reason in decision.blocking_reasons:
            lines.extend(
                [
                    f"- `{reason.requirement_id}`: {reason.name}",
                    f"  - Severity: `{reason.severity}`",
                    f"  - Message: {reason.message}",
                ]
            )

    lines.extend(["", "## Warnings", ""])
    if not decision.warnings:
        lines.append("- None.")
    else:
        for warning in decision.warnings:
            lines.extend(
                [
                    f"- `{warning.requirement_id}`: {warning.name}",
                    f"  - Severity: `{warning.severity}`",
                    f"  - Message: {warning.message}",
                ]
            )

    lines.extend(
        [
            "",
            "## Checked Requirements",
            "",
            f"- Count: {len(decision.checked_requirements)}",
        ]
    )
    lines.extend(f"- `{requirement_id}`" for requirement_id in decision.checked_requirements)

    lines.extend(["", "## Non-Executable Guarantees", ""])
    lines.extend(f"- {guarantee}" for guarantee in decision.non_executable_guarantees)
    lines.append("")
    return "\n".join(lines)


def export_deep_recon_eligibility_json(
    decision: DeepReconEligibilityDecision,
) -> dict[str, object]:
    """Return a deterministic JSON-serialisable eligibility payload."""

    return {
        "schema_version": 1,
        "eligible": decision.eligible,
        "status": decision.status,
        "blocking_reasons": [
            asdict(reason)
            for reason in decision.blocking_reasons
        ],
        "warnings": [
            asdict(warning)
            for warning in decision.warnings
        ],
        "checked_requirements": list(decision.checked_requirements),
        "non_executable_guarantees": list(decision.non_executable_guarantees),
    }


def _reason(requirement: DeepReconPreflightRequirement) -> DeepReconEligibilityReason:
    return DeepReconEligibilityReason(
        requirement_id=requirement.requirement_id,
        name=requirement.name,
        severity=requirement.severity,
        message=requirement.failure_message,
    )
