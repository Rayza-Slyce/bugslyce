"""Static Deep Recon readiness summary rendering.

This renderer consumes only Deep Recon static contract data. It does not
inspect projects, read files, write files, create outputs, run commands, call
the runtime planner, or make network requests.
"""

from __future__ import annotations

from dataclasses import fields

from bugslyce.recon.deep_outputs import (
    get_deep_recon_planned_outputs,
    validate_deep_recon_planned_outputs,
)
from bugslyce.recon.deep_plan import (
    get_deep_recon_planned_pipeline,
    validate_deep_recon_planned_pipeline,
)
from bugslyce.recon.deep_preflight import (
    get_deep_recon_preflight_requirements,
    validate_deep_recon_preflight_requirements,
)
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    get_deep_recon_profile_contract,
)


def build_deep_recon_readiness_snapshot() -> dict[str, object]:
    """Return a deterministic JSON-serialisable Deep readiness snapshot."""

    contract = get_deep_recon_profile_contract()
    bounds = contract.bounds
    steps = get_deep_recon_planned_pipeline()
    outputs = get_deep_recon_planned_outputs()
    requirements = get_deep_recon_preflight_requirements()
    pipeline_errors = validate_deep_recon_planned_pipeline(steps)
    output_errors = validate_deep_recon_planned_outputs(outputs)
    preflight_errors = validate_deep_recon_preflight_requirements(requirements)

    active_steps = tuple(step for step in steps if step.active_collection)
    passive_steps = tuple(step for step in steps if not step.active_collection)
    blocking_requirements = tuple(requirement for requirement in requirements if requirement.blocking)

    return {
        "schema_version": 1,
        "status": {
            "deep_available": get_recon_mode("deep").is_available,
            "deep_executable": get_recon_mode("deep").is_available,
            "deep_status": contract.availability,
            "summary": "Deep Recon is available as bounded deep-bounded.",
        },
        "mode_mappings": {
            "quick": QUICK_RECON_PROFILE,
            "standard": STANDARD_RECON_PROFILE,
            "deep": DEEP_RECON_PROFILE,
        },
        "profile_contract": {
            "mode_name": contract.mode_name,
            "internal_profile": contract.internal_profile,
            "availability": contract.availability,
            "default_behaviour_status": contract.default_behaviour_status,
            "allowed_method_class": contract.allowed_method_class,
            "purpose": contract.purpose,
        },
        "bounds": {
            bound_field.name: getattr(bounds, bound_field.name)
            for bound_field in fields(bounds)
        },
        "counts": {
            "planned_steps": len(steps),
            "active_collection_steps": len(active_steps),
            "offline_correlation_reporting_steps": len(passive_steps),
            "planned_outputs": len(outputs),
            "preflight_requirements": len(requirements),
            "blocking_preflight_requirements": len(blocking_requirements),
        },
        "planned_pipeline": [
            {
                "step_id": step.step_id,
                "name": step.name,
                "active_collection": step.active_collection,
                "method_class": step.method_class,
                "uses_bounds": list(step.uses_bounds),
                "planned_outputs": list(step.planned_outputs),
            }
            for step in steps
        ],
        "planned_outputs": [
            {
                "output_id": output.output_id,
                "name": output.name,
                "output_kind": output.output_kind,
                "sensitivity": output.sensitivity,
                "producer_step_id": output.producer_step_id,
                "contains_target_data": output.contains_target_data,
            }
            for output in outputs
        ],
        "preflight_requirements": [
            {
                "requirement_id": requirement.requirement_id,
                "name": requirement.name,
                "category": requirement.category,
                "severity": requirement.severity,
                "blocking": requirement.blocking,
                "related_deep_step_ids": list(requirement.related_deep_step_ids),
                "related_output_ids": list(requirement.related_output_ids),
            }
            for requirement in requirements
        ],
        "validation": {
            "planned_pipeline_valid": not pipeline_errors,
            "planned_pipeline_errors": list(pipeline_errors),
            "planned_outputs_valid": not output_errors,
            "planned_outputs_errors": list(output_errors),
            "preflight_contract_valid": not preflight_errors,
            "preflight_contract_errors": list(preflight_errors),
        },
        "non_executable_guarantees": [
            "Deep Recon is available only through the bounded deep-bounded profile.",
            "`deep-bounded` remains bounded and scope-conscious.",
            "This readiness renderer performs no runtime collection.",
            "No project files are read or written.",
            "No commands are executed.",
            "No output files are created.",
            "Quick and Standard mappings remain unchanged.",
        ],
    }


def render_deep_recon_readiness_summary() -> str:
    """Render deterministic Markdown summarising Deep Recon readiness state."""

    contract = get_deep_recon_profile_contract()
    bounds = contract.bounds
    steps = get_deep_recon_planned_pipeline()
    outputs = get_deep_recon_planned_outputs()
    requirements = get_deep_recon_preflight_requirements()
    pipeline_errors = validate_deep_recon_planned_pipeline(steps)
    output_errors = validate_deep_recon_planned_outputs(outputs)
    preflight_errors = validate_deep_recon_preflight_requirements(requirements)

    active_steps = tuple(step for step in steps if step.active_collection)
    passive_steps = tuple(step for step in steps if not step.active_collection)
    output_kinds = tuple(sorted({output.output_kind for output in outputs}))
    sensitivity_levels = tuple(sorted({output.sensitivity for output in outputs}))
    preflight_categories = tuple(sorted({requirement.category for requirement in requirements}))
    preflight_severities = tuple(sorted({requirement.severity for requirement in requirements}))
    blocking_count = sum(1 for requirement in requirements if requirement.blocking)

    lines: list[str] = [
        "# Deep Recon Readiness Summary",
        "",
        "## Current Status",
        "",
        "Deep Recon is available as bounded deep-bounded.",
        f"`{contract.internal_profile}` is the bounded executable Deep profile.",
        "This summary is static contract rendering only.",
        "No runtime collection is performed.",
        "No project files are read or written.",
        "No commands are executed.",
        f"Quick Recon remains mapped to {QUICK_RECON_PROFILE}.",
        f"Standard Recon remains mapped to {STANDARD_RECON_PROFILE}.",
        "",
        "## Profile Contract",
        "",
        f"- Mode name: {contract.mode_name}",
        f"- Internal profile: `{contract.internal_profile}`",
        f"- Availability: {contract.availability}",
        f"- Default behaviour status: {contract.default_behaviour_status}",
        f"- Allowed method class: {contract.allowed_method_class}",
        f"- Purpose: {contract.purpose}",
        "",
        "## Bounds",
        "",
    ]

    for bound_field in fields(bounds):
        lines.append(f"- `{bound_field.name}`: `{getattr(bounds, bound_field.name)}`")

    lines.extend(
        [
            "",
            "## Planned Pipeline",
            "",
            f"- Total planned steps: {len(steps)}",
            f"- Active collection steps: {len(active_steps)}",
            f"- Offline/correlation/reporting steps: {len(passive_steps)}",
            f"- First step: `{steps[0].step_id}` - {steps[0].name}",
            f"- Final step: `{steps[-1].step_id}` - {steps[-1].name}",
            "",
            "| Step ID | Name | Active | Method class |",
            "| --- | --- | --- | --- |",
        ]
    )
    for step in steps:
        active_label = "active" if step.active_collection else "passive"
        lines.append(
            f"| `{step.step_id}` | {step.name} | {active_label} | {step.method_class} |"
        )

    lines.extend(
        [
            "",
            "## Planned Outputs",
            "",
            f"- Total planned outputs: {len(outputs)}",
            f"- Output kinds used: {', '.join(output_kinds)}",
            f"- Sensitivity levels used: {', '.join(sensitivity_levels)}",
            f"- Final output: `{outputs[-1].output_id}` - {outputs[-1].name}",
            "",
            "| Output ID | Name | Kind | Sensitivity | Producer step |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for output in outputs:
        lines.append(
            f"| `{output.output_id}` | {output.name} | {output.output_kind} | "
            f"{output.sensitivity} | `{output.producer_step_id}` |"
        )

    lines.extend(
        [
            "",
            "## Preflight Gates",
            "",
            f"- Total preflight requirements: {len(requirements)}",
            f"- Categories used: {', '.join(preflight_categories)}",
            f"- Severity levels used: {', '.join(preflight_severities)}",
            f"- Blocking requirements: {blocking_count}",
            "",
            "| Requirement ID | Name | Category | Severity | Blocking |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for requirement in requirements:
        blocking_label = "yes" if requirement.blocking else "no"
        lines.append(
            f"| `{requirement.requirement_id}` | {requirement.name} | "
            f"{requirement.category} | {requirement.severity} | {blocking_label} |"
        )

    lines.extend(
        [
            "",
            "## Validation Status",
            "",
        ]
    )
    _append_validation_status(lines, "Planned pipeline contract", pipeline_errors)
    _append_validation_status(lines, "Planned output taxonomy", output_errors)
    _append_validation_status(lines, "Preflight contract", preflight_errors)

    lines.extend(
        [
            "",
            "## Non-Executable Guarantees",
            "",
            "- This renderer does not run Deep Recon.",
            "- `deep-bounded` remains bounded and scope-conscious.",
            "- This renderer does not perform runtime preflight checks.",
            "- This renderer does not read or write project files.",
            "- This renderer does not create reports, evidence packs, or output files.",
            "- This renderer does not execute commands or make network requests.",
            "- Quick and Standard mappings remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


def _append_validation_status(
    lines: list[str],
    label: str,
    errors: tuple[str, ...],
) -> None:
    if not errors:
        lines.append(f"- {label}: valid")
        return
    lines.append(f"- {label}: invalid")
    lines.extend(f"  - {error}" for error in errors)
