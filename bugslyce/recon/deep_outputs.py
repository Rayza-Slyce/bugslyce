"""Static Deep Recon planned output and artefact taxonomy.

The taxonomy in this module is descriptive contract data only. It does not
create files, directories, reports, archives, commands, or network requests.
"""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_plan import get_deep_recon_planned_pipeline


OUTPUT_KINDS = (
    "evidence",
    "index",
    "correlation",
    "queue",
    "report_section",
    "runbook_section",
    "export_manifest",
)
SENSITIVITY_LEVELS = ("low", "medium", "high")
LOCAL_RETENTION_NOTE = "Keep locally and review before sharing."
HIGH_SENSITIVITY_NOTE = "May contain sensitive target context; review before sharing."
NO_EXECUTION_NOTE = "Planned taxonomy only; no runtime output is created."


@dataclass(frozen=True)
class DeepReconPlannedOutput:
    """One future Deep Recon output as non-executable contract data."""

    output_id: str
    name: str
    description: str
    output_kind: str
    producer_step_id: str
    consumed_by_step_ids: tuple[str, ...]
    sensitivity: str
    contains_target_data: bool
    retention_note: str
    safety_notes: tuple[str, ...]


DEEP_RECON_PLANNED_OUTPUTS: tuple[DeepReconPlannedOutput, ...] = (
    DeepReconPlannedOutput(
        output_id="deep-output-scope-safety-summary",
        name="Deep Scope and Safety Summary",
        description="Summarises scope, authorisation reminders, and Deep bounds before future collection.",
        output_kind="report_section",
        producer_step_id="deep-01-scope-validation",
        consumed_by_step_ids=("deep-23-deep-report-runbook-generation",),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-service-inventory",
        name="Deep Service Inventory",
        description="Indexes discovered services for later Deep enrichment and HTTP service mapping.",
        output_kind="index",
        producer_step_id="deep-02-tcp-service-discovery",
        consumed_by_step_ids=("deep-03-service-version-enrichment", "deep-04-http-service-matrix"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-service-version-context",
        name="Deep Service Version Context",
        description="Records service/version context for later service and technology correlation.",
        output_kind="evidence",
        producer_step_id="deep-03-service-version-enrichment",
        consumed_by_step_ids=("deep-04-http-service-matrix", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-http-service-matrix",
        name="Deep HTTP Service Matrix",
        description="Maps HTTP services by host, port, scheme, status, headers, and observed technology context.",
        output_kind="index",
        producer_step_id="deep-04-http-service-matrix",
        consumed_by_step_ids=("deep-05-http-metadata-collection", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-http-metadata",
        name="Deep HTTP Metadata",
        description="Records bounded HTTP metadata observations for later route and service correlation.",
        output_kind="evidence",
        producer_step_id="deep-05-http-metadata-collection",
        consumed_by_step_ids=("deep-06-common-metadata-discovery", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-common-metadata",
        name="Deep Common Metadata",
        description="Records common metadata observations such as robots, sitemap, security, humans, favicon, and manifest context.",
        output_kind="evidence",
        producer_step_id="deep-06-common-metadata-discovery",
        consumed_by_step_ids=("deep-07-baseline-content-discovery", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-baseline-content-discovery",
        name="Deep Baseline Content Discovery",
        description="Indexes bounded baseline content-discovery observations for later follow-up and directory selection.",
        output_kind="evidence",
        producer_step_id="deep-07-baseline-content-discovery",
        consumed_by_step_ids=(
            "deep-08-discovered-path-follow-up",
            "deep-09-strong-signal-directory-selection",
            "deep-20-route-source-service-correlation",
        ),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-discovered-path-context",
        name="Deep Discovered Path Context",
        description="Records bounded follow-up context for discovered paths already inside the approved target context.",
        output_kind="evidence",
        producer_step_id="deep-08-discovered-path-follow-up",
        consumed_by_step_ids=(
            "deep-09-strong-signal-directory-selection",
            "deep-10-bounded-second-pass-content-discovery",
            "deep-20-route-source-service-correlation",
        ),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-strong-signal-directory-set",
        name="Deep Strong-Signal Directory Set",
        description="Indexes evidence-backed directories selected for one future bounded second-pass review.",
        output_kind="index",
        producer_step_id="deep-09-strong-signal-directory-selection",
        consumed_by_step_ids=("deep-10-bounded-second-pass-content-discovery",),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-second-pass-content-discovery",
        name="Deep Second-Pass Content Discovery",
        description="Records bounded second-pass observations around selected strong-signal directories.",
        output_kind="evidence",
        producer_step_id="deep-10-bounded-second-pass-content-discovery",
        consumed_by_step_ids=("deep-11-shallow-same-origin-crawl", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-shallow-crawl-routes",
        name="Deep Shallow Crawl Routes",
        description="Indexes same-origin route references from a future shallow bounded crawl.",
        output_kind="index",
        producer_step_id="deep-11-shallow-same-origin-crawl",
        consumed_by_step_ids=(
            "deep-12-selected-html-body-fetch",
            "deep-13-same-origin-js-source-discovery",
            "deep-20-route-source-service-correlation",
        ),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-selected-body-text",
        name="Deep Selected Body Text",
        description="Stores selected bounded body text for later source, route, parameter, and form inventory.",
        output_kind="evidence",
        producer_step_id="deep-12-selected-html-body-fetch",
        consumed_by_step_ids=(
            "deep-13-same-origin-js-source-discovery",
            "deep-15-static-route-extraction",
            "deep-17-parameter-inventory",
            "deep-18-html-form-inventory",
            "deep-20-route-source-service-correlation",
        ),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-js-source-reference-inventory",
        name="Deep JavaScript/Source Reference Inventory",
        description="Indexes same-origin JavaScript and source-like references observed in selected text.",
        output_kind="index",
        producer_step_id="deep-13-same-origin-js-source-discovery",
        consumed_by_step_ids=("deep-14-same-origin-js-source-text-collection", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-js-source-text",
        name="Deep JavaScript/Source Text",
        description="Stores bounded same-origin JavaScript/source text as text only for static review.",
        output_kind="evidence",
        producer_step_id="deep-14-same-origin-js-source-text-collection",
        consumed_by_step_ids=(
            "deep-15-static-route-extraction",
            "deep-16-source-map-detection-collection",
            "deep-17-parameter-inventory",
            "deep-20-route-source-service-correlation",
        ),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-static-route-inventory",
        name="Deep Static Route Inventory",
        description="Indexes route-shaped strings extracted from collected local HTML, JavaScript, and source text.",
        output_kind="index",
        producer_step_id="deep-15-static-route-extraction",
        consumed_by_step_ids=("deep-17-parameter-inventory", "deep-20-route-source-service-correlation"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-source-map-context",
        name="Deep Source Map Context",
        description="Stores bounded same-origin source map context when directly referenced by collected source text.",
        output_kind="evidence",
        producer_step_id="deep-16-source-map-detection-collection",
        consumed_by_step_ids=("deep-17-parameter-inventory", "deep-20-route-source-service-correlation"),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-parameter-inventory",
        name="Deep Parameter Inventory",
        description="Indexes parameters observed in URLs, HTML, JavaScript, and source text for manual review.",
        output_kind="index",
        producer_step_id="deep-17-parameter-inventory",
        consumed_by_step_ids=("deep-20-route-source-service-correlation", "deep-22-deep-manual-review-queue"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-form-inventory",
        name="Deep Form Inventory",
        description="Indexes observed HTML form methods, actions, and field names without interaction.",
        output_kind="index",
        producer_step_id="deep-18-html-form-inventory",
        consumed_by_step_ids=("deep-20-route-source-service-correlation", "deep-22-deep-manual-review-queue"),
        sensitivity="medium",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-backup-config-source-checks",
        name="Deep Backup/Config/Source Checks",
        description="Records tightly allowlisted backup, config, and source exposure path observations.",
        output_kind="evidence",
        producer_step_id="deep-19-backup-config-source-exposure-checks",
        consumed_by_step_ids=("deep-20-route-source-service-correlation", "deep-22-deep-manual-review-queue"),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-route-source-service-correlation",
        name="Deep Route/Source/Service Correlation",
        description="Correlates services, routes, sources, technologies, parameters, and artefacts into review context.",
        output_kind="correlation",
        producer_step_id="deep-20-route-source-service-correlation",
        consumed_by_step_ids=(
            "deep-21-deep-investigation-threads",
            "deep-22-deep-manual-review-queue",
            "deep-23-deep-report-runbook-generation",
        ),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-investigation-threads",
        name="Deep Investigation Threads",
        description="Groups correlated Deep evidence into richer manual investigation paths.",
        output_kind="correlation",
        producer_step_id="deep-21-deep-investigation-threads",
        consumed_by_step_ids=("deep-22-deep-manual-review-queue", "deep-23-deep-report-runbook-generation"),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-manual-review-queue",
        name="Deep Manual Review Queue",
        description="Prioritises correlated Deep review prompts for manual operator validation.",
        output_kind="queue",
        producer_step_id="deep-22-deep-manual-review-queue",
        consumed_by_step_ids=("deep-23-deep-report-runbook-generation",),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-report-section-set",
        name="Deep Report Section Set",
        description="Defines future Deep report sections generated from deterministic evidence and review queues.",
        output_kind="report_section",
        producer_step_id="deep-23-deep-report-runbook-generation",
        consumed_by_step_ids=("deep-24-evidence-pack-export",),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-runbook-section-set",
        name="Deep Runbook Section Set",
        description="Defines future Deep runbook sections generated from deterministic evidence and review queues.",
        output_kind="runbook_section",
        producer_step_id="deep-23-deep-report-runbook-generation",
        consumed_by_step_ids=("deep-24-evidence-pack-export",),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
    DeepReconPlannedOutput(
        output_id="deep-output-evidence-pack-manifest",
        name="Deep Evidence Pack Manifest",
        description="Defines future local evidence-pack organisation by service, route, and investigation thread.",
        output_kind="export_manifest",
        producer_step_id="deep-24-evidence-pack-export",
        consumed_by_step_ids=(),
        sensitivity="high",
        contains_target_data=True,
        retention_note=LOCAL_RETENTION_NOTE,
        safety_notes=(NO_EXECUTION_NOTE, HIGH_SENSITIVITY_NOTE),
    ),
)


def get_deep_recon_planned_outputs() -> tuple[DeepReconPlannedOutput, ...]:
    """Return static Deep Recon planned output taxonomy data."""

    return DEEP_RECON_PLANNED_OUTPUTS


def get_deep_recon_planned_outputs_by_step() -> dict[str, tuple[DeepReconPlannedOutput, ...]]:
    """Group planned Deep outputs by producer step ID."""

    grouped: dict[str, list[DeepReconPlannedOutput]] = {}
    for output in DEEP_RECON_PLANNED_OUTPUTS:
        grouped.setdefault(output.producer_step_id, []).append(output)
    return {
        step_id: tuple(outputs)
        for step_id, outputs in sorted(grouped.items())
    }


def validate_deep_recon_planned_outputs(
    outputs: tuple[DeepReconPlannedOutput, ...],
) -> tuple[str, ...]:
    """Validate Deep planned output taxonomy without creating outputs."""

    errors: list[str] = []
    pipeline = get_deep_recon_planned_pipeline()
    step_order = {step.step_id: index for index, step in enumerate(pipeline)}
    step_ids = set(step_order)
    output_ids: set[str] = set()
    produced_by_step: set[str] = set()
    forbidden_claims = (
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
        if output.output_id in output_ids:
            errors.append(f"duplicate output id: {output.output_id}")
        output_ids.add(output.output_id)

        if output.output_kind not in OUTPUT_KINDS:
            errors.append(f"{output.output_id} has unknown output kind: {output.output_kind}")
        if output.sensitivity not in SENSITIVITY_LEVELS:
            errors.append(f"{output.output_id} has unknown sensitivity: {output.sensitivity}")
        if output.producer_step_id not in step_ids:
            errors.append(f"{output.output_id} has unknown producer step: {output.producer_step_id}")
        else:
            produced_by_step.add(output.producer_step_id)

        producer_order = step_order.get(output.producer_step_id, -1)
        for consumer_step_id in output.consumed_by_step_ids:
            if consumer_step_id not in step_ids:
                errors.append(f"{output.output_id} has unknown consumer step: {consumer_step_id}")
                continue
            if step_order[consumer_step_id] <= producer_order:
                errors.append(
                    f"{output.output_id} consumer does not point forwards: "
                    f"{consumer_step_id}"
                )

        if output.contains_target_data and not output.retention_note.strip():
            errors.append(f"{output.output_id} contains target data without retention note")
        if output.sensitivity == "high" and not output.safety_notes:
            errors.append(f"{output.output_id} is high sensitivity without safety notes")

        text = " ".join((output.description, *output.safety_notes)).casefold()
        for forbidden in forbidden_claims:
            if forbidden.casefold() in text:
                errors.append(f"{output.output_id} contains forbidden claim: {forbidden}")

    for step_id in step_ids:
        if step_id not in produced_by_step:
            errors.append(f"planned pipeline step has no output: {step_id}")

    return tuple(errors)
