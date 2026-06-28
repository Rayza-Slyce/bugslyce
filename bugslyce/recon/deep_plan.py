"""Static Deep Recon planned pipeline contract.

The data in this module is descriptive only. It does not enable Deep Recon,
build executable commands, run scans, read files, write files, or make network
requests.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from bugslyce.recon.modes import (
    DEEP_RECON_BOUNDS,
    DEEP_RECON_CAPABILITY_CATEGORIES,
    DeepReconBounds,
)


@dataclass(frozen=True)
class DeepReconPlannedStep:
    """One future Deep Recon pipeline step as non-executable contract data."""

    step_id: str
    name: str
    purpose: str
    capability_category: str
    active_collection: bool
    method_class: str
    uses_bounds: tuple[str, ...]
    planned_outputs: tuple[str, ...]
    depends_on: tuple[str, ...]
    safety_notes: tuple[str, ...]


HTTP_BOUNDS = (
    "max_total_requests",
    "max_requests_per_service",
    "request_timeout_seconds",
    "rate_limit_delay_seconds",
)
CRAWL_BOUNDS = (
    "max_crawl_depth",
    "max_crawl_pages",
    "max_redirects",
    "max_body_bytes",
    "request_timeout_seconds",
    "rate_limit_delay_seconds",
)
SOURCE_BOUNDS = (
    "max_js_files",
    "max_source_files",
    "max_body_bytes",
    "request_timeout_seconds",
    "rate_limit_delay_seconds",
)
SOURCE_MAP_BOUNDS = (
    "max_source_map_files",
    "max_body_bytes",
    "request_timeout_seconds",
    "rate_limit_delay_seconds",
)
SECOND_PASS_BOUNDS = (
    "max_second_pass_directories",
    "max_second_pass_requests_per_directory",
    "max_requests_per_service",
    "request_timeout_seconds",
    "rate_limit_delay_seconds",
)

NO_EXECUTION_NOTE = "Planned contract only; no executable command is defined."
GET_HEAD_NOTE = "Future collection must use bounded GET/HEAD-style recon only."
NO_INTERACTION_NOTE = (
    "Must not submit forms, attempt authentication, brute force, or use "
    "browser automation."
)
TEXT_ONLY_NOTE = "Collect source-like material as text only; do not execute JavaScript."


DEEP_RECON_PLANNED_PIPELINE: tuple[DeepReconPlannedStep, ...] = (
    DeepReconPlannedStep(
        step_id="deep-01-scope-validation",
        name="Environment and scope validation",
        purpose="Validate local readiness, authorisation reminders, target scope, and Deep bounds before any future collection.",
        capability_category="service/route/source correlation",
        active_collection=False,
        method_class="local validation",
        uses_bounds=(),
        planned_outputs=("deep-scope-safety-summary",),
        depends_on=(),
        safety_notes=(NO_EXECUTION_NOTE, "Deep must stop if authorisation or scope is unclear."),
    ),
    DeepReconPlannedStep(
        step_id="deep-02-tcp-service-discovery",
        name="TCP/service discovery",
        purpose="Plan deeper service discovery for explicitly authorised targets while keeping timeout and rate limits explicit.",
        capability_category="service/route/source correlation",
        active_collection=True,
        method_class="bounded service recon",
        uses_bounds=("request_timeout_seconds", "rate_limit_delay_seconds"),
        planned_outputs=("deep-service-inventory",),
        depends_on=("deep-01-scope-validation",),
        safety_notes=(NO_EXECUTION_NOTE, "No UDP, NSE, exploit, or brute-force behaviour is defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-03-service-version-enrichment",
        name="Service/version enrichment",
        purpose="Plan bounded service and version enrichment for services discovered inside approved scope.",
        capability_category="service/route/source correlation",
        active_collection=True,
        method_class="bounded service recon",
        uses_bounds=("request_timeout_seconds", "rate_limit_delay_seconds"),
        planned_outputs=("deep-service-version-context",),
        depends_on=("deep-02-tcp-service-discovery",),
        safety_notes=(NO_EXECUTION_NOTE, "No vulnerability validation or exploit checks are defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-04-http-service-matrix",
        name="HTTP service matrix",
        purpose="Organise discovered HTTP services by host, port, scheme, status, headers, and observed technology context.",
        capability_category="service/route/source correlation",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-http-service-matrix",),
        depends_on=("deep-03-service-version-enrichment",),
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedStep(
        step_id="deep-05-http-metadata-collection",
        name="HTTP metadata collection",
        purpose="Plan bounded HTTP metadata collection across discovered same-origin services.",
        capability_category="common metadata discovery",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=HTTP_BOUNDS,
        planned_outputs=("deep-http-metadata",),
        depends_on=("deep-04-http-service-matrix",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, NO_INTERACTION_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-06-common-metadata-discovery",
        name="Common metadata discovery",
        purpose="Plan tightly bounded checks for robots, sitemap, security, humans, favicon, manifest, and common metadata.",
        capability_category="common metadata discovery",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=HTTP_BOUNDS,
        planned_outputs=("deep-common-metadata",),
        depends_on=("deep-05-http-metadata-collection",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, NO_INTERACTION_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-07-baseline-content-discovery",
        name="Baseline content discovery",
        purpose="Plan larger bounded content discovery than Standard while preserving explicit request and rate limits.",
        capability_category="expanded content discovery",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=HTTP_BOUNDS,
        planned_outputs=("deep-baseline-content-discovery",),
        depends_on=("deep-06-common-metadata-discovery",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, "No uncontrolled crawling or unbounded wordlists are defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-08-discovered-path-follow-up",
        name="Discovered-path follow-up",
        purpose="Plan bounded follow-up of discovered paths that are already inside the approved target context.",
        capability_category="expanded content discovery",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=HTTP_BOUNDS,
        planned_outputs=("deep-discovered-path-context",),
        depends_on=("deep-07-baseline-content-discovery",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, NO_INTERACTION_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-09-strong-signal-directory-selection",
        name="Strong-signal directory selection",
        purpose="Select only high-signal directories for any future bounded second-pass discovery.",
        capability_category="strong-signal second-pass discovery",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-strong-signal-directory-set",),
        depends_on=("deep-08-discovered-path-follow-up",),
        safety_notes=(NO_EXECUTION_NOTE, "Selection must be evidence-backed and bounded."),
    ),
    DeepReconPlannedStep(
        step_id="deep-10-bounded-second-pass-content-discovery",
        name="Bounded second-pass content discovery",
        purpose="Plan one bounded second-pass discovery layer around selected strong-signal directories only.",
        capability_category="strong-signal second-pass discovery",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=SECOND_PASS_BOUNDS,
        planned_outputs=("deep-second-pass-content-discovery",),
        depends_on=("deep-09-strong-signal-directory-selection",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, "No recursive uncontrolled discovery is defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-11-shallow-same-origin-crawl",
        name="Shallow same-origin crawl",
        purpose="Plan a shallow same-origin crawl from selected HTML pages under explicit depth, page, redirect, and body-size limits.",
        capability_category="shallow same-origin crawl",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=CRAWL_BOUNDS,
        planned_outputs=("deep-shallow-crawl-routes",),
        depends_on=("deep-10-bounded-second-pass-content-discovery",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, "No browser automation or JavaScript execution is defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-12-selected-html-body-fetch",
        name="Selected HTML/body fetch",
        purpose="Plan selected bounded body fetches for high-signal HTML/application responses.",
        capability_category="selected body/source fetch",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=("max_body_bytes", "request_timeout_seconds", "rate_limit_delay_seconds"),
        planned_outputs=("deep-selected-body-text",),
        depends_on=("deep-11-shallow-same-origin-crawl",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, NO_INTERACTION_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-13-same-origin-js-source-discovery",
        name="Same-origin JavaScript/source discovery",
        purpose="Plan identification of same-origin JavaScript and source-like references from already selected HTML/source text.",
        capability_category="JavaScript/source text collection",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-js-source-reference-inventory",),
        depends_on=("deep-12-selected-html-body-fetch",),
        safety_notes=(NO_EXECUTION_NOTE, TEXT_ONLY_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-14-same-origin-js-source-text-collection",
        name="Same-origin JavaScript/source text collection",
        purpose="Plan bounded same-origin JavaScript/source file collection as text only.",
        capability_category="JavaScript/source text collection",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=SOURCE_BOUNDS,
        planned_outputs=("deep-js-source-text",),
        depends_on=("deep-13-same-origin-js-source-discovery",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, TEXT_ONLY_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-15-static-route-extraction",
        name="Static route extraction",
        purpose="Extract route-shaped strings from collected local HTML, JavaScript, and source text without executing code.",
        capability_category="static route extraction",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-static-route-inventory",),
        depends_on=("deep-14-same-origin-js-source-text-collection",),
        safety_notes=(NO_EXECUTION_NOTE, TEXT_ONLY_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-16-source-map-detection-collection",
        name="Source map detection and bounded same-origin collection",
        purpose="Plan source map detection and bounded same-origin collection only when directly referenced.",
        capability_category="source map detection",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=SOURCE_MAP_BOUNDS,
        planned_outputs=("deep-source-map-context",),
        depends_on=("deep-15-static-route-extraction",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, TEXT_ONLY_NOTE),
    ),
    DeepReconPlannedStep(
        step_id="deep-17-parameter-inventory",
        name="Parameter inventory",
        purpose="Build a static parameter inventory from URLs, HTML, JavaScript, and source text.",
        capability_category="parameter inventory",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-parameter-inventory",),
        depends_on=("deep-16-source-map-detection-collection",),
        safety_notes=(NO_EXECUTION_NOTE, "Inventory only; no payload submission is defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-18-html-form-inventory",
        name="HTML form inventory without submission",
        purpose="Inventory observed HTML forms, methods, and field names without submitting forms.",
        capability_category="form inventory without submission",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-form-inventory",),
        depends_on=("deep-17-parameter-inventory",),
        safety_notes=(NO_EXECUTION_NOTE, "Form submission and authentication testing are not defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-19-backup-config-source-exposure-checks",
        name="Backup/config/source exposure checks with a tight allowlist",
        purpose="Plan tightly allowlisted GET/HEAD checks for common backup, config, and source exposure paths.",
        capability_category="backup/config/source exposure checks",
        active_collection=True,
        method_class="GET/HEAD-style recon",
        uses_bounds=HTTP_BOUNDS,
        planned_outputs=("deep-backup-config-source-checks",),
        depends_on=("deep-18-html-form-inventory",),
        safety_notes=(NO_EXECUTION_NOTE, GET_HEAD_NOTE, "No payload injection or write actions are defined."),
    ),
    DeepReconPlannedStep(
        step_id="deep-20-route-source-service-correlation",
        name="Route/source/service correlation",
        purpose="Correlate services, routes, sources, technologies, parameters, and artefacts into review context.",
        capability_category="service/route/source correlation",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-route-source-service-correlation",),
        depends_on=("deep-19-backup-config-source-exposure-checks",),
        safety_notes=(NO_EXECUTION_NOTE,),
    ),
    DeepReconPlannedStep(
        step_id="deep-21-deep-investigation-threads",
        name="Deep investigation threads",
        purpose="Group correlated Deep evidence into richer manual investigation paths.",
        capability_category="deep investigation threads",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-investigation-threads",),
        depends_on=("deep-20-route-source-service-correlation",),
        safety_notes=(NO_EXECUTION_NOTE, "Threads are review prompts, not confirmed findings."),
    ),
    DeepReconPlannedStep(
        step_id="deep-22-deep-manual-review-queue",
        name="Deep manual review queue",
        purpose="Prioritise correlated Deep review prompts for manual operator validation.",
        capability_category="deep manual review queue",
        active_collection=False,
        method_class="offline correlation",
        uses_bounds=(),
        planned_outputs=("deep-manual-review-queue",),
        depends_on=("deep-21-deep-investigation-threads",),
        safety_notes=(NO_EXECUTION_NOTE, "Review queue items must not claim confirmed vulnerability."),
    ),
    DeepReconPlannedStep(
        step_id="deep-23-deep-report-runbook-generation",
        name="Deep report/runbook generation",
        purpose="Plan richer Deep report and runbook sections from deterministic evidence and review queues.",
        capability_category="deep report/runbook output",
        active_collection=False,
        method_class="reporting",
        uses_bounds=(),
        planned_outputs=("deep-report", "deep-runbook"),
        depends_on=("deep-22-deep-manual-review-queue",),
        safety_notes=(NO_EXECUTION_NOTE, "Reports must preserve cautious manual-review wording."),
    ),
    DeepReconPlannedStep(
        step_id="deep-24-evidence-pack-export",
        name="Evidence pack export",
        purpose="Plan evidence-pack organisation by service, route, and investigation thread.",
        capability_category="deep report/runbook output",
        active_collection=False,
        method_class="reporting",
        uses_bounds=(),
        planned_outputs=("deep-evidence-pack",),
        depends_on=("deep-23-deep-report-runbook-generation",),
        safety_notes=(NO_EXECUTION_NOTE, "Export remains local unless the operator shares it manually."),
    ),
)


def get_deep_recon_planned_pipeline() -> tuple[DeepReconPlannedStep, ...]:
    """Return static Deep Recon planned pipeline data."""

    return DEEP_RECON_PLANNED_PIPELINE


def validate_deep_recon_planned_pipeline(
    steps: tuple[DeepReconPlannedStep, ...],
    *,
    bounds: DeepReconBounds = DEEP_RECON_BOUNDS,
) -> tuple[str, ...]:
    """Validate Deep planned pipeline contract data without executing anything."""

    errors: list[str] = []
    bound_names = {field.name for field in fields(bounds)}
    categories = set(DEEP_RECON_CAPABILITY_CATEGORIES)
    seen: set[str] = set()
    forbidden_method_terms = (
        "exploit",
        "authentication testing",
        "form submission",
        "browser automation",
        "javascript execution",
        "arbitrary command",
    )

    if len(steps) != 24:
        errors.append(f"expected 24 steps, found {len(steps)}")

    for index, step in enumerate(steps):
        if step.step_id in seen:
            errors.append(f"duplicate step id: {step.step_id}")
        seen.add(step.step_id)

        if step.capability_category not in categories:
            errors.append(
                f"{step.step_id} uses unknown capability category: "
                f"{step.capability_category}"
            )

        for bound_name in step.uses_bounds:
            if bound_name not in bound_names:
                errors.append(f"{step.step_id} uses unknown bound: {bound_name}")

        if step.active_collection and not step.uses_bounds:
            errors.append(f"{step.step_id} is active collection without bounds")
        if step.active_collection and not step.safety_notes:
            errors.append(f"{step.step_id} is active collection without safety notes")

        prior_step_ids = {prior.step_id for prior in steps[:index]}
        for dependency in step.depends_on:
            if dependency not in seen:
                errors.append(f"{step.step_id} depends on unknown step: {dependency}")
            elif dependency not in prior_step_ids:
                errors.append(
                    f"{step.step_id} dependency does not point backwards: "
                    f"{dependency}"
                )

        lowered_method = step.method_class.lower()
        for forbidden in forbidden_method_terms:
            if forbidden in lowered_method:
                errors.append(
                    f"{step.step_id} method class contains forbidden term: "
                    f"{forbidden}"
                )

    return tuple(errors)
