"""Deterministic Phase 93C Deep review orchestration.

This module composes existing offline Deep review stages from already supplied
bounded collection results. It does not collect, fetch, discover files, inspect
directories, or enable Deep Recon.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from bugslyce.recon.deep_collection_review_bundle import (
    DeepCollectionReviewBundle,
    build_deep_collection_review_bundle,
    empty_deep_metadata_collection_review_summary,
    render_deep_collection_review_bundle_markdown,
)
from bugslyce.recon.deep_form_inventory import (
    DeepFormInventoryResult,
    build_deep_form_inventory,
    render_deep_form_inventory_markdown,
)
from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult,
    build_deep_html_route_extraction,
    render_deep_html_route_extraction_markdown,
)
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    build_deep_http_fingerprint_summary,
    render_deep_http_fingerprint_summary_markdown,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteExtractionResult,
    build_deep_javascript_route_extraction,
    render_deep_javascript_route_extraction_markdown,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_parameter_inventory import (
    DeepParameterInventoryResult,
    build_deep_parameter_inventory,
    render_deep_parameter_inventory_markdown,
)
from bugslyce.recon.deep_redirect_auth_flow_review import (
    DeepRedirectAuthFlowReview,
    build_deep_redirect_auth_flow_review,
    render_deep_redirect_auth_flow_review_markdown,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    build_deep_response_similarity_review,
    render_deep_response_similarity_review_markdown,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupResult,
    render_deep_shallow_route_followup_result_markdown,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
    build_deep_source_route_collection_review,
)
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult


ORCHESTRATION_SCHEMA_VERSION = "1.0"
DEEP_RECON_REVIEW_MARKDOWN = "deep_recon_review.md"
DEEP_RECON_RUNBOOK_MARKDOWN = "deep_recon_runbook.md"
DEEP_RECON_ORCHESTRATION_JSON = "deep_recon_orchestration.json"
STAGE_ORDER = (
    "collection_review",
    "http_fingerprints",
    "redirect_auth_flow",
    "response_similarity",
    "html_routes",
    "javascript_routes",
    "shallow_route_followup",
    "form_inventory",
    "parameter_inventory",
)
SAFETY_NOTES = (
    "Offline orchestration over supplied collection results.",
    "No network requests were made by orchestration.",
    "No form submission was performed by orchestration.",
    "No form action was fetched by orchestration.",
    "No JavaScript was executed by orchestration.",
    "No parameter value was retained, replayed, guessed, or mutated by orchestration.",
    "Deep outputs are static manual review context only.",
    "No confirmed vulnerability claim is made by orchestration.",
    "Deep mode was not enabled.",
)


@dataclass(frozen=True)
class DeepReconOrchestrationResult:
    """Composed Deep review output for passive report/runbook/export seams."""

    collection_review_bundle: DeepCollectionReviewBundle
    source_route_collection_review: DeepSourceRouteCollectionReviewSummary
    http_fingerprint_summary: DeepHttpFingerprintSummary
    redirect_auth_flow_review: DeepRedirectAuthFlowReview
    response_similarity_review: DeepResponseSimilarityReview
    html_route_extraction: DeepHtmlRouteExtractionResult
    javascript_route_extraction: DeepJavaScriptRouteExtractionResult
    shallow_route_followup: DeepShallowRouteFollowupResult
    form_inventory: DeepFormInventoryResult
    parameter_inventory: DeepParameterInventoryResult
    stage_order: tuple[str, ...]
    stage_counts: tuple[tuple[str, int], ...]
    deep_recon_markdown: str
    deep_recon_runbook_markdown: str
    safety_notes: tuple[str, ...]


def build_deep_recon_orchestration(
    source_collection: DeepSourceRouteCollectionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
) -> DeepReconOrchestrationResult:
    """Compose completed offline Deep review stages without collection or IO."""

    empty_metadata = _empty_metadata_collection_result()
    source_review = build_deep_source_route_collection_review(source_collection)
    collection_bundle = build_deep_collection_review_bundle(
        empty_deep_metadata_collection_review_summary(),
        source_review,
    )
    http_summary = build_deep_http_fingerprint_summary(
        empty_metadata,
        source_collection,
    )
    redirect_review = build_deep_redirect_auth_flow_review(http_summary)
    similarity_review = build_deep_response_similarity_review(
        http_summary,
        redirect_review,
    )
    html_routes = build_deep_html_route_extraction(source_collection)
    javascript_routes = build_deep_javascript_route_extraction(source_collection)
    form_inventory = build_deep_form_inventory(source_collection, shallow_followups)
    parameter_inventory = build_deep_parameter_inventory(
        source_collection,
        shallow_followups,
        html_routes,
        javascript_routes,
    )
    stage_counts = _stage_counts(
        collection_bundle,
        http_summary,
        redirect_review,
        similarity_review,
        html_routes,
        javascript_routes,
        shallow_followups,
        form_inventory,
        parameter_inventory,
    )
    safety_notes = _safety_notes(
        collection_bundle.safety_notes,
        http_summary.safety_notes,
        redirect_review.safety_notes,
        similarity_review.safety_notes,
        html_routes.safety_notes,
        javascript_routes.safety_notes,
        shallow_followups.safety_notes,
        form_inventory.safety_notes,
        parameter_inventory.safety_notes,
    )
    report_markdown = _combined_report_markdown(
        (
            render_deep_collection_review_bundle_markdown(collection_bundle),
            render_deep_http_fingerprint_summary_markdown(http_summary),
            render_deep_redirect_auth_flow_review_markdown(redirect_review),
            render_deep_response_similarity_review_markdown(similarity_review),
            render_deep_html_route_extraction_markdown(html_routes),
            render_deep_javascript_route_extraction_markdown(javascript_routes),
            render_deep_shallow_route_followup_result_markdown(shallow_followups),
            render_deep_form_inventory_markdown(form_inventory),
            render_deep_parameter_inventory_markdown(parameter_inventory),
        )
    )
    runbook_markdown = _render_deep_recon_runbook_markdown(stage_counts, safety_notes)
    return DeepReconOrchestrationResult(
        collection_review_bundle=collection_bundle,
        source_route_collection_review=source_review,
        http_fingerprint_summary=http_summary,
        redirect_auth_flow_review=redirect_review,
        response_similarity_review=similarity_review,
        html_route_extraction=html_routes,
        javascript_route_extraction=javascript_routes,
        shallow_route_followup=shallow_followups,
        form_inventory=form_inventory,
        parameter_inventory=parameter_inventory,
        stage_order=STAGE_ORDER,
        stage_counts=stage_counts,
        deep_recon_markdown=report_markdown,
        deep_recon_runbook_markdown=runbook_markdown,
        safety_notes=safety_notes,
    )


def write_deep_recon_orchestration_artifacts(
    result: DeepReconOrchestrationResult,
    output_dir: Path,
    *,
    force: bool = False,
) -> tuple[Path, ...]:
    """Write fixed local Deep orchestration artefacts for explicit export."""

    output_dir = output_dir.expanduser().resolve()
    if not output_dir.exists():
        raise ValueError(f"Deep orchestration output directory does not exist: {output_dir}")
    if not output_dir.is_dir():
        raise ValueError(f"Deep orchestration output path is not a directory: {output_dir}")

    paths = (
        output_dir / DEEP_RECON_REVIEW_MARKDOWN,
        output_dir / DEEP_RECON_RUNBOOK_MARKDOWN,
        output_dir / DEEP_RECON_ORCHESTRATION_JSON,
    )
    for path in paths:
        resolved = path.resolve(strict=False)
        if resolved.parent != output_dir or resolved.name != path.name:
            raise ValueError(f"Unsafe Deep orchestration artefact path: {path}")
        if resolved.exists() and not force:
            raise ValueError(
                f"Deep orchestration artefact already exists: {resolved}. "
                "Re-run with force=True to overwrite it."
            )
        if resolved.exists() and not resolved.is_file():
            raise ValueError(f"Deep orchestration artefact path is not a file: {resolved}")

    payload = _orchestration_json_payload(result)
    paths[0].write_text(result.deep_recon_markdown, encoding="utf-8")
    paths[1].write_text(result.deep_recon_runbook_markdown, encoding="utf-8")
    paths[2].write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tuple(path.resolve(strict=False) for path in paths)


def _empty_metadata_collection_result() -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )


def _stage_counts(
    collection_bundle: DeepCollectionReviewBundle,
    http_summary: DeepHttpFingerprintSummary,
    redirect_review: DeepRedirectAuthFlowReview,
    similarity_review: DeepResponseSimilarityReview,
    html_routes: DeepHtmlRouteExtractionResult,
    javascript_routes: DeepJavaScriptRouteExtractionResult,
    shallow_followups: DeepShallowRouteFollowupResult,
    form_inventory: DeepFormInventoryResult,
    parameter_inventory: DeepParameterInventoryResult,
) -> tuple[tuple[str, int], ...]:
    return (
        ("collection_review", len(collection_bundle.priorities)),
        ("http_fingerprints", len(http_summary.fingerprints)),
        ("redirect_auth_flow", len(redirect_review.observations)),
        ("response_similarity", len(similarity_review.groups)),
        ("html_routes", len(html_routes.routes)),
        ("javascript_routes", len(javascript_routes.candidates)),
        ("shallow_route_followup", shallow_followups.summary_counts.responses_collected),
        ("form_inventory", len(form_inventory.forms)),
        ("parameter_inventory", len(parameter_inventory.parameters)),
    )


def _combined_report_markdown(blocks: tuple[str, ...]) -> str:
    sections = tuple(block.strip() for block in blocks if block.strip())
    return "\n\n".join(sections).rstrip() + "\n"


def _render_deep_recon_runbook_markdown(
    stage_counts: tuple[tuple[str, int], ...],
    safety_notes: tuple[str, ...],
) -> str:
    lines = [
        "## Deep Recon Review Guide",
        "",
        "This compact guide indexes already-rendered Deep review sections for manual review.",
        "It is not a copy of the full Deep report.",
        "",
        "### Completed Review Stages",
        "",
    ]
    for index, stage_id in enumerate(STAGE_ORDER, start=1):
        lines.append(f"{index}. `{stage_id}` - review the corresponding Deep report section.")

    lines.extend(["", "### Bounded Stage Counts", ""])
    for stage_id, count in stage_counts:
        lines.append(f"- `{stage_id}`: {count}")

    lines.extend(
        [
            "",
            "### Operator Notes",
            "",
            "- Results are evidence for manual review, not confirmed vulnerabilities.",
            "- Review the generated Deep report sections in the listed order.",
            "- No exploit commands, active test strings, form submission, or parameter mutation are provided.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _safety_notes(*note_groups: tuple[str, ...]) -> tuple[str, ...]:
    notes: list[str] = list(SAFETY_NOTES)
    for group in note_groups:
        notes.extend(group)
    deduped: list[str] = []
    seen: set[str] = set()
    for note in notes:
        if note not in seen:
            seen.add(note)
            deduped.append(note)
    return tuple(deduped)


def _orchestration_json_payload(result: DeepReconOrchestrationResult) -> dict[str, object]:
    return {
        "schema_version": ORCHESTRATION_SCHEMA_VERSION,
        "stage_order": list(result.stage_order),
        "stage_counts": [
            {"stage": stage, "count": count}
            for stage, count in result.stage_counts
        ],
        "safety_notes": list(result.safety_notes),
        "report_markdown_file": DEEP_RECON_REVIEW_MARKDOWN,
        "runbook_markdown_file": DEEP_RECON_RUNBOOK_MARKDOWN,
        "no_network_requests_made": True,
        "deep_mode_enabled": False,
    }
