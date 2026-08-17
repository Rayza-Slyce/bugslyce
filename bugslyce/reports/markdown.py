"""Deterministic Markdown and JSON output generation for BugSlyce."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from html import escape as escape_html
import json
from pathlib import Path
from typing import Any

from bugslyce.core.engagement_context import engagement_context_label
from bugslyce.core.models import Candidate, ProjectState
from bugslyce.core.sensitive_evidence import REPORT_SENSITIVE_EVIDENCE_NOTICE
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    LIKELY_SIGNAL,
    POSSIBLE_SIGNAL,
    classify_encoded_artifact,
    effective_candidate_priority,
)
from bugslyce.reports.operator_summary import (
    OperatorSummary,
    OperatorSummaryLead,
    build_operator_summary,
)
from bugslyce.reports.operator_report_view import OperatorReportView
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageView,
    write_analysis_coverage_artifact,
)
from bugslyce.reports.analysis_coverage_presentation import (
    build_analysis_coverage_presentation,
)
from bugslyce.reports.investigation_context import InvestigationContextItem
from bugslyce.reports.investigation_context_presentation import (
    InvestigationContextPresentationIndex,
    build_investigation_context_presentation_index,
)
from bugslyce.reports.provenance import build_workflow_provenance


PRIORITY_ORDER = ("high", "medium", "low", "kill_switch")
SURFACE_LABELS = {
    "auth_surface": "Auth surfaces",
    "admin_surface": "Admin surfaces",
    "environment_surface": "Environment surfaces",
    "api_surface": "API surfaces",
    "file_or_content_surface": "File/content surfaces",
    "object_reference_review": "Object-reference review surfaces",
    "redirect_parameter_review": "Redirect-parameter review surfaces",
    "low_signal_static": "Static/CDN low-signal areas",
    "high_port_http_service": "High-port HTTP services",
    "multiple_http_services": "Hosts with multiple HTTP services",
    "robots_artifact": "Robots artefacts",
    "hidden_path_review": "Hidden-looking path surfaces",
}


def render_markdown_report(
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    human_triage_brief_markdown: str | None = None,
    manual_review_leads_markdown: str | None = None,
    deep_recon_markdown: str | None = None,
    investigation_threads_markdown: str | None = None,
    http_route_relationships_markdown: str | None = None,
    route_source_review_markdown: str | None = None,
    readable_evidence_cards_markdown: str | None = None,
    collection_confidence_markdown: str | None = None,
    operator_summary_leads: tuple[OperatorSummaryLead, ...] = (),
    operator_summary: OperatorSummary | None = None,
    operator_report_view: OperatorReportView | None = None,
) -> str:
    """Render a cautious deterministic triage report."""

    context_index = (
        build_investigation_context_presentation_index(
            operator_report_view.investigation_context
        )
        if operator_report_view is not None
        else None
    )

    lines: list[str] = [
        "# BugSlyce Recon Pack",
        "",
        f"Generated at: `{project_state.generated_at}`",
        "",
        "This is an evidence-grounded recon pack built from structured local inputs. "
        "Candidates are manual review leads, priority means manual attention priority rather than severity, "
        "and no confirmed findings are claimed.",
        "",
    ]

    _operator_summary(
        lines,
        project_state,
        candidates,
        additional_leads=operator_summary_leads,
        summary=operator_summary,
        context_index=context_index,
    )
    _analysis_coverage(
        lines,
        (
            operator_report_view.analysis_coverage
            if operator_report_view is not None
            else AnalysisCoverageView(())
        ),
    )
    _optional_prerendered_section(lines, collection_confidence_markdown)
    _optional_prerendered_section(lines, human_triage_brief_markdown)
    _manual_review_leads_section(lines, manual_review_leads_markdown)
    # Phase 93A: already-rendered Deep Markdown belongs at the same report seam
    # as manual-review content, immediately after Manual Review Leads when present.
    _optional_prerendered_section(lines, deep_recon_markdown)
    _investigation_threads_section(lines, investigation_threads_markdown)
    _optional_prerendered_section(lines, http_route_relationships_markdown)
    _route_source_review_section(lines, route_source_review_markdown)
    _optional_prerendered_section(lines, readable_evidence_cards_markdown)
    _scope_summary(lines, project_state)
    _recon_manifest(lines, project_state)
    _workflow_provenance(lines, project_state)
    _input_files(lines, project_state)
    _asset_inventory(lines, project_state)
    _http_services(lines, project_state)
    _surface_areas(lines, candidates)
    _priority_queue(lines, project_state, candidates)
    _evidence_table(lines, project_state, context_index)
    _operator_notes(lines, project_state)
    _sensitive_evidence_notice(lines)
    _safe_next_steps(lines)
    _kill_switch_warnings(lines, project_state, candidates)
    _unknowns(lines)

    return "\n".join(lines).rstrip() + "\n"


def _operator_summary(
    lines: list[str],
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    additional_leads: tuple[OperatorSummaryLead, ...] = (),
    summary: OperatorSummary | None = None,
    context_index: InvestigationContextPresentationIndex | None = None,
) -> None:
    if summary is None:
        summary = build_operator_summary(
            project_state,
            candidates,
            additional_leads=additional_leads,
        )
    lines.extend(["## Operator Summary", "", "### Review First", ""])
    if not summary.ranked_leads:
        lines.extend(
            [
                "No evidence-backed leads met the conservative summary threshold.",
                "",
            ]
        )
    else:
        for lead in summary.ranked_leads:
            context = (
                context_index.primary_by_anchor_id.get(lead.lead_id)
                if context_index is not None
                else None
            )
            if context is not None:
                lines.append(f'<a id="{context.anchor_reference.anchor_token}"></a>')
            lines.extend(
                [
                    f"{lead.rank}. **{_md(lead.title)}**",
                    f"   - Lead ID: `{_md(lead.lead_id)}`",
                    f"   - Type: `{_md(lead.lead_type)}`",
                    f"   - Rationale: {_md(lead.rationale)}",
                    f"   - Endpoint(s): {_complete_code_list(lead.endpoints)}",
                    f"   - Evidence: {_complete_code_list(lead.evidence_ids)}",
                    f"   - Suggested next action: {_md(lead.suggested_next_action)}",
                    f"   - Signal: `{lead.signal}`",
                    "",
                ]
            )
            if context is not None and context.context_items:
                _markdown_investigation_context(
                    lines,
                    context.context_items,
                    context_index,
                    frozenset(item.id for item in project_state.evidence),
                )

    lines.extend(["### Low-Signal / Avoid Rabbit Holes", ""])
    if not summary.low_signal:
        lines.extend(
            [
                "No structured low-signal items were identified for this dataset.",
                "",
            ]
        )
    else:
        for item in summary.low_signal:
            lines.extend(
                [
                    f"- **{_md(item.title)}**: {_md(item.reason)}",
                    f"  - Endpoint(s): {format_endpoint_list(item.endpoints)}",
                    f"  - Evidence: {format_evidence_ids(item.evidence_ids)}",
                ]
            )
        lines.append("")

    lines.extend(["### Current Coverage", ""])
    lines.extend(f"- {_md(item)}" for item in summary.coverage)
    lines.append("")


def _complete_code_list(values: list[str] | tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    return ", ".join(
        "`" + str(value).replace("`", "'") + "`" for value in values
    )


def _analysis_coverage(lines: list[str], view: AnalysisCoverageView) -> None:
    """Render only source-attributable C2 claims already supplied to the report."""

    lines.extend(
        [
            "## Analysis Coverage",
            "",
            (
                "Coverage is evidence-limited: this report lists only analysis states "
                "proven by retained execution evidence. An analyser/source not listed "
                "here may have run; absence is not a clean result."
            ),
            "",
        ]
    )
    items = build_analysis_coverage_presentation(view)
    if not items:
        lines.extend(
            [
                (
                    "No source-attributable analysis coverage claims can be proven from "
                    "the retained execution evidence available to this report."
                ),
                "",
            ]
        )
        return
    for presentation in items:
        unit = presentation.item.unit
        lines.extend(
            [
                f"- **{presentation.state_label}**",
                f"  - Capability: {_context_code(unit.capability)}",
                f"  - Source role: {_context_code(unit.source_role)}",
                f"  - Source identity: {_context_code(unit.source_id)}",
            ]
        )
        if presentation.finding_count_label:
            lines.append(f"  - Finding count: {presentation.finding_count_label}")
        if presentation.execution_note_label:
            lines.append(f"  - Execution: {presentation.execution_note_label}")
        if presentation.unknown_reason_label:
            lines.append(f"  - Reason: {presentation.unknown_reason_label}")
    lines.append("")


def _markdown_investigation_context(
    lines: list[str],
    items: tuple[InvestigationContextItem, ...],
    index: InvestigationContextPresentationIndex,
    rendered_evidence_ids: frozenset[str],
) -> None:
    lines.append("   - Investigation context:")
    for item in items:
        evidence = ", ".join(
            _markdown_internal_reference(
                evidence_id,
                (
                    index.reference_by_target.get(("evidence", evidence_id))
                    if evidence_id in rendered_evidence_ids
                    else None
                ),
            )
            for evidence_id in item.evidence_ids
        )
        details = [
            f"{_context_text(item.relationship_kind.title())}: {_context_text(item.label)}",
        ]
        if item.route_url:
            details.append(f"route {_context_code(item.route_url)}")
        if item.source_ids:
            details.append(f"source {_context_code_list(item.source_ids)}")
        if item.source_urls:
            details.append(f"source URL {_context_code_list(item.source_urls)}")
        if item.body_sha256s:
            details.append(f"body SHA-256 {_context_code_list(item.body_sha256s)}")
        if item.related_ids:
            details.append(f"related context {_context_code_list(item.related_ids)}")
        if evidence:
            details.append(f"evidence {evidence}")
        lines.append("     - " + "; ".join(details))
    lines.append("")


def _markdown_internal_reference(value: str, reference: object | None) -> str:
    anchor = getattr(reference, "anchor_token", "")
    label = _context_text(value)
    return f"[`{label}`](#{anchor})" if anchor else f"`{label}`"


def _context_text(value: object) -> str:
    safe = escape_html(str(value), quote=True)
    return _md(_markdown_literal(safe))


def _markdown_literal(value: str) -> str:
    """Keep target-derived context text readable without Markdown authority."""

    escaped = value.replace("\\", "\\\\")
    return escaped.translate(
        str.maketrans(
            {
                "`": "\\`",
                "*": "\\*",
                "_": "\\_",
                "[": "\\[",
                "]": "\\]",
                "(": "\\(",
                ")": "\\)",
                "!": "\\!",
                "#": "\\#",
            }
        )
    )


def _context_code_list(values: tuple[str, ...]) -> str:
    return ", ".join(_context_code(value) for value in values)


def _context_code(value: object) -> str:
    """Render one target-derived value as a safely delimited code literal."""

    literal = str(value).replace("\n", " ")
    delimiter = "`" * (_longest_backtick_run(literal) + 1)
    padding = " " if literal.startswith("`") or literal.endswith("`") else ""
    return f"{delimiter}{padding}{literal}{padding}{delimiter}"


def _longest_backtick_run(value: str) -> int:
    longest = 0
    current = 0
    for character in value:
        if character == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def write_project_outputs(
    project_state: ProjectState,
    candidates: list[Candidate],
    output_dir: Path,
    *,
    human_triage_brief_markdown: str | None = None,
    manual_review_leads_markdown: str | None = None,
    deep_recon_markdown: str | None = None,
    investigation_threads_markdown: str | None = None,
    http_route_relationships_markdown: str | None = None,
    route_source_review_markdown: str | None = None,
    readable_evidence_cards_markdown: str | None = None,
    collection_confidence_markdown: str | None = None,
    operator_summary_leads: tuple[OperatorSummaryLead, ...] = (),
    operator_summary: OperatorSummary | None = None,
    operator_report_view: OperatorReportView | None = None,
    analysis_coverage_evidence: tuple[AnalysisCoverageExecutionEvidence, ...] | None = None,
) -> tuple[Path, Path]:
    """Write report.md and project_state.json to the provided output directory."""

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.md"
    json_path = output_dir / "project_state.json"

    report_path.write_text(
        render_markdown_report(
            project_state,
            candidates,
            human_triage_brief_markdown=human_triage_brief_markdown,
            manual_review_leads_markdown=manual_review_leads_markdown,
            deep_recon_markdown=deep_recon_markdown,
            investigation_threads_markdown=investigation_threads_markdown,
            http_route_relationships_markdown=http_route_relationships_markdown,
            route_source_review_markdown=route_source_review_markdown,
            readable_evidence_cards_markdown=readable_evidence_cards_markdown,
            collection_confidence_markdown=collection_confidence_markdown,
            operator_summary_leads=operator_summary_leads,
            operator_summary=operator_summary,
            operator_report_view=operator_report_view,
        ),
        encoding="utf-8",
    )
    json_path.write_text(export_project_state_json(project_state, candidates), encoding="utf-8")
    if analysis_coverage_evidence is not None:
        write_analysis_coverage_artifact(
            output_dir,
            analysis_coverage_evidence,
        )

    return report_path, json_path


def _optional_prerendered_section(
    lines: list[str],
    markdown: str | None,
) -> None:
    if markdown is None:
        return
    section = markdown.strip()
    if not section:
        return
    lines.extend(section.splitlines())
    lines.append("")


def _manual_review_leads_section(
    lines: list[str],
    manual_review_leads_markdown: str | None,
) -> None:
    if manual_review_leads_markdown is None:
        return
    section = manual_review_leads_markdown.strip()
    if not section:
        return
    lines.extend(section.splitlines())
    lines.append("")


def _investigation_threads_section(
    lines: list[str],
    investigation_threads_markdown: str | None,
) -> None:
    if investigation_threads_markdown is None:
        return
    section = investigation_threads_markdown.strip()
    if not section:
        return
    lines.extend(section.splitlines())
    lines.append("")


def _route_source_review_section(
    lines: list[str],
    route_source_review_markdown: str | None,
) -> None:
    if route_source_review_markdown is None:
        return
    section = route_source_review_markdown.strip()
    if not section:
        return
    lines.extend(section.splitlines())
    lines.append("")


def export_project_state_json(project_state: ProjectState, candidates: list[Candidate]) -> str:
    """Return a stable JSON export containing project state and candidates."""

    payload = {
        "project_state": asdict(project_state),
        "candidates": [asdict(candidate) for candidate in candidates],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _scope_summary(lines: list[str], project_state: ProjectState) -> None:
    lines.extend(
        [
            "## Scope Summary",
            "",
            f"- Project: `{project_state.project_name}`",
            f"- Engagement context: {engagement_context_label(project_state.engagement_context)}",
            f"- Input directory: `{project_state.input_dir}`",
            f"- Parsed scope summary: {project_state.scope_summary}",
            "- Scope status uses simple exact-host and suffix matching. Review programme scope before manual testing.",
            "",
        ]
    )


def _recon_manifest(lines: list[str], project_state: ProjectState) -> None:
    manifest = project_state.recon_manifest
    if manifest is None:
        return
    lines.extend(
        [
            "## Recon Manifest",
            "",
            f"- Schema version: `{_md(manifest.schema_version)}`",
            f"- Target: `{_md(manifest.target)}`",
            f"- Created by: {_md(manifest.created_by or 'unspecified')}",
            f"- Profile (raw): {_md(manifest.profile or 'unspecified')}",
            f"- Artefact count: {len(manifest.artifacts)}",
            "",
        ]
    )


def _workflow_provenance(lines: list[str], project_state: ProjectState) -> None:
    if project_state.recon_manifest is None:
        return
    summary = build_workflow_provenance(project_state)
    lines.extend(
        [
            "## Workflow / Provenance Summary",
            "",
            f"- Base discovery profile: `{_md(summary.base_discovery_profile)}`",
            (
                "- Enrichment phases detected: "
                f"{_workflow_list(summary.enrichment_phases)}"
            ),
            (
                "- Content discovery profiles detected: "
                f"{_workflow_list(summary.content_discovery_profiles)}"
            ),
            (
                "- Follow-up phases detected: "
                f"{_workflow_list(summary.followup_phases)}"
            ),
            (
                "- Raw discovered path evidence rows: "
                f"{summary.raw_discovered_path_rows}"
            ),
            f"- Unique discovered paths: {summary.unique_discovered_paths}",
            (
                "- Duplicate path rows retained for auditability: "
                f"{summary.duplicate_discovered_path_rows}"
            ),
            "",
        ]
    )


def _input_files(lines: list[str], project_state: ProjectState) -> None:
    lines.extend(["## Input Files Processed", ""])
    if not project_state.processed_files:
        lines.append("- No input files were processed.")
    else:
        lines.extend(f"- `{path}`" for path in project_state.processed_files)
    lines.append("")


def _asset_inventory(lines: list[str], project_state: ProjectState) -> None:
    lines.extend(["## Asset Inventory", ""])
    if not project_state.assets:
        lines.extend(["No assets were assembled from the parsed inputs.", ""])
        return

    lines.extend(["| Hostname | Scope Status | Tags | Evidence IDs |", "| --- | --- | --- | --- |"])
    for asset in project_state.assets:
        lines.append(
            "| "
            f"{_md(asset.hostname)} | "
            f"{_scope_status(asset.in_scope)} | "
            f"{_csv(asset.tags)} | "
            f"{format_evidence_ids(asset.evidence_ids)} |"
        )
    lines.append("")


def _http_services(lines: list[str], project_state: ProjectState) -> None:
    lines.extend(["## Live HTTP Services", ""])
    if not project_state.http_services:
        lines.extend(["No HTTP service metadata was assembled from the parsed inputs.", ""])
        return

    lines.extend(
        [
            "| URL | Status Code | Title | Technologies | Evidence IDs |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for service in project_state.http_services:
        lines.append(
            "| "
            f"{_md(service.url)} | "
            f"{service.status_code if service.status_code is not None else 'unknown'} | "
            f"{_md(service.title or 'unknown')} | "
            f"{_csv(service.technologies)} | "
            f"{format_evidence_ids(service.evidence_ids)} |"
        )
    lines.append("")


def _surface_areas(lines: list[str], candidates: list[Candidate]) -> None:
    lines.extend(["## Attack Surface Summary", ""])
    grouped: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        if candidate.candidate_type in SURFACE_LABELS:
            grouped[candidate.candidate_type].append(candidate)

    if not grouped:
        lines.extend(["No grouped surface areas were generated from deterministic tags.", ""])
        return

    for candidate_type, label in SURFACE_LABELS.items():
        items = grouped.get(candidate_type, [])
        if not items:
            continue
        lines.append(f"- {label}: {len(items)} candidate(s)")
    lines.append("")


def _priority_queue(
    lines: list[str],
    project_state: ProjectState,
    candidates: list[Candidate],
) -> None:
    lines.extend(["## Manual Review Queue", ""])
    candidates_by_priority: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        candidates_by_priority[
            effective_candidate_priority(project_state, candidate)
        ].append(candidate)

    for priority in PRIORITY_ORDER:
        lines.extend([f"### {priority}", ""])
        items = candidates_by_priority.get(priority, [])
        if not items:
            lines.extend(["No candidates in this priority bucket.", ""])
            continue
        for candidate in items:
            lines.extend(
                _candidate_lines(
                    candidate,
                    priority=effective_candidate_priority(project_state, candidate),
                )
            )
            lines.append("")


def _candidate_lines(candidate: Candidate, *, priority: str | None = None) -> list[str]:
    lines = [
        f"#### {candidate.id}: {_md(candidate.title)}",
        "",
        f"- Candidate type: `{candidate.candidate_type}`",
        f"- Priority: `{priority or candidate.priority}`",
        f"- Rationale: {_md(candidate.rationale)}",
        f"- Affected assets: {_csv(candidate.affected_assets)}",
        f"- Affected endpoints: {format_endpoint_list(candidate.affected_endpoints)}",
        f"- Evidence IDs: {_csv(candidate.evidence_ids)}",
        "- Suggested manual validation:",
    ]
    lines.extend(f"  - {_md(item)}" for item in candidate.suggested_manual_validation)
    if candidate.kill_switch_guidance:
        lines.append(f"- Kill-switch guidance: {_md(candidate.kill_switch_guidance)}")
    return lines


def _evidence_table(
    lines: list[str],
    project_state: ProjectState,
    context_index: InvestigationContextPresentationIndex | None = None,
) -> None:
    lines.extend(["## Evidence Summary", ""])
    if project_state.recon_summary:
        summary = project_state.recon_summary
        lines.extend(
            [
                f"- Open ports recorded: {summary.open_port_count}",
                f"- HTTP services recorded: {summary.http_service_count}",
                f"- Interesting artefacts recorded: {summary.interesting_artifact_count}",
                f"- Manual review candidates: {summary.candidate_count}",
                "",
            ]
        )

    if project_state.port_services:
        lines.extend(
            [
                "### Port Services",
                "",
                "| Host | Port | Protocol | State | Service | Product / Version | Evidence IDs |",
                "| --- | ---: | --- | --- | --- | --- | --- |",
            ]
        )
        for service in project_state.port_services:
            details = " ".join(value for value in (service.product, service.version) if value) or "unknown"
            lines.append(
                f"| {_md(service.host)} | {service.port} | {_md(service.protocol)} | "
                f"{_md(service.state)} | {_md(service.service or 'unknown')} | {_md(details)} | "
                f"{format_evidence_ids(service.evidence_ids)} |"
            )
        lines.append("")

    if project_state.discovered_paths:
        lines.extend(
            [
                "### Discovered Paths",
                "",
                (
                    "This table contains raw path evidence rows. Repeated URLs may "
                    "appear when multiple collection phases observed the same path; "
                    "unique-path counts are summarised above."
                ),
                "",
                "| URL | Status | Length | Redirect | Evidence IDs |",
                "| --- | ---: | ---: | --- | --- |",
            ]
        )
        for path in project_state.discovered_paths:
            lines.append(
                f"| {_md(path.url)} | {path.status_code if path.status_code is not None else 'unknown'} | "
                f"{path.content_length if path.content_length is not None else 'unknown'} | "
                f"{_md(path.redirect_location or 'none')} | {format_evidence_ids(path.evidence_ids)} |"
            )
        lines.append("")

    if project_state.http_artifacts:
        lines.extend(
            [
                "### HTTP Artefacts",
                "",
                "| URL | Artefact Type | Value | Evidence IDs |",
                "| --- | --- | --- | --- |",
            ]
        )
        for artifact in project_state.http_artifacts:
            lines.append(
                f"| {_md(artifact.url or 'unknown')} | {_md(artifact.artifact_type)} | "
                f"{_md(_compact(artifact.value))} | {format_evidence_ids(artifact.evidence_ids)} |"
            )
        lines.append("")
        _encoded_artifact_classification(lines, project_state)

    lines.extend(["### Raw Evidence References", ""])
    if not project_state.evidence:
        lines.extend(["No evidence records were assembled from the parsed inputs.", ""])
        return

    lines.extend(["| Evidence ID | Source File | Type | Value |", "| --- | --- | --- | --- |"])
    for evidence in project_state.evidence:
        reference = (
            context_index.reference_by_target.get(("evidence", evidence.id))
            if context_index is not None
            else None
        )
        evidence_label = evidence.id
        if reference is not None:
            evidence_label = (
                f'<a id="{reference.anchor_token}"></a>{evidence_label}'
            )
        backlink = (
            context_index.evidence_backlink_by_id.get(evidence.id)
            if context_index is not None
            else None
        )
        if backlink is not None:
            links = ", ".join(
                f"[Review First context](#{anchor.anchor_token})"
                for anchor in backlink.primary_anchor_references
            )
            evidence_label += f"<br>Back to: {links}"
        lines.append(
            "| "
            f"{evidence_label} | "
            f"{_md(evidence.source_file)} | "
            f"{_md(evidence.evidence_type)} | "
            f"{_md(_compact(evidence.value))} |"
        )
    lines.append("")


def _encoded_artifact_classification(
    lines: list[str],
    project_state: ProjectState,
) -> None:
    classified = []
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type not in {"encoded_like_artifact", "hidden_element"}:
            continue
        classified.append((artifact, classify_encoded_artifact(artifact)))
    if not classified:
        return

    lines.extend(["### Encoded Artefact Classification", ""])
    groups = (
        ("Likely / Possible Signal", {LIKELY_SIGNAL, POSSIBLE_SIGNAL}),
        ("Likely Noise", {LIKELY_NOISE}),
    )
    for heading, categories in groups:
        items = [
            (artifact, classification)
            for artifact, classification in classified
            if classification.category in categories
        ]
        lines.extend([f"#### {heading}", ""])
        if not items:
            lines.extend(["No artefacts in this classification group.", ""])
            continue
        for artifact, classification in items[:6]:
            lines.extend(
                [
                    f"- `{_md(_compact(artifact.value, limit=80))}`",
                    f"  - Classification: `{classification.category}`",
                    f"  - Endpoint: {_md(artifact.url or 'unknown')}",
                    f"  - Evidence: {format_evidence_ids(artifact.evidence_ids)}",
                    f"  - Reason: {_md(classification.reason)}",
                ]
            )
        if len(items) > 6:
            lines.append(f"- ... +{len(items) - 6} more; see the full HTTP Artefacts table above.")
        lines.append("")


def _operator_notes(lines: list[str], project_state: ProjectState) -> None:
    note_evidence = [item for item in project_state.evidence if item.evidence_type == "note"]
    if not note_evidence:
        return

    lines.extend(["## Operator Notes / Context", ""])
    lines.extend(f"- [{item.id}] {_md(_compact(item.value))}" for item in note_evidence)
    lines.extend(
        [
            "",
            "Operator notes are contextual input only and do not create manual review candidates.",
            "",
        ]
    )


def _safe_next_steps(lines: list[str]) -> None:
    lines.extend(
        [
            "## Safe Next Steps",
            "",
            "- Review programme scope before any manual testing.",
            "- Manually validate candidates and document expected behaviour.",
            "- Collect request/response evidence before escalating any lead.",
            "- Avoid unsupported claims in notes and summaries.",
            "- Stop on low-signal paths unless new evidence appears.",
            "",
        ]
    )


def _sensitive_evidence_notice(lines: list[str]) -> None:
    lines.extend(["## Sensitive Evidence Notice", ""])
    for paragraph in REPORT_SENSITIVE_EVIDENCE_NOTICE:
        lines.extend([paragraph, ""])


def _kill_switch_warnings(lines: list[str], project_state: ProjectState, candidates: list[Candidate]) -> None:
    lines.extend(["## Kill-switch / Rabbit-hole Warnings", ""])
    kill_switch_candidates = [candidate for candidate in candidates if candidate.priority == "kill_switch"]

    if not kill_switch_candidates and not project_state.warnings:
        lines.extend(["No kill-switch candidates or project warnings were generated.", ""])
        return

    for candidate in kill_switch_candidates:
        guidance = candidate.kill_switch_guidance or "Review programme scope before manual testing."
        lines.append(f"- {candidate.id}: {_md(guidance)}")
    for warning in project_state.warnings:
        lines.append(f"- Project warning: {_md(warning)}")
    lines.append("")


def _unknowns(lines: list[str]) -> None:
    lines.extend(
        [
            "## Unknowns / Requires Manual Validation",
            "",
            "Candidates are evidence-backed review signals, not confirmed findings. "
            "Manual validation is required before any issue is described or escalated.",
            "",
        ]
    )


def _scope_status(value: bool | None) -> str:
    if value is True:
        return "in_scope"
    if value is False:
        return "out_of_scope"
    return "unknown"


def _csv(values: list[str]) -> str:
    if not values:
        return "none"
    return ", ".join(_md(value) for value in values)


def _workflow_list(values: list[str]) -> str:
    if not values:
        return "none detected"
    return ", ".join(f"`{_md(value)}`" for value in values)


def format_evidence_ids(evidence_ids: list[str], max_items: int = 4) -> str:
    """Format evidence IDs compactly for Markdown tables."""

    return _format_limited_list(evidence_ids, max_items)


def format_endpoint_list(endpoints: list[str], max_items: int = 4) -> str:
    """Format endpoint lists compactly for Markdown candidate sections."""

    return _format_limited_list(endpoints, max_items)


def _format_limited_list(values: list[str], max_items: int) -> str:
    if not values:
        return "none"
    if len(values) <= max_items:
        return _csv(values)

    visible = values[:max_items]
    remaining = len(values) - max_items
    return f"{_csv(visible)} ... +{remaining} more"


def _compact(value: str, limit: int = 120) -> str:
    compacted = " ".join(value.split())
    if len(compacted) <= limit:
        return compacted
    return compacted[: limit - 3].rstrip() + "..."


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
