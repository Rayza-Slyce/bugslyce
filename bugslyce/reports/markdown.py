"""Deterministic Markdown and JSON output generation for BugSlyce."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from bugslyce.core.models import Candidate, ProjectState


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
}


def render_markdown_report(project_state: ProjectState, candidates: list[Candidate]) -> str:
    """Render a cautious deterministic triage report."""

    lines: list[str] = [
        "# BugSlyce Triage Report",
        "",
        "This report is a deterministic manual-review aid. Candidates are not findings and require manual validation.",
        "",
    ]

    _scope_summary(lines, project_state)
    _input_files(lines, project_state)
    _asset_inventory(lines, project_state)
    _http_services(lines, project_state)
    _surface_areas(lines, candidates)
    _priority_queue(lines, candidates)
    _evidence_table(lines, project_state)
    _safe_next_steps(lines)
    _kill_switch_warnings(lines, project_state, candidates)
    _unknowns(lines)

    return "\n".join(lines).rstrip() + "\n"


def write_project_outputs(
    project_state: ProjectState,
    candidates: list[Candidate],
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write report.md and project_state.json to the provided output directory."""

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.md"
    json_path = output_dir / "project_state.json"

    report_path.write_text(render_markdown_report(project_state, candidates), encoding="utf-8")
    json_path.write_text(export_project_state_json(project_state, candidates), encoding="utf-8")

    return report_path, json_path


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
            f"- Input directory: `{project_state.input_dir}`",
            f"- Parsed scope summary: {project_state.scope_summary}",
            "- Scope status uses simple exact-host and suffix matching. Review programme scope before manual testing.",
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
    lines.extend(["## Interesting Surface Areas", ""])
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


def _priority_queue(lines: list[str], candidates: list[Candidate]) -> None:
    lines.extend(["## Priority Manual Testing Queue", ""])
    candidates_by_priority: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        candidates_by_priority[candidate.priority].append(candidate)

    for priority in PRIORITY_ORDER:
        lines.extend([f"### {priority}", ""])
        items = candidates_by_priority.get(priority, [])
        if not items:
            lines.extend(["No candidates in this priority bucket.", ""])
            continue
        for candidate in items:
            lines.extend(_candidate_lines(candidate))
            lines.append("")


def _candidate_lines(candidate: Candidate) -> list[str]:
    lines = [
        f"#### {candidate.id}: {_md(candidate.title)}",
        "",
        f"- Candidate type: `{candidate.candidate_type}`",
        f"- Priority: `{candidate.priority}`",
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


def _evidence_table(lines: list[str], project_state: ProjectState) -> None:
    lines.extend(["## Evidence Table", ""])
    if not project_state.evidence:
        lines.extend(["No evidence records were assembled from the parsed inputs.", ""])
        return

    lines.extend(["| Evidence ID | Source File | Type | Value |", "| --- | --- | --- | --- |"])
    for evidence in project_state.evidence:
        lines.append(
            "| "
            f"{evidence.id} | "
            f"{_md(evidence.source_file)} | "
            f"{_md(evidence.evidence_type)} | "
            f"{_md(_compact(evidence.value))} |"
        )
    lines.append("")


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
            "## Unknowns / Needs Manual Validation",
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
