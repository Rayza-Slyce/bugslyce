"""Read-only status and next-step advice for an existing recon directory."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from bugslyce.core.models import ProjectState
from bugslyce.core.project import build_project_state
from bugslyce.core.scope import parse_scope, scope_entry_target
from bugslyce.recon.path_followup import discover_same_origin_followup_urls
from bugslyce.reports.provenance import WorkflowProvenance, build_workflow_provenance
from bugslyce.time_utils import Clock, utc_now_iso
from bugslyce.triage.candidates import generate_candidates


@dataclass(frozen=True)
class ReconStatusPhase:
    """One locally detected recon phase."""

    id: str
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReconStatusResult:
    """Serializable status summary derived only from local evidence."""

    target: str
    input_dir: str
    source_input_dir: str
    generated_at: str
    manifest_profile: str | None
    workflow_summary: WorkflowProvenance
    scope_file: str | None
    scope_status: str
    phases: list[ReconStatusPhase]
    artifact_overview: dict[str, int]
    latest_execution: dict[str, Any] | None
    phase_specific_metadata: list[str]
    next_actions: list[str]
    safety_notes: list[str]


def build_recon_status(
    input_dir: Path,
    scope_file: Path | None = None,
    clock: Clock | None = None,
) -> ReconStatusResult:
    """Inspect a recon directory without executing commands or rewriting evidence."""

    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest(manifest_path)
    target = _required_text(manifest, "target", "Recon manifest does not contain a target.")
    profile = _optional_text(manifest.get("profile"))
    artifacts = _manifest_artifacts(manifest)

    scope_status = "not checked"
    resolved_scope: Path | None = None
    if scope_file is not None:
        resolved_scope = scope_file.expanduser().resolve()
        scope_status = _scope_status(target, resolved_scope)

    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_text = _read_optional_text(input_dir / "report.md")
    latest_execution = _load_latest_execution(input_dir)
    pipeline_metadata, pipeline_warning = _load_pipeline_metadata(input_dir, target)
    if pipeline_metadata is not None:
        latest_execution = _merge_pipeline_metadata(latest_execution, pipeline_metadata)
    elif pipeline_warning:
        latest_execution = _merge_pipeline_warning(latest_execution, pipeline_warning)
    phase_specific_metadata = _phase_specific_metadata(input_dir)
    artifact_files = [str(item.get("file", "")) for item in artifacts]

    detected = _detect_phases(
        input_dir=input_dir,
        artifact_files=artifact_files,
        report_text=report_text,
        latest_execution=latest_execution,
        phase_specific_metadata=phase_specific_metadata,
        scope_detected=any(
            evidence.evidence_type.startswith("scope_")
            for evidence in project_state.evidence
        ),
    )
    overview = _artifact_overview(
        project_state,
        candidates_count=len(candidates),
        artifact_files=artifact_files,
        input_dir=input_dir,
        pipeline_metadata=pipeline_metadata,
    )
    next_actions = _next_actions(
        project_state=project_state,
        manifest=manifest,
        target=target,
        detected=detected,
    )
    workflow_summary = build_workflow_provenance(project_state)

    return ReconStatusResult(
        target=target,
        input_dir=str(input_dir),
        source_input_dir=str(input_dir),
        generated_at=utc_now_iso(clock),
        manifest_profile=profile,
        workflow_summary=workflow_summary,
        scope_file=str(resolved_scope) if resolved_scope else None,
        scope_status=scope_status,
        phases=list(detected.values()),
        artifact_overview=overview,
        latest_execution=latest_execution,
        phase_specific_metadata=phase_specific_metadata,
        next_actions=next_actions,
        safety_notes=[
            "Status only; local evidence was inspected.",
            "No commands were executed.",
            "No network requests were made.",
            "Advice is based only on local evidence.",
            "Manual validation is still required.",
            "Absence of evidence is not proof of safety.",
        ],
    )


def write_recon_status(
    result: ReconStatusResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write deterministic status files without replacing recon evidence."""

    input_dir = input_dir.expanduser().resolve()
    json_path = input_dir / "recon_status.json"
    markdown_path = input_dir / "recon_status.md"
    json_path.write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_recon_status_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_recon_status_markdown(result: ReconStatusResult) -> str:
    """Render the full local recon status report."""

    lines = [
        "# BugSlyce Recon Status",
        "",
        f"Generated at: `{result.generated_at}`",
        "",
        "## Target",
        "",
        f"- Target: `{result.target}`",
        f"- Input directory: `{result.input_dir}`",
        f"- Manifest profile (raw): `{result.manifest_profile or 'not recorded'}`",
        f"- Scope status: {result.scope_status}",
    ]
    pipeline_profile = _deep_pipeline_profile(result)
    if pipeline_profile:
        lines.append(f"- Pipeline profile: `{pipeline_profile}`")
    deep_total = result.artifact_overview.get("deep_pipeline_phases_total", 0)
    if deep_total:
        lines.append(
            "- Deep pipeline phases: "
            f"{result.artifact_overview.get('deep_pipeline_phases_detected', 0)}/{deep_total}"
        )
    if result.scope_file:
        lines.append(f"- Scope file: `{result.scope_file}`")

    workflow = result.workflow_summary
    lines.extend(
        [
            "",
            "## Workflow / Provenance Summary",
            "",
            f"- Base discovery profile: `{workflow.base_discovery_profile}`",
            f"- Enrichment phases detected: {_display_list(workflow.enrichment_phases)}",
            (
                "- Content discovery profiles detected: "
                f"{_display_list(workflow.content_discovery_profiles)}"
            ),
            f"- Follow-up phases detected: {_display_list(workflow.followup_phases)}",
            f"- Raw discovered path evidence rows: {workflow.raw_discovered_path_rows}",
            f"- Unique discovered paths: {workflow.unique_discovered_paths}",
            (
                "- Duplicate discovered path evidence rows retained for auditability: "
                f"{workflow.duplicate_discovered_path_rows}"
            ),
        ]
    )

    lines.extend(["", "## Completed Phases Detected", ""])
    for phase in result.phases:
        lines.append(f"- {phase.name}: **{phase.status}** - {phase.detail}")

    lines.extend(["", "## Artefact Overview", ""])
    for key, value in result.artifact_overview.items():
        lines.append(f"- {key.replace('_', ' ').title()}: {value}")

    lines.extend(["", "## Latest Execution", ""])
    if result.latest_execution:
        for key, value in result.latest_execution.items():
            lines.append(f"- {key.replace('_', ' ').title()}: {_display_value(value)}")
    else:
        lines.append("- No generic latest execution metadata was detected.")
    if result.phase_specific_metadata:
        lines.append(
            "- Phase-specific metadata: "
            + ", ".join(f"`{name}`" for name in result.phase_specific_metadata)
        )
    else:
        lines.append("- Phase-specific metadata: none detected")

    lines.extend(["", "## Current Next-Step Advice", ""])
    for action in result.next_actions:
        lines.append(f"- {action}")

    lines.extend(["", "## Safety Notes", ""])
    for note in result.safety_notes:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def render_recon_status_summary(
    result: ReconStatusResult,
    json_path: Path,
    markdown_path: Path,
) -> str:
    """Render concise CLI status output."""

    detected_count = sum(phase.status == "detected" for phase in result.phases)
    lines = [
        "BugSlyce recon status complete",
        f"Generated at: {result.generated_at}",
        f"Target: {result.target}",
        f"Input directory: {result.input_dir}",
        f"Manifest profile (raw): {result.manifest_profile or 'not recorded'}",
        f"Workflow base: {result.workflow_summary.base_discovery_profile}",
        (
            "Content discovery profiles: "
            f"{_display_list(result.workflow_summary.content_discovery_profiles)}"
        ),
        (
            "Discovered paths: "
            f"{result.workflow_summary.raw_discovered_path_rows} raw evidence row(s), "
            f"{result.workflow_summary.unique_discovered_paths} unique, "
            f"{result.workflow_summary.duplicate_discovered_path_rows} duplicate row(s)"
        ),
        f"Scope status: {result.scope_status}",
        f"Detected phases: {detected_count}/{len(result.phases)}",
    ]
    pipeline_profile = _deep_pipeline_profile(result)
    if pipeline_profile:
        lines.append(f"Pipeline profile: {pipeline_profile}")
    deep_total = result.artifact_overview.get("deep_pipeline_phases_total", 0)
    if deep_total:
        lines.append(
            "Deep pipeline phases: "
            f"{result.artifact_overview.get('deep_pipeline_phases_detected', 0)}/{deep_total}"
        )
    lines.extend(
        [
            "Recommended next safe action:",
            f"- {result.next_actions[0]}",
        ]
    )
    for action in result.next_actions[1:]:
        lines.append(f"- {action}")
    lines.extend(
        [
            f"Status JSON path: {json_path}",
            f"Status Markdown path: {markdown_path}",
            "No commands were executed.",
            "No network requests were made.",
        ]
    )
    return "\n".join(lines)


def _load_manifest(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Recon manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Recon manifest must contain a JSON object: {path}")
    if not isinstance(payload.get("artifacts"), list):
        raise ValueError(f"Recon manifest field 'artifacts' must be a list: {path}")
    return payload


def _scope_status(target: str, scope_file: Path) -> str:
    if not scope_file.is_file():
        raise ValueError(f"Scope file does not exist: {scope_file}")
    parsed = parse_scope(scope_file)
    target_normalized = target.strip().lower().rstrip(".")
    in_scope_targets = {
        normalized
        for value in parsed.in_scope
        if (normalized := scope_entry_target(value)) is not None
    }
    if target_normalized in in_scope_targets:
        return "in scope"
    return "warning: target is not an exact target-like entry in the supplied scope"


def _detect_phases(
    input_dir: Path,
    artifact_files: list[str],
    report_text: str,
    latest_execution: dict[str, Any] | None,
    phase_specific_metadata: list[str],
    scope_detected: bool,
) -> dict[str, ReconStatusPhase]:
    names = [Path(value).name for value in artifact_files]
    latest_mode = str((latest_execution or {}).get("mode", ""))
    content_plan_present = (
        (input_dir / "content_discovery_plan.json").is_file()
        or bool((latest_execution or {}).get("plan_path"))
        or _phase_metadata_references_plan(input_dir)
    )
    checks = [
        ("scope", "Scope loaded", scope_detected, "scope evidence present"),
        (
            "nmap_full",
            "Nmap full TCP discovery",
            "nmap-allports.txt" in names,
            "nmap all-ports artifact present",
        ),
        (
            "nmap_services",
            "Nmap service/version scan",
            any(name.startswith("nmap-services") for name in names),
            "nmap service artifact present",
        ),
        (
            "http_metadata",
            "HTTP metadata",
            any(
                name.startswith(("homepage-", "robots-", "curl-headers-"))
                and not name.startswith(
                    ("curl-headers-followup-", "curl-headers-content-followup-")
                )
                for name in names
            ),
            "headers, robots, or homepage artifact present",
        ),
        (
            "path_followup",
            "Existing evidence path follow-up",
            any(name.startswith("curl-headers-followup-") for name in names),
            "evidence-derived path header artifact present",
        ),
        (
            "content_plan",
            "Content discovery plan",
            content_plan_present,
            "local plan or plan reference detected",
        ),
        (
            "content_tiny",
            "Tiny root content discovery",
            any(name.startswith("gobuster-tiny-") for name in names),
            "tiny-profile gobuster artifact present",
        ),
        (
            "content_light",
            "Light root content discovery",
            any(name.startswith("gobuster-") and not name.startswith("gobuster-tiny-") for name in names),
            "light-profile gobuster artifact present",
        ),
        (
            "content_followup",
            "Content-result follow-up",
            any(name.startswith("curl-headers-content-followup-") for name in names)
            or latest_mode == "content-followup",
            "content-result header artifact or execution metadata present",
        ),
        (
            "body_fetch",
            "Selective body fetch",
            any(name.startswith("body-fetch-") for name in names)
            or latest_mode == "body-fetch",
            "body-fetch HTML artifact or execution metadata present",
        ),
        (
            "operator_summary",
            "Operator summary/report generated",
            "## Operator Summary" in report_text,
            "report contains the Operator Summary",
        ),
        (
            "encoded_classification",
            "Encoded-artifact classification visible",
            "Encoded Artefact Classification" in report_text,
            "report contains encoded-artifact classification",
        ),
        (
            "latest_execution",
            "Latest execution metadata",
            latest_execution is not None,
            "generic recon_execution metadata present",
        ),
        (
            "content_run_metadata",
            "Phase-specific content-run metadata",
            any("content_run" in name for name in phase_specific_metadata),
            "phase-specific content-run metadata present",
        ),
    ]
    return {
        phase_id: ReconStatusPhase(
            id=phase_id,
            name=name,
            status="detected" if present else "not detected",
            detail=detail if present else "no supporting local evidence detected",
        )
        for phase_id, name, present, detail in checks
    }


def _artifact_overview(
    project_state: ProjectState,
    candidates_count: int,
    artifact_files: list[str],
    input_dir: Path,
    pipeline_metadata: dict[str, Any] | None = None,
) -> dict[str, int]:
    open_ports = {
        (record.host, record.port, record.protocol)
        for record in project_state.port_services
        if record.state.lower() == "open"
    }
    raw_path_count = len(project_state.discovered_paths)
    unique_path_count = len(
        {record.url.strip() for record in project_state.discovered_paths if record.url.strip()}
    )
    overview = {
        "open_ports": len(open_ports),
        "http_services": len(project_state.http_services),
        "raw_discovered_path_evidence_rows": raw_path_count,
        "unique_discovered_paths": unique_path_count,
        "duplicate_discovered_path_evidence_rows": raw_path_count - unique_path_count,
        "http_artifacts": len(project_state.http_artifacts),
        "manual_review_candidates": candidates_count,
        "gobuster_outputs": sum(Path(value).name.startswith("gobuster-") for value in artifact_files),
        "body_fetch_files": sum(Path(value).name.startswith("body-fetch-") for value in artifact_files),
        "execution_metadata_files": len(list(input_dir.glob("recon_execution*.json")))
        + len(list(input_dir.glob("recon_execution*.md"))),
    }
    deep_counts = _deep_pipeline_phase_counts(input_dir, pipeline_metadata)
    if deep_counts is not None:
        detected, total = deep_counts
        overview["deep_pipeline_phases_detected"] = detected
        overview["deep_pipeline_phases_total"] = total
    return overview


def _load_latest_execution(input_dir: Path) -> dict[str, Any] | None:
    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    payload: dict[str, Any] = {}
    if json_path.is_file():
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key in (
                    "mode",
                    "profile",
                    "commands_started",
                    "commands_completed",
                    "commands_timed_out",
                    "execution_count",
                    "selected_step_id",
                    "selected_origin",
                    "partial_artifacts_imported",
                    "completed_artifacts_imported",
                ):
                    if key in raw:
                        payload[key] = raw[key]
                artifact_paths = raw.get("artifact_paths")
                if isinstance(artifact_paths, list):
                    payload["artifacts_recorded"] = len(artifact_paths)
        except (OSError, UnicodeError, json.JSONDecodeError):
            payload["status"] = "metadata JSON could not be parsed"
    if markdown_path.is_file():
        heading = next(
            (
                line.lstrip("#").strip()
                for line in markdown_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("#")
            ),
            None,
        )
        if heading:
            payload["heading"] = heading
    return payload or None


def _load_pipeline_metadata(input_dir: Path, target: str) -> tuple[dict[str, Any] | None, str | None]:
    path = input_dir / "project_pipeline.json"
    if not path.is_file():
        return None, None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "project_pipeline.json could not be parsed"
    if not isinstance(payload, dict):
        return None, "project_pipeline.json was not an object"
    pipeline_target = _optional_text(payload.get("target"))
    if pipeline_target is None or pipeline_target.lower().rstrip(".") != target:
        return None, "project_pipeline.json target did not match"
    output_dir = payload.get("output_dir")
    if not isinstance(output_dir, str):
        return None, "project_pipeline.json output_dir was invalid"
    try:
        if Path(output_dir).expanduser().resolve() != input_dir:
            return None, "project_pipeline.json output_dir did not match"
    except (OSError, RuntimeError):
        return None, "project_pipeline.json output_dir was invalid"
    if payload.get("profile") not in {"lab-safe-tiny", "standard-bounded", "deep-bounded"}:
        return None, "project_pipeline.json profile was invalid"
    if payload.get("final_status") not in {"pending", "running", "completed", "failed"}:
        return None, "project_pipeline.json final_status was invalid"
    steps = payload.get("steps")
    if not isinstance(steps, list):
        return None, "project_pipeline.json steps were invalid"
    valid_step_statuses = {"pending", "running", "completed", "failed", "skipped_existing", "noop"}
    for step in steps:
        if not isinstance(step, dict):
            return None, "project_pipeline.json step was invalid"
        if not isinstance(step.get("step_id"), str) or not isinstance(step.get("status"), str):
            return None, "project_pipeline.json step fields were invalid"
        if step["status"] not in valid_step_statuses:
            return None, "project_pipeline.json step status was invalid"
    return payload, None


def _merge_pipeline_metadata(
    latest_execution: dict[str, Any] | None,
    pipeline_metadata: dict[str, Any],
) -> dict[str, Any] | None:
    merged = dict(latest_execution or {})
    profile = pipeline_metadata.get("profile")
    final_status = pipeline_metadata.get("final_status")
    if isinstance(profile, str) and profile:
        merged["pipeline_profile"] = profile
    if isinstance(final_status, str) and final_status:
        merged["pipeline_final_status"] = final_status
    return merged or None


def _merge_pipeline_warning(
    latest_execution: dict[str, Any] | None,
    warning: str,
) -> dict[str, Any]:
    merged = dict(latest_execution or {})
    merged["pipeline_metadata_warning"] = warning
    return merged


def _deep_pipeline_phase_counts(
    input_dir: Path,
    pipeline_metadata: dict[str, Any] | None,
) -> tuple[int, int] | None:
    fixed_groups = (
        (
            input_dir / "deep_source_route_collection.md",
            input_dir / "deep_source_route_collection.json",
        ),
        (
            input_dir / "deep_recon_review.md",
            input_dir / "deep_recon_runbook.md",
            input_dir / "deep_recon_orchestration.json",
        ),
    )
    has_any_deep_file = any(path.exists() for group in fixed_groups for path in group)
    profile = (pipeline_metadata or {}).get("profile")
    if profile != "deep-bounded":
        if has_any_deep_file:
            return 0, len(fixed_groups)
        return None
    statuses = _pipeline_step_statuses(pipeline_metadata)
    detected = 0
    if statuses.get("PIPELINE-STEP-010D") == "completed" and all(
        path.is_file() for path in fixed_groups[0]
    ):
        detected += 1
    if statuses.get("PIPELINE-STEP-011D") == "completed" and all(
        path.is_file() for path in fixed_groups[1]
    ):
        detected += 1
    return detected, len(fixed_groups)


def _pipeline_step_statuses(pipeline_metadata: dict[str, Any] | None) -> dict[str, str]:
    steps = (pipeline_metadata or {}).get("steps")
    if not isinstance(steps, list):
        return {}
    statuses: dict[str, str] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("step_id")
        status = step.get("status")
        if isinstance(step_id, str) and isinstance(status, str):
            statuses[step_id] = status
    return statuses


def _deep_pipeline_profile(result: ReconStatusResult) -> str | None:
    profile = (result.latest_execution or {}).get("pipeline_profile")
    return profile if profile == "deep-bounded" else None


def _phase_specific_metadata(input_dir: Path) -> list[str]:
    names = {
        path.name
        for pattern in ("recon_execution_*.json", "recon_execution_*.md")
        for path in input_dir.glob(pattern)
    }
    return sorted(names)


def _phase_metadata_references_plan(input_dir: Path) -> bool:
    for path in input_dir.glob("recon_execution_*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and _optional_text(payload.get("plan_path")):
            return True
    return False


def _next_actions(
    project_state: ProjectState,
    manifest: dict[str, object],
    target: str,
    detected: dict[str, ReconStatusPhase],
) -> list[str]:
    has = lambda phase_id: detected[phase_id].status == "detected"
    content_considered, content_pending = _pending_content_followups(
        project_state,
        manifest,
        target,
    )
    body_considered, body_pending = _pending_body_fetches(project_state, manifest, target)
    path_followup_pending = discover_same_origin_followup_urls(
        project_state,
        target,
        max_followups=max(1, len(project_state.http_artifacts)),
    )

    actions: list[str] = []
    if (has("nmap_full") or _has_nmap_discovery(manifest)) and not has("nmap_services"):
        actions.append(
            "Recommended next safe action: run `bugslyce recon nmap-services` "
            "against the existing discovery output after scope review."
        )
    elif project_state.http_services and not has("http_metadata"):
        actions.append(
            "Recommended next safe action: run `bugslyce recon http-metadata` "
            "for the already discovered HTTP services."
        )
    elif content_pending:
        actions.append(
            "Recommended next safe action: run `bugslyce recon content-followup`; "
            f"{len(content_pending)} eligible URL(s) remain from {content_considered} "
            "content-discovery path(s) considered."
        )
    elif body_pending:
        actions.append(
            "Recommended next safe action: run `bugslyce recon body-fetch`; "
            f"{len(body_pending)} eligible URL(s) remain from {body_considered} "
            "followed path(s) considered."
        )
    elif (
        path_followup_pending
        and has("http_metadata")
        and not has("path_followup")
        and not (has("content_tiny") or has("content_light"))
    ):
        actions.append(
            "Recommended next safe action: run `bugslyce recon path-followup` "
            "for same-origin paths already present in HTTP evidence."
        )
    elif project_state.http_services and not (
        has("content_plan") or has("content_tiny") or has("content_light")
    ):
        actions.append(
            "Recommended next safe action: create a `lab-root-tiny` "
            "`bugslyce recon content-plan` for the discovered HTTP origins."
        )
    else:
        actions.append(
            "No eligible automated follow-up appears pending; review the Operator "
            "Summary and raw evidence manually."
        )

    if has("content_tiny") and not has("content_light"):
        actions.append(
            "Optional broader root discovery: create a `lab-root-light` content plan "
            "and run approved origins one immutable step at a time."
        )
    return actions


def _pending_content_followups(
    project_state: ProjectState,
    manifest: dict[str, object],
    target: str,
) -> tuple[int, list[str]]:
    followed = {
        _normalize_url(url)
        for artifact in _manifest_artifacts(manifest)
        if Path(str(artifact.get("file", ""))).name.startswith("curl-headers-content-followup-")
        and (url := _optional_text(artifact.get("url")))
    }
    robots = {
        _normalize_url(url)
        for artifact in _manifest_artifacts(manifest)
        if artifact.get("type") == "robots" and (url := _optional_text(artifact.get("url")))
    }
    home_origins = {
        _origin(url)
        for artifact in _manifest_artifacts(manifest)
        if artifact.get("type") == "html"
        and (url := _optional_text(artifact.get("url")))
        and urlparse(url).path in {"", "/"}
    }
    considered: set[str] = set()
    pending: set[str] = set()
    for record in project_state.discovered_paths:
        if not Path(record.source).name.startswith("gobuster-"):
            continue
        considered.add(record.url)
        parsed = urlparse(record.url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
            continue
        normalized = _normalize_url(record.url)
        if record.status_code in {301, 302} and record.redirect_location:
            redirected = urlparse(urljoin(normalized, record.redirect_location))
            if redirected.hostname == target and redirected.netloc == parsed.netloc:
                normalized = _normalize_url(redirected.geturl())
                parsed = redirected
        path = parsed.path or "/"
        if (
            path == "/"
            or parsed.fragment
            or _has_traversal(path)
            or normalized in followed
            or normalized in robots
            or record.status_code == 404
            or "dead_path" in record.tags
        ):
            continue
        if path.rstrip("/").lower().endswith("/robots.txt"):
            continue
        if path.rstrip("/").lower().endswith("/index.html") and _origin(normalized) in home_origins:
            continue
        pending.add(normalized)
    return len(considered), sorted(pending)


def _pending_body_fetches(
    project_state: ProjectState,
    manifest: dict[str, object],
    target: str,
) -> tuple[int, list[str]]:
    artifacts = _manifest_artifacts(manifest)
    followed = {
        _normalize_url(url)
        for artifact in artifacts
        if Path(str(artifact.get("file", ""))).name.startswith("curl-headers-content-followup-")
        and (url := _optional_text(artifact.get("url")))
    }
    fetched = {
        _normalize_url(url)
        for artifact in artifacts
        if artifact.get("type") == "html" and (url := _optional_text(artifact.get("url")))
    }
    status_by_url = {
        _normalize_url(record.url): record.status_code
        for record in project_state.discovered_paths
        if Path(record.source).name.startswith("curl-headers-content-followup-")
    }
    static_suffixes = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".css", ".js", ".svg",
        ".woff", ".ttf", ".pdf", ".zip", ".tar", ".gz",
    }
    application_suffixes = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}
    pending: list[str] = []
    for url in sorted(followed):
        parsed = urlparse(url)
        path = parsed.path or "/"
        suffix = Path(path.rstrip("/")).suffix.lower()
        if (
            parsed.hostname != target
            or parsed.scheme not in {"http", "https"}
            or status_by_url.get(url) != 200
            or path == "/"
            or path.rstrip("/").lower().endswith(("/robots.txt", "/index.html"))
            or parsed.fragment
            or _has_traversal(path)
            or url in fetched
            or suffix in static_suffixes
            or (suffix and suffix not in application_suffixes)
        ):
            continue
        pending.append(url)
    return len(followed), pending


def _has_nmap_discovery(manifest: dict[str, object]) -> bool:
    return any(
        artifact.get("type") == "nmap"
        and Path(str(artifact.get("file", ""))).name in {
            "nmap-allports.txt",
            "nmap-top1000.txt",
        }
        for artifact in _manifest_artifacts(manifest)
    )


def _manifest_artifacts(manifest: dict[str, object]) -> list[dict[str, object]]:
    value = manifest.get("artifacts")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _required_text(payload: dict[str, object], key: str, message: str) -> str:
    value = _optional_text(payload.get(key))
    if value is None:
        raise ValueError(message)
    return value.lower().rstrip(".")


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _has_traversal(path: str) -> bool:
    return any(part == ".." for part in path.split("/"))


def _display_value(value: object) -> str:
    if value is None:
        return "not recorded"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _display_list(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none detected"
