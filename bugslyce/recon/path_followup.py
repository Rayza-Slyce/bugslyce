"""Check bounded same-origin paths already present in BugSlyce evidence."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse, urlunparse

from bugslyce.core.models import (
    ProjectState,
    ReconPathFollowupExecutionResult,
)
from bugslyce.core.project import build_project_state
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.path_followup_commands import (
    MAX_PATH_FOLLOWUPS,
    build_path_followup_commands,
)
from bugslyce.recon.runner import LivePathFollowupRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


FOLLOWUP_ARTIFACT_TYPES = {"link", "script_or_asset", "allow_rule", "disallow_rule"}


class PathFollowupNoWork(Exception):
    """Clean outcome when no same-origin path follow-up URL is eligible."""

    def __init__(self, considered: int) -> None:
        super().__init__(
            "No eligible same-origin paths were found in existing HTTP evidence."
        )
        self.considered = considered


def discover_same_origin_followup_urls(
    project_state: ProjectState,
    target: str,
    max_followups: int = MAX_PATH_FOLLOWUPS,
) -> list[str]:
    """Return deterministic evidence-derived same-origin URLs."""

    allowed_origins = _discovered_origins(project_state, target)
    urls: set[str] = set()
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type not in FOLLOWUP_ARTIFACT_TYPES:
            continue
        value = artifact.value.strip()
        if not _is_concrete_relative_path(value):
            continue
        source = urlparse(artifact.url)
        origin = urlunparse((source.scheme, source.netloc, "/", "", "", ""))
        if origin not in allowed_origins:
            continue
        joined = urljoin(origin, value)
        parsed = urlparse(joined)
        if parsed.hostname != target or parsed.scheme not in {"http", "https"}:
            continue
        normalized = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, "")
        )
        if parsed.path in {"", "/", "/robots.txt"}:
            continue
        urls.add(normalized)
    return sorted(urls, key=_followup_sort_key)[:max_followups]


def run_path_followup_workflow(
    input_dir: Path,
    scope_file: Path,
    runner: LivePathFollowupRunner | None = None,
) -> ReconPathFollowupExecutionResult:
    """Run HEAD checks for previously discovered same-origin paths."""

    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    if manifest is None:
        raise ValueError("Path follow-up requires recon_manifest.json from an HTTP metadata run.")
    if not _has_http_metadata_artifacts(manifest):
        raise ValueError(
            "Path follow-up requires saved HTML or robots artifacts from an HTTP metadata run."
        )

    initial_state = build_project_state(input_dir)
    target_value = manifest.get("target")
    if not isinstance(target_value, str) or not target_value.strip():
        raise ValueError("Recon manifest does not contain a target.")
    target = validate_explicit_nmap_target_scope(target_value.strip().lower(), scope_file)

    allowed_origins = _discovered_origins(initial_state, target)
    if not allowed_origins:
        raise ValueError("No discovered HTTP service origins are available for path follow-up.")
    all_urls = discover_same_origin_followup_urls(
        initial_state,
        target,
        max_followups=max(MAX_PATH_FOLLOWUPS, len(initial_state.http_artifacts)),
    )
    if not all_urls:
        raise PathFollowupNoWork(len(initial_state.http_artifacts))
    followup_urls = all_urls[:MAX_PATH_FOLLOWUPS]
    warnings = list(initial_state.warnings)
    if len(all_urls) > MAX_PATH_FOLLOWUPS:
        warnings.append(f"Discovered-path follow-up capped at {MAX_PATH_FOLLOWUPS} URLs.")

    commands = build_path_followup_commands(followup_urls, target, input_dir)
    live_runner = runner or LivePathFollowupRunner(
        input_dir,
        target,
        allowed_origins,
        set(followup_urls),
    )
    command_results = []
    for command in commands:
        result = live_runner.run(command)
        if result.error or result.exit_code != 0:
            raise ValueError(
                result.error or "Discovered-path follow-up did not complete successfully."
            )
        if not Path(result.output_file).is_file():
            raise ValueError(
                "Discovered-path follow-up completed without creating its expected output file."
            )
        command_results.append(result)

    updated_manifest = _updated_manifest(manifest, followup_urls, command_results)
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)
    combined_warnings = list(dict.fromkeys([*warnings, *project_state.warnings]))
    return ReconPathFollowupExecutionResult(
        mode="path-followup",
        target=target,
        scope_file=str(scope_file),
        input_dir=str(input_dir),
        followup_urls=followup_urls,
        artifact_paths=[result.output_file for result in command_results],
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=len(command_results),
        command_results=command_results,
        warnings=combined_warnings,
    )


def write_path_followup_execution_result(
    result: ReconPathFollowupExecutionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for path follow-up execution."""

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_path_followup_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_path_followup_execution_markdown(
    result: ReconPathFollowupExecutionResult,
) -> str:
    """Render execution metadata for bounded discovered-path checks."""

    return "\n".join(
        [
            "# BugSlyce Discovered-Path Follow-up",
            "",
            f"- Target: `{result.target}`",
            f"- Input/output directory: `{result.input_dir}`",
            f"- Paths processed: {len(result.followup_urls)}",
            f"- Artifacts written: {len(result.artifact_paths)}",
            f"- Manifest: `{result.manifest_path}`",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            "Discovered-path follow-up requests were executed.",
            "No content discovery, brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_path_followup_no_work(outcome: PathFollowupNoWork) -> str:
    """Render a calm CLI summary for an idempotent no-work result."""

    return "\n".join(
        [
            "No eligible same-origin paths were found in existing HTTP evidence.",
            f"HTTP artifacts considered: {outcome.considered}",
            (
                "All currently observed paths are absent, static, off-scope, "
                "duplicate, or not actionable for path follow-up."
            ),
            "No path-followup request was executed.",
        ]
    )


def render_path_followup_execution_summary(
    result: ReconPathFollowupExecutionResult,
) -> str:
    """Render concise CLI output for discovered-path follow-up."""

    return "\n".join(
        [
            "BugSlyce discovered-path follow-up complete",
            f"Target: {result.target}",
            f"Input/output directory: {result.input_dir}",
            f"Paths processed: {len(result.followup_urls)}",
            f"Artifacts written: {len(result.artifact_paths)}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "Discovered-path follow-up requests were executed.",
            "No content discovery, brute force, exploitation, or form submission was run.",
        ]
    )


def _discovered_origins(project_state: ProjectState, target: str) -> set[str]:
    origins: set[str] = set()
    for service in project_state.http_services:
        parsed = urlparse(service.url)
        if parsed.scheme in {"http", "https"} and parsed.hostname == target:
            origins.add(urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")))
    return origins


def _is_concrete_relative_path(value: str) -> bool:
    if not value.startswith("/") or value.startswith("//") or value.startswith("/\\"):
        return False
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    decoded_segments = [unquote(segment).lower() for segment in parsed.path.split("/")]
    return all(segment not in {".", ".."} for segment in decoded_segments)


def _load_manifest_payload(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Recon manifest must contain a JSON object: {path}")
    return payload


def _has_http_metadata_artifacts(manifest: dict[str, object]) -> bool:
    artifacts = manifest.get("artifacts")
    return isinstance(artifacts, list) and any(
        isinstance(artifact, dict) and artifact.get("type") in {"html", "robots"}
        for artifact in artifacts
    )


def _updated_manifest(
    manifest: dict[str, object],
    followup_urls: list[str],
    command_results,
) -> dict[str, object]:
    payload = dict(manifest)
    existing = payload.get("artifacts")
    artifacts = list(existing) if isinstance(existing, list) else []
    generated_names = {Path(result.output_file).name for result in command_results}
    artifacts = [
        artifact
        for artifact in artifacts
        if not (
            isinstance(artifact, dict)
            and artifact.get("file") in generated_names
        )
    ]
    results_by_url = {
        result.command_id: result
        for result in command_results
    }
    for index, url in enumerate(followup_urls, start=1):
        result = results_by_url.get(f"CMD-PATH-FOLLOWUP-{index:03d}")
        if result is None:
            continue
        artifacts.append(
            {
                "type": "http_headers",
                "file": Path(result.output_file).name,
                "url": url,
                "description": "Bounded header request for discovered same-origin path",
            }
        )

    original_profile = payload.get("profile")
    suffix = "-plus-path-followup"
    if isinstance(original_profile, str) and original_profile:
        profile = original_profile if original_profile.endswith(suffix) else f"{original_profile}{suffix}"
    else:
        profile = "http-metadata-plus-path-followup"
    payload.update({"profile": profile, "artifacts": artifacts})
    return payload


def _followup_sort_key(url: str) -> tuple[str, int, str, str]:
    parsed = urlparse(url)
    return (
        parsed.scheme,
        parsed.port or (443 if parsed.scheme == "https" else 80),
        parsed.path,
        parsed.query,
    )
