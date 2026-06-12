"""Dynamically follow up paths found by prior content discovery."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
import json
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse, urlunparse

from bugslyce.core.models import (
    DiscoveredPath,
    ProjectState,
    ReconContentFollowupExecutionResult,
)
from bugslyce.core.project import build_project_state
from bugslyce.recon.content_followup_commands import (
    MAX_CONTENT_FOLLOWUPS,
    MAX_CONTENT_FOLLOWUPS_PER_ORIGIN,
    build_content_followup_commands,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.runner import LiveContentFollowupRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


INTERESTING_SEGMENTS = {
    "admin",
    "login",
    "upload",
    "uploads",
    "backup",
    "old",
    "dev",
    "test",
    "staging",
    "private",
    "secret",
    "hidden",
    "api",
    "portal",
    "dashboard",
    "config",
    "files",
}
STATIC_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".css",
    ".js",
    ".svg",
    ".woff",
    ".ttf",
}


class ContentFollowupExecutionIncomplete(ValueError):
    """Raised after an honest incomplete follow-up result is assembled."""

    def __init__(self, message: str, result: ReconContentFollowupExecutionResult) -> None:
        super().__init__(message)
        self.result = result


def select_content_followup_urls(
    project_state: ProjectState,
    target: str,
    manifest: dict[str, object],
    max_total: int = MAX_CONTENT_FOLLOWUPS,
    max_per_origin: int = MAX_CONTENT_FOLLOWUPS_PER_ORIGIN,
) -> tuple[int, list[str]]:
    """Rank generic gobuster-derived paths and return bounded selected URLs."""

    already_followed = _already_followed_urls(manifest)
    robots_urls = _manifest_urls(manifest, {"robots"})
    homepage_origins = {
        _origin(url)
        for url in _manifest_urls(manifest, {"html"})
        if urlparse(url).path in {"", "/"}
    }
    considered_urls: set[str] = set()
    best_by_url: dict[str, tuple[int, str]] = {}
    for record in project_state.discovered_paths:
        if not _is_content_discovery_record(record):
            continue
        considered_urls.add(record.url)
        normalized = _eligible_url(
            record,
            target,
            already_followed,
            robots_urls,
            homepage_origins,
        )
        if normalized is None:
            continue
        score = _score_discovered_path(record, normalized)
        current = best_by_url.get(normalized)
        if current is None or score > current[0]:
            best_by_url[normalized] = (score, normalized)

    ranked = sorted(best_by_url.values(), key=lambda item: (-item[0], item[1]))
    selected: list[str] = []
    per_origin: dict[str, int] = defaultdict(int)
    for _score, url in ranked:
        origin = _origin(url)
        if per_origin[origin] >= max_per_origin:
            continue
        selected.append(url)
        per_origin[origin] += 1
        if len(selected) >= max_total:
            break
    return len(considered_urls), selected


def run_content_followup_workflow(
    input_dir: Path,
    scope_file: Path,
    runner: LiveContentFollowupRunner | None = None,
) -> ReconContentFollowupExecutionResult:
    """Run bounded HEAD checks for selected content-discovery results."""

    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    target_value = manifest.get("target")
    if not isinstance(target_value, str) or not target_value.strip():
        raise ValueError("Recon manifest does not contain a target.")
    target = validate_explicit_nmap_target_scope(target_value.strip().lower(), scope_file)

    initial_state = build_project_state(input_dir)
    considered, selected_urls = select_content_followup_urls(
        initial_state,
        target,
        manifest,
    )
    if considered == 0:
        raise ValueError("No discovered_path records from content discovery artifacts were found.")
    if not selected_urls:
        raise ValueError("No eligible content-discovery result URLs remain for follow-up.")

    allowed_origins = {_origin(url) for url in selected_urls}
    commands = build_content_followup_commands(selected_urls, target, input_dir)
    live_runner = runner or LiveContentFollowupRunner(
        input_dir,
        target,
        allowed_origins,
        set(selected_urls),
    )
    command_results = []
    for command in commands:
        result = live_runner.run(command)
        if result.executed:
            command_results.append(result)
        if result.executed and result.exit_code is None and result.error:
            completed_results = [
                item for item in command_results if item.exit_code == 0 and not item.error
            ]
            execution_result = _finalize_execution(
                input_dir,
                scope_file,
                target,
                manifest_path,
                manifest,
                considered,
                selected_urls,
                command_results,
                completed_results,
                timed_out=1,
            )
            raise ContentFollowupExecutionIncomplete(
                result.error,
                execution_result,
            )
        if result.error or result.exit_code != 0:
            raise ValueError(result.error or "Content-result follow-up did not complete successfully.")
        if not Path(result.output_file).is_file():
            raise ValueError(
                "Content-result follow-up completed without creating its expected output file."
            )
    return _finalize_execution(
        input_dir,
        scope_file,
        target,
        manifest_path,
        manifest,
        considered,
        selected_urls,
        command_results,
        command_results,
        timed_out=0,
    )


def _finalize_execution(
    input_dir: Path,
    scope_file: Path,
    target: str,
    manifest_path: Path,
    manifest: dict[str, object],
    considered: int,
    selected_urls: list[str],
    command_results,
    artifact_results,
    timed_out: int,
) -> ReconContentFollowupExecutionResult:
    completed_urls = selected_urls[: len(artifact_results)]
    updated_manifest = _updated_manifest(manifest, completed_urls, artifact_results)
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)
    return ReconContentFollowupExecutionResult(
        mode="content-followup",
        target=target,
        scope_file=str(scope_file),
        input_dir=str(input_dir),
        discovered_paths_considered=considered,
        followup_urls_selected=selected_urls,
        artifact_paths=[result.output_file for result in artifact_results],
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        commands_started=len(command_results),
        commands_completed=len(artifact_results),
        commands_timed_out=timed_out,
        command_results=command_results,
        no_recursion=True,
        no_wordlists=True,
        no_arbitrary_urls=True,
        no_exploitation=True,
        warnings=project_state.warnings,
    )


def write_content_followup_execution_result(
    result: ReconContentFollowupExecutionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for content-result follow-up."""

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_content_followup_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_content_followup_execution_markdown(
    result: ReconContentFollowupExecutionResult,
) -> str:
    """Render execution metadata for content-result follow-up."""

    return "\n".join(
        [
            "# BugSlyce Content-Result Follow-up",
            "",
            f"- Target: `{result.target}`",
            f"- Input/output directory: `{result.input_dir}`",
            f"- Discovered paths considered: {result.discovered_paths_considered}",
            f"- Follow-up URLs selected: {len(result.followup_urls_selected)}",
            f"- Commands started: {result.commands_started}",
            f"- Commands completed: {result.commands_completed}",
            f"- Commands timed out: {result.commands_timed_out}",
            f"- Artifacts written: {len(result.artifact_paths)}",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            "Content-result follow-up requests were executed.",
            "No recursion, wordlists, brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_content_followup_execution_summary(
    result: ReconContentFollowupExecutionResult,
) -> str:
    """Render concise CLI output for content-result follow-up."""

    return "\n".join(
        [
            "BugSlyce content-result follow-up complete",
            f"Target: {result.target}",
            f"Input/output directory: {result.input_dir}",
            f"Discovered paths considered: {result.discovered_paths_considered}",
            f"Follow-up URLs selected: {len(result.followup_urls_selected)}",
            f"Artifacts written: {len(result.artifact_paths)}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "Content-result follow-up requests were executed.",
            "No recursion, wordlists, brute force, exploitation, or form submission was run.",
        ]
    )


def _eligible_url(
    record: DiscoveredPath,
    target: str,
    already_followed: set[str],
    robots_urls: set[str],
    homepage_origins: set[str],
) -> str | None:
    parsed = urlparse(record.url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
        return None
    if parsed.fragment or _has_traversal(parsed.path):
        return None
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    if record.status_code in {301, 302} and record.redirect_location:
        redirected = urlparse(urljoin(normalized, record.redirect_location))
        if (
            redirected.scheme in {"http", "https"}
            and redirected.hostname == target
            and redirected.netloc == parsed.netloc
            and not redirected.fragment
            and not _has_traversal(redirected.path)
        ):
            normalized = urlunparse(
                (
                    redirected.scheme,
                    redirected.netloc,
                    redirected.path or "/",
                    "",
                    redirected.query,
                    "",
                )
            )
            parsed = redirected
    if parsed.path in {"", "/"} or normalized in already_followed or normalized in robots_urls:
        return None
    if parsed.path.rstrip("/").lower().endswith("/robots.txt"):
        return None
    if parsed.path.rstrip("/").lower().endswith("/index.html") and _origin(normalized) in homepage_origins:
        return None
    if record.status_code == 404 or "dead_path" in record.tags:
        return None
    return normalized


def _score_discovered_path(record: DiscoveredPath, url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.lower()
    score = 0
    if record.status_code in {401, 403}:
        score += 7
    elif record.status_code == 200:
        score += 4
    elif record.status_code in {301, 302}:
        score += 3
    if path.endswith("/"):
        score += 3
    redirect_path = urlparse(record.redirect_location or "").path
    if record.status_code in {301, 302} and redirect_path.endswith("/"):
        score += 2
    suffix = Path(path.rstrip("/")).suffix.lower()
    if not suffix:
        score += 2
    segments = {segment for segment in path.strip("/").split("/") if segment}
    score += 2 * len(segments & INTERESTING_SEGMENTS)
    if suffix in STATIC_SUFFIXES or "static_asset" in record.tags:
        score -= 6
    if "dead_low_signal" in record.tags or "low_signal" in record.tags:
        score -= 3
    return score


def _is_content_discovery_record(record: DiscoveredPath) -> bool:
    return Path(record.source).name.startswith("gobuster-")


def _already_followed_urls(manifest: dict[str, object]) -> set[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        artifact["url"]
        for artifact in artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("url"), str)
        and (
            str(artifact.get("file", "")).startswith("curl-headers-content-followup-")
            or "content-discovery result follow-up" in str(artifact.get("description", "")).lower()
        )
    }


def _manifest_urls(manifest: dict[str, object], types: set[str]) -> set[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        artifact["url"]
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("type") in types
        and isinstance(artifact.get("url"), str)
    }


def _updated_manifest(
    manifest: dict[str, object],
    selected_urls: list[str],
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
    results = {result.command_id: result for result in command_results}
    for index, url in enumerate(selected_urls, start=1):
        result = results.get(f"CMD-CONTENT-FOLLOWUP-{index:03d}")
        if result is None:
            continue
        artifacts.append(
            {
                "type": "http_headers",
                "file": Path(result.output_file).name,
                "url": url,
                "description": "Bounded header request for content-discovery result follow-up",
            }
        )
    original_profile = payload.get("profile")
    suffix = "-plus-content-followup"
    if isinstance(original_profile, str) and original_profile:
        payload["profile"] = (
            original_profile
            if original_profile.endswith(suffix)
            else f"{original_profile}{suffix}"
        )
    payload["artifacts"] = artifacts
    return payload


def _load_manifest_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Recon manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Recon manifest must contain a JSON object: {path}")
    return payload


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _has_traversal(path: str) -> bool:
    return any(unquote(segment).lower() in {".", ".."} for segment in path.split("/"))
