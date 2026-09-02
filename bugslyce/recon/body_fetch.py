"""Selectively fetch bodies for high-signal paths already followed by BugSlyce."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, replace
import json
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

from bugslyce.core.engagement_policy import enforce_r0b2_bug_bounty_live_block
from bugslyce.core.models import ProjectState, ReconBodyFetchExecutionResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.body_fetch_commands import (
    MAX_BODY_FETCHES,
    MAX_BODY_FETCHES_PER_ORIGIN,
    build_body_fetch_commands,
)
from bugslyce.recon.content_followup import (
    CONTENT_DISCOVERY_ARTIFACT_TYPES,
    INCOMPLETE_CONTENT_DISCOVERY_TAGS,
    select_content_followup_urls,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.runner import LiveBodyFetchRunner
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
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
}
APPLICATION_SUFFIXES = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}


class BodyFetchExecutionIncomplete(ValueError):
    """Raised after an honest incomplete body-fetch result is assembled."""

    def __init__(self, message: str, result: ReconBodyFetchExecutionResult) -> None:
        super().__init__(message)
        self.result = result


class BodyFetchNoWork(Exception):
    """Clean idempotent outcome when no new body URL is eligible."""

    def __init__(self, considered: int) -> None:
        super().__init__("No eligible new high-signal followed-path URLs remain for body fetch.")
        self.considered = considered


def select_body_fetch_urls(
    project_state: ProjectState,
    target: str,
    manifest: dict[str, object],
    max_total: int = MAX_BODY_FETCHES,
    max_per_origin: int = MAX_BODY_FETCHES_PER_ORIGIN,
) -> tuple[int, list[str]]:
    """Rank eligible 200-status URLs from prior content-followup evidence."""

    followed_urls = _content_followup_urls(manifest)
    already_fetched = _body_fetched_urls(manifest)
    robots_urls = _manifest_urls(manifest, {"robots"})
    homepage_origins = {
        _origin(url)
        for url in _manifest_urls(manifest, {"html"})
        if urlparse(url).path in {"", "/"}
    }
    status_by_url: dict[str, int | None] = {}
    for record in project_state.discovered_paths:
        if Path(record.source).name.startswith("curl-headers-content-followup-"):
            status_by_url[_normalize_url(record.url)] = record.status_code

    considered = {_normalize_url(url) for url in followed_urls}
    scored: list[tuple[int, str]] = []
    for url in considered:
        normalized = _eligible_url(
            url,
            status_by_url.get(url),
            target,
            already_fetched,
            robots_urls,
            homepage_origins,
        )
        if normalized is None:
            continue
        scored.append((_score_url(normalized), normalized))

    ranked = sorted(scored, key=lambda item: (-item[0], item[1]))
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
    return len(considered), selected


def run_body_fetch_workflow(
    input_dir: Path,
    scope_file: Path,
    runner: LiveBodyFetchRunner | None = None,
    project_runtime=None,
) -> ReconBodyFetchExecutionResult:
    """Run bounded GET requests for selected prior content-followup URLs."""

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
    if project_runtime is None:
        enforce_r0b2_bug_bounty_live_block(initial_state.engagement_context)
    else:
        from bugslyce.recon.project_runtime import require_project_runtime_binding

        require_project_runtime_binding(
            project_runtime,
            input_dir,
            scope_file,
            target,
            runner,
            "curl",
        )
    considered, selected_urls = select_body_fetch_urls(initial_state, target, manifest)
    if considered == 0:
        content_considered, pending_followup_urls = select_content_followup_urls(
            initial_state,
            target,
            manifest,
        )
        if content_considered > 0 and not pending_followup_urls:
            raise BodyFetchNoWork(0)
        if _completed_content_discovery_is_empty(input_dir, manifest):
            raise BodyFetchNoWork(0)
        raise ValueError("No prior content-followup header artefacts were found.")
    if not selected_urls:
        raise BodyFetchNoWork(considered)

    allowed_origins = {_origin(url) for url in selected_urls}
    commands = build_body_fetch_commands(selected_urls, target, input_dir)
    live_runner = runner or LiveBodyFetchRunner(
        input_dir,
        target,
        allowed_origins,
        set(selected_urls),
    )
    command_results = []
    completed_results = []
    retained_paths: list[str] = []
    partial_body_bytes: dict[str, int] = {}
    failed_transfers = 0
    timed_out = 0
    operational_warnings: list[str] = []
    for command in commands:
        result = live_runner.run(command)
        if result.command_id != command.id or result.output_file != command.output_file:
            raise ValueError("Selective body-fetch result does not match its approved command.")
        if not result.executed:
            raise ValueError(result.error or "Selective body fetch did not complete successfully.")
        if result.error or result.exit_code != 0:
            recoverable_failure = _is_recoverable_transfer_failure(result, command)
            if result.error is None:
                result = replace(
                    result,
                    error=(
                        "Selective body fetch returned an incomplete execution result."
                        if result.exit_code is None
                        else f"Curl exited with code {result.exit_code}."
                    ),
                )
            partial_path, retained_bytes = _retain_partial_body(
                Path(command.output_file),
                input_dir,
            )
            if partial_path is not None:
                result = replace(result, output_file=str(partial_path))
                retained_paths.append(str(partial_path))
                partial_body_bytes[str(partial_path)] = retained_bytes
            stderr_path = _validated_stderr_sidecar(result.stderr_path, input_dir)
            if not recoverable_failure:
                raise ValueError(result.error)
            failed_transfers += 1
            if result.exit_code is None:
                timed_out += 1
            if stderr_path is not None:
                retained_paths.append(str(stderr_path))
            command_results.append(result)
            operational_warnings.append(
                f"Selective body-fetch command {command.id} had a failed transfer; "
                "any incomplete response was retained as partial evidence."
            )
            continue
        output_path = Path(result.output_file)
        if output_path.is_symlink() or not output_path.is_file():
            raise ValueError("Selective body fetch completed without creating its expected output file.")
        command_results.append(result)
        completed_results.append(result)
        retained_paths.append(result.output_file)

    return _finalize_execution(
        input_dir,
        scope_file,
        target,
        manifest_path,
        manifest,
        considered,
        selected_urls,
        command_results,
        completed_results,
        retained_paths,
        timed_out=timed_out,
        failed_transfers=failed_transfers,
        partial_body_bytes=partial_body_bytes,
        operational_warnings=operational_warnings,
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
    retained_paths: list[str],
    timed_out: int,
    failed_transfers: int,
    partial_body_bytes: dict[str, int],
    operational_warnings: list[str],
) -> ReconBodyFetchExecutionResult:
    updated_manifest = _updated_manifest(manifest, selected_urls, artifact_results)
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)
    return ReconBodyFetchExecutionResult(
        mode="body-fetch",
        target=target,
        scope_file=str(scope_file),
        input_dir=str(input_dir),
        candidate_urls_considered=considered,
        body_urls_selected=selected_urls,
        artifact_paths=retained_paths,
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
        no_form_submission=True,
        no_exploitation=True,
        warnings=[*project_state.warnings, *operational_warnings],
        failed_transfers=failed_transfers,
        partial_bodies_retained=len(partial_body_bytes),
        partial_body_bytes=partial_body_bytes,
    )


def write_body_fetch_execution_result(
    result: ReconBodyFetchExecutionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for selective body fetch."""

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_body_fetch_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_body_fetch_execution_markdown(result: ReconBodyFetchExecutionResult) -> str:
    """Render execution metadata for selective body fetch."""

    return "\n".join(
        [
            "# BugSlyce Selective Body Fetch",
            "",
            f"- Target: `{result.target}`",
            f"- Input/output directory: `{result.input_dir}`",
            f"- Candidate URLs considered: {result.candidate_urls_considered}",
            f"- Body URLs selected: {len(result.body_urls_selected)}",
            f"- Commands started: {result.commands_started}",
            f"- Commands completed: {result.commands_completed}",
            f"- Failed transfers: {result.failed_transfers}",
            f"- Partial bodies retained: {result.partial_bodies_retained}",
            f"- Commands timed out: {result.commands_timed_out}",
            f"- Artefacts written: {len(result.artifact_paths)}",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            "Selective body fetch requests were executed.",
            "No recursion, wordlists, brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_body_fetch_execution_summary(result: ReconBodyFetchExecutionResult) -> str:
    """Render concise CLI output for selective body fetch."""

    return "\n".join(
        [
            "BugSlyce selective body fetch complete",
            f"Target: {result.target}",
            f"Input/output directory: {result.input_dir}",
            f"Candidate URLs considered: {result.candidate_urls_considered}",
            f"Body URLs selected: {len(result.body_urls_selected)}",
            f"Failed transfers: {result.failed_transfers}",
            f"Partial bodies retained: {result.partial_bodies_retained}",
            f"Artefacts written: {len(result.artifact_paths)}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "Selective body fetch requests were executed.",
            "No recursion, wordlists, brute force, exploitation, or form submission was run.",
        ]
    )


def render_body_fetch_no_work(outcome: BodyFetchNoWork) -> str:
    """Render a calm CLI summary for an idempotent no-work result."""

    return "\n".join(
        [
            "No eligible new high-signal followed-path URLs remain for body fetch.",
            f"Followed paths considered: {outcome.considered}",
            (
                "All currently followed paths are already body-fetched, excluded, "
                "non-HTML, 403/404, duplicate, or low-signal."
            ),
            "No body-fetch request was executed.",
        ]
    )


def _eligible_url(
    url: str,
    status_code: int | None,
    target: str,
    already_fetched: set[str],
    robots_urls: set[str],
    homepage_origins: set[str],
) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
        return None
    if parsed.fragment or _has_traversal(parsed.path):
        return None
    normalized = _normalize_url(url)
    path = parsed.path or "/"
    path_lower = path.rstrip("/").lower()
    if status_code != 200:
        return None
    if path in {"", "/"} or normalized in already_fetched or normalized in robots_urls:
        return None
    if path_lower.endswith("/robots.txt"):
        return None
    if path_lower.endswith("/index.html") and _origin(normalized) in homepage_origins:
        return None
    suffix = Path(path.rstrip("/")).suffix.lower()
    if suffix in STATIC_SUFFIXES:
        return None
    if suffix and suffix not in APPLICATION_SUFFIXES:
        return None
    return normalized


def _score_url(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.lower()
    score = 4
    if path.endswith("/"):
        score += 3
    suffix = Path(path.rstrip("/")).suffix.lower()
    if not suffix:
        score += 2
    elif suffix in APPLICATION_SUFFIXES:
        score += 2
    segments = {
        token
        for segment in path.strip("/").split("/")
        for token in segment.replace("_", "-").split("-")
        if token
    }
    score += 2 * len(segments & INTERESTING_SEGMENTS)
    return score


def _completed_content_discovery_is_empty(
    input_dir: Path,
    manifest: dict[str, object],
) -> bool:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False

    completed_paths: list[Path] = []
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or artifact.get("type") not in CONTENT_DISCOVERY_ARTIFACT_TYPES
        ):
            continue
        raw_tags = artifact.get("tags")
        tags = (
            {tag for tag in raw_tags if isinstance(tag, str)}
            if isinstance(raw_tags, list)
            else set()
        )
        if INCOMPLETE_CONTENT_DISCOVERY_TAGS & tags:
            return False
        file_value = artifact.get("file")
        if not isinstance(file_value, str) or not file_value:
            continue
        path = input_dir / Path(file_value).name
        if not path.is_file():
            return False
        completed_paths.append(path)

    return bool(completed_paths) and all(
        path.stat().st_size == 0 for path in completed_paths
    )


def _content_followup_urls(manifest: dict[str, object]) -> set[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        _normalize_url(artifact["url"])
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("type") == "http_headers"
        and isinstance(artifact.get("url"), str)
        and (
            str(artifact.get("file", "")).startswith("curl-headers-content-followup-")
            or "content-discovery result follow-up" in str(artifact.get("description", "")).lower()
        )
    }


def _body_fetched_urls(manifest: dict[str, object]) -> set[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        _normalize_url(artifact["url"])
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("type") == "html"
        and isinstance(artifact.get("url"), str)
    }


def _manifest_urls(manifest: dict[str, object], types: set[str]) -> set[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        _normalize_url(artifact["url"])
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
        if not (isinstance(artifact, dict) and artifact.get("file") in generated_names)
    ]
    results = {result.command_id: result for result in command_results}
    for index, url in enumerate(selected_urls, start=1):
        result = results.get(f"CMD-BODY-FETCH-{index:03d}")
        if result is None:
            continue
        artifacts.append(
            {
                "type": "html",
                "file": Path(result.output_file).name,
                "url": url,
                "description": (
                    "Bounded body request for selected high-signal "
                    "content-discovery follow-up path"
                ),
            }
        )
    if command_results:
        original_profile = payload.get("profile")
        suffix = "-plus-body-fetch"
        if isinstance(original_profile, str) and original_profile:
            payload["profile"] = (
                original_profile
                if original_profile.endswith(suffix)
                else f"{original_profile}{suffix}"
            )
    payload["artifacts"] = artifacts
    return payload


def _retain_partial_body(output_path: Path, input_dir: Path) -> tuple[Path | None, int]:
    if output_path.parent.resolve() != input_dir.resolve():
        raise ValueError("Selective body-fetch output escaped its approved directory.")
    if output_path.is_symlink():
        raise ValueError("Selective body-fetch output must not be a symbolic link.")
    if not output_path.exists():
        return None, 0
    if not output_path.is_file():
        raise ValueError("Selective body-fetch output is not a regular file.")
    partial_path = Path(f"{output_path}.partial")
    if partial_path.exists() or partial_path.is_symlink():
        raise ValueError("Selective body-fetch partial output already exists.")
    output_path.rename(partial_path)
    return partial_path, partial_path.stat().st_size


def _is_recoverable_transfer_failure(result, command) -> bool:
    expected_timeout_error = (
        f"Selective body fetch exceeded {command.timeout_seconds} seconds."
    )
    return result.exit_code == 18 or (
        result.exit_code is None
        and result.error == expected_timeout_error
    )


def _validated_stderr_sidecar(value: str | None, input_dir: Path) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    if path.parent.resolve() != input_dir.resolve() or path.is_symlink() or not path.is_file():
        raise ValueError("Selective body-fetch stderr sidecar is unsafe or missing.")
    return path


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


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _has_traversal(path: str) -> bool:
    return any(unquote(segment).lower() in {".", ".."} for segment in path.split("/"))
