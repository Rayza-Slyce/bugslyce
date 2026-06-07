"""Single-request, scoped curl header collection workflow."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from bugslyce.core.models import ReconCurlHeaderExecutionResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.commands import build_live_curl_header_command
from bugslyce.recon.runner import LiveCurlHeaderRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


def run_curl_header_workflow(
    url: str,
    scope_file: Path,
    output_dir: Path,
    timeout_seconds: int = 10,
    runner: LiveCurlHeaderRunner | None = None,
) -> ReconCurlHeaderExecutionResult:
    """Run one confirmed curl header request and build local recon-pack outputs."""

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http:// or https:// and include a host.")
    if not scope_file.exists():
        raise ValueError(f"Scope file does not exist: {scope_file}")
    if not scope_file.is_file():
        raise ValueError(f"Scope path is not a file: {scope_file}")
    try:
        scope_text = scope_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read scope file {scope_file}: {exc}") from exc
    if not _host_is_literal_in_scope(parsed.hostname, scope_text):
        raise ValueError(f"URL host '{parsed.hostname}' does not appear in the supplied scope file.")

    output_dir = output_dir.expanduser().resolve()
    command = build_live_curl_header_command(url, output_dir, timeout_seconds)
    output_dir.mkdir(parents=True, exist_ok=True)
    command_result = (runner or LiveCurlHeaderRunner(output_dir)).run(command)
    if command_result.error or command_result.exit_code != 0:
        raise ValueError(command_result.error or "Curl header request did not complete successfully.")

    header_path = Path(command_result.output_file)
    if not header_path.is_file():
        raise ValueError("Curl header request completed without creating the expected header output.")

    local_scope_path = output_dir / "scope.md"
    local_scope_path.write_text(scope_text, encoding="utf-8")
    manifest_path = output_dir / "recon_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": parsed.hostname,
                "scope_file": local_scope_path.name,
                "created_by": "bugslyce-curl-headers",
                "profile": "curl-headers-only",
                "artifacts": [
                    {
                        "type": "http_headers",
                        "file": header_path.name,
                        "url": url,
                        "description": "Single bounded curl header request",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    project_state = build_project_state(output_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, output_dir)
    return ReconCurlHeaderExecutionResult(
        mode="curl-headers-only",
        url=url,
        host=parsed.hostname,
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        header_output_path=str(header_path),
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=1,
        scanners_executed=False,
        command_result=command_result,
        warnings=project_state.warnings,
    )


def write_curl_header_execution_result(
    result: ReconCurlHeaderExecutionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for one curl header request."""

    json_path = output_dir / "recon_execution.json"
    markdown_path = output_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_curl_header_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_curl_header_execution_markdown(result: ReconCurlHeaderExecutionResult) -> str:
    """Render careful execution metadata for the scoped header request."""

    return "\n".join(
        [
            "# BugSlyce Curl Header Execution",
            "",
            f"- URL: `{result.url}`",
            f"- Host: `{result.host}`",
            f"- Scope file: `{result.scope_file}`",
            f"- Output directory: `{result.output_dir}`",
            f"- Header output: `{result.header_output_path}`",
            f"- Manifest: `{result.manifest_path}`",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            f"- Curl header requests executed: {result.execution_count}",
            f"- Scanners executed: `{str(result.scanners_executed).lower()}`",
            "",
            "One bounded curl header request was executed.",
            "No scanners, brute force, exploitation, or content discovery were run.",
            "",
        ]
    )


def render_curl_header_execution_summary(result: ReconCurlHeaderExecutionResult) -> str:
    """Render concise CLI output for the scoped header request."""

    return "\n".join(
        [
            "BugSlyce curl header execution complete",
            f"URL: {result.url}",
            f"Output directory: {result.output_dir}",
            f"Header output path: {result.header_output_path}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "One curl header request was executed.",
            "No scanners, brute force, exploitation, or content discovery were run.",
        ]
    )


def _host_is_literal_in_scope(host: str, scope_text: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9.-]){re.escape(host)}(?![A-Za-z0-9.-])"
    return re.search(pattern, scope_text, flags=re.IGNORECASE) is not None
