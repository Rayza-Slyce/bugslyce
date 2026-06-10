"""Scoped nmap service/version workflow for previously discovered TCP ports."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from bugslyce.core.models import ReconNmapServiceExecutionResult
from bugslyce.core.project import build_project_state
from bugslyce.parsers.nmap import parse_nmap_normal
from bugslyce.recon.nmap_profiles import (
    build_live_nmap_service_scan_command,
    validate_explicit_nmap_target_scope,
)
from bugslyce.recon.runner import LiveNmapServiceRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


DISCOVERY_FILES = ("nmap-allports.txt", "nmap-top1000.txt")
SERVICE_ARTIFACT_DESCRIPTION = (
    "Single bounded nmap service/version scan for discovered open TCP ports"
)


def extract_open_tcp_ports(path: Path, default_host: str | None = None) -> tuple[str, list[int]]:
    """Extract one target and sorted unique open TCP ports from nmap normal output."""

    records = parse_nmap_normal(path, default_host)
    ports = sorted(
        {
            record.port
            for record in records
            if record.protocol == "tcp"
            and record.state == "open"
            and 1 <= record.port <= 65535
        }
    )
    hosts = {record.host for record in records if record.host}
    if len(hosts) > 1:
        raise ValueError("Nmap discovery output contains more than one target.")
    target = next(iter(hosts), default_host or "")
    return target, ports


def run_nmap_service_workflow(
    input_dir: Path,
    scope_file: Path,
    runner: LiveNmapServiceRunner | None = None,
) -> ReconNmapServiceExecutionResult:
    """Run one service/version command against previously discovered open ports."""

    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    manifest_target = _manifest_target(manifest)
    discovery_path = _find_discovery_file(input_dir)
    parsed_target, ports = extract_open_tcp_ports(discovery_path, manifest_target)
    target = manifest_target or parsed_target
    if not target:
        raise ValueError("Could not determine one target from the existing discovery output.")
    if not ports:
        raise ValueError(f"No open TCP ports were found in {discovery_path.name}.")
    target = validate_explicit_nmap_target_scope(target, scope_file)

    command = build_live_nmap_service_scan_command(target, ports, input_dir)
    command_result = (runner or LiveNmapServiceRunner(input_dir)).run(command)
    if command_result.error or command_result.exit_code != 0:
        raise ValueError(command_result.error or "Nmap service scan did not complete successfully.")

    nmap_output_path = Path(command_result.output_file)
    if not nmap_output_path.is_file():
        raise ValueError("Nmap completed without creating the expected service output file.")

    try:
        scope_text = scope_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read scope file {scope_file}: {exc}") from exc
    local_scope_path = input_dir / "scope.md"
    local_scope_path.write_text(scope_text, encoding="utf-8")
    updated_manifest = _updated_manifest(
        manifest,
        target,
        local_scope_path.name,
        discovery_path.name,
    )
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)
    return ReconNmapServiceExecutionResult(
        mode="nmap-services",
        target=target,
        profile="lab-service-scan",
        scope_file=str(scope_file),
        input_dir=str(input_dir),
        ports=ports,
        nmap_output_path=str(nmap_output_path),
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=1,
        command_result=command_result,
        warnings=project_state.warnings,
    )


def write_nmap_service_execution_result(
    result: ReconNmapServiceExecutionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for one service/version command."""

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_nmap_service_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_nmap_service_execution_markdown(
    result: ReconNmapServiceExecutionResult,
) -> str:
    """Render execution metadata for one service/version command."""

    return "\n".join(
        [
            "# BugSlyce Nmap Service Scan Execution",
            "",
            f"- Target: `{result.target}`",
            f"- Input/output directory: `{result.input_dir}`",
            f"- Ports scanned: `{','.join(str(port) for port in result.ports)}`",
            f"- Nmap output: `{result.nmap_output_path}`",
            f"- Manifest: `{result.manifest_path}`",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            "One nmap service/version command was executed.",
            "No NSE scripts, UDP scans, content discovery, brute force, or exploitation were run.",
            "",
        ]
    )


def render_nmap_service_execution_summary(
    result: ReconNmapServiceExecutionResult,
) -> str:
    """Render concise CLI output for one service/version command."""

    return "\n".join(
        [
            "BugSlyce nmap service scan complete",
            f"Target: {result.target}",
            f"Input/output directory: {result.input_dir}",
            f"Ports scanned: {','.join(str(port) for port in result.ports)}",
            f"Nmap output path: {result.nmap_output_path}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "One nmap service/version command was executed.",
            "No NSE scripts, UDP scans, content discovery, brute force, or exploitation were run.",
        ]
    )


def _find_discovery_file(input_dir: Path) -> Path:
    for filename in DISCOVERY_FILES:
        path = input_dir / filename
        if path.is_file():
            return path
    raise ValueError(
        "Input directory does not contain nmap-allports.txt or nmap-top1000.txt."
    )


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


def _manifest_target(manifest: dict[str, object] | None) -> str | None:
    if manifest is None:
        return None
    value = manifest.get("target")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Recon manifest does not contain a target.")
    return value.strip().lower()


def _updated_manifest(
    manifest: dict[str, object] | None,
    target: str,
    scope_filename: str,
    discovery_filename: str,
) -> dict[str, object]:
    payload = dict(manifest or {})
    artifacts = payload.get("artifacts")
    artifact_list = list(artifacts) if isinstance(artifacts, list) else []
    discovery_artifact = next(
        (
            artifact
            for artifact in artifact_list
            if isinstance(artifact, dict) and artifact.get("file") == discovery_filename
        ),
        None,
    )
    if discovery_artifact is None:
        discovery_description = (
            "Single bounded nmap full TCP discovery command"
            if discovery_filename == "nmap-allports.txt"
            else "Single bounded nmap top-1000 TCP discovery command"
        )
        artifact_list.insert(
            0,
            {
                "type": "nmap",
                "file": discovery_filename,
                "description": discovery_description,
            },
        )
    artifact_list = [
        artifact
        for artifact in artifact_list
        if not (
            isinstance(artifact, dict)
            and artifact.get("file") == "nmap-services-all.txt"
        )
    ]
    artifact_list.append(
        {
            "type": "nmap",
            "file": "nmap-services-all.txt",
            "description": SERVICE_ARTIFACT_DESCRIPTION,
        }
    )

    original_profile = payload.get("profile")
    if isinstance(original_profile, str) and original_profile:
        base_profile = original_profile.removesuffix("-plus-services")
        profile = f"{base_profile}-plus-services"
    else:
        profile = "nmap-discovery-plus-services"
    payload.update(
        {
            "schema_version": str(payload.get("schema_version") or "1.0"),
            "target": target,
            "scope_file": scope_filename,
            "created_by": str(payload.get("created_by") or "bugslyce-nmap-services"),
            "profile": profile,
            "artifacts": artifact_list,
        }
    )
    return payload
