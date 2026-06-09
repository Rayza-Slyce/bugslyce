"""Single-command, scoped nmap top-1000 discovery workflow."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from bugslyce.core.models import ReconNmapDiscoveryExecutionResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.nmap_profiles import (
    build_live_nmap_full_tcp_command,
    build_live_nmap_top_ports_command,
    get_nmap_profile,
    validate_explicit_nmap_target_scope,
)
from bugslyce.recon.runner import LiveNmapDiscoveryRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


def run_nmap_discovery_workflow(
    target: str,
    scope_file: Path,
    output_dir: Path,
    profile_name: str = "lab-tcp-top",
    runner: LiveNmapDiscoveryRunner | None = None,
) -> ReconNmapDiscoveryExecutionResult:
    """Run one approved nmap discovery command and build recon-pack outputs."""

    if profile_name not in {"lab-tcp-top", "lab-tcp-full"}:
        raise ValueError(
            "Live nmap execution currently supports only profiles "
            "'lab-tcp-top' and 'lab-tcp-full'."
        )

    output_dir = output_dir.expanduser().resolve()
    target = validate_explicit_nmap_target_scope(target, scope_file)
    profile = get_nmap_profile(profile_name)
    command = (
        build_live_nmap_top_ports_command(target, output_dir)
        if profile_name == "lab-tcp-top"
        else build_live_nmap_full_tcp_command(target, output_dir)
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    command_result = (runner or LiveNmapDiscoveryRunner(output_dir)).run(command)
    if command_result.error or command_result.exit_code != 0:
        raise ValueError(command_result.error or "Nmap discovery did not complete successfully.")

    nmap_output_path = Path(command_result.output_file)
    if not nmap_output_path.is_file():
        raise ValueError("Nmap completed without creating the expected normal output file.")

    try:
        scope_text = scope_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read scope file {scope_file}: {exc}") from exc
    local_scope_path = output_dir / "scope.md"
    local_scope_path.write_text(scope_text, encoding="utf-8")
    manifest_path = output_dir / "recon_manifest.json"
    discovery_label = (
        "top-1000 TCP discovery" if profile_name == "lab-tcp-top" else "full TCP discovery"
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": command.argv[-1],
                "scope_file": local_scope_path.name,
                "created_by": "bugslyce-nmap-discover",
                "profile": profile.name,
                "artifacts": [
                    {
                        "type": "nmap",
                        "file": nmap_output_path.name,
                        "description": f"Single bounded nmap {discovery_label} command",
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
    return ReconNmapDiscoveryExecutionResult(
        mode="nmap-discover",
        target=command.argv[-1],
        profile=profile.name,
        scope_file=str(scope_file),
        output_dir=str(output_dir),
        nmap_output_path=str(nmap_output_path),
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=1,
        command_result=command_result,
        warnings=project_state.warnings,
    )


def write_nmap_discovery_execution_result(
    result: ReconNmapDiscoveryExecutionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for one nmap discovery command."""

    json_path = output_dir / "recon_execution.json"
    markdown_path = output_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_nmap_discovery_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_nmap_discovery_execution_markdown(
    result: ReconNmapDiscoveryExecutionResult,
) -> str:
    """Render careful execution metadata for one nmap discovery command."""

    discovery_label = _discovery_label(result.profile)
    return "\n".join(
        [
            "# BugSlyce Nmap Discovery Execution",
            "",
            f"- Target: `{result.target}`",
            f"- Profile: `{result.profile}`",
            f"- Scope file: `{result.scope_file}`",
            f"- Output directory: `{result.output_dir}`",
            f"- Nmap output: `{result.nmap_output_path}`",
            f"- Manifest: `{result.manifest_path}`",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            f"- Nmap discovery commands executed: {result.execution_count}",
            "",
            f"One nmap {discovery_label} command was executed.",
            "No NSE scripts, service scans, UDP scans, content discovery, brute force, or exploitation were run.",
            "",
        ]
    )


def render_nmap_discovery_execution_summary(
    result: ReconNmapDiscoveryExecutionResult,
) -> str:
    """Render concise CLI output for one nmap discovery command."""

    discovery_label = _discovery_label(result.profile)
    return "\n".join(
        [
            "BugSlyce nmap discovery complete",
            f"Target: {result.target}",
            f"Profile: {result.profile}",
            f"Output directory: {result.output_dir}",
            f"Nmap output path: {result.nmap_output_path}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            f"One nmap {discovery_label} command was executed.",
            "No NSE scripts, service scans, UDP scans, content discovery, brute force, or exploitation were run.",
        ]
    )


def _discovery_label(profile_name: str) -> str:
    return "top-1000 TCP discovery" if profile_name == "lab-tcp-top" else "full TCP discovery"
