"""Collect bounded HTTP metadata from nmap-discovered HTTP services."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState, ReconHTTPMetadataExecutionResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.http_metadata_commands import (
    MAX_HTTP_METADATA_SERVICES,
    build_http_metadata_commands,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.runner import LiveHTTPMetadataRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


def discover_http_origins(
    project_state: ProjectState,
    target: str,
    max_services: int = MAX_HTTP_METADATA_SERVICES,
) -> list[str]:
    """Return deterministic origins for open HTTP services found by nmap."""

    origins: set[str] = set()
    for service in project_state.port_services:
        service_name = (service.service or "").lower()
        if (
            service.host != target
            or service.state != "open"
            or service.protocol != "tcp"
            or not _is_http_service(service_name)
        ):
            continue
        scheme = "https" if "https" in service_name or service.port == 443 else "http"
        default_port = 443 if scheme == "https" else 80
        host = f"[{target}]" if ":" in target else target
        netloc = host if service.port == default_port else f"{host}:{service.port}"
        origins.add(f"{scheme}://{netloc}/")
    return sorted(origins, key=_origin_sort_key)[:max_services]


def run_http_metadata_workflow(
    input_dir: Path,
    scope_file: Path,
    runner: LiveHTTPMetadataRunner | None = None,
) -> ReconHTTPMetadataExecutionResult:
    """Collect headers, robots.txt, and homepage HTML from discovered services."""

    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    initial_state = build_project_state(input_dir)
    target = _resolve_target(manifest, initial_state)
    target = validate_explicit_nmap_target_scope(target, scope_file)
    all_origins = discover_http_origins(
        initial_state,
        target,
        max_services=max(MAX_HTTP_METADATA_SERVICES, len(initial_state.port_services)),
    )
    if not all_origins:
        raise ValueError("No open HTTP services were found in existing nmap service evidence.")
    origins = all_origins[:MAX_HTTP_METADATA_SERVICES]
    warnings = list(initial_state.warnings)
    if len(all_origins) > MAX_HTTP_METADATA_SERVICES:
        warnings.append(
            f"HTTP metadata collection capped at {MAX_HTTP_METADATA_SERVICES} services."
        )

    commands = build_http_metadata_commands(origins, target, input_dir)
    live_runner = runner or LiveHTTPMetadataRunner(input_dir, target, set(origins))
    command_results = []
    for command in commands:
        result = live_runner.run(command)
        if result.error or result.exit_code != 0:
            raise ValueError(result.error or "HTTP metadata request did not complete successfully.")
        if not Path(result.output_file).is_file():
            raise ValueError("HTTP metadata request completed without creating its expected output file.")
        command_results.append(result)

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
        origins,
        command_results,
    )
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)
    combined_warnings = list(dict.fromkeys([*warnings, *project_state.warnings]))
    return ReconHTTPMetadataExecutionResult(
        mode="http-metadata",
        target=target,
        scope_file=str(scope_file),
        input_dir=str(input_dir),
        http_services=origins,
        artifact_paths=[result.output_file for result in command_results],
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=len(command_results),
        command_results=command_results,
        warnings=combined_warnings,
    )


def write_http_metadata_execution_result(
    result: ReconHTTPMetadataExecutionResult,
    input_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for HTTP metadata collection."""

    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_http_metadata_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_http_metadata_execution_markdown(
    result: ReconHTTPMetadataExecutionResult,
) -> str:
    """Render execution metadata for bounded HTTP metadata requests."""

    return "\n".join(
        [
            "# BugSlyce HTTP Metadata Collection",
            "",
            f"- Target: `{result.target}`",
            f"- Input/output directory: `{result.input_dir}`",
            f"- HTTP services processed: {len(result.http_services)}",
            f"- Artefacts written: {len(result.artifact_paths)}",
            f"- Manifest: `{result.manifest_path}`",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            "HTTP metadata requests were executed.",
            "No content discovery, brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_http_metadata_execution_summary(
    result: ReconHTTPMetadataExecutionResult,
) -> str:
    """Render concise CLI output for HTTP metadata collection."""

    return "\n".join(
        [
            "BugSlyce HTTP metadata collection complete",
            f"Target: {result.target}",
            f"Input/output directory: {result.input_dir}",
            f"HTTP services processed: {len(result.http_services)}",
            f"Artefacts written: {len(result.artifact_paths)}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            "HTTP metadata requests were executed.",
            "No content discovery, brute force, exploitation, or form submission was run.",
        ]
    )


def _resolve_target(
    manifest: dict[str, object] | None,
    project_state: ProjectState,
) -> str:
    if manifest is not None:
        value = manifest.get("target")
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
        raise ValueError("Recon manifest does not contain a target.")
    hosts = {service.host for service in project_state.port_services if service.host}
    if len(hosts) != 1:
        raise ValueError("Could not determine one target from existing nmap service evidence.")
    return next(iter(hosts))


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


def _updated_manifest(
    manifest: dict[str, object] | None,
    target: str,
    scope_filename: str,
    origins: list[str],
    command_results,
) -> dict[str, object]:
    payload = dict(manifest or {})
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

    results_by_name = {
        Path(result.output_file).name: result
        for result in command_results
    }
    for origin in origins:
        parsed = urlparse(origin)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        safe_host = _safe_host(parsed.hostname or target)
        entries = [
            (
                "http_headers",
                f"curl-headers-{safe_host}-{port}.txt",
                origin,
                "Bounded curl header request for discovered HTTP service",
            ),
            (
                "robots",
                f"robots-{safe_host}-{port}.txt",
                f"{origin}robots.txt",
                "Bounded robots.txt request for discovered HTTP service",
            ),
            (
                "html",
                f"homepage-{safe_host}-{port}.html",
                origin,
                "Bounded homepage HTML request for discovered HTTP service",
            ),
        ]
        for artifact_type, filename, url, description in entries:
            if filename in results_by_name:
                artifacts.append(
                    {
                        "type": artifact_type,
                        "file": filename,
                        "url": url,
                        "description": description,
                    }
                )

    original_profile = payload.get("profile")
    base_profile = (
        original_profile.removesuffix("-plus-http-metadata")
        if isinstance(original_profile, str) and original_profile
        else "nmap-services"
    )
    payload.update(
        {
            "schema_version": str(payload.get("schema_version") or "1.0"),
            "target": target,
            "scope_file": scope_filename,
            "created_by": str(payload.get("created_by") or "bugslyce-http-metadata"),
            "profile": f"{base_profile}-plus-http-metadata",
            "artifacts": artifacts,
        }
    )
    return payload


def _is_http_service(service_name: str) -> bool:
    return service_name in {"http", "https", "http-proxy", "https-alt"} or "http" in service_name


def _origin_sort_key(origin: str) -> tuple[int, str]:
    parsed = urlparse(origin)
    return parsed.port or (443 if parsed.scheme == "https" else 80), origin


def _safe_host(hostname: str) -> str:
    return "".join(
        character if character.isalnum() or character in ".-" else "-"
        for character in hostname.lower()
    ).strip(".-") or "host"
