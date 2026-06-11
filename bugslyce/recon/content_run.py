"""Execute only approved root discovery steps from a BugSlyce content plan."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import json
from pathlib import Path
import shutil
from typing import Any
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import (
    ContentDiscoveryPlan,
    ContentDiscoveryStep,
    ReconContentDiscoveryExecutionResult,
    ReconPlannedArtifact,
)
from bugslyce.core.project import build_project_state
from bugslyce.recon.content_commands import build_live_content_discovery_command
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_CREATED_BY,
    CONTENT_DISCOVERY_PROFILE,
    CONTENT_DISCOVERY_SCHEMA_VERSION,
    MAX_CONTENT_PLAN_ORIGINS,
    discover_content_plan_origins,
    get_content_discovery_profile,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.runner import LiveContentDiscoveryRunner
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


class ContentDiscoveryExecutionIncomplete(ValueError):
    """Raised after an honest partial execution result has been assembled."""

    def __init__(self, message: str, result: ReconContentDiscoveryExecutionResult) -> None:
        super().__init__(message)
        self.result = result


def load_content_discovery_plan(path: Path) -> ContentDiscoveryPlan:
    """Load and strictly validate a BugSlyce content discovery plan."""

    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Content discovery plan does not exist: {path}")
    if path.name != "content_discovery_plan.json":
        raise ValueError("Live content discovery requires content_discovery_plan.json.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse content discovery plan {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Content discovery plan must contain a JSON object.")

    schema_version = payload.get("schema_version")
    if schema_version not in {None, CONTENT_DISCOVERY_SCHEMA_VERSION}:
        raise ValueError(f"Unsupported content discovery plan schema: {schema_version}.")
    created_by = payload.get("created_by")
    if created_by not in {None, CONTENT_DISCOVERY_CREATED_BY}:
        raise ValueError("Content discovery plan provenance is not recognised.")

    target = _required_text(payload, "target")
    profile = _required_text(payload, "profile")
    profile_definition = get_content_discovery_profile(profile)
    input_dir = Path(_required_text(payload, "input_dir")).expanduser().resolve()
    output_dir = Path(_required_text(payload, "output_dir")).expanduser().resolve()
    scope_file = _required_text(payload, "scope_file")
    if output_dir != path.parent:
        raise ValueError("Content discovery plan must remain in its planned output directory.")
    if not input_dir.is_dir():
        raise ValueError(f"Original recon input directory does not exist: {input_dir}")
    if not _safe_output_dir(input_dir):
        raise ValueError("Original recon input directory is not an approved local recon path.")
    if not _safe_output_dir(output_dir):
        raise ValueError("Content discovery plan output directory is not an approved local path.")

    raw_origins = payload.get("origins")
    if not isinstance(raw_origins, list) or any(not isinstance(item, str) for item in raw_origins):
        raise ValueError("Content discovery plan origins must be a list of strings.")
    origins = list(dict.fromkeys(raw_origins))

    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("Content discovery plan must contain at least one planned step.")
    if len(raw_steps) > MAX_CONTENT_PLAN_ORIGINS:
        raise ValueError(
            f"Content discovery plan exceeds the {MAX_CONTENT_PLAN_ORIGINS}-origin limit."
        )
    steps = [
        _parse_step(item, index, target, output_dir, profile_definition)
        for index, item in enumerate(raw_steps, start=1)
    ]
    step_origins = [step.origin for step in steps]
    if origins != step_origins:
        raise ValueError("Content discovery plan origins do not match its planned steps.")
    if len(origins) != len(set(origins)):
        raise ValueError("Content discovery plan contains duplicate origins.")
    if payload.get("no_commands_executed") is not True:
        raise ValueError("Content discovery plan is not marked as non-executing.")

    warnings = _string_list(payload.get("warnings"), "warnings")
    safety_notes = _string_list(payload.get("safety_notes"), "safety_notes")
    return ContentDiscoveryPlan(
        schema_version=CONTENT_DISCOVERY_SCHEMA_VERSION,
        created_by=CONTENT_DISCOVERY_CREATED_BY,
        target=target,
        profile=profile,
        input_dir=str(input_dir),
        scope_file=scope_file,
        output_dir=str(output_dir),
        origins=origins,
        steps=steps,
        warnings=warnings,
        safety_notes=safety_notes,
        no_commands_executed=True,
    )


def run_content_discovery_workflow(
    plan_path: Path,
    scope_file: Path,
    runner: LiveContentDiscoveryRunner | None = None,
    wordlist_check: Callable[[Path], bool] | None = None,
) -> ReconContentDiscoveryExecutionResult:
    """Execute exact root discovery commands from one validated plan."""

    plan_path = plan_path.expanduser().resolve()
    plan = load_content_discovery_plan(plan_path)
    target = validate_explicit_nmap_target_scope(plan.target, scope_file)
    input_dir = Path(plan.input_dir)
    output_dir = Path(plan.output_dir)

    state_before = build_project_state(input_dir)
    if (
        state_before.recon_manifest is None
        or state_before.recon_manifest.target.strip().lower() != target
    ):
        raise ValueError("Original recon manifest target does not match the content plan.")
    current_origins = set(
        discover_content_plan_origins(
            state_before,
            target,
            max_origins=max(MAX_CONTENT_PLAN_ORIGINS, len(state_before.http_services)),
        )
    )
    if any(origin not in current_origins for origin in plan.origins):
        raise ValueError(
            "Content discovery plan contains an origin not present in current BugSlyce evidence."
        )

    profile_definition = get_content_discovery_profile(plan.profile)
    checker = wordlist_check or Path.is_file
    if not checker(profile_definition.wordlist):
        raise ValueError(
            f"Approved content discovery wordlist does not exist: {profile_definition.wordlist}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    commands = [
        build_live_content_discovery_command(step, plan)
        for step in plan.steps
    ]
    live_runner = runner or LiveContentDiscoveryRunner(
        output_dir,
        target,
        set(plan.origins),
        plan.profile,
    )
    command_results = []
    for command in commands:
        result = live_runner.run(command)
        if result.executed:
            command_results.append(result)
        if _is_timeout_result(result):
            partial_sources = [
                (previous.command_id, Path(previous.output_file), False)
                for previous in command_results[:-1]
                if previous.exit_code == 0 and not previous.error
            ]
            output_path = Path(result.output_file)
            if output_path.is_file() and output_path.stat().st_size > 0:
                partial_sources.append((result.command_id, output_path, True))
            execution_result = _finalize_execution(
                plan_path,
                plan,
                scope_file,
                command_results,
                partial_sources,
                timed_out_result=result,
            )
            raise ContentDiscoveryExecutionIncomplete(result.error or "Content discovery timed out.", execution_result)
        if result.error or result.exit_code != 0:
            raise ValueError(result.error or "Content discovery did not complete successfully.")
        output_path = Path(result.output_file)
        if not output_path.is_file():
            raise ValueError(
                "Content discovery completed without creating its expected output file."
            )
    artifact_sources = [
        (result.command_id, Path(result.output_file), False)
        for result in command_results
    ]
    return _finalize_execution(
        plan_path,
        plan,
        scope_file,
        command_results,
        artifact_sources,
        timed_out_result=None,
    )


def write_content_discovery_execution_result(
    result: ReconContentDiscoveryExecutionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for controlled root discovery."""

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "content_discovery_execution.json"
    markdown_path = output_dir / "content_discovery_execution.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_content_discovery_execution_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_content_discovery_execution_markdown(
    result: ReconContentDiscoveryExecutionResult,
) -> str:
    """Render controlled content discovery execution metadata."""

    return "\n".join(
        [
            "# BugSlyce Content Discovery Execution",
            "",
            f"- Target: `{result.target}`",
            f"- Profile: `{result.profile}`",
            f"- Plan path: `{result.plan_path}`",
            f"- Original recon directory: `{result.input_dir}`",
            f"- Plan output directory: `{result.output_dir}`",
            f"- Origins executed: {len(result.origins)}",
            f"- Commands started: {result.commands_started}",
            f"- Commands completed: {result.commands_completed}",
            f"- Commands timed out: {result.commands_timed_out}",
            f"- Gobuster artifacts written: {len(result.artifact_paths)}",
            f"- Partial artifacts imported: {result.partial_artifacts_imported}",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            (
                "Root content discovery timed out after starting."
                if result.commands_timed_out
                else "Root content discovery commands were executed."
            ),
            "No recursion, extensions, brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_content_discovery_execution_summary(
    result: ReconContentDiscoveryExecutionResult,
) -> str:
    """Render concise CLI output for controlled root discovery."""

    return "\n".join(
        [
            "BugSlyce content discovery complete",
            f"Target: {result.target}",
            f"Profile: {result.profile}",
            f"Plan path: {result.plan_path}",
            f"Original recon directory: {result.input_dir}",
            f"Planned/executed origins: {len(result.origins)}",
            f"Commands started: {result.commands_started}",
            f"Commands completed: {result.commands_completed}",
            f"Commands timed out: {result.commands_timed_out}",
            f"Gobuster artifacts written: {len(result.artifact_paths)}",
            f"Partial artifacts imported: {result.partial_artifacts_imported}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            (
                "Root content discovery timed out after starting."
                if result.commands_timed_out
                else "Root content discovery commands were executed."
            ),
            "No recursion, extensions, brute force, exploitation, or form submission was run.",
        ]
    )


def _parse_step(
    value: object,
    index: int,
    target: str,
    output_dir: Path,
    profile_definition,
) -> ContentDiscoveryStep:
    if not isinstance(value, dict):
        raise ValueError(f"Content discovery step #{index} must be an object.")
    step_id = _required_text(value, "step_id")
    if step_id != f"CONTENT-STEP-{index:03d}":
        raise ValueError(f"Content discovery step #{index} has an invalid step ID.")
    origin = _required_text(value, "origin")
    parsed = urlparse(origin)
    normalized_origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname != target
        or origin != normalized_origin
    ):
        raise ValueError(f"Content discovery step #{index} is not a target root origin.")

    if value.get("allowed_tool") != "gobuster":
        raise ValueError(f"Content discovery step #{index} must allow only gobuster.")
    if value.get("risk_level") != "moderate":
        raise ValueError(f"Content discovery step #{index} has an invalid risk level.")
    for key, expected in (
        ("requires_confirmation", True),
        ("scope_sensitive", True),
        ("recursive_discovery", False),
        ("ready_for_execution", False),
        ("no_commands_executed", True),
    ):
        if value.get(key, False if expected is False else None) is not expected:
            raise ValueError(f"Content discovery step #{index} has invalid {key}.")
    extensions = value.get("extensions", [])
    if extensions != []:
        raise ValueError(f"Content discovery step #{index} must not include extensions.")

    expected_artifact_value = value.get("expected_artifact")
    if not isinstance(expected_artifact_value, dict):
        raise ValueError(f"Content discovery step #{index} lacks an expected artifact.")
    expected_file = _required_text(expected_artifact_value, "file")
    if Path(expected_file).name != expected_file:
        raise ValueError(f"Content discovery step #{index} has an unsafe artifact filename.")
    expected_artifact = ReconPlannedArtifact(
        type=_required_text(expected_artifact_value, "type"),
        file=expected_file,
        url=_optional_text(expected_artifact_value, "url"),
        base_url=_optional_text(expected_artifact_value, "base_url"),
        description=_optional_text(expected_artifact_value, "description"),
    )
    if expected_artifact.type != "gobuster" or expected_artifact.base_url != origin:
        raise ValueError(f"Content discovery step #{index} has invalid artifact context.")

    command_preview = value.get("command_preview")
    if not isinstance(command_preview, list) or any(
        not isinstance(item, str) for item in command_preview
    ):
        raise ValueError(f"Content discovery step #{index} command preview must be argv.")
    expected_argv = [
        "gobuster",
        "dir",
        "-u",
        origin,
        "-w",
        str(profile_definition.wordlist),
        "-t",
        str(profile_definition.threads),
        "-o",
        str(output_dir / expected_file),
    ]
    if command_preview != expected_argv:
        raise ValueError(
            f"Content discovery step #{index} does not match the approved command shape."
        )

    return ContentDiscoveryStep(
        step_id=step_id,
        origin=origin,
        command_preview=command_preview,
        expected_artifact=expected_artifact,
        risk_level="moderate",
        requires_confirmation=True,
        scope_sensitive=True,
        allowed_tool="gobuster",
        recursive_discovery=False,
        extensions=[],
        ready_for_execution=False,
        no_commands_executed=True,
    )


def _load_manifest_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Original recon manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse original recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Original recon manifest must contain a JSON object.")
    return payload


def _updated_manifest(
    manifest: dict[str, object],
    plan: ContentDiscoveryPlan,
    artifacts_to_import: list[tuple[ContentDiscoveryStep, Path, bool]],
) -> dict[str, object]:
    payload = dict(manifest)
    existing = payload.get("artifacts")
    artifacts = list(existing) if isinstance(existing, list) else []
    generated_names = {path.name for _step, path, _partial in artifacts_to_import}
    artifacts = [
        artifact
        for artifact in artifacts
        if not (
            isinstance(artifact, dict)
            and artifact.get("file") in generated_names
        )
    ]
    for step, artifact_path, partial in artifacts_to_import:
        artifacts.append(
            {
                "type": "gobuster",
                "file": artifact_path.name,
                "base_url": step.origin,
                "description": (
                    "Partial gobuster output from timed-out approved content discovery command"
                    if partial
                    else "Bounded root content discovery from approved BugSlyce content plan"
                ),
                "tags": ["partial", "timed_out"] if partial else [],
            }
        )
    if artifacts_to_import:
        original_profile = payload.get("profile")
        suffix = "-plus-content-discovery"
        if isinstance(original_profile, str) and original_profile:
            profile = (
                original_profile
                if original_profile.endswith(suffix)
                else f"{original_profile}{suffix}"
            )
        else:
            profile = f"{plan.profile}-plus-content-discovery"
        payload["profile"] = profile
    payload["artifacts"] = artifacts
    return payload


def _finalize_execution(
    plan_path: Path,
    plan: ContentDiscoveryPlan,
    scope_file: Path,
    command_results,
    artifact_sources: list[tuple[str, Path, bool]],
    timed_out_result,
) -> ReconContentDiscoveryExecutionResult:
    input_dir = Path(plan.input_dir)
    output_dir = Path(plan.output_dir)
    step_by_id = {step.step_id: step for step in plan.steps}
    copied: list[tuple[ContentDiscoveryStep, Path, bool]] = []
    for command_id, source_value, partial in artifact_sources:
        source = source_value.resolve()
        step = step_by_id[command_id]
        destination = (input_dir / source.name).resolve()
        try:
            destination.relative_to(input_dir.resolve())
        except ValueError as exc:
            raise ValueError("Content discovery artifact destination escaped the recon directory.") from exc
        if source != destination:
            shutil.copy2(source, destination)
        copied.append((step, destination, partial))

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    updated_manifest = _updated_manifest(manifest, plan, copied)
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)

    completed = sum(result.exit_code == 0 and not result.error for result in command_results)
    timed_out = 1 if timed_out_result is not None else 0
    started_steps = [
        step_by_id[result.command_id]
        for result in command_results
        if result.command_id in step_by_id
    ]
    return ReconContentDiscoveryExecutionResult(
        mode="content-run",
        plan_path=str(plan_path),
        target=plan.target,
        profile=plan.profile,
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        origins=[step.origin for step in started_steps],
        artifact_paths=[str(path) for _step, path, _partial in copied],
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=len(command_results),
        commands_started=len(command_results),
        commands_completed=completed,
        commands_timed_out=timed_out,
        partial_artifacts_imported=sum(partial for _step, _path, partial in copied),
        timed_out_step_id=timed_out_result.command_id if timed_out_result else None,
        timed_out_origin=(
            step_by_id[timed_out_result.command_id].origin
            if timed_out_result and timed_out_result.command_id in step_by_id
            else None
        ),
        command_results=command_results,
        no_recursion=True,
        no_extensions=True,
        no_arbitrary_urls=True,
        no_exploitation=True,
        warnings=project_state.warnings,
    )


def _is_timeout_result(result) -> bool:
    return (
        result.executed
        and result.exit_code is None
        and bool(result.error)
        and "started and exceeded" in result.error
    )


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Content discovery plan field '{key}' is required.")
    return value.strip()


def _optional_text(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Content discovery plan {name} must be a list of strings.")
    return list(value)


def _safe_output_dir(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(Path("/tmp"))
        return True
    except ValueError:
        return any(
            part in {"private_recon", "raw-recon", "bugslyce-output"}
            for part in resolved.parts
        )
