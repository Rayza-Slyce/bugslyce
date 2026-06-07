"""Dry-run recon execution previews with no command execution capability."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from bugslyce.core.models import (
    ReconExecutionPreview,
    ReconExecutionStepPreview,
    ReconPlan,
    ReconPlannedArtifact,
    ReconPlanStep,
)


DRY_RUN_WARNINGS = [
    "This is a dry run only.",
    "No commands were executed.",
    "Future execution must be authorised and in scope.",
    "Review command previews before enabling execution.",
    "Keep raw outputs in gitignored local directories.",
]


def load_recon_plan(path: Path) -> ReconPlan:
    """Load and validate a BugSlyce recon_plan.json file."""

    if not path.exists():
        raise ValueError(f"Recon plan file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Recon plan path is not a file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Recon plan contains invalid JSON: {path}: {exc.msg}") from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read recon plan {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Recon plan must contain a JSON object.")
    required_text = {
        name: _required_text(payload, name)
        for name in ("target", "scope_file", "profile", "output_dir", "created_by")
    }
    if required_text["created_by"] != "bugslyce-recon-planner":
        raise ValueError("Plan does not look like a BugSlyce recon plan.")

    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list):
        raise ValueError("Recon plan field 'steps' must be a list.")
    if not raw_steps:
        raise ValueError("Recon plan must contain at least one step.")
    steps = [_parse_step(value, index) for index, value in enumerate(raw_steps, start=1)]

    raw_artifacts = payload.get("planned_artifacts", [])
    if not isinstance(raw_artifacts, list):
        raise ValueError("Recon plan field 'planned_artifacts' must be a list.")
    artifacts = [_parse_artifact(value, index) for index, value in enumerate(raw_artifacts, start=1)]

    return ReconPlan(
        target=required_text["target"],
        scope_file=required_text["scope_file"],
        profile=required_text["profile"],
        output_dir=required_text["output_dir"],
        created_by=required_text["created_by"],
        steps=steps,
        planned_artifacts=artifacts,
        safety_notes=_string_list(payload, "safety_notes"),
        warnings=_string_list(payload, "warnings"),
    )


def build_execution_preview(
    plan: ReconPlan,
    plan_path: Path,
    output_dir: Path | None = None,
) -> ReconExecutionPreview:
    """Build a dry-run preview from a validated plan."""

    steps = [
        ReconExecutionStepPreview(
            step_id=step.id,
            name=step.name,
            phase=step.phase,
            command_preview=step.command_preview,
            expected_artifacts=step.expected_artifacts,
            would_execute=bool(step.command_preview and step.command_preview.strip()),
            requires_confirmation=step.requires_confirmation,
            risk_level=step.risk_level,
            scope_sensitive=step.scope_sensitive,
        )
        for step in plan.steps
    ]
    destination = output_dir or plan_path.parent
    return ReconExecutionPreview(
        target=plan.target,
        profile=plan.profile,
        plan_path=str(plan_path),
        output_dir=str(destination),
        step_count=len(steps),
        command_count=sum(1 for step in steps if step.would_execute),
        steps=steps,
        warnings=[*DRY_RUN_WARNINGS, *plan.warnings],
        no_commands_executed=True,
    )


def render_execution_preview_markdown(preview: ReconExecutionPreview) -> str:
    """Render a readable dry-run execution preview."""

    lines = [
        "# BugSlyce Recon Execution Preview",
        "",
        f"- Target: `{preview.target}`",
        f"- Profile: `{preview.profile}`",
        f"- Plan path: `{preview.plan_path}`",
        f"- Preview output directory: `{preview.output_dir}`",
        f"- Planned steps: {preview.step_count}",
        f"- Commands that would be run later: {preview.command_count}",
        f"- No commands executed: `{str(preview.no_commands_executed).lower()}`",
        "",
        "## Safety Warnings",
        "",
    ]
    lines.extend(f"- {warning}" for warning in preview.warnings)
    lines.extend(["", "## Step Preview", ""])
    for step in preview.steps:
        lines.extend(
            [
                f"### {step.step_id}: {step.name}",
                "",
                f"- Phase: `{step.phase}`",
                f"- Would execute later: `{str(step.would_execute).lower()}`",
                f"- Requires confirmation: `{str(step.requires_confirmation).lower()}`",
                f"- Risk level: `{step.risk_level}`",
                f"- Scope sensitive: `{str(step.scope_sensitive).lower()}`",
                f"- Command preview: `{step.command_preview}`" if step.command_preview else "- Command preview: none",
                "- Expected artifacts: "
                + (", ".join(f"`{value}`" for value in step.expected_artifacts) or "none"),
                "",
            ]
        )
    lines.extend(["No commands were executed.", ""])
    return "\n".join(lines)


def write_execution_preview(
    preview: ReconExecutionPreview,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown dry-run previews."""

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "recon_execution_preview.json"
    markdown_path = output_dir / "recon_execution_preview.md"
    json_path.write_text(json.dumps(asdict(preview), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_execution_preview_markdown(preview), encoding="utf-8")
    return json_path, markdown_path


def render_execution_preview_summary(
    preview: ReconExecutionPreview,
    json_path: Path,
    markdown_path: Path,
) -> str:
    """Render concise CLI output for a dry-run preview."""

    return "\n".join(
        [
            "BugSlyce recon dry-run complete",
            f"Plan path: {preview.plan_path}",
            f"Planned steps: {preview.step_count}",
            f"Commands that would be run later: {preview.command_count}",
            f"Preview JSON path: {json_path}",
            f"Preview Markdown path: {markdown_path}",
            "No commands were executed.",
        ]
    )


def _parse_step(value: object, index: int) -> ReconPlanStep:
    if not isinstance(value, dict):
        raise ValueError(f"Recon plan step #{index} must be an object.")
    command_preview = value.get("command_preview")
    if command_preview is not None and not isinstance(command_preview, str):
        raise ValueError(f"Recon plan step #{index} command_preview must be a string or null.")
    return ReconPlanStep(
        id=_required_text(value, "id", f"step #{index}"),
        name=_required_text(value, "name", f"step #{index}"),
        phase=_required_text(value, "phase", f"step #{index}"),
        description=_required_text(value, "description", f"step #{index}"),
        command_preview=command_preview.strip() if isinstance(command_preview, str) and command_preview.strip() else None,
        expected_artifacts=_string_list(value, "expected_artifacts", f"step #{index}"),
        requires_confirmation=_required_bool(value, "requires_confirmation", f"step #{index}"),
        risk_level=_required_text(value, "risk_level", f"step #{index}"),
        scope_sensitive=_required_bool(value, "scope_sensitive", f"step #{index}"),
    )


def _parse_artifact(value: object, index: int) -> ReconPlannedArtifact:
    if not isinstance(value, dict):
        raise ValueError(f"Recon planned artifact #{index} must be an object.")
    return ReconPlannedArtifact(
        type=_required_text(value, "type", f"planned artifact #{index}"),
        file=_required_text(value, "file", f"planned artifact #{index}"),
        url=_optional_text(value, "url", f"planned artifact #{index}"),
        base_url=_optional_text(value, "base_url", f"planned artifact #{index}"),
        description=_optional_text(value, "description", f"planned artifact #{index}"),
    )


def _required_text(
    payload: dict[str, Any],
    key: str,
    context: str = "recon plan",
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} field '{key}' must be a non-empty string.")
    return value.strip()


def _optional_text(payload: dict[str, Any], key: str, context: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{context} field '{key}' must be a string or null.")
    return value.strip() or None


def _required_bool(payload: dict[str, Any], key: str, context: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{context} field '{key}' must be a boolean.")
    return value


def _string_list(
    payload: dict[str, Any],
    key: str,
    context: str = "recon plan",
) -> list[str]:
    value = payload.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{context} field '{key}' must be a list of strings.")
    return [item for item in value if item]
