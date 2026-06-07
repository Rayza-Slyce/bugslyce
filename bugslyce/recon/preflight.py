"""Local recon-plan safety preflight without command execution."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import shutil
from typing import Any

from bugslyce.core.models import ReconPlan, ReconPreflightCheck, ReconPreflightResult
from bugslyce.recon.executor import load_recon_plan
from bugslyce.recon.profiles import recon_profile_names


EXPECTED_TOOLS = {
    "lab-full": ("nmap", "curl", "gobuster"),
    "bug-bounty-standard": ("nmap", "curl", "gobuster"),
    "passive-only": (),
}
FORBIDDEN_COMMAND_TOKENS = (
    "hydra",
    "medusa",
    "sqlmap",
    "nuclei",
    "masscan",
    "wfuzz",
    "nikto",
    "--script vuln",
    "brute",
    "password",
    "exploit",
    "payload",
)


def run_preflight(plan_path: Path) -> ReconPreflightResult:
    """Inspect a recon plan and local readiness without executing commands."""

    payload = _read_payload(plan_path)
    target = _text_value(payload, "target")
    profile = _text_value(payload, "profile")
    output_dir = _text_value(payload, "output_dir") or str(plan_path.parent)
    created_by = _text_value(payload, "created_by")
    checks: list[ReconPreflightCheck] = []

    checks.append(
        _check(
            "PREFLIGHT-001",
            "Plan provenance",
            "pass" if created_by == "bugslyce-recon-planner" else "fail",
            (
                "Plan provenance matches the BugSlyce recon planner."
                if created_by == "bugslyce-recon-planner"
                else "Plan provenance is missing or does not match the BugSlyce recon planner."
            ),
            "Verify the plan was generated with 'bugslyce recon plan'.",
        )
    )

    plan: ReconPlan | None = None
    try:
        plan = load_recon_plan(plan_path, require_provenance=False)
    except ValueError as exc:
        checks.append(
            _check(
                "PREFLIGHT-002",
                "Plan structure",
                "fail",
                str(exc),
                "Regenerate the plan with 'bugslyce recon plan'.",
            )
        )
    else:
        checks.append(
            _check(
                "PREFLIGHT-002",
                "Plan structure",
                "pass",
                f"Plan contains {len(plan.steps)} validated step(s).",
            )
        )

    if plan is not None:
        checks.extend(
            [
                _profile_check(plan),
                _scope_check(plan, plan_path),
                _output_directory_check(plan.output_dir),
                _command_preview_check(plan),
            ]
        )
        checks.extend(_tool_checks(plan.profile))

    warnings = [check.message for check in checks if check.status == "warn"]
    errors = [check.message for check in checks if check.status == "fail"]
    return ReconPreflightResult(
        plan_path=str(plan_path),
        target=target,
        profile=profile,
        output_dir=output_dir,
        passed=not errors,
        checks=checks,
        warnings=warnings,
        errors=errors,
        no_commands_executed=True,
    )


def render_preflight_markdown(result: ReconPreflightResult) -> str:
    """Render a compact Markdown preflight report."""

    counts = _status_counts(result)
    lines = [
        "# BugSlyce Recon Preflight",
        "",
        f"- Plan path: `{result.plan_path}`",
        f"- Target: `{result.target or 'unknown'}`",
        f"- Profile: `{result.profile or 'unknown'}`",
        f"- Output directory: `{result.output_dir}`",
        f"- Passed: `{str(result.passed).lower()}`",
        f"- Checks: {counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail",
        f"- No commands executed: `{str(result.no_commands_executed).lower()}`",
        "",
        "## Checks",
        "",
        "| ID | Check | Status | Message | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in result.checks:
        lines.append(
            f"| {check.id} | {_md(check.name)} | `{check.status}` | "
            f"{_md(check.message)} | {_md(check.remediation or 'none')} |"
        )
    lines.extend(
        [
            "",
            "No commands were executed.",
            "",
        ]
    )
    return "\n".join(lines)


def write_preflight_result(
    result: ReconPreflightResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown preflight results."""

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "recon_preflight.json"
    markdown_path = output_dir / "recon_preflight.md"
    json_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_preflight_markdown(result), encoding="utf-8")
    return json_path, markdown_path


def render_preflight_summary(
    result: ReconPreflightResult,
    json_path: Path,
    markdown_path: Path,
) -> str:
    """Render concise CLI preflight output."""

    counts = _status_counts(result)
    return "\n".join(
        [
            "BugSlyce recon preflight complete",
            f"Plan path: {result.plan_path}",
            f"Passed: {str(result.passed).lower()}",
            f"Checks: {counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail",
            f"JSON path: {json_path}",
            f"Markdown path: {markdown_path}",
            "No commands were executed.",
        ]
    )


def _profile_check(plan: ReconPlan) -> ReconPreflightCheck:
    supported = plan.profile in recon_profile_names()
    return _check(
        "PREFLIGHT-003",
        "Supported profile",
        "pass" if supported else "fail",
        (
            f"Profile '{plan.profile}' is supported."
            if supported
            else f"Profile '{plan.profile}' is not supported."
        ),
        "Regenerate the plan with a supported recon profile.",
    )


def _scope_check(plan: ReconPlan, plan_path: Path) -> ReconPreflightCheck:
    scope_path = _resolve_scope_path(plan.scope_file, plan_path)
    if scope_path is None or not scope_path.is_file():
        status = "warn" if plan.profile == "passive-only" else "fail"
        return _check(
            "PREFLIGHT-004",
            "Scope alignment",
            status,
            f"Scope file is not readable: {plan.scope_file}",
            "Provide a readable scope file and regenerate the plan.",
        )
    try:
        scope_text = scope_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        status = "warn" if plan.profile == "passive-only" else "fail"
        return _check(
            "PREFLIGHT-004",
            "Scope alignment",
            status,
            f"Scope file could not be read: {scope_path}",
            "Check local file permissions and scope-file encoding.",
        )

    aligned = plan.target.casefold() in scope_text.casefold()
    if aligned:
        return _check(
            "PREFLIGHT-004",
            "Scope alignment",
            "pass",
            f"Target '{plan.target}' appears in the scope file.",
        )
    status = "warn" if plan.profile == "passive-only" else "fail"
    return _check(
        "PREFLIGHT-004",
        "Scope alignment",
        status,
        f"Target '{plan.target}' does not appear in the scope file.",
        (
            "Passive-only planning may continue without live activity."
            if status == "warn"
            else "Update the scope file or regenerate the plan for an authorised target."
        ),
    )


def _output_directory_check(output_dir: str) -> ReconPreflightCheck:
    path = Path(output_dir).expanduser().resolve()
    project_root = Path.cwd().resolve()
    home = Path.home().resolve()
    unsafe_roots = [
        project_root,
        project_root / "examples",
        project_root / "tests",
        project_root / "bugslyce",
    ]
    safe_named_parts = {"private_recon", "raw-recon", "bugslyce-output"}

    if _is_relative_to(path, Path("/tmp")) or any(part in safe_named_parts for part in path.parts):
        return _check(
            "PREFLIGHT-005",
            "Output directory safety",
            "pass",
            f"Planned output directory uses an expected local recon path: {path}",
        )
    if path == home or any(path == root or _is_relative_to(path, root) for root in unsafe_roots):
        return _check(
            "PREFLIGHT-005",
            "Output directory safety",
            "fail",
            f"Planned output directory may expose recon data to project or home paths: {path}",
            "Use private_recon/, raw-recon/, bugslyce-output/, or /tmp/.",
        )
    return _check(
        "PREFLIGHT-005",
        "Output directory safety",
        "warn",
        f"Planned output directory is outside known gitignored recon paths: {path}",
        "Prefer private_recon/, raw-recon/, bugslyce-output/, or /tmp/.",
    )


def _command_preview_check(plan: ReconPlan) -> ReconPreflightCheck:
    matches: list[str] = []
    for step in plan.steps:
        command = (step.command_preview or "").casefold()
        for token in FORBIDDEN_COMMAND_TOKENS:
            if token in command and token not in matches:
                matches.append(token)
    if matches:
        return _check(
            "PREFLIGHT-006",
            "Command-preview guardrails",
            "fail",
            f"Command previews contain forbidden token(s): {', '.join(matches)}.",
            "Remove unsupported high-risk activity and regenerate the plan.",
        )
    return _check(
        "PREFLIGHT-006",
        "Command-preview guardrails",
        "pass",
        "Command previews do not contain configured forbidden high-risk tokens.",
    )


def _tool_checks(profile: str) -> list[ReconPreflightCheck]:
    tools = EXPECTED_TOOLS.get(profile)
    if tools is None:
        return []
    if not tools:
        return [
            _check(
                "PREFLIGHT-TOOL-000",
                "Tool availability",
                "pass",
                "Passive-only profile does not require external recon tools.",
            )
        ]
    checks: list[ReconPreflightCheck] = []
    for index, tool in enumerate(tools, start=1):
        available_path = shutil.which(tool)
        checks.append(
            _check(
                f"PREFLIGHT-TOOL-{index:03d}",
                f"Tool availability: {tool}",
                "pass" if available_path else "fail",
                (
                    f"Required tool '{tool}' is available at {available_path}."
                    if available_path
                    else f"Required tool '{tool}' was not found on PATH."
                ),
                f"Install '{tool}' locally before any future controlled execution.",
            )
        )
    return checks


def _read_payload(path: Path) -> dict[str, Any]:
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
    return payload


def _resolve_scope_path(value: str, plan_path: Path) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = path.resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (plan_path.parent / path).resolve()


def _check(
    check_id: str,
    name: str,
    status: str,
    message: str,
    remediation: str | None = None,
) -> ReconPreflightCheck:
    severity = {"pass": "informational", "warn": "warning", "fail": "error"}[status]
    return ReconPreflightCheck(check_id, name, status, message, severity, remediation)


def _text_value(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) else ""


def _status_counts(result: ReconPreflightResult) -> dict[str, int]:
    return {
        status: sum(1 for check in result.checks if check.status == status)
        for status in ("pass", "warn", "fail")
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
