"""Build and serialize recon plans without executing commands."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from bugslyce.core.models import ReconPlan, ReconPlannedArtifact, ReconPlanStep
from bugslyce.recon.profiles import get_recon_profile


NO_EXECUTION_NOTE = "No commands were executed."


def build_recon_plan(
    target: str,
    scope_file: Path,
    output_dir: Path,
    profile: str,
) -> ReconPlan:
    """Build a deterministic planning-only recon plan."""

    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty.")
    if not scope_file.exists():
        raise ValueError(f"Scope file does not exist: {scope_file}")
    if not scope_file.is_file():
        raise ValueError(f"Scope path is not a file: {scope_file}")

    recon_profile = get_recon_profile(profile)
    try:
        scope_text = scope_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read scope file {scope_file}: {exc}") from exc

    target_in_scope_text = target.casefold() in scope_text.casefold()
    warnings: list[str] = []
    if not target_in_scope_text:
        message = f"Target '{target}' does not appear in scope file {scope_file}."
        if recon_profile.name != "passive-only":
            raise ValueError(f"{message} Refusing to plan live recon activity.")
        warnings.append(f"{message} Passive-only planning is allowed because no live recon is included.")

    steps, artifacts = _profile_plan(recon_profile.name, target, output_dir)
    safety_notes = [
        NO_EXECUTION_NOTE,
        "This plan is a preview for future controlled execution and must be reviewed by an operator.",
        "Keep raw recon artifacts and generated outputs in local, gitignored directories.",
        *recon_profile.safety_notes,
    ]
    return ReconPlan(
        target=target,
        scope_file=str(scope_file),
        profile=recon_profile.name,
        output_dir=str(output_dir),
        created_by="bugslyce-recon-planner",
        steps=steps,
        planned_artifacts=artifacts,
        safety_notes=safety_notes,
        warnings=warnings,
    )


def write_recon_plan(plan: ReconPlan, output_dir: Path | None = None) -> tuple[Path, Path]:
    """Write planning-only JSON and Markdown documents."""

    destination = output_dir or Path(plan.output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "recon_plan.json"
    markdown_path = destination / "recon_plan.md"
    json_path.write_text(json.dumps(asdict(plan), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_recon_plan(plan), encoding="utf-8")
    return json_path, markdown_path


def render_recon_plan(plan: ReconPlan) -> str:
    """Render a readable planning-only Markdown document."""

    lines = [
        "# BugSlyce Recon Plan",
        "",
        f"- Target: `{plan.target}`",
        f"- Scope file: `{plan.scope_file}`",
        f"- Profile: `{plan.profile}`",
        f"- Planned output directory: `{plan.output_dir}`",
        f"- Created by: `{plan.created_by}`",
        "",
        "## Safety",
        "",
    ]
    lines.extend(f"- {note}" for note in plan.safety_notes)
    if plan.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in plan.warnings)

    lines.extend(["", "## Planned Steps", ""])
    for step in plan.steps:
        lines.extend(
            [
                f"### {step.id}: {step.name}",
                "",
                f"- Phase: `{step.phase}`",
                f"- Description: {step.description}",
                f"- Risk level: `{step.risk_level}`",
                f"- Requires confirmation: `{str(step.requires_confirmation).lower()}`",
                f"- Scope sensitive: `{str(step.scope_sensitive).lower()}`",
                f"- Command preview: `{step.command_preview}`" if step.command_preview else "- Command preview: none",
                "- Expected artifacts: "
                + (", ".join(f"`{item}`" for item in step.expected_artifacts) or "none"),
                "",
            ]
        )

    lines.extend(["## Planned Manifest Entries", ""])
    if not plan.planned_artifacts:
        lines.append("- No new raw artifacts are planned for this profile.")
    else:
        for artifact in plan.planned_artifacts:
            context = artifact.url or artifact.base_url or "context determined from future evidence"
            lines.append(
                f"- `{artifact.type}` -> `{artifact.file}`: "
                f"{artifact.description or 'Planned raw recon artifact'} ({context})"
            )
    lines.extend(["", NO_EXECUTION_NOTE, ""])
    return "\n".join(lines)


def render_recon_plan_summary(plan: ReconPlan, json_path: Path, markdown_path: Path) -> str:
    """Render concise CLI output for a completed planning operation."""

    lines = [
        "BugSlyce recon plan created",
        f"Target: {plan.target}",
        f"Profile: {plan.profile}",
        f"Output directory: {plan.output_dir}",
        f"JSON path: {json_path}",
        f"Markdown path: {markdown_path}",
        f"Planned steps: {len(plan.steps)}",
        f"Planned artifacts: {len(plan.planned_artifacts)}",
    ]
    lines.extend(f"Warning: {warning}" for warning in plan.warnings)
    lines.append(NO_EXECUTION_NOTE)
    return "\n".join(lines)


def _profile_plan(
    profile: str,
    target: str,
    output_dir: Path,
) -> tuple[list[ReconPlanStep], list[ReconPlannedArtifact]]:
    if profile == "lab-full":
        return _lab_full_plan(target, output_dir)
    if profile == "bug-bounty-standard":
        return _bug_bounty_standard_plan(target, output_dir)
    return _passive_only_plan()


def _lab_full_plan(
    target: str,
    output_dir: Path,
) -> tuple[list[ReconPlanStep], list[ReconPlannedArtifact]]:
    artifacts = _active_artifacts(include_recursive=True)
    steps = [
        _step("STEP-001", "Confirm target scope", "scope", "Review the target against the supplied scope.", None, [], False, "low"),
        _step(
            "STEP-002",
            "Full TCP port discovery",
            "service-discovery",
            "Plan a bounded full TCP port scan against the authorised lab target.",
            f"nmap -p- --min-rate <bounded-rate> -oN {output_dir}/nmap-allports.txt {target}",
            ["nmap-allports.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-003",
            "Service and version discovery",
            "service-enumeration",
            "Plan service identification for ports discovered by the prior step.",
            f"nmap -sV -p <discovered-ports> -oN {output_dir}/nmap-services-all.txt {target}",
            ["nmap-services-all.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-004",
            "HTTP probing and response header checks",
            "http-discovery",
            "Plan bounded header checks for discovered HTTP services.",
            f"curl -I --max-time <timeout> <discovered-http-url> --output {output_dir}/curl-headers-<http-port>.txt",
            ["curl-headers-<http-port>.txt"],
            True,
            "low",
        ),
        _step(
            "STEP-005",
            "Robots and sitemap checks",
            "http-metadata",
            "Plan retrieval of standard robots and sitemap metadata from discovered HTTP services.",
            f"curl --max-time <timeout> <http-origin>/robots.txt --output {output_dir}/robots-<http-port>.txt",
            ["robots-<http-port>.txt", "sitemap-<http-port>.xml"],
            True,
            "low",
        ),
        _step(
            "STEP-006",
            "Root content discovery",
            "content-discovery",
            "Plan bounded directory discovery against each discovered HTTP service root.",
            f"gobuster dir -u <http-origin>/ -w <approved-wordlist> -o {output_dir}/gobuster-<http-port>-root.txt",
            ["gobuster-<http-port>-root.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-007",
            "Limited recursive content discovery",
            "content-discovery",
            "Plan one bounded follow-up pass for selected discovered directories after operator review.",
            f"gobuster dir -u <approved-discovered-url> -w <approved-wordlist> -o {output_dir}/gobuster-<http-port>-<path>.txt",
            ["gobuster-<http-port>-<path>.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-008",
            "Saved HTML metadata collection",
            "http-metadata",
            "Plan saving selected HTML responses for deterministic metadata parsing.",
            f"curl --max-time <timeout> <selected-http-url> --output {output_dir}/homepage-<http-port>.html",
            ["homepage-<http-port>.html"],
            True,
            "low",
        ),
    ]
    return steps, artifacts


def _bug_bounty_standard_plan(
    target: str,
    output_dir: Path,
) -> tuple[list[ReconPlanStep], list[ReconPlannedArtifact]]:
    artifacts = _active_artifacts(include_recursive=False)
    steps = [
        _step("STEP-001", "Confirm programme scope", "scope", "Review scope, exclusions, and programme limits.", None, [], False, "low"),
        _step(
            "STEP-002",
            "Controlled port discovery",
            "service-discovery",
            "Plan conservative port discovery using bounded rates and timeouts.",
            f"nmap --top-ports <approved-count> -oN {output_dir}/nmap-allports.txt {target}",
            ["nmap-allports.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-003",
            "Service and version discovery",
            "service-enumeration",
            "Plan service identification only for ports found by the controlled discovery step.",
            f"nmap -sV -p <discovered-ports> -oN {output_dir}/nmap-services-all.txt {target}",
            ["nmap-services-all.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-004",
            "HTTP probing and response header checks",
            "http-discovery",
            "Plan low-rate header checks against discovered in-scope HTTP services.",
            f"curl -I --max-time <timeout> <discovered-http-url> --output {output_dir}/curl-headers-<http-port>.txt",
            ["curl-headers-<http-port>.txt"],
            True,
            "low",
        ),
        _step(
            "STEP-005",
            "Robots and sitemap checks",
            "http-metadata",
            "Plan standard metadata checks without broad path guessing.",
            f"curl --max-time <timeout> <http-origin>/robots.txt --output {output_dir}/robots-<http-port>.txt",
            ["robots-<http-port>.txt", "sitemap-<http-port>.xml"],
            True,
            "low",
        ),
        _step(
            "STEP-006",
            "Conservative content discovery",
            "content-discovery",
            "Plan a bounded, low-rate root discovery pass with an approved wordlist.",
            f"gobuster dir -u <http-origin>/ -w <approved-small-wordlist> -o {output_dir}/gobuster-<http-port>-root.txt",
            ["gobuster-<http-port>-root.txt"],
            True,
            "moderate",
        ),
        _step(
            "STEP-007",
            "Saved HTML metadata collection",
            "http-metadata",
            "Plan saving selected in-scope HTML responses for local metadata parsing.",
            f"curl --max-time <timeout> <selected-http-url> --output {output_dir}/homepage-<http-port>.html",
            ["homepage-<http-port>.html"],
            True,
            "low",
        ),
    ]
    return steps, artifacts


def _passive_only_plan() -> tuple[list[ReconPlanStep], list[ReconPlannedArtifact]]:
    return (
        [
            _step(
                "STEP-001",
                "Inventory supplied artifacts",
                "offline-import",
                "Identify supported local recon artifacts already supplied by the operator.",
                None,
                [],
                False,
                "low",
                scope_sensitive=False,
            ),
            _step(
                "STEP-002",
                "Validate recon manifest",
                "offline-import",
                "Validate local manifest metadata and constrain artifact paths to the input directory.",
                None,
                ["recon_manifest.json"],
                False,
                "low",
                scope_sensitive=False,
            ),
            _step(
                "STEP-003",
                "Build deterministic recon pack",
                "offline-analysis",
                "Parse supplied evidence and produce deterministic Markdown and JSON outputs.",
                None,
                ["report.md", "project_state.json"],
                False,
                "low",
                scope_sensitive=False,
            ),
        ],
        [],
    )


def _active_artifacts(include_recursive: bool) -> list[ReconPlannedArtifact]:
    artifacts = [
        ReconPlannedArtifact("nmap", "nmap-allports.txt", description="Full or controlled TCP discovery output."),
        ReconPlannedArtifact("nmap", "nmap-services-all.txt", description="Service and version discovery output."),
        ReconPlannedArtifact(
            "http_headers",
            "curl-headers-<http-port>.txt",
            url="<discovered-http-url>",
            description="Saved HTTP response headers.",
        ),
        ReconPlannedArtifact(
            "robots",
            "robots-<http-port>.txt",
            url="<http-origin>/robots.txt",
            description="Saved robots metadata.",
        ),
        ReconPlannedArtifact(
            "html",
            "sitemap-<http-port>.xml",
            url="<http-origin>/sitemap.xml",
            description="Saved sitemap metadata where available.",
        ),
        ReconPlannedArtifact(
            "gobuster",
            "gobuster-<http-port>-root.txt",
            base_url="<http-origin>/",
            description="Bounded root content discovery output.",
        ),
        ReconPlannedArtifact(
            "html",
            "homepage-<http-port>.html",
            url="<selected-http-url>",
            description="Saved HTML for deterministic metadata extraction.",
        ),
    ]
    if include_recursive:
        artifacts.append(
            ReconPlannedArtifact(
                "gobuster",
                "gobuster-<http-port>-<path>.txt",
                base_url="<approved-discovered-url>",
                description="Limited follow-up content discovery output.",
            )
        )
    return artifacts


def _step(
    step_id: str,
    name: str,
    phase: str,
    description: str,
    command_preview: str | None,
    expected_artifacts: list[str],
    requires_confirmation: bool,
    risk_level: str,
    scope_sensitive: bool = True,
) -> ReconPlanStep:
    return ReconPlanStep(
        id=step_id,
        name=name,
        phase=phase,
        description=description,
        command_preview=command_preview,
        expected_artifacts=expected_artifacts,
        requires_confirmation=requires_confirmation,
        risk_level=risk_level,
        scope_sensitive=scope_sensitive,
    )
