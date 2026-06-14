"""Thin command-line wrapper for deterministic BugSlyce runs."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from bugslyce import __version__
from bugslyce.config import (
    forget_provider_keys,
    init_config,
    load_env_config,
    render_config_show,
    reset_config,
)
from bugslyce.core.project import build_project_state
from bugslyce.llm.prompt_builder import build_minimised_triage_context
from bugslyce.llm.providers import LLMProviderNotImplementedError, get_llm_provider
from bugslyce.project_session import (
    build_project_next,
    initialize_project,
    inspect_project_status,
    load_project,
    render_project_init_summary,
    render_project_next,
    render_project_show,
    render_project_status,
)
from bugslyce.recon.curl_headers import (
    render_curl_header_execution_summary,
    run_curl_header_workflow,
    write_curl_header_execution_result,
)
from bugslyce.recon.body_fetch import (
    BodyFetchExecutionIncomplete,
    BodyFetchNoWork,
    render_body_fetch_no_work,
    render_body_fetch_execution_summary,
    run_body_fetch_workflow,
    write_body_fetch_execution_result,
)
from bugslyce.recon.content_plan import (
    build_content_discovery_plan,
    content_discovery_profile_names,
    render_content_discovery_plan_summary,
    write_content_discovery_plan,
)
from bugslyce.recon.content_run import (
    ContentDiscoveryExecutionIncomplete,
    render_content_discovery_execution_summary,
    run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.content_followup import (
    ContentFollowupExecutionIncomplete,
    ContentFollowupNoWork,
    render_content_followup_no_work,
    render_content_followup_execution_summary,
    run_content_followup_workflow,
    write_content_followup_execution_result,
)
from bugslyce.recon.executor import (
    build_execution_preview,
    load_recon_plan,
    render_passive_execution_summary,
    render_execution_preview_summary,
    run_passive_execution,
    write_passive_execution_result,
    write_execution_preview,
)
from bugslyce.recon.export import export_recon_evidence_pack, render_recon_export_summary
from bugslyce.recon.http_metadata import (
    render_http_metadata_execution_summary,
    run_http_metadata_workflow,
    write_http_metadata_execution_result,
)
from bugslyce.recon.planner import (
    build_recon_plan,
    render_recon_plan_summary,
    write_recon_plan,
)
from bugslyce.recon.nmap_profiles import (
    build_nmap_command_plan,
    nmap_profile_names,
    render_nmap_command_plan_summary,
    write_nmap_command_plan,
)
from bugslyce.recon.nmap_discover import (
    render_nmap_discovery_execution_summary,
    run_nmap_discovery_workflow,
    write_nmap_discovery_execution_result,
)
from bugslyce.recon.nmap_services import (
    render_nmap_service_execution_summary,
    run_nmap_service_workflow,
    write_nmap_service_execution_result,
)
from bugslyce.recon.path_followup import (
    render_path_followup_execution_summary,
    run_path_followup_workflow,
    write_path_followup_execution_result,
)
from bugslyce.recon.preflight import (
    render_preflight_summary,
    run_preflight,
    write_preflight_result,
)
from bugslyce.recon.profiles import recon_profile_names
from bugslyce.recon.status import (
    build_recon_status,
    render_recon_status_summary,
    write_recon_status,
)
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


def main(argv: Sequence[str] | None = None) -> int:
    """Run the BugSlyce CLI."""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args.input_dir, args.output_dir)
    if args.command == "config":
        return _config(args)
    if args.command == "project":
        return _project(args)
    if args.command == "recon":
        return _recon(args)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugslyce",
        description="Local-first bug bounty recon triage assistant.",
    )
    parser.add_argument("--version", action="version", version=f"bugslyce {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser(
        "run",
        help="Build deterministic triage outputs from existing recon files.",
    )
    run_parser.add_argument("input_dir", type=Path, help="Directory containing existing recon input files.")
    run_parser.add_argument(
        "--output",
        dest="output_dir",
        type=Path,
        required=True,
        help="Directory where report.md and project_state.json will be written.",
    )

    config_parser = subparsers.add_parser(
        "config",
        help="Manage local future LLM provider settings.",
    )
    config_subparsers = config_parser.add_subparsers(dest="config_command")
    config_subparsers.add_parser("show", help="Show local BugSlyce config.")
    config_subparsers.add_parser("init", help="Interactively initialise local config.")
    config_subparsers.add_parser("forget-key", help="Remove provider API keys from .env.")
    config_subparsers.add_parser("reset", help="Reset local LLM config to no-LLM defaults.")

    project_parser = subparsers.add_parser(
        "project",
        help="Manage local BugSlyce project/session files.",
    )
    project_subparsers = project_parser.add_subparsers(dest="project_command")
    project_init_parser = project_subparsers.add_parser(
        "init",
        help="Create a local BugSlyce project file.",
    )
    project_init_parser.add_argument("--name", required=True, help="Safe local project name.")
    project_init_parser.add_argument("--target", required=True, help="One target IP or hostname.")
    project_init_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Existing Markdown scope file.",
    )
    project_init_parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Project recon output directory.",
    )
    project_init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing bugslyce_project.json file.",
    )
    project_show_parser = project_subparsers.add_parser(
        "show",
        help="Show saved project metadata without inspecting recon evidence.",
    )
    project_show_parser.add_argument(
        "--project",
        dest="project_file",
        required=True,
        type=Path,
        help="Path to bugslyce_project.json.",
    )
    project_status_parser = project_subparsers.add_parser(
        "status",
        help="Inspect project recon progress without running recon.",
    )
    project_status_parser.add_argument(
        "--project",
        dest="project_file",
        required=True,
        type=Path,
        help="Path to bugslyce_project.json.",
    )
    project_next_parser = project_subparsers.add_parser(
        "next",
        help="Preview the next safe project action without executing it.",
    )
    project_next_parser.add_argument(
        "--project",
        dest="project_file",
        required=True,
        type=Path,
        help="Path to bugslyce_project.json.",
    )

    recon_parser = subparsers.add_parser(
        "recon",
        help="Plan, inspect, or run narrowly scoped recon workflows.",
    )
    recon_subparsers = recon_parser.add_subparsers(dest="recon_command")
    plan_parser = recon_subparsers.add_parser(
        "plan",
        help="Create a planning-only recon plan.",
    )
    plan_parser.add_argument("--target", required=True, help="Authorised target to include in the plan.")
    plan_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file used for basic target presence validation.",
    )
    plan_parser.add_argument(
        "--profile",
        required=True,
        help=f"Planning profile: {', '.join(recon_profile_names())}.",
    )
    plan_parser.add_argument(
        "--output",
        dest="output_dir",
        required=True,
        type=Path,
        help="Directory where recon_plan.json and recon_plan.md will be written.",
    )
    execute_parser = recon_subparsers.add_parser(
        "execute",
        help="Preview a recon plan without executing commands.",
    )
    execute_parser.add_argument(
        "--plan",
        dest="plan_path",
        required=True,
        type=Path,
        help="Path to a BugSlyce recon_plan.json file.",
    )
    execute_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Required safety flag; writes execution preview files only.",
    )
    execute_parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Package existing local artifacts for a passive-only plan.",
    )
    execute_parser.add_argument(
        "--input-dir",
        type=Path,
        help="Optional local artifact directory; defaults to the plan output directory.",
    )
    preflight_parser = recon_subparsers.add_parser(
        "preflight",
        help="Check local readiness and plan safety without executing commands.",
    )
    preflight_parser.add_argument(
        "--plan",
        dest="plan_path",
        required=True,
        type=Path,
        help="Path to a BugSlyce recon_plan.json file.",
    )
    curl_headers_parser = recon_subparsers.add_parser(
        "curl-headers",
        help="Run one confirmed, scoped, bounded curl header request.",
    )
    curl_headers_parser.add_argument("--url", required=True, help="Explicit authorised HTTP or HTTPS URL.")
    curl_headers_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file that must contain the URL host.",
    )
    curl_headers_parser.add_argument(
        "--output",
        dest="output_dir",
        required=True,
        type=Path,
        help="Directory for raw headers, manifest, recon pack, and execution metadata.",
    )
    curl_headers_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Bounded curl timeout in seconds (default: 10, maximum: 30).",
    )
    curl_headers_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm the single scoped curl header request.",
    )
    nmap_plan_parser = recon_subparsers.add_parser(
        "nmap-plan",
        help="Create one approved nmap command plan without executing it.",
    )
    nmap_plan_parser.add_argument("--target", required=True, help="One authorised hostname or IP target.")
    nmap_plan_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the target in its In Scope section.",
    )
    nmap_plan_parser.add_argument(
        "--profile",
        required=True,
        choices=nmap_profile_names(),
        help="Approved planning-only nmap profile.",
    )
    nmap_plan_parser.add_argument(
        "--ports",
        help="Comma-separated ports required only for lab-service-scan.",
    )
    nmap_plan_parser.add_argument(
        "--output",
        dest="output_dir",
        required=True,
        type=Path,
        help="Directory for nmap_command_plan.json and nmap_command_plan.md.",
    )
    nmap_discover_parser = recon_subparsers.add_parser(
        "nmap-discover",
        help="Run one confirmed, scoped nmap TCP discovery command.",
    )
    nmap_discover_parser.add_argument("--target", required=True, help="One authorised hostname or IP target.")
    nmap_discover_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the target in its In Scope section.",
    )
    nmap_discover_parser.add_argument(
        "--profile",
        required=True,
        help="Approved live profile: lab-tcp-top or lab-tcp-full.",
    )
    nmap_discover_parser.add_argument(
        "--output",
        dest="output_dir",
        required=True,
        type=Path,
        help="Directory for nmap output, manifest, recon pack, and execution metadata.",
    )
    nmap_discover_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm the single scoped nmap discovery command.",
    )
    nmap_services_parser = recon_subparsers.add_parser(
        "nmap-services",
        help="Run one scoped service/version scan on previously discovered open TCP ports.",
    )
    nmap_services_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce nmap discovery output directory.",
    )
    nmap_services_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing discovery target.",
    )
    nmap_services_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm the derived-port nmap service/version command.",
    )
    http_metadata_parser = recon_subparsers.add_parser(
        "http-metadata",
        help="Collect bounded metadata from nmap-discovered HTTP services.",
    )
    http_metadata_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce output directory containing nmap service evidence.",
    )
    http_metadata_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing discovery target.",
    )
    http_metadata_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm bounded HTTP metadata requests.",
    )
    path_followup_parser = recon_subparsers.add_parser(
        "path-followup",
        help="Check bounded same-origin paths already present in collected evidence.",
    )
    path_followup_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce output directory containing HTTP metadata artifacts.",
    )
    path_followup_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing recon target.",
    )
    path_followup_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm bounded checks of evidence-derived paths.",
    )
    content_plan_parser = recon_subparsers.add_parser(
        "content-plan",
        help="Plan bounded root content discovery without executing commands.",
    )
    content_plan_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce output directory containing discovered HTTP services.",
    )
    content_plan_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing recon target.",
    )
    content_plan_parser.add_argument(
        "--profile",
        required=True,
        help=(
            "Supported planning profiles: "
            f"{', '.join(content_discovery_profile_names())}."
        ),
    )
    content_plan_parser.add_argument(
        "--output",
        dest="output_dir",
        required=True,
        type=Path,
        help="Safe directory for content_discovery_plan.json and Markdown.",
    )
    content_run_parser = recon_subparsers.add_parser(
        "content-run",
        help="Execute an approved BugSlyce root content discovery plan.",
    )
    content_run_parser.add_argument(
        "--plan",
        dest="plan_path",
        required=True,
        type=Path,
        help="Path to a BugSlyce content_discovery_plan.json file.",
    )
    content_run_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the plan target.",
    )
    content_run_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm approved root content discovery execution.",
    )
    content_run_parser.add_argument(
        "--step-id",
        help="Execute only this existing step ID from the approved plan.",
    )
    content_followup_parser = recon_subparsers.add_parser(
        "content-followup",
        help="Check selected paths already found by content discovery.",
    )
    content_followup_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce recon directory containing gobuster evidence.",
    )
    content_followup_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing recon target.",
    )
    content_followup_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm bounded content-result header requests.",
    )
    body_fetch_parser = recon_subparsers.add_parser(
        "body-fetch",
        help="Fetch selected bodies for high-signal paths already followed by BugSlyce.",
    )
    body_fetch_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce recon directory containing content-followup headers.",
    )
    body_fetch_parser.add_argument(
        "--scope",
        dest="scope_file",
        required=True,
        type=Path,
        help="Scope file containing the existing recon target.",
    )
    body_fetch_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Explicitly confirm bounded selective body GET requests.",
    )
    status_parser = recon_subparsers.add_parser(
        "status",
        help="Inspect local recon progress and safe next steps without live activity.",
    )
    status_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce recon directory to inspect.",
    )
    status_parser.add_argument(
        "--scope",
        dest="scope_file",
        type=Path,
        help="Optional scope file used to report exact target alignment.",
    )
    export_parser = recon_subparsers.add_parser(
        "export",
        help="Create a portable ZIP from an existing local evidence pack.",
    )
    export_parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Existing BugSlyce recon directory to package.",
    )
    export_parser.add_argument(
        "--output",
        dest="output_path",
        required=True,
        type=Path,
        help="Destination .zip path for the evidence pack.",
    )
    export_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing export ZIP.",
    )

    return parser


def _run(input_dir: Path, output_dir: Path) -> int:
    if not input_dir.exists():
        print(f"Error: input directory does not exist: {input_dir}", file=sys.stderr)
        return 2
    if not input_dir.is_dir():
        print(f"Error: input path is not a directory: {input_dir}", file=sys.stderr)
        return 2

    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    config = load_env_config()
    provider_name = config.get("BUGSLYCE_LLM_PROVIDER", "none")
    model = config.get("BUGSLYCE_LLM_MODEL", "") or None

    try:
        provider = get_llm_provider(provider_name, model)
    except LLMProviderNotImplementedError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    triage_context = build_minimised_triage_context(project_state, candidates)
    llm_result = provider.generate_report_enhancement(triage_context) if provider.is_available() else None
    report_path, json_path = write_project_outputs(project_state, candidates, output_dir)

    print("BugSlyce run complete")
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Report path: {report_path}")
    print(f"JSON path: {json_path}")
    print(f"Assets: {len(project_state.assets)}")
    print(f"Endpoints: {len(project_state.endpoints)}")
    print(f"Candidates: {len(candidates)}")
    if llm_result and llm_result.provider == "none":
        print("LLM provider: none (deterministic report only)")
    else:
        print(f"LLM provider: {provider.name}")

    return 0


def _config(args: argparse.Namespace) -> int:
    if args.config_command == "show":
        print(render_config_show())
        return 0
    if args.config_command == "init":
        try:
            init_config()
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print("BugSlyce config updated")
        return 0
    if args.config_command == "forget-key":
        forget_provider_keys()
        print("BugSlyce provider API keys removed from .env")
        return 0
    if args.config_command == "reset":
        reset_config()
        print("BugSlyce config reset to no-LLM defaults")
        return 0

    print("Error: config command required", file=sys.stderr)
    return 2


def _project(args: argparse.Namespace) -> int:
    if args.project_command == "init":
        try:
            project, project_path = initialize_project(
                name=args.name,
                target=args.target,
                scope_file=args.scope_file,
                output_dir=args.output_dir,
                force=args.force,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2
        print(render_project_init_summary(project, project_path))
        return 0

    if args.project_command == "show":
        try:
            project = load_project(args.project_file)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2
        print(render_project_show(project, args.project_file))
        return 0

    if args.project_command == "status":
        try:
            result = inspect_project_status(args.project_file)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2
        print(render_project_status(result))
        return 0

    if args.project_command == "next":
        try:
            result = build_project_next(args.project_file)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2
        print(render_project_next(result))
        return 0

    print(
        "Error: project command required. Use 'bugslyce project init --help', "
        "'bugslyce project show --help', 'bugslyce project status --help', "
        "or 'bugslyce project next --help'.",
        file=sys.stderr,
    )
    return 2


def _recon(args: argparse.Namespace) -> int:
    if args.recon_command == "plan":
        try:
            plan = build_recon_plan(
                target=args.target,
                scope_file=args.scope_file,
                output_dir=args.output_dir,
                profile=args.profile,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            return 2

        json_path, markdown_path = write_recon_plan(plan, args.output_dir)
        print(render_recon_plan_summary(plan, json_path, markdown_path))
        return 0

    if args.recon_command == "execute":
        if args.dry_run and args.passive_only:
            print("Error: choose either --dry-run or --passive-only, not both.", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            return 2
        if not args.dry_run and not args.passive_only:
            print(
                "Error: Live recon execution is not implemented yet. "
                "Re-run with --dry-run to preview planned execution or "
                "--passive-only to package existing local artifacts.",
                file=sys.stderr,
            )
            print("No commands were executed.", file=sys.stderr)
            return 2

        if args.dry_run:
            try:
                plan = load_recon_plan(args.plan_path)
                preview = build_execution_preview(
                    plan,
                    args.plan_path,
                    output_dir=args.plan_path.parent,
                )
                json_path, markdown_path = write_execution_preview(preview, args.plan_path.parent)
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                print("No commands were executed.", file=sys.stderr)
                return 2

            print(render_execution_preview_summary(preview, json_path, markdown_path))
            return 0

        try:
            plan = load_recon_plan(args.plan_path)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No network commands were executed.", file=sys.stderr)
            return 2
        if plan.profile != "passive-only":
            print(
                f"Error: Plan profile '{plan.profile}' is not passive-only. "
                "Live recon execution is not implemented yet.",
                file=sys.stderr,
            )
            print("No network commands were executed.", file=sys.stderr)
            return 2

        try:
            preflight = run_preflight(args.plan_path)
            preflight_json_path, preflight_markdown_path = write_preflight_result(
                preflight,
                args.plan_path.parent,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No network commands were executed.", file=sys.stderr)
            return 2
        if not preflight.passed:
            print("Error: recon preflight failed; passive execution was not started.", file=sys.stderr)
            print(f"Preflight JSON path: {preflight_json_path}", file=sys.stderr)
            print(f"Preflight Markdown path: {preflight_markdown_path}", file=sys.stderr)
            print("No network commands were executed.", file=sys.stderr)
            return 2

        output_dir = Path(plan.output_dir)
        input_dir = args.input_dir or output_dir
        try:
            result = run_passive_execution(
                plan=plan,
                plan_path=args.plan_path,
                input_dir=input_dir,
                output_dir=output_dir,
                preflight_passed=preflight.passed,
                preflight_warnings=preflight.warnings,
            )
            execution_json_path, execution_markdown_path = write_passive_execution_result(
                result,
                output_dir,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No network commands were executed.", file=sys.stderr)
            return 2

        print(
            render_passive_execution_summary(
                result,
                execution_json_path,
                execution_markdown_path,
            )
        )
        return 0

    if args.recon_command == "preflight":
        try:
            result = run_preflight(args.plan_path)
            json_path, markdown_path = write_preflight_result(result, args.plan_path.parent)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            return 2

        print(render_preflight_summary(result, json_path, markdown_path))
        return 0 if result.passed else 2

    if args.recon_command == "curl-headers":
        if not args.confirm:
            print(
                "Error: live curl header execution requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No network request was executed.", file=sys.stderr)
            return 2
        try:
            result = run_curl_header_workflow(
                url=args.url,
                scope_file=args.scope_file,
                output_dir=args.output_dir,
                timeout_seconds=args.timeout,
            )
            write_curl_header_execution_result(result, Path(result.output_dir))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

        print(render_curl_header_execution_summary(result))
        return 0

    if args.recon_command == "nmap-plan":
        try:
            profile, command = build_nmap_command_plan(
                target=args.target,
                scope_file=args.scope_file,
                profile_name=args.profile,
                output_dir=args.output_dir,
                ports=args.ports,
            )
            json_path, markdown_path = write_nmap_command_plan(
                profile,
                command,
                args.output_dir,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            return 2

        print(
            render_nmap_command_plan_summary(
                profile,
                command,
                args.output_dir,
                json_path,
                markdown_path,
            )
        )
        return 0

    if args.recon_command == "nmap-discover":
        if not args.confirm:
            print(
                "Error: live nmap execution requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No nmap command was executed.", file=sys.stderr)
            return 2
        try:
            result = run_nmap_discovery_workflow(
                target=args.target,
                scope_file=args.scope_file,
                output_dir=args.output_dir,
                profile_name=args.profile,
            )
            write_nmap_discovery_execution_result(result, Path(result.output_dir))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No nmap command was executed.", file=sys.stderr)
            return 2

        print(render_nmap_discovery_execution_summary(result))
        return 0

    if args.recon_command == "nmap-services":
        if not args.confirm:
            print(
                "Error: live nmap service scan requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No nmap command was executed.", file=sys.stderr)
            return 2
        try:
            result = run_nmap_service_workflow(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            write_nmap_service_execution_result(result, Path(result.input_dir))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No nmap command was executed.", file=sys.stderr)
            return 2

        print(render_nmap_service_execution_summary(result))
        return 0

    if args.recon_command == "http-metadata":
        if not args.confirm:
            print(
                "Error: live HTTP metadata collection requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No HTTP request was executed.", file=sys.stderr)
            return 2
        try:
            result = run_http_metadata_workflow(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            write_http_metadata_execution_result(result, Path(result.input_dir))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No HTTP metadata request was executed.", file=sys.stderr)
            return 2

        print(render_http_metadata_execution_summary(result))
        return 0

    if args.recon_command == "path-followup":
        if not args.confirm:
            print(
                "Error: live discovered-path follow-up requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No discovered-path request was executed.", file=sys.stderr)
            return 2
        try:
            result = run_path_followup_workflow(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            write_path_followup_execution_result(result, Path(result.input_dir))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No discovered-path request was executed.", file=sys.stderr)
            return 2

        print(render_path_followup_execution_summary(result))
        return 0

    if args.recon_command == "content-plan":
        try:
            plan = build_content_discovery_plan(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
                profile=args.profile,
                output_dir=args.output_dir,
            )
            json_path, markdown_path = write_content_discovery_plan(
                plan,
                args.output_dir,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            return 2

        print(render_content_discovery_plan_summary(plan, json_path, markdown_path))
        return 0

    if args.recon_command == "content-run":
        if not args.confirm:
            print(
                "Error: live content discovery requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No gobuster command was executed.", file=sys.stderr)
            return 2
        try:
            result = run_content_discovery_workflow(
                plan_path=args.plan_path,
                scope_file=args.scope_file,
                step_id=args.step_id,
                progress_callback=print,
            )
            write_content_discovery_execution_result(
                result,
                Path(result.output_dir),
            )
        except ContentDiscoveryExecutionIncomplete as exc:
            result = exc.result
            execution_json, execution_markdown = write_content_discovery_execution_result(
                result,
                Path(result.output_dir),
            )
            print(f"Error: {exc}", file=sys.stderr)
            print(render_content_discovery_execution_summary(result), file=sys.stderr)
            print(f"Execution JSON path: {execution_json}", file=sys.stderr)
            print(f"Execution Markdown path: {execution_markdown}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No gobuster command was executed.", file=sys.stderr)
            return 2

        print(render_content_discovery_execution_summary(result))
        return 0

    if args.recon_command == "content-followup":
        if not args.confirm:
            print(
                "Error: live content-result follow-up requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No content-result request was executed.", file=sys.stderr)
            return 2
        try:
            result = run_content_followup_workflow(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            write_content_followup_execution_result(
                result,
                Path(result.input_dir),
            )
        except ContentFollowupExecutionIncomplete as exc:
            result = exc.result
            write_content_followup_execution_result(result, Path(result.input_dir))
            print(f"Error: {exc}", file=sys.stderr)
            print(render_content_followup_execution_summary(result), file=sys.stderr)
            return 2
        except ContentFollowupNoWork as outcome:
            print(render_content_followup_no_work(outcome))
            return 0
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No content-result request was executed.", file=sys.stderr)
            return 2

        print(render_content_followup_execution_summary(result))
        return 0

    if args.recon_command == "body-fetch":
        if not args.confirm:
            print(
                "Error: live selective body fetch requires explicit --confirm.",
                file=sys.stderr,
            )
            print("No body-fetch request was executed.", file=sys.stderr)
            return 2
        try:
            result = run_body_fetch_workflow(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            write_body_fetch_execution_result(result, Path(result.input_dir))
        except BodyFetchExecutionIncomplete as exc:
            result = exc.result
            write_body_fetch_execution_result(result, Path(result.input_dir))
            print(f"Error: {exc}", file=sys.stderr)
            print(render_body_fetch_execution_summary(result), file=sys.stderr)
            return 2
        except BodyFetchNoWork as outcome:
            print(render_body_fetch_no_work(outcome))
            return 0
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No body-fetch request was executed.", file=sys.stderr)
            return 2

        print(render_body_fetch_execution_summary(result))
        return 0

    if args.recon_command == "status":
        try:
            result = build_recon_status(
                input_dir=args.input_dir,
                scope_file=args.scope_file,
            )
            json_path, markdown_path = write_recon_status(result, args.input_dir)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2

        print(render_recon_status_summary(result, json_path, markdown_path))
        return 0

    if args.recon_command == "export":
        try:
            result = export_recon_evidence_pack(
                input_dir=args.input_dir,
                output_path=args.output_path,
                force=args.force,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print("No live commands were executed.", file=sys.stderr)
            print("No network requests were made.", file=sys.stderr)
            return 2

        print(render_recon_export_summary(result))
        return 0

    print(
        "Error: recon command required. Use 'bugslyce recon plan --help' "
        "'bugslyce recon execute --help', 'bugslyce recon preflight --help', "
        "'bugslyce recon curl-headers --help', 'bugslyce recon nmap-plan --help', "
        "'bugslyce recon nmap-discover --help', 'bugslyce recon nmap-services --help', "
        "'bugslyce recon http-metadata --help', "
        "'bugslyce recon path-followup --help', "
        "'bugslyce recon content-plan --help', "
        "'bugslyce recon content-run --help', "
        "'bugslyce recon content-followup --help', "
        "'bugslyce recon body-fetch --help', "
        "'bugslyce recon status --help', "
        "or 'bugslyce recon export --help'.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
