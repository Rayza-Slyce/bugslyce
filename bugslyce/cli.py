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
from bugslyce.recon.planner import (
    build_recon_plan,
    render_recon_plan_summary,
    write_recon_plan,
)
from bugslyce.recon.profiles import recon_profile_names
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

    recon_parser = subparsers.add_parser(
        "recon",
        help="Preview future recon activity without executing commands.",
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


def _recon(args: argparse.Namespace) -> int:
    if args.recon_command != "plan":
        print("Error: recon command required. Use 'bugslyce recon plan --help'.", file=sys.stderr)
        return 2

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


if __name__ == "__main__":
    raise SystemExit(main())
