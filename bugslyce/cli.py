"""Thin command-line wrapper for deterministic BugSlyce runs."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from bugslyce.core.project import build_project_state
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


def main(argv: Sequence[str] | None = None) -> int:
    """Run the BugSlyce CLI."""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args.input_dir, args.output_dir)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugslyce",
        description="Local-first bug bounty recon triage assistant.",
    )
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
    report_path, json_path = write_project_outputs(project_state, candidates, output_dir)

    print("BugSlyce run complete")
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Report path: {report_path}")
    print(f"JSON path: {json_path}")
    print(f"Assets: {len(project_state.assets)}")
    print(f"Endpoints: {len(project_state.endpoints)}")
    print(f"Candidates: {len(candidates)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
