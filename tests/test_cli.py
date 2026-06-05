"""Tests for the thin BugSlyce CLI wrapper."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.cli import main


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_cli_run_succeeds_against_basic_saas(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "cli-output"

    exit_code = main(["run", str(FIXTURES_ROOT / "basic_saas"), "--output", str(output_dir)])

    captured = capsys.readouterr()
    report_path = output_dir / "report.md"
    json_path = output_dir / "project_state.json"

    assert exit_code == 0
    assert output_dir.exists()
    assert report_path.exists()
    assert json_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["candidates"]
    assert str(report_path) in captured.out
    assert "Candidates:" in captured.out


def test_cli_missing_input_directory_returns_nonzero(tmp_path: Path, capsys) -> None:
    missing_input = tmp_path / "missing"
    output_dir = tmp_path / "output"

    exit_code = main(["run", str(missing_input), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "input directory does not exist" in captured.err
    assert not output_dir.exists()
