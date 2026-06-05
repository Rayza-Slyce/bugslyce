"""Tests for the thin BugSlyce CLI wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def test_cli_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce" in captured.out


def test_cli_run_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce run" in captured.out
    assert "--output" in captured.out


def test_cli_config_show_exits_successfully(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["config", "show"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce config" in captured.out
    assert "LLM provider: none" in captured.out


def test_cli_config_reset_uses_temp_env(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "BUGSLYCE_LLM_PROVIDER=gemini\nGEMINI_API_KEY=secret-value\nUNRELATED=value\n",
        encoding="utf-8",
    )

    exit_code = main(["config", "reset"])

    captured = capsys.readouterr()
    text = (tmp_path / ".env").read_text(encoding="utf-8")

    assert exit_code == 0
    assert "no-LLM defaults" in captured.out
    assert "BUGSLYCE_LLM_PROVIDER=none" in text
    assert "GEMINI_API_KEY=" in text
    assert "secret-value" not in text
    assert "UNRELATED=value" in text
