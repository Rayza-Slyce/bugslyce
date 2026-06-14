"""Tests for the preview-only wizard entrypoint."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bugslyce.cli import main


def test_wizard_prints_safe_guided_workflow(capsys) -> None:
    exit_code = main(["wizard"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce guided mode" in captured.out
    assert "local-first recon triage for authorised testing" in captured.out
    assert "bugslyce project init" in captured.out
    assert "bugslyce project status" in captured.out
    assert "bugslyce project next" in captured.out
    assert "bugslyce recon export" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert "Review programme scope before running recon." in captured.out


def test_wizard_help_exists(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["wizard", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce wizard" in captured.out


def test_root_help_lists_wizard(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "wizard" in captured.out
    assert "safe guided workflow previews" in captured.out


def test_wizard_creates_no_files_and_does_not_run_subprocess(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    def fail_subprocess(*args, **kwargs):
        raise AssertionError("wizard must not call subprocess.run")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", fail_subprocess)

    before = set(tmp_path.iterdir())
    exit_code = main(["wizard"])
    after = set(tmp_path.iterdir())

    captured = capsys.readouterr()
    assert exit_code == 0
    assert before == after
    assert "No commands were executed." in captured.out
