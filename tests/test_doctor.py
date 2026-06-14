"""Tests for the read-only local readiness doctor."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from bugslyce import __version__
from bugslyce.cli import main
from bugslyce.doctor import (
    DIRBUSTER_SMALL_WORDLIST,
    build_doctor_report,
    doctor_exit_code,
    render_doctor_text,
)


def test_doctor_reports_environment_tools_and_wordlists() -> None:
    tool_paths = {
        "nmap": "/usr/bin/nmap",
        "curl": "/usr/bin/curl",
        "gobuster": "/usr/bin/gobuster",
    }

    report = build_doctor_report(
        which=tool_paths.get,
        path_exists=lambda path: path == DIRBUSTER_SMALL_WORDLIST,
        bundled_wordlist_probe=lambda: (
            True,
            "/package/bugslyce/wordlists/lab-root-tiny.txt",
        ),
    )
    rendered = render_doctor_text(report)

    assert report.readiness == "ready"
    assert doctor_exit_code(report) == 0
    assert "BugSlyce doctor" in rendered
    assert f"BugSlyce version: {__version__}" in rendered
    assert "Python:" in rendered
    assert "Virtual environment:" in rendered
    assert "nmap: found at /usr/bin/nmap" in rendered
    assert "curl: found at /usr/bin/curl" in rendered
    assert "gobuster: found at /usr/bin/gobuster" in rendered
    assert "bundled lab-root-tiny: found" in rendered
    assert "dirbuster small: found" in rendered
    assert "Project commands: available" in rendered


def test_missing_optional_content_tools_produce_warnings_not_failure() -> None:
    report = build_doctor_report(
        which=lambda tool: "/usr/bin/curl" if tool == "curl" else None,
        path_exists=lambda path: False,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
    )
    rendered = render_doctor_text(report)

    assert report.readiness == "ready with warnings"
    assert doctor_exit_code(report) == 0
    assert "gobuster: not found" in rendered
    assert "Content discovery execution is unavailable" in rendered
    assert "optional lab-root-light profile is unavailable" in rendered


def test_missing_bundled_wordlist_is_not_ready() -> None:
    report = build_doctor_report(
        which=lambda tool: f"/usr/bin/{tool}",
        path_exists=lambda path: True,
        bundled_wordlist_probe=lambda: (False, None),
    )
    rendered = render_doctor_text(report)

    assert report.readiness == "not ready"
    assert doctor_exit_code(report) != 0
    assert "bundled lab-root-tiny: missing" in rendered


def test_cli_doctor_is_read_only_and_does_not_execute_subprocess(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    def fail_subprocess(*args, **kwargs):
        raise AssertionError("doctor must not call subprocess")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    before = set(tmp_path.iterdir())

    exit_code = main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code in {0, 2}
    assert "BugSlyce doctor" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert set(tmp_path.iterdir()) == before


def test_root_help_includes_doctor(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "doctor" in captured.out
    assert "Check local BugSlyce readiness" in captured.out


def test_doctor_module_has_no_execution_or_network_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "doctor.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source
