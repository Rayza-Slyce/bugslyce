"""Tests for the read-only local readiness doctor."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess

import pytest

from bugslyce import __version__
from bugslyce.cli import main
from bugslyce.doctor import (
    DEEP_BOUNDED_CORE_WORDLIST,
    DoctorReport,
    DIRBUSTER_SMALL_WORDLIST,
    ResourceReadiness,
    STANDARD_BOUNDED_CORE_WORDLIST,
    TINY_WORDLIST,
    ToolReadiness,
    build_doctor_report,
    doctor_exit_code,
    mode_readiness_failures,
    render_doctor_text,
)


def test_doctor_reports_environment_tools_and_wordlists() -> None:
    tool_paths = {
        "nmap": "/usr/bin/nmap",
        "curl": "/usr/bin/curl",
    }

    report = build_doctor_report(
        which=tool_paths.get,
        path_exists=lambda path: path
        in {
            DIRBUSTER_SMALL_WORDLIST,
            TINY_WORDLIST,
            STANDARD_BOUNDED_CORE_WORDLIST,
            DEEP_BOUNDED_CORE_WORDLIST,
        },
        path_is_file=lambda path: True,
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: str(path).startswith("/usr/bin/"),
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (
            True,
            "/package/bugslyce/wordlists/lab-root-tiny.txt",
        ),
    )
    rendered = render_doctor_text(report)

    assert report.readiness == "ready"
    assert report.core_ready is True
    assert report.recon_ready is True
    assert report.overall_ready is True
    assert doctor_exit_code(report) == 0
    assert "BugSlyce doctor" in rendered
    assert f"BugSlyce version: {__version__}" in rendered
    assert "Python version:" in rendered
    assert "Minimum supported Python: 3.11" in rendered
    assert "Virtual environment:" in rendered
    assert "nmap: ready (/usr/bin/nmap)" in rendered
    assert "curl: ready (/usr/bin/curl)" in rendered
    assert "gobuster:" not in rendered
    assert "lab-root-tiny: ready" in rendered
    assert "standard-bounded-core: ready" in rendered
    assert "deep-bounded-core: ready" in rendered
    assert "dirbuster small: found" in rendered
    assert "Project/CLI command surface: ready" in rendered
    assert "Manual Setup Only: ready" in rendered
    assert "Reconnaissance: ready" in rendered
    assert "Quick Recon:" not in rendered
    assert "Standard Recon:" not in rendered
    assert "Deep Recon:" not in rendered


def test_build_doctor_report_produces_complete_structured_readiness() -> None:
    report = _ready_report()

    assert tuple(tool.name for tool in report.tools) == ("nmap", "curl")
    assert tuple(resource.name for resource in report.resources) == (
        "lab-root-tiny",
        "standard-bounded-core",
        "deep-bounded-core",
    )
    assert mode_readiness_failures(report, "deep") == ()
    assert doctor_exit_code(report) == 0


def test_gobuster_absence_does_not_block_current_reconnaissance_readiness() -> None:
    report = build_doctor_report(
        which=lambda tool: f"/usr/bin/{tool}" if tool in {"nmap", "curl"} else None,
        path_exists=lambda path: path in {
            TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST
        } or str(path).startswith("/usr/bin/"),
        path_is_file=lambda _path: True,
        path_is_dir=lambda _path: False,
        path_is_executable=lambda path: str(path).startswith("/usr/bin/"),
        path_is_readable=lambda _path: True,
        path_size=lambda _path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
    )

    assert report.recon_ready is True
    assert doctor_exit_code(report) == 0
    assert "gobuster" not in report.tool_paths


def test_missing_required_tools_block_recon_but_not_manual_setup() -> None:
    report = build_doctor_report(
        which=lambda tool: "/usr/bin/curl" if tool == "curl" else None,
        path_exists=lambda path: path
        in {TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST},
        path_is_file=lambda path: True,
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: str(path) == "/usr/bin/curl",
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
    )
    rendered = render_doctor_text(report)

    assert report.core_ready is True
    assert report.recon_ready is False
    assert report.readiness == "not ready"
    assert doctor_exit_code(report) == 2
    assert "nmap: blocked (not found)" in rendered
    assert "Manual Setup Only: ready" in rendered
    assert "Reconnaissance: blocked" in rendered
    assert "Install `nmap`" in rendered
    assert any("optional legacy lab-root-light" in warning for warning in report.warnings)


def test_missing_bundled_wordlist_is_not_ready() -> None:
    report = build_doctor_report(
        which=lambda tool: f"/usr/bin/{tool}",
        path_exists=lambda path: str(path).startswith("/usr/bin/"),
        path_is_file=lambda path: str(path).startswith("/usr/bin/"),
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: str(path).startswith("/usr/bin/"),
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (False, None),
    )
    rendered = render_doctor_text(report)

    assert report.readiness == "not ready"
    assert doctor_exit_code(report) != 0
    assert "lab-root-tiny: blocked" in rendered
    assert "resource file is missing" in rendered


def test_invalid_tool_path_is_not_ready() -> None:
    report = build_doctor_report(
        which=lambda tool: f"/tools/{tool}",
        path_exists=lambda path: path
        in {TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST},
        path_is_file=lambda path: path
        in {TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST},
        path_is_dir=lambda path: str(path) == "/tools/nmap",
        path_is_executable=lambda path: False,
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
    )
    rendered = render_doctor_text(report)

    assert report.recon_ready is False
    assert "nmap: blocked (/tools/nmap)" in rendered
    assert "resolved path is a directory" in rendered


def test_runtime_version_check_is_testable() -> None:
    old = build_doctor_report(
        which=lambda tool: f"/usr/bin/{tool}",
        path_exists=lambda path: path
        in {TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST},
        path_is_file=lambda path: True,
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: True,
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
        python_version_info=(3, 10, 9),
    )
    minimum = build_doctor_report(
        which=lambda tool: f"/usr/bin/{tool}",
        path_exists=lambda path: path
        in {TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST},
        path_is_file=lambda path: True,
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: True,
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
        python_version_info=(3, 11, 0),
    )

    assert old.python_supported is False
    assert old.core_ready is False
    assert doctor_exit_code(old) == 2
    assert minimum.python_supported is True
    assert minimum.core_ready is True


def test_mode_readiness_resource_blockers_are_profile_specific() -> None:
    tiny_missing = _ready_report_with_missing_resources({TINY_WORDLIST})
    standard_missing = _ready_report_with_missing_resources({STANDARD_BOUNDED_CORE_WORDLIST})
    deep_missing = _ready_report_with_missing_resources({DEEP_BOUNDED_CORE_WORDLIST})

    assert mode_readiness_failures(tiny_missing, "deep") == ()
    assert mode_readiness_failures(standard_missing, "deep") == ()
    assert mode_readiness_failures(deep_missing, "deep") == (
        "Reconnaissance is blocked: required bundled resource `deep-bounded-core` is unavailable: resource file is missing.",
    )
    assert tiny_missing.recon_ready is True
    assert standard_missing.recon_ready is True
    assert deep_missing.recon_ready is False
    assert doctor_exit_code(tiny_missing) == 0
    assert doctor_exit_code(standard_missing) == 0
    assert doctor_exit_code(deep_missing) == 2
    modes = {mode.mode: mode.status for mode in standard_missing.modes}
    assert modes["manual_setup"] == "ready"
    assert modes["deep"] == "ready"
    assert set(modes) == {"manual_setup", "deep"}


@pytest.mark.parametrize("tool", ("nmap", "curl"))
def test_mode_readiness_shared_tools_block_all_executable_modes(tool: str) -> None:
    report = _ready_report_with_missing_tool(tool)

    assert mode_readiness_failures(report, "deep") == (
        f"Reconnaissance is blocked: required pipeline tool `{tool}` is unavailable: not found on PATH.",
    )


def test_mode_readiness_can_omit_only_policy_skipped_nmap() -> None:
    report = _ready_report_with_missing_tool("nmap")

    assert mode_readiness_failures(
        report,
        "deep",
        nmap_required=False,
    ) == ()
    assert mode_readiness_failures(report, "deep") == (
        "Reconnaissance is blocked: required pipeline tool `nmap` is unavailable: "
        "not found on PATH.",
    )
    with pytest.raises(ValueError, match="Nmap requirement must be boolean"):
        mode_readiness_failures(
            report,
            "deep",
            nmap_required="no",
        )


def test_mode_readiness_core_failure_blocks_all_modes_and_unknown_fails_closed() -> None:
    report = _ready_report(python_version_info=(3, 10, 9))

    assert mode_readiness_failures(report, "deep") == (
        "Reconnaissance is blocked: supported Python runtime is unavailable.",
    )
    with pytest.raises(ValueError, match="Unknown doctor mode"):
        mode_readiness_failures(report, "manual_setup")


def test_mode_readiness_failure_ordering_is_deterministic() -> None:
    report = build_doctor_report(
        which=lambda tool: None,
        path_exists=lambda path: False,
        path_is_file=lambda path: False,
        path_is_dir=lambda path: False,
        path_is_executable=lambda path: False,
        path_is_readable=lambda path: False,
        path_size=lambda path: 0,
        bundled_wordlist_probe=lambda: (False, None),
    )

    assert mode_readiness_failures(report, "deep") == (
        "Reconnaissance is blocked: required pipeline tool `nmap` is unavailable: not found on PATH.",
        "Reconnaissance is blocked: required pipeline tool `curl` is unavailable: not found on PATH.",
        "Reconnaissance is blocked: required bundled resource `deep-bounded-core` is unavailable: resource file is missing.",
    )


@pytest.mark.parametrize("missing_tool", ("nmap", "curl"))
def test_mode_readiness_missing_tool_record_blocks_all_modes(missing_tool: str) -> None:
    report = _ready_report()
    report = replace(
        report,
        tools=tuple(tool for tool in report.tools if tool.name != missing_tool),
    )

    assert mode_readiness_failures(report, "deep") == (
        f"Reconnaissance is blocked: required readiness record for pipeline tool `{missing_tool}` is missing.",
    )
    assert doctor_exit_code(report) == 2


def test_mode_readiness_duplicate_and_inconsistent_tool_records_fail_closed() -> None:
    report = _ready_report()
    nmap = report.tools[0]
    duplicate = replace(report, tools=(nmap, *report.tools))
    found_false = replace(report, tools=(replace(nmap, ready=True, found=False), *report.tools[1:]))
    executable_false = replace(
        report,
        tools=(replace(nmap, ready=True, executable=False), *report.tools[1:]),
    )
    workflow_missing = replace(
        report,
        tools=(replace(nmap, blocked_workflows=("quick", "standard")), *report.tools[1:]),
    )

    assert mode_readiness_failures(duplicate, "deep") == (
        "Reconnaissance is blocked: duplicate readiness records exist for pipeline tool `nmap`.",
    )
    assert mode_readiness_failures(found_false, "deep") == (
        "Reconnaissance is blocked: readiness record for `nmap` is internally inconsistent.",
    )
    assert mode_readiness_failures(executable_false, "deep") == (
        "Reconnaissance is blocked: readiness record for `nmap` is internally inconsistent.",
    )
    assert mode_readiness_failures(workflow_missing, "deep") == (
        "Reconnaissance is blocked: readiness record for pipeline tool `nmap` does not declare `deep`.",
    )
    assert doctor_exit_code(duplicate) == 2


def test_mode_readiness_missing_resource_records_are_profile_specific() -> None:
    report = _ready_report()
    tiny_missing = replace(
        report,
        resources=tuple(
            resource for resource in report.resources if resource.name != "lab-root-tiny"
        ),
    )
    standard_missing = replace(
        report,
        resources=tuple(
            resource
            for resource in report.resources
            if resource.name != "standard-bounded-core"
        ),
    )
    deep_missing = replace(
        report,
        resources=tuple(
            resource
            for resource in report.resources
            if resource.name != "deep-bounded-core"
        ),
    )

    assert mode_readiness_failures(tiny_missing, "deep") == ()
    assert mode_readiness_failures(standard_missing, "deep") == ()
    assert mode_readiness_failures(deep_missing, "deep") == (
        "Reconnaissance is blocked: required readiness record for bundled resource `deep-bounded-core` is missing.",
    )
    assert doctor_exit_code(tiny_missing) == 0
    assert doctor_exit_code(standard_missing) == 0
    assert doctor_exit_code(deep_missing) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("exists", False),
        ("regular_file", False),
        ("readable", False),
        ("non_empty", False),
        ("inside_package", False),
    ),
)
def test_mode_readiness_inconsistent_resource_record_fails_closed(
    field: str,
    value: bool,
) -> None:
    report = _ready_report()
    deep = next(resource for resource in report.resources if resource.name == "deep-bounded-core")
    updated = replace(
        report,
        resources=tuple(
            replace(resource, ready=True, **{field: value})
            if resource.name == "deep-bounded-core"
            else resource
            for resource in report.resources
        ),
    )

    assert deep.name == "deep-bounded-core"
    assert mode_readiness_failures(updated, "deep") == (
        "Reconnaissance is blocked: readiness record for bundled resource `deep-bounded-core` is internally inconsistent.",
    )


def test_mode_readiness_duplicate_and_workflow_missing_resource_records_fail_closed() -> None:
    report = _ready_report()
    deep = next(resource for resource in report.resources if resource.name == "deep-bounded-core")
    duplicate = replace(report, resources=(*report.resources, deep))
    workflow_missing = replace(
        report,
        resources=tuple(
            replace(resource, blocked_workflows=("quick", "standard"))
            if resource.name == "deep-bounded-core"
            else resource
            for resource in report.resources
        ),
    )

    assert mode_readiness_failures(duplicate, "deep") == (
        "Reconnaissance is blocked: duplicate readiness records exist for bundled resource `deep-bounded-core`.",
    )
    assert mode_readiness_failures(workflow_missing, "deep") == (
        "Reconnaissance is blocked: readiness record for bundled resource `deep-bounded-core` does not declare `deep`.",
    )


def test_mode_readiness_contradictory_core_fields_fail_closed() -> None:
    report = replace(_ready_report(), core_ready=True, python_supported=False)

    assert mode_readiness_failures(report, "deep") == (
        "Reconnaissance is blocked: core readiness fields are internally inconsistent.",
    )
    assert doctor_exit_code(report) == 2


def test_doctor_exit_code_fails_closed_for_contradictory_global_readiness() -> None:
    ready = _ready_report()

    assert doctor_exit_code(replace(ready, recon_ready=False)) == 2
    assert doctor_exit_code(replace(ready, overall_ready=False)) == 2


def _ready_report_with_missing_resources(missing: set[Path]):
    return _ready_report(
        path_exists=lambda path: path
        in {
            DIRBUSTER_SMALL_WORDLIST,
            TINY_WORDLIST,
            STANDARD_BOUNDED_CORE_WORDLIST,
            DEEP_BOUNDED_CORE_WORDLIST,
        }
        and path not in missing,
        bundled_wordlist_probe=lambda: (
            TINY_WORDLIST not in missing,
            "/package/bugslyce/wordlists/lab-root-tiny.txt",
        ),
    )


def _ready_report_with_missing_tool(missing_tool: str):
    return _ready_report(
        which=lambda tool: None if tool == missing_tool else f"/usr/bin/{tool}",
    )


def _ready_report(**overrides):
    kwargs = {
        "which": lambda tool: f"/usr/bin/{tool}",
        "path_exists": lambda path: path
        in {
            DIRBUSTER_SMALL_WORDLIST,
            TINY_WORDLIST,
            STANDARD_BOUNDED_CORE_WORDLIST,
            DEEP_BOUNDED_CORE_WORDLIST,
        },
        "path_is_file": lambda path: True,
        "path_is_dir": lambda path: False,
        "path_is_executable": lambda path: str(path).startswith("/usr/bin/"),
        "path_is_readable": lambda path: True,
        "path_size": lambda path: 10,
        "bundled_wordlist_probe": lambda: (
            True,
            "/package/bugslyce/wordlists/lab-root-tiny.txt",
        ),
    }
    kwargs.update(overrides)
    return build_doctor_report(**kwargs)


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
