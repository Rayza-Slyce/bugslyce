"""Tests for structured recon commands and simulated runner."""

from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from bugslyce.core.models import ReconCommand
from bugslyce.recon.commands import build_recon_commands, validate_recon_command
from bugslyce.recon.nmap_profiles import (
    build_nmap_full_tcp_command,
    build_nmap_service_scan_command,
    build_nmap_top_ports_command,
    validate_nmap_command,
)
from bugslyce.recon.planner import build_recon_plan
from bugslyce.recon.runner import SimulatedReconRunner


def test_recon_command_serialises_cleanly(tmp_path: Path) -> None:
    command = _safe_command(tmp_path, "curl", ["curl", "-I", "http://10.10.10.10/"])

    payload = json.loads(json.dumps(asdict(command)))

    assert payload["tool"] == "curl"
    assert payload["argv"] == ["curl", "-I", "http://10.10.10.10/"]
    assert payload["ready_for_execution"] is True


def test_command_builder_creates_structured_commands_from_lab_full_plan(tmp_path: Path) -> None:
    plan = _lab_plan(tmp_path)

    commands, warnings = build_recon_commands(plan)

    assert warnings == []
    assert len(commands) == 7
    assert [command.tool for command in commands] == [
        "nmap",
        "nmap",
        "curl",
        "curl",
        "gobuster",
        "gobuster",
        "curl",
    ]
    assert all(isinstance(command.argv, list) for command in commands)
    assert all(command.argv[0] == command.tool for command in commands)
    assert all(command.ready_for_execution is False for command in commands)
    assert all(command.placeholders for command in commands)


def test_command_builder_skips_scope_only_step(tmp_path: Path) -> None:
    plan = _lab_plan(tmp_path)

    commands, _warnings = build_recon_commands(plan)

    assert all(command.id != "CMD-001" for command in commands)
    assert all(command.phase != "scope" for command in commands)


@pytest.mark.parametrize(
    ("tool", "argv", "output_name"),
    [
        (
            "curl",
            ["curl", "-I", "--max-time", "20", "http://10.10.10.10/"],
            "curl-headers-80.txt",
        ),
        (
            "gobuster",
            ["gobuster", "dir", "-u", "http://10.10.10.10/", "-w", "small.txt"],
            "gobuster-80-root.txt",
        ),
    ],
)
def test_validation_accepts_safe_allowlisted_argv(
    tmp_path: Path,
    tool: str,
    argv: list[str],
    output_name: str,
) -> None:
    command = _safe_command(tmp_path, tool, argv, output_name)

    result = validate_recon_command(command, tmp_path)

    assert result.valid is True
    assert result.errors == []


def test_validation_rejects_non_allowlisted_tool(tmp_path: Path) -> None:
    command = _safe_command(tmp_path, "custom-tool", ["custom-tool", "--check"])

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("not allowlisted" in error for error in result.errors)


@pytest.mark.parametrize("unsafe_arg", ["value;next", "a&&b", "a||b", "a|b", "`id`", "$(id)", ">out", "<in"])
def test_validation_rejects_shell_metacharacters(tmp_path: Path, unsafe_arg: str) -> None:
    command = _safe_command(tmp_path, "curl", ["curl", unsafe_arg])

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("shell metacharacter" in error for error in result.errors)


@pytest.mark.parametrize("forbidden", ["hydra", "sqlmap", "nuclei", "masscan", "brute", "password", "exploit", "payload"])
def test_validation_rejects_forbidden_tools_or_tokens(tmp_path: Path, forbidden: str) -> None:
    command = _safe_command(tmp_path, "curl", ["curl", forbidden])

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("forbidden token" in error for error in result.errors)


def test_validation_rejects_output_outside_planned_directory(tmp_path: Path) -> None:
    command = replace(
        build_nmap_top_ports_command("10.10.10.10", tmp_path),
        output_file=str(tmp_path.parent / "outside.txt"),
    )

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("planned output directory" in error for error in result.errors)


def test_validation_rejects_non_list_argv(tmp_path: Path) -> None:
    command = replace(
        build_nmap_top_ports_command("10.10.10.10", tmp_path),
        argv=("nmap", "-p-"),  # type: ignore[arg-type]
    )

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert "argv must be a list of strings." in result.errors


def test_validation_rejects_unresolved_builder_command(tmp_path: Path) -> None:
    commands, _warnings = build_recon_commands(_lab_plan(tmp_path))

    result = validate_recon_command(commands[0], tmp_path / "bugslyce-output")

    assert result.valid is False
    assert any("unresolved placeholders" in error for error in result.errors)


def test_simulated_runner_returns_result_without_execution(tmp_path: Path) -> None:
    command = build_nmap_top_ports_command("10.10.10.10", tmp_path)
    runner = SimulatedReconRunner(tmp_path)

    result = runner.run(command)

    assert result.executed is False
    assert result.simulated is True
    assert result.exit_code == 0
    assert result.error is None
    assert result.stdout_path is None
    assert result.stderr_path is None
    assert result.started_at.endswith("Z")
    assert result.ended_at.endswith("Z")
    assert not Path(command.output_file).exists()


def test_nmap_top_ports_builder_creates_approved_argv(tmp_path: Path) -> None:
    command = build_nmap_top_ports_command("10.10.10.10", tmp_path)

    assert command.argv == [
        "nmap",
        "-sS",
        "-Pn",
        "--top-ports",
        "1000",
        "-oN",
        str((tmp_path / "nmap-top1000.txt").resolve()),
        "10.10.10.10",
    ]
    assert command.ready_for_execution is False
    assert command.requires_confirmation is True
    assert command.scope_sensitive is True
    assert validate_recon_command(command, tmp_path).valid is True


def test_nmap_full_tcp_builder_creates_approved_argv(tmp_path: Path) -> None:
    command = build_nmap_full_tcp_command("lab.example.test", tmp_path)

    assert command.argv == [
        "nmap",
        "-sS",
        "-Pn",
        "-p-",
        "--min-rate",
        "5000",
        "-oN",
        str((tmp_path / "nmap-allports.txt").resolve()),
        "lab.example.test",
    ]
    assert validate_nmap_command(command, tmp_path).valid is True


def test_nmap_service_scan_builder_validates_explicit_ports(tmp_path: Path) -> None:
    command = build_nmap_service_scan_command(
        "10.10.10.10",
        "80,6498,65524",
        tmp_path,
    )

    assert command.argv == [
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        "80,6498,65524",
        "-oN",
        str((tmp_path / "nmap-services-all.txt").resolve()),
        "10.10.10.10",
    ]
    assert "-sC" not in command.argv
    assert validate_nmap_command(command, tmp_path).valid is True


@pytest.mark.parametrize("ports", ["", "0", "65536", "80-90", "80,tcp", "80;id"])
def test_nmap_service_scan_rejects_invalid_ports(tmp_path: Path, ports: str) -> None:
    with pytest.raises(ValueError, match="port"):
        build_nmap_service_scan_command("10.10.10.10", ports, tmp_path)


@pytest.mark.parametrize(
    "unsafe_argv",
    [
        ["nmap", "-A", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-O", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "--script", "default", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "--script=vuln", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sU", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-T5", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sS", "-Pn", "--top-ports", "1000", "-oN", "out.txt", "10.10.10.10", "10.10.10.11"],
    ],
)
def test_nmap_validation_rejects_unapproved_shapes(
    tmp_path: Path,
    unsafe_argv: list[str],
) -> None:
    command = replace(
        build_nmap_top_ports_command("10.10.10.10", tmp_path),
        argv=unsafe_argv,
    )

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("approved command profile" in error for error in result.errors)


def test_nmap_validation_rejects_shell_metacharacters(tmp_path: Path) -> None:
    command = replace(
        build_nmap_top_ports_command("10.10.10.10", tmp_path),
        argv=[
            "nmap",
            "-sS",
            "-Pn",
            "--top-ports",
            "1000",
            "-oN",
            str((tmp_path / "nmap-top1000.txt").resolve()),
            "10.10.10.10;id",
        ],
    )

    result = validate_recon_command(command, tmp_path)

    assert result.valid is False
    assert any("shell metacharacter" in error for error in result.errors)


def test_simulated_runner_reports_validation_failure(tmp_path: Path) -> None:
    command = _safe_command(tmp_path, "curl", ["curl", "payload"])

    result = SimulatedReconRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.simulated is True
    assert result.exit_code is None
    assert result.error is not None
    assert not Path(command.output_file).exists()


def test_command_builder_contains_no_execution_apis() -> None:
    root = Path(__file__).resolve().parents[1] / "bugslyce" / "recon"
    source = (root / "commands.py").read_text(encoding="utf-8").casefold()

    forbidden = ("subprocess", "os.system", "popen", "pexpect", "shell=true")
    assert all(value not in source for value in forbidden)


def test_nmap_planning_module_contains_no_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "recon" / "nmap_profiles.py"
    ).read_text(encoding="utf-8").casefold()

    forbidden = ("subprocess", "os.system", "popen", "pexpect", "shell=true")
    assert all(value not in source for value in forbidden)


def _lab_plan(tmp_path: Path):
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    return build_recon_plan(
        "10.10.10.10",
        scope,
        tmp_path / "bugslyce-output",
        "lab-full",
    )


def _safe_command(
    output_dir: Path,
    tool: str,
    argv: list[str],
    output_name: str = "output.txt",
) -> ReconCommand:
    return ReconCommand(
        id="CMD-TEST",
        tool=tool,
        argv=argv,
        output_file=str(output_dir / output_name),
        timeout_seconds=60,
        phase="test",
        risk_level="low",
        requires_confirmation=True,
        scope_sensitive=True,
        description="Structured command validation test.",
        ready_for_execution=True,
        placeholders=[],
    )
