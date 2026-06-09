"""Tests for the narrowly scoped live nmap top-1000 workflow."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.recon.nmap_discover import run_nmap_discovery_workflow
from bugslyce.recon.nmap_profiles import (
    build_live_nmap_full_tcp_command,
    build_live_nmap_top_ports_command,
    validate_live_nmap_discovery_command,
    validate_live_nmap_top_ports_command,
)
from bugslyce.recon.runner import LiveNmapDiscoveryRunner


def test_live_nmap_command_has_exact_lab_tcp_top_shape(tmp_path: Path) -> None:
    command = build_live_nmap_top_ports_command("10.10.10.10", tmp_path)

    assert command.argv == [
        "nmap",
        "-sS",
        "-Pn",
        "--top-ports",
        "1000",
        "-oN",
        str(tmp_path.resolve() / "nmap-top1000.txt"),
        "10.10.10.10",
    ]
    assert command.ready_for_execution is True
    assert command.placeholders == []
    assert validate_live_nmap_top_ports_command(command, tmp_path).valid is True


def test_live_nmap_command_has_exact_lab_tcp_full_shape(tmp_path: Path) -> None:
    command = build_live_nmap_full_tcp_command("10.10.10.10", tmp_path)

    assert command.argv == [
        "nmap",
        "-sS",
        "-Pn",
        "-p-",
        "--min-rate",
        "5000",
        "-oN",
        str(tmp_path.resolve() / "nmap-allports.txt"),
        "10.10.10.10",
    ]
    assert command.ready_for_execution is True
    assert command.placeholders == []
    assert validate_live_nmap_discovery_command(command, tmp_path).valid is True


def test_live_nmap_runner_uses_list_argv_and_bounded_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    command = build_live_nmap_top_ports_command("10.10.10.10", tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text(
            "Nmap scan report for 10.10.10.10\nPORT   STATE SERVICE\n80/tcp open  http\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is True
    assert result.simulated is False
    assert result.exit_code == 0
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == command.timeout_seconds
    assert "shell" not in kwargs


def test_live_full_nmap_runner_uses_list_argv_and_bounded_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    command = build_live_nmap_full_tcp_command("10.10.10.10", tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text(
            "Nmap scan report for 10.10.10.10\nPORT     STATE SERVICE\n65524/tcp open  unknown\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is True
    assert result.exit_code == 0
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == command.timeout_seconds
    assert "shell" not in kwargs


def test_live_nmap_runner_refuses_non_nmap_tool(tmp_path: Path, monkeypatch) -> None:
    command = replace(
        build_live_nmap_top_ports_command("10.10.10.10", tmp_path),
        tool="curl",
        argv=["curl", "-I", "http://10.10.10.10/"],
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert "restricted to the nmap tool" in (result.error or "")
    assert called is False


@pytest.mark.parametrize(
    "unsafe_argv",
    [
        ["nmap", "-A", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-O", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "--script=vuln", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sU", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-T5", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-D", "RND:5", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-S", "192.0.2.10", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sV", "-Pn", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        [
            "nmap",
            "-sS",
            "-Pn",
            "--top-ports",
            "1000",
            "-oN",
            "out.txt",
            "10.10.10.10",
            "10.10.10.11",
        ],
    ],
)
def test_live_nmap_runner_refuses_unapproved_shapes(
    tmp_path: Path,
    monkeypatch,
    unsafe_argv: list[str],
) -> None:
    command = replace(
        build_live_nmap_top_ports_command("10.10.10.10", tmp_path),
        argv=unsafe_argv,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert "approved lab-tcp-top or lab-tcp-full argv shape" in (result.error or "")
    assert called is False


def test_live_nmap_runner_refuses_mutated_full_tcp_shape(
    tmp_path: Path,
    monkeypatch,
) -> None:
    command = replace(
        build_live_nmap_full_tcp_command("10.10.10.10", tmp_path),
        argv=[
            "nmap",
            "-sS",
            "-Pn",
            "-p-",
            "--min-rate",
            "6000",
            "-oN",
            str(tmp_path / "nmap-allports.txt"),
            "10.10.10.10",
        ],
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert "approved lab-tcp-top or lab-tcp-full argv shape" in (result.error or "")
    assert called is False


def test_live_nmap_runner_rejects_output_outside_directory(tmp_path: Path) -> None:
    command = replace(
        build_live_nmap_top_ports_command("10.10.10.10", tmp_path),
        output_file=str(tmp_path.parent / "nmap-top1000.txt"),
    )

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert "selected output directory" in (result.error or "") or "inside" in (result.error or "")


def test_live_nmap_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    command = build_live_nmap_top_ports_command("10.10.10.10", tmp_path)

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error == f"Nmap discovery exceeded {command.timeout_seconds} seconds."


def test_live_full_nmap_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    command = build_live_nmap_full_tcp_command("10.10.10.10", tmp_path)

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapDiscoveryRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error == f"Nmap discovery exceeded {command.timeout_seconds} seconds."


def test_nmap_workflow_writes_manifest_and_recon_pack_with_mock_runner(tmp_path: Path) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    result = run_nmap_discovery_workflow(
        "10.10.10.10",
        scope,
        output,
        runner=_MockNmapRunner(),
    )
    manifest = json.loads((output / "recon_manifest.json").read_text(encoding="utf-8"))
    exported = json.loads((output / "project_state.json").read_text(encoding="utf-8"))

    assert result.execution_count == 1
    assert result.profile == "lab-tcp-top"
    assert (output / "nmap-top1000.txt").exists()
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert manifest["created_by"] == "bugslyce-nmap-discover"
    assert manifest["profile"] == "lab-tcp-top"
    assert manifest["artifacts"] == [
        {
            "type": "nmap",
            "file": "nmap-top1000.txt",
            "description": "Single bounded nmap top-1000 TCP discovery command",
        }
    ]
    assert exported["project_state"]["port_services"][0]["port"] == 80


def test_full_nmap_workflow_writes_manifest_and_recon_pack_with_mock_runner(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    result = run_nmap_discovery_workflow(
        "10.10.10.10",
        scope,
        output,
        profile_name="lab-tcp-full",
        runner=_MockNmapRunner(),
    )
    manifest = json.loads((output / "recon_manifest.json").read_text(encoding="utf-8"))

    assert result.execution_count == 1
    assert result.profile == "lab-tcp-full"
    assert (output / "nmap-allports.txt").exists()
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert manifest["profile"] == "lab-tcp-full"
    assert manifest["artifacts"] == [
        {
            "type": "nmap",
            "file": "nmap-allports.txt",
            "description": "Single bounded nmap full TCP discovery command",
        }
    ]


def test_nmap_workflow_rejects_unsupported_profile(tmp_path: Path) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="only profiles 'lab-tcp-top' and 'lab-tcp-full'"):
        run_nmap_discovery_workflow(
            "10.10.10.10",
            scope,
            tmp_path / "output",
            profile_name="lab-service-scan",
            runner=_MockNmapRunner(),
        )


def test_nmap_workflow_rejects_target_absent_from_scope(tmp_path: Path) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_nmap_discovery_workflow(
            "10.10.10.10",
            scope,
            tmp_path / "output",
            runner=_MockNmapRunner(),
        )


def test_nmap_workflow_requires_explicit_target_not_only_cidr(tmp_path: Path) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.0/24\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_nmap_discovery_workflow(
            "10.10.10.10",
            scope,
            tmp_path / "output",
            runner=_MockNmapRunner(),
        )


class _MockNmapRunner:
    def run(self, command):
        output = Path(command.output_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            "\n".join(
                [
                    "Nmap scan report for 10.10.10.10",
                    "PORT   STATE SERVICE",
                    "80/tcp open  http",
                    "Nmap done: 1 IP address (1 host up) scanned",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:01+00:00",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=None,
        )
