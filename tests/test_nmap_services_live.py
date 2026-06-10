"""Tests for scoped nmap service/version scanning of discovered ports."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.recon.nmap_profiles import (
    build_live_nmap_service_scan_command,
    validate_live_nmap_service_scan_command,
)
from bugslyce.recon.nmap_services import (
    extract_open_tcp_ports,
    run_nmap_service_workflow,
)
from bugslyce.recon.runner import LiveNmapServiceRunner


def test_extract_open_tcp_ports_sorts_dedupes_and_ignores_non_open_tcp(
    tmp_path: Path,
) -> None:
    source = tmp_path / "nmap-allports.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT      STATE    SERVICE",
                "65524/tcp open     unknown",
                "80/tcp    open     http",
                "80/tcp    open     http",
                "443/tcp   closed   https",
                "8080/tcp  filtered http-proxy",
                "53/udp    open     domain",
                "6498/tcp  open     unknown",
            ]
        ),
        encoding="utf-8",
    )

    target, ports = extract_open_tcp_ports(source)

    assert target == "10.10.10.10"
    assert ports == [80, 6498, 65524]


def test_live_service_command_has_exact_derived_port_shape(tmp_path: Path) -> None:
    command = build_live_nmap_service_scan_command(
        "10.10.10.10",
        [80, 6498, 65524],
        tmp_path,
    )

    assert command.argv == [
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        "80,6498,65524",
        "-oN",
        str(tmp_path.resolve() / "nmap-services-all.txt"),
        "10.10.10.10",
    ]
    assert command.ready_for_execution is True
    assert validate_live_nmap_service_scan_command(command, tmp_path).valid is True


def test_live_service_runner_uses_list_argv_and_bounded_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    command = build_live_nmap_service_scan_command("10.10.10.10", [80, 6498], tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text(
            "Nmap scan report for 10.10.10.10\n"
            "PORT     STATE SERVICE VERSION\n"
            "80/tcp   open  http    nginx 1.16.1\n"
            "6498/tcp open  ssh     OpenSSH 7.6\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapServiceRunner(tmp_path).run(command)

    assert result.executed is True
    assert result.exit_code == 0
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == command.timeout_seconds
    assert "shell" not in kwargs


def test_live_service_runner_refuses_non_nmap_tool(tmp_path: Path, monkeypatch) -> None:
    command = replace(
        build_live_nmap_service_scan_command("10.10.10.10", [80], tmp_path),
        tool="curl",
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapServiceRunner(tmp_path).run(command)

    assert result.executed is False
    assert "restricted to the nmap tool" in (result.error or "")
    assert called is False


@pytest.mark.parametrize(
    "unsafe_argv",
    [
        ["nmap", "-A", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-O", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sC", "-sV", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "--script=vuln", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sU", "-p", "53", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-T5", "-sV", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-D", "RND:5", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-S", "192.0.2.10", "-p", "80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sV", "-Pn", "-p", "80-90", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sV", "-Pn", "-p", "80,80", "-oN", "out.txt", "10.10.10.10"],
        ["nmap", "-sV", "-Pn", "-p", "80;id", "-oN", "out.txt", "10.10.10.10"],
        [
            "nmap",
            "-sV",
            "-Pn",
            "-p",
            "80",
            "-oN",
            "out.txt",
            "10.10.10.10",
            "10.10.10.11",
        ],
    ],
)
def test_live_service_runner_refuses_unapproved_shapes(
    tmp_path: Path,
    monkeypatch,
    unsafe_argv: list[str],
) -> None:
    command = replace(
        build_live_nmap_service_scan_command("10.10.10.10", [80], tmp_path),
        argv=unsafe_argv,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapServiceRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error
    assert called is False


def test_live_service_runner_rejects_output_outside_directory(tmp_path: Path) -> None:
    command = replace(
        build_live_nmap_service_scan_command("10.10.10.10", [80], tmp_path),
        output_file=str(tmp_path.parent / "nmap-services-all.txt"),
    )

    result = LiveNmapServiceRunner(tmp_path).run(command)

    assert result.executed is False
    assert "inside" in (result.error or "")


def test_live_service_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    command = build_live_nmap_service_scan_command("10.10.10.10", [80], tmp_path)

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveNmapServiceRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error == f"Nmap service scan exceeded {command.timeout_seconds} seconds."


def test_service_workflow_prefers_allports_and_updates_manifest(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    input_dir = tmp_path / "output"
    _discovery_directory(input_dir, "nmap-allports.txt")
    (input_dir / "nmap-top1000.txt").write_text(
        "Nmap scan report for 10.10.10.10\nPORT   STATE SERVICE\n443/tcp open https\n",
        encoding="utf-8",
    )

    result = run_nmap_service_workflow(
        input_dir,
        scope,
        runner=_MockServiceRunner(),
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    exported = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.ports == [80, 6498, 65524]
    assert (input_dir / "nmap-services-all.txt").exists()
    assert (input_dir / "report.md").exists()
    assert manifest["artifacts"][0]["file"] == "nmap-allports.txt"
    assert manifest["artifacts"][1]["file"] == "nmap-services-all.txt"
    assert manifest["profile"] == "lab-tcp-full-plus-services"
    services = {
        (item["port"], item["service"], item["product"])
        for item in exported["project_state"]["port_services"]
    }
    assert (6498, "ssh", "OpenSSH") in services
    assert (65524, "http", "Apache") in services
    assert any(
        item["url"] == "http://10.10.10.10:65524/"
        for item in exported["project_state"]["http_services"]
    )


def test_service_workflow_falls_back_to_top1000(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    input_dir = tmp_path / "output"
    _discovery_directory(input_dir, "nmap-top1000.txt")

    result = run_nmap_service_workflow(
        input_dir,
        scope,
        runner=_MockServiceRunner(),
    )

    assert result.ports == [80, 6498, 65524]


def test_service_workflow_rejects_missing_input_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        run_nmap_service_workflow(
            tmp_path / "missing",
            _scope(tmp_path),
            runner=_MockServiceRunner(),
        )


def test_service_workflow_rejects_missing_discovery_artifact(tmp_path: Path) -> None:
    input_dir = tmp_path / "output"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="does not contain nmap-allports.txt"):
        run_nmap_service_workflow(
            input_dir,
            _scope(tmp_path),
            runner=_MockServiceRunner(),
        )


def test_service_workflow_rejects_no_open_tcp_ports(tmp_path: Path) -> None:
    input_dir = tmp_path / "output"
    _discovery_directory(input_dir, "nmap-allports.txt", states="closed")

    with pytest.raises(ValueError, match="No open TCP ports"):
        run_nmap_service_workflow(
            input_dir,
            _scope(tmp_path),
            runner=_MockServiceRunner(),
        )


def test_service_workflow_rejects_target_not_in_scope(tmp_path: Path) -> None:
    input_dir = tmp_path / "output"
    _discovery_directory(input_dir, "nmap-allports.txt")
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_nmap_service_workflow(
            input_dir,
            scope,
            runner=_MockServiceRunner(),
        )


def _scope(tmp_path: Path) -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    return scope


def _discovery_directory(
    input_dir: Path,
    filename: str,
    states: str = "open",
) -> None:
    input_dir.mkdir(parents=True, exist_ok=True)
    input_dir.joinpath(filename).write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT      STATE SERVICE",
                f"80/tcp    {states}  http",
                f"6498/tcp  {states}  unknown",
                f"65524/tcp {states}  unknown",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    input_dir.joinpath("recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "created_by": "bugslyce-nmap-discover",
                "profile": (
                    "lab-tcp-full"
                    if filename == "nmap-allports.txt"
                    else "lab-tcp-top"
                ),
                "artifacts": [
                    {
                        "type": "nmap",
                        "file": filename,
                        "description": "Discovery output",
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


class _MockServiceRunner:
    def run(self, command):
        output = Path(command.output_file)
        output.write_text(
            "\n".join(
                [
                    "Nmap scan report for 10.10.10.10",
                    "PORT      STATE SERVICE VERSION",
                    "80/tcp    open  http    nginx 1.16.1",
                    "6498/tcp  open  ssh     OpenSSH 7.6p1",
                    "65524/tcp open  http    Apache httpd 2.4.43",
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
