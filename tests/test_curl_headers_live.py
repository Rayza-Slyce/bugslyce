"""Tests for the narrowly scoped live curl header workflow."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.recon.commands import (
    build_live_curl_header_command,
    validate_live_curl_header_command,
)
from bugslyce.recon.curl_headers import run_curl_header_workflow
from bugslyce.recon.runner import LiveCurlHeaderRunner


def test_live_curl_command_has_exact_header_only_shape(tmp_path: Path) -> None:
    command = build_live_curl_header_command(
        "http://10.10.10.10:8080/login",
        tmp_path,
        timeout_seconds=10,
    )

    assert command.tool == "curl"
    assert command.argv == [
        "curl",
        "-I",
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--output",
        str(tmp_path.resolve() / "curl-headers-10.10.10.10-8080.txt"),
        "http://10.10.10.10:8080/login",
    ]
    assert command.ready_for_execution is True
    assert command.placeholders == []
    assert validate_live_curl_header_command(command, tmp_path).valid is True


def test_live_runner_uses_list_argv_and_bounded_process_timeout(tmp_path: Path, monkeypatch) -> None:
    command = build_live_curl_header_command("http://10.10.10.10/", tmp_path, 10)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("HTTP/1.1 200 OK\nServer: test\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveCurlHeaderRunner(tmp_path).run(command)

    assert result.executed is True
    assert result.simulated is False
    assert result.exit_code == 0
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == 10
    assert "shell" not in kwargs


def test_live_runner_refuses_non_curl_tool(tmp_path: Path, monkeypatch) -> None:
    command = replace(
        build_live_curl_header_command("http://10.10.10.10/", tmp_path),
        tool="nmap",
        argv=["nmap", "-p-", "10.10.10.10"],
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveCurlHeaderRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error is not None
    assert "restricted to curl" in result.error
    assert called is False


def test_live_runner_refuses_non_header_curl_shape(tmp_path: Path, monkeypatch) -> None:
    command = replace(
        build_live_curl_header_command("http://10.10.10.10/", tmp_path),
        argv=["curl", "http://10.10.10.10/", "--output", str(tmp_path / "body.txt")],
        output_file=str(tmp_path / "body.txt"),
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveCurlHeaderRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.error is not None
    assert "header-only argv shape" in result.error
    assert called is False


def test_live_runner_handles_process_timeout(tmp_path: Path, monkeypatch) -> None:
    command = build_live_curl_header_command("http://10.10.10.10/", tmp_path, 5)

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveCurlHeaderRunner(tmp_path).run(command)

    assert result.executed is False
    assert result.exit_code is None
    assert result.error == "Curl header request exceeded 5 seconds."


def test_curl_header_workflow_writes_manifest_and_recon_pack_with_mock_runner(tmp_path: Path) -> None:
    scope = tmp_path / "authorised-scope.md"
    scope.write_text("# Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    result = run_curl_header_workflow(
        "http://10.10.10.10/",
        scope,
        output,
        runner=_MockLiveRunner(),
    )
    manifest = json.loads((output / "recon_manifest.json").read_text(encoding="utf-8"))

    assert result.execution_count == 1
    assert result.scanners_executed is False
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert manifest["created_by"] == "bugslyce-curl-headers"
    assert manifest["profile"] == "curl-headers-only"
    assert manifest["artifacts"][0]["type"] == "http_headers"
    assert manifest["artifacts"][0]["url"] == "http://10.10.10.10/"
    assert manifest["artifacts"][0]["file"] == Path(result.header_output_path).name
    exported = json.loads((output / "project_state.json").read_text(encoding="utf-8"))
    warnings = exported["project_state"]["warnings"]
    assert not any(
        filename in warning
        for warning in warnings
        for filename in ("subdomains.txt", "httpx.jsonl", "urls.txt", "notes.md")
    )


@pytest.mark.parametrize("url", ["ftp://10.10.10.10/", "not-a-url", "http://"])
def test_curl_header_workflow_rejects_non_http_urls(tmp_path: Path, url: str) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("- 10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="http:// or https://"):
        run_curl_header_workflow(url, scope, tmp_path / "output", runner=_MockLiveRunner())


def test_curl_header_workflow_rejects_host_absent_from_scope(tmp_path: Path) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("- 192.0.2.20\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not appear"):
        run_curl_header_workflow(
            "http://10.10.10.10/",
            scope,
            tmp_path / "output",
            runner=_MockLiveRunner(),
        )


def test_live_runner_source_uses_only_narrow_process_api() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "recon" / "runner.py"
    ).read_text(encoding="utf-8")

    assert "subprocess.run(" in source
    assert "shell=True" not in source
    assert "subprocess.Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source


class _MockLiveRunner:
    def run(self, command):
        output = Path(command.output_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            "HTTP/1.1 200 OK\nServer: Sanitised-Test\nContent-Length: 0\n",
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
            ended_at="2026-01-01T00:00:00+00:00",
            duration_seconds=0.0,
            executed=True,
            simulated=False,
            error=None,
        )
