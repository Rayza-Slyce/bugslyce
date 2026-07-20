"""Tests for bounded HTTP metadata collection from discovered services."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.http_metadata import (
    discover_http_origins,
    run_http_metadata_workflow,
)
from bugslyce.recon.http_metadata_commands import (
    MAX_HTTP_METADATA_SERVICES,
    build_http_metadata_commands,
    validate_live_http_metadata_command,
)
from bugslyce.recon.interpretation_sources import artefact_sources_from_project_state
from bugslyce.recon.robots_policy import (
    represented_robots_status_codes,
    robots_policy_review_eligible,
)
from bugslyce.recon.runner import LiveHTTPMetadataRunner
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.human_triage import build_human_triage_brief
from bugslyce.triage.candidates import generate_candidates


def test_http_metadata_builds_exact_commands_for_default_and_high_ports(
    tmp_path: Path,
) -> None:
    origins = ["http://10.10.10.10/", "http://10.10.10.10:65524/"]

    commands = build_http_metadata_commands(origins, "10.10.10.10", tmp_path)

    assert len(commands) == 6
    assert commands[0].argv == [
        "curl",
        "-I",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(tmp_path.resolve() / "curl-headers-10.10.10.10-80.txt"),
        "http://10.10.10.10/",
    ]
    assert commands[1].argv[-1] == "http://10.10.10.10/robots.txt"
    assert commands[1].argv == [
        "curl",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--write-out",
        "%{http_code}",
        "--output",
        str(tmp_path.resolve() / "robots-10.10.10.10-80.txt"),
        "http://10.10.10.10/robots.txt",
    ]
    assert commands[2].argv[-1] == "http://10.10.10.10/"
    assert commands[3].output_file.endswith("curl-headers-10.10.10.10-65524.txt")
    assert all(
        validate_live_http_metadata_command(
            command,
            tmp_path,
            "10.10.10.10",
            set(origins),
        ).valid
        for command in commands
    )


def test_http_metadata_runner_uses_list_argv_and_bounded_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    origins = {"http://10.10.10.10/"}
    command = build_http_metadata_commands(list(origins), "10.10.10.10", tmp_path)[0]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is True
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == 10
    assert "shell" not in kwargs


def test_http_metadata_runner_retains_status_from_the_single_robots_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    origins = {"http://10.10.10.10/"}
    command = build_http_metadata_commands(
        list(origins),
        "10.10.10.10",
        tmp_path,
    )[1]
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("Resource unavailable", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="404", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert len(calls) == 1
    assert calls[0][0] == command.argv
    assert result.exit_code == 0
    assert result.http_status_code == 404
    assert Path(result.output_file).read_text(encoding="utf-8") == "Resource unavailable"


def test_http_metadata_runner_refuses_non_curl_tool(tmp_path: Path, monkeypatch) -> None:
    origins = {"http://10.10.10.10/"}
    command = replace(
        build_http_metadata_commands(list(origins), "10.10.10.10", tmp_path)[0],
        tool="nmap",
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is False
    assert "restricted to curl" in (result.error or "")
    assert called is False


@pytest.mark.parametrize(
    "unsafe_argv",
    [
        ["curl", "-X", "POST", "http://10.10.10.10/"],
        ["curl", "-X", "PUT", "http://10.10.10.10/"],
        ["curl", "-X", "DELETE", "http://10.10.10.10/"],
        ["curl", "-L", "http://10.10.10.10/"],
        ["curl", "--data", "value", "http://10.10.10.10/"],
        ["curl", "http://10.10.10.10/admin"],
    ],
)
def test_http_metadata_runner_refuses_arbitrary_curl_shapes(
    tmp_path: Path,
    monkeypatch,
    unsafe_argv: list[str],
) -> None:
    origins = {"http://10.10.10.10/"}
    command = replace(
        build_http_metadata_commands(list(origins), "10.10.10.10", tmp_path)[0],
        argv=unsafe_argv,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is False
    assert "approved HTTP metadata argv shape" in (result.error or "")
    assert called is False


def test_http_metadata_runner_refuses_other_target(tmp_path: Path) -> None:
    origins = {"http://10.10.10.10/"}
    command = build_http_metadata_commands(
        ["http://192.0.2.10/"],
        "192.0.2.10",
        tmp_path,
    )[0]

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is False
    assert "discovered target host" in (result.error or "")


def test_http_metadata_runner_rejects_output_outside_directory(tmp_path: Path) -> None:
    origins = {"http://10.10.10.10/"}
    command = replace(
        build_http_metadata_commands(list(origins), "10.10.10.10", tmp_path)[0],
        output_file=str(tmp_path.parent / "curl-headers-10.10.10.10-80.txt"),
    )

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is False
    assert "inside" in (result.error or "")


def test_http_metadata_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    origins = {"http://10.10.10.10/"}
    command = build_http_metadata_commands(list(origins), "10.10.10.10", tmp_path)[0]

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)

    result = LiveHTTPMetadataRunner(tmp_path, "10.10.10.10", origins).run(command)

    assert result.executed is False
    assert result.error == "HTTP metadata request exceeded 10 seconds."


def test_http_metadata_workflow_writes_artifacts_manifest_and_recon_pack(
    tmp_path: Path,
) -> None:
    input_dir, scope = _nmap_service_directory(tmp_path)

    result = run_http_metadata_workflow(
        input_dir,
        scope,
        runner=_MockHTTPMetadataRunner(),
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    exported = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.http_services == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]
    assert result.execution_count == 6
    assert len(result.artifact_paths) == 6
    assert (input_dir / "curl-headers-10.10.10.10-80.txt").exists()
    assert (input_dir / "robots-10.10.10.10-65524.txt").exists()
    assert (input_dir / "homepage-10.10.10.10-65524.html").exists()
    assert (input_dir / "report.md").exists()
    assert (input_dir / "project_state.json").exists()
    assert [artifact["file"] for artifact in manifest["artifacts"][:2]] == [
        "nmap-allports.txt",
        "nmap-services-all.txt",
    ]
    assert len(manifest["artifacts"]) == 8
    assert manifest["profile"] == "lab-tcp-full-plus-services-plus-http-metadata"
    services = {
        item["url"]: item
        for item in exported["project_state"]["http_services"]
    }
    assert services["http://10.10.10.10/"]["status_code"] == 200
    assert services["http://10.10.10.10:65524/"]["status_code"] == 200
    assert any(
        artifact["artifact_type"] == "robots"
        for artifact in exported["project_state"]["http_artifacts"]
    )
    assert any(
        artifact["artifact_type"] == "page_title"
        for artifact in exported["project_state"]["http_artifacts"]
    )


def test_http_metadata_workflow_retains_robots_404_status_end_to_end(
    tmp_path: Path,
) -> None:
    input_dir, scope = _nmap_service_directory(
        tmp_path,
        include_high_port_http=False,
    )
    runner = _StatusHTTPMetadataRunner(
        robots_status=404,
        robots_body="<!doctype html><title>Resource unavailable</title>",
    )

    result = run_http_metadata_workflow(input_dir, scope, runner=runner)
    state = build_project_state(input_dir)
    robots_url = "http://10.10.10.10/robots.txt"

    assert result.execution_count == 3
    assert len(runner.calls) == 3
    assert sum(command.phase == "http-robots" for command in runner.calls) == 1
    assert represented_robots_status_codes(state, robots_url) == (404,)
    assert robots_policy_review_eligible(state, robots_url) is False
    assert all(
        candidate.candidate_type != "robots_artifact"
        for candidate in generate_candidates(state)
    )
    assert all(
        source.url != robots_url
        for source in artefact_sources_from_project_state(state)
    )
    assert assemble_standard_interpretation_from_project_state(
        state
    ).review_lead_count == 0
    brief = build_human_triage_brief(state, generate_candidates(state))
    assert all("robots" not in item.title.lower() for item in brief.start_here)
    assert all("robots" not in card.title.lower() for card in brief.evidence_cards)
    robots_evidence = [
        evidence
        for evidence in state.evidence
        if evidence.evidence_type == "robots"
        and evidence.context.get("url") == robots_url
    ]
    assert len(robots_evidence) == 1
    assert robots_evidence[0].context["status_code"] == 404
    assert (input_dir / "robots-10.10.10.10-80.txt").read_text(
        encoding="utf-8"
    ) == "<!doctype html><title>Resource unavailable</title>"


def test_http_metadata_workflow_preserves_successful_robots_policy(
    tmp_path: Path,
) -> None:
    input_dir, scope = _nmap_service_directory(
        tmp_path,
        include_high_port_http=False,
    )
    runner = _StatusHTTPMetadataRunner(
        robots_status=200,
        robots_body="User-agent: *\nDisallow: /hidden-area/\n",
    )

    run_http_metadata_workflow(input_dir, scope, runner=runner)
    state = build_project_state(input_dir)
    robots_url = "http://10.10.10.10/robots.txt"
    candidates = generate_candidates(state)
    robots_candidate = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "robots_artifact"
    )
    interpretation = assemble_standard_interpretation_from_project_state(state)

    assert sum(command.phase == "http-robots" for command in runner.calls) == 1
    assert represented_robots_status_codes(state, robots_url) == (200,)
    assert robots_policy_review_eligible(state, robots_url) is True
    assert robots_candidate.priority == "low"
    assert robots_candidate.affected_endpoints == [robots_url]
    assert robots_candidate.evidence_ids
    assert any(
        artefact.artifact_type == "disallow_rule"
        and artefact.value == "/hidden-area/"
        for artefact in state.http_artifacts
    )
    assert interpretation.review_lead_count == 1
    assert interpretation.review_leads[0].category == "robots"
    report = (input_dir / "report.md").read_text(encoding="utf-8")
    assert "Robots artefact review for 10.10.10.10" in report


def test_http_metadata_workflow_refuses_missing_input(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        run_http_metadata_workflow(
            tmp_path / "missing",
            _scope(tmp_path),
            runner=_MockHTTPMetadataRunner(),
        )


def test_http_metadata_workflow_refuses_no_discovered_http_services(
    tmp_path: Path,
) -> None:
    input_dir, scope = _nmap_service_directory(tmp_path, include_http=False)

    with pytest.raises(ValueError, match="No open HTTP services"):
        run_http_metadata_workflow(
            input_dir,
            scope,
            runner=_MockHTTPMetadataRunner(),
        )


def test_http_metadata_workflow_refuses_target_not_in_scope(tmp_path: Path) -> None:
    input_dir, _scope_path = _nmap_service_directory(tmp_path)
    scope = tmp_path / "other-scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_http_metadata_workflow(
            input_dir,
            scope,
            runner=_MockHTTPMetadataRunner(),
        )


def test_http_metadata_service_cap_is_deterministic(tmp_path: Path) -> None:
    input_dir = tmp_path / "many"
    input_dir.mkdir()
    lines = [
        "Nmap scan report for 10.10.10.10",
        "PORT      STATE SERVICE VERSION",
        *[
            f"{8000 + index}/tcp open  http    TestServer {index}"
            for index in range(MAX_HTTP_METADATA_SERVICES + 2)
        ],
    ]
    (input_dir / "nmap-services-all.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    state = build_project_state(input_dir)

    origins = discover_http_origins(state, "10.10.10.10")

    assert len(origins) == MAX_HTTP_METADATA_SERVICES
    assert origins[0] == "http://10.10.10.10:8000/"
    assert origins[-1] == "http://10.10.10.10:8009/"


def _scope(tmp_path: Path) -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    return scope


def _nmap_service_directory(
    tmp_path: Path,
    include_http: bool = True,
    include_high_port_http: bool = True,
) -> tuple[Path, Path]:
    input_dir = tmp_path / "output"
    input_dir.mkdir()
    scope = _scope(tmp_path)
    (input_dir / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT      STATE SERVICE\n"
        "80/tcp    open  unknown\n"
        "6498/tcp  open  unknown\n"
        "65524/tcp open  unknown\n",
        encoding="utf-8",
    )
    service_lines = [
        "Nmap scan report for 10.10.10.10",
        "PORT      STATE SERVICE VERSION",
        "6498/tcp  open  ssh     OpenSSH 7.6p1",
    ]
    if include_http:
        service_lines.append("80/tcp    open  http    nginx 1.16.1")
        if include_high_port_http:
            service_lines.append("65524/tcp open  http    Apache httpd 2.4.43")
    (input_dir / "nmap-services-all.txt").write_text(
        "\n".join(service_lines) + "\n",
        encoding="utf-8",
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "created_by": "bugslyce-nmap-discover",
                "profile": "lab-tcp-full-plus-services",
                "artifacts": [
                    {
                        "type": "nmap",
                        "file": "nmap-allports.txt",
                        "description": "Discovery output",
                    },
                    {
                        "type": "nmap",
                        "file": "nmap-services-all.txt",
                        "description": "Service output",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return input_dir, scope


class _MockHTTPMetadataRunner:
    def run(self, command):
        output = Path(command.output_file)
        if output.name.startswith("curl-headers-"):
            output.write_text(
                "HTTP/1.1 200 OK\nServer: Sanitised-Test\nContent-Type: text/html\n\n",
                encoding="utf-8",
            )
        elif output.name.startswith("robots-"):
            output.write_text("User-agent: *\nDisallow: /private/\n", encoding="utf-8")
        else:
            output.write_text(
                "<html><title>Sanitised Service</title><a href=\"/login\">Login</a></html>",
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


class _StatusHTTPMetadataRunner:
    def __init__(self, *, robots_status: int, robots_body: str) -> None:
        self.robots_status = robots_status
        self.robots_body = robots_body
        self.calls = []

    def run(self, command):
        self.calls.append(command)
        output = Path(command.output_file)
        if command.phase == "http-headers":
            output.write_text(
                "HTTP/1.1 200 OK\nContent-Type: text/html\n\n",
                encoding="utf-8",
            )
            status = 200
        elif command.phase == "http-robots":
            output.write_text(self.robots_body, encoding="utf-8")
            status = self.robots_status
        else:
            output.write_text(
                "<html><title>Synthetic service</title></html>",
                encoding="utf-8",
            )
            status = 200
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
            http_status_code=status,
        )
