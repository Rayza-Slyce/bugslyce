"""Tests for dynamic follow-up of content-discovery results."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import DiscoveredPath, ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.content_followup import (
    ContentFollowupExecutionIncomplete,
    run_content_followup_workflow,
    select_content_followup_urls,
    write_content_followup_execution_result,
)
from bugslyce.recon.content_followup_commands import (
    MAX_CONTENT_FOLLOWUPS,
    MAX_CONTENT_FOLLOWUPS_PER_ORIGIN,
    build_content_followup_commands,
    content_followup_filename,
    validate_live_content_followup_command,
)
from bugslyce.recon.runner import LiveContentFollowupRunner


def test_content_followup_selects_varied_paths_without_required_literal(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _content_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))

    considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)

    assert considered == 9
    assert "http://10.10.10.10/admin" in selected
    assert "http://10.10.10.10/uploads/" in selected
    assert "http://10.10.10.10/api" in selected
    assert "http://10.10.10.10/old" in selected
    assert "http://10.10.10.10:8080/server-status" in selected
    assert all("hidden" not in url for url in selected)


def test_content_followup_excludes_external_duplicates_robots_index_and_dead(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _content_input(tmp_path)
    state = build_project_state(input_dir)
    state = replace(
        state,
        discovered_paths=[
            *state.discovered_paths,
            DiscoveredPath(
                url="https://example.org/external",
                status_code=200,
                content_length=1,
                redirect_location=None,
                source=str(input_dir / "gobuster-external-root.txt"),
                evidence_ids=["EVID-PATH-X"],
                tags=[],
            ),
        ],
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))

    _considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)

    assert "https://example.org/external" not in selected
    assert "http://10.10.10.10/robots.txt" not in selected
    assert "http://10.10.10.10/index.html" not in selected
    assert "http://10.10.10.10/missing" not in selected
    assert selected.count("http://10.10.10.10/admin") == 1


def test_content_followup_deprioritises_static_assets(tmp_path: Path) -> None:
    input_dir, _scope = _content_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))

    _considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)

    assert selected.index("http://10.10.10.10/admin") < selected.index(
        "http://10.10.10.10/assets/app.js"
    )


def test_content_followup_caps_total_and_per_origin(tmp_path: Path) -> None:
    input_dir, _scope = _content_input(tmp_path)
    state = build_project_state(input_dir)
    records = []
    for port in (8000, 8001, 8002):
        for index in range(15):
            records.append(
                DiscoveredPath(
                    url=f"http://10.10.10.10:{port}/path-{index:02d}",
                    status_code=200,
                    content_length=10,
                    redirect_location=None,
                    source=str(input_dir / f"gobuster-10.10.10.10-{port}-root.txt"),
                    evidence_ids=[f"EVID-{port}-{index}"],
                    tags=[],
                )
            )
    state = replace(state, discovered_paths=records)
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))

    _considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)

    assert len(selected) == MAX_CONTENT_FOLLOWUPS
    counts: dict[str, int] = {}
    for url in selected:
        origin = url.split("/path-", 1)[0]
        counts[origin] = counts.get(origin, 0) + 1
    assert max(counts.values()) == MAX_CONTENT_FOLLOWUPS_PER_ORIGIN


def test_content_followup_skips_previously_followed_url(tmp_path: Path) -> None:
    input_dir, _scope = _content_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "type": "http_headers",
            "file": "curl-headers-content-followup-10.10.10.10-80-admin.txt",
            "url": "http://10.10.10.10/admin",
            "description": "Bounded header request for content-discovery result follow-up",
        }
    )
    state = build_project_state(input_dir)

    _considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)

    assert "http://10.10.10.10/admin" not in selected


def test_content_followup_builds_deterministic_head_command(tmp_path: Path) -> None:
    url = "http://10.10.10.10:8080/server-status"
    command = build_content_followup_commands([url], "10.10.10.10", tmp_path)[0]

    assert command.argv == [
        "curl",
        "-I",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(tmp_path.resolve() / content_followup_filename(url)),
        url,
    ]
    assert validate_live_content_followup_command(
        command,
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:8080/"},
        {url},
    ).valid


def test_content_followup_runner_uses_list_argv_and_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    url = "http://10.10.10.10/admin"
    command = build_content_followup_commands([url], "10.10.10.10", tmp_path)[0]
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("HTTP/1.1 403 Forbidden\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {url},
    ).run(command)

    assert result.executed is True
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert kwargs["timeout"] == 10
    assert "shell" not in kwargs


@pytest.mark.parametrize(
    "change",
    [
        {"tool": "nmap"},
        {"argv": ["curl", "-X", "POST", "http://10.10.10.10/admin"]},
        {"argv": ["curl", "-X", "PUT", "http://10.10.10.10/admin"]},
        {"argv": ["curl", "-X", "DELETE", "http://10.10.10.10/admin"]},
        {"argv": ["curl", "-L", "http://10.10.10.10/admin"]},
        {"argv": ["curl", "--data", "x", "http://10.10.10.10/admin"]},
    ],
)
def test_content_followup_runner_refuses_unapproved_commands(
    tmp_path: Path,
    monkeypatch,
    change: dict[str, object],
) -> None:
    url = "http://10.10.10.10/admin"
    command = replace(
        build_content_followup_commands([url], "10.10.10.10", tmp_path)[0],
        **change,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {url},
    ).run(command)

    assert result.executed is False
    assert called is False


def test_content_followup_runner_refuses_unselected_url_and_outside_output(
    tmp_path: Path,
) -> None:
    selected = "http://10.10.10.10/admin"
    guessed = build_content_followup_commands(
        ["http://10.10.10.10/guessed"],
        "10.10.10.10",
        tmp_path,
    )[0]
    outside = replace(
        build_content_followup_commands([selected], "10.10.10.10", tmp_path)[0],
        output_file=str(tmp_path.parent / "outside.txt"),
    )
    runner = LiveContentFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {selected},
    )

    assert "selected from discovered-path evidence" in (runner.run(guessed).error or "")
    assert "inside" in (runner.run(outside).error or "")


def test_content_followup_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    url = "http://10.10.10.10/admin"
    command = build_content_followup_commands([url], "10.10.10.10", tmp_path)[0]

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {url},
    ).run(command)

    assert result.executed is True
    assert result.error == "Content-result follow-up exceeded 10 seconds."


def test_content_followup_workflow_writes_manifest_report_and_metadata(
    tmp_path: Path,
) -> None:
    input_dir, scope = _content_input(tmp_path)

    result = run_content_followup_workflow(
        input_dir,
        scope,
        runner=_MockContentFollowupRunner(),
    )
    execution_json, execution_markdown = write_content_followup_execution_result(
        result,
        input_dir,
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    exported = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.discovered_paths_considered == 9
    assert result.commands_started == len(result.followup_urls_selected)
    assert result.commands_completed == len(result.followup_urls_selected)
    assert result.commands_timed_out == 0
    assert all(Path(path).is_file() for path in result.artifact_paths)
    assert execution_json.is_file()
    assert execution_markdown.is_file()
    assert (input_dir / "report.md").is_file()
    assert any(
        artifact.get("description")
        == "Bounded header request for content-discovery result follow-up"
        for artifact in manifest["artifacts"]
    )
    assert any(
        path["url"] == "http://10.10.10.10/admin"
        and path["status_code"] == 403
        for path in exported["project_state"]["discovered_paths"]
    )


def test_content_followup_timeout_records_started_request(tmp_path: Path) -> None:
    input_dir, scope = _content_input(tmp_path)

    with pytest.raises(ContentFollowupExecutionIncomplete) as exc_info:
        run_content_followup_workflow(
            input_dir,
            scope,
            runner=_TimeoutContentFollowupRunner(),
        )

    result = exc_info.value.result
    write_content_followup_execution_result(result, input_dir)
    execution = json.loads((input_dir / "recon_execution.json").read_text(encoding="utf-8"))

    assert result.commands_started == 1
    assert result.commands_completed == 0
    assert result.commands_timed_out == 1
    assert result.artifact_paths == []
    assert execution["commands_timed_out"] == 1
    assert (input_dir / "report.md").is_file()


def test_content_followup_refuses_missing_input_scope_and_no_paths(tmp_path: Path) -> None:
    input_dir, _scope = _content_input(tmp_path)
    scope = tmp_path / "other-scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Input directory does not exist"):
        run_content_followup_workflow(
            tmp_path / "missing",
            scope,
            runner=_MockContentFollowupRunner(),
        )
    with pytest.raises(ValueError, match="not explicitly listed"):
        run_content_followup_workflow(
            input_dir,
            scope,
            runner=_MockContentFollowupRunner(),
        )

    empty = tmp_path / "empty" / "private_recon" / "lab"
    empty.mkdir(parents=True)
    (empty / "scope.md").write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (empty / "recon_manifest.json").write_text(
        json.dumps({"schema_version": "1.0", "target": "10.10.10.10", "artifacts": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="No discovered_path records"):
        run_content_followup_workflow(
            empty,
            empty / "scope.md",
            runner=_MockContentFollowupRunner(),
        )


class _MockContentFollowupRunner:
    def run(self, command):
        status = "403 Forbidden" if command.argv[-1].endswith("/admin") else "200 OK"
        Path(command.output_file).write_text(
            f"HTTP/1.1 {status}\nContent-Type: text/html\nContent-Length: 12\n",
            encoding="utf-8",
        )
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-06-12T00:00:00+00:00",
            ended_at="2026-06-12T00:00:01+00:00",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=None,
        )


class _TimeoutContentFollowupRunner:
    def run(self, command):
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=None,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-06-12T00:00:00+00:00",
            ended_at="2026-06-12T00:00:10+00:00",
            duration_seconds=10.0,
            executed=True,
            simulated=False,
            error="Content-result follow-up exceeded 10 seconds.",
        )


def _content_input(tmp_path: Path) -> tuple[Path, Path]:
    input_dir = tmp_path / "private_recon" / "lab"
    input_dir.mkdir(parents=True)
    scope = input_dir / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (input_dir / "nmap-services-all.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT      STATE SERVICE VERSION",
                "80/tcp    open  http    nginx",
                "8080/tcp  open  http    Apache",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    root_lines = [
        "admin (Status: 403) [Size: 10]",
        "uploads (Status: 301) [Size: 10] [--> http://10.10.10.10/uploads/]",
        "api (Status: 200) [Size: 20]",
        "old (Status: 200) [Size: 30]",
        "assets/app.js (Status: 200) [Size: 40]",
        "robots.txt (Status: 200) [Size: 50]",
        "index.html (Status: 200) [Size: 60]",
        "missing (Status: 404) [Size: 0]",
        "admin (Status: 403) [Size: 10]",
    ]
    (input_dir / "gobuster-10.10.10.10-80-root.txt").write_text(
        "\n".join(root_lines) + "\n",
        encoding="utf-8",
    )
    (input_dir / "gobuster-10.10.10.10-8080-root.txt").write_text(
        "server-status (Status: 403) [Size: 12]\n",
        encoding="utf-8",
    )
    (input_dir / "homepage-80.html").write_text("<title>Home</title>", encoding="utf-8")
    (input_dir / "robots-80.txt").write_text("User-agent: *\n", encoding="utf-8")
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-root-tiny-plus-content-discovery",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-services-all.txt"},
                    {
                        "type": "html",
                        "file": "homepage-80.html",
                        "url": "http://10.10.10.10/",
                    },
                    {
                        "type": "robots",
                        "file": "robots-80.txt",
                        "url": "http://10.10.10.10/robots.txt",
                    },
                    {
                        "type": "gobuster",
                        "file": "gobuster-10.10.10.10-80-root.txt",
                        "base_url": "http://10.10.10.10/",
                    },
                    {
                        "type": "gobuster",
                        "file": "gobuster-10.10.10.10-8080-root.txt",
                        "base_url": "http://10.10.10.10:8080/",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return input_dir, scope
