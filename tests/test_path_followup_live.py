"""Tests for bounded follow-up checks of evidence-derived paths."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.path_followup import (
    PathFollowupNoWork,
    discover_same_origin_followup_urls,
    render_path_followup_no_work,
    run_path_followup_workflow,
    write_path_followup_execution_result,
)
from bugslyce.recon.path_followup_commands import (
    MAX_PATH_FOLLOWUPS,
    build_path_followup_commands,
    validate_live_path_followup_command,
)
from bugslyce.recon.runner import LivePathFollowupRunner


def test_path_followup_discovers_only_evidence_derived_same_origin_paths(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _http_metadata_directory(tmp_path)
    state = build_project_state(input_dir)

    urls = discover_same_origin_followup_urls(state, "10.10.10.10")

    assert urls == [
        "http://10.10.10.10:65524/icons/openlogo-75.png",
        "http://10.10.10.10:65524/manual",
        "http://10.10.10.10:65524/private/",
    ]
    assert all("example.org" not in url for url in urls)
    assert all("#" not in url for url in urls)
    assert all(not url.endswith("/robots.txt") for url in urls)


def test_path_followup_builds_fixed_head_commands(tmp_path: Path) -> None:
    urls = [
        "http://10.10.10.10:65524/manual",
        "http://10.10.10.10:65524/icons/openlogo-75.png",
    ]

    commands = build_path_followup_commands(urls, "10.10.10.10", tmp_path)
    origins = {"http://10.10.10.10:65524/"}

    assert commands[0].argv == [
        "curl",
        "-I",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(tmp_path.resolve() / "curl-headers-followup-10.10.10.10-65524-manual.txt"),
        "http://10.10.10.10:65524/manual",
    ]
    assert commands[1].output_file.endswith(
        "curl-headers-followup-10.10.10.10-65524-icons-openlogo-75.png.txt"
    )
    assert all(
        validate_live_path_followup_command(
            command,
            tmp_path,
            "10.10.10.10",
            origins,
            set(urls),
        ).valid
        for command in commands
    )


def test_path_followup_runner_uses_list_argv_and_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    url = "http://10.10.10.10:65524/manual"
    command = build_path_followup_commands([url], "10.10.10.10", tmp_path)[0]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("HTTP/1.1 404 Not Found\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LivePathFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:65524/"},
        {url},
    ).run(command)

    assert result.executed is True
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == 10
    assert "shell" not in kwargs


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"tool": "nmap"}, "restricted to curl"),
        ({"argv": ["curl", "-X", "POST", "http://10.10.10.10:65524/manual"]}, "approved"),
        ({"argv": ["curl", "-X", "PUT", "http://10.10.10.10:65524/manual"]}, "approved"),
        ({"argv": ["curl", "-X", "DELETE", "http://10.10.10.10:65524/manual"]}, "approved"),
        ({"argv": ["curl", "-L", "http://10.10.10.10:65524/manual"]}, "approved"),
        ({"argv": ["curl", "--data", "x", "http://10.10.10.10:65524/manual"]}, "approved"),
    ],
)
def test_path_followup_runner_refuses_unapproved_commands(
    tmp_path: Path,
    monkeypatch,
    change: dict[str, object],
    expected: str,
) -> None:
    url = "http://10.10.10.10:65524/manual"
    command = replace(
        build_path_followup_commands([url], "10.10.10.10", tmp_path)[0],
        **change,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LivePathFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:65524/"},
        {url},
    ).run(command)

    assert result.executed is False
    assert expected in (result.error or "")
    assert called is False


def test_path_followup_runner_refuses_other_target_origin_and_unknown_url(
    tmp_path: Path,
) -> None:
    approved = "http://10.10.10.10:65524/manual"
    runner = LivePathFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:65524/"},
        {approved},
    )
    other_target = build_path_followup_commands(
        ["http://192.0.2.10/manual"],
        "192.0.2.10",
        tmp_path,
    )[0]
    unknown_path = build_path_followup_commands(
        ["http://10.10.10.10:65524/guessed"],
        "10.10.10.10",
        tmp_path,
    )[0]

    assert "target host" in (runner.run(other_target).error or "")
    assert "structured BugSlyce evidence" in (runner.run(unknown_path).error or "")


def test_path_followup_runner_rejects_output_outside_directory(tmp_path: Path) -> None:
    url = "http://10.10.10.10:65524/manual"
    command = replace(
        build_path_followup_commands([url], "10.10.10.10", tmp_path)[0],
        output_file=str(tmp_path.parent / "outside.txt"),
    )
    result = LivePathFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:65524/"},
        {url},
    ).run(command)

    assert result.executed is False
    assert "inside" in (result.error or "")


def test_path_followup_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    url = "http://10.10.10.10:65524/manual"
    command = build_path_followup_commands([url], "10.10.10.10", tmp_path)[0]

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LivePathFollowupRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:65524/"},
        {url},
    ).run(command)

    assert result.executed is False
    assert result.error == "Discovered-path follow-up exceeded 10 seconds."


def test_path_followup_workflow_writes_artifacts_manifest_and_recon_pack(
    tmp_path: Path,
) -> None:
    input_dir, scope = _http_metadata_directory(tmp_path)

    result = run_path_followup_workflow(input_dir, scope, runner=_MockPathFollowupRunner())
    execution_json, execution_markdown = write_path_followup_execution_result(
        result,
        input_dir,
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    exported = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.followup_urls == [
        "http://10.10.10.10:65524/icons/openlogo-75.png",
        "http://10.10.10.10:65524/manual",
        "http://10.10.10.10:65524/private/",
    ]
    assert result.execution_count == 3
    assert all(Path(path).exists() for path in result.artifact_paths)
    assert (input_dir / "report.md").exists()
    assert (input_dir / "project_state.json").exists()
    assert execution_json == input_dir / "recon_execution.json"
    assert execution_markdown == input_dir / "recon_execution.md"
    assert execution_json.exists()
    assert execution_markdown.exists()
    files = [artifact["file"] for artifact in manifest["artifacts"]]
    assert "nmap-services-all.txt" in files
    assert "homepage-10.10.10.10-65524.html" in files
    assert "curl-headers-followup-10.10.10.10-65524-manual.txt" in files
    assert manifest["profile"].endswith("-plus-path-followup")
    assert any(
        path["url"] == "http://10.10.10.10:65524/manual"
        and path["status_code"] == 404
        for path in exported["project_state"]["discovered_paths"]
    )


def test_path_followup_refuses_missing_input_metadata_and_scope(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    with pytest.raises(ValueError, match="Input directory does not exist"):
        run_path_followup_workflow(tmp_path / "missing", scope, runner=_MockPathFollowupRunner())

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="recon_manifest.json"):
        run_path_followup_workflow(empty, scope, runner=_MockPathFollowupRunner())

    input_dir, _ = _http_metadata_directory(tmp_path / "other")
    out_scope = tmp_path / "out-scope.md"
    out_scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not explicitly listed"):
        run_path_followup_workflow(
            input_dir,
            out_scope,
            runner=_MockPathFollowupRunner(),
        )


def test_path_followup_no_eligible_paths_is_clean_noop(tmp_path: Path) -> None:
    input_dir, scope = _http_metadata_directory(tmp_path, include_paths=False)

    class NoRunner:
        def run(self, _command):
            raise AssertionError("runner must not be called for no-op path-followup")

    with pytest.raises(PathFollowupNoWork) as exc_info:
        run_path_followup_workflow(input_dir, scope, runner=NoRunner())

    rendered = render_path_followup_no_work(exc_info.value)
    assert "No eligible same-origin paths were found" in rendered
    assert "No path-followup request was executed." in rendered


def test_path_followup_cap_is_deterministic(tmp_path: Path) -> None:
    input_dir, _scope_path = _http_metadata_directory(tmp_path, include_paths=False)
    links = "".join(f'<a href="/item-{index:02d}">item</a>' for index in range(25))
    (input_dir / "homepage-10.10.10.10-65524.html").write_text(
        f"<html><body>{links}</body></html>",
        encoding="utf-8",
    )
    state = build_project_state(input_dir)

    urls = discover_same_origin_followup_urls(state, "10.10.10.10")

    assert len(urls) == MAX_PATH_FOLLOWUPS
    assert urls == sorted(urls)


class _MockPathFollowupRunner:
    def run(self, command):
        status = "404 Not Found" if command.argv[-1].endswith("/manual") else "200 OK"
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
            started_at="2026-06-10T00:00:00+00:00",
            ended_at="2026-06-10T00:00:00+00:00",
            duration_seconds=0.0,
            executed=True,
            simulated=False,
            error=None,
        )


def _http_metadata_directory(
    tmp_path: Path,
    include_paths: bool = True,
) -> tuple[Path, Path]:
    input_dir = tmp_path / "recon"
    input_dir.mkdir(parents=True)
    scope = _scope(tmp_path)
    (input_dir / "scope.md").write_text(scope.read_text(encoding="utf-8"), encoding="utf-8")
    (input_dir / "nmap-services-all.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT      STATE SERVICE VERSION",
                "65524/tcp open  http    Apache httpd 2.4.43",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    html = "<html><head><title>Lab</title></head><body>"
    if include_paths:
        html += (
            '<a href="/manual">manual</a>'
            '<a href="/manual#section">duplicate</a>'
            '<img src="/icons/openlogo-75.png">'
            '<a href="https://example.org/external">external</a>'
            '<a href="#about">anchor</a>'
            '<a href="/">root</a>'
            '<a href="/robots.txt">robots</a>'
            '<a href="/../escape">escape</a>'
        )
    html += "</body></html>"
    (input_dir / "homepage-10.10.10.10-65524.html").write_text(html, encoding="utf-8")
    robots = "User-agent: *\n"
    if include_paths:
        robots += "Disallow: /private/\nAllow: /\n"
    (input_dir / "robots-10.10.10.10-65524.txt").write_text(robots, encoding="utf-8")
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "created_by": "bugslyce-http-metadata",
                "profile": "lab-tcp-full-plus-services-plus-http-metadata",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-services-all.txt"},
                    {
                        "type": "html",
                        "file": "homepage-10.10.10.10-65524.html",
                        "url": "http://10.10.10.10:65524/",
                    },
                    {
                        "type": "robots",
                        "file": "robots-10.10.10.10-65524.txt",
                        "url": "http://10.10.10.10:65524/robots.txt",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return input_dir, scope


def _scope(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = tmp_path / "scope-source.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    return scope
