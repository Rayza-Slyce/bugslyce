"""Tests for selective body fetch from prior followed-path evidence."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import DiscoveredPath, ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.body_fetch import (
    run_body_fetch_workflow,
    select_body_fetch_urls,
    write_body_fetch_execution_result,
)
from bugslyce.recon.body_fetch_commands import (
    MAX_BODY_FETCHES,
    MAX_BODY_FETCHES_PER_ORIGIN,
    body_fetch_filename,
    build_body_fetch_commands,
    validate_live_body_fetch_command,
)
from bugslyce.recon.runner import LiveBodyFetchRunner


def test_body_fetch_selects_varied_generic_application_paths(tmp_path: Path) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = _manifest(input_dir)

    considered, selected = select_body_fetch_urls(state, "10.10.10.10", manifest)

    assert considered == 13
    assert "http://10.10.10.10/admin/" in selected
    assert "http://10.10.10.10/uploads/" in selected
    assert "http://10.10.10.10/api/" in selected
    assert "http://10.10.10.10/portal/" in selected
    assert "http://10.10.10.10:8080/old-login/" in selected
    assert all("hidden" not in url for url in selected)


def test_body_fetch_excludes_external_duplicates_known_pages_errors_and_static(
    tmp_path: Path,
) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = _manifest(input_dir)
    manifest["artifacts"].extend(
        [
            _followup_artifact("https://example.org/external", "external"),
            _followup_artifact("http://10.10.10.10/admin/", "admin-duplicate"),
        ]
    )
    state = replace(
        state,
        discovered_paths=[
            *state.discovered_paths,
            DiscoveredPath(
                url="https://example.org/external",
                status_code=200,
                content_length=10,
                redirect_location=None,
                source="curl-headers-content-followup-external.txt",
                evidence_ids=["EVID-EXTERNAL"],
                tags=[],
            ),
        ],
    )

    _considered, selected = select_body_fetch_urls(state, "10.10.10.10", manifest)

    assert "https://example.org/external" not in selected
    assert "http://10.10.10.10/" not in selected
    assert "http://10.10.10.10/robots.txt" not in selected
    assert "http://10.10.10.10/index.html" not in selected
    assert "http://10.10.10.10/forbidden" not in selected
    assert "http://10.10.10.10/missing" not in selected
    assert "http://10.10.10.10/assets/app.js" not in selected
    assert selected.count("http://10.10.10.10/admin/") == 1


def test_body_fetch_skips_already_fetched_url(tmp_path: Path) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = _manifest(input_dir)
    manifest["artifacts"].append(
        {
            "type": "html",
            "file": "body-fetch-10.10.10.10-80-admin.html",
            "url": "http://10.10.10.10/admin/",
            "description": (
                "Bounded body request for selected high-signal "
                "content-discovery follow-up path"
            ),
        }
    )

    _considered, selected = select_body_fetch_urls(state, "10.10.10.10", manifest)

    assert "http://10.10.10.10/admin/" not in selected


def test_body_fetch_skips_url_with_existing_html_artifact(tmp_path: Path) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    state = build_project_state(input_dir)
    manifest = _manifest(input_dir)
    manifest["artifacts"].append(
        {
            "type": "html",
            "file": "saved-admin.html",
            "url": "http://10.10.10.10/admin/",
            "description": "Previously saved HTML evidence",
        }
    )

    _considered, selected = select_body_fetch_urls(state, "10.10.10.10", manifest)

    assert "http://10.10.10.10/admin/" not in selected


def test_body_fetch_caps_total_and_per_origin(tmp_path: Path) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    state = build_project_state(input_dir)
    records = []
    artifacts = []
    for port in (8000, 8001, 8002):
        for index in range(12):
            url = f"http://10.10.10.10:{port}/app-{index:02d}/"
            records.append(
                DiscoveredPath(
                    url=url,
                    status_code=200,
                    content_length=10,
                    redirect_location=None,
                    source=f"curl-headers-content-followup-{port}-{index}.txt",
                    evidence_ids=[f"EVID-{port}-{index}"],
                    tags=[],
                )
            )
            artifacts.append(_followup_artifact(url, f"{port}-{index}"))
    state = replace(state, discovered_paths=records)
    manifest = {
        "target": "10.10.10.10",
        "artifacts": artifacts,
    }

    considered, selected = select_body_fetch_urls(state, "10.10.10.10", manifest)

    assert considered == 36
    assert len(selected) == MAX_BODY_FETCHES
    counts: dict[str, int] = {}
    for url in selected:
        origin = url.split("/app-", 1)[0]
        counts[origin] = counts.get(origin, 0) + 1
    assert max(counts.values()) == MAX_BODY_FETCHES_PER_ORIGIN


def test_body_fetch_builds_deterministic_get_command(tmp_path: Path) -> None:
    url = "http://10.10.10.10:8080/old-login/"
    command = build_body_fetch_commands([url], "10.10.10.10", tmp_path)[0]

    assert command.argv == [
        "curl",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(tmp_path.resolve() / body_fetch_filename(url)),
        url,
    ]
    assert command.argv[1] != "-I"
    assert validate_live_body_fetch_command(
        command,
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10:8080/"},
        {url},
    ).valid


def test_body_fetch_runner_uses_list_argv_and_timeout(tmp_path: Path, monkeypatch) -> None:
    url = "http://10.10.10.10/admin/"
    command = build_body_fetch_commands([url], "10.10.10.10", tmp_path)[0]
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("<title>Admin</title>", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveBodyFetchRunner(
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
        {"argv": ["curl", "-I", "http://10.10.10.10/admin/"]},
        {"argv": ["curl", "-X", "POST", "http://10.10.10.10/admin/"]},
        {"argv": ["curl", "-X", "PUT", "http://10.10.10.10/admin/"]},
        {"argv": ["curl", "-X", "DELETE", "http://10.10.10.10/admin/"]},
        {"argv": ["curl", "-L", "http://10.10.10.10/admin/"]},
        {"argv": ["curl", "--data", "x", "http://10.10.10.10/admin/"]},
    ],
)
def test_body_fetch_runner_refuses_unapproved_commands(
    tmp_path: Path,
    monkeypatch,
    change: dict[str, object],
) -> None:
    url = "http://10.10.10.10/admin/"
    command = replace(
        build_body_fetch_commands([url], "10.10.10.10", tmp_path)[0],
        **change,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveBodyFetchRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {url},
    ).run(command)

    assert result.executed is False
    assert called is False


def test_body_fetch_runner_refuses_unselected_url_and_outside_output(tmp_path: Path) -> None:
    selected = "http://10.10.10.10/admin/"
    guessed = build_body_fetch_commands(
        ["http://10.10.10.10/guessed/"],
        "10.10.10.10",
        tmp_path,
    )[0]
    outside = replace(
        build_body_fetch_commands([selected], "10.10.10.10", tmp_path)[0],
        output_file=str(tmp_path.parent / "outside.html"),
    )
    runner = LiveBodyFetchRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {selected},
    )

    assert "selected from prior followed-path evidence" in (runner.run(guessed).error or "")
    assert "inside" in (runner.run(outside).error or "")


def test_body_fetch_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    url = "http://10.10.10.10/admin/"
    command = build_body_fetch_commands([url], "10.10.10.10", tmp_path)[0]

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveBodyFetchRunner(
        tmp_path,
        "10.10.10.10",
        {"http://10.10.10.10/"},
        {url},
    ).run(command)

    assert result.executed is True
    assert result.error == "Selective body fetch exceeded 10 seconds."


def test_body_fetch_workflow_writes_html_manifest_report_and_metadata(tmp_path: Path) -> None:
    input_dir, scope = _body_fetch_input(tmp_path)

    result = run_body_fetch_workflow(input_dir, scope, runner=_MockBodyFetchRunner())
    execution_json, execution_markdown = write_body_fetch_execution_result(result, input_dir)
    manifest = _manifest(input_dir)
    exported = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.candidate_urls_considered == 13
    assert result.commands_started == len(result.body_urls_selected)
    assert result.commands_completed == len(result.body_urls_selected)
    assert result.commands_timed_out == 0
    assert execution_json.is_file()
    assert execution_markdown.is_file()
    assert execution_markdown.read_text(encoding="utf-8").startswith(
        "# BugSlyce Selective Body Fetch"
    )
    assert json.loads(execution_json.read_text(encoding="utf-8"))["mode"] == "body-fetch"
    assert (input_dir / "report.md").is_file()
    assert all(Path(path).is_file() for path in result.artifact_paths)
    assert any(
        artifact.get("type") == "html"
        and "selected high-signal" in artifact.get("description", "")
        for artifact in manifest["artifacts"]
    )
    assert any(
        artifact["artifact_type"] == "page_title"
        and artifact["value"] == "Followed Application"
        for artifact in exported["project_state"]["http_artifacts"]
    )


def test_body_fetch_refuses_missing_input_scope_and_no_eligible_evidence(tmp_path: Path) -> None:
    input_dir, _scope = _body_fetch_input(tmp_path)
    other_scope = tmp_path / "scope.md"
    other_scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Input directory does not exist"):
        run_body_fetch_workflow(
            tmp_path / "missing",
            other_scope,
            runner=_MockBodyFetchRunner(),
        )
    with pytest.raises(ValueError, match="not explicitly listed"):
        run_body_fetch_workflow(input_dir, other_scope, runner=_MockBodyFetchRunner())

    empty = tmp_path / "empty" / "private_recon" / "lab"
    empty.mkdir(parents=True)
    scope = empty / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (empty / "recon_manifest.json").write_text(
        json.dumps({"schema_version": "1.0", "target": "10.10.10.10", "artifacts": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="No prior content-followup"):
        run_body_fetch_workflow(empty, scope, runner=_MockBodyFetchRunner())


class _MockBodyFetchRunner:
    def run(self, command):
        Path(command.output_file).write_text(
            "\n".join(
                [
                    "<html><head><title>Followed Application</title></head>",
                    "<body><!-- saved body metadata -->",
                    '<a href="/dashboard">Dashboard</a>',
                    '<input type="hidden" name="token" value="TOKEN_LIKE_PLACEHOLDER">',
                    "</body></html>",
                ]
            ),
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


def _body_fetch_input(tmp_path: Path) -> tuple[Path, Path]:
    input_dir = tmp_path / "private_recon" / "lab"
    input_dir.mkdir(parents=True)
    scope = input_dir / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (input_dir / "homepage-80.html").write_text("<title>Home</title>", encoding="utf-8")
    (input_dir / "robots-80.txt").write_text("User-agent: *\n", encoding="utf-8")

    cases = [
        ("http://10.10.10.10/admin/", 200, "admin"),
        ("http://10.10.10.10/uploads/", 200, "uploads"),
        ("http://10.10.10.10/api/", 200, "api"),
        ("http://10.10.10.10/portal/", 200, "portal"),
        ("http://10.10.10.10:8080/old-login/", 200, "old-login"),
        ("http://10.10.10.10/docs.html", 200, "docs-html"),
        ("http://10.10.10.10/forbidden", 403, "forbidden"),
        ("http://10.10.10.10/missing", 404, "missing"),
        ("http://10.10.10.10/assets/app.js", 200, "app-js"),
        ("http://10.10.10.10/robots.txt", 200, "robots"),
        ("http://10.10.10.10/index.html", 200, "index"),
        ("http://10.10.10.10/", 200, "root"),
        ("http://10.10.10.10/archive.zip", 200, "archive"),
    ]
    artifacts = [
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
    ]
    for url, status, token in cases:
        filename = f"curl-headers-content-followup-{token}.txt"
        reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}[status]
        (input_dir / filename).write_text(
            f"HTTP/1.1 {status} {reason}\nContent-Type: text/html\nContent-Length: 12\n",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "http_headers",
                "file": filename,
                "url": url,
                "description": "Bounded header request for content-discovery result follow-up",
            }
        )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-root-tiny-plus-content-followup",
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )
    return input_dir, scope


def _manifest(input_dir: Path) -> dict[str, object]:
    return json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))


def _followup_artifact(url: str, token: str) -> dict[str, str]:
    return {
        "type": "http_headers",
        "file": f"curl-headers-content-followup-{token}.txt",
        "url": url,
        "description": "Bounded header request for content-discovery result follow-up",
    }
