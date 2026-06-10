"""Tests for controlled live root content discovery from approved plans."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.models import ReconCommandResult
from bugslyce.recon.content_commands import (
    CONTENT_DISCOVERY_TIMEOUT_SECONDS,
    build_live_content_discovery_command,
)
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_PROFILE,
    build_content_discovery_plan,
    write_content_discovery_plan,
)
from bugslyce.recon.content_run import (
    load_content_discovery_plan,
    run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.runner import LiveContentDiscoveryRunner


def test_content_run_executes_approved_plan_and_rebuilds_recon_pack(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda _path: True,
    )
    execution_json, execution_markdown = write_content_discovery_execution_result(
        result,
        output_dir,
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    project = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))

    assert result.execution_count == 2
    assert result.origins == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]
    assert all(Path(path).is_file() for path in result.artifact_paths)
    assert (input_dir / "gobuster-10.10.10.10-80-root.txt").is_file()
    assert (input_dir / "gobuster-10.10.10.10-65524-root.txt").is_file()
    assert (input_dir / "report.md").is_file()
    assert (input_dir / "project_state.json").is_file()
    assert execution_json.is_file()
    assert execution_markdown.is_file()
    assert result.no_recursion is True
    assert result.no_extensions is True
    assert result.no_arbitrary_urls is True
    assert result.no_exploitation is True
    gobuster_artifacts = [
        artifact for artifact in manifest["artifacts"] if artifact["type"] == "gobuster"
    ]
    assert len(gobuster_artifacts) == 2
    assert all(artifact["base_url"] in result.origins for artifact in gobuster_artifacts)
    assert any(
        path["url"] == "http://10.10.10.10/admin"
        for path in project["project_state"]["discovered_paths"]
    )


def test_content_run_refuses_missing_malformed_and_unsupported_plan(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_content_discovery_plan(tmp_path / "content_discovery_plan.json")

    malformed_dir = tmp_path / "bugslyce-output" / "malformed"
    malformed_dir.mkdir(parents=True)
    malformed = malformed_dir / "content_discovery_plan.json"
    malformed.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not parse"):
        load_content_discovery_plan(malformed)

    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path / "unsupported")
    payload = _payload(plan_path)
    payload["profile"] = "recursive-full"
    _write_payload(plan_path, payload)
    with pytest.raises(ValueError, match="supports only profile"):
        load_content_discovery_plan(plan_path)


def test_content_run_refuses_target_not_in_scope(tmp_path: Path) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    scope = tmp_path / "other-scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_MockContentRunner(),
            wordlist_check=lambda _path: True,
        )


def test_content_run_refuses_unsafe_original_recon_directory(tmp_path: Path) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    payload = _payload(plan_path)
    payload["input_dir"] = str(Path.home())
    _write_payload(plan_path, payload)

    with pytest.raises(ValueError, match="not an approved local recon path"):
        load_content_discovery_plan(plan_path)


def test_content_run_refuses_missing_wordlist_without_running(tmp_path: Path) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path)
    runner = _NeverRunContentRunner()

    with pytest.raises(ValueError, match="wordlist does not exist"):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda _path: False,
        )

    assert runner.called is False


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: _mutate_origin(payload, "http://192.0.2.10/"),
            "not a target root origin",
        ),
        (
            lambda payload: payload["steps"][0]["command_preview"].extend(["-x", "php"]),
            "approved command shape",
        ),
        (
            lambda payload: payload["steps"][0].update({"recursive_discovery": True}),
            "invalid recursive_discovery",
        ),
        (
            lambda payload: payload["steps"][0]["command_preview"].__setitem__(
                5, "/tmp/custom-wordlist.txt"
            ),
            "approved command shape",
        ),
        (
            lambda payload: _escape_output(payload),
            "unsafe artifact filename",
        ),
    ],
)
def test_content_run_refuses_tampered_plan(
    tmp_path: Path,
    mutate,
    message: str,
) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    payload = _payload(plan_path)
    mutate(payload)
    _write_payload(plan_path, payload)

    with pytest.raises(ValueError, match=message):
        load_content_discovery_plan(plan_path)


def test_content_run_refuses_wrong_provenance(tmp_path: Path) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    payload = _payload(plan_path)
    payload["created_by"] = "other-tool"
    _write_payload(plan_path, payload)

    with pytest.raises(ValueError, match="provenance"):
        load_content_discovery_plan(plan_path)


def test_content_run_loader_accepts_legacy_structurally_exact_plan(tmp_path: Path) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    payload = _payload(plan_path)
    payload.pop("schema_version")
    payload.pop("created_by")
    for step in payload["steps"]:
        step.pop("recursive_discovery")
        step.pop("extensions")
        step.pop("ready_for_execution")
    _write_payload(plan_path, payload)

    plan = load_content_discovery_plan(plan_path)

    assert plan.created_by == "bugslyce-content-planner"
    assert all(step.recursive_discovery is False for step in plan.steps)


def test_content_runner_uses_list_argv_and_timeout(tmp_path: Path, monkeypatch) -> None:
    plan_path, _scope, _input_dir, output_dir = _written_plan(tmp_path)
    plan = load_content_discovery_plan(plan_path)
    command = build_live_content_discovery_command(plan.steps[0], plan)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(command.output_file).write_text("/admin (Status: 200) [Size: 10]\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentDiscoveryRunner(
        output_dir,
        plan.target,
        set(plan.origins),
    ).run(command)

    assert result.executed is True
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert argv == command.argv
    assert kwargs["timeout"] == CONTENT_DISCOVERY_TIMEOUT_SECONDS
    assert "shell" not in kwargs


@pytest.mark.parametrize(
    "command_change",
    [
        {"tool": "curl"},
        {"argv": ["gobuster", "dir", "-u", "http://10.10.10.10/", "--recursive"]},
        {"argv": ["gobuster", "dir", "-u", "http://10.10.10.10/", "-x", "php"]},
    ],
)
def test_content_runner_refuses_unapproved_commands(
    tmp_path: Path,
    monkeypatch,
    command_change: dict[str, object],
) -> None:
    plan_path, _scope, _input_dir, output_dir = _written_plan(tmp_path)
    plan = load_content_discovery_plan(plan_path)
    command = replace(
        build_live_content_discovery_command(plan.steps[0], plan),
        **command_change,
    )
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("process call must not occur")

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentDiscoveryRunner(
        output_dir,
        plan.target,
        set(plan.origins),
    ).run(command)

    assert result.executed is False
    assert called is False


def test_content_runner_enforces_timeout(tmp_path: Path, monkeypatch) -> None:
    plan_path, _scope, _input_dir, output_dir = _written_plan(tmp_path)
    plan = load_content_discovery_plan(plan_path)
    command = build_live_content_discovery_command(plan.steps[0], plan)

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr("bugslyce.recon.runner.subprocess.run", fake_run)
    result = LiveContentDiscoveryRunner(
        output_dir,
        plan.target,
        set(plan.origins),
    ).run(command)

    assert result.executed is False
    assert result.error == "Content discovery exceeded 900 seconds."


class _MockContentRunner:
    def run(self, command):
        Path(command.output_file).write_text(
            "/admin (Status: 200) [Size: 10]\n"
            "robots.txt (Status: 200) [Size: 20]\n",
            encoding="utf-8",
        )
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-06-11T00:00:00+00:00",
            ended_at="2026-06-11T00:00:01+00:00",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=None,
        )


class _NeverRunContentRunner:
    def __init__(self) -> None:
        self.called = False

    def run(self, _command):
        self.called = True
        raise AssertionError("runner must not be called")


def _written_plan(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
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
                "65524/tcp open  http    Apache",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-tcp-full-plus-services",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-services-all.txt"}
                ],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "bugslyce-output" / "content-plan"
    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_PROFILE,
        output_dir,
    )
    plan_path, _markdown_path = write_content_discovery_plan(plan)
    return plan_path, scope, input_dir, output_dir


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_payload(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _mutate_origin(payload: dict, origin: str) -> None:
    payload["origins"][0] = origin
    payload["steps"][0]["origin"] = origin
    payload["steps"][0]["command_preview"][3] = origin
    payload["steps"][0]["expected_artifact"]["base_url"] = origin


def _escape_output(payload: dict) -> None:
    payload["steps"][0]["expected_artifact"]["file"] = "../escape.txt"
    payload["steps"][0]["command_preview"][9] = str(
        Path(payload["output_dir"]).parent / "escape.txt"
    )
