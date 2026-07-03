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
    CONTENT_DISCOVERY_TINY_PROFILE,
    STANDARD_BOUNDED_CORE_PROFILE,
    STANDARD_AUTH_CORE_PROFILE,
    TINY_WORDLIST,
    build_content_discovery_plan,
    write_content_discovery_plan,
)
from bugslyce.recon.content_run import (
    ContentDiscoveryExecutionIncomplete,
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
    assert result.commands_started == 2
    assert result.commands_completed == 2
    assert result.commands_timed_out == 0
    assert result.partial_artifacts_imported == 0
    assert result.completed_artifacts_imported == 2
    assert result.selected_step_id is None
    assert result.selected_origin is None
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
    with pytest.raises(ValueError, match="Unsupported content discovery profile"):
        load_content_discovery_plan(plan_path)


@pytest.mark.parametrize(
    "profile",
    [
        CONTENT_DISCOVERY_TINY_PROFILE,
        STANDARD_AUTH_CORE_PROFILE,
        STANDARD_BOUNDED_CORE_PROFILE,
        CONTENT_DISCOVERY_PROFILE,
    ],
)
def test_content_run_accepts_supported_profiles(tmp_path: Path, profile: str) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path, profile=profile)

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda _path: True,
    )

    assert result.profile == profile
    if profile == CONTENT_DISCOVERY_TINY_PROFILE:
        assert all("gobuster-tiny-" in Path(path).name for path in result.artifact_paths)
    if profile == STANDARD_AUTH_CORE_PROFILE:
        assert all(
            "gobuster-standard-auth-core-" in Path(path).name
            for path in result.artifact_paths
        )
    if profile == STANDARD_BOUNDED_CORE_PROFILE:
        assert all(
            "gobuster-standard-bounded-core-" in Path(path).name
            for path in result.artifact_paths
        )


def test_content_run_executes_only_selected_existing_step(tmp_path: Path) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(tmp_path)
    plan = load_content_discovery_plan(plan_path)
    runner = _RecordingContentRunner()

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=runner,
        wordlist_check=lambda _path: True,
        step_id="CONTENT-STEP-002",
    )

    assert [command.id for command in runner.commands] == ["CONTENT-STEP-002"]
    assert runner.commands[0].argv == plan.steps[1].command_preview
    assert result.origins == ["http://10.10.10.10:65524/"]
    assert result.selected_step_id == "CONTENT-STEP-002"
    assert result.selected_origin == "http://10.10.10.10:65524/"
    assert result.commands_started == 1
    assert result.commands_completed == 1
    assert result.completed_artifacts_imported == 1
    assert result.partial_artifacts_imported == 0
    assert (input_dir / "gobuster-10.10.10.10-65524-root.txt").is_file()
    assert not (input_dir / "gobuster-10.10.10.10-80-root.txt").exists()


def test_content_run_progress_reports_selected_step_before_and_after_runner(
    tmp_path: Path,
) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path)
    messages: list[str] = []
    runner = _ProgressAssertingRunner(messages)

    run_content_discovery_workflow(
        plan_path,
        scope,
        runner=runner,
        wordlist_check=lambda _path: True,
        step_id="CONTENT-STEP-002",
        progress_callback=messages.append,
    )

    output = "\n".join(messages)
    assert "BugSlyce content discovery step starting" in output
    assert "Step: CONTENT-STEP-002" in output
    assert "Progress: 1/1" in output
    assert "Origin: http://10.10.10.10:65524/" in output
    assert "Profile: lab-root-light" in output
    assert "Timeout: 900 seconds" in output
    assert "BugSlyce content discovery step complete" in output
    assert "Elapsed seconds:" in output
    assert "Artefact:" in output


def test_content_run_progress_reports_each_planned_step(tmp_path: Path) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path)
    messages: list[str] = []

    run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda _path: True,
        progress_callback=messages.append,
    )

    output = "\n".join(messages)
    assert "Progress: 1/2" in output
    assert "Progress: 2/2" in output
    assert output.count("BugSlyce content discovery step complete") == 2


def test_content_run_refuses_unknown_selected_step_without_running(tmp_path: Path) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path)
    runner = _NeverRunContentRunner()

    with pytest.raises(ValueError, match="not present in the approved plan"):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda _path: True,
            step_id="CONTENT-STEP-999",
        )

    assert runner.called is False


def test_selected_step_still_requires_scope_and_profile_wordlist(tmp_path: Path) -> None:
    plan_path, _scope, _input_dir, _output_dir = _written_plan(tmp_path)
    other_scope = tmp_path / "scope.md"
    other_scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        run_content_discovery_workflow(
            plan_path,
            other_scope,
            runner=_NeverRunContentRunner(),
            wordlist_check=lambda _path: True,
            step_id="CONTENT-STEP-001",
        )

    runner = _NeverRunContentRunner()
    with pytest.raises(ValueError, match="wordlist does not exist"):
        run_content_discovery_workflow(
            plan_path,
            _scope,
            runner=runner,
            wordlist_check=lambda _path: False,
            step_id="CONTENT-STEP-001",
        )
    assert runner.called is False


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
            "unsafe artefact filename",
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

    assert result.executed is True
    assert result.error == (
        "Content discovery command CONTENT-STEP-001 for http://10.10.10.10/ "
        "started and exceeded 900 seconds."
    )


def test_content_run_timeout_without_output_records_started_and_timed_out(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)

    with pytest.raises(ContentDiscoveryExecutionIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_TimeoutContentRunner(write_partial=False),
            wordlist_check=lambda _path: True,
        )

    result = exc_info.value.result
    execution_json, _execution_markdown = write_content_discovery_execution_result(
        result,
        output_dir,
    )
    payload = json.loads(execution_json.read_text(encoding="utf-8"))
    assert result.commands_started == 1
    assert result.commands_completed == 0
    assert result.commands_timed_out == 1
    assert result.partial_artifacts_imported == 0
    assert result.completed_artifacts_imported == 0
    assert result.selected_step_id is None
    assert result.selected_origin is None
    assert result.timed_out_step_id == "CONTENT-STEP-001"
    assert result.timed_out_origin == "http://10.10.10.10/"
    assert result.artifact_paths == []
    assert payload["commands_started"] == 1
    assert (input_dir / "report.md").is_file()
    assert "started and exceeded" in str(exc_info.value)


def test_content_run_timeout_imports_nonempty_partial_output(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )

    with pytest.raises(ContentDiscoveryExecutionIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_TimeoutContentRunner(write_partial=True),
            wordlist_check=lambda path: path == TINY_WORDLIST,
        )

    result = exc_info.value.result
    write_content_discovery_execution_result(result, output_dir)
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    project = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))
    partial = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact.get("type") == "gobuster"
    ]

    assert result.commands_started == 1
    assert result.commands_completed == 0
    assert result.commands_timed_out == 1
    assert result.partial_artifacts_imported == 1
    assert result.completed_artifacts_imported == 0
    assert len(result.artifact_paths) == 1
    assert Path(result.artifact_paths[0]).is_file()
    assert partial[0]["tags"] == ["partial", "timed_out"]
    assert "Partial gobuster output" in partial[0]["description"]
    assert any(
        path["url"] == "http://10.10.10.10/hidden"
        for path in project["project_state"]["discovered_paths"]
    )
    assert (input_dir / "report.md").is_file()


def test_content_run_timeout_progress_is_honest(tmp_path: Path) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(tmp_path)
    messages: list[str] = []

    with pytest.raises(ContentDiscoveryExecutionIncomplete):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_TimeoutContentRunner(write_partial=True),
            wordlist_check=lambda _path: True,
            step_id="CONTENT-STEP-001",
            progress_callback=messages.append,
        )

    output = "\n".join(messages)
    assert "BugSlyce content discovery step timed out" in output
    assert "Step: CONTENT-STEP-001" in output
    assert "Origin: http://10.10.10.10/" in output
    assert "Elapsed seconds:" in output
    assert "Partial output imported: true" in output
    assert "No gobuster command was executed" not in output


def test_content_run_preserves_completed_first_step_when_second_times_out(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)

    with pytest.raises(ContentDiscoveryExecutionIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_SuccessThenTimeoutContentRunner(write_partial=True),
            wordlist_check=lambda _path: True,
        )

    result = exc_info.value.result
    execution_json, _execution_markdown = write_content_discovery_execution_result(
        result,
        output_dir,
    )
    metadata = json.loads(execution_json.read_text(encoding="utf-8"))
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    gobuster_artifacts = [
        artifact for artifact in manifest["artifacts"] if artifact["type"] == "gobuster"
    ]

    assert result.commands_started == 2
    assert result.commands_completed == 1
    assert result.commands_timed_out == 1
    assert result.completed_artifacts_imported == 1
    assert result.partial_artifacts_imported == 1
    assert result.timed_out_step_id == "CONTENT-STEP-002"
    assert result.timed_out_origin == "http://10.10.10.10:65524/"
    assert len(result.artifact_paths) == 2
    assert len(gobuster_artifacts) == 2
    assert any(artifact["tags"] == [] for artifact in gobuster_artifacts)
    assert any(artifact["tags"] == ["partial", "timed_out"] for artifact in gobuster_artifacts)
    assert metadata["completed_artifacts_imported"] == 1
    assert (input_dir / "report.md").is_file()
    assert (input_dir / "project_state.json").is_file()


def test_content_run_overwrites_generic_latest_metadata_and_keeps_phase_copy(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)
    (input_dir / "recon_execution.md").write_text(
        "# BugSlyce Selective Body Fetch\n",
        encoding="utf-8",
    )
    (input_dir / "recon_execution.json").write_text(
        json.dumps({"mode": "body-fetch"}),
        encoding="utf-8",
    )

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda _path: True,
        step_id="CONTENT-STEP-001",
    )
    latest_json, latest_markdown = write_content_discovery_execution_result(
        result,
        output_dir,
    )
    latest_payload = json.loads(latest_json.read_text(encoding="utf-8"))
    latest_text = latest_markdown.read_text(encoding="utf-8")

    assert latest_json == input_dir / "recon_execution.json"
    assert latest_markdown == input_dir / "recon_execution.md"
    assert latest_payload["mode"] == "content-run"
    assert latest_payload["profile"] == "lab-root-light"
    assert latest_payload["selected_step_id"] == "CONTENT-STEP-001"
    assert latest_payload["selected_origin"] == "http://10.10.10.10/"
    assert latest_payload["completed_artifacts_imported"] == 1
    assert latest_payload["partial_artifacts_imported"] == 0
    assert latest_text.startswith("# BugSlyce Content Discovery Execution")
    assert "Selective Body Fetch" not in latest_text
    assert (input_dir / "recon_execution_content_run.json").is_file()
    assert (input_dir / "recon_execution_content_run.md").is_file()
    assert (output_dir / "content_discovery_execution.json").is_file()
    assert (output_dir / "content_discovery_execution.md").is_file()


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


class _RecordingContentRunner(_MockContentRunner):
    def __init__(self) -> None:
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        return super().run(command)


class _ProgressAssertingRunner(_MockContentRunner):
    def __init__(self, messages: list[str]) -> None:
        self.messages = messages

    def run(self, command):
        assert self.messages
        assert "step starting" in self.messages[-1]
        assert f"Step: {command.id}" in self.messages[-1]
        return super().run(command)


class _NeverRunContentRunner:
    def __init__(self) -> None:
        self.called = False

    def run(self, _command):
        self.called = True
        raise AssertionError("runner must not be called")


class _TimeoutContentRunner:
    def __init__(self, write_partial: bool) -> None:
        self.write_partial = write_partial

    def run(self, command):
        if self.write_partial:
            Path(command.output_file).write_text(
                "hidden (Status: 301) [Size: 169] "
                "[--> http://10.10.10.10/hidden/]\n",
                encoding="utf-8",
            )
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=None,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-06-11T00:00:00+00:00",
            ended_at="2026-06-11T00:02:00+00:00",
            duration_seconds=120.0,
            executed=True,
            simulated=False,
            error=(
                f"Content discovery command {command.id} for {command.argv[3]} "
                f"started and exceeded {command.timeout_seconds} seconds."
            ),
        )


class _SuccessThenTimeoutContentRunner:
    def __init__(self, write_partial: bool) -> None:
        self.write_partial = write_partial
        self.calls = 0

    def run(self, command):
        self.calls += 1
        if self.calls == 1:
            return _MockContentRunner().run(command)
        if self.write_partial:
            Path(command.output_file).write_text(
                "private (Status: 301) [Size: 169] "
                "[--> http://10.10.10.10:65524/private/]\n",
                encoding="utf-8",
            )
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=None,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-06-11T00:00:00+00:00",
            ended_at="2026-06-11T00:15:00+00:00",
            duration_seconds=900.0,
            executed=True,
            simulated=False,
            error=(
                f"Content discovery command {command.id} for {command.argv[3]} "
                f"started and exceeded {command.timeout_seconds} seconds."
            ),
        )


def _written_plan(
    tmp_path: Path,
    profile: str = CONTENT_DISCOVERY_PROFILE,
) -> tuple[Path, Path, Path, Path]:
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
        profile,
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
