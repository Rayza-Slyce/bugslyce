"""Tests for controlled live root content discovery from approved plans."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from itertools import count
import json
from pathlib import Path
import subprocess

import pytest

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IdentificationHeader,
    build_bug_bounty_policy,
)
from bugslyce.core.models import ReconCommandResult
from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_IPV4,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.core.project import build_project_state
from bugslyce.project_session import (
    initialize_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.content_commands import (
    CONTENT_DISCOVERY_TIMEOUT_SECONDS,
    build_live_content_discovery_command,
)
from bugslyce.recon.body_fetch import select_body_fetch_urls
from bugslyce.recon.content_followup import select_content_followup_urls
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
    BASELINE_ARTIFACT_NAME,
    BASELINE_CLASSIFICATION_STABLE_FALLBACK,
    BASELINE_POLICY_INTERNAL_COMPARATOR,
    ContentDiscoveryBaselineRefused,
    ContentDiscoveryComparatorIncomplete,
    ContentDiscoveryExecutionIncomplete,
    load_content_discovery_plan,
    run_content_discovery_workflow as _run_content_discovery_workflow,
    write_content_discovery_execution_result,
)
from bugslyce.recon.http_enforcement import (
    HTTPExecutorClosed,
    HTTPTransportFailure,
    HTTPTransportRequest,
    HTTPTransportResponse,
    InternalHTTPExecutor,
    InternalHTTPResponse,
    PeerBoundHTTPTransport,
)
from bugslyce.recon.runner import LiveContentDiscoveryRunner


def run_content_discovery_workflow(*args, **kwargs):
    """Keep workflow tests offline with a conventional negative baseline."""

    kwargs.setdefault("http_executor", _ConventionalBaselineExecutor())
    token_numbers = count(1)
    kwargs.setdefault("token_factory", lambda: f"test-token-{next(token_numbers)}")
    return _run_content_discovery_workflow(*args, **kwargs)


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
    baseline = json.loads(
        (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    )

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
    assert all(
        origin["comparator_runtime_budget_seconds"] is None
        for origin in baseline["origins"]
    )
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
    assert result.origins == ["http://10.10.10.10/"]
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
    assert result.origins == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]
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


def test_stable_fallback_uses_internal_comparator_with_truthful_provenance(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    executor = _StableFallbackExecutor()
    runner = _NeverRunContentRunner()

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=runner,
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=executor,
    )

    baseline = json.loads((input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8"))
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    project = json.loads((input_dir / "project_state.json").read_text(encoding="utf-8"))
    internal_artifacts = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact["type"] == "content_discovery_internal"
    ]

    assert runner.called is False
    assert len(executor.urls) == 3 + 25
    assert executor.urls[3:] == [
        f"http://10.10.10.10/{entry}"
        for entry in TINY_WORDLIST.read_text(encoding="utf-8").splitlines()
    ]
    assert result.commands_started == 0
    assert result.commands_completed == 0
    assert result.completed_artifacts_imported == 1
    assert result.origin_decisions[0].classification == BASELINE_CLASSIFICATION_STABLE_FALLBACK
    assert result.origin_decisions[0].selected_policy == BASELINE_POLICY_INTERNAL_COMPARATOR
    assert result.origin_decisions[0].baseline_equivalent_candidates == 23
    assert result.origin_decisions[0].retained_candidates == 2
    assert len(internal_artifacts) == 1
    assert internal_artifacts[0]["tags"] == ["internal_exact_body_comparator"]
    assert not internal_artifacts[0]["file"].startswith("gobuster")
    assert "internal exact-body comparator" in internal_artifacts[0]["description"]
    assert baseline["origins"][0]["baseline_equivalent_candidate_count"] == 23
    assert baseline["origins"][0]["retained_candidate_count"] == 2
    assert baseline["origins"][0]["comparator_runtime_budget_seconds"] == 85
    assert "identity-sentinel" not in json.dumps(baseline)
    assert "stable application shell" not in json.dumps(baseline)
    assert any(
        path["url"] == "http://10.10.10.10/index.html"
        for path in project["project_state"]["discovered_paths"]
    )
    assert any(
        path["url"] == "http://10.10.10.10/hidden"
        for path in project["project_state"]["discovered_paths"]
    )
    state = build_project_state(input_dir)
    considered, followups = select_content_followup_urls(
        state,
        "10.10.10.10",
        manifest,
    )
    assert considered == 2
    assert "http://10.10.10.10/hidden" in followups


def test_internal_comparator_progress_is_rate_limited_and_truthful(
    tmp_path: Path,
) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    clock = _ComparatorProgressClock(seconds_per_candidate=1.0)
    executor = _ComparatorProgressExecutor(clock)
    messages: list[str] = []

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_NeverRunContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=executor,
        comparator_monotonic=clock.monotonic,
        comparator_progress_callback=messages.append,
        comparator_progress_interval_seconds=6.0,
    )

    assert messages[0] == (
        "6/25 candidates checked; 2 retained; 4 baseline-equivalent; elapsed 6s"
    )
    assert messages[1].startswith("12/25 candidates checked;")
    assert messages[-1] == (
        "25/25 candidates checked; 2 retained; 23 baseline-equivalent; elapsed 25s"
    )
    assert len(messages) == 5
    assert all("\r" not in message and "\n" not in message for message in messages)
    completed = [int(message.split("/", 1)[0]) for message in messages]
    assert completed == sorted(completed)
    assert all(value <= 25 for value in completed)
    assert result.origin_decisions[0].retained_candidates == 2
    assert result.origin_decisions[0].baseline_equivalent_candidates == 23


def test_internal_comparator_progress_default_threshold_and_fast_silence(
    tmp_path: Path,
) -> None:
    slow_plan, slow_scope, _input_dir, _output_dir = _written_plan(
        tmp_path / "slow",
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    slow_clock = _ComparatorProgressClock(seconds_per_candidate=0.5)
    slow_messages: list[str] = []
    run_content_discovery_workflow(
        slow_plan,
        slow_scope,
        runner=_NeverRunContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=_ComparatorProgressExecutor(slow_clock),
        comparator_monotonic=slow_clock.monotonic,
        comparator_progress_callback=slow_messages.append,
    )

    assert slow_messages[0].startswith("24/25 candidates checked;")
    assert "elapsed 12s" in slow_messages[0]

    fast_plan, fast_scope, _input_dir, _output_dir = _written_plan(
        tmp_path / "fast",
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    fast_messages: list[str] = []
    run_content_discovery_workflow(
        fast_plan,
        fast_scope,
        runner=_NeverRunContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=_StableFallbackExecutor(),
        comparator_progress_callback=fast_messages.append,
    )

    assert fast_messages == []


def test_internal_comparator_progress_preserves_requests_and_evidence(
    tmp_path: Path,
) -> None:
    results = []
    comparator_outputs = []
    candidate_urls = []
    for name, callback in (("silent", None), ("visible", lambda _message: None)):
        plan_path, scope, input_dir, _output_dir = _written_plan(
            tmp_path / name,
            profile=CONTENT_DISCOVERY_TINY_PROFILE,
        )
        clock = _ComparatorProgressClock(seconds_per_candidate=1.0)
        executor = _ComparatorProgressExecutor(clock)
        result = run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_NeverRunContentRunner(),
            wordlist_check=lambda path: path == TINY_WORDLIST,
            step_id="CONTENT-STEP-001",
            http_executor=executor,
            comparator_monotonic=clock.monotonic,
            comparator_progress_callback=callback,
            comparator_progress_interval_seconds=6.0,
        )
        results.append(result.origin_decisions)
        candidate_urls.append(executor.urls[3:])
        comparator_path = next(
            Path(path)
            for path in result.artifact_paths
            if Path(path).name.startswith("content-discovery-internal-")
        )
        comparator_outputs.append(comparator_path.read_text(encoding="utf-8"))
        assert "candidates checked" not in json.dumps(
            json.loads((input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8"))
        )

    assert results[0] == results[1]
    assert candidate_urls[0] == candidate_urls[1]
    assert len(candidate_urls[0]) == 25
    assert comparator_outputs[0] == comparator_outputs[1]


def test_internal_comparator_progress_callback_failure_is_hard(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    clock = _ComparatorProgressClock(seconds_per_candidate=1.0)
    executor = _ComparatorProgressExecutor(clock)

    def fail_progress(_message: str) -> None:
        raise RuntimeError("fixture progress callback failure")

    with pytest.raises(RuntimeError, match="fixture progress callback failure"):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_NeverRunContentRunner(),
            wordlist_check=lambda path: path == TINY_WORDLIST,
            step_id="CONTENT-STEP-001",
            http_executor=executor,
            comparator_monotonic=clock.monotonic,
            comparator_progress_callback=fail_progress,
            comparator_progress_interval_seconds=3.0,
        )

    assert len(executor.urls) == 3 + 3
    assert not any(
        artifact.get("type") == "content_discovery_internal"
        for artifact in json.loads(
            (input_dir / "recon_manifest.json").read_text(encoding="utf-8")
        )["artifacts"]
    )


def test_comparator_budget_uses_effective_executor_request_rate(tmp_path: Path) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    executor = _StableFallbackExecutor()
    executor.configuration = _PacingConfiguration(Decimal("2"))

    run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_NeverRunContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=executor,
    )

    baseline = json.loads(
        (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    )
    assert baseline["origins"][0]["comparator_runtime_budget_seconds"] == 98


def test_unstable_origin_writes_all_baselines_before_refusing_all_discovery(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)
    executor = _UnstableSecondOriginExecutor()
    runner = _NeverRunContentRunner()

    with pytest.raises(ContentDiscoveryBaselineRefused, match="No content discovery") as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda _path: True,
            http_executor=executor,
        )

    baseline_path = input_dir / BASELINE_ARTIFACT_NAME
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert exc_info.value.baseline_artifact_path == baseline_path
    assert runner.called is False
    assert len(executor.urls) == 6
    assert len(payload["origins"]) == 2
    assert [item["classification"] for item in payload["origins"]] == [
        "conventional_negative",
        "unstable",
    ]
    assert not list(output_dir.glob("gobuster-*.txt"))
    assert not list(output_dir.glob("content-discovery-internal-*.txt"))


def test_failed_baseline_is_written_before_content_discovery_refusal(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, output_dir = _written_plan(tmp_path)
    executor = _FailedBaselineExecutor()
    runner = _NeverRunContentRunner()

    with pytest.raises(ContentDiscoveryBaselineRefused):
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda _path: True,
            step_id="CONTENT-STEP-001",
            http_executor=executor,
        )

    payload = json.loads(
        (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    )
    assert payload["origins"][0]["classification"] == "failed"
    assert payload["origins"][0]["completed_observations"] == 2
    assert len(executor.urls) == 3
    assert runner.called is False
    assert not list(output_dir.glob("gobuster-*.txt"))
    assert not list(output_dir.glob("content-discovery-internal-*.txt"))


def test_fingerprint_derived_port_3000_origin_enters_baseline_classification(
    tmp_path: Path,
) -> None:
    _old_plan, scope, input_dir, output_dir = _written_plan(tmp_path)
    (input_dir / "nmap-services-all.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT     STATE SERVICE VERSION",
                "3000/tcp open  ppp?",
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port3000-TCP:V=7.94%r(GetRequest,80,",
                'SF:"HTTP/1\\.1\\x20200\\x20OK\\r\\nContent-Type:\\x20text/html")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_TINY_PROFILE,
        output_dir,
    )
    plan_path, _markdown = write_content_discovery_plan(plan)
    executor = _ConventionalBaselineExecutor()

    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        http_executor=executor,
    )

    assert plan.origins == ["http://10.10.10.10:3000/"]
    assert result.origin_decisions[0].origin == "http://10.10.10.10:3000/"
    assert len(executor.urls) == 3
    assert all(url.startswith("http://10.10.10.10:3000/") for url in executor.urls)


def test_production_default_builds_configured_programme_scoped_executor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    _configure_bug_bounty_project(input_dir, scope, excluded=False)
    clock = _AdvancingHTTPClock()
    transport = _RecordingPeerBoundTransport()
    created: list[InternalHTTPExecutor] = []

    def create_executor(configuration, programme_scope_policy):
        assert configuration.maximum_request_starts_per_second == Decimal("2")
        assert configuration.maximum_concurrent_requests == 1
        executor = InternalHTTPExecutor(
            configuration,
            programme_scope_policy=programme_scope_policy,
            transport=transport,
            ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        created.append(executor)
        return executor

    monkeypatch.setattr(
        "bugslyce.recon.content_run.enforce_r0b2_bug_bounty_live_block",
        lambda _context: None,
    )
    monkeypatch.setattr(
        "bugslyce.recon.content_run._create_project_http_executor",
        create_executor,
    )

    result = _run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        token_factory=iter(("one", "two", "three")).__next__,
    )

    evidence = (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    assert len(created) == 1
    assert len(transport.requests) == 3
    assert all(request.selected_ipv4 == "10.10.10.10" for request in transport.requests)
    assert all(("User-Agent", "R2-IDENTITY-UA") in request.headers for request in transport.requests)
    assert all(("X-Researcher-ID", "R2-IDENTITY-HEADER") in request.headers for request in transport.requests)
    assert sum(Decimal(str(item)) for item in clock.sleeps) == Decimal("1.0")
    assert all(item == 0.1 for item in clock.sleeps)
    assert result.origin_decisions[0].selected_policy == "gobuster"
    assert "R2-IDENTITY-UA" not in evidence
    assert "R2-IDENTITY-HEADER" not in evidence
    with pytest.raises(HTTPExecutorClosed):
        created[0].request("http://10.10.10.10/after-close")


def test_production_default_scope_refusal_reaches_zero_transport_calls(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    _configure_bug_bounty_project(input_dir, scope, excluded=True)
    transport = _RecordingPeerBoundTransport()
    resolver_calls: list[tuple[str, int]] = []
    created: list[InternalHTTPExecutor] = []

    def create_executor(configuration, programme_scope_policy):
        executor = InternalHTTPExecutor(
            configuration,
            programme_scope_policy=programme_scope_policy,
            transport=transport,
            ipv4_resolver=lambda hostname, port: (
                resolver_calls.append((hostname, port)) or ("192.0.2.10",)
            ),
        )
        created.append(executor)
        return executor

    monkeypatch.setattr(
        "bugslyce.recon.content_run.enforce_r0b2_bug_bounty_live_block",
        lambda _context: None,
    )
    monkeypatch.setattr(
        "bugslyce.recon.content_run._create_project_http_executor",
        create_executor,
    )

    with pytest.raises(ContentDiscoveryBaselineRefused):
        _run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_NeverRunContentRunner(),
            wordlist_check=lambda path: path == TINY_WORDLIST,
            step_id="CONTENT-STEP-001",
            token_factory=iter(("one", "two", "three")).__next__,
        )

    assert len(created) == 1
    assert transport.requests == []
    assert resolver_calls == []
    assert created[0].total_request_attempts == 0
    assert created[0]._closed is True


def test_injected_executor_remains_caller_owned(tmp_path: Path) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    executor = _ConventionalBaselineExecutor()

    run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_MockContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=executor,
    )

    assert executor.closed is False


def test_comparator_failure_updates_baseline_evidence_before_raising(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    executor = _ComparatorFailureExecutor()
    runner = _NeverRunContentRunner()

    with pytest.raises(ContentDiscoveryComparatorIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda path: path == TINY_WORDLIST,
            http_executor=executor,
        )

    payload = json.loads(
        (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    )
    first_origin = payload["origins"][0]
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))

    assert exc_info.value.baseline_artifact_path == input_dir / BASELINE_ARTIFACT_NAME
    assert len(executor.urls) == 9
    assert executor.urls[-3:] == [
        "http://10.10.10.10/index.html",
        "http://10.10.10.10/robots.txt",
        "http://10.10.10.10/hidden",
    ]
    assert first_origin["classification"] == "stable_fallback"
    assert first_origin["baseline_equivalent_candidate_count"] == 1
    assert first_origin["retained_candidate_count"] == 1
    assert "stopped before completing" in first_origin["failure_or_instability_reason"]
    assert any("not complete" in item for item in first_origin["limitations"])
    assert not any(
        artifact.get("type") == "content_discovery_internal"
        for artifact in manifest["artifacts"]
    )
    assert runner.called is False
    assert not any(
        ":65524/" in url and ".bugslyce-negative-" not in url
        for url in executor.urls
    )


def test_comparator_deadline_preserves_counts_and_stops_before_next_candidate(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    clock = _ComparatorDeadlineClock()
    executor = _ComparatorDeadlineExecutor(clock)
    runner = _NeverRunContentRunner()

    with pytest.raises(ContentDiscoveryComparatorIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=runner,
            wordlist_check=lambda path: path == TINY_WORDLIST,
            http_executor=executor,
            comparator_monotonic=clock.monotonic,
        )

    payload = json.loads(
        (input_dir / BASELINE_ARTIFACT_NAME).read_text(encoding="utf-8")
    )
    first_origin = payload["origins"][0]

    assert exc_info.value.baseline_artifact_path == input_dir / BASELINE_ARTIFACT_NAME
    assert executor.candidate_urls == [
        "http://10.10.10.10/index.html",
        "http://10.10.10.10/robots.txt",
    ]
    assert executor.candidate_timeouts == [10, 5]
    assert first_origin["baseline_equivalent_candidate_count"] == 1
    assert first_origin["retained_candidate_count"] == 1
    assert "85-second aggregate runtime budget" in first_origin[
        "failure_or_instability_reason"
    ]
    assert first_origin["comparator_runtime_budget_seconds"] == 85
    assert any("not complete" in item for item in first_origin["limitations"])
    assert runner.called is False
    assert not any(
        artifact.get("type") == "content_discovery_internal"
        for artifact in json.loads(
            (input_dir / "recon_manifest.json").read_text(encoding="utf-8")
        )["artifacts"]
    )
    assert not any(
        ":65524/" in url and ".bugslyce-negative-" not in url
        for url in executor.urls
    )


def test_completed_comparator_and_timed_out_gobuster_report_started_origins(
    tmp_path: Path,
) -> None:
    plan_path, scope, _input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )

    with pytest.raises(ContentDiscoveryExecutionIncomplete) as exc_info:
        run_content_discovery_workflow(
            plan_path,
            scope,
            runner=_TimeoutContentRunner(write_partial=False),
            wordlist_check=lambda path: path == TINY_WORDLIST,
            http_executor=_StableThenConventionalExecutor(),
        )

    assert exc_info.value.result.origins == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]


def test_internal_comparator_records_feed_existing_body_fetch_selection(
    tmp_path: Path,
) -> None:
    plan_path, scope, input_dir, _output_dir = _written_plan(
        tmp_path,
        profile=CONTENT_DISCOVERY_TINY_PROFILE,
    )
    result = run_content_discovery_workflow(
        plan_path,
        scope,
        runner=_NeverRunContentRunner(),
        wordlist_check=lambda path: path == TINY_WORDLIST,
        step_id="CONTENT-STEP-001",
        http_executor=_StableFallbackExecutor(),
    )
    state = build_project_state(input_dir)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    considered, followups = select_content_followup_urls(
        state,
        "10.10.10.10",
        manifest,
    )
    retained_url = "http://10.10.10.10/hidden"
    suppressed_url = "http://10.10.10.10/robots.txt"

    assert considered == 2
    assert retained_url in followups
    assert suppressed_url not in {record.url for record in state.discovered_paths}

    followup_file = input_dir / "curl-headers-content-followup-internal-hidden.txt"
    followup_file.write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
    manifest["artifacts"].append(
        {
            "type": "http_headers",
            "file": followup_file.name,
            "url": retained_url,
            "description": "Content-discovery result follow-up headers",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    followed_state = build_project_state(input_dir)
    considered_bodies, selected_bodies = select_body_fetch_urls(
        followed_state,
        "10.10.10.10",
        manifest,
    )

    assert result.origin_decisions[0].retained_candidates == 2
    assert considered_bodies == 1
    assert selected_bodies == [retained_url]
    assert suppressed_url not in selected_bodies


class _ConventionalBaselineExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.closed = False

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        body = f"not found: {url}".encode()
        return _internal_response(url, status=404, body=body)

    def close(self) -> None:
        self.closed = True


class _StableFallbackExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if ".bugslyce-negative-" in url or url.endswith("/robots.txt"):
            return _internal_response(url, status=200, body=b"stable application shell")
        if url.endswith("/index.html"):
            return _internal_response(url, status=200, body=b"stable applicatiOn shell")
        if url.endswith("/hidden"):
            return _internal_response(url, status=200, body=b"genuine endpoint")
        return _internal_response(url, status=200, body=b"stable application shell")


class _ComparatorProgressClock:
    def __init__(self, *, seconds_per_candidate: float) -> None:
        self.now = 0.0
        self.seconds_per_candidate = seconds_per_candidate

    def monotonic(self) -> float:
        return self.now


class _ComparatorProgressExecutor(_StableFallbackExecutor):
    def __init__(self, clock: _ComparatorProgressClock) -> None:
        super().__init__()
        self.clock = clock

    def request(self, url: str, **kwargs) -> InternalHTTPResponse:
        response = super().request(url, **kwargs)
        if ".bugslyce-negative-" not in url:
            self.clock.now += self.clock.seconds_per_candidate
        return response


class _PacingConfiguration:
    def __init__(self, rate: Decimal) -> None:
        self.maximum_request_starts_per_second = rate


class _UnstableSecondOriginExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.second_origin_calls = 0

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if ":65524/" not in url:
            return _internal_response(url, status=404, body=b"missing")
        self.second_origin_calls += 1
        return _internal_response(
            url,
            status=200,
            body=(b"shell-a" if self.second_origin_calls != 2 else b"shell-b"),
        )


class _FailedBaselineExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if len(self.urls) == 2:
            raise HTTPTransportFailure("timeout")
        return _internal_response(url, status=404, body=b"missing")


class _ComparatorFailureExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if ".bugslyce-negative-" in url:
            if ":65524/" in url:
                return _internal_response(url, status=404, body=b"missing")
            return _internal_response(url, status=200, body=b"stable shell")
        if url.endswith("/index.html"):
            return _internal_response(url, status=200, body=b"stable shell")
        if url.endswith("/robots.txt"):
            return _internal_response(url, status=200, body=b"genuine endpoint")
        if url.endswith("/hidden"):
            raise HTTPTransportFailure("transport_error")
        raise AssertionError(f"unexpected comparator request: {url}")


class _ComparatorDeadlineClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


class _ComparatorDeadlineExecutor:
    def __init__(self, clock: _ComparatorDeadlineClock) -> None:
        self.clock = clock
        self.urls: list[str] = []
        self.candidate_urls: list[str] = []
        self.candidate_timeouts: list[int] = []

    def request(self, url: str, **kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if ".bugslyce-negative-" in url:
            if ":65524/" in url:
                return _internal_response(url, status=404, body=b"missing")
            return _internal_response(url, status=200, body=b"stable shell")
        self.candidate_urls.append(url)
        self.candidate_timeouts.append(kwargs["timeout_seconds"])
        if len(self.candidate_urls) == 1:
            self.clock.now = 80.0
            return _internal_response(url, status=200, body=b"stable shell")
        self.clock.now = 86.0
        return _internal_response(url, status=200, body=b"genuine endpoint")


class _StableThenConventionalExecutor:
    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        if ":65524/" in url:
            return _internal_response(url, status=404, body=b"missing")
        if ".bugslyce-negative-" in url or url.endswith("/robots.txt"):
            return _internal_response(url, status=200, body=b"stable shell")
        return _internal_response(url, status=200, body=b"genuine endpoint")


class _RecordingPeerBoundTransport(PeerBoundHTTPTransport):
    def __init__(self) -> None:
        self.requests: list[HTTPTransportRequest] = []

    def __call__(self, request: HTTPTransportRequest) -> HTTPTransportResponse:
        self.requests.append(request)
        return HTTPTransportResponse(
            status_code=404,
            headers=(),
            body=f"missing: {request.url}".encode(),
        )


class _AdvancingHTTPClock:
    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += Decimal(str(seconds))


def _internal_response(
    url: str,
    *,
    status: int,
    body: bytes,
) -> InternalHTTPResponse:
    return InternalHTTPResponse(
        requested_url=url,
        final_url=url,
        status_code=status,
        headers=(("X-Identity", "identity-sentinel"),),
        body=body,
        elapsed_seconds=0.01,
        redirects=(),
    )


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


def _configure_bug_bounty_project(
    input_dir: Path,
    scope: Path,
    *,
    excluded: bool,
) -> None:
    _project, project_file = initialize_project(
        "r2-production-default",
        "10.10.10.10",
        scope,
        input_dir,
        engagement_context="bug_bounty",
    )
    engagement_policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="2",
        maximum_http_concurrency=1,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", "R2-IDENTITY-HEADER"),
        ),
        custom_user_agent="R2-IDENTITY-UA",
        updated_at="2026-08-01T10:00:00Z",
    )
    project, _policy_path = save_project_engagement_policy(
        project_file,
        engagement_policy,
    )
    rules = [
        build_programme_scope_rule(
            rule_id="include-host",
            action=ACTION_INCLUDE,
            kind=RULE_EXACT_IPV4,
            value="10.10.10.10",
            private_note="R2-PRIVATE-NOTE",
            private_source_wording="R2-PRIVATE-SOURCE",
        )
    ]
    if excluded:
        rules.append(
            build_programme_scope_rule(
                rule_id="exclude-host",
                action=ACTION_EXCLUDE,
                kind=RULE_EXACT_IPV4,
                value="10.10.10.10",
            )
        )
    programme_policy = build_programme_scope_policy(
        rules,
        updated_at="2026-08-01T10:00:00Z",
    )
    save_project_programme_scope_policy(project_file, programme_policy)


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
