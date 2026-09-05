"""Tests for the dependency-free interactive launcher."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce.cli import main
from bugslyce.interactive import (
    QUICK_RECON_LABEL,
    _run_pipeline,
    render_recon_mode_menu,
    map_user_recon_mode_to_internal_profile,
    run_interactive_launcher,
)
from bugslyce.project_pipeline import (
    NORMAL_PIPELINE_PROFILE,
    ProjectPipelineFailed,
    STANDARD_PIPELINE_PROFILE,
)
from bugslyce.project_session import PROJECT_SCHEMA_VERSION


def test_no_args_non_interactive_prints_help(capsys) -> None:
    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "usage: bugslyce" in captured.out
    assert "doctor" in captured.out


def test_no_args_interactive_calls_launcher(monkeypatch) -> None:
    called: list[bool] = []

    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("sys.stdout", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(
        "bugslyce.cli.run_interactive_launcher",
        lambda: called.append(True) or 0,
    )

    assert main([]) == 0
    assert called == [True]


def test_recon_mode_menu_uses_user_facing_names() -> None:
    menu = render_recon_mode_menu()

    assert "Run Reconnaissance" in menu
    assert "Manual Setup Only" in menu
    assert QUICK_RECON_LABEL not in menu
    assert "Standard Recon" not in menu
    assert "Deep Recon" not in menu
    assert "Quick Safe Recon" not in menu
    assert "Standard Safe Recon" not in menu
    assert "lab-safe-tiny" not in menu
    assert "full bounded reconnaissance workflow" in menu
    assert map_user_recon_mode_to_internal_profile("1") == NORMAL_PIPELINE_PROFILE
    assert map_user_recon_mode_to_internal_profile("2") is None
    with pytest.raises(ValueError, match="Unknown recon mode"):
        map_user_recon_mode_to_internal_profile("3")
    with pytest.raises(ValueError, match="Unknown recon mode"):
        map_user_recon_mode_to_internal_profile("4")


def test_launcher_auth_abort_creates_nothing(monkeypatch, tmp_path: Path) -> None:
    def fail_scaffold(*args, **kwargs):
        raise AssertionError("scaffold must not run without exact YES")

    monkeypatch.setattr("bugslyce.interactive.scaffold_project", fail_scaffold)
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "1", "no", ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code != 0
    assert "Confirmation was not provided." in output
    assert "Confirmation must be exactly YES." in output
    assert "No project was created." in output
    assert "No commands were executed." in output
    assert "No network requests were made." in output


def test_launcher_lowercase_yes_retries_and_exact_yes_confirms(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    calls: list[str] = []
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: calls.append("scaffold")
        or _scaffold_result(project_file),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "2", "yes", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert calls == ["scaffold"]
    assert "Confirmation must be exactly YES." in output
    assert "Project created." in output


def test_launcher_invalid_target_retries_then_accepts_ipv4(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10", "10.10.10.10", "projects", "", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["target"] == "10.10.10.10"
    assert "Target must be a plain IPv4 address, hostname, or simple http/https URL." in rendered
    assert "* 10.10.10.10" in rendered
    assert "Project created." in output


def test_launcher_invalid_target_cancel_creates_nothing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: pytest.fail("scaffold must not run after target cancel"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run after target cancel"),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "https://example.com/admin", ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 2
    assert "Target entry was cancelled." in output
    assert "No project was created." in output
    assert "No commands were executed." in output
    assert "No network requests were made." in output
    assert "paths, queries, fragments, credentials" in rendered


@pytest.mark.parametrize(
    ("target_input", "expected_target"),
    [
        ("https://example.com", "example.com"),
        ("http://10.10.10.10", "10.10.10.10"),
    ],
)
def test_launcher_accepts_simple_urls_and_normalises_target(
    monkeypatch,
    tmp_path: Path,
    target_input: str,
    expected_target: str,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", target_input, "projects", "", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["target"] == expected_target
    assert f"* Input: {target_input}" in rendered
    assert f"* Target: {expected_target}" in rendered


@pytest.mark.parametrize(
    "target_input",
    [
        "https://example.com/admin",
        "https://example.com?x=1",
        "https://user:pass@example.com",
    ],
)
def test_launcher_rejects_unsafe_url_targets(
    monkeypatch,
    tmp_path: Path,
    target_input: str,
) -> None:
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: pytest.fail("scaffold must not run for invalid URL target"),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", target_input, ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 2
    assert "Target must be a plain IPv4 address, hostname, or simple http/https URL." in rendered
    assert "No project was created." in output


def test_reconnaissance_selection_runs_deep_bounded_profile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    calls: list[str] = []
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda **kwargs: calls.append(kwargs["profile"]) or SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "DEEP PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "1", "YES", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert calls == ["deep-bounded"]
    assert "DEEP PIPELINE SUMMARY" in output


def test_manual_setup_only_scaffolds_and_shows_next_without_pipeline(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    calls: list[str] = []
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: calls.append("scaffold")
        or _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.build_project_next",
        lambda path: pytest.fail("manual setup should not need low-level next preview"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert calls == ["scaffold"]
    rendered = "\n".join(output)
    assert "BugSlyce project scaffold created" in rendered
    assert "Suggested command preview:" not in rendered
    assert rendered.count("No commands were executed.") == 1
    assert rendered.count("No network requests were made.") == 1
    assert "Project created." in output
    assert "Next steps:" in output
    assert any("bugslyce project run" in line for line in output)
    assert any("bugslyce project next" in line for line in output)
    assert "No recon was run." in output


def test_start_new_project_default_projects_dir_uses_home_level_output(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("bugslyce.interactive.Path.home", lambda: home)
    expected_projects_dir = home / "bugslyce-output"
    project_file = expected_projects_dir / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}

    def fake_scaffold(**kwargs):
        received.update(kwargs)
        return _scaffold_result(project_file)

    monkeypatch.setattr("bugslyce.interactive.scaffold_project", fake_scaffold)
    output: list[str] = []
    prompts: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "", "", "2", "YES"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(inputs)

    exit_code = run_interactive_launcher(
        input_func=fake_input,
        print_func=output.append,
        cwd=tmp_path / "cwd",
    )

    rendered = "\n".join(output)
    rendered_prompts = "\n".join(prompts)
    assert exit_code == 0
    assert received["projects_dir"] == expected_projects_dir
    assert "Projects directory" in rendered_prompts
    assert "Press Enter to use default" in rendered_prompts
    assert str(expected_projects_dir) in rendered_prompts
    assert "Or type a different path:" in rendered_prompts
    assert "Project summary:" in rendered
    assert f"* Projects directory: {expected_projects_dir}" in rendered
    assert f"* Project directory: {expected_projects_dir / 'demo'}" in rendered
    assert "* Recon mode: Manual Setup Only" in rendered
    assert str(project_file) in rendered


def test_start_new_project_custom_projects_dir_still_resolves_from_cwd(
    monkeypatch,
    tmp_path: Path,
) -> None:
    expected_projects_dir = (tmp_path / "cwd" / "custom-output").resolve()
    project_file = expected_projects_dir / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}

    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "custom-output", "", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path / "cwd",
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["projects_dir"] == expected_projects_dir
    assert f"* Projects directory: {expected_projects_dir}" in rendered


def test_start_new_project_accepts_engagement_context_choice(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    output: list[str] = []
    prompts: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "2", "2", "YES"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(inputs)

    exit_code = run_interactive_launcher(
        input_func=fake_input,
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    rendered_prompts = "\n".join(prompts)
    assert exit_code == 0
    assert received["engagement_context"] == "ctf_lab"
    assert "Engagement context:" in rendered_prompts
    assert "CTF / learning lab" in rendered_prompts
    assert "* Engagement context: CTF / learning lab" in rendered


@pytest.mark.parametrize(
    ("context_input", "expected_context", "expected_label"),
    [
        ("", "unknown", "Unknown / not specified"),
        ("ctf", "ctf_lab", "CTF / learning lab"),
        ("thm", "ctf_lab", "CTF / learning lab"),
        ("bug bounty", "bug_bounty", "Bug bounty"),
        (
            "internal authorized",
            "internal_authorised",
            "Internal authorised assessment",
        ),
    ],
)
def test_start_new_project_accepts_engagement_context_aliases(
    monkeypatch,
    tmp_path: Path,
    context_input: str,
    expected_context: str,
    expected_label: str,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_policy_interactively",
        lambda *_args, **_kwargs: SimpleNamespace(saved=False, cancelled=True),
    )
    output: list[str] = []
    prompts: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", context_input, "2", "YES"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(inputs)

    exit_code = run_interactive_launcher(
        input_func=fake_input,
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    rendered_prompts = "\n".join(prompts)
    assert exit_code == 0
    assert received["engagement_context"] == expected_context
    assert "Choose engagement context [1-4, default 1]:" in rendered_prompts
    assert f"* Engagement context: {expected_label}" in rendered


def test_start_new_project_invalid_engagement_context_reprompts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: received.update(kwargs) or _scaffold_result(project_file),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "ctf maybe", "ctf", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["engagement_context"] == "ctf_lab"
    assert (
        "Please choose 1, 2, 3, 4, or press Enter for Unknown / not specified."
        in output
    )
    assert "* Engagement context: CTF / learning lab" in rendered


def test_reconnaissance_run_now_calls_pipeline(monkeypatch, tmp_path: Path) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "1", "YES", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert received["project_file"] == project_file
    assert received["profile"] == NORMAL_PIPELINE_PROFILE
    assert received["resume"] is False
    assert callable(received["progress_callback"])
    assert "PIPELINE SUMMARY" in output


def test_reconnaissance_run_now_uses_resolved_home_project_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("bugslyce.interactive.Path.home", lambda: home)
    project_file = home / "bugslyce-output" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "", "", "1", "YES", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path / "cwd",
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["project_file"] == project_file
    assert f"* Project directory: {project_file.parent}" in rendered
    assert "* Recon mode: Reconnaissance" in rendered


def test_interactive_pipeline_handles_finalisation_failure_without_failed_ordinary_step(
    tmp_path: Path,
    monkeypatch,
) -> None:
    result = SimpleNamespace(
        failed_step="PIPELINE-FINALISE",
        steps=[
            SimpleNamespace(step_id=f"PIPELINE-STEP-{index:03d}", status="completed")
            for index in range(1, 13)
        ],
    )

    def fail_finalisation(**kwargs):
        raise ProjectPipelineFailed("final output refresh failed", result)

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fail_finalisation)
    output: list[str] = []

    exit_code = _run_pipeline(
        tmp_path / "bugslyce_project.json",
        output.append,
        profile=NORMAL_PIPELINE_PROFILE,
        resume=False,
    )

    rendered = "\n".join(output)
    assert exit_code == 2
    assert "Error: final output refresh failed" in rendered
    assert "bounded collection pipeline steps had completed" in rendered
    assert "final output reconciliation or evidence-pack publication failed" in rendered
    assert "classified as failed" in rendered
    assert "No successful final evidence pack is being advertised." in rendered
    assert "Review local artefacts and pipeline diagnostics." in rendered
    assert "No later steps were executed." not in rendered


def test_interactive_pipeline_shows_ordinary_failure_cleanup_note(
    tmp_path: Path,
    monkeypatch,
) -> None:
    result = SimpleNamespace(
        failed_step="PIPELINE-STEP-012",
        steps=[SimpleNamespace(step_id="PIPELINE-STEP-012", status="failed")],
    )
    message = (
        "archive write failed. Cleanup warning: temporary export archive cleanup "
        "failed: permission denied."
    )

    def fail_export(**kwargs):
        raise ProjectPipelineFailed(message, result)

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fail_export)
    output: list[str] = []

    exit_code = _run_pipeline(
        tmp_path / "bugslyce_project.json",
        output.append,
        profile=NORMAL_PIPELINE_PROFILE,
        resume=False,
    )

    rendered = "\n".join(output)
    assert exit_code == 2
    assert f"Error: {message}" in rendered
    assert "Pipeline stopped at step PIPELINE-STEP-012." in rendered
    assert "No later steps were executed." in rendered


def test_reconnaissance_no_run_shows_command_preview(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.build_project_next",
        lambda path: pytest.fail("no-run should not need low-level next preview"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "1", "YES", "no", ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    rendered = "\n".join(output)
    assert any("bugslyce project run" in line and "--confirm" in line for line in output)
    assert all("--profile" not in line for line in output)
    assert "Reconnaissance was not started." in output
    assert "Suggested command preview:" not in rendered
    assert rendered.count("No commands were executed.") == 1
    assert rendered.count("No network requests were made.") == 1
    assert "Project created." in output


def test_resume_yes_calls_pipeline_with_resume(monkeypatch, tmp_path: Path) -> None:
    project_file = tmp_path / "project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda path: SimpleNamespace(name="demo", target="10.10.10.10"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_show",
        lambda project, path: "PROJECT SHOW",
    )
    monkeypatch.setattr(
        "bugslyce.interactive.inspect_project_status",
        lambda path, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_status",
        lambda result: "PROJECT STATUS",
    )

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["2", str(project_file), "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert received["project_file"] == project_file
    assert received["profile"] == NORMAL_PIPELINE_PROFILE
    assert received["resume"] is True
    assert "PROJECT SHOW" in output
    assert "PROJECT STATUS" in output


def test_resume_refuses_prior_standard_pipeline_profile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "project.json"
    output_dir = tmp_path / "project-output"
    output_dir.mkdir()
    (output_dir / "project_pipeline.json").write_text(
        json.dumps({"profile": STANDARD_PIPELINE_PROFILE}) + "\n",
        encoding="utf-8",
    )
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda path: SimpleNamespace(
            name="demo",
            target="10.10.10.10",
            output_dir=str(output_dir),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_show",
        lambda project, path: "PROJECT SHOW",
    )
    monkeypatch.setattr(
        "bugslyce.interactive.inspect_project_status",
        lambda path, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_status",
        lambda result: "PROJECT STATUS",
    )

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["2", str(project_file), "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 2
    assert received == {}
    assert any("Historical Quick/Standard project pipelines cannot be resumed" in line for line in output)


def test_resume_uses_prior_deep_pipeline_profile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "project.json"
    output_dir = tmp_path / "project-output"
    output_dir.mkdir()
    (output_dir / "project_pipeline.json").write_text(
        json.dumps({"profile": NORMAL_PIPELINE_PROFILE}) + "\n",
        encoding="utf-8",
    )
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda path: SimpleNamespace(
            name="demo",
            target="10.10.10.10",
            output_dir=str(output_dir),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_show",
        lambda project, path: "PROJECT SHOW",
    )
    monkeypatch.setattr(
        "bugslyce.interactive.inspect_project_status",
        lambda path, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_status",
        lambda result: "PROJECT STATUS",
    )

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_pipeline_summary",
        lambda result: "PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["2", str(project_file), "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert received["project_file"] == project_file
    assert received["profile"] == NORMAL_PIPELINE_PROFILE
    assert received["resume"] is True


def test_resume_no_shows_command_preview(monkeypatch, tmp_path: Path) -> None:
    project_file = tmp_path / "project.json"
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda path: SimpleNamespace(name="demo", target="10.10.10.10"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_show",
        lambda project, path: "PROJECT SHOW",
    )
    monkeypatch.setattr(
        "bugslyce.interactive.inspect_project_status",
        lambda path, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_status",
        lambda result: "PROJECT STATUS",
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )
    output: list[str] = []
    inputs = iter(["2", str(project_file), ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert any("--resume" in line for line in output)
    assert "No commands were executed." in output


def test_resume_preview_completed_deep_project_is_read_only_before_confirmation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file, canonical_paths = _completed_deep_project(tmp_path)
    before = {path: path.read_bytes() for path in canonical_paths}
    monkeypatch.setattr(
        "bugslyce.project_session.write_recon_status",
        lambda *args, **kwargs: pytest.fail("status preview must not write files"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run without YES"),
    )
    output: list[str] = []
    inputs = iter(["2", str(project_file), ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert "Name: demo" in rendered
    assert "Target: 10.10.10.10" in rendered
    assert "Pipeline profile: deep-bounded" in rendered
    assert "Deep pipeline phases: 2/2" in rendered
    assert "Status JSON path:" not in rendered
    assert "Status Markdown path:" not in rendered
    assert "--resume" in rendered
    assert {path: path.read_bytes() for path in canonical_paths} == before


def test_resume_confirm_completed_deep_project_keeps_preview_read_only(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file, canonical_paths = _completed_deep_project(tmp_path)
    before = {path: path.read_bytes() for path in canonical_paths}
    monkeypatch.setattr(
        "bugslyce.project_session.write_recon_status",
        lambda *args, **kwargs: pytest.fail("status preview must not write files"),
    )
    received: dict[str, object] = {}

    def fake_pipeline(**kwargs):
        received.update(kwargs)
        return SimpleNamespace(
            project_name="demo",
            target="10.10.10.10",
            profile="deep-bounded",
            project_file=str(project_file),
            output_dir=str(project_file.parent),
            resume_requested=True,
            final_status="completed",
            completed_steps=1,
            skipped_steps=13,
            no_op_steps=0,
            failed_step=None,
            report_path=str(project_file.parent / "report.md"),
            runbook_path=str(project_file.parent / "runbook.md"),
            export_path=str(project_file.parent.parent / "demo-evidence-pack.zip"),
            steps=[],
        )

    monkeypatch.setattr("bugslyce.interactive.run_project_pipeline", fake_pipeline)
    output: list[str] = []
    inputs = iter(["2", str(project_file), "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["resume"] is True
    assert received["profile"] == "deep-bounded"
    assert "* Completed: 1" in rendered
    assert "* Skipped existing: 13" in rendered
    assert "* Failed: 0" in rendered
    assert {path: path.read_bytes() for path in canonical_paths} == before


def test_list_projects_and_doctor_paths(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "bugslyce.interactive.list_projects",
        lambda path: calls.append(f"list:{path}") or SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_inventory",
        lambda result: "PROJECT LIST",
    )
    output: list[str] = []
    inputs = iter(["3", "projects"])

    assert run_interactive_launcher(lambda prompt: next(inputs), output.append, tmp_path) == 0
    assert calls == [f"list:{(tmp_path / 'projects').resolve()}"]
    assert "PROJECT LIST" in output

    monkeypatch.setattr(
        "bugslyce.interactive.build_doctor_report",
        lambda: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_doctor_text",
        lambda result: "DOCTOR REPORT",
    )
    output = []
    inputs = iter(["4"])
    assert run_interactive_launcher(lambda prompt: next(inputs), output.append, tmp_path) == 0
    assert "DOCTOR REPORT" in output


def test_list_projects_default_uses_home_level_output(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("bugslyce.interactive.Path.home", lambda: home)
    expected_projects_dir = home / "bugslyce-output"
    calls: list[Path] = []
    monkeypatch.setattr(
        "bugslyce.interactive.list_projects",
        lambda path: calls.append(path) or SimpleNamespace(),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_inventory",
        lambda result: "PROJECT LIST",
    )
    output: list[str] = []
    prompts: list[str] = []
    inputs = iter(["3", ""])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(inputs)

    exit_code = run_interactive_launcher(
        input_func=fake_input,
        print_func=output.append,
        cwd=tmp_path / "cwd",
    )

    assert exit_code == 0
    assert calls == [expected_projects_dir]
    rendered_prompts = "\n".join(prompts)
    assert "Projects directory" in rendered_prompts
    assert "Press Enter to use default" in rendered_prompts
    assert str(expected_projects_dir) in rendered_prompts
    assert "Or type a different path:" in rendered_prompts
    assert "PROJECT LIST" in output


def test_interactive_module_has_no_direct_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "bugslyce" / "interactive.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "shell=True" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source


def _scaffold_result(project_file: Path) -> SimpleNamespace:
    return SimpleNamespace(
        project=SimpleNamespace(
            name="demo",
            target="10.10.10.10",
            engagement_context="unknown",
        ),
        project_directory=str(project_file.parent),
        scope_file=str(project_file.parent / "scope.md"),
        project_file=str(project_file),
    )


def _completed_deep_project(tmp_path: Path) -> tuple[Path, tuple[Path, ...]]:
    project_dir = tmp_path / "projects" / "demo"
    project_dir.mkdir(parents=True)
    scope_file = project_dir / "scope.md"
    scope_file.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    project_file = project_dir / "bugslyce_project.json"
    project_file.write_text(
        json.dumps(
            {
                "schema_version": PROJECT_SCHEMA_VERSION,
                "name": "demo",
                "target": "10.10.10.10",
                "scope_file": str(scope_file),
                "output_dir": str(project_dir),
                "created_by": "bugslyce",
                "default_profiles": {},
                "created_at": "2026-06-15T12:00:00+00:00",
                "engagement_context": "unknown",
                "notes": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_artifacts = [
        "nmap-allports.txt",
        "nmap-services-all.txt",
        "curl-headers-10.10.10.10-80.txt",
        "curl-headers-followup-10.10.10.10-80-manual.txt",
        "gobuster-tiny-10.10.10.10-80-root.txt",
        "curl-headers-content-followup-10.10.10.10-80-admin.txt",
        "body-fetch-10.10.10.10-80-admin.html",
    ]
    for name in manifest_artifacts:
        (project_dir / name).write_text(f"{name}\n", encoding="utf-8")
    (project_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "target": "10.10.10.10",
                "profile": "deep-bounded",
                "artifacts": [
                    {
                        "type": "html" if name.endswith(".html") else "http_headers",
                        "file": name,
                    }
                    for name in manifest_artifacts
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    export_path = tmp_path / "projects" / "demo-evidence-pack.zip"
    canonical_names = (
        "report.md",
        "recon_status.md",
        "recon_status.json",
        "runbook.md",
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
        "project_pipeline.json",
        "project_pipeline.md",
    )
    for name in canonical_names:
        (project_dir / name).write_text(f"{name} original\n", encoding="utf-8")
    (project_dir / "project_pipeline.json").write_text(
        json.dumps(
            {
                "target": "10.10.10.10",
                "profile": "deep-bounded",
                "project_file": str(project_file),
                "output_dir": str(project_dir),
                "final_status": "completed",
                "export_path": str(export_path),
                "steps": [
                    {"step_id": "PIPELINE-STEP-002", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-003", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-004", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-005", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-006", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-007", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-008", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-009", "status": "noop"},
                    {"step_id": "PIPELINE-STEP-010D", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-011D", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-010", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-011", "status": "completed"},
                    {"step_id": "PIPELINE-STEP-012", "status": "completed"},
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    export_path.write_bytes(b"zip original")
    return project_file, tuple(
        [project_dir / name for name in canonical_names] + [export_path]
    )

def test_ready_bug_bounty_reconnaissance_continues_from_policy_to_scope(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    stages: list[str] = []
    prompts: list[str] = []
    output: list[str] = []

    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )

    def fake_policy(*_args, **_kwargs):
        stages.append("policy")
        return SimpleNamespace(saved=True, cancelled=False, policy=object())

    def fake_scope(*_args, **_kwargs):
        stages.append("scope")
        return 0

    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_policy_interactively",
        fake_policy,
    )
    monkeypatch.setattr(
        "bugslyce.interactive.assess_engagement_policy",
        lambda _policy: SimpleNamespace(not_ready_reasons=()),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_programme_scope",
        fake_scope,
    )
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda *_args, **_kwargs: SimpleNamespace(
            programme_scope_file="programme_scope.json",
        ),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )

    answers = iter(
        [
            "1",
            "demo",
            "10.10.10.10",
            "projects",
            "3",
            "1",
            "YES",
            "2",
            "",
        ]
    )

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    exit_code = run_interactive_launcher(
        input_func=fake_input,
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert stages == ["policy", "scope"]
    assert any("Run Reconnaissance now?" in prompt for prompt in prompts)
    assert "Reconnaissance was not started." in output


def test_programme_scope_menu_dispatches_hackerone_import_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from bugslyce.interactive import _configure_bug_bounty_programme_scope

    project_file = tmp_path / "project" / "bugslyce_project.json"
    calls: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        "bugslyce.interactive.import_hackerone_programme_scope",
        lambda project, csv_path, **_kwargs: calls.append((project, csv_path)) or 0,
    )
    output: list[str] = []
    iter_values = iter(("1", "scope.csv"))

    assert _configure_bug_bounty_programme_scope(
        project_file,
        input_func=lambda _prompt: next(iter_values),
        print_func=output.append,
        error_func=pytest.fail,
        cwd=tmp_path,
    ) == 0
    assert calls == [(project_file, tmp_path / "scope.csv")]
    assert "Import HackerOne CSV" in "\n".join(output)
    assert "Configure manually" in "\n".join(output)


def test_programme_scope_menu_preserves_manual_and_back_paths(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from bugslyce.interactive import _configure_bug_bounty_programme_scope

    project_file = tmp_path / "project" / "bugslyce_project.json"
    manual_calls: list[Path] = []
    import_calls: list[Path] = []
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_programme_scope",
        lambda project, **_kwargs: manual_calls.append(project) or 0,
    )
    monkeypatch.setattr(
        "bugslyce.interactive.import_hackerone_programme_scope",
        lambda _project, csv_path, **_kwargs: import_calls.append(csv_path) or 0,
    )
    manual_values = iter(("2",))
    back_values = iter(("3",))

    assert _configure_bug_bounty_programme_scope(
        project_file,
        input_func=lambda _prompt: next(manual_values),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        cwd=tmp_path,
    ) == 0
    assert manual_calls == [project_file]
    assert _configure_bug_bounty_programme_scope(
        project_file,
        input_func=lambda _prompt: next(back_values),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        cwd=tmp_path,
    ) is None
    assert import_calls == []


def test_csv_path_back_returns_to_scope_menu_without_calling_importer(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from bugslyce.interactive import _configure_bug_bounty_programme_scope

    project_file = tmp_path / "project" / "bugslyce_project.json"
    import_calls: list[tuple[Path, Path]] = []
    manual_calls: list[Path] = []
    monkeypatch.setattr(
        "bugslyce.interactive.import_hackerone_programme_scope",
        lambda project, csv_path, **_kwargs: import_calls.append((project, csv_path)) or 0,
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_programme_scope",
        lambda project, **_kwargs: manual_calls.append(project) or 0,
    )
    answers = iter(("1", "BACK", "2"))

    assert _configure_bug_bounty_programme_scope(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        cwd=tmp_path,
    ) == 0
    assert import_calls == []
    assert manual_calls == [project_file]


def test_programme_scope_back_stops_new_project_before_scope_completion(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    output: list[str] = []
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **_kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_policy_interactively",
        lambda *_args, **_kwargs: SimpleNamespace(
            saved=True, cancelled=False, policy=object(),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.assess_engagement_policy",
        lambda _policy: SimpleNamespace(not_ready_reasons=()),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda *_args, **_kwargs: pytest.fail("BACK must not continue scope completion"),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *_args, **_kwargs: pytest.fail("BACK must not start reconnaissance"),
    )
    answers = iter(("1", "demo", "10.10.10.10", "projects", "3", "1", "YES", "3"))

    assert run_interactive_launcher(
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
        cwd=tmp_path,
    ) == 0
    assert "Programme-scope setup was left unfinished." in "\n".join(output)


def test_ready_bug_bounty_scope_cancel_remains_fail_closed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    output: list[str] = []

    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_policy_interactively",
        lambda *_args, **_kwargs: SimpleNamespace(
            saved=True,
            cancelled=False,
            policy=object(),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.assess_engagement_policy",
        lambda _policy: SimpleNamespace(not_ready_reasons=()),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_programme_scope",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "bugslyce.interactive.load_project",
        lambda *_args, **_kwargs: SimpleNamespace(programme_scope_file=None),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )

    answers = iter(
        [
            "1",
            "demo",
            "10.10.10.10",
            "projects",
            "3",
            "1",
            "YES",
            "2",
        ]
    )

    exit_code = run_interactive_launcher(
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert "Reconnaissance was selected but not started. Programme scope was not saved." in output
    assert "No network requests were made." in output
