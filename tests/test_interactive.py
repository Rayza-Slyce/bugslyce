"""Tests for the dependency-free interactive launcher."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce.cli import main
from bugslyce.interactive import (
    QUICK_RECON_LABEL,
    render_recon_mode_menu,
    map_user_recon_mode_to_internal_profile,
    run_interactive_launcher,
)
from bugslyce.project_pipeline import PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE


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

    assert QUICK_RECON_LABEL in menu
    assert "Manual Setup Only" in menu
    assert "Standard Recon" in menu
    assert "Deep Recon" in menu
    assert "Quick Safe Recon" not in menu
    assert "Standard Safe Recon" not in menu
    assert "lab-safe-tiny" not in menu
    assert "Manual Review Leads" in menu
    assert "without increasing scan volume" in menu
    assert map_user_recon_mode_to_internal_profile("1") == PIPELINE_PROFILE
    assert map_user_recon_mode_to_internal_profile("2") is None
    assert map_user_recon_mode_to_internal_profile("3") == STANDARD_PIPELINE_PROFILE
    assert map_user_recon_mode_to_internal_profile("4") == "deep-bounded"


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


def test_deep_recon_selection_runs_deep_bounded_profile(
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
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "4", "YES", "YES"])

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


def test_quick_recon_run_now_calls_pipeline(monkeypatch, tmp_path: Path) -> None:
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
    assert received["profile"] == PIPELINE_PROFILE
    assert received["resume"] is False
    assert callable(received["progress_callback"])
    assert "PIPELINE SUMMARY" in output


def test_standard_recon_run_now_calls_standard_pipeline(
    monkeypatch,
    tmp_path: Path,
) -> None:
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
        lambda result: "STANDARD PIPELINE SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "3", "YES", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert received["project_file"] == project_file
    assert received["profile"] == STANDARD_PIPELINE_PROFILE
    assert received["resume"] is False
    assert "* Recon mode: Standard Recon" in rendered
    assert "STANDARD PIPELINE SUMMARY" in output


def test_quick_recon_run_now_uses_resolved_home_project_file(
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
    assert "* Recon mode: Quick Recon" in rendered


def test_quick_recon_no_run_shows_command_preview(
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
        lambda path: pytest.fail("quick no-run should not need low-level next preview"),
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
    assert any("--profile lab-safe-tiny --confirm" in line for line in output)
    assert "Quick Recon was not started." in output
    assert "Suggested command preview:" not in rendered
    assert rendered.count("No commands were executed.") == 1
    assert rendered.count("No network requests were made.") == 1
    assert "Project created." in output


def test_standard_recon_no_run_shows_standard_command_preview(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.run_project_pipeline",
        lambda *args, **kwargs: pytest.fail("pipeline must not run"),
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "", "3", "YES", ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    rendered = "\n".join(output)
    assert exit_code == 0
    assert "Standard Recon was not started." in output
    assert "To run Standard Recon later:" in rendered
    assert f"--profile {STANDARD_PIPELINE_PROFILE} --confirm" in rendered
    assert "No recon was run." in output


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
        lambda path: SimpleNamespace(),
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
    assert received["profile"] == PIPELINE_PROFILE
    assert received["resume"] is True
    assert "PROJECT SHOW" in output
    assert "PROJECT STATUS" in output


def test_resume_uses_prior_standard_pipeline_profile(
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
        lambda path: SimpleNamespace(),
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
    assert received["profile"] == STANDARD_PIPELINE_PROFILE
    assert received["resume"] is True


def test_resume_uses_prior_quick_pipeline_profile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "project.json"
    output_dir = tmp_path / "project-output"
    output_dir.mkdir()
    (output_dir / "project_pipeline.json").write_text(
        json.dumps({"profile": PIPELINE_PROFILE}) + "\n",
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
        lambda path: SimpleNamespace(),
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
    assert received["profile"] == PIPELINE_PROFILE
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
        lambda path: SimpleNamespace(),
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
