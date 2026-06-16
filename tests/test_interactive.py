"""Tests for the dependency-free interactive launcher."""

from __future__ import annotations

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
from bugslyce.project_pipeline import PIPELINE_PROFILE


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
    assert map_user_recon_mode_to_internal_profile("1") == PIPELINE_PROFILE
    assert map_user_recon_mode_to_internal_profile("2") is None
    with pytest.raises(ValueError, match="Standard Recon is not available yet"):
        map_user_recon_mode_to_internal_profile("3")
    with pytest.raises(ValueError, match="Deep Recon is not available yet"):
        map_user_recon_mode_to_internal_profile("4")


def test_launcher_auth_abort_creates_nothing(monkeypatch, tmp_path: Path) -> None:
    def fail_scaffold(*args, **kwargs):
        raise AssertionError("scaffold must not run without exact YES")

    monkeypatch.setattr("bugslyce.interactive.scaffold_project", fail_scaffold)
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "1", "no", ""])

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
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_scaffold_summary",
        lambda result: "SCAFFOLD SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "2", "yes", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert calls == ["scaffold"]
    assert "Confirmation must be exactly YES." in output
    assert "Project created." in output


def test_unavailable_recon_modes_retry_until_available(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_scaffold_summary",
        lambda result: "SCAFFOLD SUMMARY",
    )
    output: list[str] = []
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "3", "4", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert output.count("This recon mode is not available yet.") == 2
    assert output.count("Choose Quick Recon or Manual Setup Only.") == 2
    assert "Project created." in output


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
        "bugslyce.interactive.render_project_scaffold_summary",
        lambda result: "SCAFFOLD SUMMARY",
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
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "2", "YES"])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert calls == ["scaffold"]
    assert "SCAFFOLD SUMMARY" in output
    assert "Project created." in output
    assert "Next steps:" in output
    assert any("bugslyce project run" in line for line in output)
    assert any("bugslyce project next" in line for line in output)
    assert "No recon was run." in output


def test_quick_recon_run_now_calls_pipeline(monkeypatch, tmp_path: Path) -> None:
    project_file = tmp_path / "projects" / "demo" / "bugslyce_project.json"
    received: dict[str, object] = {}
    monkeypatch.setattr(
        "bugslyce.interactive.scaffold_project",
        lambda **kwargs: _scaffold_result(project_file),
    )
    monkeypatch.setattr(
        "bugslyce.interactive.render_project_scaffold_summary",
        lambda result: "SCAFFOLD SUMMARY",
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
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "1", "YES", "YES"])

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
        "bugslyce.interactive.render_project_scaffold_summary",
        lambda result: "SCAFFOLD SUMMARY",
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
    inputs = iter(["1", "demo", "10.10.10.10", "projects", "1", "YES", "no", ""])

    exit_code = run_interactive_launcher(
        input_func=lambda prompt: next(inputs),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert any("--profile lab-safe-tiny --confirm" in line for line in output)
    assert "Quick Recon was not started." in output
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
        project=SimpleNamespace(name="demo", target="10.10.10.10"),
        project_directory=str(project_file.parent),
        scope_file=str(project_file.parent / "scope.md"),
        project_file=str(project_file),
    )
