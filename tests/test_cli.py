"""Tests for the thin BugSlyce CLI wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.cli import main


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_cli_run_succeeds_against_basic_saas(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "cli-output"

    exit_code = main(["run", str(FIXTURES_ROOT / "basic_saas"), "--output", str(output_dir)])

    captured = capsys.readouterr()
    report_path = output_dir / "report.md"
    json_path = output_dir / "project_state.json"

    assert exit_code == 0
    assert output_dir.exists()
    assert report_path.exists()
    assert json_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["candidates"]
    assert str(report_path) in captured.out
    assert "Candidates:" in captured.out
    assert "LLM provider: none (deterministic report only)" in captured.out


def test_cli_missing_input_directory_returns_nonzero(tmp_path: Path, capsys) -> None:
    missing_input = tmp_path / "missing"
    output_dir = tmp_path / "output"

    exit_code = main(["run", str(missing_input), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "input directory does not exist" in captured.err
    assert not output_dir.exists()


def test_cli_input_path_file_returns_nonzero(tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "input.txt"
    output_dir = tmp_path / "output"
    input_file.write_text("not a directory", encoding="utf-8")

    exit_code = main(["run", str(input_file), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "input path is not a directory" in captured.err
    assert not output_dir.exists()


def test_cli_version_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "bugslyce 0.1.0" in captured.out


def test_cli_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce" in captured.out


def test_cli_run_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce run" in captured.out
    assert "--output" in captured.out


def test_cli_recon_plan_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "plan", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon plan" in captured.out
    assert "--target" in captured.out
    assert "--scope" in captured.out
    assert "--profile" in captured.out


def test_cli_recon_plan_writes_outputs(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "plan-output"

    exit_code = main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-full",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads((output / "recon_plan.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "recon_plan.md").exists()
    assert payload["profile"] == "lab-full"
    assert payload["planned_artifacts"]
    assert "No commands were executed." in captured.out


def test_cli_recon_plan_scope_failure_writes_nothing(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 192.0.2.20\n", encoding="utf-8")
    output = tmp_path / "plan-output"

    exit_code = main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-full",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "does not appear in scope file" in captured.err
    assert "No commands were executed." in captured.err
    assert not output.exists()


def test_cli_recon_plan_unsupported_profile_fails_gracefully(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "plan-output"

    exit_code = main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "unsupported",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Unsupported recon profile" in captured.err
    assert "No commands were executed." in captured.err
    assert not output.exists()


def test_cli_config_show_exits_successfully(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["config", "show"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce config" in captured.out
    assert "LLM provider: none" in captured.out


def test_cli_config_reset_uses_temp_env(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "BUGSLYCE_LLM_PROVIDER=gemini\nGEMINI_API_KEY=secret-value\nUNRELATED=value\n",
        encoding="utf-8",
    )

    exit_code = main(["config", "reset"])

    captured = capsys.readouterr()
    text = (tmp_path / ".env").read_text(encoding="utf-8")

    assert exit_code == 0
    assert "no-LLM defaults" in captured.out
    assert "BUGSLYCE_LLM_PROVIDER=none" in text
    assert "GEMINI_API_KEY=" in text
    assert "secret-value" not in text
    assert "UNRELATED=value" in text


def test_cli_run_with_default_config_still_writes_report(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output"

    exit_code = main(["run", str(FIXTURES_ROOT / "basic_saas"), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert (output_dir / "report.md").exists()
    assert (output_dir / "project_state.json").exists()
    assert "LLM provider: none" in captured.out


def test_cli_run_with_future_provider_fails_gracefully(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "BUGSLYCE_LLM_PROVIDER=gemini\nBUGSLYCE_LLM_MODEL=gemini-flash\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"

    exit_code = main(["run", str(FIXTURES_ROOT / "basic_saas"), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "LLM provider 'gemini' is configured but not implemented yet" in captured.err
    assert "bugslyce config reset" in captured.err
    assert not output_dir.exists()


def test_cli_run_with_only_scope_file_succeeds(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- `app.example-bounty.test`\n",
        encoding="utf-8",
    )

    exit_code = main(["run", str(input_dir), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert (output_dir / "report.md").exists()
    assert (output_dir / "project_state.json").exists()
    assert "Candidates:" in captured.out


def test_cli_run_with_empty_optional_files_succeeds(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    for filename in ("scope.md", "subdomains.txt", "httpx.jsonl", "urls.txt", "notes.md"):
        (input_dir / filename).write_text("", encoding="utf-8")

    exit_code = main(["run", str(input_dir), "--output", str(output_dir)])

    assert exit_code == 0
    assert (output_dir / "report.md").exists()
    assert (output_dir / "project_state.json").exists()


def test_cli_run_succeeds_against_local_lab_ip(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "lab-output"

    exit_code = main(["run", str(FIXTURES_ROOT / "local_lab_ip"), "--output", str(output_dir)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert (output_dir / "report.md").exists()
    assert (output_dir / "project_state.json").exists()
    assert "Candidates:" in captured.out
    assert "10.10.10.10" in (output_dir / "report.md").read_text(encoding="utf-8")


def test_cli_run_succeeds_against_lab_recon_pack(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "recon-pack-output"

    exit_code = main(["run", str(FIXTURES_ROOT / "lab_recon_pack"), "--output", str(output_dir)])

    assert exit_code == 0
    assert "# BugSlyce Recon Pack" in (output_dir / "report.md").read_text(encoding="utf-8")
    exported = json.loads((output_dir / "project_state.json").read_text(encoding="utf-8"))
    assert all(candidate["candidate_type"] != "manual_note_review" for candidate in exported["candidates"])


def test_cli_run_succeeds_against_raw_recon_pack(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "raw-recon-output"

    exit_code = main(["run", str(FIXTURES_ROOT / "lab_raw_recon_pack"), "--output", str(output_dir)])

    assert exit_code == 0
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    exported = json.loads((output_dir / "project_state.json").read_text(encoding="utf-8"))
    assert "# BugSlyce Recon Pack" in report
    assert exported["project_state"]["port_services"]
    assert exported["project_state"]["http_artifacts"]
    assert exported["project_state"]["discovered_paths"]
