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


def test_cli_recon_execute_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "execute", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon execute" in captured.out
    assert "--plan" in captured.out
    assert "--dry-run" in captured.out
    assert "--passive-only" in captured.out
    assert "--input-dir" in captured.out


def test_cli_recon_preflight_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "preflight", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon preflight" in captured.out
    assert "--plan" in captured.out


def test_cli_recon_curl_headers_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "curl-headers", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon curl-headers" in captured.out
    assert "--url" in captured.out
    assert "--scope" in captured.out
    assert "--output" in captured.out
    assert "--confirm" in captured.out


def test_cli_recon_nmap_plan_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "nmap-plan", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon nmap-plan" in captured.out
    assert "--target" in captured.out
    assert "--scope" in captured.out
    assert "--profile" in captured.out
    assert "--ports" in captured.out


def test_cli_recon_nmap_discover_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "nmap-discover", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon nmap-discover" in captured.out
    assert "--target" in captured.out
    assert "--scope" in captured.out
    assert "--profile" in captured.out
    assert "--output" in captured.out
    assert "--confirm" in captured.out


def test_cli_recon_nmap_discover_requires_confirm(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    exit_code = main(
        [
            "recon",
            "nmap-discover",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-top",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "requires explicit --confirm" in captured.err
    assert "No nmap command was executed." in captured.err
    assert not output.exists()


def test_cli_recon_nmap_discover_refuses_unsupported_profile(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    exit_code = main(
        [
            "recon",
            "nmap-discover",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-service-scan",
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "supports only profiles 'lab-tcp-top' and 'lab-tcp-full'" in captured.err
    assert "No nmap command was executed." in captured.err
    assert not output.exists()


def test_cli_recon_nmap_discover_refuses_target_not_in_scope(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text(
        "# Scope\n\n## In Scope\n\n- 192.0.2.10\n\n## Out of Scope\n\n- Scanners\n",
        encoding="utf-8",
    )
    output = tmp_path / "output"

    exit_code = main(
        [
            "recon",
            "nmap-discover",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-top",
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "not explicitly listed in the supplied in-scope target entries" in captured.err
    assert "No nmap command was executed." in captured.err
    assert not output.exists()


def test_cli_recon_nmap_discover_uses_mocked_runner_and_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    def fake_run(_runner, command):
        nmap_output = Path(command.output_file)
        nmap_output.parent.mkdir(parents=True, exist_ok=True)
        nmap_output.write_text(
            "Nmap scan report for 10.10.10.10\nPORT   STATE SERVICE\n80/tcp open  http\n",
            encoding="utf-8",
        )
        from bugslyce.core.models import ReconCommandResult

        return ReconCommandResult(
            command_id=command.id,
            tool="nmap",
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:01+00:00",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=None,
        )

    monkeypatch.setattr("bugslyce.recon.nmap_discover.LiveNmapDiscoveryRunner.run", fake_run)

    exit_code = main(
        [
            "recon",
            "nmap-discover",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-top",
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    execution = json.loads((output / "recon_execution.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "nmap-top1000.txt").exists()
    assert (output / "recon_manifest.json").exists()
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert (output / "recon_execution.md").exists()
    assert execution["profile"] == "lab-tcp-top"
    assert "One nmap top-1000 TCP discovery command was executed." in captured.out


def test_cli_recon_nmap_discover_full_uses_mocked_runner_and_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    def fake_run(_runner, command):
        nmap_output = Path(command.output_file)
        nmap_output.parent.mkdir(parents=True, exist_ok=True)
        nmap_output.write_text(
            "Nmap scan report for 10.10.10.10\nPORT     STATE SERVICE\n65524/tcp open  unknown\n",
            encoding="utf-8",
        )
        from bugslyce.core.models import ReconCommandResult

        return ReconCommandResult(
            command_id=command.id,
            tool="nmap",
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:01+00:00",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=None,
        )

    monkeypatch.setattr("bugslyce.recon.nmap_discover.LiveNmapDiscoveryRunner.run", fake_run)

    exit_code = main(
        [
            "recon",
            "nmap-discover",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-full",
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    manifest = json.loads((output / "recon_manifest.json").read_text(encoding="utf-8"))
    execution = json.loads((output / "recon_execution.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "nmap-allports.txt").exists()
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert (output / "recon_execution.md").exists()
    assert manifest["profile"] == "lab-tcp-full"
    assert manifest["artifacts"][0]["file"] == "nmap-allports.txt"
    assert execution["profile"] == "lab-tcp-full"
    assert "One nmap full TCP discovery command was executed." in captured.out


def test_cli_recon_nmap_plan_writes_non_executing_outputs(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "nmap-plan"

    exit_code = main(
        [
            "recon",
            "nmap-plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-top",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads((output / "nmap_command_plan.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "nmap_command_plan.md").exists()
    assert payload["profile"]["name"] == "lab-tcp-top"
    assert payload["command"]["ready_for_execution"] is False
    assert payload["no_commands_executed"] is True
    assert "BugSlyce nmap command plan created" in captured.out
    assert "No commands were executed." in captured.out


def test_cli_recon_nmap_plan_refuses_target_not_in_scope(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")
    output = tmp_path / "nmap-plan"

    exit_code = main(
        [
            "recon",
            "nmap-plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "lab-tcp-top",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "not present in the supplied in-scope target entries" in captured.err
    assert "No commands were executed." in captured.err
    assert not output.exists()


def test_cli_recon_curl_headers_requires_confirm(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    exit_code = main(
        [
            "recon",
            "curl-headers",
            "--url",
            "http://10.10.10.10/",
            "--scope",
            str(scope),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "requires explicit --confirm" in captured.err
    assert "No network request was executed." in captured.err
    assert not output.exists()


def test_cli_recon_curl_headers_rejects_out_of_scope_host(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("- 192.0.2.20\n", encoding="utf-8")
    output = tmp_path / "output"

    exit_code = main(
        [
            "recon",
            "curl-headers",
            "--url",
            "http://10.10.10.10/",
            "--scope",
            str(scope),
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "does not appear in the supplied scope file" in captured.err
    assert not output.exists()


def test_cli_recon_curl_headers_uses_mocked_runner_and_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "output"

    def fake_run(_runner, command):
        header_path = Path(command.output_file)
        header_path.parent.mkdir(parents=True, exist_ok=True)
        header_path.write_text("HTTP/1.1 200 OK\nContent-Length: 0\n", encoding="utf-8")
        from bugslyce.core.models import ReconCommandResult

        return ReconCommandResult(
            command_id=command.id,
            tool="curl",
            exit_code=0,
            stdout_path=None,
            stderr_path=None,
            output_file=command.output_file,
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:00+00:00",
            duration_seconds=0.0,
            executed=True,
            simulated=False,
            error=None,
        )

    monkeypatch.setattr("bugslyce.recon.curl_headers.LiveCurlHeaderRunner.run", fake_run)

    exit_code = main(
        [
            "recon",
            "curl-headers",
            "--url",
            "http://10.10.10.10/",
            "--scope",
            str(scope),
            "--output",
            str(output),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    manifest = json.loads((output / "recon_manifest.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "report.md").exists()
    assert (output / "project_state.json").exists()
    assert (output / "recon_execution.json").exists()
    assert (output / "recon_execution.md").exists()
    assert manifest["artifacts"][0]["url"] == "http://10.10.10.10/"
    assert "One curl header request was executed." in captured.out
    assert "No scanners, brute force, exploitation, or content discovery were run." in captured.out


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


def test_cli_recon_execute_dry_run_writes_preview_files(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "plan-output"
    assert main(
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
    ) == 0
    capsys.readouterr()

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(output / "recon_plan.json"),
            "--dry-run",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads((output / "recon_execution_preview.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "recon_execution_preview.md").exists()
    assert payload["no_commands_executed"] is True
    assert payload["command_count"] == 7
    assert "BugSlyce recon dry-run complete" in captured.out
    assert "No commands were executed." in captured.out


def test_cli_recon_execute_without_dry_run_fails_safely(tmp_path: Path, capsys) -> None:
    plan_path = tmp_path / "recon_plan.json"
    plan_path.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "execute", "--plan", str(plan_path)])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Live recon execution is not implemented yet" in captured.err
    assert "Re-run with --dry-run" in captured.err
    assert "No commands were executed." in captured.err
    assert not (tmp_path / "recon_execution_preview.json").exists()


def test_cli_recon_execute_missing_plan_fails_safely(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(tmp_path / "missing.json"),
            "--dry-run",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Recon plan file does not exist" in captured.err
    assert "No commands were executed." in captured.err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{bad json", "invalid JSON"),
        (json.dumps({"created_by": "bugslyce-recon-planner", "steps": []}), "field 'target'"),
    ],
)
def test_cli_recon_execute_invalid_plan_fails_safely(
    tmp_path: Path,
    capsys,
    content: str,
    message: str,
) -> None:
    plan_path = tmp_path / "recon_plan.json"
    plan_path.write_text(content, encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(plan_path),
            "--dry-run",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert message in captured.err
    assert "No commands were executed." in captured.err
    assert not (tmp_path / "recon_execution_preview.json").exists()


def test_cli_recon_execute_passive_only_writes_recon_pack_and_metadata(
    tmp_path: Path,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / "passive"
    assert main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "passive-only",
            "--output",
            str(output),
        ]
    ) == 0
    capsys.readouterr()

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(output / "recon_plan.json"),
            "--passive-only",
            "--input-dir",
            str(FIXTURES_ROOT / "lab_raw_recon_pack"),
        ]
    )

    captured = capsys.readouterr()
    execution = json.loads((output / "recon_execution.json").read_text(encoding="utf-8"))
    project_state = json.loads((output / "project_state.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "report.md").exists()
    assert (output / "recon_execution.md").exists()
    assert execution["mode"] == "passive-only"
    assert execution["no_network_commands_executed"] is True
    assert project_state["project_state"]["port_services"]
    assert "BugSlyce passive execution complete" in captured.out
    assert "No network commands were executed." in captured.out


@pytest.mark.parametrize("profile", ["lab-full", "bug-bounty-standard"])
def test_cli_recon_execute_passive_only_refuses_active_plan(
    tmp_path: Path,
    capsys,
    profile: str,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / profile
    assert main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            profile,
            "--output",
            str(output),
        ]
    ) == 0
    capsys.readouterr()

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(output / "recon_plan.json"),
            "--passive-only",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert f"Plan profile '{profile}' is not passive-only" in captured.err
    assert "Live recon execution is not implemented yet" in captured.err
    assert "No network commands were executed." in captured.err
    assert not (output / "report.md").exists()


def test_cli_recon_execute_passive_only_requires_input_directory(
    tmp_path: Path,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / "passive"
    assert main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "passive-only",
            "--output",
            str(output),
        ]
    ) == 0
    capsys.readouterr()

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(output / "recon_plan.json"),
            "--passive-only",
            "--input-dir",
            str(tmp_path / "missing-input"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "input directory does not exist" in captured.err
    assert "No network commands were executed." in captured.err
    assert not (output / "report.md").exists()


def test_cli_recon_execute_passive_only_stops_on_failed_preflight(
    tmp_path: Path,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / "passive"
    assert main(
        [
            "recon",
            "plan",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--profile",
            "passive-only",
            "--output",
            str(output),
        ]
    ) == 0
    capsys.readouterr()
    plan_path = output / "recon_plan.json"
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["output_dir"] = str(Path.cwd() / "tests")
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "execute",
            "--plan",
            str(plan_path),
            "--passive-only",
            "--input-dir",
            str(FIXTURES_ROOT / "lab_raw_recon_pack"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "recon preflight failed" in captured.err
    assert "Preflight JSON path:" in captured.err
    assert "No network commands were executed." in captured.err
    assert (output / "recon_preflight.json").exists()
    assert not (output / "report.md").exists()


def test_cli_recon_preflight_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / "plan"
    assert main(
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
    ) == 0
    capsys.readouterr()
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda tool: f"/usr/bin/{tool}")

    exit_code = main(["recon", "preflight", "--plan", str(output / "recon_plan.json")])

    captured = capsys.readouterr()
    payload = json.loads((output / "recon_preflight.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (output / "recon_preflight.md").exists()
    assert payload["passed"] is True
    assert "BugSlyce recon preflight complete" in captured.out
    assert "No commands were executed." in captured.out


def test_cli_recon_preflight_returns_nonzero_on_failed_check(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Test Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    output = tmp_path / "bugslyce-output" / "plan"
    assert main(
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
    ) == 0
    capsys.readouterr()
    monkeypatch.setattr("bugslyce.recon.preflight.shutil.which", lambda _tool: None)

    exit_code = main(["recon", "preflight", "--plan", str(output / "recon_plan.json")])

    captured = capsys.readouterr()
    payload = json.loads((output / "recon_preflight.json").read_text(encoding="utf-8"))

    assert exit_code != 0
    assert payload["passed"] is False
    assert "Passed: false" in captured.out
    assert "No commands were executed." in captured.out


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
