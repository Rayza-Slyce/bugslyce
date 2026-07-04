"""Tests for the thin BugSlyce CLI wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.cli import main
from bugslyce.core.models import ReconContentDiscoveryExecutionResult
from bugslyce.recon.body_fetch import BodyFetchNoWork
from bugslyce.recon.content_followup import ContentFollowupNoWork
from bugslyce.recon.content_run import ContentDiscoveryExecutionIncomplete
from bugslyce.recon.path_followup import PathFollowupNoWork


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
    assert "bugslyce 0.3.0" in captured.out


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


def test_cli_recon_deep_readiness_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-readiness", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-readiness" in captured.out
    assert "--json" in captured.out
    assert "--target" not in captured.out
    assert "--scope" not in captured.out
    assert "--output" not in captured.out
    assert "--confirm" not in captured.out


def test_cli_recon_deep_readiness_prints_static_summary(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["recon", "deep-readiness"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("# Deep Recon Readiness Summary")
    assert "Deep Recon is planned and unavailable." in captured.out
    assert "`deep-bounded` is a planned profile contract, not an executable profile." in captured.out
    assert "This summary is static contract rendering only." in captured.out
    assert "No runtime collection is performed." in captured.out
    assert "No project files are read or written." in captured.out
    assert "No commands are executed." in captured.out
    assert "Quick Recon remains mapped to lab-safe-tiny." in captured.out
    assert "Standard Recon remains mapped to standard-bounded." in captured.out
    assert "Total planned steps: 24" in captured.out
    assert "Active collection steps: 12" in captured.out
    assert "Offline/correlation/reporting steps: 12" in captured.out
    assert "Total planned outputs: 25" in captured.out
    assert "Total preflight requirements: 22" in captured.out
    assert "Planned pipeline contract: valid" in captured.out
    assert "Planned output taxonomy: valid" in captured.out
    assert "Preflight contract: valid" in captured.out
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_readiness_prints_static_json_snapshot(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["recon", "deep-readiness", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    snapshot = json.loads(captured.out)
    assert snapshot["schema_version"] == 1
    assert snapshot["status"]["deep_available"] is False
    assert snapshot["status"]["deep_executable"] is False
    assert snapshot["mode_mappings"] == {
        "quick": "lab-safe-tiny",
        "standard": "standard-bounded",
        "deep": "deep-bounded",
    }
    assert snapshot["counts"] == {
        "planned_steps": 24,
        "active_collection_steps": 12,
        "offline_correlation_reporting_steps": 12,
        "planned_outputs": 25,
        "preflight_requirements": 22,
        "blocking_preflight_requirements": 22,
    }
    assert snapshot["validation"] == {
        "planned_pipeline_valid": True,
        "planned_pipeline_errors": [],
        "planned_outputs_valid": True,
        "planned_outputs_errors": [],
        "preflight_contract_valid": True,
        "preflight_contract_errors": [],
    }
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "extra_args",
    (
        ["--target", "10.10.10.10"],
        ["--scope", "scope.md"],
        ["--output", "deep-readiness.json"],
        ["--confirm"],
    ),
)
def test_cli_recon_deep_readiness_rejects_runtime_arguments(
    extra_args: list[str],
    capsys,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-readiness", *extra_args])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert (
        "unrecognized arguments" in captured.err
        or "ambiguous option" in captured.err
    )


def test_cli_recon_deep_metadata_plan_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-plan", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-metadata-plan" in captured.out
    assert "--service-url" in captured.out
    assert "--json" in captured.out
    assert "--max-services" in captured.out
    for forbidden in (
        "--target",
        "--scope",
        "--output",
        "--run",
        "--execute",
        "--fetch",
        "--scan",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_metadata_plan_defaults_to_empty_markdown(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["recon", "deep-metadata-plan"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("# Deep Common Metadata Request Plan")
    assert "- Planned requests: 0" in captured.out
    assert "- Skipped services: 0" in captured.out
    assert "- None." in captured.out
    assert "No network requests are performed." in captured.out
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_plan_renders_markdown_for_service_url(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "recon",
            "deep-metadata-plan",
            "--service-url",
            "https://example.test/app",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("# Deep Common Metadata Request Plan")
    assert "- Planned requests: 8" in captured.out
    assert "`deep-meta-0001` `GET` https://example.test/robots.txt" in captured.out
    assert "https://example.test/sitemap.xml" in captured.out
    assert "https://example.test/security.txt" in captured.out
    assert "https://example.test/.well-known/security.txt" in captured.out
    assert "https://example.test/humans.txt" in captured.out
    assert "https://example.test/crossdomain.xml" in captured.out
    assert "https://example.test/clientaccesspolicy.xml" in captured.out
    assert "https://example.test/favicon.ico" in captured.out
    assert "/app/robots.txt" not in captured.out
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_plan_renders_json_for_service_url(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "recon",
            "deep-metadata-plan",
            "--json",
            "--service-url",
            "https://example.test/app",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["request_count"] == 8
    assert payload["skipped_service_count"] == 0
    assert payload["requests"][0]["request_id"] == "deep-meta-0001"
    assert payload["requests"][0]["url"] == "https://example.test/robots.txt"
    assert "No network requests are performed." in payload["non_executable_guarantees"]
    assert "No output files are created." in payload["non_executable_guarantees"]
    assert _walk_keys(payload).isdisjoint(
        {"argv", "command_preview", "execute", "subprocess"}
    )
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_plan_reports_skipped_services(capsys) -> None:
    exit_code = main(
        [
            "recon",
            "deep-metadata-plan",
            "--json",
            "--service-url",
            "ftp://example.test",
            "--service-url",
            "http://",
            "--service-url",
            "https://example.test",
            "--service-url",
            "https://EXAMPLE.test/app",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["request_count"] == 8
    assert payload["skipped_services"] == [
        {
            "reason": "unsupported_scheme",
            "source": "cli-service-url",
            "url": "ftp://example.test",
        },
        {
            "reason": "malformed_url",
            "source": "cli-service-url",
            "url": "http://",
        },
        {
            "reason": "duplicate_origin",
            "source": "cli-service-url",
            "url": "https://EXAMPLE.test/app",
        },
    ]


def test_cli_recon_deep_metadata_plan_respects_max_services(capsys) -> None:
    exit_code = main(
        [
            "recon",
            "deep-metadata-plan",
            "--json",
            "--max-services",
            "1",
            "--service-url",
            "https://one.example",
            "--service-url",
            "https://two.example",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["request_count"] == 8
    assert payload["bounds"]["max_services"] == 1
    assert payload["skipped_services"] == [
        {
            "reason": "service_limit_exceeded",
            "source": "cli-service-url",
            "url": "https://two.example",
        }
    ]


def test_cli_recon_deep_metadata_plan_rejects_negative_max_services(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-plan", "--max-services", "-1"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "must be a non-negative integer" in captured.err


@pytest.mark.parametrize(
    "extra_args",
    (
        ["--target", "10.10.10.10"],
        ["--scope", "scope.md"],
        ["--scope-file", "scope.md"],
        ["--project", "bugslyce_project.json"],
        ["--input", "input.json"],
        ["--output", "plan.json"],
        ["--output-dir", "out"],
        ["--confirm"],
        ["--run"],
        ["--execute"],
        ["--fetch"],
        ["--request"],
        ["--scan"],
    ),
)
def test_cli_recon_deep_metadata_plan_rejects_runtime_arguments(
    extra_args: list[str],
    capsys,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-plan", *extra_args])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert (
        "unrecognized arguments" in captured.err
        or "ambiguous option" in captured.err
    )


def test_cli_recon_deep_metadata_review_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-review", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-metadata-review" in captured.out
    assert "--input-dir" in captured.out
    assert "Deep metadata review" in captured.out
    assert "Deep Recon" in captured.out
    assert "URL fetching" in captured.out
    for forbidden in (
        "--target",
        "--scope",
        "--output",
        "--run",
        "--execute",
        "--fetch",
        "--scan",
        "--json",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_metadata_review_renders_local_metadata_lead(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "robots-10.10.10.10-80.txt").write_text(
        "Wubbalubbadubdub\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Metadata Review")
    assert "robots.txt clue-like value observed" in captured.out
    assert "Wubbalubbadubdub" in captured.out
    assert "not confirmed findings" in captured.out
    assert before == after
    assert not (input_dir / "deep_metadata_review.md").exists()
    assert not (input_dir / "deep_metadata_review.json").exists()


def test_cli_recon_deep_metadata_review_renders_no_leads_for_minimal_project(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "minimal"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert "No Deep metadata review leads were generated" in captured.out
    assert before == after


def test_cli_recon_deep_metadata_review_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-metadata-review", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_review_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "deep-metadata-review", "--input-dir", str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"


def test_cli_recon_deep_metadata_coverage_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-coverage", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-metadata-coverage" in captured.out
    assert "--input-dir" in captured.out
    assert "Deep metadata coverage" in captured.out
    assert "Deep Recon" in captured.out
    assert "URL fetching" in captured.out
    for forbidden in (
        "--target",
        "--scope",
        "--output",
        "--run",
        "--execute",
        "--fetch",
        "--scan",
        "--json",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_metadata_coverage_renders_local_coverage_summary(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "robots-10.10.10.10-80.txt").write_text(
        "Wubbalubbadubdub\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-coverage", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Metadata Coverage")
    assert "- Planned metadata URLs: 8" in captured.out
    assert "- Collected metadata URLs: 1" in captured.out
    assert "- Planned but uncollected: 7" in captured.out
    assert "### Collected" in captured.out
    assert "### Planned But Uncollected" in captured.out
    assert "does not fetch URLs" in captured.out
    assert "does not execute Deep Recon" in captured.out
    assert "Uncollected does not imply absence" in captured.out
    assert before == after
    assert not (input_dir / "deep_metadata_coverage.md").exists()
    assert not (input_dir / "deep_metadata_coverage.json").exists()


def test_cli_recon_deep_metadata_coverage_suppresses_duplicate_origin_skip_noise(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- example.test\n",
        encoding="utf-8",
    )
    (input_dir / "robots-example.test-80.txt").write_text(
        "remember-this\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            f"http://example.test/assets/{index}.png"
            for index in range(1, 20)
        )
        + "\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-coverage", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert "## Deep Metadata Coverage" in captured.out
    assert "### Suppressed Planner Skips" in captured.out
    assert "`duplicate_origin`: 21 duplicate source URL(s) suppressed" in captured.out
    assert "http://example.test/assets/1.png" not in captured.out
    assert "http://example.test/assets/19.png" not in captured.out
    assert captured.out.count("duplicate_origin") == 1
    assert before == after
    assert not (input_dir / "deep_metadata_coverage.md").exists()
    assert not (input_dir / "deep_metadata_coverage.json").exists()


def test_cli_recon_deep_metadata_coverage_renders_zero_counts_for_minimal_project(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "minimal"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-coverage", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert "## Deep Metadata Coverage" in captured.out
    assert "- Planned metadata URLs: 0" in captured.out
    assert "- Collected metadata URLs: 0" in captured.out
    assert "- Observed metadata references: 0" in captured.out
    assert "- Planned but uncollected: 0" in captured.out
    assert before == after


def test_cli_recon_deep_metadata_coverage_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-metadata-coverage", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_coverage_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "deep-metadata-coverage", "--input-dir", str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"


def test_cli_recon_deep_eligibility_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-eligibility", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-eligibility" in captured.out
    assert "--json" in captured.out
    assert "--authorisation-declared" in captured.out
    assert "--engagement-context" in captured.out
    assert "--target " not in captured.out
    assert "--scope " not in captured.out
    assert "--output" not in captured.out
    assert "--confirm " not in captured.out


def test_cli_recon_deep_eligibility_defaults_to_blocked_markdown(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["recon", "deep-eligibility"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("# Deep Recon Eligibility")
    assert "- Status: `blocked`" in captured.out
    assert "- Eligible: `false`" in captured.out
    assert "`deep-preflight-authorisation-declared`" in captured.out
    assert "`deep-preflight-engagement-context-explicit`" in captured.out
    assert "`deep-preflight-no-inferred-scope`" in captured.out
    assert "`deep-preflight-operator-confirmation`" in captured.out
    assert "No commands are executed." in captured.out
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_eligibility_defaults_to_blocked_json(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(["recon", "deep-eligibility", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["schema_version"] == 1
    assert payload["eligible"] is False
    assert payload["status"] == "blocked"
    assert {
        reason["requirement_id"]
        for reason in payload["blocking_reasons"]
    }.issuperset(
        {
            "deep-preflight-authorisation-declared",
            "deep-preflight-engagement-context-explicit",
            "deep-preflight-no-inferred-scope",
            "deep-preflight-operator-confirmation",
        }
    )
    assert payload["non_executable_guarantees"]
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_eligibility_can_render_explicit_eligible_json(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    args = [
        "recon",
        "deep-eligibility",
        "--json",
        "--authorisation-declared",
        "--engagement-context",
        "ctf_lab",
        "--target-in-scope",
        "--scope-rules-present",
        "--scope-not-inferred",
        "--target-control-confirmed",
        "--bounds-acknowledged",
        "--no-form-submission-required",
        "--no-authentication-testing-required",
        "--no-brute-force-required",
        "--no-browser-automation-required",
        "--no-javascript-execution-required",
        "--no-payload-injection-required",
        "--no-automatic-external-reporting-required",
        "--local-retention-acknowledged",
        "--operator-confirmed-deep-intent",
    ]

    exit_code = main(args)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["eligible"] is True
    assert payload["status"] == "eligible"
    assert payload["blocking_reasons"] == []
    assert "Deep Recon remains unavailable." in payload["non_executable_guarantees"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "extra_args",
    (
        ["--target", "10.10.10.10"],
        ["--scope", "scope.md"],
        ["--scope-file", "scope.md"],
        ["--project", "bugslyce_project.json"],
        ["--input", "input.json"],
        ["--output", "eligibility.json"],
        ["--output-dir", "out"],
        ["--confirm"],
        ["--run"],
        ["--execute"],
    ),
)
def test_cli_recon_deep_eligibility_rejects_runtime_arguments(
    extra_args: list[str],
    capsys,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-eligibility", *extra_args])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert (
        "unrecognized arguments" in captured.err
        or "ambiguous option" in captured.err
    )


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


def test_cli_recon_nmap_services_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "nmap-services", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon nmap-services" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--ports" not in captured.out


def test_cli_recon_http_metadata_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "http-metadata", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon http-metadata" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--url" not in captured.out


def test_cli_recon_path_followup_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "path-followup", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon path-followup" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--url" not in captured.out


def test_cli_recon_path_followup_requires_confirm(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recon",
            "path-followup",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "requires explicit --confirm" in captured.err
    assert "No discovered-path request was executed." in captured.err


def test_cli_recon_content_plan_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "content-plan", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon content-plan" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--profile" in captured.out
    assert "--output" in captured.out
    assert "--confirm" not in captured.out


def test_cli_recon_content_run_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "content-run", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon content-run" in captured.out
    assert "--plan" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--step-id" in captured.out
    assert "--url" not in captured.out
    assert "--wordlist" not in captured.out


def test_cli_recon_content_run_requires_confirm(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recon",
            "content-run",
            "--plan",
            str(tmp_path / "content_discovery_plan.json"),
            "--scope",
            str(tmp_path / "scope.md"),
            "--step-id",
            "CONTENT-STEP-002",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "requires explicit --confirm" in captured.err
    assert "No gobuster command was executed." in captured.err


def test_cli_recon_content_followup_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "content-followup", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon content-followup" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--url" not in captured.out
    assert "--path" not in captured.out


def test_cli_recon_content_followup_requires_confirm(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recon",
            "content-followup",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "requires explicit --confirm" in captured.err
    assert "No content-result request was executed." in captured.err


def test_cli_recon_path_followup_clean_noop_returns_success(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "bugslyce.cli.run_path_followup_workflow",
        lambda **_kwargs: (_ for _ in ()).throw(PathFollowupNoWork(3)),
    )
    monkeypatch.setattr(
        "bugslyce.cli.write_path_followup_execution_result",
        lambda *_args, **_kwargs: pytest.fail("no-op should not write execution artefacts"),
    )

    exit_code = main(
        [
            "recon",
            "path-followup",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Error:" not in captured.out
    assert "Error:" not in captured.err
    assert "No eligible same-origin paths were found" in captured.out
    assert "HTTP artefacts considered: 3" in captured.out
    assert "No path-followup request was executed." in captured.out


def test_cli_recon_content_followup_clean_noop_returns_success(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "bugslyce.cli.run_content_followup_workflow",
        lambda **_kwargs: (_ for _ in ()).throw(ContentFollowupNoWork(6)),
    )

    exit_code = main(
        [
            "recon",
            "content-followup",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Error:" not in captured.out
    assert "Error:" not in captured.err
    assert "No eligible new content-discovery result URLs remain" in captured.out
    assert "Discovered paths considered: 6" in captured.out
    assert "No content-result request was executed." in captured.out


def test_cli_recon_body_fetch_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "body-fetch", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon body-fetch" in captured.out
    assert "--input-dir" in captured.out
    assert "--scope" in captured.out
    assert "--confirm" in captured.out
    assert "--url" not in captured.out
    assert "--path" not in captured.out


def test_cli_recon_body_fetch_requires_confirm(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "recon",
            "body-fetch",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "requires explicit --confirm" in captured.err
    assert "No body-fetch request was executed." in captured.err


def test_cli_recon_body_fetch_clean_noop_returns_success(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "bugslyce.cli.run_body_fetch_workflow",
        lambda **_kwargs: (_ for _ in ()).throw(BodyFetchNoWork(4)),
    )

    exit_code = main(
        [
            "recon",
            "body-fetch",
            "--input-dir",
            str(tmp_path),
            "--scope",
            str(tmp_path / "scope.md"),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Error:" not in captured.out
    assert "Error:" not in captured.err
    assert "No eligible new high-signal followed-path URLs remain" in captured.out
    assert "Followed paths considered: 4" in captured.out
    assert "No body-fetch request was executed." in captured.out
def test_cli_recon_content_run_timeout_is_honest(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    result = ReconContentDiscoveryExecutionResult(
        mode="content-run",
        plan_path=str(tmp_path / "content_discovery_plan.json"),
        target="10.10.10.10",
        profile="lab-root-tiny",
        input_dir=str(tmp_path / "private_recon" / "lab"),
        output_dir=str(tmp_path / "bugslyce-output" / "plan"),
        origins=["http://10.10.10.10/"],
        artifact_paths=[],
        manifest_path=str(tmp_path / "private_recon" / "lab" / "recon_manifest.json"),
        report_path=str(tmp_path / "private_recon" / "lab" / "report.md"),
        project_state_path=str(tmp_path / "private_recon" / "lab" / "project_state.json"),
        execution_count=1,
        commands_started=1,
        commands_completed=0,
        commands_timed_out=1,
        selected_step_id=None,
        selected_origin=None,
        partial_artifacts_imported=0,
        completed_artifacts_imported=0,
        timed_out_step_id="CONTENT-STEP-001",
        timed_out_origin="http://10.10.10.10/",
        command_results=[],
        no_recursion=True,
        no_extensions=True,
        no_arbitrary_urls=True,
        no_exploitation=True,
        warnings=[],
    )

    def fake_workflow(**_kwargs):
        raise ContentDiscoveryExecutionIncomplete(
            "Content discovery command CONTENT-STEP-001 started and exceeded 120 seconds.",
            result,
        )

    monkeypatch.setattr("bugslyce.cli.run_content_discovery_workflow", fake_workflow)

    exit_code = main(
        [
            "recon",
            "content-run",
            "--plan",
            result.plan_path,
            "--scope",
            str(tmp_path / "scope.md"),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "started and exceeded" in captured.err
    assert "Commands started: 1" in captured.err
    assert "Commands timed out: 1" in captured.err
    assert "No gobuster command was executed." not in captured.err


def test_cli_recon_content_run_forwards_selected_step(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    captured_kwargs = {}
    result = ReconContentDiscoveryExecutionResult(
        mode="content-run",
        plan_path=str(tmp_path / "content_discovery_plan.json"),
        target="10.10.10.10",
        profile="lab-root-light",
        input_dir=str(tmp_path / "private_recon" / "lab"),
        output_dir=str(tmp_path / "bugslyce-output" / "plan"),
        origins=["http://10.10.10.10:65524/"],
        artifact_paths=[],
        manifest_path=str(tmp_path / "private_recon" / "lab" / "recon_manifest.json"),
        report_path=str(tmp_path / "private_recon" / "lab" / "report.md"),
        project_state_path=str(tmp_path / "private_recon" / "lab" / "project_state.json"),
        execution_count=1,
        commands_started=1,
        commands_completed=1,
        commands_timed_out=0,
        selected_step_id="CONTENT-STEP-002",
        selected_origin="http://10.10.10.10:65524/",
        partial_artifacts_imported=0,
        completed_artifacts_imported=1,
        timed_out_step_id=None,
        timed_out_origin=None,
        command_results=[],
        no_recursion=True,
        no_extensions=True,
        no_arbitrary_urls=True,
        no_exploitation=True,
        warnings=[],
    )

    def fake_workflow(**kwargs):
        captured_kwargs.update(kwargs)
        return result

    monkeypatch.setattr("bugslyce.cli.run_content_discovery_workflow", fake_workflow)
    monkeypatch.setattr(
        "bugslyce.cli.write_content_discovery_execution_result",
        lambda *_args: (tmp_path / "execution.json", tmp_path / "execution.md"),
    )

    exit_code = main(
        [
            "recon",
            "content-run",
            "--plan",
            result.plan_path,
            "--scope",
            str(tmp_path / "scope.md"),
            "--step-id",
            "CONTENT-STEP-002",
            "--confirm",
        ]
    )

    assert exit_code == 0
    assert captured_kwargs["step_id"] == "CONTENT-STEP-002"
    assert "Selected step ID: CONTENT-STEP-002" in capsys.readouterr().out


def test_cli_recon_http_metadata_requires_confirm(tmp_path: Path, capsys) -> None:
    input_dir = tmp_path / "output"
    input_dir.mkdir()
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "http-metadata",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "requires explicit --confirm" in captured.err
    assert "No HTTP request was executed." in captured.err


def test_cli_recon_http_metadata_uses_mocked_runner_and_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    input_dir = tmp_path / "output"
    input_dir.mkdir()
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (input_dir / "nmap-services-all.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT      STATE SERVICE VERSION\n"
        "80/tcp    open  http    nginx 1.16.1\n"
        "65524/tcp open  http    Apache httpd 2.4.43\n",
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
                    {
                        "type": "nmap",
                        "file": "nmap-services-all.txt",
                        "description": "Service output",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_run(_runner, command):
        output = Path(command.output_file)
        if output.name.startswith("curl-headers-"):
            output.write_text("HTTP/1.1 200 OK\nServer: Test\n\n", encoding="utf-8")
        elif output.name.startswith("robots-"):
            output.write_text("User-agent: *\nDisallow: /private/\n", encoding="utf-8")
        else:
            output.write_text("<title>Test Service</title>", encoding="utf-8")
        from bugslyce.core.models import ReconCommandResult

        return ReconCommandResult(
            command_id=command.id,
            tool="curl",
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

    monkeypatch.setattr("bugslyce.recon.http_metadata.LiveHTTPMetadataRunner.run", fake_run)

    exit_code = main(
        [
            "recon",
            "http-metadata",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    execution = json.loads((input_dir / "recon_execution.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (input_dir / "curl-headers-10.10.10.10-80.txt").exists()
    assert (input_dir / "robots-10.10.10.10-65524.txt").exists()
    assert (input_dir / "homepage-10.10.10.10-65524.html").exists()
    assert (input_dir / "report.md").exists()
    assert (input_dir / "project_state.json").exists()
    assert (input_dir / "recon_execution.md").exists()
    assert execution["execution_count"] == 6
    assert "HTTP metadata requests were executed." in captured.out


def test_cli_recon_nmap_services_requires_confirm(tmp_path: Path, capsys) -> None:
    input_dir = tmp_path / "output"
    input_dir.mkdir()
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "nmap-services",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "requires explicit --confirm" in captured.err
    assert "No nmap command was executed." in captured.err


def test_cli_recon_nmap_services_refuses_missing_input(tmp_path: Path, capsys) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "nmap-services",
            "--input-dir",
            str(tmp_path / "missing"),
            "--scope",
            str(scope),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Input directory does not exist" in captured.err
    assert "No nmap command was executed." in captured.err


def test_cli_recon_nmap_services_uses_mocked_runner_and_writes_outputs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    input_dir = tmp_path / "output"
    input_dir.mkdir()
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (input_dir / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT      STATE SERVICE\n"
        "80/tcp    open  http\n"
        "6498/tcp  open  unknown\n"
        "65524/tcp open  unknown\n",
        encoding="utf-8",
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "created_by": "bugslyce-nmap-discover",
                "profile": "lab-tcp-full",
                "artifacts": [
                    {
                        "type": "nmap",
                        "file": "nmap-allports.txt",
                        "description": "Discovery output",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_run(_runner, command):
        service_output = Path(command.output_file)
        service_output.write_text(
            "Nmap scan report for 10.10.10.10\n"
            "PORT      STATE SERVICE VERSION\n"
            "80/tcp    open  http    nginx 1.16.1\n"
            "6498/tcp  open  ssh     OpenSSH 7.6p1\n"
            "65524/tcp open  http    Apache httpd 2.4.43\n",
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

    monkeypatch.setattr("bugslyce.recon.nmap_services.LiveNmapServiceRunner.run", fake_run)

    exit_code = main(
        [
            "recon",
            "nmap-services",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
            "--confirm",
        ]
    )

    captured = capsys.readouterr()
    execution = json.loads((input_dir / "recon_execution.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert (input_dir / "nmap-services-all.txt").exists()
    assert (input_dir / "recon_manifest.json").exists()
    assert (input_dir / "report.md").exists()
    assert (input_dir / "project_state.json").exists()
    assert (input_dir / "recon_execution.md").exists()
    assert execution["ports"] == [80, 6498, 65524]
    assert "One nmap service/version command was executed." in captured.out


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


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_walk_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for nested in value:
            keys.update(_walk_keys(nested))
        return keys
    return set()
