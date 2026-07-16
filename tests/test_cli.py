"""Tests for the thin BugSlyce CLI wrapper."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from bugslyce import __version__
import bugslyce.cli as cli_module
from bugslyce.cli import main
from bugslyce.core.models import ReconContentDiscoveryExecutionResult
from bugslyce.recon.body_fetch import BodyFetchNoWork
from bugslyce.recon.content_followup import ContentFollowupNoWork
from bugslyce.recon.content_run import ContentDiscoveryExecutionIncomplete
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
    deep_metadata_collection_result_to_dict,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepHTTPResponse,
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
    DeepMetadataSkippedItem,
)
from bugslyce.recon.deep_collection_review_bundle import (
    build_deep_collection_review_bundle,
    empty_deep_metadata_collection_review_summary,
    empty_deep_source_route_collection_review_summary,
    render_deep_collection_review_bundle_markdown,
)
from bugslyce.recon.deep_metadata_collection_review import (
    build_deep_metadata_collection_review,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collection_review import (
    build_deep_source_route_collection_review,
    render_deep_source_route_collection_review_markdown,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)
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
    assert f"bugslyce {__version__}" in captured.out


def test_cli_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce" in captured.out
    assert (
        "Local-first recon triage for authorised labs, CTFs, and scoped assessments."
        in captured.out
    )


def test_cli_project_run_help_lists_all_executable_profiles(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "run", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce project run" in captured.out
    for profile in (QUICK_RECON_PROFILE, STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE):
        assert profile in captured.out
    stale_help = (
        "Approved project pipeline profile: "
        "lab-safe-tiny or standard-bounded."
    )
    assert stale_help not in captured.out
    assert "unsafe partial Deep state is refused" in captured.out


def test_cli_run_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce run" in captured.out
    assert "--output" in captured.out


def test_cli_recon_help_lists_deep_collection_review_bundle(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon" in captured.out
    assert "deep-collection-review-bundle" in captured.out


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
    assert "Deep Recon is available as bounded deep-bounded." in captured.out
    assert "`deep-bounded` is the bounded executable Deep profile." in captured.out
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
    assert snapshot["status"]["deep_available"] is True
    assert snapshot["status"]["deep_executable"] is True
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


def test_cli_recon_deep_source_route_coverage_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-source-route-coverage", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-source-route-coverage" in captured.out
    assert "--input-dir" in captured.out
    assert "Deep source/route coverage" in captured.out
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


def test_cli_recon_deep_source_route_coverage_renders_local_summary(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/assets",
                "http://10.10.10.10/assets/app.js",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-source-route-coverage", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Source/Route Coverage")
    assert "- Referenced only:" in captured.out
    assert "- Static noise:" in captured.out
    assert "- Metadata context:" in captured.out
    assert "http://10.10.10.10/login.php" in captured.out
    assert "http://10.10.10.10/assets" in captured.out
    reviewable_section = captured.out.split("### Static / Directory Context", 1)[0]
    assert "http://10.10.10.10/assets` - static_asset" not in reviewable_section
    assert "does not fetch URLs" in captured.out
    assert "does not execute Deep Recon" in captured.out
    assert "coverage view, not a finding list" in captured.out
    lowered = captured.out.lower()
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
    ):
        assert forbidden not in lowered
    assert before == after
    for forbidden_output in (
        "deep_source_route_coverage.md",
        "deep_source_route_coverage.json",
        "deep_source_route_coverage",
        "deep-source-route-coverage.md",
        "deep-source-route-coverage.json",
    ):
        assert not (input_dir / forbidden_output).exists()


def test_cli_recon_deep_source_route_coverage_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-source-route-coverage", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_source_route_coverage_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(
        ["recon", "deep-source-route-coverage", "--input-dir", str(input_file)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"
    assert not (tmp_path / "deep_source_route_coverage.md").exists()
    assert not (tmp_path / "deep_source_route_coverage.json").exists()
    assert not (tmp_path / "deep_source_route_coverage").exists()
    assert not (tmp_path / "deep-source-route-coverage.md").exists()
    assert not (tmp_path / "deep-source-route-coverage.json").exists()


def test_cli_recon_deep_source_route_coverage_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def test_cli_recon_deep_preview_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-preview", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-preview" in captured.out
    assert "--input-dir" in captured.out
    assert "Deep review bundle" in captured.out
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


def test_cli_recon_deep_preview_renders_bundle_stdout_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/assets",
                "http://10.10.10.10/assets/app.js",
                "http://10.10.10.10/api/v1/users",
                "http://10.10.10.10/actuator/health",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "robots-10.10.10.10-80.txt").write_text(
        "remember-this\n",
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(["recon", "deep-preview", "--input-dir", str(input_dir)])

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Preview Bundle")
    assert "### Summary" in captured.out
    assert "### Manual Review Priorities" in captured.out
    assert "does not fetch URLs" in captured.out
    assert "run live recon" in captured.out
    assert "execute Deep Recon" in captured.out
    assert "prioritisation view, not a finding list" in captured.out
    assert "Deep Recon was not executed" in captured.out
    lowered = captured.out.lower()
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit found",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
        "confirmed exposure",
    ):
        assert forbidden not in lowered
    assert before == after
    for forbidden_output in (
        "deep_preview.md",
        "deep_preview.json",
        "deep-preview.md",
        "deep-preview.json",
        "deep_preview",
        "deep-preview",
        "deep_preview_bundle.md",
        "deep_preview_bundle.json",
    ):
        assert not (input_dir / forbidden_output).exists()


def test_cli_recon_deep_preview_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-preview", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_preview_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "deep-preview", "--input-dir", str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No network requests were made." in captured.err
    assert "Deep Recon was not executed." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"
    assert not (tmp_path / "deep_preview.md").exists()
    assert not (tmp_path / "deep_preview.json").exists()
    assert not (tmp_path / "deep-preview.md").exists()
    assert not (tmp_path / "deep-preview.json").exists()
    assert not (tmp_path / "deep_preview").exists()
    assert not (tmp_path / "deep-preview").exists()
    assert not (tmp_path / "deep_preview_bundle.md").exists()
    assert not (tmp_path / "deep_preview_bundle.json").exists()


def test_cli_recon_deep_preview_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def test_cli_recon_deep_metadata_collect_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-collect", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-metadata-collect" in captured.out
    assert "--input-dir" in captured.out
    assert "--write-artifacts" in captured.out
    assert "metadata" in captured.out
    assert "Deep Recon" in captured.out
    assert "does not collect routes" in captured.out
    for forbidden in (
        "--target",
        "--scope",
        "--output",
        "--output-dir",
        "--json",
        "--crawl",
        "--routes",
        "--auth",
        "--forms",
        "--cookies",
        "--headers",
        "--payload",
        "--execute",
        "--deep",
        "--force",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_metadata_collect_renders_stdout_only(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "httpx.jsonl").write_text(
        '{"url":"http://10.10.10.10/","host":"10.10.10.10","status_code":200}\n',
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []

    def fake_fetcher(request, bounds):
        calls.append((request.url, request.source))
        assert bounds.max_response_bytes > 0
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("content-type", "text/plain"),),
            body=f"metadata body for {request.url}".encode("utf-8"),
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(cli_module, "urllib_deep_http_fetcher", fake_fetcher)
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(["recon", "deep-metadata-collect", "--input-dir", str(input_dir)])

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Metadata Collection Result")
    assert "### Summary" in captured.out
    assert "### Collected Metadata" in captured.out
    assert "### Skipped Requests" in captured.out
    assert "### Safety Notes" in captured.out
    assert "bounded metadata collection result" in captured.out
    assert "does not collect non-metadata routes" in captured.out
    assert "This stage produces static manual-review context only" in captured.out
    assert calls
    assert all(source == "metadata_coverage" for _, source in calls)
    assert all("/login.php" not in url for url, _ in calls)
    assert before == after
    assert not (input_dir / "deep_metadata_collection.md").exists()
    assert not (input_dir / "deep_metadata_collection.json").exists()
    for forbidden_output in (
        "deep_metadata_collection.md",
        "deep_metadata_collection.json",
        "deep-metadata-collection.md",
        "deep-metadata-collection.json",
        "deep_metadata_collection",
        "deep-metadata-collection",
        "deep_metadata",
        "deep-metadata",
        "deep",
    ):
        assert not (input_dir / forbidden_output).exists()


def test_cli_recon_deep_metadata_collect_writes_artifacts_when_requested(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "httpx.jsonl").write_text(
        '{"url":"http://10.10.10.10/","host":"10.10.10.10","status_code":200}\n',
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []
    full_body = ("metadata body for export " * 80).encode("utf-8")

    def fake_fetcher(request, bounds):
        calls.append((request.url, request.source))
        assert bounds.max_response_bytes > len(full_body)
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("content-type", "text/plain"),),
            body=full_body,
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(cli_module, "urllib_deep_http_fetcher", fake_fetcher)
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        [
            "recon",
            "deep-metadata-collect",
            "--input-dir",
            str(input_dir),
            "--write-artifacts",
        ]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    markdown_path = input_dir / "deep_metadata_collection.md"
    json_path = input_dir / "deep_metadata_collection.json"
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Metadata Collection Result")
    assert "Deep metadata collection artefacts written:" in captured.out
    assert str(markdown_path) in captured.out
    assert str(json_path) in captured.out
    assert set(after) - set(before) == {
        "deep_metadata_collection.md",
        "deep_metadata_collection.json",
    }
    assert markdown_path.read_text(encoding="utf-8").startswith(
        "## Deep Metadata Collection Result"
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["total_collected"] == len(payload["collected"])
    assert payload["total_skipped"] == len(payload["skipped"])
    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "bugslyce.deep_metadata_collection"
    assert full_body.decode("utf-8") not in json_path.read_text(encoding="utf-8")
    assert calls
    assert all(source == "metadata_coverage" for _, source in calls)
    assert all("/login.php" not in url for url, _ in calls)
    assert not (input_dir / "deep_metadata_collection").exists()
    assert not (input_dir / "deep-metadata-collection").exists()
    assert not (input_dir / "deep_metadata").exists()
    assert not (input_dir / "deep-metadata").exists()
    assert not (input_dir / "deep").exists()


def test_cli_recon_deep_metadata_collect_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-metadata-collect", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_collect_missing_input_with_write_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(
        [
            "recon",
            "deep-metadata-collect",
            "--input-dir",
            str(missing),
            "--write-artifacts",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_collect_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "deep-metadata-collect", "--input-dir", str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"
    for forbidden_output in (
        "deep_metadata_collection.md",
        "deep_metadata_collection.json",
        "deep-metadata-collection.md",
        "deep-metadata-collection.json",
        "deep_metadata_collection",
        "deep-metadata-collection",
        "deep_metadata",
        "deep-metadata",
        "deep",
    ):
        assert not (tmp_path / forbidden_output).exists()


def test_cli_recon_deep_metadata_collect_file_input_with_write_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "deep-metadata-collect",
            "--input-dir",
            str(input_file),
            "--write-artifacts",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"
    assert not (tmp_path / "deep_metadata_collection.md").exists()
    assert not (tmp_path / "deep_metadata_collection.json").exists()


def test_cli_recon_deep_metadata_collect_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def test_cli_recon_deep_source_route_collect_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-source-route-collect", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-source-route-collect" in captured.out
    assert "--input-dir" in captured.out
    assert "--write-artifacts" in captured.out
    assert "source_route_coverage" in captured.out
    assert "stdout-only by default" in captured.out
    assert "writes artefacts only when" in captured.out
    assert "explicitly supplied" in captured.out
    assert "does not crawl" in captured.out
    assert "Deep Recon" in captured.out
    for forbidden in (
        "--output",
        "--output-dir",
        "--json",
        "--target",
        "--scope",
        "--crawl",
        "--recursive",
        "--routes",
        "--auth",
        "--forms",
        "--cookies",
        "--headers",
        "--payload",
        "--execute",
        "--deep",
        "--force",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_source_route_collect_renders_stdout_only(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/admin?sort=name",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "httpx.jsonl").write_text(
        '{"url":"http://10.10.10.10/","host":"10.10.10.10","status_code":200}\n',
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []

    def fake_fetcher(request, bounds):
        calls.append((request.url, request.source))
        assert bounds.max_response_bytes > 0
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("content-type", "text/html"),),
            body=f"source route body for {request.url}".encode("utf-8"),
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(cli_module, "urllib_deep_http_fetcher", fake_fetcher)
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(["recon", "deep-source-route-collect", "--input-dir", str(input_dir)])

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Source/Route Collection Result")
    assert "### Summary" in captured.out
    assert "### Collected Source/Route Responses" in captured.out
    assert "### Skipped Requests" in captured.out
    assert "### Safety Notes" in captured.out
    assert "It collects only policy-allowed source_route_coverage requests." in captured.out
    assert "It does not crawl." in captured.out
    assert "It does not collect query-string URLs." in captured.out
    assert "This stage produces static manual-review context only." in captured.out
    assert calls
    assert all(source == "source_route_coverage" for _, source in calls)
    assert all("?" not in url for url, _ in calls)
    assert all("/robots.txt" not in url for url, _ in calls)
    assert before == after
    for forbidden_output in (
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        "deep-source-route-collection.md",
        "deep-source-route-collection.json",
        "deep_source_route_collection",
        "deep-source-route-collection",
        "deep_source_route",
        "deep-source-route",
        "deep",
    ):
        assert not (input_dir / forbidden_output).exists()


def test_cli_recon_deep_source_route_collect_writes_artifacts_when_requested(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "\n".join(
            (
                "http://10.10.10.10/",
                "http://10.10.10.10/login.php",
                "http://10.10.10.10/admin?sort=name",
                "http://10.10.10.10/robots.txt",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "httpx.jsonl").write_text(
        '{"url":"http://10.10.10.10/","host":"10.10.10.10","status_code":200}\n',
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []
    full_body = ("source route body for export " * 80).encode("utf-8")

    def fake_fetcher(request, bounds):
        calls.append((request.url, request.source))
        assert bounds.max_response_bytes > len(full_body)
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("content-type", "text/html"),),
            body=full_body,
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(cli_module, "urllib_deep_http_fetcher", fake_fetcher)
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        [
            "recon",
            "deep-source-route-collect",
            "--input-dir",
            str(input_dir),
            "--write-artifacts",
        ]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    markdown_path = input_dir / "deep_source_route_collection.md"
    json_path = input_dir / "deep_source_route_collection.json"
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Source/Route Collection Result")
    assert "Deep source/route collection artefacts written:" in captured.out
    assert str(markdown_path) in captured.out
    assert str(json_path) in captured.out
    assert set(after) - set(before) == {
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
    }
    assert markdown_path.read_text(encoding="utf-8").startswith(
        "## Deep Source/Route Collection Result"
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "bugslyce.deep_source_route_collection"
    assert isinstance(payload["collected"], list)
    assert isinstance(payload["skipped"], list)
    assert "body" not in _walk_keys(payload)
    assert full_body.decode("utf-8") not in json_path.read_text(encoding="utf-8")
    assert calls
    assert all(source == "source_route_coverage" for _, source in calls)
    assert all("?" not in url for url, _ in calls)
    assert all("/robots.txt" not in url for url, _ in calls)
    assert not (input_dir / "deep_source_route_collection").exists()
    assert not (input_dir / "deep-source-route-collection").exists()
    assert not (input_dir / "deep_source_route").exists()
    assert not (input_dir / "deep-source-route").exists()
    assert not (input_dir / "deep").exists()


def test_cli_recon_deep_source_route_collect_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["recon", "deep-source-route-collect", "--input-dir", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    _assert_deep_source_route_collection_guardrails(captured.err)
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_source_route_collect_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(["recon", "deep-source-route-collect", "--input-dir", str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    _assert_deep_source_route_collection_guardrails(captured.err)
    assert input_file.read_text(encoding="utf-8") == "{}"
    assert not (tmp_path / "deep_source_route_collection.md").exists()
    assert not (tmp_path / "deep_source_route_collection.json").exists()


def test_cli_recon_deep_source_route_collect_plan_failure_returns_nonzero(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )

    def failing_builder(_project_state):
        raise ValueError("bad local evidence")

    monkeypatch.setattr(
        cli_module,
        "build_deep_collection_request_plan_from_project_state",
        failing_builder,
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(["recon", "deep-source-route-collect", "--input-dir", str(input_dir)])

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 2
    assert "could not build Deep source/route collection plan" in captured.err
    _assert_deep_source_route_collection_guardrails(captured.err)
    assert before == after


def test_cli_recon_deep_source_route_collect_write_error_returns_nonzero(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "urls.txt").write_text(
        "http://10.10.10.10/\nhttp://10.10.10.10/login.php\n",
        encoding="utf-8",
    )

    def fake_fetcher(request, _bounds):
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(),
            body=b"source route body",
            elapsed_seconds=0.01,
        )

    def failing_writer(_result, _output_dir):
        raise OSError("disk full")

    monkeypatch.setattr(cli_module, "urllib_deep_http_fetcher", fake_fetcher)
    monkeypatch.setattr(
        cli_module,
        "write_deep_source_route_collection_artifacts",
        failing_writer,
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        [
            "recon",
            "deep-source-route-collect",
            "--input-dir",
            str(input_dir),
            "--write-artifacts",
        ]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 2
    assert captured.out.startswith("## Deep Source/Route Collection Result")
    assert "could not write Deep source/route collection artefacts" in captured.err
    assert "No crawling was performed." in captured.err
    assert "No forms were submitted." in captured.err
    assert "No authentication was attempted." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert "No files were written." not in captured.err
    assert before == after


def test_cli_recon_deep_source_route_collect_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def test_cli_recon_deep_metadata_collection_review_help_exits_successfully(
    capsys,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-metadata-collection-review", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-metadata-collection-review" in captured.out
    assert "--input-dir" in captured.out
    assert "offline" in captured.out
    assert "no HTTP requests" in captured.out
    assert "Deep Recon" in captured.out
    for forbidden in (
        "--output",
        "--output-dir",
        "--write-artifacts",
        "--json",
        "--target",
        "--scope",
        "--crawl",
        "--routes",
        "--auth",
        "--forms",
        "--cookies",
        "--headers",
        "--payload",
        "--execute",
        "--deep",
        "--force",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_metadata_collection_review_renders_stdout_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    collection_path = input_dir / DEEP_METADATA_COLLECTION_JSON
    collection_path.write_text(
        json.dumps(deep_metadata_collection_result_to_dict(_deep_collection_result())),
        encoding="utf-8",
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-metadata-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("## Deep Metadata Collection Review")
    for expected in (
        "### Summary",
        "### Status Buckets",
        "### Review Leads",
        "### Duplicate Body Signatures",
        "### Skip Reasons",
        "### Safety Notes",
        "No HTTP requests were made by this review.",
        "No files were written by this review.",
        "This stage produces static manual-review context only.",
    ):
        assert expected in captured.out
    assert before == after
    assert after == [DEEP_METADATA_COLLECTION_JSON]


def test_cli_recon_deep_metadata_collection_review_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(
        ["recon", "deep-metadata-collection-review", "--input-dir", str(missing)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_metadata_collection_review_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(
        ["recon", "deep-metadata-collection-review", "--input-dir", str(input_file)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"


def test_cli_recon_deep_metadata_collection_review_missing_json_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()

    exit_code = main(
        ["recon", "deep-metadata-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "deep_metadata_collection.json does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert sorted(path.name for path in input_dir.iterdir()) == []


def test_cli_recon_deep_metadata_collection_review_invalid_json_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    collection_path = input_dir / DEEP_METADATA_COLLECTION_JSON
    collection_path.write_text('{"schema_version": 2}', encoding="utf-8")
    before = collection_path.read_text(encoding="utf-8")

    exit_code = main(
        ["recon", "deep-metadata-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load deep metadata collection" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert collection_path.read_text(encoding="utf-8") == before
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_METADATA_COLLECTION_JSON
    ]


def test_cli_recon_deep_metadata_collection_review_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def test_cli_recon_deep_source_route_collection_review_help_exits_successfully(
    capsys,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-source-route-collection-review", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-source-route-collection-review" in captured.out
    assert "--input-dir" in captured.out
    assert "offline" in captured.out
    assert "no HTTP requests" in captured.out
    assert "Deep Recon" in captured.out
    for forbidden in (
        "--output",
        "--output-dir",
        "--write-artifacts",
        "--json",
        "--target",
        "--scope",
        "--crawl",
        "--routes",
        "--auth",
        "--forms",
        "--cookies",
        "--headers",
        "--payload",
        "--execute",
        "--deep",
        "--force",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_source_route_collection_review_renders_stdout_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    result = _deep_source_route_collection_result()
    collection_path = input_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    collection_path.write_text(
        json.dumps(deep_source_route_collection_result_to_dict(result)),
        encoding="utf-8",
    )
    expected = render_deep_source_route_collection_review_markdown(
        build_deep_source_route_collection_review(result)
    )
    before = sorted(path.name for path in input_dir.iterdir())

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    after = sorted(path.name for path in input_dir.iterdir())
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.rstrip() == expected
    assert captured.out.startswith("## Deep Source/Route Collection Review")
    assert "redirect_to_login" in captured.out
    assert "cookie_set_on_redirect" in captured.out
    assert "403_forbidden" in captured.out
    assert "query_string_route_skipped" in captured.out
    assert "metadata_request_skipped" in captured.out
    assert "EVID-PORTAL" in captured.out
    assert "EVID-SKIP" in captured.out
    assert "body-preview-portal" not in captured.out
    assert before == after
    assert after == [DEEP_SOURCE_ROUTE_COLLECTION_JSON]


def test_cli_recon_deep_source_route_collection_review_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(missing)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert list(tmp_path.iterdir()) == []


def test_cli_recon_deep_source_route_collection_review_missing_json_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "deep_source_route_collection.json does not exist" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert sorted(path.name for path in input_dir.iterdir()) == []


def test_cli_recon_deep_source_route_collection_review_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")

    exit_code = main(
        [
            "recon",
            "deep-source-route-collection-review",
            "--input-dir",
            str(input_file),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert input_file.read_text(encoding="utf-8") == "{}"


def test_cli_recon_deep_source_route_collection_review_invalid_json_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    collection_path = input_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    collection_path.write_text("{not json", encoding="utf-8")
    before = collection_path.read_text(encoding="utf-8")

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load deep source/route collection" in captured.err
    assert "No files were written." in captured.err
    assert "No directories were created." in captured.err
    assert "No HTTP requests were made." in captured.err
    assert "This stage produces static manual-review context only." in captured.err
    assert collection_path.read_text(encoding="utf-8") == before
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON
    ]


def test_cli_recon_deep_source_route_collection_review_bad_schema_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    collection_path = input_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    payload = deep_source_route_collection_result_to_dict(
        _deep_source_route_collection_result()
    )
    payload["schema_version"] = 2
    collection_path.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load deep source/route collection" in captured.err
    assert "schema_version" in captured.err
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON
    ]


def test_cli_recon_deep_source_route_collection_review_bad_generated_by_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    collection_path = input_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    payload = deep_source_route_collection_result_to_dict(
        _deep_source_route_collection_result()
    )
    payload["generated_by"] = "bugslyce.other"
    collection_path.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main(
        ["recon", "deep-source-route-collection-review", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load deep source/route collection" in captured.err
    assert "generated_by" in captured.err
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON
    ]


def test_cli_recon_deep_collection_review_bundle_help_exits_successfully(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "deep-collection-review-bundle", "--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: bugslyce recon deep-collection-review-bundle" in captured.out
    assert "--input-dir" in captured.out
    assert "unified offline review bundle" in captured.out
    assert "collection JSON artefacts" in captured.out
    assert "no HTTP requests" in captured.out
    assert "Deep Recon" in captured.out
    for forbidden in (
        "--output",
        "--output-dir",
        "--write-artifacts",
        "--json",
        "--target",
        "--scope",
        "--crawl",
        "--routes",
        "--auth",
        "--forms",
        "--cookies",
        "--headers",
        "--payload",
        "--execute",
        "--deep",
        "--force",
    ):
        assert forbidden not in captured.out


def test_cli_recon_deep_collection_review_bundle_loads_both_artifacts_stdout_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    metadata_result = _deep_collection_result()
    source_result = _deep_source_route_collection_result()
    _write_collection_payloads(
        input_dir,
        metadata_result=metadata_result,
        source_result=source_result,
    )
    expected = _expected_collection_review_bundle_markdown(
        metadata_result=metadata_result,
        source_result=source_result,
    )
    before_listing = sorted(path.name for path in input_dir.iterdir())
    before_hashes = _file_hashes(input_dir)

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.rstrip() == expected
    assert captured.out.startswith("## Deep Collection Review Bundle")
    assert "Metadata responses collected: 2" in captured.out
    assert "Source/route responses collected: 3" in captured.out
    assert "redirect_to_login" in captured.out
    assert "metadata_found" in captured.out
    assert sorted(path.name for path in input_dir.iterdir()) == before_listing
    assert _file_hashes(input_dir) == before_hashes


def test_cli_recon_deep_collection_review_bundle_metadata_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    metadata_result = _deep_collection_result()
    _write_collection_payloads(input_dir, metadata_result=metadata_result)

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Metadata responses collected: 2" in captured.out
    assert "Source/route responses collected: 0" in captured.out
    assert "metadata_found" in captured.out
    assert "source_route_collection_review" not in captured.out
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_METADATA_COLLECTION_JSON
    ]


def test_cli_recon_deep_collection_review_bundle_source_route_only(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    source_result = _deep_source_route_collection_result()
    _write_collection_payloads(input_dir, source_result=source_result)

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Metadata responses collected: 0" in captured.out
    assert "Source/route responses collected: 3" in captured.out
    assert "redirect_to_login" in captured.out
    assert "metadata_collection_review" not in captured.out
    assert sorted(path.name for path in input_dir.iterdir()) == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON
    ]


def test_cli_recon_deep_collection_review_bundle_missing_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing"

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(missing)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input directory does not exist" in captured.err
    _assert_deep_collection_review_bundle_guardrails(captured.err)
    assert list(tmp_path.iterdir()) == []
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_file_input_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_file = tmp_path / "project_state.json"
    input_file.write_text("{}", encoding="utf-8")
    before = input_file.read_text(encoding="utf-8")

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_file)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "input path is not a directory" in captured.err
    _assert_deep_collection_review_bundle_guardrails(captured.err)
    assert input_file.read_text(encoding="utf-8") == before
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_no_artifacts_returns_nonzero(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "no supported Deep collection JSON artefacts found" in captured.err
    _assert_deep_collection_review_bundle_guardrails(captured.err)
    assert sorted(path.name for path in input_dir.iterdir()) == []
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_malformed_metadata_fails(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    _write_collection_payloads(
        input_dir,
        metadata_text="{not json",
        source_result=_deep_source_route_collection_result(),
    )
    before_hashes = _file_hashes(input_dir)

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load Deep collection review bundle inputs" in captured.err
    _assert_deep_collection_review_bundle_guardrails(captured.err)
    assert _file_hashes(input_dir) == before_hashes
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_malformed_source_route_fails(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    _write_collection_payloads(
        input_dir,
        metadata_result=_deep_collection_result(),
        source_text="{not json",
    )
    before_hashes = _file_hashes(input_dir)

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load Deep collection review bundle inputs" in captured.err
    _assert_deep_collection_review_bundle_guardrails(captured.err)
    assert _file_hashes(input_dir) == before_hashes
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_invalid_metadata_schema_fails(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    payload = deep_metadata_collection_result_to_dict(_deep_collection_result())
    payload["generated_by"] = "bugslyce.other"
    _write_collection_payloads(
        input_dir,
        metadata_text=json.dumps(payload),
    )

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load Deep collection review bundle inputs" in captured.err
    assert "generated_by" in captured.err
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_invalid_source_schema_fails(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    payload = deep_source_route_collection_result_to_dict(
        _deep_source_route_collection_result()
    )
    payload["schema_version"] = 2
    _write_collection_payloads(
        input_dir,
        source_text=json.dumps(payload),
    )

    exit_code = main(
        ["recon", "deep-collection-review-bundle", "--input-dir", str(input_dir)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not load Deep collection review bundle inputs" in captured.err
    assert "schema_version" in captured.err
    assert "## Deep Collection Review Bundle" not in captured.out


def test_cli_recon_deep_collection_review_bundle_keeps_modes_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _write_collection_payloads(
    input_dir: Path,
    *,
    metadata_result: DeepMetadataCollectionResult | None = None,
    source_result: DeepSourceRouteCollectionResult | None = None,
    metadata_text: str | None = None,
    source_text: str | None = None,
) -> None:
    if metadata_result is not None:
        metadata_text = json.dumps(
            deep_metadata_collection_result_to_dict(metadata_result)
        )
    if source_result is not None:
        source_text = json.dumps(
            deep_source_route_collection_result_to_dict(source_result)
        )
    if metadata_text is not None:
        (input_dir / DEEP_METADATA_COLLECTION_JSON).write_text(
            metadata_text,
            encoding="utf-8",
        )
    if source_text is not None:
        (input_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON).write_text(
            source_text,
            encoding="utf-8",
        )


def _expected_collection_review_bundle_markdown(
    *,
    metadata_result: DeepMetadataCollectionResult | None = None,
    source_result: DeepSourceRouteCollectionResult | None = None,
) -> str:
    if metadata_result is None:
        metadata_review = empty_deep_metadata_collection_review_summary()
    else:
        metadata_review = build_deep_metadata_collection_review(metadata_result)
    if source_result is None:
        source_review = empty_deep_source_route_collection_review_summary()
    else:
        source_review = build_deep_source_route_collection_review(source_result)
    return render_deep_collection_review_bundle_markdown(
        build_deep_collection_review_bundle(metadata_review, source_review)
    )


def _file_hashes(directory: Path) -> dict[str, str]:
    return {
        path.name: sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def _assert_deep_collection_review_bundle_guardrails(stderr: str) -> None:
    assert "No files were written." in stderr
    assert "No directories were created." in stderr
    assert "No HTTP requests were made." in stderr
    assert "No collection was performed." in stderr
    assert "This stage produces static manual-review context only." in stderr


def _deep_source_route_collection_result() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(
            DeepSourceRouteCollectedItem(
                url="http://example.test/index.html",
                method="GET",
                status_code=200,
                final_url="http://example.test/index.html",
                headers=(("content-type", "text/html"),),
                body_preview="body-preview-index",
                body_sha256="index-hash",
                body_bytes=128,
                elapsed_seconds=0.03,
                source="source_route_coverage",
                reason="discovered_unfetched_application_route",
                evidence_ids=("EVID-INDEX",),
            ),
            DeepSourceRouteCollectedItem(
                url="http://example.test/portal.php",
                method="GET",
                status_code=302,
                final_url="http://example.test/portal.php",
                headers=(
                    ("Location", "/login.php"),
                    ("Set-Cookie", "session=redacted; HttpOnly"),
                ),
                body_preview="body-preview-portal",
                body_sha256="portal-hash",
                body_bytes=0,
                elapsed_seconds=0.05,
                source="source_route_coverage",
                reason="discovered_unfetched_auth_route",
                evidence_ids=("EVID-PORTAL",),
            ),
            DeepSourceRouteCollectedItem(
                url="http://example.test/server-status",
                method="GET",
                status_code=403,
                final_url="http://example.test/server-status",
                headers=(("server", "Apache"),),
                body_preview="body-preview-status",
                body_sha256="status-hash",
                body_bytes=64,
                elapsed_seconds=0.04,
                source="source_route_coverage",
                reason="discovered_unfetched_admin_or_status_route",
                evidence_ids=("EVID-STATUS",),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="http://example.test/assets?C=N",
                method="GET",
                reason="query_string_not_allowed",
                source="source_route_coverage",
                evidence_ids=("EVID-SKIP",),
            ),
            DeepSourceRouteSkippedItem(
                url="http://example.test/robots.txt",
                method="GET",
                reason="metadata_request",
                source="metadata_coverage",
                evidence_ids=("EVID-META-SKIP",),
            ),
        ),
        total_considered=5,
        total_collected=3,
        total_skipped=2,
    )


def _deep_collection_result() -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=(
            DeepMetadataCollectedItem(
                url="http://example.test/robots.txt",
                method="GET",
                status_code=200,
                final_url="http://example.test/robots.txt",
                headers=(("content-type", "text/plain"),),
                body_preview="User-agent: *",
                body_sha256="robots-hash",
                body_bytes=12,
                elapsed_seconds=0.01,
                source="metadata_coverage",
                reason="planned_uncollected_metadata",
                evidence_ids=("EVID-META-1",),
            ),
            DeepMetadataCollectedItem(
                url="http://example.test/security.txt",
                method="GET",
                status_code=404,
                final_url="http://example.test/security.txt",
                headers=(("content-type", "text/plain"),),
                body_preview="not found",
                body_sha256="missing-hash",
                body_bytes=9,
                elapsed_seconds=0.01,
                source="metadata_coverage",
                reason="planned_uncollected_metadata",
                evidence_ids=("EVID-META-2",),
            ),
        ),
        skipped=(
            DeepMetadataSkippedItem(
                url="http://example.test/login.php",
                method="GET",
                reason="non_metadata_request",
                source="source_route_coverage",
                evidence_ids=("EVID-ROUTE",),
            ),
        ),
        total_considered=3,
        total_collected=2,
        total_skipped=1,
    )


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
    assert (
        "Deep Recon is available only through the bounded deep-bounded profile."
        in payload["non_executable_guarantees"]
    )
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


def _assert_deep_source_route_collection_guardrails(stderr: str) -> None:
    assert "No files were written." in stderr
    assert "No directories were created." in stderr
    assert "No crawling was performed." in stderr
    assert "No forms were submitted." in stderr
    assert "No authentication was attempted." in stderr
    assert "This stage produces static manual-review context only." in stderr


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
