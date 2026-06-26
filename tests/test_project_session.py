"""Tests for local BugSlyce project/session management."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import shutil

import pytest

from bugslyce.core.engagement_context import (
    engagement_context_label,
    engagement_context_review_guidance,
    normalise_engagement_context,
    parse_engagement_context_choice,
)
from bugslyce.cli import main
from bugslyce.project_session import (
    PROJECT_FILENAME,
    initialize_project,
    inspect_project_status,
    load_project,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "demo_recon"
    / "lab_raw_recon_pack"
)
FIXED_TIME = datetime(2026, 6, 14, 13, 45, 12, tzinfo=timezone.utc)


def test_project_init_creates_expected_json_and_output_directory(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "nested" / "output"

    project, project_path = initialize_project(
        "smoke-test",
        "10.10.10.10",
        scope,
        output_dir,
        clock=lambda: FIXED_TIME,
    )
    payload = json.loads(project_path.read_text(encoding="utf-8"))

    assert output_dir.is_dir()
    assert project_path == output_dir / PROJECT_FILENAME
    assert payload["schema_version"] == "1.0"
    assert payload["name"] == "smoke-test"
    assert payload["target"] == "10.10.10.10"
    assert payload["scope_file"] == str(scope.resolve())
    assert payload["output_dir"] == str(output_dir.resolve())
    assert payload["created_by"] == "bugslyce"
    assert payload["created_at"] == "2026-06-14T13:45:12Z"
    assert payload["engagement_context"] == "unknown"
    assert payload["default_profiles"] == {
        "tcp_discovery": "lab-tcp-full",
        "content_discovery_smoke": "lab-root-tiny",
        "content_discovery_broader": "lab-root-light",
    }
    assert payload["notes"] == []
    assert project.target == payload["target"]
    assert project.engagement_context == "unknown"


def test_project_init_accepts_and_labels_engagement_context(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)

    project, project_path = initialize_project(
        "context-test",
        "10.10.10.10",
        scope,
        tmp_path / "output",
        engagement_context="bug_bounty",
    )
    payload = json.loads(project_path.read_text(encoding="utf-8"))

    assert project.engagement_context == "bug_bounty"
    assert payload["engagement_context"] == "bug_bounty"
    assert engagement_context_label(project.engagement_context) == "Bug bounty"


def test_project_load_defaults_missing_or_invalid_engagement_context(
    tmp_path: Path,
) -> None:
    scope = _scope_file(tmp_path)
    _project, project_path = initialize_project(
        "legacy-test",
        "10.10.10.10",
        scope,
        tmp_path / "output",
    )
    payload = json.loads(project_path.read_text(encoding="utf-8"))

    payload.pop("engagement_context")
    project_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_project(project_path).engagement_context == "unknown"

    payload["engagement_context"] = "invalid"
    project_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_project(project_path).engagement_context == "unknown"


def test_engagement_context_helpers_are_conservative() -> None:
    assert normalise_engagement_context(None) == "unknown"
    assert normalise_engagement_context("ctf-lab") == "ctf_lab"
    assert normalise_engagement_context("internal_authorised") == "internal_authorised"
    assert normalise_engagement_context("surprise") == "unknown"
    assert engagement_context_label("ctf_lab") == "CTF / learning lab"
    assert engagement_context_label("surprise") == "Unknown / not specified"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", "unknown"),
        ("1", "unknown"),
        ("unknown", "unknown"),
        ("unspecified", "unknown"),
        ("not specified", "unknown"),
        ("default", "unknown"),
        ("2", "ctf_lab"),
        ("ctf", "ctf_lab"),
        ("lab", "ctf_lab"),
        ("ctf_lab", "ctf_lab"),
        ("ctf-lab", "ctf_lab"),
        ("tryhackme", "ctf_lab"),
        ("thm", "ctf_lab"),
        ("3", "bug_bounty"),
        ("bug", "bug_bounty"),
        ("bounty", "bug_bounty"),
        ("bug bounty", "bug_bounty"),
        ("bug_bounty", "bug_bounty"),
        ("bug-bounty", "bug_bounty"),
        ("bb", "bug_bounty"),
        ("4", "internal_authorised"),
        ("internal", "internal_authorised"),
        ("internal authorised", "internal_authorised"),
        ("internal authorized", "internal_authorised"),
        ("internal_authorised", "internal_authorised"),
        ("internal_authorized", "internal_authorised"),
        ("authorised", "internal_authorised"),
        ("authorized", "internal_authorised"),
    ],
)
def test_engagement_context_choice_parser_accepts_aliases(
    value: str,
    expected: str,
) -> None:
    assert parse_engagement_context_choice(value) == expected


def test_engagement_context_choice_parser_rejects_invalid_text() -> None:
    assert parse_engagement_context_choice("ctf maybe") is None


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        (
            "unknown",
            (
                "This is a manual review signal only. Do not assume exploitability, "
                "credentials, sensitive exposure, or business impact without validation."
            ),
        ),
        (
            "ctf_lab",
            (
                "In a CTF or learning-lab context, this may be part of an intended "
                "review trail. Correlate it locally with nearby paths, source "
                "artefacts, robots.txt, and service context before drawing conclusions."
            ),
        ),
        (
            "bug_bounty",
            (
                "In a bug bounty context, treat this as low-confidence metadata unless "
                "it connects to in-scope sensitive exposure, access control, user or "
                "tenant boundaries, reproducibility, or realistic impact."
            ),
        ),
        (
            "internal_authorised",
            (
                "In an internal authorised assessment, review this against approved "
                "scope, expected service purpose, ownership, and exposure expectations "
                "before escalating."
            ),
        ),
    ],
)
def test_engagement_context_review_guidance(context: str, expected: str) -> None:
    assert engagement_context_review_guidance(context) == expected


@pytest.mark.parametrize("name", ["../escape", "bad/name", "bad name", "", "."])
def test_project_init_rejects_unsafe_names(
    tmp_path: Path,
    name: str,
) -> None:
    scope = _scope_file(tmp_path)

    with pytest.raises(ValueError, match="Project name"):
        initialize_project(name, "10.10.10.10", scope, tmp_path / "output")


@pytest.mark.parametrize(
    "target",
    [
        "*.example.com",
        "10.10.10.0/24",
        "../target",
        "not a host",
        "10.10.10",
        "10.10",
        "999.10.10.10",
        "10.10.10.999",
        ".example.com",
        "example..com",
        "http://example.com/admin",
        "https://example.com/login",
        "https://example.com/?q=test",
        "https://example.com#fragment",
        "ftp://example.com",
        "https://user:pass@example.com",
    ],
)
def test_project_init_rejects_non_single_target(
    tmp_path: Path,
    target: str,
) -> None:
    scope = _scope_file(tmp_path)

    with pytest.raises(ValueError, match="plain IPv4 address, hostname"):
        initialize_project("test", target, scope, tmp_path / "output")


def test_project_init_accepts_domain_target(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path, target="app.example.test")

    project, _path = initialize_project(
        "domain-test",
        "app.example.test",
        scope,
        tmp_path / "output",
    )

    assert project.target == "app.example.test"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("10.10.10.10", "10.10.10.10"),
        ("192.168.1.5", "192.168.1.5"),
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("target.local", "target.local"),
        ("http://10.10.10.10", "10.10.10.10"),
        ("https://10.10.10.10", "10.10.10.10"),
        ("http://example.com", "example.com"),
        ("https://example.com", "example.com"),
    ],
)
def test_project_init_accepts_and_normalises_supported_targets(
    tmp_path: Path,
    target: str,
    expected: str,
) -> None:
    scope = _scope_file(tmp_path, target=expected)

    project, _path = initialize_project("target-test", target, scope, tmp_path / "output")

    assert project.target == expected


def test_project_init_rejects_missing_scope(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Scope file does not exist"):
        initialize_project(
            "test",
            "10.10.10.10",
            tmp_path / "missing.md",
            tmp_path / "output",
        )


def test_project_init_refuses_overwrite_without_force(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "output"
    initialize_project("first", "10.10.10.10", scope, output_dir)

    with pytest.raises(ValueError, match="--force"):
        initialize_project("second", "10.10.10.10", scope, output_dir)

    project, _path = initialize_project(
        "second",
        "10.10.10.10",
        scope,
        output_dir,
        force=True,
    )
    assert project.name == "second"


def test_project_show_prints_saved_details(tmp_path: Path, capsys) -> None:
    scope = _scope_file(tmp_path)
    _project, project_path = initialize_project(
        "show-test",
        "10.10.10.10",
        scope,
        tmp_path / "output",
        clock=lambda: FIXED_TIME,
    )

    exit_code = main(["project", "show", "--project", str(project_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce project" in captured.out
    assert "Name: show-test" in captured.out
    assert "Target: 10.10.10.10" in captured.out
    assert "Engagement context: Unknown / not specified" in captured.out
    assert f"Scope file: {scope.resolve()}" in captured.out
    assert "Created at: 2026-06-14T13:45:12Z" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out


def test_project_status_handles_output_without_recon_manifest(
    tmp_path: Path,
    capsys,
) -> None:
    scope = _scope_file(tmp_path)
    _project, project_path = initialize_project(
        "not-started",
        "10.10.10.10",
        scope,
        tmp_path / "output",
    )

    result = inspect_project_status(project_path)
    exit_code = main(["project", "status", "--project", str(project_path)])
    captured = capsys.readouterr()

    assert result.recon_pack_exists is False
    assert result.recon_status is None
    assert "No recon pack exists yet" in result.next_action
    assert exit_code == 0
    assert "Recon pack exists: false" in captured.out
    assert "Engagement context: Unknown / not specified" in captured.out
    assert "Recommended first safe action" in captured.out
    assert "No commands were executed." in captured.out


def test_project_status_uses_project_output_and_scope_for_existing_pack(
    tmp_path: Path,
    capsys,
) -> None:
    output_dir = tmp_path / "output"
    shutil.copytree(FIXTURE, output_dir)
    external_scope = tmp_path / "project-scope.md"
    external_scope.write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    _project, project_path = initialize_project(
        "existing-pack",
        "10.10.10.10",
        external_scope,
        output_dir,
    )

    result = inspect_project_status(project_path)
    exit_code = main(["project", "status", "--project", str(project_path)])
    captured = capsys.readouterr()

    assert result.recon_pack_exists is True
    assert result.recon_status is not None
    assert result.recon_status.input_dir == str(output_dir.resolve())
    assert result.recon_status.scope_file == str(external_scope.resolve())
    assert result.recon_status.scope_status == "in scope"
    assert (output_dir / "recon_status.json").is_file()
    assert (output_dir / "recon_status.md").is_file()
    assert exit_code == 0
    assert "Recon pack exists: true" in captured.out
    assert "BugSlyce recon status complete" in captured.out
    assert "No network requests were made." in captured.out


def test_project_status_reports_scope_warning_from_saved_scope(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    shutil.copytree(FIXTURE, output_dir)
    scope = _scope_file(tmp_path, target="192.0.2.10")
    _project, project_path = initialize_project(
        "scope-warning",
        "10.10.10.10",
        scope,
        output_dir,
    )

    result = inspect_project_status(project_path)

    assert result.recon_status is not None
    assert result.recon_status.scope_status.startswith("warning:")


def test_load_project_rejects_missing_saved_scope(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    _project, project_path = initialize_project(
        "missing-scope",
        "10.10.10.10",
        scope,
        tmp_path / "output",
    )
    scope.unlink()

    with pytest.raises(ValueError, match="Project scope file does not exist"):
        load_project(project_path)


def test_old_project_without_created_at_still_loads_and_displays(
    tmp_path: Path,
    capsys,
) -> None:
    scope = _scope_file(tmp_path)
    _project, project_path = initialize_project(
        "old-project",
        "10.10.10.10",
        scope,
        tmp_path / "output",
        clock=lambda: FIXED_TIME,
    )
    payload = json.loads(project_path.read_text(encoding="utf-8"))
    payload.pop("created_at")
    project_path.write_text(json.dumps(payload), encoding="utf-8")

    project = load_project(project_path)
    exit_code = main(["project", "show", "--project", str(project_path)])
    captured = capsys.readouterr()

    assert project.created_at is None
    assert exit_code == 0
    assert "Created at: not recorded" in captured.out


def test_cli_project_init_prints_local_only_safety_lines(tmp_path: Path, capsys) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "output"

    exit_code = main(
        [
            "project",
            "init",
            "--name",
            "cli-test",
            "--target",
            "10.10.10.10",
            "--scope",
            str(scope),
            "--output-dir",
            str(output_dir),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "BugSlyce project initialized" in captured.out
    assert "No commands were executed." in captured.out
    assert "No network requests were made." in captured.out
    assert (output_dir / PROJECT_FILENAME).is_file()


@pytest.mark.parametrize(
    ("arguments", "usage"),
    [
        (["project", "--help"], "usage: bugslyce project"),
        (["project", "init", "--help"], "usage: bugslyce project init"),
        (["project", "show", "--help"], "usage: bugslyce project show"),
        (["project", "status", "--help"], "usage: bugslyce project status"),
    ],
)
def test_project_help_commands(arguments: list[str], usage: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(arguments)

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert usage in captured.out


def test_project_module_has_no_command_or_network_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "project_session.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def _scope_file(tmp_path: Path, target: str = "10.10.10.10") -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text(
        f"# Scope\n\n## In Scope\n\n- {target}\n",
        encoding="utf-8",
    )
    return scope
