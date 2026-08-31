"""Acceptance contract for one normal BugSlyce reconnaissance workflow."""

from __future__ import annotations

from pathlib import Path

import pytest

from bugslyce.cli import main
from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_NONE,
    SERVICE_VERSION_NOT_PERMITTED,
    build_bug_bounty_policy,
)
from bugslyce.core.programme_scope import (
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.doctor import MANUAL_MODE_ID, build_doctor_report
from bugslyce.interactive import (
    map_user_recon_mode_to_internal_profile,
    render_recon_mode_menu,
)
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    SUPPORTED_PIPELINE_PROFILES,
    run_project_pipeline,
)
from bugslyce.project_session import (
    build_project_next,
    initialize_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.content_plan import DEEP_BOUNDED_CORE_WORDLIST
from bugslyce.recon.modes import list_recon_modes


def test_operator_recon_registry_exposes_one_reconnaissance_workflow() -> None:
    assert [
        (mode.mode_id, mode.display_name, mode.internal_profile)
        for mode in list_recon_modes()
    ] == [("deep", "Reconnaissance", "deep-bounded")]


def test_project_run_defaults_to_the_full_internal_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_file = tmp_path / "bugslyce_project.json"
    project_file.write_text("{}\n", encoding="utf-8")
    received: dict[str, object] = {}
    result = object()

    def fake_pipeline(project_file=None, profile=None, **kwargs):
        received.update(kwargs)
        received["project_file"] = project_file
        received["profile"] = profile
        return result

    monkeypatch.setattr("bugslyce.cli.run_project_pipeline", fake_pipeline)
    monkeypatch.setattr(
        "bugslyce.cli.render_project_pipeline_summary",
        lambda value: "pipeline complete" if value is result else "unexpected result",
    )

    assert (
        main(
            [
                "project",
                "run",
                "--project",
                str(project_file),
                "--confirm",
            ]
        )
        == 0
    )
    assert received["profile"] == "deep-bounded"
    assert received["project_file"] == project_file


def test_new_project_pipeline_execution_supports_only_deep_bounded() -> None:
    assert SUPPORTED_PIPELINE_PROFILES == (DEEP_PIPELINE_PROFILE,)
    assert DEEP_PIPELINE_PROFILE == "deep-bounded"


@pytest.mark.parametrize("obsolete_profile", ("lab-safe-tiny", "standard-bounded"))
def test_new_project_pipeline_rejects_obsolete_execution_profiles(
    tmp_path: Path,
    obsolete_profile: str,
) -> None:
    project_file = _ready_bug_bounty_project(tmp_path)

    with pytest.raises(ValueError, match="Unsupported project pipeline profile"):
        run_project_pipeline(project_file, obsolete_profile)


def test_interactive_launcher_offers_reconnaissance_or_manual_setup_only() -> None:
    menu = render_recon_mode_menu()

    assert "Run Reconnaissance" in menu
    assert "Manual Setup Only" in menu
    assert "Quick Recon" not in menu
    assert "Standard Recon" not in menu
    assert "Deep Recon" not in menu
    assert map_user_recon_mode_to_internal_profile("1") == "deep-bounded"
    assert map_user_recon_mode_to_internal_profile("2") is None
    with pytest.raises(ValueError, match="Unknown recon mode"):
        map_user_recon_mode_to_internal_profile("3")
    with pytest.raises(ValueError, match="Unknown recon mode"):
        map_user_recon_mode_to_internal_profile("4")


def test_project_next_recommends_the_single_normal_project_run(tmp_path: Path) -> None:
    project_file = _ready_bug_bounty_project(tmp_path)

    result = build_project_next(project_file)

    command = result.recommended_action.command_preview
    assert "bugslyce project run" in command
    assert f"--project {project_file}" in command
    assert "--confirm" in command
    assert "--profile" not in command
    assert "standard-bounded" not in command


def test_doctor_exposes_one_full_reconnaissance_readiness_mode() -> None:
    report = build_doctor_report(
        which=lambda name: f"/usr/bin/{name}",
        path_exists=lambda path: path != DEEP_BOUNDED_CORE_WORDLIST,
        path_is_file=lambda path: True,
        path_is_dir=lambda path: False,
        path_is_symlink=lambda path: False,
        path_is_executable=lambda path: True,
        path_is_readable=lambda path: True,
        path_size=lambda path: 10,
        bundled_wordlist_probe=lambda: (True, "/package/lab-root-tiny.txt"),
    )

    assert [
        (mode.mode, mode.display_name, mode.status, mode.blockers)
        for mode in report.modes
        if mode.mode != MANUAL_MODE_ID
    ] == [
        (
            "deep",
            "Reconnaissance",
            "blocked",
            ("resource:deep-bounded-core",),
        )
    ]


def _ready_bug_bounty_project(tmp_path: Path) -> Path:
    scope_file = tmp_path / "scope.md"
    scope_file.write_text("# Scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "single-recon-workflow",
        "192.0.2.10",
        scope_file,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(
        project_file,
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            identification_requirement=IDENTIFICATION_NONE,
            service_version_detection=SERVICE_VERSION_NOT_PERMITTED,
            updated_at="2026-08-30T12:00:00Z",
        ),
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy(
            (
                build_programme_scope_rule(
                    rule_id="target-ip",
                    action="include",
                    kind="exact_ipv4",
                    value="192.0.2.10",
                ),
            ),
            updated_at="2026-08-30T12:00:00Z",
        ),
    )
    return project_file
