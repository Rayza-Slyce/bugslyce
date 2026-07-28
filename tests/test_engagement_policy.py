"""Tests for the R0A engagement-policy safety foundation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from bugslyce import __version__
from bugslyce.cli import main
from bugslyce.core.engagement_context import (
    CTF_LAB_CONTEXT,
    INTERNAL_AUTHORISED_CONTEXT,
    UNKNOWN_CONTEXT,
)
from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    ENGAGEMENT_POLICY_FILENAME,
    ENGAGEMENT_POLICY_SCHEMA_VERSION,
    IDENTIFICATION_HEADERS,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IDENTIFICATION_NONE,
    IDENTIFICATION_UNKNOWN,
    IDENTIFICATION_USER_AGENT,
    NOT_YET_CONFIRMED,
    PROHIBITED_IDENTIFICATION_HEADERS,
    RATE_SOURCE_PROGRAMME,
    READINESS_FUTURE_ENFORCEMENT,
    READINESS_INCOMPLETE,
    TCP_CUSTOM,
    TCP_FULL,
    IdentificationHeader,
    assess_engagement_policy,
    build_bug_bounty_policy,
    load_engagement_policy,
    normalise_tcp_port_specification,
    policy_from_dict,
    render_redacted_policy,
    validate_http_concurrency,
    validate_http_rate,
    validate_identification_header_name,
    validate_identification_value,
    write_engagement_policy,
)
from bugslyce.core.models import ProjectState
from bugslyce.engagement_policy_setup import (
    configure_project_policy_interactively,
    show_project_policy,
)
from bugslyce.interactive import run_interactive_launcher
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    PIPELINE_PROFILE,
    PipelineResult,
    PipelineStep,
    STANDARD_PIPELINE_PROFILE,
    enforce_project_execution_policy,
    render_project_pipeline_markdown,
    run_project_pipeline,
)
from bugslyce.project_session import (
    build_project_next,
    build_project_runbook,
    initialize_project,
    load_project,
    save_project_engagement_policy,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.user_agent import (
    R0B_NON_CENTRAL_USER_AGENT_CALL_SITES,
    built_in_user_agent,
)
from bugslyce.reports.html import write_html_report
from bugslyce.reports.markdown import write_project_outputs


SENTINEL_HEADER = "researcher-secret-582013"
SENTINEL_USER_AGENT = "PrivateProgrammeIdentity/582013"


def test_bug_bounty_policy_defaults_are_conservative_and_explicit() -> None:
    policy = build_bug_bounty_policy(updated_at="2026-07-28T10:00:00Z")

    assert policy.schema_version == ENGAGEMENT_POLICY_SCHEMA_VERSION
    assert policy.engagement_context == "bug_bounty"
    assert policy.programme_rules_reviewed == NOT_YET_CONFIRMED
    assert policy.automated_reconnaissance == NOT_YET_CONFIRMED
    assert policy.maximum_http_requests_per_second == "2"
    assert policy.maximum_http_concurrency == 1
    assert policy.tcp_discovery_policy == "conservative_common_web_ports"
    assert policy.identification_requirement == IDENTIFICATION_UNKNOWN
    assessment = assess_engagement_policy(policy)
    assert assessment.readiness_state == READINESS_INCOMPLETE
    assert assessment.live_execution_state == "blocked"
    assert assessment.enforcement_state == "live_enforcement_unavailable_r0a"


def test_policy_round_trip_is_deterministic_and_sensitive_repr_is_redacted() -> None:
    policy = _complete_policy()
    payload = policy.to_dict()

    assert policy_from_dict(payload) == policy
    assert json.dumps(payload, sort_keys=True) == json.dumps(
        policy_from_dict(payload).to_dict(), sort_keys=True
    )
    assert SENTINEL_HEADER not in repr(policy)
    assert SENTINEL_USER_AGENT not in repr(policy)
    assessment = assess_engagement_policy(policy)
    assert assessment.readiness_state == READINESS_FUTURE_ENFORCEMENT
    assert assessment.live_execution_state == "blocked"


@pytest.mark.parametrize("value, expected", [(1, "1"), ("2.50", "2.5"), (0.25, "0.25")])
def test_http_rate_validation_accepts_positive_finite_numbers(value, expected) -> None:
    assert validate_http_rate(value) == expected


@pytest.mark.parametrize(
    "value",
    [0, -1, "0", "-0.1", "nan", "NaN", "inf", "-Infinity", True, False, "two", None],
)
def test_http_rate_validation_rejects_unsafe_values(value) -> None:
    with pytest.raises(ValueError, match="positive finite number"):
        validate_http_rate(value)


@pytest.mark.parametrize("value, expected", [(1, 1), ("2", 2), (1000, 1000)])
def test_http_concurrency_validation(value, expected) -> None:
    assert validate_http_concurrency(value) == expected


@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, "1.5", "x", None])
def test_http_concurrency_rejects_non_positive_or_non_integral_values(value) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        validate_http_concurrency(value)


def test_programme_rate_and_higher_concurrency_require_confirmation() -> None:
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="15.5",
        http_rate_source=RATE_SOURCE_PROGRAMME,
        maximum_http_concurrency=4,
        identification_requirement=IDENTIFICATION_NONE,
    )

    assessment = assess_engagement_policy(policy)
    assert assessment.readiness_state == READINESS_INCOMPLETE
    assert any("HTTP rate" in reason for reason in assessment.not_ready_reasons)
    assert any("Concurrent automation" in reason for reason in assessment.not_ready_reasons)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("443,80,80,8000-8002", "80,443,8000-8002"),
        ("1-3,4,5", "1-5"),
        ("65535", "65535"),
    ],
)
def test_tcp_port_normalisation_is_deterministic(value: str, expected: str) -> None:
    assert normalise_tcp_port_specification(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "0", "65536", "443-80", "a", "80,,443", "1-2-3", "-1", "1-"],
)
def test_tcp_port_validation_rejects_malformed_or_out_of_range_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalise_tcp_port_specification(value)


def test_custom_and_full_tcp_policies_require_programme_confirmation() -> None:
    custom = build_bug_bounty_policy(
        tcp_discovery_policy=TCP_CUSTOM,
        custom_tcp_ports="443,8443",
    )
    full = build_bug_bounty_policy(tcp_discovery_policy=TCP_FULL)

    assert any(
        "custom TCP policy" in reason
        for reason in assess_engagement_policy(custom).not_ready_reasons
    )
    assert any(
        "Full TCP discovery" in reason
        for reason in assess_engagement_policy(full).not_ready_reasons
    )


def test_header_validation_accepts_tokens_and_rejects_duplicates_case_insensitively() -> None:
    policy = build_bug_bounty_policy(
        identification_requirement=IDENTIFICATION_HEADERS,
        identification_headers=(IdentificationHeader("X-Researcher-ID", "alice"),),
    )
    assert policy.identification_headers[0].name == "X-Researcher-ID"

    with pytest.raises(ValueError, match="unique"):
        build_bug_bounty_policy(
            identification_requirement=IDENTIFICATION_HEADERS,
            identification_headers=(
                IdentificationHeader("X-Researcher-ID", "one"),
                IdentificationHeader("x-researcher-id", "two"),
            ),
        )


@pytest.mark.parametrize("name", sorted(PROHIBITED_IDENTIFICATION_HEADERS))
def test_every_prohibited_identification_header_is_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="cannot be used"):
        validate_identification_header_name(name.swapcase())


@pytest.mark.parametrize(
    "name",
    ["", " X-Test", "X Test", "X:Test", "X\rTest", "X\nTest", "X\x00Test", "X@Test"],
)
def test_malformed_header_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="invalid"):
        validate_identification_header_name(name)


@pytest.mark.parametrize("value", ["", "a\rb", "a\nb", "a\x00b", "a\tb", "a\x7fb"])
def test_unsafe_identification_values_are_rejected_without_echo(value: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_identification_value(value, label="Custom User-Agent")
    if value:
        assert value not in str(exc_info.value)


def test_redacted_rendering_never_exposes_identification_values() -> None:
    rendered = render_redacted_policy(_complete_policy())

    assert "X-Researcher-ID: configured" in rendered
    assert "Custom User-Agent: configured" in rendered
    assert SENTINEL_HEADER not in rendered
    assert SENTINEL_USER_AGENT not in rendered
    assert "Live bug bounty reconnaissance remains blocked" in rendered


def test_policy_storage_is_atomic_private_and_refuses_symlinks(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    policy = _complete_policy()

    policy_path = write_engagement_policy(project_dir, policy)
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o600
    assert load_engagement_policy(project_dir) == policy
    assert list(project_dir.glob(".engagement_policy.*.tmp")) == []

    policy_path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    policy_path.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file, not a link"):
        write_engagement_policy(project_dir, policy)
    assert outside.read_text(encoding="utf-8") == "outside"


def test_policy_read_refuses_group_or_world_permissions(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    policy_path = write_engagement_policy(project_dir, _complete_policy())
    os.chmod(policy_path, 0o640)

    with pytest.raises(ValueError, match="owner-only mode 0600"):
        load_engagement_policy(project_dir)


def test_project_metadata_contains_only_relative_policy_reference(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    output: list[str] = []
    answers = iter(["1", "1", "1", "", "2", "1", "YES"])

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
    )
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    metadata_text = project_file.read_text(encoding="utf-8")

    assert result.saved is True
    assert payload["engagement_policy_file"] == ENGAGEMENT_POLICY_FILENAME
    assert SENTINEL_HEADER not in metadata_text
    assert SENTINEL_USER_AGENT not in metadata_text
    assert load_project(project_file).engagement_policy_file == ENGAGEMENT_POLICY_FILENAME


def test_interactive_setup_supports_multiple_headers_and_user_agent_redacted(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(
        [
            "1",  # rules reviewed
            "1",  # automation permitted
            "1",  # conservative rate
            "",  # concurrency 1
            "2",  # conservative TCP
            "4",  # headers and User-Agent
            "X-Researcher-ID",
            SENTINEL_HEADER,
            "YES",
            "X-Programme",
            "authorised-lab",
            "",
            SENTINEL_USER_AGENT,
            "YES",  # save
        ]
    )
    output: list[str] = []

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
    )
    rendered = "\n".join(output)
    stored = load_engagement_policy(project_file.parent)

    assert result.saved is True
    assert stored.identification_requirement == IDENTIFICATION_HEADERS_AND_USER_AGENT
    assert [header.name for header in stored.identification_headers] == [
        "X-Researcher-ID",
        "X-Programme",
    ]
    assert SENTINEL_HEADER not in rendered
    assert SENTINEL_USER_AGENT not in rendered
    assert "X-Researcher-ID: configured" in rendered
    assert "Live bug bounty reconnaissance remains blocked" in rendered


def test_unreviewed_rules_save_incomplete_policy_without_later_questions(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(["2", "YES"])
    output: list[str] = []

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
    )

    assert result.saved is True
    assert result.policy is not None
    assert assess_engagement_policy(result.policy).readiness_state == READINESS_INCOMPLETE
    assert "live recon cannot begin" in "\n".join(output)


def test_policy_setup_cancellation_writes_nothing(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: "3",
        print_func=lambda _message: None,
    )

    assert result.cancelled is True
    assert not (project_file.parent / ENGAGEMENT_POLICY_FILENAME).exists()


def test_existing_policy_requires_deliberate_revision_and_normal_view_is_redacted(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    write_engagement_policy(project_file.parent, _complete_policy())

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: "",
        print_func=lambda _message: None,
    )
    rendered = show_project_policy(project_file)

    assert result.cancelled is True
    assert SENTINEL_HEADER not in rendered
    assert SENTINEL_USER_AGENT not in rendered
    assert "configured" in rendered


def test_existing_sensitive_values_are_preserved_only_after_deliberate_update(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    write_engagement_policy(project_file.parent, _complete_policy())
    answers = iter(
        [
            "YES",  # deliberately revise
            "1",  # rules reviewed
            "1",  # automation permitted
            "1",  # conservative rate
            "",  # concurrency one
            "2",  # conservative TCP
            "4",  # headers and User-Agent
            "",  # retain headers
            "",  # retain User-Agent
            "YES",  # save
        ]
    )

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=lambda _message: None,
    )
    stored = load_engagement_policy(project_file.parent)

    assert result.saved is True
    assert stored.identification_headers[0].value == SENTINEL_HEADER
    assert stored.custom_user_agent == SENTINEL_USER_AGENT


def test_wizard_programme_rate_higher_concurrency_and_custom_ports_need_confirmation(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(
        [
            "1",
            "1",
            "2",
            "8.5",
            "YES",
            "3",
            "YES",
            "3",
            "443,8000-8002",
            "YES",
            "1",
            "YES",
        ]
    )

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=lambda _message: None,
    )

    assert result.policy is not None
    assert result.policy.maximum_http_requests_per_second == "8.5"
    assert result.policy.maximum_http_concurrency == 3
    assert result.policy.custom_tcp_ports == "443,8000-8002"
    assert (
        assess_engagement_policy(result.policy).readiness_state
        == READINESS_FUTURE_ENFORCEMENT
    )


@pytest.mark.parametrize("permission_choice", ["2", "3"])
def test_wizard_automation_not_permitted_or_unknown_is_saved_incomplete(
    tmp_path: Path,
    permission_choice: str,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(["1", permission_choice, "YES"])

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=lambda _message: None,
    )

    assert result.saved is True
    assert result.policy is not None
    assert assess_engagement_policy(result.policy).readiness_state == READINESS_INCOMPLETE


def test_wizard_identification_requirements_unknown_remains_incomplete(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(["1", "1", "1", "", "2", "5", "YES"])

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=lambda _message: None,
    )

    assert result.policy is not None
    assert result.policy.identification_requirement == IDENTIFICATION_UNKNOWN
    assert assess_engagement_policy(result.policy).readiness_state == READINESS_INCOMPLETE


def test_wizard_supports_dedicated_custom_user_agent(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(["1", "1", "1", "", "2", "3", SENTINEL_USER_AGENT, "YES"])
    output: list[str] = []

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
    )

    assert result.policy is not None
    assert result.policy.identification_requirement == IDENTIFICATION_USER_AGENT
    assert result.policy.custom_user_agent == SENTINEL_USER_AGENT
    assert SENTINEL_USER_AGENT not in "\n".join(output)


def test_loading_legacy_project_does_not_rewrite_or_fabricate_policy_reference(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "legacy-scope.md"
    scope.write_text("## In Scope\n- 10.10.10.10\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "legacy-policy",
        "10.10.10.10",
        scope,
        tmp_path / "legacy",
        engagement_context="bug_bounty",
    )
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload.pop("engagement_policy_file", None)
    legacy_bytes = (json.dumps(payload, sort_keys=True) + "\n").encode()
    project_file.write_bytes(legacy_bytes)

    loaded = load_project(project_file)

    assert loaded.engagement_policy_file is None
    assert project_file.read_bytes() == legacy_bytes


def test_built_in_user_agent_uses_current_version_and_not_stale_identity() -> None:
    value = built_in_user_agent()

    assert value == f"BugSlyce/{__version__} authorised-recon"
    assert "BugSlyce/0.3" not in value
    assert R0B_NON_CENTRAL_USER_AGENT_CALL_SITES == (
        "bugslyce.recon.deep_http_fetcher.USER_AGENT",
    )


@pytest.mark.parametrize(
    "profile",
    [PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE],
)
def test_bug_bounty_pipeline_profiles_refuse_before_doctor_or_runner(
    tmp_path: Path,
    monkeypatch,
    profile: str,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    write_engagement_policy(project_file.parent, _complete_policy())
    called = False

    def fail_doctor():
        nonlocal called
        called = True
        raise AssertionError("doctor and collection setup must not be reached")

    monkeypatch.setattr("bugslyce.project_pipeline.build_doctor_report", fail_doctor)

    with pytest.raises(ValueError, match="blocked in R0A") as exc_info:
        run_project_pipeline(project_file, profile)

    assert called is False
    assert "not yet enforced" in str(exc_info.value)
    assert "R0B" in str(exc_info.value)


def test_old_bug_bounty_project_without_policy_is_blocked_before_live_work(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload.pop("engagement_policy_file", None)
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    called = False

    def fail_doctor():
        nonlocal called
        called = True
        raise AssertionError("live setup must not be reached")

    monkeypatch.setattr("bugslyce.project_pipeline.build_doctor_report", fail_doctor)
    with pytest.raises(ValueError, match="Engagement policy is missing"):
        run_project_pipeline(project_file, PIPELINE_PROFILE)
    assert called is False


def test_direct_cli_run_reports_non_bypassable_bug_bounty_refusal(
    tmp_path: Path,
    capsys,
) -> None:
    project_file = _bug_bounty_project(tmp_path)

    exit_code = main(
        [
            "project",
            "run",
            "--project",
            str(project_file),
            "--profile",
            PIPELINE_PROFILE,
            "--confirm",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "blocked in R0A" in captured.err
    assert "No pipeline phase was executed" in captured.err


@pytest.mark.parametrize("mode_choice", ["1", "3", "4"])
def test_interactive_bug_bounty_quick_standard_and_deep_are_save_only(
    tmp_path: Path,
    monkeypatch,
    mode_choice: str,
) -> None:
    monkeypatch.setattr(
        "bugslyce.interactive._run_pipeline",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("interactive live pipeline must not be called")
        ),
    )
    answers = iter(
        [
            "1",
            "bounty-test",
            "10.10.10.10",
            "projects",
            "3",
            mode_choice,
            "YES",
            "2",
            "YES",
        ]
    )
    output: list[str] = []

    exit_code = run_interactive_launcher(
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
        cwd=tmp_path,
    )
    rendered = "\n".join(output)

    assert exit_code == 0
    assert "not started" in rendered
    assert "Live bug bounty reconnaissance remains blocked" in rendered
    assert "No network requests were made" in rendered


def test_interactive_bug_bounty_resume_is_save_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.interactive._run_pipeline",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("resume live pipeline must not be called")
        ),
    )
    answers = iter(["2", str(project_file), ""])
    output: list[str] = []

    exit_code = run_interactive_launcher(
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
        cwd=tmp_path,
    )

    assert exit_code == 0
    assert "Resume was not started" in "\n".join(output)


@pytest.mark.parametrize(
    "context",
    [CTF_LAB_CONTEXT, INTERNAL_AUTHORISED_CONTEXT, UNKNOWN_CONTEXT],
)
def test_non_bug_bounty_project_contexts_retain_existing_preflight_behaviour(
    tmp_path: Path,
    context: str,
) -> None:
    scope = tmp_path / f"{context}.md"
    scope.write_text("## In Scope\n- 10.10.10.10\n", encoding="utf-8")
    project, _path = initialize_project(
        f"context-{context}",
        "10.10.10.10",
        scope,
        tmp_path / context,
        engagement_context=context,
    )

    enforce_project_execution_policy(project)


def test_policy_sentinels_do_not_enter_runbook_cli_view_or_evidence_pack(
    tmp_path: Path,
    capsys,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    write_engagement_policy(project_file.parent, _complete_policy())
    runbook = build_project_runbook(project_file)

    exit_code = main(
        ["project", "policy", "--project", str(project_file)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0

    _write_minimal_export_input(project_file.parent)
    output_zip = tmp_path / "pack.zip"
    export_recon_evidence_pack(project_file.parent, output_zip)
    archive_bytes = output_zip.read_bytes()
    with __import__("zipfile").ZipFile(output_zip) as archive:
        names = archive.namelist()
        combined = b"\n".join(archive.read(name) for name in names)
        manifest = json.loads(archive.read("bugslyce_export_manifest.json"))

    for text in (runbook.content, captured.out):
        assert SENTINEL_HEADER not in text
        assert SENTINEL_USER_AGENT not in text
    assert "bugslyce project policy" in runbook.content
    assert "Live bug bounty reconnaissance remains blocked" in runbook.content
    assert "bugslyce recon nmap-discover" not in runbook.content
    assert SENTINEL_HEADER.encode() not in archive_bytes
    assert SENTINEL_USER_AGENT.encode() not in archive_bytes
    assert ENGAGEMENT_POLICY_FILENAME not in names
    assert manifest["excluded_sensitive_files"] == [ENGAGEMENT_POLICY_FILENAME]
    assert SENTINEL_HEADER.encode() not in combined


def test_policy_sentinels_do_not_enter_markdown_or_html_reports(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    write_engagement_policy(project_file.parent, _complete_policy())
    state = ProjectState(
        project_name="policy-test",
        input_dir=str(project_file.parent),
        processed_files=[],
        scope_summary="Authorised local test scope.",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=[],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-28T10:00:00Z",
        engagement_context="bug_bounty",
    )
    report_path, _json_path = write_project_outputs(state, [], project_file.parent)
    html_path = write_html_report(project_file.parent, tmp_path / "policy-report.html")

    pipeline_markdown = render_project_pipeline_markdown(
        PipelineResult(
            project_name="policy-test",
            target="10.10.10.10",
            profile=PIPELINE_PROFILE,
            project_file=str(project_file),
            scope_file=str(tmp_path / "scope.md"),
            output_dir=str(project_file.parent),
            started_at="2026-07-28T10:00:00Z",
            completed_at=None,
            final_status="blocked",
            resume_requested=False,
            reused_existing_evidence=False,
            skipped_steps=0,
            no_op_steps=0,
            completed_steps=0,
            failed_step=None,
            steps=[
                PipelineStep(
                    step_id="PIPELINE-PREFLIGHT",
                    name="Policy preflight",
                    command_kind="local_validation",
                    status="blocked",
                    message="Live bug bounty reconnaissance remains blocked.",
                )
            ],
            report_path=None,
            runbook_path=None,
            export_path=None,
            no_unapproved_actions=True,
        )
    )

    for content in (
        report_path.read_text(encoding="utf-8"),
        html_path.read_text(encoding="utf-8"),
        pipeline_markdown,
    ):
        assert SENTINEL_HEADER not in content
        assert SENTINEL_USER_AGENT not in content


def test_project_policy_cli_help_and_missing_policy_view(capsys, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["project", "policy", "--help"])
    help_output = capsys.readouterr().out

    project_file = _bug_bounty_project(tmp_path)
    exit_code = main(["project", "policy", "--project", str(project_file)])
    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "--configure" in help_output
    assert exit_code == 0
    assert "No engagement policy is configured" in captured.out


def test_project_policy_cli_configure_uses_shared_offline_setup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    received: dict[str, object] = {}

    def fake_setup(path, **kwargs):
        received["path"] = path
        return SimpleNamespace(saved=True, cancelled=False)

    monkeypatch.setattr(
        "bugslyce.cli.configure_project_policy_interactively",
        fake_setup,
    )

    exit_code = main(
        [
            "project",
            "policy",
            "--project",
            str(project_file),
            "--configure",
        ]
    )

    assert exit_code == 0
    assert received["path"] == project_file


def test_private_policy_payload_contains_only_canonical_operator_facts() -> None:
    payload = _complete_policy().to_dict()

    assert "readiness_state" not in payload
    assert "not_ready_reasons" not in payload
    assert "enforcement_state" not in payload
    assert "live_execution_state" not in payload


def test_new_bug_bounty_project_does_not_reference_missing_policy(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))

    assert "engagement_policy_file" not in payload
    assert load_project(project_file).engagement_policy_file is None


def test_cancelled_policy_setup_does_not_add_project_reference(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    before = project_file.read_bytes()

    result = configure_project_policy_interactively(
        project_file,
        input_func=lambda _prompt: "3",
        print_func=lambda _message: None,
    )

    assert result.cancelled is True
    assert project_file.read_bytes() == before
    assert load_project(project_file).engagement_policy_file is None


def test_successful_policy_storage_adds_relative_project_reference(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)

    save_project_engagement_policy(project_file, _complete_policy())
    payload = json.loads(project_file.read_text(encoding="utf-8"))

    assert payload["engagement_policy_file"] == ENGAGEMENT_POLICY_FILENAME
    assert Path(payload["engagement_policy_file"]).is_absolute() is False
    assert SENTINEL_HEADER not in project_file.read_text(encoding="utf-8")


def test_failed_policy_storage_does_not_add_false_project_reference(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)

    monkeypatch.setattr(
        "bugslyce.project_session.write_engagement_policy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(OSError, match="disk full"):
        save_project_engagement_policy(project_file, _complete_policy())

    assert load_project(project_file).engagement_policy_file is None
    assert not (project_file.parent / ENGAGEMENT_POLICY_FILENAME).exists()


@pytest.mark.parametrize(
    "invalid_policy",
    [
        lambda policy: replace(policy, maximum_http_requests_per_second="0"),
        lambda policy: replace(policy, engagement_context="internal_authorised"),
        lambda policy: replace(
            policy,
            identification_headers=(IdentificationHeader("Cookie", "private"),),
        ),
    ],
)
def test_storage_boundary_revalidates_directly_constructed_policy_without_writing(
    tmp_path: Path,
    invalid_policy,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    policy_path = write_engagement_policy(project_dir, _complete_policy())
    before = policy_path.read_bytes()

    with pytest.raises(ValueError) as exc_info:
        write_engagement_policy(project_dir, invalid_policy(_complete_policy()))

    assert SENTINEL_HEADER not in str(exc_info.value)
    assert policy_path.read_bytes() == before


def test_policy_read_uses_same_validated_descriptor_not_reopened_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    original = _complete_policy()
    policy_path = write_engagement_policy(project_dir, original)
    substituted = replace(
        original,
        maximum_http_requests_per_second="99",
    )
    outside = tmp_path / "outside-policy.json"
    outside.write_text(
        json.dumps(substituted.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(outside, 0o600)
    original_read_text = Path.read_text

    def substitute_before_reopen(path: Path, *args, **kwargs):
        if path == policy_path:
            policy_path.unlink()
            policy_path.symlink_to(outside)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", substitute_before_reopen)

    assert load_engagement_policy(project_dir) == original


@pytest.mark.parametrize("label", ["Identification header value", "Custom User-Agent"])
@pytest.mark.parametrize("value", [" ", "\t", "  identifier  ", "identifier "])
def test_identification_values_reject_blank_or_edge_whitespace(
    value: str,
    label: str,
) -> None:
    with pytest.raises(ValueError, match="must be configured|leading or trailing"):
        validate_identification_value(value, label=label)


def test_identification_value_allows_internal_spaces() -> None:
    assert (
        validate_identification_value(
            "Programme Researcher alice",
            label="Custom User-Agent",
        )
        == "Programme Researcher alice"
    )


@pytest.mark.parametrize(
    "value",
    ["1e100000", "1e-100000", "9" * 10000, "1." + "0" * 10000],
)
def test_http_rate_rejects_technically_oversized_numeric_input(value: str) -> None:
    with pytest.raises(ValueError, match="technical size limit") as exc_info:
        validate_http_rate(value)
    assert value not in str(exc_info.value)


def test_http_rate_rejects_malformed_scientific_notation_stably() -> None:
    with pytest.raises(ValueError, match="positive finite number"):
        validate_http_rate("1e+")


def test_http_concurrency_rejects_technically_oversized_input_stably() -> None:
    value = "9" * 10000
    with pytest.raises(ValueError, match="technical size limit") as exc_info:
        validate_http_concurrency(value)
    assert value not in str(exc_info.value)


def test_tcp_and_identification_collections_have_technical_size_bounds() -> None:
    with pytest.raises(ValueError, match="technical size limit"):
        normalise_tcp_port_specification("80," * 5000 + "443")
    with pytest.raises(ValueError, match="technical count limit"):
        build_bug_bounty_policy(
            identification_requirement=IDENTIFICATION_HEADERS,
            identification_headers=tuple(
                IdentificationHeader(f"X-Researcher-{index}", "configured")
                for index in range(1000)
            ),
        )
    with pytest.raises(ValueError, match="technical size limit"):
        validate_identification_value(
            "x" * 4097,
            label="Custom User-Agent",
        )


def test_runtime_fields_are_rejected_as_non_canonical_policy_input() -> None:
    payload = _complete_policy().to_dict()
    payload["readiness_state"] = READINESS_FUTURE_ENFORCEMENT

    with pytest.raises(ValueError, match="canonical schema"):
        policy_from_dict(payload)


def test_invalid_direct_policy_is_not_created_at_storage_boundary(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    invalid = replace(_complete_policy(), engagement_context="internal_authorised")

    with pytest.raises(ValueError, match="context"):
        write_engagement_policy(project_dir, invalid)

    assert not (project_dir / ENGAGEMENT_POLICY_FILENAME).exists()
    assert list(project_dir.iterdir()) == []


def test_bug_bounty_existing_artefacts_keep_safe_offline_actions_only(
    tmp_path: Path,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    save_project_engagement_policy(project_file, _complete_policy())
    output_dir = project_file.parent
    (output_dir / "report.md").write_text("# Existing report\n", encoding="utf-8")
    (output_dir / "project_state.json").write_text("{}\n", encoding="utf-8")
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": str(tmp_path / "scope.md"),
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )

    result = build_project_next(project_file)
    actions = [result.recommended_action, *result.optional_actions]
    action_ids = {action.id for action in actions}
    commands = "\n".join(action.command_preview for action in actions)
    runbook = build_project_runbook(project_file).content

    assert result.recommended_action.id == "configure-engagement-policy"
    assert {
        "inspect-project-status",
        "review-existing-report",
        "render-html-report",
        "export-evidence-pack",
    }.issubset(action_ids)
    for forbidden in (
        "nmap-discover",
        "nmap-services",
        "curl-headers",
        "content-run",
        "path-followup",
        "body-fetch",
        "gobuster",
    ):
        assert forbidden not in commands
        assert forbidden not in runbook


@pytest.mark.parametrize("error", [OSError("disk full"), EOFError()])
def test_policy_cli_converts_expected_local_failures_to_redacted_error(
    tmp_path: Path,
    monkeypatch,
    capsys,
    error: BaseException,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    monkeypatch.setattr(
        "bugslyce.cli.configure_project_policy_interactively",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )

    exit_code = main(
        [
            "project",
            "policy",
            "--project",
            str(project_file),
            "--configure",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "No commands were executed" in captured.err
    assert SENTINEL_HEADER not in captured.err


def test_new_project_policy_storage_failure_returns_redacted_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "bugslyce.interactive.configure_project_policy_interactively",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("private sentinel")),
    )
    answers = iter(
        ["1", "bounty-error", "10.10.10.10", "projects", "3", "2", "YES"]
    )
    output: list[str] = []

    exit_code = run_interactive_launcher(
        input_func=lambda _prompt: next(answers),
        print_func=output.append,
        cwd=tmp_path,
    )
    rendered = "\n".join(output)

    assert exit_code == 2
    assert "could not be read or written safely" in rendered
    assert "private sentinel" not in rendered
    assert "No network requests were made" in rendered


def test_resume_policy_prompt_eof_returns_redacted_nonzero(tmp_path: Path) -> None:
    project_file = _bug_bounty_project(tmp_path)
    answers = iter(["2", str(project_file)])
    output: list[str] = []

    def input_with_eof(prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            raise EOFError from None

    exit_code = run_interactive_launcher(
        input_func=input_with_eof,
        print_func=output.append,
        cwd=tmp_path,
    )
    rendered = "\n".join(output)

    assert exit_code == 2
    assert "input ended before a choice" in rendered
    assert "No commands were executed" in rendered
    assert "No network requests were made" in rendered


def test_policy_write_refuses_valid_headers_that_exceed_aggregate_file_limit(
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    existing_path = write_engagement_policy(project_dir, _complete_policy())
    before = existing_path.read_bytes()
    oversized_value = "x" * 4096
    aggregate_policy = build_bug_bounty_policy(
        identification_requirement=IDENTIFICATION_HEADERS,
        identification_headers=tuple(
            IdentificationHeader(f"X-Researcher-{index:02d}", oversized_value)
            for index in range(64)
        ),
        updated_at="2026-07-28T10:00:00Z",
    )

    with pytest.raises(ValueError, match="technical size limit") as exc_info:
        write_engagement_policy(project_dir, aggregate_policy)

    assert oversized_value not in str(exc_info.value)
    assert existing_path.read_bytes() == before
    assert list(project_dir.glob(".engagement_policy.*.tmp")) == []


@pytest.mark.parametrize(
    "timestamp",
    [
        "",
        " ",
        " 2026-07-28T10:00:00Z",
        "2026-07-28T10:00:00Z ",
        "2026-07-28 10:00:00Z",
        "x" * 65,
    ],
)
def test_explicit_policy_timestamp_is_validated(timestamp: str) -> None:
    with pytest.raises(ValueError, match="timestamp|technical size limit") as exc_info:
        build_bug_bounty_policy(updated_at=timestamp)

    if timestamp.strip():
        assert timestamp not in str(exc_info.value)


def test_policy_timestamp_is_generated_only_when_omitted_and_round_trips() -> None:
    generated = build_bug_bounty_policy(
        clock=lambda: datetime(2026, 7, 28, 10, 0, 0, tzinfo=timezone.utc)
    )
    stored = _complete_policy()

    assert generated.updated_at == "2026-07-28T10:00:00Z"
    assert policy_from_dict(stored.to_dict()).updated_at == stored.updated_at


def test_empty_stored_policy_timestamp_is_not_replaced_with_current_time() -> None:
    payload = _complete_policy().to_dict()
    payload["updated_at"] = ""

    with pytest.raises(ValueError, match="timestamp"):
        policy_from_dict(payload)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_policy_read_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    fifo_path = project_dir / ENGAGEMENT_POLICY_FILENAME
    os.mkfifo(fifo_path, 0o600)
    script = "\n".join(
        (
            "from pathlib import Path",
            "from bugslyce.core.engagement_policy import load_engagement_policy",
            "import sys",
            "try:",
            "    load_engagement_policy(Path(sys.argv[1]))",
            "except ValueError as exc:",
            "    print(str(exc))",
            "    raise SystemExit(0)",
            "raise SystemExit(1)",
        )
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(project_dir)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        text=True,
        timeout=1,
    )

    assert completed.returncode == 0
    assert "regular file" in completed.stdout


def test_first_policy_save_metadata_failure_preserves_project_and_removes_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    before = project_file.read_bytes()
    original_write_text = Path.write_text
    original_replace = os.replace

    def partial_legacy_metadata_write(path: Path, text: str, *args, **kwargs):
        if path == project_file:
            original_write_text(path, "{", encoding="utf-8")
            raise OSError("metadata write interrupted")
        return original_write_text(path, text, *args, **kwargs)

    def fail_metadata_replace(source, destination, *args, **kwargs):
        if Path(destination) == project_file:
            raise OSError("metadata replace interrupted")
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", partial_legacy_metadata_write)
    monkeypatch.setattr(os, "replace", fail_metadata_replace)

    with pytest.raises(OSError, match="metadata"):
        save_project_engagement_policy(project_file, _complete_policy())

    assert project_file.read_bytes() == before
    assert load_project(project_file).engagement_policy_file is None
    assert not (project_file.parent / ENGAGEMENT_POLICY_FILENAME).exists()
    assert list(project_file.parent.glob(".bugslyce_project.*.tmp")) == []


def test_metadata_failure_restores_an_existing_unreferenced_private_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _bug_bounty_project(tmp_path)
    policy_path = write_engagement_policy(project_file.parent, _complete_policy())
    before_project = project_file.read_bytes()
    before_policy = policy_path.read_bytes()
    original_replace = os.replace

    def fail_metadata_replace(source, destination, *args, **kwargs):
        if Path(destination) == project_file:
            raise OSError("metadata replace interrupted")
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", fail_metadata_replace)

    with pytest.raises(OSError, match="metadata"):
        save_project_engagement_policy(
            project_file,
            replace(_complete_policy(), maximum_http_requests_per_second="3"),
        )

    assert project_file.read_bytes() == before_project
    assert policy_path.read_bytes() == before_policy
    assert load_project(project_file).engagement_policy_file is None


def test_bad_direct_timestamp_cannot_create_private_policy(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    invalid = replace(_complete_policy(), updated_at="x" * 65)

    with pytest.raises(ValueError, match="technical size limit"):
        write_engagement_policy(project_dir, invalid)

    assert not (project_dir / ENGAGEMENT_POLICY_FILENAME).exists()


def test_policy_write_does_not_report_failure_after_atomic_replacement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    policy_path = write_engagement_policy(project_dir, _complete_policy())
    replacement = replace(_complete_policy(), maximum_http_requests_per_second="3")

    def fail_post_replace_chmod(*_args, **_kwargs) -> None:
        raise OSError("post-replacement chmod failed")

    monkeypatch.setattr(
        "bugslyce.core.engagement_policy.os.chmod", fail_post_replace_chmod
    )

    assert write_engagement_policy(project_dir, replacement) == policy_path
    assert load_engagement_policy(project_dir) == replacement
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o600
    assert list(project_dir.glob(".engagement_policy.*.tmp")) == []


@pytest.mark.parametrize("unsafe_character", ("\u0085", "\u009f", "\u2028", "\u2029"))
@pytest.mark.parametrize(
    "label",
    ("Identification header value", "Custom User-Agent"),
)
def test_identification_values_reject_unicode_controls_and_separators(
    unsafe_character: str,
    label: str,
) -> None:
    value = f"Researcher{unsafe_character}Identifier"

    with pytest.raises(ValueError, match="unsafe control character") as exc_info:
        validate_identification_value(value, label=label)

    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "header_name",
    (
        "X-API-Key",
        "API-Key",
        "X-Auth-Token",
        "X-Access-Token",
        "X-CSRF-Token",
        "X-XSRF-Token",
    ),
)
def test_generic_credential_identification_headers_are_prohibited(
    header_name: str,
) -> None:
    for candidate in (header_name, header_name.swapcase()):
        with pytest.raises(ValueError, match="cannot be used"):
            validate_identification_header_name(candidate)


def test_policy_nested_identification_header_schema_is_exact() -> None:
    valid_payload = json.loads(json.dumps(_complete_policy().to_dict()))
    assert policy_from_dict(valid_payload) == _complete_policy()

    invalid_payloads = []
    missing_name = json.loads(json.dumps(valid_payload))
    del missing_name["identification_headers"][0]["name"]
    invalid_payloads.append(missing_name)

    missing_value = json.loads(json.dumps(valid_payload))
    del missing_value["identification_headers"][0]["value"]
    invalid_payloads.append(missing_value)

    extra_runtime = json.loads(json.dumps(valid_payload))
    extra_runtime["identification_headers"][0]["runtime_state"] = "derived"
    invalid_payloads.append(extra_runtime)

    multiple_extras = json.loads(json.dumps(valid_payload))
    multiple_extras["identification_headers"][0]["runtime_state"] = "derived"
    multiple_extras["identification_headers"][0]["extra"] = "unexpected"
    invalid_payloads.append(multiple_extras)

    for payload in invalid_payloads:
        with pytest.raises(ValueError, match="identification header schema") as exc_info:
            policy_from_dict(payload)
        assert SENTINEL_HEADER not in str(exc_info.value)


def _write_minimal_export_input(input_dir: Path) -> None:
    (input_dir / "report.md").write_text("# Report\n", encoding="utf-8")
    (input_dir / "project_state.json").write_text(
        '{"project_state": {}, "candidates": []}\n', encoding="utf-8"
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-test",
                "artifacts": [
                    {"type": "private_policy", "file": ENGAGEMENT_POLICY_FILENAME}
                ],
            }
        ),
        encoding="utf-8",
    )


def _complete_policy():
    return build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="2",
        maximum_http_concurrency=1,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", SENTINEL_HEADER),
        ),
        custom_user_agent=SENTINEL_USER_AGENT,
        updated_at="2026-07-28T10:00:00Z",
    )


def _bug_bounty_project(tmp_path: Path) -> Path:
    output_dir = tmp_path / "project"
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n- 10.10.10.10\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "policy-test",
        "10.10.10.10",
        scope,
        output_dir,
        engagement_context="bug_bounty",
    )
    return project_file
