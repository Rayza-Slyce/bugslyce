"""Deterministic collection-confidence model and rendering tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from bugslyce.recon.collection_confidence import (
    FAILED,
    INTENTIONALLY_BOUNDED,
    PARTIAL_OR_DEGRADED,
    SKIPPED_OR_UNAVAILABLE,
    UNKNOWN_LEGACY_STATE,
    build_collection_confidence_notices,
    build_collection_confidence_notices_from_project,
    render_collection_confidence_markdown,
    render_collection_confidence_runbook,
)


def test_bounded_content_and_deep_collection_remain_distinct() -> None:
    state = _state(
        profile="deep-bounded-core",
        evidence_ids=("EVID-DISCOVERY",),
    )
    source = _deep_source()

    notices = build_collection_confidence_notices(
        state,
        source_collection=source,
    )

    assert tuple(notice.notice_id for notice in notices) == (
        "CONFIDENCE-BOUNDED-CONTENT-DISCOVERY",
        "CONFIDENCE-DEEP-SOURCE-ROUTES",
    )
    assert all(notice.category == INTENTIONALLY_BOUNDED for notice in notices)
    assert notices[0].evidence_ids == ("EVID-DISCOVERY",)
    assert notices[0].artefact_references == ("recon_manifest.json",)
    assert notices[1].counts == (
        ("considered", 4),
        ("collected", 2),
        ("skipped", 2),
    )
    assert notices[1].evidence_ids == (
        "EVID-COLLECTED-A",
        "EVID-COLLECTED-B",
        "EVID-SKIPPED",
    )
    assert "not exhaustive" in notices[0].operator_implication
    assert "remain unknown" in notices[1].operator_implication


def test_structured_followup_cap_is_degraded_not_failed() -> None:
    notices = build_collection_confidence_notices(
        _state(warnings=("Discovered-path follow-up capped at 12 URLs.",))
    )

    assert len(notices) == 1
    assert notices[0].category == PARTIAL_OR_DEGRADED
    assert notices[0].counts == (("cap", 12),)
    assert "may not have follow-up response evidence" in notices[0].operator_implication
    assert "vulnerab" not in notices[0].direct_fact.lower()


def test_failed_stage_and_command_do_not_use_success_wording() -> None:
    notices = build_collection_confidence_notices(
        _state(),
        pipeline_steps=(
            {
                "step_id": "PIPELINE-STEP-TEST",
                "name": "service metadata",
                "command_kind": "service-scan",
                "status": "failed",
                "message": "collector returned an error",
            },
        ),
        command_results=(
            {
                "command_id": "CMD-TEST",
                "tool": "local-collector",
                "exit_code": 2,
                "error": None,
            },
        ),
    )

    assert len(notices) == 2
    assert all(notice.category == FAILED for notice in notices)
    assert all("success" not in notice.direct_fact.lower() for notice in notices)
    assert {notice.artefact_references[0] for notice in notices} == {
        "project_pipeline.json",
        "recon_execution.json",
    }


def test_bounded_profile_and_failed_execution_do_not_contradict() -> None:
    notices = build_collection_confidence_notices(
        _state(profile="deep-bounded-core", evidence_ids=("EVID-DISCOVERY",)),
        pipeline_steps=(
            {
                "step_id": "PIPELINE-STEP-CONTENT",
                "name": "content discovery",
                "command_kind": "content-run",
                "status": "failed",
                "message": "collector returned an error",
            },
        ),
    )

    bounded = next(notice for notice in notices if notice.category == INTENTIONALLY_BOUNDED)
    failed = next(notice for notice in notices if notice.category == FAILED)

    assert "successful" not in bounded.operator_implication.lower()
    assert "bounded" in bounded.operator_implication.lower()
    assert failed.notice_id == "CONFIDENCE-STAGE-PIPELINE-STEP-CONTENT"


def test_completed_bounded_execution_remains_cautiously_execution_neutral() -> None:
    notices = build_collection_confidence_notices(
        _state(profile="standard-bounded-core", evidence_ids=("EVID-DISCOVERY",)),
        pipeline_steps=(
            {
                "step_id": "PIPELINE-STEP-CONTENT",
                "name": "content discovery",
                "command_kind": "content-run",
                "status": "completed",
                "message": "collection completed",
            },
        ),
    )

    assert len(notices) == 1
    assert notices[0].category == INTENTIONALLY_BOUNDED
    assert "successful" not in notices[0].operator_implication.lower()


def test_skipped_and_dependency_unavailable_are_not_failures() -> None:
    notices = build_collection_confidence_notices(
        _state(),
        pipeline_steps=(
            {
                "step_id": "PIPELINE-STEP-SKIP",
                "name": "mode-specific stage",
                "command_kind": "optional-stage",
                "status": "skipped",
                "message": "excluded by selected profile",
            },
            {
                "step_id": "PIPELINE-STEP-LOCAL",
                "name": "local helper stage",
                "command_kind": "local-helper",
                "status": "unavailable",
                "message": "required local dependency unavailable",
            },
        ),
        command_results=(
            {
                "command_id": "CMD-NOT-ATTEMPTED",
                "tool": "optional-collector",
                "exit_code": None,
                "error": None,
                "executed": False,
            },
        ),
    )

    assert len(notices) == 3
    assert all(notice.category == SKIPPED_OR_UNAVAILABLE for notice in notices)
    assert any("unavailable" in notice.title.lower() for notice in notices)
    assert all(
        "No result should be inferred" in notice.operator_implication
        for notice in notices
    )


def test_legitimate_noop_and_informational_text_create_no_notice() -> None:
    notices = build_collection_confidence_notices(
        _state(
            warnings=(
                "Normal scanner progress: service detection performed.",
                "Host is up.",
            )
        ),
        pipeline_steps=(
            {
                "step_id": "PIPELINE-STEP-NOOP",
                "name": "path follow-up",
                "command_kind": "path-followup",
                "status": "noop",
                "message": "No eligible paths were available.",
            },
        ),
        command_results=(
            {
                "command_id": "CMD-OK",
                "tool": "scanner",
                "exit_code": 0,
                "error": None,
            },
        ),
    )

    assert notices == ()


def test_duplicate_warnings_and_reversed_inputs_are_deterministic() -> None:
    warnings = (
        "Discovered-path follow-up capped at 8 URLs.",
        "discovered-path follow-up capped at 8 urls.",
    )
    stages = (
        {
            "step_id": "PIPELINE-STEP-B",
            "name": "second",
            "command_kind": "collector",
            "status": "failed",
            "message": "failed",
        },
        {
            "step_id": "PIPELINE-STEP-A",
            "name": "first",
            "command_kind": "collector",
            "status": "skipped",
            "message": "profile exclusion",
        },
    )

    forward = build_collection_confidence_notices(
        _state(warnings=warnings),
        source_collection=_deep_source(reverse=False),
        pipeline_steps=stages,
    )
    reversed_result = build_collection_confidence_notices(
        _state(warnings=tuple(reversed(warnings))),
        source_collection=_deep_source(reverse=True),
        pipeline_steps=tuple(reversed(stages)),
    )

    assert forward == reversed_result
    assert sum(
        notice.notice_id == "CONFIDENCE-DEGRADED-PATH-FOLLOWUP-CAP"
        for notice in forward
    ) == 1
    assert tuple(notice.category for notice in forward) == (
        FAILED,
        PARTIAL_OR_DEGRADED,
        SKIPPED_OR_UNAVAILABLE,
        INTENTIONALLY_BOUNDED,
    )


def test_report_and_runbook_use_same_notice_provenance_without_live_commands() -> None:
    notices = build_collection_confidence_notices(
        _state(),
        source_collection=_deep_source(),
    )

    report = render_collection_confidence_markdown(notices)
    runbook = render_collection_confidence_runbook(notices)

    assert report is not None
    assert runbook is not None
    for value in (
        "CONFIDENCE-DEEP-SOURCE-ROUTES",
        "EVID-COLLECTED-A",
        "EVID-COLLECTED-B",
        "EVID-SKIPPED",
        "deep_source_route_collection.json",
    ):
        assert value in report
        assert value in runbook
    assert "body preview" not in report.lower()
    assert "curl " not in runbook
    assert "wget " not in runbook
    assert "confirmed finding" not in report.lower()


def test_unknown_legacy_state_requires_explicit_structured_flag() -> None:
    assert build_collection_confidence_notices(_state()) == ()

    notices = build_collection_confidence_notices(
        _state(),
        legacy_status_unknown=True,
    )

    assert len(notices) == 1
    assert notices[0].category == UNKNOWN_LEGACY_STATE
    assert "Do not infer successful or exhaustive" in notices[0].operator_implication


def test_project_loader_uses_structured_pipeline_and_execution_metadata(
    tmp_path: Path,
) -> None:
    (tmp_path / "project_pipeline.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "step_id": "PIPELINE-STEP-FAILED",
                        "name": "metadata stage",
                        "command_kind": "metadata",
                        "status": "failed",
                        "message": "structured failure",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "recon_execution_content_run.json").write_text(
        json.dumps(
            {
                "command_results": [
                    {
                        "command_id": "CONTENT-STEP-001",
                        "tool": "collector",
                        "exit_code": None,
                        "error": "timed out",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    notices = build_collection_confidence_notices_from_project(
        _state(),
        tmp_path,
    )

    assert len(notices) == 2
    assert all(notice.category == FAILED for notice in notices)
    command = next(notice for notice in notices if "COMMAND" in notice.notice_id)
    assert command.artefact_references == ("recon_execution_content_run.json",)
    report = render_collection_confidence_markdown(notices)
    runbook = render_collection_confidence_runbook(notices)
    assert report is not None
    assert runbook is not None
    for reference in ("project_pipeline.json", "recon_execution_content_run.json"):
        assert reference in report
        assert reference in runbook


def _state(
    *,
    profile: str | None = None,
    evidence_ids: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
) -> SimpleNamespace:
    artifacts = (
        SimpleNamespace(
            type="gobuster",
            file=f"gobuster-{profile}.txt",
        ),
    ) if profile else ()
    evidence = tuple(
        SimpleNamespace(
            id=evidence_id,
            source_file=f"/project/gobuster-{profile}.txt",
        )
        for evidence_id in evidence_ids
    )
    return SimpleNamespace(
        recon_manifest=SimpleNamespace(artifacts=artifacts) if profile else None,
        evidence=evidence,
        warnings=warnings,
    )


def _deep_source(*, reverse: bool = False) -> SimpleNamespace:
    collected = (
        SimpleNamespace(evidence_ids=("EVID-COLLECTED-A",)),
        SimpleNamespace(evidence_ids=("EVID-COLLECTED-B",)),
    )
    skipped = (
        SimpleNamespace(evidence_ids=("EVID-SKIPPED",)),
        SimpleNamespace(evidence_ids=("EVID-SKIPPED",)),
    )
    if reverse:
        collected = tuple(reversed(collected))
        skipped = tuple(reversed(skipped))
    return SimpleNamespace(
        total_considered=4,
        total_collected=2,
        total_skipped=2,
        collected=collected,
        skipped=skipped,
    )
