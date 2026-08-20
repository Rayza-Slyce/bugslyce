from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.reports.operator_summary import (
    OperatorSummary,
    OperatorSummaryLead,
)


def _api():
    from bugslyce.reports.operator_brief import (
        OPERATOR_BRIEF_FILENAME,
        build_operator_brief_view,
        load_operator_brief_artifact,
        write_operator_brief_artifact,
    )

    return (
        OPERATOR_BRIEF_FILENAME,
        build_operator_brief_view,
        load_operator_brief_artifact,
        write_operator_brief_artifact,
    )


def _lead(
    *,
    lead_id: str,
    rank: int,
    title: str,
    score: int,
    endpoint: str,
    evidence_id: str,
    lead_type: str,
) -> OperatorSummaryLead:
    return OperatorSummaryLead(
        title=title,
        why=f"Deterministic rationale for {title}.",
        endpoints=[endpoint],
        evidence_ids=[evidence_id],
        next_action=f"Review retained evidence for {title}.",
        signal="medium",
        score=score,
        lead_type=lead_type,
        lead_id=lead_id,
        rank=rank,
    )


def _summary() -> OperatorSummary:
    return OperatorSummary(
        review_first=[
            _lead(
                lead_id="LEAD-ALPHA",
                rank=1,
                title="First retained investigation lead",
                score=85,
                endpoint="http://example.test/admin",
                evidence_id="EVID-ALPHA",
                lead_type="fetched_application_page",
            ),
            _lead(
                lead_id="LEAD-BRAVO",
                rank=2,
                title="Second retained investigation lead",
                score=64,
                endpoint="example.test:445/tcp",
                evidence_id="EVID-BRAVO",
                lead_type="smb_disk_share_review",
            ),
        ],
        low_signal=[],
        coverage=["Bounded test coverage."],
    )


def test_operator_brief_initial_projection_preserves_canonical_leads_one_for_one() -> None:
    (
        _,
        build_operator_brief_view,
        _,
        _,
    ) = _api()

    summary = _summary()
    brief = build_operator_brief_view(summary)

    assert len(brief.threads) == 2
    assert [thread.title for thread in brief.threads] == [
        "First retained investigation lead",
        "Second retained investigation lead",
    ]
    assert [thread.rank for thread in brief.threads] == [1, 2]
    assert [thread.score for thread in brief.threads] == [85, 64]
    assert [thread.signal for thread in brief.threads] == ["medium", "medium"]

    first, second = brief.threads

    assert first.source_lead_ids == ("LEAD-ALPHA",)
    assert first.endpoints == ("http://example.test/admin",)
    assert first.evidence_ids == ("EVID-ALPHA",)
    assert first.why_review == (
        "Deterministic rationale for First retained investigation lead."
    )
    assert first.next_review_step == (
        "Review retained evidence for First retained investigation lead."
    )

    assert second.source_lead_ids == ("LEAD-BRAVO",)
    assert second.endpoints == ("example.test:445/tcp",)
    assert second.evidence_ids == ("EVID-BRAVO",)

    for thread in brief.threads:
        assert thread.thread_id.startswith("THREAD-")
        assert thread.observed_facts == ()
        assert thread.related_context == ()
        assert thread.conflicts == ()
        assert thread.coverage_limitations == ()
        assert thread.unknowns == ()
        assert thread.source_artefacts == ()

    assert [
        (
            disposition.source_kind,
            disposition.source_id,
            disposition.disposition,
            disposition.thread_id,
        )
        for disposition in brief.dispositions
    ] == [
        (
            "operator_summary_lead",
            "LEAD-ALPHA",
            "primary_thread",
            first.thread_id,
        ),
        (
            "operator_summary_lead",
            "LEAD-BRAVO",
            "primary_thread",
            second.thread_id,
        ),
    ]

    assert build_operator_brief_view(summary) == brief


def test_operator_brief_artifact_round_trips_and_is_byte_deterministic(
    tmp_path: Path,
) -> None:
    (
        filename,
        build_operator_brief_view,
        load_operator_brief_artifact,
        write_operator_brief_artifact,
    ) = _api()

    brief = build_operator_brief_view(_summary())
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    first_path = write_operator_brief_artifact(first_root, brief)
    second_path = write_operator_brief_artifact(second_root, brief)

    assert first_path.name == filename == "operator_brief.json"
    assert first_path.read_bytes() == second_path.read_bytes()

    payload = json.loads(first_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["generated_by"] == "bugslyce.operator_brief"
    assert len(payload["threads"]) == 2
    assert len(payload["dispositions"]) == 2

    assert load_operator_brief_artifact(first_root) == brief
    assert load_operator_brief_artifact(second_root) == brief


def test_operator_brief_missing_artifact_is_legacy_absence(
    tmp_path: Path,
) -> None:
    (
        _,
        _,
        load_operator_brief_artifact,
        _,
    ) = _api()

    assert load_operator_brief_artifact(tmp_path) is None


def test_operator_brief_present_malformed_or_unsupported_artifact_is_rejected(
    tmp_path: Path,
) -> None:
    (
        filename,
        _,
        load_operator_brief_artifact,
        _,
    ) = _api()

    path = tmp_path / filename
    path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"could not parse operator_brief\.json",
    ):
        load_operator_brief_artifact(tmp_path)

    path.write_text(
        json.dumps(
            {
                "schema_version": 999,
                "generated_by": "bugslyce.operator_brief",
                "threads": [],
                "dispositions": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="unsupported schema_version",
    ):
        load_operator_brief_artifact(tmp_path)


def test_operator_brief_persistence_rejects_symlink_target(
    tmp_path: Path,
) -> None:
    (
        filename,
        build_operator_brief_view,
        load_operator_brief_artifact,
        write_operator_brief_artifact,
    ) = _api()

    outside = tmp_path / "outside.json"
    outside.write_text("do not replace", encoding="utf-8")

    root = tmp_path / "root"
    root.mkdir()
    path = root / filename
    path.symlink_to(outside)

    brief = build_operator_brief_view(_summary())

    with pytest.raises(
        ValueError,
        match="structured artefact must be a regular file",
    ):
        write_operator_brief_artifact(root, brief)

    with pytest.raises(
        ValueError,
        match="structured artefact must be a regular file",
    ):
        load_operator_brief_artifact(root)

    assert outside.read_text(encoding="utf-8") == "do not replace"


def test_operator_brief_thread_can_exist_without_canonical_source_lead() -> None:
    from bugslyce.reports.operator_brief import (
        OperatorBriefDisposition,
        OperatorBriefThread,
        OperatorBriefView,
        PRIMARY_THREAD,
    )

    thread = OperatorBriefThread(
        thread_id="THREAD-WORKFLOW",
        title="Account workflow review",
        rank=1,
        score=80,
        signal="direct retained evidence",
        source_lead_ids=(),
        endpoints=("https://example.test/login",),
        evidence_ids=("EVID-WORKFLOW",),
        why_review="Direct retained evidence describes an account workflow.",
        next_review_step="Review the retained workflow evidence offline.",
    )
    disposition = OperatorBriefDisposition(
        source_kind="workflow_lead",
        source_id="WORKFLOW-ACCOUNT",
        disposition=PRIMARY_THREAD,
        thread_id=thread.thread_id,
    )

    brief = OperatorBriefView(
        threads=(thread,),
        dispositions=(disposition,),
    )

    assert brief.threads == (thread,)
    assert brief.threads[0].source_lead_ids == ()
    assert brief.dispositions == (disposition,)


def test_operator_brief_view_rejects_duplicate_thread_ids() -> None:
    from bugslyce.reports.operator_brief import (
        OperatorBriefThread,
        OperatorBriefView,
    )

    first = OperatorBriefThread(
        thread_id="THREAD-DUPLICATE",
        title="First thread",
        rank=1,
        score=80,
        signal="direct retained evidence",
        source_lead_ids=(),
        endpoints=("http://example.test/first",),
        evidence_ids=("EVID-FIRST",),
        why_review="First deterministic rationale.",
        next_review_step="Review first retained evidence offline.",
    )
    second = OperatorBriefThread(
        thread_id="THREAD-DUPLICATE",
        title="Second thread",
        rank=2,
        score=70,
        signal="direct retained evidence",
        source_lead_ids=(),
        endpoints=("http://example.test/second",),
        evidence_ids=("EVID-SECOND",),
        why_review="Second deterministic rationale.",
        next_review_step="Review second retained evidence offline.",
    )

    with pytest.raises(
        ValueError,
        match="duplicate thread IDs",
    ):
        OperatorBriefView(
            threads=(first, second),
            dispositions=(),
        )


def test_operator_brief_view_rejects_duplicate_disposition_sources() -> None:
    from bugslyce.reports.operator_brief import (
        OperatorBriefDisposition,
        OperatorBriefThread,
        OperatorBriefView,
        PRIMARY_THREAD,
        SUPPORTING_CONTEXT,
    )

    thread = OperatorBriefThread(
        thread_id="THREAD-ONE",
        title="One thread",
        rank=1,
        score=80,
        signal="direct retained evidence",
        source_lead_ids=(),
        endpoints=("http://example.test/one",),
        evidence_ids=("EVID-ONE",),
        why_review="Deterministic rationale.",
        next_review_step="Review retained evidence offline.",
    )

    with pytest.raises(
        ValueError,
        match="duplicate disposition sources",
    ):
        OperatorBriefView(
            threads=(thread,),
            dispositions=(
                OperatorBriefDisposition(
                    source_kind="workflow_lead",
                    source_id="WORKFLOW-ONE",
                    disposition=PRIMARY_THREAD,
                    thread_id=thread.thread_id,
                ),
                OperatorBriefDisposition(
                    source_kind="workflow_lead",
                    source_id="WORKFLOW-ONE",
                    disposition=SUPPORTING_CONTEXT,
                    thread_id=thread.thread_id,
                ),
            ),
        )


def test_operator_brief_view_rejects_unknown_disposition_thread_reference() -> None:
    from bugslyce.reports.operator_brief import (
        OperatorBriefDisposition,
        OperatorBriefThread,
        OperatorBriefView,
        PRIMARY_THREAD,
    )

    thread = OperatorBriefThread(
        thread_id="THREAD-KNOWN",
        title="Known thread",
        rank=1,
        score=80,
        signal="direct retained evidence",
        source_lead_ids=(),
        endpoints=("http://example.test/known",),
        evidence_ids=("EVID-KNOWN",),
        why_review="Deterministic rationale.",
        next_review_step="Review retained evidence offline.",
    )

    with pytest.raises(
        ValueError,
        match="unknown thread ID",
    ):
        OperatorBriefView(
            threads=(thread,),
            dispositions=(
                OperatorBriefDisposition(
                    source_kind="workflow_lead",
                    source_id="WORKFLOW-UNKNOWN",
                    disposition=PRIMARY_THREAD,
                    thread_id="THREAD-NOT-PRESENT",
                ),
            ),
        )
