"""Package 3D2A canonical-thread projection authority contracts."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.core.models import PortService, ProjectState, SMBShare
from bugslyce.recon.investigation_threads import (
    InvestigationThread,
    build_investigation_threads,
)
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.reports.operator_summary import (
    OperatorSummary,
    OperatorSummaryLead,
    build_operator_summary,
)


def _state() -> ProjectState:
    return ProjectState(
        project_name="projection", input_dir="/tmp/projection", processed_files=[],
        scope_summary="none", assets=[], endpoints=[], http_services=[], port_services=[],
        http_artifacts=[], discovered_paths=[], recon_summary=None, recon_manifest=None,
        evidence=[], warnings=[], generated_at="2026-01-01T00:00:00Z",
        engagement_context="internal_authorised",
    )


def _thread(digest: str = "a", title: str = "Canonical application review") -> InvestigationThread:
    return InvestigationThread(
        thread_id="THREAD-" + digest * 64, title=title,
        priority="medium", category="application_interface", summary="Structured direct evidence.",
        why_it_matters="Canonical rationale.", related_endpoints=("https://app.example.test/api",),
        related_evidence_ids=("EVID-CANONICAL",), related_candidate_ids=(),
        related_lead_ids=(), suggested_manual_review_order=("Review evidence.",),
        kill_switch_guidance=None,
    )


def _legacy() -> OperatorSummary:
    return OperatorSummary(
        review_first=[OperatorSummaryLead(
            title="Legacy infrastructure lead", why="Legacy rationale.",
            endpoints=["https://legacy.example.test:8443/"], evidence_ids=["EVID-LEGACY"],
            next_action="Review legacy.", signal="high", score=999,
            lead_id="LEAD-LEGACY", rank=1,
        )], low_signal=[], coverage=[],
    )


def _smb_state() -> ProjectState:
    share = SMBShare(
        host="files.example.test", port=31337, share_name="nt4wrksv",
        share_type="Disk", comment="", source_file="smb.txt",
        trigger_service_names=["microsoft-ds"],
        trigger_evidence_ids=["EVID-PORT-SMB"],
        trigger_source_files=["services.txt"], evidence_ids=["EVID-SMB-CUSTOM"],
        tags=[],
    )
    service = PortService(
        host="files.example.test", port=31337, protocol="tcp", state="open",
        service="microsoft-ds", product=None, version=None, source_file="services.txt",
        evidence_ids=["EVID-PORT-SMB"], tags=[],
    )
    return replace(_state(), port_services=[service], smb_shares=[share])


def test_markdown_review_first_prefers_canonical_thread_over_conflicting_legacy_rank() -> None:
    threads = (
        _thread("a", "First canonical review"),
        _thread("b", "Second canonical review"),
    )
    report = render_markdown_report(
        _state(), [], operator_summary=_legacy(), investigation_threads=threads,
    )

    review_first = report.split("### Low-Signal / Avoid Rabbit Holes", 1)[0]
    assert review_first.index(threads[0].thread_id) < review_first.index(threads[1].thread_id)
    assert "First canonical review" in review_first
    assert "Second canonical review" in review_first
    assert "LEAD-LEGACY" not in review_first


def test_report_view_and_terminal_projection_accept_canonical_threads() -> None:
    from bugslyce.project_pipeline import (
        PipelineCompletionSummary,
        _render_compact_run_summary,
    )
    from bugslyce.reports.operator_report_view import build_operator_report_view

    threads = (_thread("a", "First canonical review"), _thread("b", "Second canonical review"))
    view = build_operator_report_view(_legacy(), investigation_threads=threads)
    terminal = _render_compact_run_summary(PipelineCompletionSummary(
        collection_confidence_notices=(), operator_summary=_legacy(),
        investigation_threads=threads, operator_report_view=view,
    ))

    assert view.primary_anchor_ids == tuple(thread.thread_id for thread in threads)
    assert terminal is not None
    terminal_text = "\n".join(terminal)
    assert terminal_text.index(threads[0].thread_id) < terminal_text.index(threads[1].thread_id)
    assert "LEAD-LEGACY" not in terminal_text


def test_canonical_projection_preserves_smb_attention_from_full_summary() -> None:
    state = _smb_state()
    summary = build_operator_summary(state, [])
    smb = next(lead for lead in summary.ranked_leads if lead.lead_type == "smb_disk_share_review")
    threads = build_investigation_threads(
        state, compatibility_summary_leads=summary.ranked_leads,
    )
    report = render_markdown_report(
        state, [], operator_summary=summary, investigation_threads=threads,
    )

    assert smb.title in {thread.title for thread in threads}
    assert smb.title in report.split("### Low-Signal / Avoid Rabbit Holes", 1)[0]


def test_canonical_projection_preserves_successful_deep_content_attention() -> None:
    state = _state()
    legacy = OperatorSummaryLead(
        title="Successfully collected Deep content available offline",
        why="Retained successful content is available for offline review.",
        endpoints=["https://app.example.test/review/"], evidence_ids=["EVID-DEEP"],
        next_action="Review retained response.", signal="direct retained evidence",
        score=99, rank=1, lead_id="LEAD-DEEP", lead_type="successful_deep_content",
    )
    summary = OperatorSummary(review_first=[legacy], low_signal=[], coverage=[])
    threads = build_investigation_threads(state, compatibility_summary_leads=summary.ranked_leads)
    report = render_markdown_report(
        state, [], operator_summary=summary, investigation_threads=threads,
    )

    assert legacy.title in {thread.title for thread in threads}
    assert legacy.title in report.split("### Low-Signal / Avoid Rabbit Holes", 1)[0]


def test_empty_canonical_review_first_has_a_conservative_message() -> None:
    report = render_markdown_report(
        _state(), [], operator_summary=OperatorSummary(review_first=[], low_signal=[], coverage=[]),
        investigation_threads=(),
    )

    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes", 1,
    )[0]
    assert "No prioritised review item was produced." in review_first
