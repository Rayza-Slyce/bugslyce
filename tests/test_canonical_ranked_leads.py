"""Canonical ranked-lead contract regressions."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from bugslyce.core.models import PortService, SMBShare
from bugslyce.core.project import build_project_state
from bugslyce.project_pipeline import _render_compact_run_summary
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
)
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.reports.operator_summary import (
    OperatorSummaryLead,
    build_operator_summary,
)
from bugslyce.triage.candidates import generate_candidates


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "demo_recon"
    / "lab_raw_recon_pack"
)


def test_operator_summary_and_human_triage_share_one_ordered_lead_contract() -> None:
    state = build_project_state(FIXTURE)
    candidates = generate_candidates(state)
    summary = build_operator_summary(state, candidates)
    brief = build_human_triage_brief(
        state,
        candidates,
        ranked_leads=summary.review_first,
    )

    assert tuple(brief.ranked_leads) == tuple(summary.review_first)
    assert [lead.lead_id for lead in brief.ranked_leads] == [
        lead.lead_id for lead in summary.review_first
    ]
    assert [lead.rank for lead in summary.review_first] == list(
        range(1, len(summary.review_first) + 1)
    )

    standalone_triage = render_human_triage_brief_markdown(brief)
    embedded_triage = render_human_triage_brief_markdown(
        brief,
        include_ranked_leads=False,
    )
    report = render_markdown_report(
        state,
        candidates,
        human_triage_brief_markdown=embedded_triage,
        operator_summary=summary,
    )
    for lead in summary.review_first:
        assert lead.lead_id not in embedded_triage
        assert report.count(lead.lead_id) == 1
    standalone_positions = [
        standalone_triage.index(lead.lead_id) for lead in summary.review_first
    ]
    assert standalone_positions == sorted(standalone_positions)
    assert "Canonical ranked leads are listed in the Operator Summary above." in embedded_triage
    assert "### Supporting Evidence Prompts (not ranked)" in embedded_triage
    assert brief.start_here
    assert brief.start_here[0].title in embedded_triage


def test_canonical_ranked_leads_are_stable_under_reversed_inputs() -> None:
    state = build_project_state(FIXTURE)
    candidates = generate_candidates(state)
    additions = tuple(
        OperatorSummaryLead(
            title=f"Neutral ordered lead {index}",
            why="Direct retained evidence supports bounded review.",
            endpoints=[f"https://app.example.test/ordered/{index}"],
            evidence_ids=[f"EVID-ORDERED-{index:04d}"],
            next_action="Review the retained artefact.",
            signal="direct retained evidence",
            score=900 - index,
            lead_type="direct_evidence_review",
        )
        for index in range(3)
    )

    forwards = build_operator_summary(
        state,
        candidates,
        additional_leads=additions,
    ).review_first
    backwards = build_operator_summary(
        state,
        list(reversed(candidates)),
        additional_leads=tuple(reversed(additions)),
    ).review_first

    assert backwards == forwards
    assert [lead.lead_id for lead in backwards] == [
        lead.lead_id for lead in forwards
    ]


def test_detailed_markdown_preserves_complete_canonical_membership() -> None:
    state = build_project_state(FIXTURE)
    candidates = generate_candidates(state)
    endpoints = [f"https://app.example.test/review/{index:02d}" for index in range(12)]
    evidence_ids = [f"EVID-NEUTRAL-{index:04d}" for index in range(12)]
    summary = build_operator_summary(
        state,
        candidates,
        additional_leads=(
            OperatorSummaryLead(
                title="Neutral direct evidence review",
                why="Several directly observed records warrant bounded manual review.",
                endpoints=list(reversed(endpoints)),
                evidence_ids=list(reversed(evidence_ids)),
                next_action="Review the retained artefacts offline.",
                signal="direct retained evidence",
                score=999,
                lead_type="direct_evidence_review",
            ),
        ),
    )
    brief = build_human_triage_brief(
        state,
        candidates,
        ranked_leads=summary.review_first,
    )

    triage = render_human_triage_brief_markdown(
        brief,
        include_ranked_leads=False,
    )
    report = render_markdown_report(
        state,
        candidates,
        human_triage_brief_markdown=triage,
        operator_summary=summary,
    )
    lead = summary.review_first[0]

    assert lead.endpoints == sorted(endpoints)
    assert lead.evidence_ids == sorted(evidence_ids)
    for value in (*endpoints, *evidence_ids):
        assert value in report


def test_canonical_contract_deduplicates_before_assigning_rank_and_identity() -> None:
    state = build_project_state(FIXTURE)
    duplicate = OperatorSummaryLead(
        title="Shared neutral review",
        why="Direct evidence supports one manual review lead.",
        endpoints=["https://app.example.test/item"],
        evidence_ids=["EVID-NEUTRAL-0001"],
        next_action="Review the retained artefact.",
        signal="direct retained evidence",
        score=999,
        lead_type="direct_evidence_review",
    )

    leads = build_operator_summary(
        state,
        generate_candidates(state),
        additional_leads=(duplicate, duplicate),
    ).review_first

    matching = [lead for lead in leads if lead.title == duplicate.title]
    assert len(matching) == 1
    assert matching[0].rank == 1
    assert matching[0].lead_id
    assert len({lead.lead_id for lead in leads}) == len(leads)


def test_compact_presentation_preserves_canonical_rank_and_identity() -> None:
    state = build_project_state(FIXTURE)
    summary = build_operator_summary(state, generate_candidates(state))
    ranks_before = [(lead.lead_id, lead.rank) for lead in summary.review_first]

    rendered = "\n".join(
        _render_compact_run_summary(
            SimpleNamespace(
                collection_confidence_notices=(),
                operator_summary=summary,
            )
        )
        or ()
    )

    assert [(lead.lead_id, lead.rank) for lead in summary.review_first] == ranks_before
    for lead in summary.review_first[:5]:
        assert f"{lead.rank}. [{lead.lead_id}]" in rendered


def _smb_share(
    name: str,
    *,
    share_type: str = "Disk",
    evidence_id: str = "EVID-SMB-CUSTOM",
) -> SMBShare:
    return SMBShare(
        host="files.example.test",
        port=31337,
        share_name=name,
        share_type=share_type,
        comment="",
        source_file="smb-shares-files.example.test-31337-guest.txt",
        trigger_service_names=["microsoft-ds"],
        trigger_evidence_ids=["EVID-PORT-SMB"],
        trigger_source_files=["nmap-services-all.txt"],
        evidence_ids=[evidence_id],
        tags=[],
    )


def _state_with_smb_shares(
    shares: list[SMBShare],
):
    state = build_project_state(FIXTURE)
    return replace(
        state,
        http_services=[],
        http_artifacts=[],
        discovered_paths=[],
        port_services=[
            PortService(
                host="files.example.test",
                port=31337,
                protocol="tcp",
                state="open",
                service="microsoft-ds",
                product=None,
                version=None,
                source_file="nmap-services-all.txt",
                evidence_ids=["EVID-PORT-SMB"],
                tags=[],
            )
        ],
        smb_shares=shares,
    )


def test_custom_smb_disk_share_becomes_canonical_review_lead() -> None:
    state = _state_with_smb_shares(
        [_smb_share("nt4wrksv")]
    )

    summary = build_operator_summary(state, [])

    lead = next(
        item
        for item in summary.ranked_leads
        if item.lead_type == "smb_disk_share_review"
    )

    assert lead.title == "SMB Disk share observed for review: nt4wrksv"
    assert lead.endpoints == ["files.example.test:31337/tcp"]
    assert lead.evidence_ids == ["EVID-SMB-CUSTOM"]
    assert "EVID-PORT-SMB" not in lead.evidence_ids
    assert lead.score == 64
    assert lead.lead_id
    assert lead.rank > 0

    service_lead = next(
        item
        for item in summary.ranked_leads
        if item.lead_type == "non_http_service_context"
    )

    assert lead.rank < service_lead.rank
    assert lead.score > service_lead.score


def test_custom_smb_disk_share_reaches_markdown_review_first() -> None:
    state = _state_with_smb_shares(
        [_smb_share("nt4wrksv")]
    )
    summary = build_operator_summary(state, [])

    report = render_markdown_report(
        state,
        [],
        operator_summary=summary,
    )
    review_first = report.split(
        "### Review First",
        1,
    )[1].split(
        "##",
        1,
    )[0]

    assert "SMB Disk share observed for review: nt4wrksv" in review_first
    assert "EVID-SMB-CUSTOM" in review_first
    assert "files.example.test:31337/tcp" in review_first


def test_obvious_administrative_smb_shares_are_not_promoted() -> None:
    state = _state_with_smb_shares(
        [
            _smb_share("ADMIN$", evidence_id="EVID-SMB-ADMIN"),
            _smb_share("admin$", evidence_id="EVID-SMB-ADMIN-LOWER"),
            _smb_share("C$", evidence_id="EVID-SMB-C"),
            _smb_share("z$", evidence_id="EVID-SMB-Z"),
            _smb_share(
                "IPC$",
                share_type="IPC",
                evidence_id="EVID-SMB-IPC",
            ),
            _smb_share(
                "OfficePrinter",
                share_type="Printer",
                evidence_id="EVID-SMB-PRINTER",
            ),
        ]
    )

    summary = build_operator_summary(state, [])

    assert not any(
        lead.lead_type == "smb_disk_share_review"
        for lead in summary.ranked_leads
    )


def test_custom_hidden_smb_disk_share_remains_review_eligible() -> None:
    state = _state_with_smb_shares(
        [_smb_share("private$")]
    )

    summary = build_operator_summary(state, [])

    lead = next(
        item
        for item in summary.ranked_leads
        if item.lead_type == "smb_disk_share_review"
    )

    assert lead.title == "SMB Disk share observed for review: private$"
    assert lead.evidence_ids == ["EVID-SMB-CUSTOM"]


def test_smb_share_lead_order_and_identity_are_input_stable() -> None:
    shares = [
        _smb_share(
            "engineering",
            evidence_id="EVID-SMB-ENGINEERING",
        ),
        _smb_share(
            "backups",
            evidence_id="EVID-SMB-BACKUPS",
        ),
    ]

    forwards = build_operator_summary(
        _state_with_smb_shares(shares),
        [],
    ).ranked_leads
    backwards = build_operator_summary(
        _state_with_smb_shares(list(reversed(shares))),
        [],
    ).ranked_leads

    forwards_smb = [
        lead
        for lead in forwards
        if lead.lead_type == "smb_disk_share_review"
    ]
    backwards_smb = [
        lead
        for lead in backwards
        if lead.lead_type == "smb_disk_share_review"
    ]

    assert backwards_smb == forwards_smb
    assert [lead.lead_id for lead in backwards_smb] == [
        lead.lead_id for lead in forwards_smb
    ]
