"""Package 3D1 canonical investigation-thread priority contracts."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.core.models import HTTPService, ProjectState, SMBShare
from bugslyce.recon.application_service_composition import (
    build_application_service_composition,
)
from bugslyce.recon.application_service_model import build_application_service_model
from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
)
from bugslyce.recon.investigation_threads import (
    _ThreadDraft,
    _thread_sort_key,
    build_investigation_threads,
)
from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    NativeStructuredResponseFact,
)
from bugslyce.reports.operator_summary import OperatorSummaryLead


def _state() -> ProjectState:
    return ProjectState(
        project_name="priority-test",
        input_dir="/tmp/priority-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        endpoints=[],
        http_services=[
            HTTPService(
                url="https://app.example.test:8443/",
                hostname="app.example.test",
                status_code=200,
                title="Default",
                technologies=[],
                content_length=1,
                evidence_ids=["EVID-HIGH-PORT"],
                tags=[],
            )
        ],
        port_services=[],
        http_artifacts=[],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-01-01T00:00:00Z",
        engagement_context="internal_authorised",
    )


def _model():
    native = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search/",
                status_code=200,
                candidate_index=7,
                exchange_index=0,
                body_sha256="a" * 64,
            ),
        )
    )
    return build_application_service_model(
        application_composition=build_application_service_composition(
            native_observation_evidence=native,
        ),
        documentation_assertions=DocumentationAssertionExtractionResult(
            assertions=(),
            skipped_sources=(),
            sources_considered=0,
            sources_eligible=0,
        ),
        native_observation_evidence=native,
    )


def _summary_lead(
    *,
    endpoint: str = "https://app.example.test/api/routes",
    evidence_id: str = "EVID-JSON",
    title: str = "Routes disclosed by structured JSON response",
    score: int = 1,
    lead_id: str = "LEAD-LOW",
    rank: int = 99,
    lead_type: str = "structured_json_routes",
) -> OperatorSummaryLead:
    return OperatorSummaryLead(
        title=title,
        why="Direct JSON route evidence.",
        endpoints=[endpoint],
        evidence_ids=[evidence_id],
        next_action="Review retained response.",
        signal="high",
        score=score,
        lead_id=lead_id,
        rank=rank,
        lead_type=lead_type,
    )


def _application_thread(threads):
    return next(
        thread for thread in threads if thread.category == "application_interface"
    )


def _draft(category: str, title: str) -> _ThreadDraft:
    return _ThreadDraft(
        title=title,
        priority="medium",
        category=category,
        summary="summary",
        why_it_matters="why",
        related_endpoints=(f"https://app.example.test/{category}",),
        related_evidence_ids=(),
        related_candidate_ids=(),
        related_lead_ids=(),
        suggested_manual_review_order=(),
        kill_switch_guidance=None,
    )


def test_supported_application_interface_outranks_generic_high_port_context() -> None:
    threads = build_investigation_threads(
        _state(),
        application_service_model=_model(),
    )

    assert [thread.category for thread in threads] == [
        "application_interface",
        "http_service",
    ]
    assert all(thread.thread_id.startswith("THREAD-") for thread in threads)
    assert all(
        len(thread.thread_id.removeprefix("THREAD-")) == 64
        for thread in threads
    )


def test_legacy_score_rank_id_and_title_do_not_control_canonical_thread() -> None:
    first = _summary_lead()
    changed = _summary_lead(
        title="Completely different legacy display title",
        score=999,
        lead_id="LEAD-HIGH",
        rank=1,
    )

    baseline = build_investigation_threads(
        _state(),
        compatibility_summary_leads=(first,),
    )
    altered = build_investigation_threads(
        _state(),
        compatibility_summary_leads=(changed,),
    )

    assert altered == baseline
    thread = _application_thread(baseline)
    assert thread.related_evidence_ids == ("EVID-JSON",)
    assert thread.priority == "medium"


def test_provenance_evidence_ids_do_not_define_semantic_thread_identity() -> None:
    first = _summary_lead(evidence_id="EVID-A")
    second = _summary_lead(evidence_id="EVID-B")

    first_thread = _application_thread(
        build_investigation_threads(
            _state(),
            compatibility_summary_leads=(first,),
        )
    )
    second_thread = _application_thread(
        build_investigation_threads(
            _state(),
            compatibility_summary_leads=(second,),
        )
    )

    assert first_thread.thread_id == second_thread.thread_id
    assert first_thread.related_evidence_ids == ("EVID-A",)
    assert second_thread.related_evidence_ids == ("EVID-B",)

    combined = build_investigation_threads(
        _state(),
        compatibility_summary_leads=(first, second),
    )
    compatibility_threads = tuple(
        thread
        for thread in combined
        if thread.category == "application_interface"
    )

    assert len(compatibility_threads) == 1
    assert compatibility_threads[0].thread_id == first_thread.thread_id
    assert compatibility_threads[0].related_evidence_ids == (
        "EVID-A",
        "EVID-B",
    )


def test_generic_compatibility_port_signal_is_ignored() -> None:
    generic_endpoint = "https://app.example.test:9443/admin"
    generic_evidence = "EVID-GENERIC"
    generic = _summary_lead(
        endpoint=generic_endpoint,
        evidence_id=generic_evidence,
        title="Generic port context",
        score=999,
        lead_id="LEAD-GENERIC",
        rank=1,
        lead_type="high_port_http_service",
    )

    threads = build_investigation_threads(
        _state(),
        compatibility_summary_leads=(generic,),
    )

    assert len(threads) == 1
    assert all(
        generic_endpoint not in thread.related_endpoints
        for thread in threads
    )
    assert all(
        generic_evidence not in thread.related_evidence_ids
        for thread in threads
    )
    assert all(thread.priority != "high" for thread in threads)


def test_smb_compatibility_thread_uses_typed_share_not_legacy_presentation_or_rank() -> None:
    state = replace(
        _state(),
        smb_shares=[
            SMBShare(
                host="files.example.test",
                port=31337,
                share_name="nt4wrksv",
                share_type="Disk",
                comment="",
                source_file="smb.txt",
                trigger_service_names=["microsoft-ds"],
                trigger_evidence_ids=["EVID-PORT-SMB"],
                trigger_source_files=["services.txt"],
                evidence_ids=["EVID-SMB-CUSTOM"],
                tags=[],
            )
        ],
    )
    first = _summary_lead(
        endpoint="files.example.test:31337/tcp",
        evidence_id="EVID-SMB-CUSTOM",
        title="Legacy wording one",
        score=1,
        lead_id="LEAD-LOW",
        rank=99,
        lead_type="smb_disk_share_review",
    )
    changed = _summary_lead(
        endpoint="files.example.test:31337/tcp",
        evidence_id="EVID-SMB-CUSTOM",
        title="Completely different legacy wording",
        score=999,
        lead_id="LEAD-HIGH",
        rank=1,
        lead_type="smb_disk_share_review",
    )

    baseline = build_investigation_threads(
        state, compatibility_summary_leads=(first,),
    )
    altered = build_investigation_threads(
        state, compatibility_summary_leads=(changed,),
    )

    assert altered == baseline
    smb = next(thread for thread in baseline if thread.category == "service_context")
    assert smb.title == "SMB Disk share observed for review: nt4wrksv"
    assert smb.related_endpoints == ("files.example.test:31337/tcp",)
    assert smb.related_evidence_ids == ("EVID-SMB-CUSTOM",)
    assert smb.priority == "medium"


def test_low_priority_service_context_does_not_outrank_supported_application_evidence() -> None:
    service_context = _summary_lead(
        endpoint="files.example.test:22/tcp",
        evidence_id="EVID-SSH",
        title="SSH service context on 22/tcp",
        score=999,
        lead_id="LEAD-SERVICE",
        rank=1,
        lead_type="non_http_service_context",
    )

    threads = build_investigation_threads(
        _state(), application_service_model=_model(),
        compatibility_summary_leads=(service_context,),
    )

    assert threads[0].category == "application_interface"
    assert threads[-1].category == "service_context"
    assert threads[-1].priority == "low"


def test_compatibility_permutation_and_limitations_remain_canonical() -> None:
    leads = (
        _summary_lead(
            endpoint="https://app.example.test/api/one",
            evidence_id="EVID-one",
            score=100,
            lead_id="LEAD-one",
            rank=1,
        ),
        _summary_lead(
            endpoint="https://app.example.test/api/two",
            evidence_id="EVID-two",
            score=99,
            lead_id="LEAD-two",
            rank=2,
        ),
    )

    forwards = build_investigation_threads(
        _state(),
        compatibility_summary_leads=leads,
    )
    backwards = build_investigation_threads(
        _state(),
        compatibility_summary_leads=tuple(reversed(leads)),
    )

    assert backwards == forwards
    assert all(thread.thread_id.startswith("THREAD-") for thread in forwards)
    assert all(
        "structured_response_not_confirmed_api" in thread.limitation_codes
        for thread in forwards
        if thread.category == "application_interface"
    )


def test_application_priority_change_only_demotes_generic_http_context() -> None:
    ordered = sorted(
        (
            _draft("application_interface", "Application interface"),
            _draft("account_workflow", "Account workflow"),
            _draft("object_reference_surface", "Object reference"),
            _draft("http_service", "HTTP service"),
        ),
        key=_thread_sort_key,
    )

    assert [draft.category for draft in ordered] == [
        "account_workflow",
        "object_reference_surface",
        "application_interface",
        "http_service",
    ]
