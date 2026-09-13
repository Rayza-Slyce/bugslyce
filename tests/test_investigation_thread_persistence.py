"""Package 3C canonical investigation-thread persistence contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.recon.investigation_threads import InvestigationThread


def _thread() -> InvestigationThread:
    return InvestigationThread(
        thread_id="THREAD-" + "a" * 64,
        title="Observed application interface review",
        priority="medium",
        category="application_interface",
        summary="A structured response and direct redirect relationship were observed.",
        why_it_matters="The interface warrants bounded human review.",
        related_endpoints=("https://app.example.test/api/search/",),
        related_evidence_ids=("EVID-APP",),
        related_candidate_ids=(),
        related_lead_ids=(),
        suggested_manual_review_order=("Review the retained response evidence.",),
        kill_switch_guidance="Stop if the evidence does not support the interface.",
        related_native_observation_ids=(
            "native-observation:7:0",
            "native-observation:8:0",
        ),
        related_application_relation_ids=("A1-RELATION-EXAMPLE",),
        limitation_codes=(
            "redirect_destination_not_fetched",
            "structured_response_not_confirmed_api",
        ),
    )


def test_canonical_thread_snapshot_round_trips_exactly(tmp_path: Path) -> None:
    from bugslyce.recon.investigation_thread_persistence import (
        investigation_threads_to_dict,
        load_investigation_threads_artifact,
        write_investigation_threads_artifact,
    )

    threads = (_thread(),)
    path = write_investigation_threads_artifact(tmp_path, threads)

    assert path.name == "investigation_threads.json"
    assert investigation_threads_to_dict(threads) == {
        "schema_version": 1,
        "generated_by": "bugslyce.investigation_threads",
        "threads": [
            {
                "thread_id": "THREAD-" + "a" * 64,
                "title": "Observed application interface review",
                "priority": "medium",
                "category": "application_interface",
                "summary": "A structured response and direct redirect relationship were observed.",
                "why_it_matters": "The interface warrants bounded human review.",
                "related_endpoints": ["https://app.example.test/api/search/"],
                "related_evidence_ids": ["EVID-APP"],
                "related_candidate_ids": [],
                "related_lead_ids": [],
                "suggested_manual_review_order": ["Review the retained response evidence."],
                "kill_switch_guidance": "Stop if the evidence does not support the interface.",
                "related_native_observation_ids": [
                    "native-observation:7:0",
                    "native-observation:8:0",
                ],
                "related_application_relation_ids": ["A1-RELATION-EXAMPLE"],
                "limitation_codes": [
                    "redirect_destination_not_fetched",
                    "structured_response_not_confirmed_api",
                ],
            }
        ],
    }
    assert load_investigation_threads_artifact(tmp_path) == threads


def test_optional_absence_and_noncanonical_thread_payloads_fail_closed(tmp_path: Path) -> None:
    from bugslyce.recon.investigation_thread_persistence import (
        load_investigation_threads_artifact,
    )

    assert load_investigation_threads_artifact(tmp_path) is None
    path = tmp_path / "investigation_threads.json"
    payload = {
        "schema_version": 1,
        "generated_by": "bugslyce.investigation_threads",
        "threads": [
            {
                "thread_id": "THREAD-0001",
                "title": "bad",
                "priority": "low",
                "category": "bad",
                "summary": "bad",
                "why_it_matters": "bad",
                "related_endpoints": [], "related_evidence_ids": [],
                "related_candidate_ids": [], "related_lead_ids": [],
                "suggested_manual_review_order": [], "kill_switch_guidance": None,
                "related_native_observation_ids": [],
                "related_application_relation_ids": [], "limitation_codes": [],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="thread_id"):
        load_investigation_threads_artifact(tmp_path)

    payload["threads"] = [
        {**_thread_payload(_thread())},
        {**_thread_payload(_thread())},
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_investigation_threads_artifact(tmp_path)


def _thread_payload(thread: InvestigationThread) -> dict[str, object]:
    return {
        "thread_id": thread.thread_id, "title": thread.title, "priority": thread.priority,
        "category": thread.category, "summary": thread.summary,
        "why_it_matters": thread.why_it_matters,
        "related_endpoints": list(thread.related_endpoints),
        "related_evidence_ids": list(thread.related_evidence_ids),
        "related_candidate_ids": list(thread.related_candidate_ids),
        "related_lead_ids": list(thread.related_lead_ids),
        "suggested_manual_review_order": list(thread.suggested_manual_review_order),
        "kill_switch_guidance": thread.kill_switch_guidance,
        "related_native_observation_ids": list(thread.related_native_observation_ids),
        "related_application_relation_ids": list(thread.related_application_relation_ids),
        "limitation_codes": list(thread.limitation_codes),
    }


def test_thread_snapshot_closure_binds_exact_model_and_native_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Thread closure may only reuse native facts represented by the A3 model."""
    from types import SimpleNamespace

    from bugslyce.recon import evidence_pack_closure as closure
    from bugslyce.recon.native_observation_facts import (
        NativeRedirectRelationship,
        NativeStructuredResponseFact,
    )

    thread = _thread()
    fact = NativeStructuredResponseFact(
        request_url="https://app.example.test/api/search/", status_code=200,
        candidate_index=7, exchange_index=0, body_sha256="b" * 64,
    )
    model = SimpleNamespace(
        application_composition=SimpleNamespace(
            relations=(SimpleNamespace(relation_id="A1-RELATION-EXAMPLE"),),
        ),
        native_observation_evidence=SimpleNamespace(
            structured_responses=(fact,), mobile_association_declarations=(),
            redirect_relationships=(NativeRedirectRelationship(
                source_url="https://app.example.test/api/search",
                raw_location="/api/search/",
                target_url="https://app.example.test/api/search/",
                candidate_index=8,
                exchange_index=0,
            ),),
        ),
    )
    exchange = SimpleNamespace(
        body=SimpleNamespace(relative_path="bodies/sha256/bb/blob"),
        body_sha256="b" * 64,
    )
    store = SimpleNamespace(load_observation=lambda index: SimpleNamespace(exchanges=(exchange,)))
    (tmp_path / "native-observations").mkdir()
    monkeypatch.setattr(closure, "load_investigation_threads_artifact", lambda _root: (thread,))
    monkeypatch.setattr(closure, "load_application_service_model_artifact", lambda _root: model)
    monkeypatch.setattr(closure, "validate_native_observation_store", lambda _root: SimpleNamespace(body_byte_allowance=1, metadata_byte_allowance=1))
    monkeypatch.setattr(closure, "NativeObservationStore", lambda *_args, **_kwargs: store)

    references = closure._investigation_thread_references(
        tmp_path,
        (closure.EvidencePackReference(
            portable_path="raw/application.txt", owner_kind="project_state_evidence",
            owner_id="application", evidence_ids=("EVID-APP",),
            source_path="application.txt",
        ),),
        references_are_portable=False,
    )
    assert {(item.owner_kind, item.portable_path) for item in references} == {
        ("investigation_thread_snapshot", "investigation_threads.json"),
        ("investigation_thread_application_relation", "application_service_model.json"),
        ("investigation_thread_native_observation", "native-observations/observations/00000007.json"),
        ("investigation_thread_native_observation", "native-observations/observations/00000008.json"),
        ("investigation_thread_native_observation", "native-observations/bodies/sha256/bb/blob"),
        ("investigation_thread_evidence_support", "raw/application.txt"),
    }

    bad = InvestigationThread(**{**thread.__dict__, "related_native_observation_ids": ("native-observation:99:0",)})
    monkeypatch.setattr(closure, "load_investigation_threads_artifact", lambda _root: (bad,))
    with pytest.raises(ValueError, match="not represented"):
        closure._investigation_thread_references(
            tmp_path,
            (),
            references_are_portable=False,
        )

    bad_relation = InvestigationThread(
        **{
            **thread.__dict__,
            "related_application_relation_ids": (
                "APP-RELATION-" + "f" * 64,
            ),
        }
    )
    monkeypatch.setattr(
        closure,
        "load_investigation_threads_artifact",
        lambda _root: (bad_relation,),
    )
    with pytest.raises(ValueError, match="unknown application relation"):
        closure._investigation_thread_references(
            tmp_path,
            (),
            references_are_portable=False,
        )
