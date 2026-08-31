"""RED contract for deterministic Operator Brief thread policy."""

from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path
import re

import pytest

from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
)
from bugslyce.reports.operator_brief import (
    DEPRIORITISED_CONTEXT,
    EVIDENCE_ONLY,
    PRIMARY_THREAD,
    SUPPORTING_CONTEXT,
    OperatorBriefConflict,
    OperatorBriefConflictKind,
    OperatorBriefConflictObservation,
    OperatorBriefCoverageLimitation,
    OperatorBriefDisposition,
    OperatorBriefDispositionReason,
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceRanking,
    OperatorBriefSubjectKind,
    OperatorBriefThread,
    OperatorBriefView,
    load_operator_brief_artifact,
    write_operator_brief_artifact,
)


def _policy_api():
    from bugslyce.reports.operator_brief_thread_policy import (
        OperatorBriefAttentionSignal,
        OperatorBriefThreadEvidenceBasis,
        OperatorBriefThreadMateriality,
        OperatorBriefThreadPolicyDecision,
        OperatorBriefThreadPolicyReason,
        OperatorBriefThreadPolicyResult,
        OperatorBriefThreadPolicySubject,
        OperatorBriefThreadSpecificity,
        apply_operator_brief_thread_policy,
    )

    return locals()


def _ranking(
    lead_id: str,
    *,
    rank: int = 1,
    score: int = 80,
    signal: str = "legacy attention",
) -> OperatorBriefSourceRanking:
    return OperatorBriefSourceRanking(lead_id, rank, score, signal)


def _thread(
    *,
    rankings: tuple[OperatorBriefSourceRanking, ...] = (),
    thread_id: str = "THREAD-COMPAT",
    identity_key: str = "application:https://example.test",
) -> OperatorBriefThread:
    return OperatorBriefThread(
        thread_id=thread_id,
        identity_key=identity_key,
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
        title="Compatibility thread",
        rank=1,
        signal="legacy signal",
        source_lead_ids=tuple(item.source_lead_id for item in rankings),
        endpoints=("https://example.test/",),
        origins=("https://example.test",),
        evidence_ids=("EVID-ONE",),
        why_review="Retained compatibility evidence.",
        next_review_step="Review retained evidence.",
        source_rankings=rankings,
    )


def _fact(
    fact_id: str,
    *,
    semantic_class: OperatorBriefSemanticClass = OperatorBriefSemanticClass.OBSERVED,
    role: OperatorBriefFactRole = OperatorBriefFactRole.DIRECT_EVIDENCE,
    status: int | None = None,
) -> OperatorBriefFact:
    return OperatorBriefFact(
        fact_id=fact_id,
        kind=OperatorBriefFactKind.HTTP_ROUTE,
        semantic_class=semantic_class,
        role=role,
        label=f"Retained route fact {fact_id}",
        summary=f"Retained route fact {fact_id}.",
        endpoints=("https://example.test/review",),
        origins=("https://example.test",),
        evidence_ids=(f"EVID-{fact_id}",),
        route="https://example.test/review",
        http_status_code=status,
    )


def _conflict() -> OperatorBriefConflict:
    endpoint = "https://example.test/review"
    return OperatorBriefConflict(
        conflict_id="CONFLICT-STATUS",
        kind=OperatorBriefConflictKind.DIFFERING_HTTP_STATUS,
        subject_endpoint=endpoint,
        observations=(
            OperatorBriefConflictObservation(
                "OBS-404", endpoint, "GET", 404, "retained_path",
                ("EVID-404",), ("gobuster.txt",),
            ),
            OperatorBriefConflictObservation(
                "OBS-200", endpoint, "GET", 200, "retained_path",
                ("EVID-200",), ("followup.txt",),
            ),
        ),
        summary="Retained observations have differing statuses.",
    )


def _limitation(
    limitation_id: str = "COVERAGE-FORMS-ONE",
) -> OperatorBriefCoverageLimitation:
    return OperatorBriefCoverageLimitation(
        limitation_id=limitation_id,
        capability="deep_form_inventory",
        source_role="deep_source_response",
        source_id="DEEP-SOURCE-ONE",
        state=AnalysisCoverageState.ANALYSED,
        outcome=AnalysisCoverageOutcome.NO_FINDING,
        unknown_reason=None,
        execution_note=None,
        summary="Zero forms in the retained body for DEEP-SOURCE-ONE.",
    )


def _subject(
    api,
    *,
    policy_key: str = "POLICY-A",
    semantic_key: str | None = "application:https://example.test",
    subject_kind: OperatorBriefSubjectKind = OperatorBriefSubjectKind.APPLICATION,
    materiality: str = "material",
    specificity: str = "specific",
    evidence_basis: str = "direct",
    independent: bool = True,
    associated_subject_reference=None,
    replaced_by_subject_reference=None,
    facts: tuple[OperatorBriefFact, ...] = (),
    conflicts: tuple[OperatorBriefConflict, ...] = (),
    coverage_limitations: tuple[OperatorBriefCoverageLimitation, ...] = (),
    source_rankings: tuple[OperatorBriefSourceRanking, ...] = (),
    source_lead_ids: tuple[str, ...] = (),
):
    relationship_fields = {}
    if associated_subject_reference is not None:
        relationship_fields["associated_subject_reference"] = (
            associated_subject_reference
        )
    if replaced_by_subject_reference is not None:
        relationship_fields["replaced_by_subject_reference"] = (
            replaced_by_subject_reference
        )
    return api["OperatorBriefThreadPolicySubject"](
        policy_key=policy_key,
        semantic_subject_key=semantic_key,
        subject_kind=subject_kind,
        materiality=api["OperatorBriefThreadMateriality"](materiality),
        specificity=api["OperatorBriefThreadSpecificity"](specificity),
        evidence_basis=api["OperatorBriefThreadEvidenceBasis"](evidence_basis),
        independent=independent,
        facts=facts,
        conflicts=conflicts,
        coverage_limitations=coverage_limitations,
        source_rankings=source_rankings,
        source_lead_ids=source_lead_ids,
        **relationship_fields,
    )


def _subject_reference(
    subject_kind: OperatorBriefSubjectKind,
    semantic_subject_key: str,
):
    from bugslyce.reports.operator_brief_thread_policy import (
        OperatorBriefThreadPolicySubjectReference,
    )

    return OperatorBriefThreadPolicySubjectReference(
        subject_kind=subject_kind,
        semantic_subject_key=semantic_subject_key,
    )


def _apply(api, *subjects):
    return api["apply_operator_brief_thread_policy"](tuple(subjects))


def _decision(result, policy_key: str):
    return next(item for item in result.decisions if item.policy_key == policy_key)


# Existing schema and compatibility controls.


def test_thread_without_source_ranking_has_no_compatibility_score() -> None:
    assert _thread().score is None


def test_single_source_thread_preserves_exact_compatibility_score() -> None:
    assert _thread(rankings=(_ranking("LEAD-ONE", score=73),)).score == 73


def test_multi_source_thread_has_no_aggregate_score() -> None:
    assert _thread(
        rankings=(
            _ranking("LEAD-ONE", score=73),
            _ranking("LEAD-TWO", rank=2, score=91),
        )
    ).score is None


def test_reversing_multi_source_rankings_cannot_select_a_score() -> None:
    rankings = (
        _ranking("LEAD-ONE", score=73),
        _ranking("LEAD-TWO", rank=2, score=91),
    )
    assert _thread(rankings=rankings).score is None
    assert _thread(rankings=tuple(reversed(rankings))).score is None


def test_source_provenance_enrichment_cannot_create_aggregate_score() -> None:
    assert _thread(
        rankings=(
            _ranking("LEAD-ONE", score=73),
            _ranking("LEAD-TWO", rank=2, score=91),
            _ranking("LEAD-THREE", rank=3, score=40),
        )
    ).score is None


def test_thread_identity_does_not_depend_on_compatibility_score() -> None:
    first = _thread(rankings=(_ranking("LEAD-ONE", score=10),))
    second = _thread(rankings=(_ranking("LEAD-ONE", score=99),))

    assert (first.thread_id, first.identity_key) == (
        second.thread_id,
        second.identity_key,
    )


def test_schema_v1_single_score_reconstructs_one_source_ranking(tmp_path: Path) -> None:
    payload = {
        "schema_version": 1,
        "generated_by": "bugslyce.operator_brief",
        "threads": [
            {
                "thread_id": "THREAD-LEGACY",
                "title": "Legacy canonical lead",
                "rank": 1,
                "score": 73,
                "signal": "medium",
                "source_lead_ids": ["LEAD-LEGACY"],
                "endpoints": ["https://example.test/admin"],
                "evidence_ids": ["EVID-LEGACY"],
                "why_review": "Legacy deterministic rationale.",
                "next_review_step": "Review retained evidence.",
                "observed_facts": [],
                "related_context": [],
                "conflicts": [],
                "coverage_limitations": [],
                "unknowns": [],
                "source_artefacts": ["project_state.json"],
            }
        ],
        "dispositions": [
            {
                "source_kind": "operator_summary_lead",
                "source_id": "LEAD-LEGACY",
                "disposition": PRIMARY_THREAD,
                "thread_id": "THREAD-LEGACY",
            }
        ],
    }
    (tmp_path / "operator_brief.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    brief = load_operator_brief_artifact(tmp_path)

    assert brief is not None
    assert brief.threads[0].score == 73
    assert brief.threads[0].source_rankings == (
        _ranking("LEAD-LEGACY", score=73, signal="medium"),
    )


def test_schema_v2_persists_source_rankings_without_thread_score(tmp_path: Path) -> None:
    thread = _thread(rankings=(_ranking("LEAD-ONE", score=73),))
    brief = OperatorBriefView(
        threads=(thread,),
        dispositions=(
            OperatorBriefDisposition(
                "operator_summary_lead",
                "LEAD-ONE",
                PRIMARY_THREAD,
                thread.thread_id,
                OperatorBriefDispositionReason.PRIMARY_SUBJECT,
            ),
        ),
    )

    path = write_operator_brief_artifact(tmp_path, brief)
    persisted = json.loads(path.read_text(encoding="utf-8"))["threads"][0]

    assert "score" not in persisted
    assert persisted["source_rankings"][0]["score"] == 73
    assert load_operator_brief_artifact(tmp_path) == brief


@pytest.mark.parametrize(
    "disposition",
    (PRIMARY_THREAD, SUPPORTING_CONTEXT, DEPRIORITISED_CONTEXT, EVIDENCE_ONLY),
)
def test_existing_disposition_schema_represents_policy_values(disposition: str) -> None:
    requires_thread = disposition in {PRIMARY_THREAD, SUPPORTING_CONTEXT}
    item = OperatorBriefDisposition(
        source_kind="policy_subject",
        source_id=f"SUBJECT-{disposition}",
        disposition=disposition,
        thread_id="THREAD-TARGET" if requires_thread else "",
    )

    assert item.disposition == disposition


def test_existing_rank_convention_is_one_based() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        OperatorBriefThread(
            thread_id="THREAD-ZERO",
            title="Invalid zero rank",
            rank=0,
            signal="legacy",
            source_lead_ids=(),
            endpoints=(),
            evidence_ids=(),
            why_review="Invalid rank control.",
            next_review_step="No action.",
        )


def test_existing_view_has_no_five_thread_schema_cap() -> None:
    threads = tuple(
        _thread(thread_id=f"THREAD-{index}", identity_key=f"subject:{index}")
        for index in range(1, 7)
    )
    assert len(OperatorBriefView(threads=threads, dispositions=()).threads) == 6


# Future policy model and behavior.


def test_policy_api_has_no_aggregate_score_field() -> None:
    api = _policy_api()
    subject_fields = {item.name for item in fields(api["OperatorBriefThreadPolicySubject"])}
    decision_fields = {item.name for item in fields(api["OperatorBriefThreadPolicyDecision"])}

    assert "score" not in subject_fields | decision_fields
    assert "aggregate_score" not in subject_fields | decision_fields


@pytest.mark.parametrize(
    ("materiality", "specificity", "basis", "expected"),
    (
        ("material", "specific", "direct", "specific_direct"),
        ("material", "general", "direct", "general_direct"),
        ("material", "specific", "legacy", "specific_legacy"),
        ("material", "general", "legacy", "general_legacy"),
        ("context", "specific", "derived", "specific_derived"),
        ("context", "general", "derived", "general_derived"),
        ("evidence_only", "general", "direct", "evidence_only"),
    ),
)
def test_closed_attention_signal_vocabulary(
    materiality: str,
    specificity: str,
    basis: str,
    expected: str,
) -> None:
    api = _policy_api()
    subject = _subject(
        api,
        materiality=materiality,
        specificity=specificity,
        evidence_basis=basis,
        independent=materiality == "material",
    )

    assert _decision(_apply(api, subject), subject.policy_key).signal.value == expected


def test_attention_signal_ignores_source_score_and_provenance_order() -> None:
    api = _policy_api()
    first = _subject(
        api,
        source_rankings=(
            _ranking("LEAD-A", score=10),
            _ranking("LEAD-B", rank=2, score=99),
        ),
        source_lead_ids=("LEAD-A", "LEAD-B"),
    )
    second = _subject(
        api,
        source_rankings=tuple(reversed(first.source_rankings)),
        source_lead_ids=tuple(reversed(first.source_lead_ids)),
    )

    assert _decision(_apply(api, first), "POLICY-A").signal == _decision(
        _apply(api, second), "POLICY-A"
    ).signal


def test_attention_signal_ignores_fact_count() -> None:
    api = _policy_api()
    sparse = _subject(api, facts=(_fact("ONE"),))
    dense = _subject(api, facts=tuple(_fact(f"MANY-{index}") for index in range(8)))

    assert _decision(_apply(api, sparse), "POLICY-A").signal == _decision(
        _apply(api, dense), "POLICY-A"
    ).signal


def test_policy_signal_vocabulary_is_not_severity_or_probability() -> None:
    api = _policy_api()
    forbidden = {"critical", "high", "medium", "low", "risk", "severity", "probability"}
    values = {item.value for item in api["OperatorBriefAttentionSignal"]}

    assert values == {
        "specific_direct", "general_direct", "specific_legacy",
        "general_legacy", "specific_derived", "general_derived",
        "specific_documented", "general_documented",
        "evidence_only",
    }
    assert not values & forbidden


def test_material_independent_subject_is_primary() -> None:
    api = _policy_api()
    decision = _decision(_apply(api, _subject(api)), "POLICY-A")

    assert decision.disposition == PRIMARY_THREAD
    assert decision.rank == 1
    assert decision.thread_id


def test_associated_context_is_supporting_context() -> None:
    api = _policy_api()
    primary = _subject(api)
    context = _subject(
        api,
        policy_key="POLICY-CONTEXT",
        semantic_key="service:https://example.test:443",
        materiality="context",
        specificity="general",
        independent=False,
        associated_subject_reference=_subject_reference(
            primary.subject_kind, primary.semantic_subject_key
        ),
    )
    result = _apply(api, context, primary)

    assert _decision(result, "POLICY-CONTEXT").disposition == SUPPORTING_CONTEXT
    assert _decision(result, "POLICY-CONTEXT").thread_id == _decision(
        result, "POLICY-A"
    ).thread_id


def test_unassociated_context_is_deprioritised() -> None:
    api = _policy_api()
    context = _subject(
        api,
        materiality="context",
        specificity="general",
        independent=False,
    )
    decision = _decision(_apply(api, context), "POLICY-A")

    assert decision.disposition == DEPRIORITISED_CONTEXT
    assert decision.thread_id == ""


def test_evidence_only_subject_has_evidence_only_disposition() -> None:
    api = _policy_api()
    subject = _subject(
        api,
        materiality="evidence_only",
        specificity="general",
        independent=False,
    )
    decision = _decision(_apply(api, subject), "POLICY-A")

    assert decision.disposition == EVIDENCE_ONLY
    assert decision.signal.value == "evidence_only"


def test_every_input_gets_exactly_one_deterministic_disposition() -> None:
    api = _policy_api()
    subjects = (
        _subject(api),
        _subject(api, policy_key="POLICY-B", semantic_key="application:b.example"),
        _subject(
            api,
            policy_key="POLICY-C",
            semantic_key="context:c.example",
            materiality="context",
            independent=False,
        ),
    )

    first = _apply(api, *subjects)
    second = _apply(api, *reversed(subjects))

    assert first == second
    assert len(first.decisions) == len(subjects)
    assert len({item.policy_key for item in first.decisions}) == len(subjects)


def test_source_rankings_do_not_change_disposition() -> None:
    api = _policy_api()
    low = _subject(
        api,
        source_rankings=(_ranking("LEAD-LOW", score=1),),
        source_lead_ids=("LEAD-LOW",),
    )
    high = _subject(
        api,
        source_rankings=(_ranking("LEAD-HIGH", score=99),),
        source_lead_ids=("LEAD-HIGH",),
    )

    assert _decision(_apply(api, low), "POLICY-A").disposition == PRIMARY_THREAD
    assert _decision(_apply(api, high), "POLICY-A").disposition == PRIMARY_THREAD


def test_material_derived_only_subject_fails_closed() -> None:
    api = _policy_api()
    subject = _subject(api, evidence_basis="derived")

    with pytest.raises(ValueError, match="derived.*primary|material.*derived"):
        _apply(api, subject)


def test_primary_rank_policy_order_is_specificity_then_basis() -> None:
    api = _policy_api()
    subjects = (
        _subject(api, policy_key="GENERAL-LEGACY", semantic_key="d", specificity="general", evidence_basis="legacy"),
        _subject(api, policy_key="GENERAL-DIRECT", semantic_key="c", specificity="general"),
        _subject(api, policy_key="SPECIFIC-LEGACY", semantic_key="b", evidence_basis="legacy"),
        _subject(api, policy_key="SPECIFIC-DIRECT", semantic_key="a"),
    )
    result = _apply(api, *subjects)

    assert {
        item.policy_key: item.rank for item in result.decisions
    } == {
        "SPECIFIC-DIRECT": 1,
        "SPECIFIC-LEGACY": 2,
        "GENERAL-DIRECT": 3,
        "GENERAL-LEGACY": 4,
    }


def test_equal_rank_traits_use_semantic_key_tiebreak() -> None:
    api = _policy_api()
    later = _subject(api, policy_key="LATER", semantic_key="subject:z")
    earlier = _subject(api, policy_key="EARLIER", semantic_key="subject:a")
    result = _apply(api, later, earlier)

    assert _decision(result, "EARLIER").rank == 1
    assert _decision(result, "LATER").rank == 2
    assert api["OperatorBriefThreadPolicyReason"].SEMANTIC_TIEBREAK in _decision(
        result, "LATER"
    ).reason_codes


def test_rank_ignores_source_scores_and_fact_count() -> None:
    api = _policy_api()
    first = _subject(
        api,
        policy_key="FIRST",
        semantic_key="subject:a",
        facts=tuple(_fact(f"A-{index}") for index in range(10)),
        source_rankings=(_ranking("LEAD-A", score=1),),
        source_lead_ids=("LEAD-A",),
    )
    second = _subject(
        api,
        policy_key="SECOND",
        semantic_key="subject:b",
        facts=(_fact("B"),),
        source_rankings=(_ranking("LEAD-B", score=99),),
        source_lead_ids=("LEAD-B",),
    )

    result = _apply(api, second, first)
    assert (_decision(result, "FIRST").rank, _decision(result, "SECOND").rank) == (1, 2)


def test_six_material_subjects_are_primary_with_contiguous_ranks() -> None:
    api = _policy_api()
    subjects = tuple(
        _subject(api, policy_key=f"POLICY-{index}", semantic_key=f"subject:{index}")
        for index in range(6)
    )
    result = _apply(api, *reversed(subjects))
    primaries = sorted(
        (item for item in result.decisions if item.disposition == PRIMARY_THREAD),
        key=lambda item: item.rank,
    )

    assert len(primaries) == 6
    assert [item.rank for item in primaries] == [1, 2, 3, 4, 5, 6]


def test_sparse_subject_produces_one_primary_without_filler() -> None:
    api = _policy_api()
    result = _apply(api, _subject(api))

    assert len(result.subjects) == 1
    assert len(result.decisions) == 1
    assert result.decisions[0].disposition == PRIMARY_THREAD


def test_two_material_subjects_produce_two_primaries_without_filler() -> None:
    api = _policy_api()
    first = _subject(api, policy_key="FIRST", semantic_key="subject:first")
    second = _subject(api, policy_key="SECOND", semantic_key="subject:second")
    result = _apply(api, second, first)

    assert len(result.decisions) == 2
    assert {item.disposition for item in result.decisions} == {PRIMARY_THREAD}
    assert {item.rank for item in result.decisions} == {1, 2}


def test_thread_identity_uses_only_subject_kind_and_semantic_key() -> None:
    api = _policy_api()
    first = _subject(api, source_rankings=(_ranking("LEAD-A", score=1),), source_lead_ids=("LEAD-A",))
    enriched = _subject(
        api,
        specificity="general",
        evidence_basis="legacy",
        facts=(_fact("ENRICHED"),),
        coverage_limitations=(_limitation(),),
        source_rankings=(_ranking("LEAD-B", score=99),),
        source_lead_ids=("LEAD-B",),
    )
    first_id = _decision(_apply(api, first), "POLICY-A").thread_id
    second_id = _decision(_apply(api, enriched), "POLICY-A").thread_id

    assert first_id == second_id
    assert re.fullmatch(r"THREAD-[0-9A-F]{16}", first_id)


def test_rank_change_does_not_change_thread_identity() -> None:
    api = _policy_api()
    target = _subject(api, policy_key="TARGET", semantic_key="subject:z")
    first_id = _decision(_apply(api, target), "TARGET").thread_id
    result = _apply(api, _subject(api, policy_key="EARLIER", semantic_key="subject:a"), target)

    assert _decision(result, "TARGET").rank == 2
    assert _decision(result, "TARGET").thread_id == first_id


def test_conflicting_direct_states_remain_one_primary_subject() -> None:
    api = _policy_api()
    subject = _subject(
        api,
        facts=(_fact("STATUS-404", status=404), _fact("STATUS-200", status=200)),
        conflicts=(_conflict(),),
    )
    result = _apply(api, subject)
    retained = result.subjects[0]

    assert len(result.decisions) == 1
    assert result.decisions[0].disposition == PRIMARY_THREAD
    assert {item.http_status_code for item in retained.facts} == {200, 404}
    assert retained.conflicts == (_conflict(),)
    assert api["OperatorBriefThreadPolicyReason"].CONFLICTING_OBSERVATIONS in result.decisions[0].reason_codes


def test_scoped_coverage_is_retained_without_erasing_direct_primary() -> None:
    api = _policy_api()
    limitation = _limitation()
    subject = _subject(api, facts=(_fact("DIRECT"),), coverage_limitations=(limitation,))
    result = _apply(api, subject)

    assert result.subjects[0].coverage_limitations == (limitation,)
    assert result.decisions[0].disposition == PRIMARY_THREAD
    assert api["OperatorBriefThreadPolicyReason"].COVERAGE_LIMITED in result.decisions[0].reason_codes
    assert result.subjects[0].facts == (_fact("DIRECT"),)


def test_coverage_is_subject_scoped_and_deterministically_ordered() -> None:
    api = _policy_api()
    first = _subject(
        api,
        coverage_limitations=(_limitation("COVERAGE-Z"), _limitation("COVERAGE-A")),
    )
    unrelated = _subject(api, policy_key="UNRELATED", semantic_key="subject:unrelated")
    result = _apply(api, unrelated, first)
    retained = next(item for item in result.subjects if item.policy_key == "POLICY-A")
    other = next(item for item in result.subjects if item.policy_key == "UNRELATED")

    assert tuple(item.limitation_id for item in retained.coverage_limitations) == (
        "COVERAGE-A", "COVERAGE-Z"
    )
    assert other.coverage_limitations == ()


def test_missing_coverage_does_not_change_materiality_or_disposition() -> None:
    api = _policy_api()
    decision = _decision(_apply(api, _subject(api)), "POLICY-A")

    assert decision.disposition == PRIMARY_THREAD
    assert decision.signal.value == "specific_direct"


def test_policy_reason_codes_are_structured_not_prose() -> None:
    api = _policy_api()
    primary = _decision(_apply(api, _subject(api)), "POLICY-A")
    values = {item.value for item in primary.reason_codes}

    assert {"material_independent", "specific_evidence", "direct_evidence"} <= values
    assert all(isinstance(item, api["OperatorBriefThreadPolicyReason"]) for item in primary.reason_codes)


def test_general_legacy_policy_reasons_are_structured() -> None:
    api = _policy_api()
    subject = _subject(api, specificity="general", evidence_basis="legacy")
    decision = _decision(_apply(api, subject), "POLICY-A")
    reason = api["OperatorBriefThreadPolicyReason"]

    assert reason.GENERAL_EVIDENCE in decision.reason_codes
    assert reason.LEGACY_MATERIAL in decision.reason_codes


def test_disposition_reason_codes_cover_context_and_evidence_only() -> None:
    api = _policy_api()
    primary = _subject(api)
    associated = _subject(
        api, policy_key="ASSOCIATED", semantic_key="context:associated",
        materiality="context", independent=False,
        associated_subject_reference=_subject_reference(
            primary.subject_kind, primary.semantic_subject_key
        ),
    )
    unassociated = _subject(
        api, policy_key="UNASSOCIATED", semantic_key="context:unassociated",
        materiality="context", independent=False,
    )
    retained = _subject(
        api, policy_key="EVIDENCE", semantic_key="evidence:one",
        materiality="evidence_only", independent=False,
    )
    result = _apply(api, retained, unassociated, associated, primary)
    reason = api["OperatorBriefThreadPolicyReason"]

    assert reason.ASSOCIATED_CONTEXT in _decision(result, "ASSOCIATED").reason_codes
    assert reason.UNASSOCIATED_CONTEXT in _decision(result, "UNASSOCIATED").reason_codes
    assert reason.RETAINED_EVIDENCE_ONLY in _decision(result, "EVIDENCE").reason_codes


def test_stable_legacy_subject_without_replacement_survives_primary() -> None:
    api = _policy_api()
    legacy = _subject(
        api,
        semantic_key="workflow:account-reset",
        evidence_basis="legacy",
        source_rankings=(_ranking("LEAD-OLD", score=60),),
        source_lead_ids=("LEAD-OLD",),
    )
    decision = _decision(_apply(api, legacy), "POLICY-A")

    assert decision.disposition == PRIMARY_THREAD
    assert decision.signal.value == "specific_legacy"
    assert api["OperatorBriefThreadPolicyReason"].LEGACY_MATERIAL in decision.reason_codes


def test_explicit_normalized_replacement_prevents_legacy_primary_duplication() -> None:
    api = _policy_api()
    normalized = _subject(api, policy_key="NORMALIZED", semantic_key="application:normalized")
    legacy = _subject(
        api,
        policy_key="LEGACY",
        semantic_key="workflow:legacy",
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
    )
    result = _apply(api, legacy, normalized)
    legacy_decision = _decision(result, "LEGACY")

    assert legacy_decision.disposition == SUPPORTING_CONTEXT
    assert legacy_decision.thread_id == _decision(result, "NORMALIZED").thread_id
    assert api["OperatorBriefThreadPolicyReason"].NORMALIZED_REPLACEMENT in legacy_decision.reason_codes


def test_legacy_replacement_is_explicit_not_inferred_from_provenance() -> None:
    api = _policy_api()
    normalized = _subject(
        api, policy_key="NORMALIZED", semantic_key="application:normalized",
        source_lead_ids=("LEAD-SHARED",),
    )
    legacy = _subject(
        api, policy_key="LEGACY", semantic_key="workflow:legacy",
        evidence_basis="legacy", source_lead_ids=("LEAD-SHARED",),
    )
    result = _apply(api, legacy, normalized)

    assert _decision(result, "LEGACY").disposition == PRIMARY_THREAD


def test_legacy_thread_identity_ignores_lead_id_rank_score_and_signal() -> None:
    api = _policy_api()
    first = _subject(
        api, evidence_basis="legacy", semantic_key="workflow:stable",
        source_rankings=(_ranking("LEAD-ONE", rank=1, score=99, signal="high"),),
        source_lead_ids=("LEAD-ONE",),
    )
    second = _subject(
        api, evidence_basis="legacy", semantic_key="workflow:stable",
        source_rankings=(_ranking("LEAD-TWO", rank=8, score=10, signal="low"),),
        source_lead_ids=("LEAD-TWO",),
    )

    assert _decision(_apply(api, first), "POLICY-A").thread_id == _decision(
        _apply(api, second), "POLICY-A"
    ).thread_id


def test_material_legacy_without_stable_key_is_explicitly_accounted_for() -> None:
    api = _policy_api()
    legacy = _subject(
        api,
        semantic_key=None,
        evidence_basis="legacy",
        source_rankings=(_ranking("LEAD-UNSTABLE"),),
        source_lead_ids=("LEAD-UNSTABLE",),
    )
    result = _apply(api, legacy)
    decision = _decision(result, "POLICY-A")

    assert decision.disposition == DEPRIORITISED_CONTEXT
    assert decision.thread_id == ""
    assert decision.rank is None
    assert api["OperatorBriefThreadPolicyReason"].STABLE_IDENTITY_MISSING in decision.reason_codes
    assert result.subjects[0].source_rankings == legacy.source_rankings


def test_presentation_only_legacy_context_does_not_become_primary() -> None:
    api = _policy_api()
    legacy = _subject(
        api,
        evidence_basis="legacy",
        materiality="context",
        independent=False,
    )

    assert _decision(_apply(api, legacy), "POLICY-A").disposition == DEPRIORITISED_CONTEXT


def test_policy_models_do_not_require_family_adapters_or_prose_fields() -> None:
    api = _policy_api()
    names = {item.name for item in fields(api["OperatorBriefThreadPolicySubject"])}

    assert not names & {
        "title", "why_review", "next_review_step", "http_composition",
        "network_composition", "web_context_composition", "project_state",
    }


def test_specific_direct_outranks_generic_direct_without_family_names() -> None:
    api = _policy_api()
    generic = _subject(api, policy_key="GENERIC", semantic_key="surface:generic", specificity="general")
    specific = _subject(api, policy_key="SPECIFIC", semantic_key="surface:specific")
    result = _apply(api, generic, specific)

    assert _decision(result, "SPECIFIC").rank == 1
    assert _decision(result, "GENERIC").rank == 2


def test_specific_subject_is_not_drowned_by_generic_fact_density() -> None:
    api = _policy_api()
    generic = _subject(
        api, policy_key="GENERIC", semantic_key="surface:generic", specificity="general",
        facts=tuple(_fact(f"GENERIC-{index}") for index in range(12)),
    )
    specific = _subject(
        api, policy_key="SPECIFIC", semantic_key="surface:specific", facts=(_fact("SPECIFIC"),)
    )
    result = _apply(api, generic, specific)

    assert _decision(result, "SPECIFIC").rank == 1
    assert _decision(result, "SPECIFIC").signal.value == "specific_direct"


# Input and semantic-identity invariants.


def test_composite_subject_reference_contract() -> None:
    api = _policy_api()
    reference = _subject_reference(
        OperatorBriefSubjectKind.APPLICATION,
        "application:reference-target",
    )
    reference_fields = {item.name for item in fields(type(reference))}
    subject_fields = {
        item.name for item in fields(api["OperatorBriefThreadPolicySubject"])
    }

    assert reference_fields == {"subject_kind", "semantic_subject_key"}
    assert {
        "associated_subject_reference",
        "replaced_by_subject_reference",
    } <= subject_fields
    assert not {
        "associated_subject_key",
        "replaced_by_subject_key",
    } & subject_fields


def test_same_kind_duplicate_semantic_subject_is_rejected() -> None:
    api = _policy_api()
    first = _subject(
        api,
        policy_key="DUPLICATE-ONE",
        semantic_key="application:shared-subject",
    )
    second = _subject(
        api,
        policy_key="DUPLICATE-TWO",
        semantic_key="application:shared-subject",
    )

    with pytest.raises(ValueError, match="duplicate.*semantic|semantic.*duplicate"):
        _apply(api, first, second)


def test_different_kind_same_semantic_key_retains_distinct_threads() -> None:
    api = _policy_api()
    application = _subject(
        api,
        policy_key="APPLICATION",
        semantic_key="surface:shared-subject",
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
    )
    service = _subject(
        api,
        policy_key="SERVICE",
        semantic_key="surface:shared-subject",
        subject_kind=OperatorBriefSubjectKind.SERVICE_SURFACE,
    )

    result = _apply(api, application, service)
    permuted = _apply(api, service, application)
    application_decision = _decision(result, "APPLICATION")
    service_decision = _decision(result, "SERVICE")

    assert result == permuted
    assert application_decision.disposition == PRIMARY_THREAD
    assert service_decision.disposition == PRIMARY_THREAD
    assert (application_decision.rank, service_decision.rank) == (1, 2)
    assert application_decision.thread_id != service_decision.thread_id


def test_cross_kind_same_key_association_selects_composite_target() -> None:
    api = _policy_api()
    application = _subject(
        api,
        policy_key="APPLICATION",
        semantic_key="surface:shared-target",
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
    )
    service = _subject(
        api,
        policy_key="SERVICE",
        semantic_key="surface:shared-target",
        subject_kind=OperatorBriefSubjectKind.SERVICE_SURFACE,
    )
    context = _subject(
        api,
        policy_key="CONTEXT",
        semantic_key="context:application-target",
        subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
        materiality="context",
        independent=False,
        associated_subject_reference=_subject_reference(
            application.subject_kind, application.semantic_subject_key
        ),
    )

    result = _apply(api, service, context, application)

    assert _decision(result, "CONTEXT").thread_id == _decision(
        result, "APPLICATION"
    ).thread_id
    assert _decision(result, "CONTEXT").thread_id != _decision(
        result, "SERVICE"
    ).thread_id


def test_unresolved_association_reference_is_rejected() -> None:
    api = _policy_api()
    context = _subject(
        api,
        materiality="context",
        independent=False,
        associated_subject_reference=_subject_reference(
            OperatorBriefSubjectKind.APPLICATION,
            "application:missing-target",
        ),
    )

    with pytest.raises(ValueError, match="association.*primary|reference.*primary"):
        _apply(api, context)


def test_material_independent_association_input_is_rejected() -> None:
    api = _policy_api()
    primary = _subject(api, semantic_key="application:primary")
    associated_material = _subject(
        api,
        policy_key="ASSOCIATED-MATERIAL",
        semantic_key="application:associated-material",
        associated_subject_reference=_subject_reference(
            primary.subject_kind, primary.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="material.*association|association.*material"):
        _apply(api, primary, associated_material)


def test_evidence_only_association_input_is_rejected() -> None:
    api = _policy_api()
    primary = _subject(api, semantic_key="application:primary")
    retained = _subject(
        api,
        policy_key="ASSOCIATED-EVIDENCE",
        semantic_key="evidence:associated",
        materiality="evidence_only",
        independent=False,
        associated_subject_reference=_subject_reference(
            primary.subject_kind, primary.semantic_subject_key
        ),
    )

    with pytest.raises(
        ValueError, match="evidence.only.*association|association.*evidence.only"
    ):
        _apply(api, primary, retained)


def test_material_direct_replacement_input_is_rejected() -> None:
    api = _policy_api()
    normalized = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="application:normalized-target",
    )
    replacement = _subject(
        api,
        policy_key="DIRECT-REPLACEMENT",
        semantic_key="application:direct-replacement",
        replaced_by_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*legacy|legacy.*replacement"):
        _apply(api, normalized, replacement)


def test_context_replacement_input_is_rejected() -> None:
    api = _policy_api()
    normalized = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="application:normalized-target",
    )
    replacement = _subject(
        api,
        policy_key="CONTEXT-REPLACEMENT",
        semantic_key="context:replacement",
        materiality="context",
        independent=False,
        replaced_by_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*legacy|legacy.*replacement"):
        _apply(api, normalized, replacement)


def test_evidence_only_replacement_input_is_rejected() -> None:
    api = _policy_api()
    normalized = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="application:normalized-target",
    )
    replacement = _subject(
        api,
        policy_key="EVIDENCE-REPLACEMENT",
        semantic_key="evidence:replacement",
        materiality="evidence_only",
        independent=False,
        replaced_by_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*legacy|legacy.*replacement"):
        _apply(api, normalized, replacement)


def test_association_and_replacement_input_is_rejected() -> None:
    api = _policy_api()
    normalized = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="application:normalized-target",
    )
    legacy = _subject(
        api,
        policy_key="LEGACY",
        semantic_key="workflow:legacy",
        evidence_basis="legacy",
        associated_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
        replaced_by_subject_reference=_subject_reference(
            normalized.subject_kind, normalized.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="association.*replacement|replacement.*association"):
        _apply(api, normalized, legacy)


def test_normalized_replacement_target_must_be_direct() -> None:
    api = _policy_api()
    legacy_target = _subject(
        api,
        policy_key="LEGACY-TARGET",
        semantic_key="workflow:legacy-target",
        evidence_basis="legacy",
    )
    replacement = _subject(
        api,
        policy_key="LEGACY-REPLACEMENT",
        semantic_key="workflow:legacy-replacement",
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            legacy_target.subject_kind, legacy_target.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*direct|direct.*replacement"):
        _apply(api, legacy_target, replacement)


def test_unresolved_replacement_reference_is_rejected() -> None:
    api = _policy_api()
    replacement = _subject(
        api,
        policy_key="LEGACY-REPLACEMENT",
        semantic_key="workflow:legacy-replacement",
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            OperatorBriefSubjectKind.APPLICATION,
            "application:missing-target",
        ),
    )

    with pytest.raises(ValueError, match="replacement.*primary|reference.*primary"):
        _apply(api, replacement)


def test_normalized_replacement_target_must_be_primary() -> None:
    api = _policy_api()
    context_target = _subject(
        api,
        policy_key="CONTEXT-TARGET",
        semantic_key="application:context-target",
        materiality="context",
        independent=False,
    )
    replacement = _subject(
        api,
        policy_key="LEGACY-REPLACEMENT",
        semantic_key="workflow:legacy-replacement",
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            context_target.subject_kind, context_target.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*primary|primary.*replacement"):
        _apply(api, context_target, replacement)


def test_same_key_wrong_kind_reference_does_not_resolve() -> None:
    api = _policy_api()
    primary = _subject(
        api,
        semantic_key="surface:shared-target",
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
    )
    context = _subject(
        api,
        policy_key="CONTEXT",
        semantic_key="context:wrong-kind-target",
        materiality="context",
        independent=False,
        associated_subject_reference=_subject_reference(
            OperatorBriefSubjectKind.SERVICE_SURFACE,
            primary.semantic_subject_key,
        ),
    )

    with pytest.raises(ValueError, match="association.*primary|reference.*primary"):
        _apply(api, primary, context)


def test_multiple_null_key_legacy_items_remain_accounted_for() -> None:
    api = _policy_api()
    first = _subject(
        api,
        policy_key="LEGACY-NULL-ONE",
        semantic_key=None,
        evidence_basis="legacy",
    )
    second = _subject(
        api,
        policy_key="LEGACY-NULL-TWO",
        semantic_key=None,
        evidence_basis="legacy",
    )

    result = _apply(api, second, first)
    decisions = {
        item.policy_key: item for item in result.decisions
    }

    assert set(decisions) == {"LEGACY-NULL-ONE", "LEGACY-NULL-TWO"}
    assert all(
        item.disposition == DEPRIORITISED_CONTEXT
        and item.thread_id == ""
        and item.rank is None
        for item in decisions.values()
    )
    assert all(
        api["OperatorBriefThreadPolicyReason"].STABLE_IDENTITY_MISSING
        in item.reason_codes
        for item in decisions.values()
    )


def test_null_key_legacy_replacement_uses_direct_primary_context() -> None:
    api = _policy_api()
    primary = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="application:normalized-target",
    )
    legacy = _subject(
        api,
        policy_key="LEGACY-NULL-REPLACEMENT",
        semantic_key=None,
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            primary.subject_kind, primary.semantic_subject_key
        ),
    )

    result = _apply(api, legacy, primary)
    decision = _decision(result, legacy.policy_key)
    reason = api["OperatorBriefThreadPolicyReason"]

    assert decision.disposition == SUPPORTING_CONTEXT
    assert decision.thread_id == _decision(result, primary.policy_key).thread_id
    assert decision.rank is None
    assert reason.STABLE_IDENTITY_MISSING in decision.reason_codes
    assert reason.ASSOCIATED_CONTEXT in decision.reason_codes
    assert reason.NORMALIZED_REPLACEMENT in decision.reason_codes


def test_null_key_legacy_unresolved_replacement_is_rejected() -> None:
    api = _policy_api()
    legacy = _subject(
        api,
        policy_key="LEGACY-NULL-UNRESOLVED",
        semantic_key=None,
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            OperatorBriefSubjectKind.APPLICATION,
            "application:missing-target",
        ),
    )

    with pytest.raises(ValueError, match="replacement.*primary|reference.*primary"):
        _apply(api, legacy)


def test_null_key_legacy_replacement_targeting_legacy_primary_is_rejected() -> None:
    api = _policy_api()
    legacy_target = _subject(
        api,
        policy_key="LEGACY-TARGET",
        semantic_key="workflow:legacy-target",
        evidence_basis="legacy",
    )
    legacy = _subject(
        api,
        policy_key="LEGACY-NULL-REPLACEMENT",
        semantic_key=None,
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            legacy_target.subject_kind, legacy_target.semantic_subject_key
        ),
    )

    with pytest.raises(ValueError, match="replacement.*direct|direct.*replacement"):
        _apply(api, legacy_target, legacy)


def test_null_key_legacy_wrong_kind_replacement_is_rejected() -> None:
    api = _policy_api()
    primary = _subject(
        api,
        policy_key="NORMALIZED",
        semantic_key="surface:shared-target",
        subject_kind=OperatorBriefSubjectKind.APPLICATION,
    )
    legacy = _subject(
        api,
        policy_key="LEGACY-NULL-REPLACEMENT",
        semantic_key=None,
        evidence_basis="legacy",
        replaced_by_subject_reference=_subject_reference(
            OperatorBriefSubjectKind.SERVICE_SURFACE,
            primary.semantic_subject_key,
        ),
    )

    with pytest.raises(ValueError, match="replacement.*primary|reference.*primary"):
        _apply(api, primary, legacy)
