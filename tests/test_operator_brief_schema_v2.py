from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path

import pytest

from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnknownReason,
)


def _api():
    from bugslyce.reports.operator_brief import (
        OPERATOR_BRIEF_FILENAME,
        PRIMARY_THREAD,
        OperatorBriefConflict,
        OperatorBriefConflictKind,
        OperatorBriefConflictObservation,
        OperatorBriefCoverageLimitation,
        OperatorBriefDisposition,
        OperatorBriefDispositionReason,
        OperatorBriefFact,
        OperatorBriefFactKind,
        OperatorBriefFactRole,
        OperatorBriefLegacyContextKind,
        OperatorBriefSemanticClass,
        OperatorBriefSourceRanking,
        OperatorBriefSourceReference,
        OperatorBriefSubjectKind,
        OperatorBriefThread,
        OperatorBriefView,
        load_operator_brief_artifact,
        retire_operator_brief_artifact,
        write_operator_brief_artifact,
    )

    return locals()


def _source(api, source_kind: str, source_id: str):
    return api["OperatorBriefSourceReference"](
        source_kind=source_kind,
        source_id=source_id,
    )


def _smb_fact(api, *, fact_id: str = "FACT-SMB-ONE"):
    return api["OperatorBriefFact"](
        fact_id=fact_id,
        kind=api["OperatorBriefFactKind"].SMB_SHARE,
        semantic_class=api["OperatorBriefSemanticClass"].OBSERVED,
        role=api["OperatorBriefFactRole"].DIRECT_EVIDENCE,
        label="SMB Disk share observed",
        summary="Bounded enumeration directly observed a custom Disk share.",
        endpoints=("files.example.test:445/tcp",),
        origins=(),
        evidence_ids=("EVID-SMB-ONE",),
        artefact_references=("smb-shares-files.example.test-445.txt",),
        source_references=(
            _source(api, "smb_share", "files.example.test:445:nt4wrksv"),
        ),
        share_name="nt4wrksv",
        share_type="Disk",
    )


def _source_ranking(api, lead_id: str = "LEAD-ONE", rank: int = 1):
    return api["OperatorBriefSourceRanking"](
        source_lead_id=lead_id,
        rank=rank,
        score=80 - rank,
        signal="direct retained evidence",
    )


def _thread(
    api,
    *,
    thread_id: str = "THREAD-ONE",
    rank: int = 1,
    source_lead_ids: tuple[str, ...] = (),
    origins: tuple[str, ...] = (),
    facts: tuple[object, ...] = (),
    conflicts: tuple[object, ...] = (),
    coverage_limitations: tuple[object, ...] = (),
    source_rankings: tuple[object, ...] = (),
    identity_key: str = "",
):
    return api["OperatorBriefThread"](
        thread_id=thread_id,
        identity_key=identity_key or f"subject:{thread_id.lower()}",
        subject_kind=api["OperatorBriefSubjectKind"].APPLICATION,
        title=f"Investigation subject {thread_id}",
        rank=rank,
        signal="direct retained evidence",
        source_lead_ids=source_lead_ids,
        endpoints=(f"https://example.test/{rank}",),
        origins=origins,
        evidence_ids=(f"EVID-{rank}",),
        why_review="Direct retained evidence warrants offline review.",
        next_review_step="Review the retained evidence and provenance.",
        facts=facts,
        conflicts=conflicts,
        coverage_limitations=coverage_limitations,
        source_rankings=source_rankings,
        legacy_context=(),
        source_artefacts=(),
    )


def _disposition(api, thread_id: str, source_id: str, fact_ids=()):
    return api["OperatorBriefDisposition"](
        source_kind="operator_summary_lead",
        source_id=source_id,
        disposition=api["PRIMARY_THREAD"],
        thread_id=thread_id,
        reason_code=api["OperatorBriefDispositionReason"].PRIMARY_SUBJECT,
        represented_fact_ids=tuple(fact_ids),
    )


def _brief(api):
    fact = _smb_fact(api)
    thread = _thread(
        api,
        facts=(fact,),
        source_lead_ids=("LEAD-ONE",),
        source_rankings=(_source_ranking(api),),
    )
    return api["OperatorBriefView"](
        threads=(thread,),
        dispositions=(
            _disposition(api, thread.thread_id, "LEAD-ONE", (fact.fact_id,)),
        ),
    )


def _schema_1_payload(*, enrichment: bool = False) -> dict[str, object]:
    return {
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
                "next_review_step": "Review legacy retained evidence.",
                "observed_facts": (
                    ["Legacy free-text observation."] if enrichment else []
                ),
                "related_context": (
                    ["Legacy free-text relationship."] if enrichment else []
                ),
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
                "disposition": "primary_thread",
                "thread_id": "THREAD-LEGACY",
            }
        ],
    }


def _write_payload(root: Path, payload: dict[str, object]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "operator_brief.json"
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def test_schema_v2_represents_observed_direct_smb_share_fact() -> None:
    api = _api()

    fact = _smb_fact(api)

    assert fact.semantic_class is api["OperatorBriefSemanticClass"].OBSERVED
    assert fact.role is api["OperatorBriefFactRole"].DIRECT_EVIDENCE
    assert fact.kind is api["OperatorBriefFactKind"].SMB_SHARE
    assert fact.share_name == "nt4wrksv"
    assert fact.share_type == "Disk"
    assert fact.evidence_ids == ("EVID-SMB-ONE",)


def test_schema_v2_keeps_derived_response_equivalence_distinct_from_direct_facts() -> None:
    api = _api()

    fact = api["OperatorBriefFact"](
        fact_id="FACT-RESPONSE-EQUIVALENCE",
        kind=api["OperatorBriefFactKind"].RESPONSE_EQUIVALENCE,
        semantic_class=api["OperatorBriefSemanticClass"].DERIVED,
        role=api["OperatorBriefFactRole"].RELATIONSHIP_CONTEXT,
        label="Exact retained response relationship",
        summary="Two retained responses have the same exact body digest.",
        endpoints=(
            "https://example.test/",
            "https://example.test/index.php",
        ),
        origins=("https://example.test",),
        evidence_ids=("EVID-ROOT", "EVID-INDEX"),
        artefact_references=("deep_source_route_collection.json",),
        source_references=(
            _source(api, "http_response", "RESPONSE-ROOT"),
            _source(api, "http_response", "RESPONSE-INDEX"),
        ),
        body_sha256="a" * 64,
    )

    assert fact.semantic_class is api["OperatorBriefSemanticClass"].DERIVED
    assert fact.role is api["OperatorBriefFactRole"].RELATIONSHIP_CONTEXT
    assert fact.kind is api["OperatorBriefFactKind"].RESPONSE_EQUIVALENCE


def test_schema_v2_rejects_derived_fact_as_direct_evidence() -> None:
    api = _api()

    with pytest.raises(ValueError, match="direct evidence requires observed"):
        api["OperatorBriefFact"](
            fact_id="FACT-DERIVED-DIRECT",
            kind=api["OperatorBriefFactKind"].HTTP_ROUTE,
            semantic_class=api["OperatorBriefSemanticClass"].DERIVED,
            role=api["OperatorBriefFactRole"].DIRECT_EVIDENCE,
            label="Invalid derived direct evidence",
            summary="Derived interpretation cannot claim direct observation authority.",
        )


def test_response_equivalence_cannot_be_observed_direct_evidence() -> None:
    api = _api()

    with pytest.raises(ValueError, match="response equivalence.*derived"):
        api["OperatorBriefFact"](
            fact_id="FACT-EQUIVALENCE-AS-OBSERVED",
            kind=api["OperatorBriefFactKind"].RESPONSE_EQUIVALENCE,
            semantic_class=api["OperatorBriefSemanticClass"].OBSERVED,
            role=api["OperatorBriefFactRole"].DIRECT_EVIDENCE,
            label="Invalid response equivalence",
            summary="Response equivalence is a deterministic relationship.",
            endpoints=(
                "https://example.test/",
                "https://example.test/index.php",
            ),
            body_sha256="a" * 64,
        )


def test_parameter_fact_has_name_but_no_generic_raw_value_contract() -> None:
    api = _api()

    fact = api["OperatorBriefFact"](
        fact_id="FACT-PARAMETER-TENANT",
        kind=api["OperatorBriefFactKind"].PARAMETER,
        semantic_class=api["OperatorBriefSemanticClass"].OBSERVED,
        role=api["OperatorBriefFactRole"].DIRECT_EVIDENCE,
        label="Parameter name observed",
        summary="The parameter name is attributable to the exact route.",
        endpoints=("https://example.test/search",),
        origins=("https://example.test",),
        evidence_ids=("EVID-PARAMETER",),
        artefact_references=("deep_parameter_inventory.json",),
        source_references=(
            _source(api, "parameter_observation", "SOURCE-SEARCH"),
        ),
        parameter_name="tenant",
    )

    field_names = {field.name for field in fields(type(fact))}
    assert fact.parameter_name == "tenant"
    assert "value" not in field_names
    assert "parameter_value" not in field_names


def test_multiple_origins_do_not_imply_a_response_equivalence_fact() -> None:
    api = _api()

    thread = _thread(
        api,
        origins=("https://example.test", "https://example.test:8443"),
    )

    assert thread.origins == (
        "https://example.test",
        "https://example.test:8443",
    )
    assert thread.facts == ()


def test_thread_preserves_multiple_source_leads_as_separate_ranking_provenance() -> None:
    api = _api()

    thread = _thread(
        api,
        source_lead_ids=("LEAD-ALPHA", "LEAD-BRAVO"),
        source_rankings=(
            _source_ranking(api, "LEAD-ALPHA", 1),
            _source_ranking(api, "LEAD-BRAVO", 3),
        ),
    )

    assert thread.source_lead_ids == ("LEAD-ALPHA", "LEAD-BRAVO")
    assert tuple(item.source_lead_id for item in thread.source_rankings) == (
        "LEAD-ALPHA",
        "LEAD-BRAVO",
    )
    assert "score" not in {field.name for field in fields(type(thread))}


def test_schema_v2_thread_allows_no_canonical_source_lead() -> None:
    api = _api()

    thread = _thread(api, source_lead_ids=(), source_rankings=())

    assert thread.source_lead_ids == ()
    assert thread.source_rankings == ()


def test_conflict_represents_404_and_200_without_claiming_chronology() -> None:
    api = _api()
    observation_type = api["OperatorBriefConflictObservation"]
    conflict = api["OperatorBriefConflict"](
        conflict_id="CONFLICT-ADMIN-STATUS",
        kind=api["OperatorBriefConflictKind"].DIFFERING_HTTP_STATUS,
        subject_endpoint="https://example.test/admin/",
        observations=(
            observation_type(
                observation_id="OBS-404",
                endpoint="https://example.test/admin/",
                method="GET",
                status_code=404,
                collection_stage="content_result_followup",
                evidence_ids=("EVID-404",),
                artefact_references=("headers-admin.txt",),
            ),
            observation_type(
                observation_id="OBS-200",
                endpoint="https://example.test/admin/",
                method="GET",
                status_code=200,
                collection_stage="deep_source_route_collection",
                evidence_ids=("EVID-200",),
                artefact_references=("deep_source_route_collection.json",),
            ),
        ),
        summary="Retained observations record differing HTTP status codes.",
    )

    field_names = {field.name for field in fields(type(conflict))}
    assert tuple(item.status_code for item in conflict.observations) == (404, 200)
    assert "earlier_observation" not in field_names
    assert "later_observation" not in field_names
    assert "changed" not in field_names


def test_differing_http_status_conflict_requires_multiple_observations() -> None:
    api = _api()
    observation_type = api["OperatorBriefConflictObservation"]

    with pytest.raises(ValueError, match="multiple observations"):
        api["OperatorBriefConflict"](
            conflict_id="CONFLICT-ONE-STATUS",
            kind=api["OperatorBriefConflictKind"].DIFFERING_HTTP_STATUS,
            subject_endpoint="https://example.test/admin/",
            observations=(
                observation_type(
                    observation_id="OBS-ONLY",
                    endpoint="https://example.test/admin/",
                    method="GET",
                    status_code=404,
                    collection_stage="content_result_followup",
                ),
            ),
            summary="Only one retained status is represented.",
        )


def test_differing_http_status_conflict_requires_distinct_status_codes() -> None:
    api = _api()
    observation_type = api["OperatorBriefConflictObservation"]

    with pytest.raises(ValueError, match="different status codes"):
        api["OperatorBriefConflict"](
            conflict_id="CONFLICT-SAME-STATUS",
            kind=api["OperatorBriefConflictKind"].DIFFERING_HTTP_STATUS,
            subject_endpoint="https://example.test/admin/",
            observations=(
                observation_type(
                    observation_id="OBS-FIRST-404",
                    endpoint="https://example.test/admin/",
                    method="GET",
                    status_code=404,
                    collection_stage="content_result_followup",
                ),
                observation_type(
                    observation_id="OBS-SECOND-404",
                    endpoint="https://example.test/admin/",
                    method="HEAD",
                    status_code=404,
                    collection_stage="deep_source_route_collection",
                ),
            ),
            summary="Both retained observations have the same status.",
        )


def test_differing_http_status_conflict_rejects_unrelated_endpoint() -> None:
    api = _api()
    observation_type = api["OperatorBriefConflictObservation"]

    with pytest.raises(ValueError, match="subject endpoint"):
        api["OperatorBriefConflict"](
            conflict_id="CONFLICT-UNRELATED-ENDPOINT",
            kind=api["OperatorBriefConflictKind"].DIFFERING_HTTP_STATUS,
            subject_endpoint="https://example.test/admin/",
            observations=(
                observation_type(
                    observation_id="OBS-ADMIN-404",
                    endpoint="https://example.test/admin/",
                    method="GET",
                    status_code=404,
                    collection_stage="content_result_followup",
                ),
                observation_type(
                    observation_id="OBS-ACCOUNT-200",
                    endpoint="https://example.test/account/",
                    method="GET",
                    status_code=200,
                    collection_stage="deep_source_route_collection",
                ),
            ),
            summary="Different endpoints cannot prove a status conflict for one subject.",
        )


def test_coverage_limitation_is_scoped_to_exact_capability_and_input() -> None:
    api = _api()

    limitation = api["OperatorBriefCoverageLimitation"](
        limitation_id="COVERAGE-FORMS-SOURCE-A",
        capability="deep_form_inventory",
        source_role="deep_source_response",
        source_id="DEEP-SOURCE-A",
        state=AnalysisCoverageState.ANALYSED,
        outcome=AnalysisCoverageOutcome.NO_FINDING,
        unknown_reason=None,
        execution_note=None,
        summary="No applicable form finding was produced for this exact input.",
    )

    field_names = {field.name for field in fields(type(limitation))}
    assert limitation.source_id == "DEEP-SOURCE-A"
    assert limitation.state is AnalysisCoverageState.ANALYSED
    assert limitation.outcome is AnalysisCoverageOutcome.NO_FINDING
    assert "project_wide_absence" not in field_names
    assert "all_sources" not in field_names


def test_unknown_coverage_limitation_requires_an_explicit_reason() -> None:
    api = _api()

    with pytest.raises(ValueError, match="unknown reason"):
        api["OperatorBriefCoverageLimitation"](
            limitation_id="COVERAGE-UNKNOWN-WITHOUT-REASON",
            capability="deep_form_inventory",
            source_role="deep_source_response",
            source_id="DEEP-SOURCE-A",
            state=AnalysisCoverageState.UNKNOWN,
            outcome=None,
            unknown_reason=None,
            execution_note=None,
            summary="Retained evidence cannot prove exact execution state.",
        )


@pytest.mark.parametrize(
    "unknown_reason",
    (
        AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF,
        AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF,
    ),
)
def test_unknown_coverage_limitation_accepts_typed_reason(
    unknown_reason: AnalysisCoverageUnknownReason,
) -> None:
    api = _api()

    limitation = api["OperatorBriefCoverageLimitation"](
        limitation_id=f"COVERAGE-{unknown_reason.value}",
        capability="deep_form_inventory",
        source_role="deep_source_response",
        source_id="DEEP-SOURCE-A",
        state=AnalysisCoverageState.UNKNOWN,
        outcome=None,
        unknown_reason=unknown_reason,
        execution_note=None,
        summary="Retained evidence cannot prove exact execution state.",
    )

    assert limitation.unknown_reason is unknown_reason


@pytest.mark.parametrize(
    ("state", "outcome"),
    (
        (AnalysisCoverageState.ANALYSED, AnalysisCoverageOutcome.NO_FINDING),
        (AnalysisCoverageState.NOT_RUN, AnalysisCoverageOutcome.UNSUPPORTED),
        (AnalysisCoverageState.INCOMPLETE, AnalysisCoverageOutcome.PARTIAL_FAILED),
    ),
)
def test_non_unknown_coverage_limitation_valid_controls(
    state: AnalysisCoverageState,
    outcome: AnalysisCoverageOutcome,
) -> None:
    api = _api()

    limitation = api["OperatorBriefCoverageLimitation"](
        limitation_id=f"COVERAGE-{state.value}",
        capability="deep_form_inventory",
        source_role="deep_source_response",
        source_id="DEEP-SOURCE-A",
        state=state,
        outcome=outcome,
        unknown_reason=None,
        execution_note=None,
        summary="Exact input-scoped coverage state.",
    )

    assert limitation.state is state
    assert limitation.outcome is outcome


def test_operator_brief_view_allows_more_than_five_primary_threads() -> None:
    api = _api()
    threads = tuple(
        _thread(api, thread_id=f"THREAD-{index}", rank=index)
        for index in range(1, 7)
    )
    dispositions = tuple(
        _disposition(api, thread.thread_id, f"LEAD-{index}")
        for index, thread in enumerate(threads, start=1)
    )

    brief = api["OperatorBriefView"](
        threads=threads,
        dispositions=dispositions,
    )

    assert len(brief.threads) == 6


def test_schema_v2_view_rejects_duplicate_thread_ids() -> None:
    api = _api()
    first = _thread(api, thread_id="THREAD-DUPLICATE", rank=1)
    second = _thread(api, thread_id="THREAD-DUPLICATE", rank=2)

    with pytest.raises(ValueError, match="duplicate thread IDs"):
        api["OperatorBriefView"](
            threads=(first, second),
            dispositions=(),
        )


def test_schema_v2_view_rejects_duplicate_semantic_identity_keys() -> None:
    api = _api()
    first = _thread(
        api,
        thread_id="THREAD-IDENTITY-ONE",
        rank=1,
        identity_key="application:https://example.test",
    )
    second = _thread(
        api,
        thread_id="THREAD-IDENTITY-TWO",
        rank=2,
        identity_key="application:https://example.test",
    )

    with pytest.raises(ValueError, match="duplicate semantic identity"):
        api["OperatorBriefView"](
            threads=(first, second),
            dispositions=(),
        )


def test_schema_v2_view_rejects_duplicate_disposition_sources() -> None:
    api = _api()
    thread = _thread(api)
    disposition = _disposition(api, thread.thread_id, "LEAD-DUPLICATE")

    with pytest.raises(ValueError, match="duplicate disposition sources"):
        api["OperatorBriefView"](
            threads=(thread,),
            dispositions=(disposition, disposition),
        )


def test_schema_v2_view_rejects_unknown_disposition_thread_reference() -> None:
    api = _api()
    thread = _thread(api)

    with pytest.raises(ValueError, match="unknown thread ID"):
        api["OperatorBriefView"](
            threads=(thread,),
            dispositions=(
                _disposition(api, "THREAD-MISSING", "LEAD-UNKNOWN"),
            ),
        )


def test_schema_v2_rejects_duplicate_fact_identities_within_a_thread() -> None:
    api = _api()
    first = _smb_fact(api, fact_id="FACT-DUPLICATE")
    second = _smb_fact(api, fact_id="FACT-DUPLICATE")

    with pytest.raises(ValueError, match="duplicate fact IDs"):
        _thread(api, facts=(first, second))


def test_schema_v2_serialization_is_byte_deterministic(tmp_path: Path) -> None:
    api = _api()
    brief = _brief(api)

    first = api["write_operator_brief_artifact"](tmp_path / "first", brief)
    second = api["write_operator_brief_artifact"](tmp_path / "second", brief)

    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["schema_version"] == 2


def test_schema_v2_write_load_round_trip(tmp_path: Path) -> None:
    api = _api()
    brief = _brief(api)

    api["write_operator_brief_artifact"](tmp_path, brief)

    assert api["load_operator_brief_artifact"](tmp_path) == brief


def test_persisted_empty_schema_v2_brief_is_authoritative_empty(tmp_path: Path) -> None:
    api = _api()
    brief = api["OperatorBriefView"](threads=(), dispositions=())

    path = api["write_operator_brief_artifact"](tmp_path, brief)

    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 2
    assert api["load_operator_brief_artifact"](tmp_path) == brief
    assert api["load_operator_brief_artifact"](tmp_path) is not None


def test_schema_1_load_migrates_known_r3a_semantics_without_rewriting(
    tmp_path: Path,
) -> None:
    api = _api()
    path = _write_payload(tmp_path, _schema_1_payload())
    original = path.read_bytes()

    brief = api["load_operator_brief_artifact"](tmp_path)

    assert brief is not None
    assert path.read_bytes() == original
    thread = brief.threads[0]
    assert thread.subject_kind is api["OperatorBriefSubjectKind"].LEGACY_CANONICAL_LEAD
    assert thread.facts == ()
    assert thread.conflicts == ()
    assert thread.coverage_limitations == ()
    assert thread.source_rankings == (
        api["OperatorBriefSourceRanking"](
            source_lead_id="LEAD-LEGACY",
            rank=1,
            score=73,
            signal="medium",
        ),
    )


def test_schema_1_empty_brief_remains_empty_not_missing(tmp_path: Path) -> None:
    api = _api()
    payload = _schema_1_payload()
    payload["threads"] = []
    payload["dispositions"] = []
    _write_payload(tmp_path, payload)

    brief = api["load_operator_brief_artifact"](tmp_path)

    assert brief is not None
    assert brief.threads == ()
    assert brief.dispositions == ()


def test_schema_1_free_text_enrichment_remains_explicit_legacy_context(
    tmp_path: Path,
) -> None:
    api = _api()
    _write_payload(tmp_path, _schema_1_payload(enrichment=True))

    brief = api["load_operator_brief_artifact"](tmp_path)

    assert brief is not None
    thread = brief.threads[0]
    assert thread.facts == ()
    assert tuple(item.kind for item in thread.legacy_context) == (
        api["OperatorBriefLegacyContextKind"].OBSERVED_FACT_TEXT,
        api["OperatorBriefLegacyContextKind"].RELATED_CONTEXT_TEXT,
    )
    assert tuple(item.text for item in thread.legacy_context) == (
        "Legacy free-text observation.",
        "Legacy free-text relationship.",
    )


def test_unsupported_operator_brief_schema_still_fails_closed(
    tmp_path: Path,
) -> None:
    from bugslyce.reports.operator_brief import load_operator_brief_artifact

    _write_payload(
        tmp_path,
        {
            "schema_version": 999,
            "generated_by": "bugslyce.operator_brief",
            "threads": [],
            "dispositions": [],
        },
    )

    with pytest.raises(ValueError, match="unsupported schema_version"):
        load_operator_brief_artifact(tmp_path)


@pytest.mark.parametrize(
    ("field_path", "invalid_value"),
    (
        (("threads", 0, "subject_kind"), "invented_subject"),
        (("threads", 0, "facts", 0, "semantic_class"), "assumed"),
        (("threads", 0, "facts", 0, "kind"), "vulnerability"),
    ),
)
def test_schema_v2_unknown_semantic_enums_fail_closed(
    tmp_path: Path,
    field_path: tuple[object, ...],
    invalid_value: str,
) -> None:
    api = _api()
    path = api["write_operator_brief_artifact"](tmp_path, _brief(api))
    payload = json.loads(path.read_text(encoding="utf-8"))
    target = payload
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = invalid_value
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        api["load_operator_brief_artifact"](tmp_path)


def test_schema_v2_malformed_reference_fails_closed(tmp_path: Path) -> None:
    api = _api()
    path = api["write_operator_brief_artifact"](tmp_path, _brief(api))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["dispositions"][0]["thread_id"] = "THREAD-NOT-PRESENT"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown thread ID"):
        api["load_operator_brief_artifact"](tmp_path)


def test_operator_brief_retirement_remains_schema_agnostic(tmp_path: Path) -> None:
    from bugslyce.reports.operator_brief import (
        OPERATOR_BRIEF_FILENAME,
        retire_operator_brief_artifact,
    )

    path = _write_payload(
        tmp_path,
        {
            "schema_version": 2,
            "generated_by": "bugslyce.operator_brief",
            "threads": [],
            "dispositions": [],
        },
    )
    assert path.name == OPERATOR_BRIEF_FILENAME

    retire_operator_brief_artifact(tmp_path)

    assert not path.exists()


def test_operator_brief_missing_artifact_remains_legacy_absence(
    tmp_path: Path,
) -> None:
    from bugslyce.reports.operator_brief import load_operator_brief_artifact

    assert load_operator_brief_artifact(tmp_path) is None


def test_schema_v2_normalises_only_declared_set_like_fact_fields() -> None:
    api = _api()

    fact = api["OperatorBriefFact"](
        fact_id="FACT-NORMALISATION",
        kind=api["OperatorBriefFactKind"].HTTP_ROUTE,
        semantic_class=api["OperatorBriefSemanticClass"].OBSERVED,
        role=api["OperatorBriefFactRole"].DIRECT_EVIDENCE,
        label="Routes observed",
        summary="Two exact route observations retain presentation order.",
        endpoints=("https://example.test/z", "https://example.test/a"),
        origins=("https://b.test", "https://a.test", "https://b.test"),
        evidence_ids=("EVID-Z", "EVID-A", "EVID-Z"),
        artefact_references=("z.json", "a.json", "z.json"),
        source_references=(
            _source(api, "route", "SOURCE-Z"),
            _source(api, "route", "SOURCE-A"),
            _source(api, "route", "SOURCE-Z"),
        ),
        route="https://example.test/z",
    )

    assert fact.endpoints == (
        "https://example.test/z",
        "https://example.test/a",
    )
    assert fact.origins == ("https://a.test", "https://b.test")
    assert fact.evidence_ids == ("EVID-A", "EVID-Z")
    assert fact.artefact_references == ("a.json", "z.json")
    assert fact.source_references == (
        _source(api, "route", "SOURCE-A"),
        _source(api, "route", "SOURCE-Z"),
    )


def _http_response_fact(
    api,
    *,
    fact_id: str = "FACT-HTTP-RESPONSE",
    semantic_class=None,
    role=None,
    http_method: object = "GET",
    http_status_code: object = 200,
):
    return api["OperatorBriefFact"](
        fact_id=fact_id,
        kind=api["OperatorBriefFactKind"].HTTP_RESPONSE,
        semantic_class=(
            api["OperatorBriefSemanticClass"].OBSERVED
            if semantic_class is None
            else semantic_class
        ),
        role=(
            api["OperatorBriefFactRole"].DIRECT_EVIDENCE if role is None else role
        ),
        label="Retained HTTP response",
        summary="A retained response has exact method and status semantics.",
        endpoints=("https://example.test/admin",),
        origins=("https://example.test",),
        evidence_ids=("EVID-HTTP-ADMIN",),
        artefact_references=("deep_source_route_collection.json",),
        source_references=(
            _source(api, "deep_http_response", "DEEP-HTTP-ADMIN"),
        ),
        route="https://example.test/admin",
        body_sha256="a" * 64,
        http_method=http_method,
        http_status_code=http_status_code,
    )


def _schema_2_non_http_fact_payload() -> dict[str, object]:
    """Explicit pre-HTTP-field schema-2 payload for loader compatibility."""

    return {
        "schema_version": 2,
        "generated_by": "bugslyce.operator_brief",
        "threads": [
            {
                "thread_id": "THREAD-SCHEMA2-LEGACY-NON-HTTP",
                "identity_key": "smb:files.example.test:nt4wrksv",
                "subject_kind": "smb_surface",
                "title": "Legacy structured SMB subject",
                "rank": 1,
                "signal": "direct retained evidence",
                "source_lead_ids": ["LEAD-SMB"],
                "endpoints": ["files.example.test:445/tcp"],
                "origins": [],
                "evidence_ids": ["EVID-SMB-ONE"],
                "why_review": "Direct retained SMB evidence warrants review.",
                "next_review_step": "Review retained SMB enumeration evidence.",
                "facts": [
                    {
                        "fact_id": "FACT-SMB-ONE",
                        "kind": "smb_share",
                        "semantic_class": "observed",
                        "role": "direct_evidence",
                        "label": "SMB Disk share observed",
                        "summary": "A custom Disk share was directly observed.",
                        "endpoints": ["files.example.test:445/tcp"],
                        "origins": [],
                        "evidence_ids": ["EVID-SMB-ONE"],
                        "artefact_references": ["smb-shares.txt"],
                        "source_references": [
                            {
                                "source_kind": "smb_share",
                                "source_id": "files.example.test:445:nt4wrksv",
                            }
                        ],
                        "route": "",
                        "parameter_name": "",
                        "form_method": "",
                        "form_action": "",
                        "service": "",
                        "share_name": "nt4wrksv",
                        "share_type": "Disk",
                        "body_sha256": "",
                    }
                ],
                "conflicts": [],
                "coverage_limitations": [],
                "source_rankings": [
                    {
                        "source_lead_id": "LEAD-SMB",
                        "rank": 1,
                        "score": 80,
                        "signal": "direct retained evidence",
                    }
                ],
                "legacy_context": [],
                "source_artefacts": ["smb-shares.txt"],
            }
        ],
        "dispositions": [
            {
                "source_kind": "operator_summary_lead",
                "source_id": "LEAD-SMB",
                "disposition": "primary_thread",
                "thread_id": "THREAD-SCHEMA2-LEGACY-NON-HTTP",
                "reason_code": "primary_subject",
                "represented_fact_ids": ["FACT-SMB-ONE"],
            }
        ],
    }


def test_http_response_fact_preserves_typed_method_and_status() -> None:
    api = _api()

    fact = _http_response_fact(api)

    assert fact.http_method == "GET"
    assert fact.http_status_code == 200


@pytest.mark.parametrize("http_method", ("", "   "))
def test_http_response_fact_rejects_missing_or_blank_method(http_method: str) -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(api, http_method=http_method)


def test_http_response_fact_rejects_missing_status() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(api, http_status_code=None)


def test_http_response_fact_rejects_boolean_status() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(api, http_status_code=True)


def test_http_response_fact_rejects_non_integer_status() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(api, http_status_code="200")


def test_http_response_fact_rejects_derived_relationship_semantics() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(
            api,
            semantic_class=api["OperatorBriefSemanticClass"].DERIVED,
            role=api["OperatorBriefFactRole"].RELATIONSHIP_CONTEXT,
        )


def test_http_response_fact_rejects_observed_relationship_context() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _http_response_fact(
            api,
            role=api["OperatorBriefFactRole"].RELATIONSHIP_CONTEXT,
        )


def test_http_response_schema_v2_round_trip_preserves_method_and_status(
    tmp_path: Path,
) -> None:
    api = _api()
    fact = _http_response_fact(api)
    thread = _thread(
        api,
        facts=(fact,),
        source_lead_ids=("LEAD-HTTP",),
        source_rankings=(_source_ranking(api, "LEAD-HTTP"),),
    )
    brief = api["OperatorBriefView"](
        threads=(thread,),
        dispositions=(
            _disposition(api, thread.thread_id, "LEAD-HTTP", (fact.fact_id,)),
        ),
    )

    api["write_operator_brief_artifact"](tmp_path, brief)

    loaded = api["load_operator_brief_artifact"](tmp_path)
    assert loaded is not None
    assert loaded.threads[0].facts[0].http_method == "GET"
    assert loaded.threads[0].facts[0].http_status_code == 200


def test_http_response_schema_v2_serialization_is_byte_deterministic(
    tmp_path: Path,
) -> None:
    api = _api()
    fact = _http_response_fact(api)
    thread = _thread(
        api,
        facts=(fact,),
        source_lead_ids=("LEAD-HTTP",),
        source_rankings=(_source_ranking(api, "LEAD-HTTP"),),
    )
    brief = api["OperatorBriefView"](
        threads=(thread,),
        dispositions=(
            _disposition(api, thread.thread_id, "LEAD-HTTP", (fact.fact_id,)),
        ),
    )

    first = api["write_operator_brief_artifact"](tmp_path / "first", brief)
    second = api["write_operator_brief_artifact"](tmp_path / "second", brief)

    assert first.read_bytes() == second.read_bytes()


def test_pre_http_field_schema_v2_non_http_fact_remains_loadable(
    tmp_path: Path,
) -> None:
    api = _api()
    _write_payload(tmp_path, _schema_2_non_http_fact_payload())

    brief = api["load_operator_brief_artifact"](tmp_path)

    assert brief is not None
    assert brief.threads[0].facts[0].kind is api["OperatorBriefFactKind"].SMB_SHARE


def test_pre_http_field_schema_v2_empty_brief_remains_loadable(
    tmp_path: Path,
) -> None:
    api = _api()
    _write_payload(
        tmp_path,
        {
            "schema_version": 2,
            "generated_by": "bugslyce.operator_brief",
            "threads": [],
            "dispositions": [],
        },
    )

    brief = api["load_operator_brief_artifact"](tmp_path)

    assert brief is not None
    assert brief.threads == ()
    assert brief.dispositions == ()


def test_pre_http_field_schema_v2_http_response_fails_closed(
    tmp_path: Path,
) -> None:
    api = _api()
    payload = _schema_2_non_http_fact_payload()
    fact = payload["threads"][0]["facts"][0]
    fact["kind"] = "http_response"
    fact["label"] = "Legacy HTTP response"
    fact["summary"] = "Missing typed HTTP response semantics."
    fact["route"] = "https://example.test/admin"
    fact["body_sha256"] = "a" * 64
    _write_payload(tmp_path, payload)

    with pytest.raises(ValueError):
        api["load_operator_brief_artifact"](tmp_path)


def test_operator_brief_fact_has_no_arbitrary_raw_response_body_field() -> None:
    api = _api()

    field_names = {field.name for field in fields(api["OperatorBriefFact"])}

    assert {"body", "response_body", "body_text"}.isdisjoint(field_names)
