"""D1A: canonical read authority, privacy, absence and side-effect contracts."""

from dataclasses import FrozenInstanceError, asdict, replace
import builtins
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from bugslyce.core.engagement_policy import (
    IDENTIFICATION_HEADERS, IdentificationHeader, assess_engagement_policy,
    build_bug_bounty_policy, write_engagement_policy,
)
from bugslyce.core.models import Asset, Evidence, ProjectState
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE, RULE_EXACT_HOSTNAME,
    build_programme_scope_policy, build_programme_scope_rule,
)
from bugslyce.core.programme_scope_store import save_programme_scope_policy
from bugslyce.dashboard import build_dashboard_read_model
from bugslyce.project_session import (
    initialize_project, load_project,
    save_project_engagement_policy, save_project_programme_scope_policy,
)
from bugslyce.recon.application_service_composition import build_application_service_composition
from bugslyce.recon.application_service_model import build_application_service_model
from bugslyce.recon.application_service_model_persistence import write_application_service_model_artifact
from bugslyce.recon.documentation_assertions import DocumentationAssertionExtractionResult
from bugslyce.recon.investigation_thread_persistence import write_investigation_threads_artifact
from bugslyce.recon.investigation_threads import InvestigationThread
from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence, NativeRedirectRelationship,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionEvidence, AnalysisCoverageOutcome, AnalysisCoverageState,
    AnalysisCoverageUnit, load_analysis_coverage_artifact, write_analysis_coverage_artifact,
)
from bugslyce.reports.operator_brief import build_operator_brief_view, write_operator_brief_artifact
from bugslyce.reports.operator_summary import OperatorSummary, OperatorSummaryLead


def _state(root: Path) -> ProjectState:
    state = ProjectState(
        project_name="dashboard", input_dir=str(root), processed_files=[],
        scope_summary="not an authority decision", assets=[], endpoints=[],
        http_services=[], port_services=[], http_artifacts=[], discovered_paths=[],
        recon_summary=None, recon_manifest=None,
        evidence=[Evidence("EVID-ONE", "response.txt", "http", "observed", {})],
        warnings=[], generated_at="2026-09-21T00:00:00Z",
        engagement_context="internal_authorised",
    )
    (root / "project_state.json").write_text(json.dumps({
        "project_state": asdict(state), "candidates": [],
    }))
    return state


def _thread(digest: str, **changes) -> InvestigationThread:
    return replace(InvestigationThread(
        thread_id="THREAD-" + digest * 64, title="Canonical " + digest,
        priority="medium", category="application_interface", summary="Direct response.",
        why_it_matters="Inspect retained context.",
        related_endpoints=("https://example.test/api",),
        related_evidence_ids=("EVID-ONE",), related_candidate_ids=(), related_lead_ids=(),
        suggested_manual_review_order=("Read saved evidence.",), kill_switch_guidance=None,
    ), **changes)


def _forbid(*args, **kwargs):
    raise AssertionError("Dashboard must not execute or reconstruct semantics")


def test_persisted_order_subsumption_navigation_and_legacy_non_authority(tmp_path, monkeypatch):
    _state(tmp_path)
    first = _thread("b", priority="low")
    last = _thread("a", priority="high")
    child = _thread("c", subsumed_by_thread_id=first.thread_id,
                    subsumption_reason="Already covered by the parent.")
    threads = (first, child, last)
    write_investigation_threads_artifact(tmp_path, threads)
    legacy = OperatorSummary(
        review_first=[OperatorSummaryLead(
            title="Legacy wins", why="Legacy", endpoints=["https://legacy.test"],
            evidence_ids=[], next_action="Review", signal="high", score=99999,
            rank=1, lead_id="LEAD-LEGACY",
        )], low_signal=[], coverage=[],
    )
    write_operator_brief_artifact(tmp_path, build_operator_brief_view(legacy))
    monkeypatch.setattr("bugslyce.recon.investigation_threads.build_investigation_threads", _forbid)
    monkeypatch.setattr("bugslyce.reports.html_model.build_html_report_model", _forbid)
    monkeypatch.setattr("bugslyce.reports.operator_summary.build_operator_summary", _forbid)
    model = build_dashboard_read_model(tmp_path)

    assert model.investigation_threads == threads
    assert model.primary_investigation_threads == (first, last)
    assert model.primary_investigation_threads[0] is model.investigation_threads[0]
    assert model.operator_report_view.primary_anchor_ids == (first.thread_id, last.thread_id)
    assert model.operator_report_view.investigation_context.evidence_backlinks
    assert "LEAD-LEGACY" not in repr(model)
    with pytest.raises(FrozenInstanceError):
        model.investigation_threads = ()


def test_generic_evidence_exposes_only_loaded_tuple_and_preserves_absence(tmp_path):
    absent = build_dashboard_read_model(tmp_path)
    assert absent.generic_evidence is None
    _state(tmp_path)
    loaded = build_dashboard_read_model(tmp_path)
    assert loaded.generic_evidence == (Evidence("EVID-ONE", "response.txt", "http", "observed", {}),)
    assert not hasattr(loaded, "project_state")
    assert all(not isinstance(value, ProjectState) for value in vars(loaded).values())
    payload = json.loads((tmp_path / "project_state.json").read_text())
    payload["project_state"]["evidence"] = []
    (tmp_path / "project_state.json").write_text(json.dumps(payload))
    empty = build_dashboard_read_model(tmp_path)
    assert empty.generic_evidence == ()


@pytest.mark.parametrize("present", [False, True])
def test_absent_vs_authoritative_empty_never_reconstructs_priority(tmp_path, monkeypatch, present):
    _state(tmp_path)
    # Even an unusable legacy artifact is irrelevant to canonical dashboard loading.
    (tmp_path / "operator_brief.json").write_text('{"rank": 1, "score": 999999}')
    if present:
        write_investigation_threads_artifact(tmp_path, ())
    monkeypatch.setattr("bugslyce.recon.investigation_threads.build_investigation_threads", _forbid)
    monkeypatch.setattr("bugslyce.reports.operator_summary.build_operator_summary", _forbid)
    model = build_dashboard_read_model(tmp_path)
    assert model.investigation_threads == (() if present else None)
    assert model.primary_investigation_threads == (() if present else None)
    assert model.operator_report_view.primary_anchor_ids == ()
    assert model.analysis_coverage_evidence is None


def test_application_relationships_are_loaded_not_inferred(tmp_path, monkeypatch):
    evidence = NativeObservationSemanticEvidence(redirect_relationships=(
        NativeRedirectRelationship(
            source_url="https://example.test/start", raw_location="/login",
            target_url="https://example.test/login", candidate_index=0, exchange_index=0,
        ),
    ))
    application = build_application_service_model(
        application_composition=build_application_service_composition(
            native_observation_evidence=evidence,
        ),
        documentation_assertions=DocumentationAssertionExtractionResult((), (), 0, 0),
        native_observation_evidence=evidence,
    )
    assert application.application_composition.relations
    write_application_service_model_artifact(tmp_path, application)
    monkeypatch.setattr("bugslyce.recon.application_service_model.build_application_service_model", _forbid)
    monkeypatch.setattr("bugslyce.recon.application_service_composition.build_application_service_composition", _forbid)
    model = build_dashboard_read_model(tmp_path)
    assert model.application_service_model == application
    assert model.application_service_model.application_composition.relations == application.application_composition.relations
    assert model.application_service_model.native_observation_evidence.redirect_relationships[0].destination_fetched is False


def test_authority_is_owner_assessment_without_private_values(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.test\n")
    _, project_file = initialize_project(
        name="dashboard", target="example.test", scope_file=scope_file,
        output_dir=tmp_path / "project", engagement_context="bug_bounty",
    )
    project_root = project_file.parent
    _state(project_root)
    policy = build_bug_bounty_policy(
        identification_requirement=IDENTIFICATION_HEADERS,
        identification_headers=(IdentificationHeader("X-Researcher", "SECRET-HEADER"),),
        updated_at="2026-09-21T00:00:00Z",
    )
    scope = build_programme_scope_policy([
        build_programme_scope_rule(
            rule_id="private-rule", action=ACTION_INCLUDE, kind=RULE_EXACT_HOSTNAME,
            value="private.example.test", private_note="SECRET-NOTE",
            private_source_wording="SECRET-SOURCE",
        ),
    ], updated_at="2026-09-21T00:00:00Z")
    save_project_engagement_policy(project_file, policy)
    save_project_programme_scope_policy(project_file, scope)
    model = build_dashboard_read_model(project_file)
    assert model.authority.engagement_assessment == assess_engagement_policy(policy)
    assert model.authority.programme_include_rule_count == 1
    assert model.authority.programme_exclude_rule_count == 0
    serialized = json.dumps(asdict(model))
    for secret in ("SECRET-HEADER", "SECRET-NOTE", "SECRET-SOURCE", "private.example.test"):
        assert secret not in serialized
        assert secret not in repr(model)


def test_raw_artifact_root_does_not_adopt_adjacent_private_policies(tmp_path):
    _state(tmp_path)
    thread = _thread("a")
    write_investigation_threads_artifact(tmp_path, (thread,))
    write_engagement_policy(
        tmp_path, build_bug_bounty_policy(updated_at="2026-09-21T00:00:00Z"),
    )
    scope = build_programme_scope_policy([
        build_programme_scope_rule(
            rule_id="unbound", action=ACTION_INCLUDE, kind=RULE_EXACT_HOSTNAME,
            value="private.example.test", private_note="PRIVATE-NOTE",
            private_source_wording="PRIVATE-SOURCE",
        ),
    ], updated_at="2026-09-21T00:00:00Z")
    save_programme_scope_policy(tmp_path / "programme_scope.json", scope)

    model = build_dashboard_read_model(tmp_path)
    assert model.investigation_threads == (thread,)
    assert model.primary_investigation_threads == (thread,)
    assert model.authority.engagement_assessment is None
    assert model.authority.programme_include_rule_count is None
    assert model.authority.programme_exclude_rule_count is None
    assert "PRIVATE-NOTE" not in repr(model)
    assert "PRIVATE-SOURCE" not in repr(model)
    assert "private.example.test" not in repr(model)


def test_raw_artifact_root_does_not_read_adjacent_private_policies(tmp_path, monkeypatch):
    _state(tmp_path)
    (tmp_path / "engagement_policy.json").write_text("unbound private material")
    (tmp_path / "programme_scope.json").write_text("unbound private material")
    original_open = os.open

    def no_private_open(path, flags, *args, **kwargs):
        assert Path(path).name not in {"engagement_policy.json", "programme_scope.json"}
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_private_open)
    model = build_dashboard_read_model(tmp_path)
    assert model.authority.engagement_assessment is None
    assert model.authority.programme_include_rule_count is None
    assert model.authority.programme_exclude_rule_count is None


def test_observed_in_scope_assets_cannot_manufacture_authority(tmp_path):
    state = _state(tmp_path)
    state.assets.append(Asset("example.test", True, ["observed"], ["EVID-ONE"], []))
    (tmp_path / "project_state.json").write_text(json.dumps({
        "project_state": asdict(state), "candidates": [],
    }))
    model = build_dashboard_read_model(tmp_path)
    assert model.authority.engagement_assessment is None
    assert model.authority.programme_include_rule_count is None
    assert model.authority.programme_exclude_rule_count is None
    assert model.application_service_model is None


@pytest.mark.parametrize("kind", ["analysed", "not_run", "incomplete", "unknown"])
def test_coverage_is_persisted_execution_proof_not_finding_inference(tmp_path, kind):
    _state(tmp_path)
    options = {
        "analysed": dict(input_membership_proven=True, invocation_proven=True,
                         completed=True, finding_count=0),
        "not_run": dict(not_run_outcome=AnalysisCoverageOutcome.BOUNDED_SKIPPED),
        "incomplete": dict(attempted=True, partial_failure=True),
        "unknown": {},
    }
    proof = AnalysisCoverageExecutionEvidence(
        unit=AnalysisCoverageUnit("test-capability", "retained-source", "SOURCE-ONE"),
        **options[kind],
    )
    write_analysis_coverage_artifact(tmp_path, (proof,))
    model = build_dashboard_read_model(tmp_path)
    assert model.analysis_coverage_evidence == load_analysis_coverage_artifact(tmp_path)
    item = model.operator_report_view.analysis_coverage.items[0]
    assert item.state == {
        "analysed": AnalysisCoverageState.ANALYSED, "not_run": AnalysisCoverageState.NOT_RUN,
        "incomplete": AnalysisCoverageState.INCOMPLETE, "unknown": AnalysisCoverageState.UNKNOWN,
    }[kind]
    if kind == "analysed":
        assert item.outcome == AnalysisCoverageOutcome.NO_FINDING


def test_project_object_and_file_are_supported_without_exposing_notes(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.test\n")
    output = tmp_path / "project"
    _, path = initialize_project(name="dashboard", target="example.test",
                                 scope_file=scope, output_dir=output)
    session = load_project(path)
    model = build_dashboard_read_model(session)
    assert model == build_dashboard_read_model(path)
    assert model == build_dashboard_read_model(output)
    assert model.project.name == "dashboard"
    assert model.project.target == "example.test"
    assert model.investigation_threads is None


def test_confidence_reuses_structured_failure_without_claiming_analysis_coverage(tmp_path):
    _state(tmp_path)
    (tmp_path / "project_pipeline.json").write_text(json.dumps({"steps": [{
        "step_id": "PIPELINE-STEP-007", "name": "Collection", "status": "failed",
        "message": "Recorded bounded failure",
    }]}))
    model = build_dashboard_read_model(tmp_path)
    notice = next(n for n in model.confidence_notices if "Recorded bounded failure" in n.direct_fact)
    assert notice.artefact_references == ("project_pipeline.json",)
    assert "absent evidence" in notice.operator_implication
    assert model.analysis_coverage_evidence is None
    assert model == build_dashboard_read_model(tmp_path)


def test_loading_is_read_only_and_offline(tmp_path, monkeypatch):
    _state(tmp_path)
    write_investigation_threads_artifact(tmp_path, (_thread("a"),))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    original_open = builtins.open
    original_os_open = os.open

    def read_open(file, mode="r", *args, **kwargs):
        assert not any(c in mode for c in "wax+")
        return original_open(file, mode, *args, **kwargs)

    def read_os_open(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        return original_os_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", read_open)
        patch.setattr(os, "open", read_os_open)
        for name in ("mkdir", "remove", "unlink", "rename", "replace", "system"):
            patch.setattr(os, name, _forbid)
        patch.setattr(Path, "write_text", _forbid)
        patch.setattr(Path, "write_bytes", _forbid)
        patch.setattr(socket, "socket", _forbid)
        patch.setattr(socket, "getaddrinfo", _forbid)
        patch.setattr(subprocess, "Popen", _forbid)
        model = build_dashboard_read_model(tmp_path)
    assert model.investigation_threads
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_project_authority_references_remain_owned_by_project_session(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.test\n")
    session, _ = initialize_project(
        name="dashboard", target="example.test", scope_file=scope,
        output_dir=tmp_path / "project", engagement_context="bug_bounty",
    )
    referenced = replace(session, engagement_policy_file="engagement_policy.json")
    with pytest.raises(ValueError):
        build_dashboard_read_model(referenced)
    policy = build_bug_bounty_policy(updated_at="2026-09-21T00:00:00Z")
    write_engagement_policy(Path(session.output_dir), policy)
    programme_scope = build_programme_scope_policy([
        build_programme_scope_rule(
            rule_id="adjacent", action=ACTION_INCLUDE, kind=RULE_EXACT_HOSTNAME,
            value="adjacent.example.test",
        ),
    ], updated_at="2026-09-21T00:00:00Z")
    save_programme_scope_policy(
        Path(session.output_dir) / "programme_scope.json", programme_scope,
    )
    assert build_dashboard_read_model(session).authority.engagement_assessment is None
    assert build_dashboard_read_model(session).authority.programme_include_rule_count is None
    assert build_dashboard_read_model(referenced).authority.engagement_assessment == assess_engagement_policy(policy)
    assert build_dashboard_read_model(referenced).authority.programme_include_rule_count is None

    session_with_reference, _ = save_project_engagement_policy(
        Path(session.output_dir) / "bugslyce_project.json", policy,
    )
    assert build_dashboard_read_model(session_with_reference).authority.engagement_assessment == assess_engagement_policy(policy)
    (Path(session.output_dir) / "engagement_policy.json").unlink()
    with pytest.raises(ValueError, match="Engagement policy file is missing"):
        build_dashboard_read_model(Path(session.output_dir))


def test_malformed_canonical_snapshot_fails_instead_of_falling_back(tmp_path):
    (tmp_path / "investigation_threads.json").write_text('{"schema_version": 999}')
    with pytest.raises(ValueError):
        build_dashboard_read_model(tmp_path)
