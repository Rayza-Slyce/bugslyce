"""WP5C application/service Operator Brief and HTML integration contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import runpy

import pytest

from bugslyce.recon import application_service_model as a3
from bugslyce.recon.documentation_assertions import DocumentationAssertionKind
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.reports import html
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefView,
    load_operator_brief_artifact,
    write_operator_brief_artifact,
)
from bugslyce.reports.operator_brief_application_service import (
    compose_operator_brief_application_service,
)
from bugslyce.reports.operator_brief_html_presentation import (
    build_operator_brief_html_presentation,
)
from bugslyce.reports.operator_brief_assembly import assemble_operator_brief
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpCompositionInput,
    OperatorBriefHttpObservation,
    compose_operator_brief_http,
)


_A3 = runpy.run_path("tests/test_application_service_model.py")
_COMPOSITION = runpy.run_path("tests/test_operator_brief_composition_persistence.py")
_SCHEMA = runpy.run_path("tests/test_operator_brief_schema_v2.py")
_HTML = runpy.run_path("tests/test_operator_brief_html_rendering.py")


def _empty_operator_brief():
    return _COMPOSITION["_empty_composition"]()


def _model(*, observed: bool = False, target_only: bool = False, realtime: bool = False):
    documentation = _A3["_documentation"](
        _A3["_service_item"](),
        *(_A3["_realtime_item"](),) if realtime else (),
    )
    if observed:
        source, target = (
            (
                "https://observed.example.test/start",
                "https://api.example.test/login",
            )
            if target_only
            else (
                "https://api.example.test/start",
                "https://elsewhere.example.test/login",
            )
        )
        composition = _A3["_observed_composition"](
            _A3["_redirect"](source, target, "EVID-OBSERVED")
        )
    else:
        composition = _A3["_empty_composition"]()
    return _A3["_model"](a3, composition, documentation)


def _adapt(model):
    return compose_operator_brief_application_service(
        model,
        operator_brief_composition=_empty_operator_brief(),
    )


def _operator_brief_with_observed_api_origin():
    base = _empty_operator_brief()
    observation = OperatorBriefHttpObservation(
        observation_id="HTTP-OBS-API",
        source_fingerprint_id="FINGERPRINT-API",
        endpoint="https://api.example.test/start",
        final_url="https://api.example.test/start",
        origin=HttpOrigin("https", "api.example.test", 443),
        method="GET",
        status_code=302,
        status_bucket="redirect",
        body_sha256="a" * 64,
        body_bytes=0,
        body_empty=True,
        collection_stage="deep-bounded-core",
        evidence_ids=("EVID-OBSERVED",),
        artefact_references=("response-api-start.json",),
    )
    return assemble_operator_brief(
        http=compose_operator_brief_http(
            OperatorBriefHttpCompositionInput(
                observations=(observation,),
                exact_equivalences=(),
            )
        ),
        network=base.network,
        web_context=base.web_context,
        source_native=base.source_native,
    )


def test_documented_http_service_is_documented_and_never_observed() -> None:
    adaptation = _adapt(_model())
    fact = next(f for f in adaptation.facts if f.kind is OperatorBriefFactKind.DOCUMENTED_SERVICE)
    assert fact.semantic_class is OperatorBriefSemanticClass.DOCUMENTED
    assert fact.role is OperatorBriefFactRole.DOCUMENTATION_EVIDENCE
    assert fact.semantic_class is not OperatorBriefSemanticClass.OBSERVED
    assert fact.endpoints == ("https://api.example.test/v1",)


def test_documented_realtime_remains_documented_cross_protocol_and_non_executable() -> None:
    model = _model(realtime=True)
    adaptation = _adapt(model)
    fact = next(
        f for f in adaptation.facts
        if f.kind is OperatorBriefFactKind.DOCUMENTED_REALTIME_ENDPOINT
    )
    assert fact.semantic_class is OperatorBriefSemanticClass.DOCUMENTED
    assert fact.endpoints == ("wss://stream.example.test/v1/public",)
    assert "did not connect" in fact.summary
    assert not any(hasattr(model.documented_realtime_endpoints[0], name) for name in ("connect", "execute", "request"))


def test_source_side_observed_origin_correspondence_is_derived_context() -> None:
    fact = next(
        f for f in _adapt(_model(observed=True)).facts
        if f.kind is OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE
    )
    assert fact.semantic_class is OperatorBriefSemanticClass.DERIVED
    assert fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT
    assert "independently observed a redirect response" in fact.summary
    assert "does not establish that the documented service endpoint responded" in fact.summary


def test_correspondence_keeps_documentation_and_observation_provenance_separate() -> None:
    fact = next(
        f for f in _adapt(_model(observed=True)).facts
        if f.kind is OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE
    )
    kinds = {reference.source_kind for reference in fact.source_references}
    assert "documentation_assertion" in kinds
    assert "documentation_source" in kinds
    assert "application_service_observed_relation" in kinds
    assert {"EVID-SERVICE", "EVID-OBSERVED"}.issubset(fact.evidence_ids)
    presentation = build_operator_brief_html_presentation(
        _empty_operator_brief(),
        application_service_model=_model(observed=True),
    )
    rendered = html._investigation_subject(
        next(
            item for item in presentation.investigation_subjects
            if any(value.kind is OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE for value in item.facts)
        )
    )
    assert "documentation_source:" in rendered
    assert "application_service_observed_relation:" in rendered


def test_redirect_target_only_never_creates_observed_service_presentation() -> None:
    adaptation = _adapt(_model(observed=True, target_only=True))
    assert not any(
        fact.kind is OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE
        for fact in adaptation.facts
    )
    assert all(fact.semantic_class is not OperatorBriefSemanticClass.OBSERVED for fact in adaptation.facts)


def test_multiple_documentation_supports_do_not_duplicate_service_subjects() -> None:
    documentation = _A3["_documentation"](_A3["_service_item"](two_supports=True))
    model = _A3["_model"](a3, documentation=documentation)
    adaptation = _adapt(model)
    service_subjects = tuple(
        subject for subject in adaptation.subjects
        if subject.subject_kind.value == "documented_application_service"
    )
    assert len(service_subjects) == 1
    assert len(tuple(f for f in adaptation.facts if f.kind is OperatorBriefFactKind.DOCUMENTED_SERVICE)) == 1


def test_service_bases_sharing_origin_consolidate_without_losing_full_urls() -> None:
    documentation = _A3["_documentation"](
        _A3["_service_item"](path="/v1", url="https://docs.example.test/v1"),
        _A3["_service_item"](path="/v2", url="https://docs.example.test/v2"),
    )
    adaptation = _adapt(_A3["_model"](a3, documentation=documentation))
    service_subjects = tuple(
        subject for subject in adaptation.subjects
        if subject.subject_kind.value == "documented_application_service"
    )
    assert len(service_subjects) == 1
    assert service_subjects[0].endpoints == (
        "https://api.example.test/v1",
        "https://api.example.test/v2",
    )


def test_exact_origin_correspondence_supports_existing_http_thread_only() -> None:
    composition = _operator_brief_with_observed_api_origin()
    presentation = build_operator_brief_html_presentation(
        composition,
        application_service_model=_model(observed=True),
    )
    application = next(
        item for item in presentation.investigation_subjects
        if item.source_family == "application_service"
    )
    primary = tuple(item for item in presentation.investigation_subjects if item.rank is not None)
    assert application.disposition == "supporting_context"
    assert application.rank is None
    assert len(primary) == 1
    assert application.thread_id == primary[0].thread_id


def test_independent_a2_facts_remain_resource_scoped_documented_context() -> None:
    body = b"""<html><main>
      <h2>HTTP operation</h2><pre>POST /v1/accounts/{accountId}/token</pre>
      <table><tr><th>Header name</th><th>Required</th></tr><tr><td>X-Client-Token</td><td>Yes</td></tr></table>
      <dl><dt>Required authentication scheme</dt><dd>Bearer</dd></dl>
      <table><tr><th>Required OAuth scope</th></tr><tr><td>account:write</td></tr></table>
    </main></html>"""
    documentation = _A3["_documentation"](_A3["_source_item"](body))
    model = _A3["_model"](
        a3,
        composition=_A3["_empty_composition"](),
        documentation=documentation,
    )
    adaptation = _adapt(model)
    assert {assertion.kind for assertion in model.documentation_assertions.assertions} == {
        DocumentationAssertionKind.HTTP_OPERATION,
        DocumentationAssertionKind.REQUIRED_HEADER,
        DocumentationAssertionKind.AUTHENTICATION_SCHEME,
        DocumentationAssertionKind.OAUTH_SCOPE,
    }
    assert len(adaptation.subjects) == 1
    assert adaptation.subjects[0].subject_kind.value == "documentation_context"
    assert all(fact.semantic_class is OperatorBriefSemanticClass.DOCUMENTED for fact in adaptation.facts)
    assert all("no service or operation association" in fact.summary for fact in adaptation.facts)


def test_unsupported_relationships_findings_and_categories_are_not_created() -> None:
    adaptation = _adapt(_model(realtime=True))
    vocabulary = {kind.value for kind in OperatorBriefFactKind}
    assert not vocabulary & {
        "otp", "bootstrap", "credential_flow", "access_posture",
        "graphql", "commerce", "admin", "semantic_category",
    }
    assert all(not subject.policy_subject.coverage_limitations for subject in adaptation.subjects)


def test_presentation_preserves_human_titles_and_secondary_machine_ids() -> None:
    presentation = build_operator_brief_html_presentation(
        _empty_operator_brief(),
        application_service_model=_model(realtime=True),
    )
    assert presentation.investigation_subjects
    assert all(item.display_title.startswith("Documented ") for item in presentation.investigation_subjects)
    assert all(item.policy_key not in item.display_title for item in presentation.investigation_subjects)
    rendered = "".join(html._investigation_subject(item) for item in presentation.investigation_subjects)
    assert "Semantic subject key" in rendered
    assert "Policy key" in rendered


def test_html_visibly_distinguishes_observed_documented_and_derived_truth() -> None:
    facts = _adapt(_model(observed=True)).facts
    documented = next(
        fact for fact in facts if fact.kind is OperatorBriefFactKind.DOCUMENTED_SERVICE
    )
    derived = next(
        fact for fact in facts
        if fact.kind is OperatorBriefFactKind.SERVICE_ORIGIN_CORRESPONDENCE
    )
    observed = replace(
        documented,
        fact_id="FACT-OBSERVED",
        kind=OperatorBriefFactKind.SERVICE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
    )
    rendered = html._investigation_facts((observed, documented, derived))
    assert ">Observed</span>" in rendered
    assert ">Documented</span>" in rendered
    assert ">Derived</span>" in rendered


def test_rendered_report_keeps_unassociated_documented_context_collapsed(
    tmp_path: Path,
) -> None:
    base = _HTML["_model_with_composition"](tmp_path)
    application_model = _model(realtime=True)
    presentation = build_operator_brief_html_presentation(
        base.operator_brief_composition,
        application_service_model=application_model,
    )
    rendered = html.render_html_report(
        replace(
            base,
            application_service_model=application_model,
            operator_brief_presentation=presentation,
        )
    )
    assert "Documented application and service context" in rendered
    assert "wss://stream.example.test/v1/public" in rendered
    assert ">Documented</span>" in rendered
    assert "did not connect" in rendered
    assert "<h3>application_service:" not in rendered


def test_documented_schema_3_round_trip_and_schema_2_compatibility(tmp_path: Path) -> None:
    api = _SCHEMA["_api"]()
    base = _SCHEMA["_smb_fact"](api)
    documented = replace(
        base,
        fact_id="FACT-DOCUMENTED",
        kind=OperatorBriefFactKind.DOCUMENTED_SERVICE,
        semantic_class=OperatorBriefSemanticClass.DOCUMENTED,
        role=OperatorBriefFactRole.DOCUMENTATION_EVIDENCE,
        label="Documented HTTP service",
        summary="Documentation describes https://api.example.test/v1.",
    )
    thread = _SCHEMA["_thread"](api, facts=(documented,))
    brief = OperatorBriefView(threads=(thread,), dispositions=())
    path = write_operator_brief_artifact(tmp_path / "schema-3", brief)
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 3
    assert load_operator_brief_artifact(path.parent) == brief

    schema_2 = json.loads(path.read_text(encoding="utf-8"))
    schema_2["schema_version"] = 2
    relabelled_path = tmp_path / "schema-2-relabelled" / "operator_brief.json"
    relabelled_path.parent.mkdir()
    relabelled_path.write_text(json.dumps(schema_2), encoding="utf-8")
    with pytest.raises(ValueError, match="schema 3"):
        load_operator_brief_artifact(relabelled_path.parent)

    legacy_path = tmp_path / "schema-2" / "operator_brief.json"
    legacy_path.parent.mkdir()
    legacy_path.write_text(
        json.dumps(_SCHEMA["_schema_2_non_http_fact_payload"]()),
        encoding="utf-8",
    )
    legacy = load_operator_brief_artifact(legacy_path.parent)
    assert legacy is not None
    assert legacy.threads[0].facts[0].kind is OperatorBriefFactKind.SMB_SHARE


def test_documented_fact_role_semantic_pairing_fails_closed() -> None:
    fact = next(f for f in _adapt(_model()).facts if f.kind is OperatorBriefFactKind.DOCUMENTED_SERVICE)
    with pytest.raises(ValueError, match="Documented|documentation"):
        replace(fact, semantic_class=OperatorBriefSemanticClass.OBSERVED)
    with pytest.raises(ValueError, match="Documented|documentation|direct evidence"):
        replace(fact, role=OperatorBriefFactRole.DIRECT_EVIDENCE)


def test_adapter_and_presentation_are_immutable_and_preserve_exact_a3() -> None:
    model = _model()
    adaptation = _adapt(model)
    assert adaptation.application_service_model is model
    with pytest.raises(FrozenInstanceError):
        adaptation.application_service_model = _model()  # type: ignore[misc]


def test_thread_evidence_vocabulary_adds_documented_without_reclassifying_existing() -> None:
    from bugslyce.reports.operator_brief_thread_policy import OperatorBriefThreadEvidenceBasis

    assert {value.value for value in OperatorBriefThreadEvidenceBasis} == {
        "direct", "documented", "derived", "legacy",
    }


def test_public_adapter_is_target_independent_and_has_no_execution_surface() -> None:
    model = _model(realtime=True)
    adaptation = _adapt(model)
    assert not any(
        hasattr(adaptation, name)
        for name in ("run", "execute", "request", "connect", "authorise", "schedule")
    )
    public_values = {
        *(kind.value for kind in OperatorBriefFactKind),
        *(kind.value for kind in OperatorBriefSemanticClass),
    }
    assert all("example.test" not in value for value in public_values)
