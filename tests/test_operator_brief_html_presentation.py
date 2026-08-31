"""RED contract for pure canonical Operator Brief HTML presentation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from importlib import import_module
from inspect import signature
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from bugslyce.recon.application_service_model import ApplicationServiceModel
from bugslyce.reports import html_model
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
)
from bugslyce.reports.html_model import HtmlReportModel, build_html_report_model
from bugslyce.reports.operator_brief import (
    OperatorBriefCoverageLimitation,
    OperatorBriefSourceRanking,
)
from bugslyce.reports.operator_brief_assembly import (
    OperatorBriefComposition,
    assemble_operator_brief,
)
from bugslyce.reports.operator_brief_composition_persistence import (
    load_operator_brief_composition_artifact,
    write_operator_brief_composition_artifact,
)
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefSourceNativeComposition,
)


_ROOT = Path(__file__).resolve().parents[1]
_PERSISTENCE_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_composition_persistence.py")
)
_LOADING_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_composition_loading_integration.py")
)
_PRESENTATION_MODULE = "bugslyce.reports.operator_brief_html_presentation"


def _presentation_api() -> SimpleNamespace:
    module = import_module(_PRESENTATION_MODULE)
    names = (
        "OperatorBriefHtmlPresentation",
        "OperatorBriefInvestigationSubject",
        "OperatorBriefSourceNativePresentationDetail",
        "build_operator_brief_html_presentation",
    )
    return SimpleNamespace(
        module=module,
        **{name: getattr(module, name) for name in names},
    )


def _fresh_presentation_api(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Import only the future projection module after effective seams are guarded."""

    monkeypatch.delitem(sys.modules, _PRESENTATION_MODULE, raising=False)
    return _presentation_api()


def _representative_composition() -> OperatorBriefComposition:
    return _PERSISTENCE_HELPERS["_representative_composition"]()


def _empty_composition() -> OperatorBriefComposition:
    return _PERSISTENCE_HELPERS["_empty_composition"]()


def _ranked_out_of_storage_order_composition() -> OperatorBriefComposition:
    empty_network = _PERSISTENCE_HELPERS["_empty_network"]
    empty_web = _PERSISTENCE_HELPERS["_empty_web"]
    http = _PERSISTENCE_HELPERS["_http"]
    policy = _PERSISTENCE_HELPERS["_policy"]
    source_native = _PERSISTENCE_HELPERS["_source_native"]

    storage_first = replace(policy("ATTENTION"), policy_key="AAA-STORAGE-FIRST")
    return assemble_operator_brief(
        http=http(),
        network=empty_network(),
        web_context=empty_web(),
        source_native=source_native(storage_first),
    )


def _single_owner_composition(owner: str) -> OperatorBriefComposition:
    empty_http = _PERSISTENCE_HELPERS["_empty_http"]
    empty_network = _PERSISTENCE_HELPERS["_empty_network"]
    empty_web = _PERSISTENCE_HELPERS["_empty_web"]
    http = _PERSISTENCE_HELPERS["_http"]
    network = _PERSISTENCE_HELPERS["_network"]
    web = _PERSISTENCE_HELPERS["_web"]
    policy = _PERSISTENCE_HELPERS["_policy"]
    source_native = _PERSISTENCE_HELPERS["_source_native"]

    if owner == "network":
        return assemble_operator_brief(
            http=empty_http(),
            network=network(),
            web_context=empty_web(),
            source_native=OperatorBriefSourceNativeComposition(subjects=()),
        )
    if owner == "web_context":
        return assemble_operator_brief(
            http=empty_http(),
            network=empty_network(),
            web_context=web(),
            source_native=OperatorBriefSourceNativeComposition(subjects=()),
        )
    if owner == "source_native":
        return assemble_operator_brief(
            http=empty_http(),
            network=empty_network(),
            web_context=empty_web(),
            source_native=source_native(policy("ONLY-SOURCE-NATIVE")),
        )
    raise AssertionError(f"unknown single-owner fixture: {owner}")


def _limited_composition() -> OperatorBriefComposition:
    empty_http = _PERSISTENCE_HELPERS["_empty_http"]
    empty_network = _PERSISTENCE_HELPERS["_empty_network"]
    empty_web = _PERSISTENCE_HELPERS["_empty_web"]
    policy = _PERSISTENCE_HELPERS["_policy"]
    source_native = _PERSISTENCE_HELPERS["_source_native"]
    limitation = OperatorBriefCoverageLimitation(
        limitation_id="COVERAGE-R3C-LOCAL",
        capability="deep_form_inventory",
        source_role="deep_source_response",
        source_id="DEEP-R3C-LOCAL",
        state=AnalysisCoverageState.ANALYSED,
        outcome=AnalysisCoverageOutcome.NO_FINDING,
        unknown_reason=None,
        execution_note=None,
        summary="Zero forms in the retained body for DEEP-R3C-LOCAL.",
    )
    limited_policy = replace(
        policy("LIMITED"),
        coverage_limitations=(limitation,),
    )
    return assemble_operator_brief(
        http=empty_http(),
        network=empty_network(),
        web_context=empty_web(),
        source_native=source_native(limited_policy),
    )


def _provenance_composition() -> OperatorBriefComposition:
    empty_http = _PERSISTENCE_HELPERS["_empty_http"]
    empty_network = _PERSISTENCE_HELPERS["_empty_network"]
    empty_web = _PERSISTENCE_HELPERS["_empty_web"]
    policy = _PERSISTENCE_HELPERS["_policy"]
    source_native = _PERSISTENCE_HELPERS["_source_native"]
    ranking = OperatorBriefSourceRanking(
        source_lead_id="R3C-PROVENANCE-LEAD",
        rank=1,
        score=42,
        signal="retained_source_provenance",
    )
    provenance_policy = replace(
        policy("PROVENANCE"),
        source_rankings=(ranking,),
        source_lead_ids=(ranking.source_lead_id,),
    )
    return assemble_operator_brief(
        http=empty_http(),
        network=empty_network(),
        web_context=empty_web(),
        source_native=source_native(provenance_policy),
    )


def _plain_text_composition() -> OperatorBriefComposition:
    empty_http = _PERSISTENCE_HELPERS["_empty_http"]
    empty_network = _PERSISTENCE_HELPERS["_empty_network"]
    empty_web = _PERSISTENCE_HELPERS["_empty_web"]
    policy = _PERSISTENCE_HELPERS["_policy"]
    source_native = _PERSISTENCE_HELPERS["_source_native"]
    plain_policy = replace(
        policy("PLAIN-TEXT"),
        semantic_subject_key='source-native:plain<>&"\'',
    )
    return assemble_operator_brief(
        http=empty_http(),
        network=empty_network(),
        web_context=empty_web(),
        source_native=source_native(plain_policy),
    )


def _ranked_then_unranked_policy_keys(
    composition: OperatorBriefComposition,
) -> tuple[str, ...]:
    decisions = {
        item.policy_key: item for item in composition.thread_policy_result.decisions
    }
    ranked = tuple(
        item.policy_key
        for item in sorted(
            composition.policy_subjects,
            key=lambda item: decisions[item.policy_key].rank or 0,
        )
        if decisions[item.policy_key].rank is not None
    )
    unranked = tuple(
        item.policy_key
        for item in composition.policy_subjects
        if decisions[item.policy_key].rank is None
    )
    return ranked + unranked


def _owner_by_policy_key(
    composition: OperatorBriefComposition,
) -> dict[str, tuple[str, object]]:
    """Resolve every policy key through its closed canonical owner identity."""

    candidates: list[tuple[str, object, str]] = []
    for family, semantic_family, subjects in (
        ("http", "http", composition.http.subjects),
        ("network", "network", composition.network.subjects),
        ("web_context", "web", composition.web_context.subjects),
    ):
        candidates.extend(
            (family, owner, f"{semantic_family}:{owner.subject_id}")
            for owner in subjects
        )
    candidates.extend(
        (
            "source_native",
            owner,
            owner.policy_subject.semantic_subject_key or "",
        )
        for owner in composition.source_native.subjects
    )

    resolved: dict[str, tuple[str, object]] = {}
    for family, owner, semantic_subject_key in candidates:
        matches = tuple(
            subject
            for subject in composition.policy_subjects
            if subject.semantic_subject_key == semantic_subject_key
        )
        if len(matches) != 1:
            raise AssertionError(
                "canonical owner identity must resolve exactly one policy subject"
            )
        policy_key = matches[0].policy_key
        if policy_key in resolved:
            raise AssertionError("canonical policy key has more than one owner")
        resolved[policy_key] = (family, owner)

    if set(resolved) != {item.policy_key for item in composition.policy_subjects}:
        raise AssertionError("canonical policy subjects do not all resolve to owners")
    return resolved


def _guard_semantic_replay(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical semantic replay is forbidden during projection")

    seams = (
        ("bugslyce.reports.operator_brief_assembly", "assemble_operator_brief"),
        (
            "bugslyce.reports.operator_brief_multi_family_assembly",
            "assemble_operator_brief_policy_subjects",
        ),
        ("bugslyce.reports.operator_brief_http", "compose_operator_brief_http"),
        (
            "bugslyce.reports.operator_brief_network",
            "compose_operator_brief_network",
        ),
        (
            "bugslyce.reports.operator_brief_web_context",
            "compose_operator_brief_web_context",
        ),
        (
            "bugslyce.reports.operator_brief_source_native",
            "compose_operator_brief_source_native",
        ),
        (
            "bugslyce.reports.operator_brief_thread_policy",
            "apply_operator_brief_thread_policy",
        ),
        (
            "bugslyce.reports.operator_brief_project",
            "build_project_operator_brief_composition",
        ),
    )
    for module_name, attribute in seams:
        monkeypatch.setattr(f"{module_name}.{attribute}", forbidden)
    return forbidden


def _guard_persistence_io(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical persistence I/O is forbidden during projection")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence.load_operator_brief_composition_artifact",
        forbidden,
    )
    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence.write_operator_brief_composition_artifact",
        forbidden,
    )
    return forbidden


def _assert_guarded_aliases(
    module: object,
    names: tuple[str, ...],
    forbidden: object,
) -> None:
    for name in names:
        if hasattr(module, name):
            assert getattr(module, name) is forbidden


def _project(api: SimpleNamespace, composition: OperatorBriefComposition) -> object:
    return api.build_operator_brief_html_presentation(composition)


# Existing-source controls.


def test_source_control_representative_composition_is_nontrivial_and_resolved() -> None:
    composition = _representative_composition()
    decisions = {
        item.policy_key: item for item in composition.thread_policy_result.decisions
    }
    owner_fact_ids = {
        item.fact_id
        for owner in (composition.http, composition.network, composition.web_context)
        for item in owner.facts
    }
    owner_conflict_ids = {item.conflict_id for item in composition.http.conflicts}

    assert len(composition.policy_subjects) > 1
    assert set(decisions) == {item.policy_key for item in composition.policy_subjects}
    assert {item.rank for item in decisions.values() if item.rank is not None} == {
        1,
        2,
        3,
        4,
        5,
    }
    assert any(item.disposition == "primary_thread" for item in decisions.values())
    assert any(item.disposition == "supporting_context" for item in decisions.values())
    assert composition.http.subjects
    assert composition.network.subjects
    assert composition.web_context.subjects
    assert composition.source_native.subjects
    assert any(item.conflicts for item in composition.policy_subjects)
    associated = next(
        item
        for item in composition.policy_subjects
        if item.associated_subject_reference is not None
    )
    assert associated.associated_subject_reference in {
        type(associated.associated_subject_reference)(
            subject_kind=subject.subject_kind,
            semantic_subject_key=subject.semantic_subject_key,
        )
        for subject in composition.policy_subjects
        if subject.semantic_subject_key is not None
    }
    assert all(
        {fact.fact_id for fact in subject.facts}.issubset(owner_fact_ids)
        for subject in composition.policy_subjects
        if subject.facts
    )
    assert all(
        {conflict.conflict_id for conflict in subject.conflicts}.issubset(
            owner_conflict_ids
        )
        for subject in composition.policy_subjects
        if subject.conflicts
    )
    assert all(
        value
        for subject in composition.policy_subjects
        for fact in subject.facts
        for value in (*fact.evidence_ids, *fact.artefact_references)
    )
    owners = _owner_by_policy_key(composition)
    assert set(owners) == {item.policy_key for item in composition.policy_subjects}
    assert {family for family, _owner in owners.values()} == {
        "http",
        "network",
        "web_context",
        "source_native",
    }


def test_source_control_ranked_order_is_not_storage_order() -> None:
    composition = _ranked_out_of_storage_order_composition()
    expected = _ranked_then_unranked_policy_keys(composition)

    assert composition.policy_subjects[0].policy_key == "AAA-STORAGE-FIRST"
    assert expected[0] != composition.policy_subjects[0].policy_key
    assert expected == tuple(
        decision.policy_key
        for decision in sorted(
            composition.thread_policy_result.decisions,
            key=lambda item: item.rank or 0,
        )
        if decision.rank is not None
    )


def test_source_control_empty_and_single_owner_compositions_are_typed() -> None:
    assert not _empty_composition().policy_subjects
    for owner in ("network", "web_context", "source_native"):
        composition = _single_owner_composition(owner)
        assert composition.policy_subjects
        assert len(composition.thread_policy_result.decisions) == len(
            composition.policy_subjects
        )


def test_source_control_policy_provenance_is_typed_and_exact() -> None:
    subject = _provenance_composition().policy_subjects[0]

    assert subject.source_lead_ids == ("R3C-PROVENANCE-LEAD",)
    assert subject.source_rankings == (
        OperatorBriefSourceRanking(
            source_lead_id="R3C-PROVENANCE-LEAD",
            rank=1,
            score=42,
            signal="retained_source_provenance",
        ),
    )


def test_source_control_legacy_html_model_still_builds_without_canonical(
    tmp_path: Path,
) -> None:
    root = _LOADING_HELPERS["_write_html_pack"](tmp_path / "legacy-html-pack")

    model = build_html_report_model(root)

    assert model.operator_brief_composition is None
    assert model.operator_summary.ranked_leads
    assert model.operator_brief.threads
    assert not (root / "operator_brief_composition.json").exists()


# Future projection contract. Individual failures should currently stop at _presentation_api().


def test_future_projection_public_api_is_small_pure_composition_boundary() -> None:
    api = _presentation_api()
    function = api.build_operator_brief_html_presentation

    assert tuple(signature(function).parameters) == (
        "composition",
        "application_service_model",
    )
    assert get_type_hints(function) == {
        "composition": OperatorBriefComposition,
        "application_service_model": ApplicationServiceModel | None,
        "return": api.OperatorBriefHtmlPresentation,
    }
    assert tuple(api.OperatorBriefHtmlPresentation.__dataclass_fields__) == (
        "investigation_subjects",
    )
    required_subject_fields = {
        "policy_key",
        "semantic_subject_key",
        "subject_kind",
        "materiality",
        "specificity",
        "evidence_basis",
        "independent",
        "associated_subject_reference",
        "replaced_by_subject_reference",
        "thread_id",
        "rank",
        "disposition",
        "signal",
        "reason_codes",
        "facts",
        "conflicts",
        "coverage_limitations",
        "source_family",
        "evidence_ids",
        "artefact_references",
        "source_rankings",
        "source_lead_ids",
        "source_native_detail",
    }
    assert required_subject_fields.issubset(
        api.OperatorBriefInvestigationSubject.__dataclass_fields__
    )
    assert tuple(api.OperatorBriefSourceNativePresentationDetail.__dataclass_fields__) == (
        "family",
        "endpoints",
        "origins",
        "source_references",
        "interpretation",
    )


def test_future_projection_is_deterministic_immutable_and_orders_by_persisted_rank() -> None:
    composition = _ranked_out_of_storage_order_composition()
    before = deepcopy(composition)
    api = _presentation_api()

    first = _project(api, composition)
    second = _project(api, composition)

    assert first == second
    assert composition == before
    assert tuple(item.policy_key for item in first.investigation_subjects) == (
        _ranked_then_unranked_policy_keys(composition)
    )


def test_future_projection_preserves_exact_normalised_owner_evidence_parity() -> None:
    composition = _representative_composition()
    owners = _owner_by_policy_key(composition)
    api = _presentation_api()

    presentation = _project(api, composition)
    for item in presentation.investigation_subjects:
        family, owner = owners[item.policy_key]
        assert item.source_family == family
        assert item.evidence_ids == owner.evidence_ids
        assert item.artefact_references == owner.artefact_references


def test_future_projection_preserves_policy_identity_relationship_and_decision_parity() -> None:
    api = _presentation_api()

    for composition in (_representative_composition(), _provenance_composition()):
        presentation = _project(api, composition)
        projected = {
            item.policy_key: item for item in presentation.investigation_subjects
        }
        decisions = {
            item.policy_key: item for item in composition.thread_policy_result.decisions
        }

        assert set(projected) == {item.policy_key for item in composition.policy_subjects}
        for subject in composition.policy_subjects:
            item = projected[subject.policy_key]
            decision = decisions[subject.policy_key]
            assert item.semantic_subject_key == subject.semantic_subject_key
            assert item.subject_kind == subject.subject_kind
            assert item.materiality == subject.materiality
            assert item.specificity == subject.specificity
            assert item.evidence_basis == subject.evidence_basis
            assert item.independent is subject.independent
            assert item.associated_subject_reference == subject.associated_subject_reference
            assert item.replaced_by_subject_reference == subject.replaced_by_subject_reference
            assert item.source_rankings == subject.source_rankings
            assert item.source_lead_ids == subject.source_lead_ids
            assert item.thread_id == decision.thread_id
            assert item.rank == decision.rank
            assert item.disposition == decision.disposition
            assert item.signal == decision.signal
            assert item.reason_codes == decision.reason_codes


def test_future_projection_preserves_fact_conflict_evidence_and_artefact_ownership() -> None:
    composition = _representative_composition()
    api = _presentation_api()

    presentation = _project(api, composition)
    projected = {item.policy_key: item for item in presentation.investigation_subjects}

    for subject in composition.policy_subjects:
        item = projected[subject.policy_key]
        assert item.facts == subject.facts
        assert item.conflicts == subject.conflicts
        assert tuple(
            value
            for fact in item.facts
            for value in (*fact.evidence_ids, *fact.artefact_references)
        ) == tuple(
            value
            for fact in subject.facts
            for value in (*fact.evidence_ids, *fact.artefact_references)
        )
        for conflict in item.conflicts:
            source = next(
                value
                for value in subject.conflicts
                if value.conflict_id == conflict.conflict_id
            )
            assert conflict == source
            assert conflict.observations == source.observations


def test_future_projection_retains_subject_scoped_coverage_limitations() -> None:
    composition = _limited_composition()
    api = _presentation_api()

    presentation = _project(api, composition)

    assert len(presentation.investigation_subjects) == 1
    assert presentation.investigation_subjects[0].coverage_limitations == (
        composition.policy_subjects[0].coverage_limitations
    )


def test_future_projection_keeps_artefact_references_exact_and_plain_text() -> None:
    composition = _plain_text_composition()
    api = _presentation_api()

    presentation = _project(api, composition)
    item = presentation.investigation_subjects[0]

    assert item.semantic_subject_key == 'source-native:plain<>&"\''
    assert item.artefact_references == composition.source_native.subjects[0].artefact_references
    assert item.artefact_references == ("native/source.js",)
    assert all(not value.startswith(("raw/", "file://", "/")) for value in item.artefact_references)


@pytest.mark.parametrize("owner", ("network", "web_context"))
def test_future_projection_supports_single_owner_compositions(owner: str) -> None:
    composition = _single_owner_composition(owner)
    api = _presentation_api()

    presentation = _project(api, composition)

    assert len(presentation.investigation_subjects) == len(composition.policy_subjects)
    assert {item.source_family for item in presentation.investigation_subjects} == {owner}


def test_future_projection_preserves_source_native_owner_detail() -> None:
    composition = _single_owner_composition("source_native")
    source = composition.source_native.subjects[0]
    api = _presentation_api()

    presentation = _project(api, composition)
    item = presentation.investigation_subjects[0]
    detail = item.source_native_detail

    assert item.source_family == "source_native"
    assert item.evidence_ids == source.evidence_ids
    assert item.artefact_references == source.artefact_references
    assert detail is not None
    assert detail.family == source.family
    assert detail.endpoints == source.endpoints
    assert detail.origins == source.origins
    assert detail.source_references == source.source_references
    assert detail.interpretation == source.interpretation


def test_future_projection_of_empty_composition_invents_no_subjects() -> None:
    api = _presentation_api()

    presentation = _project(api, _empty_composition())

    assert presentation.investigation_subjects == ()


def test_future_projection_has_no_legacy_action_or_semantic_replay_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _representative_composition()
    forbidden = _guard_semantic_replay(monkeypatch)
    api = _fresh_presentation_api(monkeypatch)
    _assert_guarded_aliases(
        api.module,
        (
            "assemble_operator_brief",
            "assemble_operator_brief_policy_subjects",
            "compose_operator_brief_http",
            "compose_operator_brief_network",
            "compose_operator_brief_web_context",
            "compose_operator_brief_source_native",
            "apply_operator_brief_thread_policy",
            "build_project_operator_brief_composition",
        ),
        forbidden,
    )

    presentation = _project(api, composition)

    assert presentation.investigation_subjects
    assert not {
        "OperatorSummaryLead",
        "Candidate",
        "ReviewLead",
        "HumanTriage",
    } & set(vars(api.module))


def test_future_projection_performs_no_canonical_persistence_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _representative_composition()
    forbidden = _guard_persistence_io(monkeypatch)
    api = _fresh_presentation_api(monkeypatch)
    _assert_guarded_aliases(
        api.module,
        (
            "load_operator_brief_composition_artifact",
            "write_operator_brief_composition_artifact",
        ),
        forbidden,
    )

    presentation = _project(api, composition)

    assert presentation.investigation_subjects


def test_future_html_model_declares_operator_brief_presentation_field() -> None:
    field = HtmlReportModel.__dataclass_fields__["operator_brief_presentation"]

    assert field.default is None


def test_future_html_model_builds_presentation_once_from_loaded_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, loaded_object, _canonical_bytes = _LOADING_HELPERS["_write_canonical_html_pack"](
        tmp_path / "canonical-html-pack"
    )
    api = _presentation_api()
    calls: list[OperatorBriefComposition] = []
    loader_calls: list[Path] = []
    expected_projection = object()

    def load(supplied_root: Path) -> OperatorBriefComposition:
        loader_calls.append(supplied_root.resolve())
        return loaded_object

    def build(supplied: OperatorBriefComposition) -> object:
        calls.append(supplied)
        return expected_projection

    monkeypatch.setattr(
        html_model,
        "load_operator_brief_composition_artifact",
        load,
    )

    monkeypatch.setattr(
        html_model,
        "build_operator_brief_html_presentation",
        build,
        raising=False,
    )

    model = build_html_report_model(root)

    assert loader_calls == [root.resolve()]
    assert model.operator_brief_composition is loaded_object
    assert calls == [loaded_object]
    assert calls[0] is loaded_object
    assert model.operator_brief_presentation is expected_projection


def test_future_html_model_legacy_absence_keeps_presentation_none(tmp_path: Path) -> None:
    root = _LOADING_HELPERS["_write_html_pack"](tmp_path / "legacy-html-pack")

    model = build_html_report_model(root)

    assert model.operator_brief_composition is None
    assert model.operator_brief_presentation is None
    assert model.operator_summary.ranked_leads


def test_future_html_model_canonical_and_legacy_coexistence_remains_canonical_only(
    tmp_path: Path,
) -> None:
    root, composition, _canonical_bytes = _LOADING_HELPERS["_write_canonical_html_pack"](
        tmp_path / "canonical-html-pack"
    )
    model = build_html_report_model(root)

    assert model.operator_brief_composition == composition
    assert tuple(item.policy_key for item in model.operator_brief_presentation.investigation_subjects) == (
        _ranked_then_unranked_policy_keys(composition)
    )
    assert {
        item.policy_key for item in model.operator_brief_presentation.investigation_subjects
    } == {item.policy_key for item in composition.policy_subjects}


def test_source_control_corrupt_canonical_still_fails_before_projection(
    tmp_path: Path,
) -> None:
    root = _LOADING_HELPERS["_write_html_pack"](tmp_path / "corrupt-html-pack")
    path = root / "operator_brief_composition.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError):
        build_html_report_model(root)


def test_source_control_projection_fixture_round_trips_before_guards(tmp_path: Path) -> None:
    composition = _representative_composition()

    write_operator_brief_composition_artifact(tmp_path, composition)
    loaded = load_operator_brief_composition_artifact(tmp_path)

    assert loaded == composition
