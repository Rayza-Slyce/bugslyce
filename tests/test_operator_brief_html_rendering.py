"""RED contract for canonical Operator Brief HTML rendering."""

from __future__ import annotations

from dataclasses import replace
from html import escape, unescape
from importlib import import_module
import inspect
from pathlib import Path
import re
import runpy
import sys

import pytest

from bugslyce.reports import html as html_module
from bugslyce.reports.html import render_html_report
from bugslyce.reports.html_model import HtmlReportModel, build_html_report_model
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_composition_persistence import (
    write_operator_brief_composition_artifact,
)


_ROOT = Path(__file__).resolve().parents[1]
_PERSISTENCE_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_composition_persistence.py")
)
_LOADING_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_composition_loading_integration.py")
)
_R3C_B_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_html_presentation.py")
)
_HTML_MODULE = "bugslyce.reports.html"


def _model_with_composition(
    tmp_path: Path,
    composition: OperatorBriefComposition | None = None,
) -> HtmlReportModel:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root, _initial, _canonical_bytes = _LOADING_HELPERS["_write_canonical_html_pack"](
        tmp_path / "canonical-html-pack"
    )
    if composition is not None:
        write_operator_brief_composition_artifact(root, composition)
    return build_html_report_model(root)


def _legacy_model(tmp_path: Path) -> HtmlReportModel:
    root = _LOADING_HELPERS["_write_html_pack"](tmp_path / "legacy-html-pack")
    return build_html_report_model(root)


def _source_native_only_composition(policy: object) -> OperatorBriefComposition:
    return _R3C_B_HELPERS["assemble_operator_brief"](
        http=_PERSISTENCE_HELPERS["_empty_http"](),
        network=_PERSISTENCE_HELPERS["_empty_network"](),
        web_context=_PERSISTENCE_HELPERS["_empty_web"](),
        source_native=_PERSISTENCE_HELPERS["_source_native"](policy),
    )


def _none_semantic_key_composition() -> OperatorBriefComposition:
    policy = replace(
        _PERSISTENCE_HELPERS["_policy"]("NONE-SEMANTIC-KEY"),
        semantic_subject_key=None,
    )
    return _source_native_only_composition(policy)


def _special_policy_key_composition() -> OperatorBriefComposition:
    policy = replace(
        _PERSISTENCE_HELPERS["_policy"]("SPECIAL-POLICY-KEY"),
        policy_key='POLICY<>&"\'',
    )
    return _source_native_only_composition(policy)


def _high_word_composition() -> OperatorBriefComposition:
    policy = replace(
        _PERSISTENCE_HELPERS["_policy"]("HIGH-WORD"),
        semantic_subject_key="source-native:high-evidence",
    )
    return _source_native_only_composition(policy)


def _priority_section(html: str) -> str:
    sections = re.findall(
        r'<section id="[^"]+" class="report-section"><h2>Investigation priorities</h2>(.*?)</section>',
        html,
        flags=re.DOTALL,
    )
    assert len(sections) == 1
    return sections[0]


def _subject_block(section: str, policy_key: str) -> str:
    escaped_key = re.escape(escape(policy_key, quote=True))
    matches = re.findall(
        rf'<article\b[^>]*data-policy-key="{escaped_key}"[^>]*>(.*?)</article>',
        section,
        flags=re.DOTALL,
    )
    assert len(matches) == 1
    return matches[0]


def _rendered_policy_keys(section: str) -> tuple[str, ...]:
    return tuple(
        unescape(value)
        for value in re.findall(r'<article\b[^>]*data-policy-key="([^"]+)"', section)
    )


def _visible_rank_pattern(rank: int) -> re.Pattern[str]:
    return re.compile(rf"\bRank\s*[:#]?\s*{rank}\b", re.IGNORECASE)


def _guard_semantic_replay(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical semantic replay is forbidden during rendering")

    for module_name, attribute in (
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
    ):
        monkeypatch.setattr(f"{module_name}.{attribute}", forbidden)
    return forbidden


def _fresh_html_module(monkeypatch: pytest.MonkeyPatch):
    """Import the renderer after dependency guards bind any direct aliases."""

    monkeypatch.delitem(sys.modules, _HTML_MODULE, raising=False)
    return import_module(_HTML_MODULE)


# Existing-source controls.


def test_source_control_canonical_model_has_ranked_supporting_facts_and_conflict(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    presentation = model.operator_brief_presentation

    assert presentation is not None
    assert presentation.investigation_subjects
    assert any(item.rank is not None for item in presentation.investigation_subjects)
    assert any(item.disposition == "supporting_context" for item in presentation.investigation_subjects)
    assert any(item.facts for item in presentation.investigation_subjects)
    assert any(item.conflicts for item in presentation.investigation_subjects)


def test_source_control_local_coverage_limitation_remains_subject_scoped(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _R3C_B_HELPERS["_limited_composition"](),
    )
    subject = model.operator_brief_presentation.investigation_subjects[0]

    assert subject.coverage_limitations[0].source_id == "DEEP-R3C-LOCAL"
    assert subject.coverage_limitations[0].summary == (
        "Zero forms in the retained body for DEEP-R3C-LOCAL."
    )


def test_source_control_legacy_model_has_no_canonical_presentation(tmp_path: Path) -> None:
    model = _legacy_model(tmp_path)

    assert model.operator_brief_composition is None
    assert model.operator_brief_presentation is None


def test_source_control_legacy_html_remains_renderable(tmp_path: Path) -> None:
    html = render_html_report(_legacy_model(tmp_path))

    assert '<h2>Operator summary</h2>' in html
    assert '<h2>Supporting triage evidence</h2>' in html
    assert '<h2>Manual review leads</h2>' in html


def test_source_control_renderer_escapes_text_and_is_offline(tmp_path: Path) -> None:
    html = render_html_report(_legacy_model(tmp_path))

    assert html_module._h('<>&"\'') == "&lt;&gt;&amp;&quot;&#x27;"
    lowered = html.lower()
    assert "<link" not in lowered
    assert "fetch(" not in lowered
    assert "xmlhttprequest" not in lowered
    assert 'href="http' not in lowered
    assert "file://" not in lowered
    assert "default-src 'none'" in lowered


def test_source_control_current_renderer_uses_native_details_and_no_markdown(
    tmp_path: Path,
) -> None:
    html = render_html_report(_legacy_model(tmp_path))

    assert "<details" in html
    assert "<summary" in html
    assert "markdown" not in inspect.getsource(html_module).lower()


def test_source_control_optional_semantic_key_and_special_policy_key_are_typed(
    tmp_path: Path,
) -> None:
    none_model = _model_with_composition(tmp_path / "none", _none_semantic_key_composition())
    special_model = _model_with_composition(
        tmp_path / "special",
        _special_policy_key_composition(),
    )

    assert none_model.operator_brief_presentation.investigation_subjects[0].semantic_subject_key is None
    assert special_model.operator_brief_presentation.investigation_subjects[0].policy_key == 'POLICY<>&"\''


def test_source_control_rank_pattern_requires_a_visible_rank_label() -> None:
    assert _visible_rank_pattern(1).search("Rank 1")
    assert _visible_rank_pattern(2).search("rank: 2")
    assert _visible_rank_pattern(1).search("EVID-1 HTTP 200") is None


def test_source_control_heading_guard_rejects_h4_through_h6() -> None:
    heading_jump = re.compile(r"<h[4-6]\b")

    assert heading_jump.search("<h4>detail</h4>")
    assert heading_jump.search("<h6>detail</h6>")
    assert heading_jump.search("<h3>subject</h3>") is None


# Future canonical renderer contract.


def test_future_canonical_report_has_one_early_investigation_priorities_section(
    tmp_path: Path,
) -> None:
    html = render_html_report(_model_with_composition(tmp_path))
    section = _priority_section(html)

    assert html.index("<h2>Overview</h2>") < html.index("<h2>Investigation priorities</h2>")
    assert html.index("<h2>Investigation priorities</h2>") < html.index(
        "<h2>Analysis coverage</h2>"
    )
    assert html.index("<h2>Investigation priorities</h2>") < html.index(
        "<h2>HTTP evidence</h2>"
    )
    assert section


def test_future_primary_items_preserve_presentation_tuple_order_and_identity(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _R3C_B_HELPERS["_ranked_out_of_storage_order_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)
    expected = tuple(
        item.policy_key for item in model.operator_brief_presentation.investigation_subjects
    )

    assert _rendered_policy_keys(section) == expected
    assert "AAA-STORAGE-FIRST" not in expected[:1]
    assert not re.search(r"<h[4-6]\b", section)
    for item in model.operator_brief_presentation.investigation_subjects:
        block = _subject_block(section, item.policy_key)
        if item.semantic_subject_key is not None:
            assert item.semantic_subject_key in block
        else:
            assert item.subject_kind.value in block


def test_future_primary_subjects_show_rank_and_disposition_without_severity(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path)
    html = render_html_report(model)
    section = _priority_section(html)

    for item in model.operator_brief_presentation.investigation_subjects:
        block = _subject_block(section, item.policy_key)
        if item.rank is not None:
            assert _visible_rank_pattern(item.rank).search(block)
            assert _visible_rank_pattern(item.rank).search(
                f"EVID-{item.rank} HTTP {item.rank}"
            ) is None
        else:
            assert not re.search(r"\bRank\s*[:#]?\s*\d+\b", block, re.IGNORECASE)
        assert item.disposition.replace("_", " ") in block.lower()


def test_future_canonical_evidence_words_are_not_censored_or_made_severity(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path, _high_word_composition())
    subject = model.operator_brief_presentation.investigation_subjects[0]
    html = render_html_report(model)
    block = _subject_block(_priority_section(html), subject.policy_key)

    assert "source-native:high-evidence" in block
    assert not re.search(
        r"\bSeverity\s*[:#]?\s*(?:Critical|High|Medium|Low)\b",
        block,
        re.IGNORECASE,
    )


def test_future_direct_facts_and_provenance_stay_with_their_subject(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)

    for item in model.operator_brief_presentation.investigation_subjects:
        block = _subject_block(section, item.policy_key)
        for fact in item.facts:
            assert fact.summary in block
            assert fact.fact_id in block
            for evidence_id in fact.evidence_ids:
                assert evidence_id in block
        for evidence_id in item.evidence_ids:
            assert evidence_id in block
        for source_lead_id in item.source_lead_ids:
            assert source_lead_id in block


def test_future_artefact_references_are_text_not_filesystem_links(tmp_path: Path) -> None:
    model = _model_with_composition(
        tmp_path,
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)
    subject = next(
        item
        for item in model.operator_brief_presentation.investigation_subjects
        if "native/source.js" in item.artefact_references
    )
    block = _subject_block(section, subject.policy_key)

    assert "native/source.js" in block
    assert 'href="native/source.js"' not in block
    assert 'href="raw/native/source.js"' not in block
    assert "file://" not in block
    assert "/native/source.js" not in block


def test_future_conflicts_and_local_coverage_are_structurally_subject_scoped(
    tmp_path: Path,
) -> None:
    conflict_model = _model_with_composition(
        tmp_path / "conflict",
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    conflict_section = _priority_section(render_html_report(conflict_model))
    conflict_subject = next(
        item
        for item in conflict_model.operator_brief_presentation.investigation_subjects
        if item.conflicts
    )
    conflict_block = _subject_block(conflict_section, conflict_subject.policy_key)
    conflict = conflict_subject.conflicts[0]

    assert "Conflicting observations" in conflict_block
    assert conflict.conflict_id in conflict_block
    for observation in conflict.observations:
        assert observation.observation_id in conflict_block
        assert str(observation.status_code) in conflict_block

    limited_model = _model_with_composition(
        tmp_path / "limited",
        _R3C_B_HELPERS["_limited_composition"](),
    )
    limited_section = _priority_section(render_html_report(limited_model))
    limited_subject = limited_model.operator_brief_presentation.investigation_subjects[0]
    limited_block = _subject_block(limited_section, limited_subject.policy_key)

    assert "Coverage limitation" in limited_block
    assert "DEEP-R3C-LOCAL" in limited_block
    assert "Zero forms in the retained body for DEEP-R3C-LOCAL." in limited_block
    assert "No forms exist" not in limited_section


def test_future_source_native_detail_and_interpretation_are_operator_visible(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)
    subject = next(
        item
        for item in model.operator_brief_presentation.investigation_subjects
        if item.source_native_detail is not None
    )
    detail = subject.source_native_detail
    assert detail is not None
    block = _subject_block(section, subject.policy_key)

    assert detail.family.value in block
    assert all(endpoint in block for endpoint in detail.endpoints)
    assert all(origin in block for origin in detail.origins)
    assert all(reference.source_id in block for reference in detail.source_references)
    assert detail.interpretation.artefact_type in block
    assert detail.interpretation.value_sha256 in block
    assert not re.search(r"\b(?:Suggested action|Next action|Why review)\b", block, re.I)


def test_future_canonical_text_is_escaped_once(tmp_path: Path) -> None:
    model = _model_with_composition(
        tmp_path,
        _R3C_B_HELPERS["_plain_text_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)

    assert "source-native:plain&lt;&gt;&amp;&quot;&#x27;" in section
    assert 'source-native:plain<>&"\'' not in section
    assert "&amp;lt;" not in section


def test_future_subject_without_semantic_key_uses_subject_kind_identity(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path, _none_semantic_key_composition())
    subject = model.operator_brief_presentation.investigation_subjects[0]
    html = render_html_report(model)
    block = _subject_block(_priority_section(html), subject.policy_key)

    assert subject.semantic_subject_key is None
    assert subject.subject_kind.value in block


def test_future_special_character_policy_key_is_decoded_without_double_escaping(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path, _special_policy_key_composition())
    html = render_html_report(model)
    section = _priority_section(html)

    assert _rendered_policy_keys(section) == ("POLICY<>&\"'",)


def test_future_canonical_nonempty_suppresses_legacy_primary_sections_and_actions(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path)
    legacy_action = model.operator_summary.ranked_leads[0].suggested_next_action
    html = render_html_report(model)
    section = _priority_section(html)

    assert '<h2>Operator summary</h2>' not in html, "canonical priorities replace legacy summary"
    assert '<h2>Supporting triage evidence</h2>' not in html, "canonical priorities replace triage prompts"
    assert '<h2>Manual review leads</h2>' not in html, "canonical priorities replace manual leads"
    assert legacy_action not in section


def test_future_empty_canonical_omits_priorities_without_legacy_resurrection(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(
        tmp_path,
        _R3C_B_HELPERS["_empty_composition"](),
    )
    html = render_html_report(model)

    assert "<h2>Investigation priorities</h2>" not in html
    if '<h2>Operator summary</h2>' in html:
        pytest.fail("empty canonical must not restore summary")
    if '<h2>Supporting triage evidence</h2>' in html:
        pytest.fail("empty canonical must not restore triage")
    if '<h2>Manual review leads</h2>' in html:
        pytest.fail("empty canonical must not restore manual leads")
    assert not re.search(
        r"\b(?:all clear|no vulnerabilities|nothing found|safe to proceed)\b",
        html,
        re.I,
    )


def test_source_control_legacy_only_project_retains_legacy_primary_sections(
    tmp_path: Path,
) -> None:
    html = render_html_report(_legacy_model(tmp_path))

    assert "<h2>Investigation priorities</h2>" not in html
    assert '<h2>Operator summary</h2>' in html
    assert '<h2>Supporting triage evidence</h2>' in html
    assert '<h2>Manual review leads</h2>' in html


def test_future_renderer_uses_projection_without_replay_or_composition_backtracking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _model_with_composition(tmp_path)
    _guard_semantic_replay(monkeypatch)

    def forbidden_policy_subjects(_self: OperatorBriefComposition) -> object:
        raise AssertionError("renderer must not traverse canonical composition")

    monkeypatch.setattr(
        OperatorBriefComposition,
        "policy_subjects",
        property(forbidden_policy_subjects),
    )
    module = _fresh_html_module(monkeypatch)
    html = module.render_html_report(model)

    assert "operator_brief_composition" not in inspect.getsource(module)
    assert _priority_section(html)


def test_future_renderer_does_not_reload_canonical_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    model = _model_with_composition(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("renderer must not load canonical persistence")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence.load_operator_brief_composition_artifact",
        forbidden,
    )
    module = _fresh_html_module(monkeypatch)
    html = module.render_html_report(model)

    assert _priority_section(html)


def test_future_canonical_rendering_is_deterministic_and_remains_offline(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path)

    first = render_html_report(model)
    second = render_html_report(model)
    section = _priority_section(first)

    assert first == second
    assert "<link" not in first.lower()
    assert "fetch(" not in first.lower()
    assert "xmlhttprequest" not in first.lower()
    assert "Suggested action" not in section
