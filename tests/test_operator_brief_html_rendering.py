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
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSubjectKind,
    OperatorBriefThread,
    OperatorBriefView,
    write_operator_brief_artifact,
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


def _human_blog_operator_brief() -> OperatorBriefView:
    """Small persisted operator thread set for primary-surface scale coverage."""

    directory_fact = OperatorBriefFact(
        fact_id="HTTP-FACT-DIRECTORY-LISTING",
        kind=OperatorBriefFactKind.HTTP_RESPONSE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="Directory-listing-style response",
        summary=(
            "GET http://blog.thm/uploads/ returned 200 with a "
            "directory-listing-style response."
        ),
        endpoints=("http://blog.thm/uploads/",),
        origins=("http://blog.thm/",),
        evidence_ids=("EVID-HTTP-DIRECTORY",),
        artefact_references=("deep/http/uploads.html",),
        http_method="GET",
        http_status_code=200,
    )
    content_fact = OperatorBriefFact(
        fact_id="HTTP-FACT-DEEP-CONTENT",
        kind=OperatorBriefFactKind.RETAINED_CONTENT,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="Successfully collected Deep content",
        summary=(
            "Successfully collected Deep content is available offline for "
            "review at http://blog.thm/wp-login.php."
        ),
        endpoints=("http://blog.thm/wp-login.php",),
        origins=("http://blog.thm/",),
        evidence_ids=("EVID-HTTP-DEEP-CONTENT",),
        artefact_references=("deep/http/wp-login.html",),
    )
    smb_fact = OperatorBriefFact(
        fact_id="SMB-FACT-BILLYSMB",
        kind=OperatorBriefFactKind.SMB_SHARE,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="SMB Disk share",
        summary=(
            "Anonymous SMB enumeration observed Disk share BillySMB on "
            "10.82.174.151:445."
        ),
        endpoints=("smb://10.82.174.151/BillySMB",),
        evidence_ids=("EVID-SMB-BILLYSMB",),
        artefact_references=("smb-shares-10.82.174.151.txt",),
        service="netbios-ssn",
        share_name="BillySMB",
        share_type="Disk",
    )
    return OperatorBriefView(
        threads=(
            OperatorBriefThread(
                thread_id="BLOG-THREAD-DIRECTORY",
                identity_key="blog:directory-listing",
                subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
                title="Directory-listing-style responses observed",
                rank=1,
                signal="direct retained HTTP evidence",
                source_lead_ids=(),
                endpoints=("http://blog.thm/uploads/",),
                origins=("http://blog.thm/",),
                evidence_ids=("EVID-HTTP-DIRECTORY",),
                why_review=(
                    "A directory-listing-style response may expose files and "
                    "routes needing offline review."
                ),
                next_review_step=(
                    "Review the retained directory response and enumerate its "
                    "listed paths offline."
                ),
                facts=(directory_fact,),
            ),
            OperatorBriefThread(
                thread_id="BLOG-THREAD-DEEP-CONTENT",
                identity_key="blog:deep-content",
                subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
                title="Successfully collected Deep content available offline",
                rank=2,
                signal="retained Deep content evidence",
                source_lead_ids=(),
                endpoints=("http://blog.thm/wp-login.php",),
                origins=("http://blog.thm/",),
                evidence_ids=("EVID-HTTP-DEEP-CONTENT",),
                why_review=(
                    "Retained Deep content can be reviewed without further "
                    "network collection."
                ),
                next_review_step=(
                    "Inspect the retained Deep content and related route "
                    "evidence offline."
                ),
                facts=(content_fact,),
            ),
            OperatorBriefThread(
                thread_id="BLOG-THREAD-SMB",
                identity_key="blog:smb-disk-share",
                subject_kind=OperatorBriefSubjectKind.SMB_SURFACE,
                title="SMB Disk share observed for review: BillySMB",
                rank=3,
                signal="anonymous SMB enumeration evidence",
                source_lead_ids=(),
                endpoints=("smb://10.82.174.151/BillySMB",),
                origins=(),
                evidence_ids=("EVID-SMB-BILLYSMB",),
                why_review=(
                    "The retained SMB share observation provides a concrete "
                    "storage surface for review."
                ),
                next_review_step=(
                    "Review the retained SMB enumeration output and share "
                    "context offline."
                ),
                facts=(smb_fact,),
            ),
        ),
        dispositions=(),
    )


def _model_with_human_brief_and_composition(
    tmp_path: Path,
    composition: OperatorBriefComposition | None = None,
) -> HtmlReportModel:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root, _initial, _canonical_bytes = _LOADING_HELPERS["_write_canonical_html_pack"](
        tmp_path / "canonical-human-brief-pack"
    )
    composition = composition or _PERSISTENCE_HELPERS["_representative_composition"]()
    write_operator_brief_composition_artifact(root, composition)
    write_operator_brief_artifact(root, _human_blog_operator_brief())
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


def _primary_card_blocks(section: str) -> tuple[str, ...]:
    return tuple(
        re.findall(
            r'<article\b[^>]*class="[^"]*\binvestigation-subject\b[^"]*"[^>]*>(.*?)</article>',
            section,
            flags=re.DOTALL,
        )
    )


def _primary_card_headings(section: str) -> tuple[str, ...]:
    return tuple(
        unescape(value)
        for value in re.findall(r"<h3>(.*?)</h3>", section, flags=re.DOTALL)
    )


def _primary_card_for_title(section: str, title: str) -> str:
    matches = tuple(
        block
        for block in _primary_card_blocks(section)
        if f"<h3>{escape(title)}</h3>" in block
    )
    assert len(matches) == 1
    return matches[0]


def _technical_value_is_secondary_if_in_priorities(section: str, value: str) -> None:
    """Allow technical evidence in priorities only through collapsed detail."""

    escaped_value = escape(value)
    if escaped_value not in section:
        return
    disclosures = re.findall(r"<details\b[^>]*>.*?</details>", section, flags=re.DOTALL)
    containing_disclosures = tuple(
        disclosure for disclosure in disclosures if escaped_value in disclosure
    )
    assert containing_disclosures, (
        f"technical value {value!r} must be secondary disclosure when it is "
        "rendered in Investigation priorities"
    )
    for disclosure in containing_disclosures:
        opening_tag = re.match(r"<details\b([^>]*)>", disclosure)
        assert opening_tag is not None
        assert not re.search(r"(?:^|\s)open(?:\s|=|$)", opening_tag.group(1), re.I), (
            f"technical value {value!r} must remain collapsed when it is "
            "rendered in Investigation priorities"
        )
    visible_primary_html = re.sub(
        r"<details\b[^>]*>.*?</details>",
        "",
        section,
        flags=re.DOTALL,
    )
    assert escaped_value not in visible_primary_html, (
        f"technical value {value!r} must not be duplicated as visible primary "
        "content in Investigation priorities"
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


def test_future_primary_items_follow_persisted_human_threads_not_policy_subject_scale(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path)
    model = replace(
        model,
        project_state=replace(
            model.project_state,
            warnings=["Retained collection warning remains visible to the operator."],
        ),
    )
    html = render_html_report(model)
    section = _priority_section(html)
    expected_titles = tuple(thread.title for thread in model.operator_brief.threads)
    policy_subjects = model.operator_brief_presentation.investigation_subjects
    headings = _primary_card_headings(section)

    assert len(policy_subjects) >= len(expected_titles) * 2
    assert len(_primary_card_blocks(section)) == len(expected_titles)
    assert headings == expected_titles
    assert "<h2>Analysis coverage</h2>" in html
    assert "<h2>Warnings and skipped collection</h2>" in html
    assert "Retained collection warning remains visible to the operator." in html
    assert not re.search(r"<h[4-6]\b", section)
    assert not any(
        value in heading
        for heading in headings
        for item in policy_subjects
        for value in (item.policy_key, item.semantic_subject_key)
        if value is not None
    )

    # Canonical subjects remain discoverable as supporting technical provenance.
    assert all(item.policy_key in html for item in policy_subjects)
    for item in policy_subjects:
        _technical_value_is_secondary_if_in_priorities(section, item.policy_key)
        if item.semantic_subject_key is not None:
            _technical_value_is_secondary_if_in_priorities(section, item.semantic_subject_key)


def test_future_primary_human_threads_show_rank_context_review_reason_and_safe_next_step(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path)
    html = render_html_report(model)
    section = _priority_section(html)

    for thread in model.operator_brief.threads:
        block = _primary_card_for_title(section, thread.title)
        assert _visible_rank_pattern(thread.rank).search(block)
        assert all(endpoint in block for endpoint in thread.endpoints)
        assert thread.why_review in block
        assert thread.next_review_step in block
        assert not re.search(
            r"\bSeverity\s*[:#]?\s*(?:Critical|High|Medium|Low)\b",
            block,
            re.IGNORECASE,
        )


def test_future_canonical_evidence_words_are_not_censored_or_made_severity(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path, _high_word_composition())
    html = render_html_report(model)
    section = _priority_section(html)

    assert "source-native:high-evidence" in html
    assert "source-native:high-evidence" not in _primary_card_headings(section)
    _technical_value_is_secondary_if_in_priorities(section, "source-native:high-evidence")
    assert _primary_card_headings(section) == tuple(
        thread.title for thread in model.operator_brief.threads
    )
    assert not re.search(
        r"\bSeverity\s*[:#]?\s*(?:Critical|High|Medium|Low)\b",
        section,
        re.IGNORECASE,
    )


def test_future_human_direct_facts_are_primary_and_machine_provenance_is_secondary(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path)
    html = render_html_report(model)
    section = _priority_section(html)

    for thread in model.operator_brief.threads:
        block = _primary_card_for_title(section, thread.title)
        for fact in thread.facts:
            assert fact.summary in block
            assert fact.fact_id in html
            assert fact.fact_id not in _primary_card_headings(section)
            _technical_value_is_secondary_if_in_priorities(section, fact.fact_id)
            for evidence_id in fact.evidence_ids:
                assert evidence_id in html
                _technical_value_is_secondary_if_in_priorities(section, evidence_id)
    assert "<strong>Provenance</strong>" in html
    assert all(
        item.policy_key in html
        for item in model.operator_brief_presentation.investigation_subjects
    )
    for item in model.operator_brief_presentation.investigation_subjects:
        _technical_value_is_secondary_if_in_priorities(section, item.policy_key)


def test_future_artefact_references_are_text_not_filesystem_links(tmp_path: Path) -> None:
    model = _model_with_composition(
        tmp_path,
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)
    assert "native/source.js" in html
    assert 'href="native/source.js"' not in html
    assert 'href="raw/native/source.js"' not in html
    assert "file://" not in html
    assert "/native/source.js" not in html
    _technical_value_is_secondary_if_in_priorities(section, "native/source.js")


def test_future_conflicts_and_local_coverage_remain_locally_scoped_technical_evidence(
    tmp_path: Path,
) -> None:
    conflict_model = _model_with_composition(
        tmp_path / "conflict",
        _PERSISTENCE_HELPERS["_representative_composition"](),
    )
    conflict_html = render_html_report(conflict_model)
    conflict_section = _priority_section(conflict_html)
    conflict_subject = next(
        item
        for item in conflict_model.operator_brief_presentation.investigation_subjects
        if item.conflicts
    )
    conflict = conflict_subject.conflicts[0]

    assert "Conflicting observations" in conflict_html
    assert conflict.conflict_id in conflict_html
    _technical_value_is_secondary_if_in_priorities(conflict_section, conflict.conflict_id)
    for observation in conflict.observations:
        assert observation.observation_id in conflict_html
        assert str(observation.status_code) in conflict_html
        _technical_value_is_secondary_if_in_priorities(
            conflict_section,
            observation.observation_id,
        )

    limited_model = _model_with_composition(
        tmp_path / "limited",
        _R3C_B_HELPERS["_limited_composition"](),
    )
    limited_html = render_html_report(limited_model)
    limited_section = _priority_section(limited_html)
    assert "Coverage limitation" in limited_html
    assert "DEEP-R3C-LOCAL" in limited_html
    assert "Zero forms in the retained body for DEEP-R3C-LOCAL." in limited_html
    assert "No forms exist" not in limited_html
    _technical_value_is_secondary_if_in_priorities(limited_section, "DEEP-R3C-LOCAL")


def test_future_source_native_detail_and_interpretation_remain_discoverable_as_technical_evidence(
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
    assert detail.family.value in html
    assert all(endpoint in html for endpoint in detail.endpoints)
    assert all(origin in html for origin in detail.origins)
    assert all(reference.source_id in html for reference in detail.source_references)
    assert detail.interpretation.artefact_type in html
    assert detail.interpretation.value_sha256 in html
    for value in (
        detail.family.value,
        *detail.endpoints,
        *detail.origins,
        *(reference.source_id for reference in detail.source_references),
        detail.interpretation.artefact_type,
        detail.interpretation.value_sha256,
    ):
        _technical_value_is_secondary_if_in_priorities(section, value)


def test_future_canonical_text_is_escaped_once(tmp_path: Path) -> None:
    model = _model_with_composition(
        tmp_path,
        _R3C_B_HELPERS["_plain_text_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)

    value = 'source-native:plain<>&"\''
    assert escape(value) in html
    assert value not in html
    assert "&amp;lt;" not in html
    _technical_value_is_secondary_if_in_priorities(section, value)


def test_future_primary_headings_do_not_fall_back_to_machine_subject_identity(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path)
    html = render_html_report(model)
    section = _priority_section(html)
    headings = _primary_card_headings(section)

    assert headings == tuple(thread.title for thread in model.operator_brief.threads)
    assert not {
        item.subject_kind.value for item in model.operator_brief_presentation.investigation_subjects
    } & set(headings)


def test_future_special_character_policy_key_is_decoded_without_double_escaping(
    tmp_path: Path,
) -> None:
    model = _model_with_composition(tmp_path, _special_policy_key_composition())
    html = render_html_report(model)
    section = _priority_section(html)

    value = 'POLICY<>&"\''
    assert escape(value) in html
    assert value not in html
    assert "&amp;lt;" not in html
    _technical_value_is_secondary_if_in_priorities(section, value)


def test_future_canonical_nonempty_suppresses_legacy_primary_sections_and_actions(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(tmp_path)
    legacy_action = model.operator_summary.ranked_leads[0].suggested_next_action
    html = render_html_report(model)
    section = _priority_section(html)

    assert '<h2>Operator summary</h2>' not in html, "canonical priorities replace legacy summary"
    assert '<h2>Supporting triage evidence</h2>' not in html, "canonical priorities replace triage prompts"
    assert '<h2>Manual review leads</h2>' not in html, "canonical priorities replace manual leads"
    assert legacy_action not in section
    assert _primary_card_headings(section) == tuple(
        thread.title for thread in model.operator_brief.threads
    )


def test_future_empty_canonical_uses_human_threads_without_legacy_resurrection(
    tmp_path: Path,
) -> None:
    model = _model_with_human_brief_and_composition(
        tmp_path,
        _R3C_B_HELPERS["_empty_composition"](),
    )
    html = render_html_report(model)
    section = _priority_section(html)

    assert _primary_card_headings(section) == tuple(
        thread.title for thread in model.operator_brief.threads
    )
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

    no_human_threads = replace(
        model,
        operator_brief=OperatorBriefView(threads=(), dispositions=()),
    )
    no_human_html = render_html_report(no_human_threads)
    assert "<h2>Investigation priorities</h2>" not in no_human_html
    assert '<h2>Operator summary</h2>' not in no_human_html
    assert '<h2>Supporting triage evidence</h2>' not in no_human_html
    assert '<h2>Manual review leads</h2>' not in no_human_html
    assert not re.search(
        r"\b(?:all clear|no vulnerabilities|nothing found|safe to proceed)\b",
        no_human_html,
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
