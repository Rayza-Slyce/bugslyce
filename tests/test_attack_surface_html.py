"""Focused human attack-surface presentation contracts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import runpy

from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpFingerprintSummaryCounts,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_redirect_auth_flow_review import (
    build_deep_redirect_auth_flow_review,
)
from bugslyce.recon.deep_response_similarity_review import (
    build_deep_response_similarity_review,
)
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionNote,
    AnalysisCoverageItem,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnit,
    AnalysisCoverageUnknownReason,
    AnalysisCoverageView,
)
from bugslyce.reports.html import render_html_report
from bugslyce.reports.operator_brief import OperatorBriefView
from bugslyce.reports.operator_summary import OperatorSummary


_ROOT = Path(__file__).resolve().parents[1]
_HTML_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_html_rendering.py")
)


def _fingerprint(
    fingerprint_id: str,
    url: str,
    status: int,
    content_type: str,
    *,
    title: str | None = None,
) -> DeepHttpResponseFingerprint:
    return DeepHttpResponseFingerprint(
        fingerprint_id=fingerprint_id,
        collection_section="source_route_collection",
        requested_url=url,
        final_url=url,
        method="GET",
        status_code=status,
        status_bucket=(
            "2xx_success"
            if 200 <= status <= 299
            else "4xx_client_error"
        ),
        title_observed_in_bounded_preview=title,
        content_type=content_type,
        server="example-server",
        redirect_location=None,
        set_cookie_present=False,
        set_cookie_count=0,
        cookie_names=(),
        body_sha256=f"sha256-{fingerprint_id}",
        body_bytes=4096,
        body_empty=False,
        interesting_headers=(),
        headers_not_observed=(),
        evidence_ids=(f"EVID-{fingerprint_id}",),
    )


def _summary(
    *fingerprints: DeepHttpResponseFingerprint,
) -> DeepHttpFingerprintSummary:
    statuses = tuple(item.status_code for item in fingerprints)
    return DeepHttpFingerprintSummary(
        fingerprints=tuple(fingerprints),
        repeated_body_groups=(),
        summary_counts=DeepHttpFingerprintSummaryCounts(
            total_collected_responses=len(fingerprints),
            metadata_responses=0,
            source_route_responses=len(fingerprints),
            responses_2xx=sum(200 <= value <= 299 for value in statuses),
            responses_3xx=sum(300 <= value <= 399 for value in statuses),
            responses_4xx=sum(400 <= value <= 499 for value in statuses),
            responses_5xx=sum(500 <= value <= 599 for value in statuses),
            responses_other_status=sum(
                not 200 <= value <= 599 for value in statuses
            ),
            responses_with_title_observed_in_bounded_preview=sum(
                item.title_observed_in_bounded_preview is not None
                for item in fingerprints
            ),
            responses_setting_cookies=0,
            exact_repeated_non_empty_body_groups=0,
        ),
        safety_notes=(),
    )


def _model_with_http(tmp_path: Path, summary: DeepHttpFingerprintSummary):
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)
    redirects = build_deep_redirect_auth_flow_review(summary)
    return replace(
        model,
        http_fingerprints=summary,
        redirect_review=redirects,
        similarity_review=build_deep_response_similarity_review(summary, redirects),
    )


def _coverage_item(
    source_id: str,
    count: int,
    *,
    capability: str = "deep_javascript_route_extraction",
    source_role: str = "deep_source_response",
    state: AnalysisCoverageState = AnalysisCoverageState.ANALYSED,
    outcome: AnalysisCoverageOutcome | None = AnalysisCoverageOutcome.FINDING_PRESENT,
    unknown_reason: AnalysisCoverageUnknownReason | None = None,
    execution_note: AnalysisCoverageExecutionNote | None = None,
) -> AnalysisCoverageItem:
    return AnalysisCoverageItem(
        unit=AnalysisCoverageUnit(capability, source_role, source_id),
        state=state,
        outcome=outcome,
        finding_count=count if state is AnalysisCoverageState.ANALYSED else None,
        unknown_reason=unknown_reason,
        execution_note=execution_note,
    )


def test_attack_surface_summary_counts_typed_responses_and_exposes_routes(
    tmp_path: Path,
) -> None:
    summary = _summary(
        _fingerprint("HTML", "https://app.example.test/account", 200, "text/html"),
        _fingerprint(
            "JS",
            "https://app.example.test/static/client.js",
            200,
            "application/javascript; charset=utf-8",
        ),
        _fingerprint("BLOCK-1", "https://app.example.test/private", 403, "text/html"),
        _fingerprint("BLOCK-2", "https://app.example.test/secret", 403, "text/html"),
        _fingerprint("MISSING", "https://app.example.test/missing", 404, "text/html"),
    )

    html = render_html_report(_model_with_http(tmp_path, summary))
    attack_surface = html.split('<section id="attack-surface"', 1)[1].split(
        "</section>", 1
    )[0]

    assert "<h2>Attack surface summary</h2>" in html
    assert "Retained HTTP responses</span><strong>5</strong>" in attack_surface
    assert "Successful responses</span><strong>2</strong>" in attack_surface
    assert "HTTP 403 responses</span><strong>2</strong>" in attack_surface
    assert "Not-found responses</span><strong>1</strong>" in attack_surface
    assert "Successful JavaScript resources</span><strong>1</strong>" in attack_surface
    assert "Successful non-JavaScript URLs</span><strong>1</strong>" in attack_surface
    assert "Successful non-JavaScript application routes" not in attack_surface
    assert "https://app.example.test/account" in attack_surface
    assert "https://app.example.test/static/client.js" not in attack_surface
    assert html.index("<h2>Attack surface summary</h2>") < html.index(
        "<h2>HTTP evidence</h2>"
    )
    assert '<option value="attack_surface">Attack surface</option>' in html
    assert 'data-category="attack_surface"' in html


def test_successful_non_javascript_url_metric_matches_distinct_rendered_urls(
    tmp_path: Path,
) -> None:
    summary = _summary(
        _fingerprint("HTML-A", "https://app.example.test/account", 200, "text/html"),
        _fingerprint("HTML-B", "https://app.example.test/account", 200, "text/html"),
        _fingerprint("XML", "https://app.example.test/sitemap.xml", 200, "text/xml"),
    )

    html = render_html_report(_model_with_http(tmp_path, summary))
    attack_surface = html.split('<section id="attack-surface"', 1)[1].split(
        "</section>", 1
    )[0]

    assert "Successful responses</span><strong>3</strong>" in attack_surface
    assert "Successful non-JavaScript URLs</span><strong>2</strong>" in attack_surface
    assert "Successful non-JavaScript URLs (2)" in attack_surface
    assert attack_surface.count("https://app.example.test/account") == 1
    assert "https://app.example.test/sitemap.xml" in attack_surface
    assert "HTML-A" in html
    assert "HTML-B" in html
    assert "EVID-HTML-A" in html
    assert "EVID-HTML-B" in html


def test_human_triage_is_worth_reviewing_context_not_a_ranked_thread(
    tmp_path: Path,
) -> None:
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)
    model = replace(
        model,
        operator_summary=OperatorSummary(review_first=[], low_signal=[], coverage=[]),
        operator_brief=OperatorBriefView(threads=(), dispositions=()),
    )
    item = replace(
        model.human_triage_brief.start_here[0],
        value=(
            "Access boundaries: https://app.example.test/login-old; "
            "other account routes: https://app.example.test/dashboard"
        ),
    )
    model = replace(
        model,
        human_triage_brief=replace(
            model.human_triage_brief,
            start_here=(item,),
        ),
    )

    html = render_html_report(model)
    attack_surface = html.split('<section id="attack-surface"', 1)[1].split(
        "</section>", 1
    )[0]

    assert "<h3>Worth reviewing</h3>" in attack_surface
    assert item.title in attack_surface
    assert item.value in attack_surface
    assert item.why_it_matters in attack_surface
    assert item.suggested_manual_action in attack_surface
    assert item.evidence_ids[0] in attack_surface
    assert "<h2>Investigation priorities</h2>" not in html
    assert model.operator_brief.threads == ()


def test_start_here_prompts_are_not_duplicated_in_supporting_triage(
    tmp_path: Path,
) -> None:
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)
    primary = replace(
        model.human_triage_brief.start_here[0],
        title="Primary prompt only",
        value="primary review context",
    )
    additional = replace(
        model.human_triage_brief.evidence_values[-1],
        title="Additional evidence only",
        value="additional retained context",
    )
    model = replace(
        model,
        operator_summary=OperatorSummary(review_first=[], low_signal=[], coverage=[]),
        operator_brief=OperatorBriefView(threads=(), dispositions=()),
        human_triage_brief=replace(
            model.human_triage_brief,
            start_here=(primary,),
            evidence_values=(primary, additional),
        ),
    )

    html = render_html_report(model)
    attack_surface = html.split('<section id="attack-surface"', 1)[1].split(
        "</section>", 1
    )[0]
    supporting = html.split('<section id="human-triage"', 1)[1].split(
        "</section>", 1
    )[0]

    assert primary.title in attack_surface
    assert primary.title not in supporting
    assert additional.title in supporting
    assert additional.value in supporting
    assert '<option value="human_triage">Human triage</option>' in html


def test_populated_priorities_precede_attack_surface_summary(tmp_path: Path) -> None:
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)

    html = render_html_report(model)

    assert model.operator_brief.threads
    assert html.index("<h2>Investigation priorities</h2>") < html.index(
        "<h2>Attack surface summary</h2>"
    )


def test_analysis_coverage_aggregates_matching_sources_and_retains_each_record(
    tmp_path: Path,
) -> None:
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)
    items = (
        _coverage_item("JS-SOURCE-A", 2),
        _coverage_item("JS-SOURCE-B", 5),
        _coverage_item("JS-SOURCE-C", 1),
    )
    model = replace(
        model,
        operator_report_view=replace(
            model.operator_report_view,
            analysis_coverage=AnalysisCoverageView(items),
        ),
    )

    html = render_html_report(model)
    coverage = html.split('<section id="analysis-coverage"', 1)[1].split(
        "</section>", 1
    )[0]

    assert "3 retained JavaScript sources were analysed" in coverage
    assert "8 source-attributed route findings" in coverage
    assert "unique routes" not in coverage
    assert "JavaScript route analysis" in coverage
    assert coverage.index("3 retained JavaScript sources were analysed") < coverage.index(
        "<details"
    )
    assert coverage.count("Exact per-source execution records") == 1
    for item in items:
        assert item.unit.source_id in coverage


def test_analysis_coverage_does_not_merge_different_epistemic_states(
    tmp_path: Path,
) -> None:
    model = _HTML_HELPERS["_model_with_human_brief_and_composition"](tmp_path)
    items = (
        _coverage_item("JS-SOURCE-A", 2),
        _coverage_item(
            "OTHER-SOURCE",
            0,
            capability="deep_parameter_inventory",
            source_role="retained_body",
            state=AnalysisCoverageState.UNKNOWN,
            outcome=None,
            unknown_reason=(
                AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF
            ),
        ),
    )
    model = replace(
        model,
        operator_report_view=replace(
            model.operator_report_view,
            analysis_coverage=AnalysisCoverageView(items),
        ),
    )

    html = render_html_report(model)
    coverage = html.split('<section id="analysis-coverage"', 1)[1].split(
        "</section>", 1
    )[0]

    assert coverage.count("Exact per-source execution records") == 2
    assert "Analysed · Finding present" in coverage
    assert "Unknown" in coverage
    assert "Exact execution proof unavailable" in coverage


def test_repeated_blocked_group_is_unverified_coverage_with_provenance(
    tmp_path: Path,
) -> None:
    summary = _summary(
        _fingerprint(
            "DEEP-HTTP-FP-BLOCK-A",
            "https://app.example.test/private-a",
            403,
            "text/html",
            title="Access denied",
        ),
        _fingerprint(
            "DEEP-HTTP-FP-BLOCK-B",
            "https://app.example.test/private-b",
            403,
            "text/html",
            title="Access denied",
        ),
    )

    html = render_html_report(_model_with_http(tmp_path, summary))
    attack_surface = html.split('<section id="attack-surface"', 1)[1].split(
        "</section>", 1
    )[0]

    assert "2 requests received HTTP 403 responses" in attack_surface
    assert "remain unverified" in attack_surface
    assert "do not establish resource presence or absence" in attack_surface
    assert "Access denied" in attack_surface
    assert "https://app.example.test/private-a" in attack_surface
    assert "https://app.example.test/private-b" in attack_surface
    assert "DEEP-HTTP-FP-BLOCK-A" in html
    assert "EVID-DEEP-HTTP-FP-BLOCK-A" in html
    assert "<h2>Technical investigation evidence</h2>" in html
