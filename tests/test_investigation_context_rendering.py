"""Focused presentation tests for frozen C1 investigation context."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.reports.html import _html_investigation_context
from bugslyce.reports.investigation_context import (
    DERIVED,
    OBSERVED,
    RELATED,
    InvestigationContextAssembly,
    InvestigationContextBacklink,
    InvestigationContextItem,
    InvestigationContextView,
    ReportNavigationReference,
)
from bugslyce.reports.investigation_context_presentation import (
    build_investigation_context_presentation_index,
)
from bugslyce.reports.markdown import _markdown_investigation_context


def test_rich_context_has_substantive_html_markdown_parity_and_exact_provenance() -> None:
    assembly = _rich_assembly()
    index = build_investigation_context_presentation_index(assembly)
    context = assembly.primary_contexts[0]
    markdown_lines: list[str] = []

    _markdown_investigation_context(
        markdown_lines,
        context.context_items,
        index,
        frozenset(("EVID-ALPHA",)),
    )
    markdown = "\n".join(markdown_lines)
    html = _html_investigation_context(
        context.context_items,
        index,
        frozenset(("EVID-ALPHA",)),
        frozenset(("https://example.test/search?tenant=alpha",)),
    )

    for claim in (
        "Mapped exact-query route relationship",
        "tenant",
        "Exact represented form action",
        "Account workflow",
        "https://example.test/search?tenant=alpha",
        "SOURCE-ALPHA",
    ):
        assert claim in markdown
        assert claim in html
    assert "SOURCE-BETA" not in markdown
    assert "SOURCE-BETA" not in html
    assert "tenant=beta" not in markdown
    assert "tenant=beta" not in html
    assert "&lt;retained&gt;" in markdown
    assert "&lt;retained&gt;" in html
    assert '<script data-controlled="1">' not in markdown
    assert '<script data-controlled="1">' not in html
    route_anchor = index.route_reference_by_url[
        "https://example.test/search?tenant=alpha"
    ].anchor_token
    assert f'href="#{route_anchor}"' in html


def test_presentation_index_preserves_one_stable_target_and_exact_query_backlinks() -> None:
    assembly = _rich_assembly()
    reversed_assembly = InvestigationContextAssembly(
        primary_contexts=tuple(reversed(assembly.primary_contexts)),
        evidence_backlinks=tuple(reversed(assembly.evidence_backlinks)),
        route_backlinks=tuple(reversed(assembly.route_backlinks)),
    )

    forward = build_investigation_context_presentation_index(assembly)
    backward = build_investigation_context_presentation_index(reversed_assembly)

    assert dict(forward.reference_by_target) == dict(backward.reference_by_target)
    assert tuple(forward.reference_by_target) == (
        ("operator_summary_lead", "LEAD-ALPHA"),
        ("evidence", "EVID-ALPHA"),
        ("deep_parameter", "DEEP-PARAM-0001"),
        ("route", "https://example.test/search?tenant=alpha"),
    )
    assert set(forward.route_backlink_by_url) == {
        "https://example.test/search?tenant=alpha"
    }
    assert "https://example.test/search?tenant=beta" not in forward.route_backlink_by_url


def test_markdown_context_keeps_target_controlled_syntax_literal() -> None:
    assembly = _rich_assembly()
    index = build_investigation_context_presentation_index(assembly)
    context = assembly.primary_contexts[0]
    labels = (
        "[controlled](#ctx-evidence-evid-alpha)",
        "[controlled](javascript:alert(1))",
        "`code` **bold** [link](https://example.invalid/)",
    )

    for label in labels:
        lines: list[str] = []
        _markdown_investigation_context(
            lines,
            (replace(context.context_items[0], label=label),),
            index,
            frozenset(("EVID-ALPHA",)),
        )
        rendered = "\n".join(lines)

        assert label not in rendered
        assert "[controlled](#ctx-evidence-evid-alpha)" not in rendered
        assert "[controlled](javascript:alert(1))" not in rendered
        assert "[link](https://example.invalid/)" not in rendered
        assert "\\[controlled\\]\\(" in rendered or "\\`code\\`" in rendered
        assert "[`EVID-ALPHA`](#ctx-evidence-evid-alpha)" in rendered

        html = _html_investigation_context(
            (replace(context.context_items[0], label=label),),
            index,
            frozenset(("EVID-ALPHA",)),
        )
        assert 'href="javascript:' not in html
        assert 'href="#ctx-evidence-evid-alpha"' in html


def test_markdown_context_code_values_preserve_exact_target_text() -> None:
    assembly = _rich_assembly()
    index = build_investigation_context_presentation_index(assembly)
    context = assembly.primary_contexts[0]
    route = "/api/user_profile?mode=(fast)#details"
    source_id = "SOURCE_alpha"
    source_url = "https://example.test/static/user_profile.js?mode=(fast)#fragment"
    source_with_backtick = "SOURCE`literal"
    item = replace(
        context.context_items[0],
        route_url=route,
        source_ids=(source_id, source_with_backtick),
        source_urls=(source_url,),
    )
    lines: list[str] = []

    _markdown_investigation_context(
        lines,
        (item,),
        index,
        frozenset(("EVID-ALPHA",)),
    )
    rendered = "\n".join(lines)

    assert f"`{route}`" in rendered
    assert f"`{source_id}`" in rendered
    assert f"`{source_url}`" in rendered
    assert f"``{source_with_backtick}``" in rendered


def test_markdown_context_code_values_preserve_entities_and_edge_backticks() -> None:
    assembly = _rich_assembly()
    index = build_investigation_context_presentation_index(assembly)
    context = assembly.primary_contexts[0]
    route = "https://example.test/search?a=1&b=2"
    source_url = "https://example.test/static/app.js?a=1&b=2&mode=fast"
    values = ("`leading", "trailing`", "`both`", "SOURCE`literal")
    item = replace(
        context.context_items[0],
        route_url=route,
        source_ids=values,
        source_urls=(source_url, "<script>not-html</script>"),
    )
    lines: list[str] = []

    _markdown_investigation_context(
        lines,
        (item,),
        index,
        frozenset(("EVID-ALPHA",)),
    )
    rendered = "\n".join(lines)

    assert f"`{route}`" in rendered
    assert "&amp;" not in rendered
    assert f"`{source_url}`" in rendered
    assert "`` `leading ``" in rendered
    assert "`` trailing` ``" in rendered
    assert "`` `both` ``" in rendered
    assert "``SOURCE`literal``" in rendered
    assert "<script>not-html</script>" in rendered


def _rich_assembly() -> InvestigationContextAssembly:
    primary = ReportNavigationReference(
        "operator_summary_lead",
        "LEAD-ALPHA",
        "ctx-operator_summary_lead-lead-alpha",
    )
    evidence = ReportNavigationReference(
        "evidence",
        "EVID-ALPHA",
        "ctx-evidence-evid-alpha",
    )
    parameter = ReportNavigationReference(
        "deep_parameter",
        "DEEP-PARAM-0001",
        "ctx-deep_parameter-deep-param-0001",
    )
    route = "https://example.test/search?tenant=alpha"
    items = (
        InvestigationContextItem(
            OBSERVED,
            OBSERVED,
            "evidence",
            "EVID-ALPHA",
            'Exact <retained> evidence <script data-controlled="1">',
            "",
            ("EVID-ALPHA",),
            ("SOURCE-ALPHA",),
            (),
            (),
            (),
        ),
        InvestigationContextItem(
            "route_reasoning",
            DERIVED,
            "route_reasoning_context",
            "REASON-ALPHA",
            "Mapped exact-query route relationship",
            route,
            ("EVID-ALPHA",),
            ("SOURCE-ALPHA",),
            (),
            (),
            (route,),
        ),
        InvestigationContextItem(
            "route_parameter",
            RELATED,
            "deep_parameter",
            "DEEP-PARAM-0001",
            "tenant",
            route,
            ("EVID-ALPHA",),
            ("SOURCE-ALPHA",),
            ("https://example.test/static/app.js",),
            (),
            ("query",),
        ),
        InvestigationContextItem(
            "form_action",
            RELATED,
            "deep_form",
            "DEEP-FORM-0001",
            "Exact represented form action",
            route,
            ("EVID-ALPHA",),
            ("SOURCE-ALPHA",),
            ("https://example.test/account",),
            (),
            ("get",),
        ),
        InvestigationContextItem(
            "workflow",
            RELATED,
            "workflow_lead",
            "",
            "Account workflow",
            route,
            ("EVID-ALPHA",),
            (),
            (route,),
            (),
            ("account",),
        ),
    )
    context = InvestigationContextView(
        anchor_kind="operator_summary_lead",
        anchor_id="LEAD-ALPHA",
        anchor_label="Controlled lead",
        anchor_reference=primary,
        context_items=items,
        navigation_references=(primary, evidence, parameter),
    )
    return InvestigationContextAssembly(
        primary_contexts=(context,),
        evidence_backlinks=(
            InvestigationContextBacklink("EVID-ALPHA", (primary,)),
        ),
        route_backlinks=(InvestigationContextBacklink(route, (primary,)),),
    )
