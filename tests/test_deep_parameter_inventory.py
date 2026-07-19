"""Tests for offline Deep parameter-name inventory."""

from __future__ import annotations

import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult,
    DeepHtmlRouteExtractionSummaryCounts,
    DeepHtmlRouteReference,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteCandidate,
    DeepJavaScriptRouteExtractionResult,
    DeepJavaScriptRouteExtractionSummaryCounts,
)
from bugslyce.recon.deep_parameter_inventory import (
    MAX_PARAMETER_NAME_CHARS,
    MAX_RENDERED_VALUES,
    MAX_RENDERED_VALUE_CHARS,
    _format_values,
    build_deep_parameter_inventory,
    render_deep_parameter_inventory_markdown,
)
import bugslyce.recon.deep_parameter_inventory as inventory_module
from bugslyce.recon.deep_parameter_inventory import _format_parameter_name
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)


def test_value_list_truncation_never_renders_negative_remaining_count() -> None:
    assert _format_values(()) == "`none`"
    assert "+-" not in _format_values(("GET",))
    exact_limit = tuple(f"value-{index}" for index in range(MAX_RENDERED_VALUES))
    assert "+-" not in _format_values(exact_limit)
    above_limit = _format_values((*exact_limit, "extra"))
    assert "... +1 more" in above_limit
    assert "+-" not in above_limit
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_inputs_produce_safe_empty_result_and_renderer_sections() -> None:
    result = build_deep_parameter_inventory(_source_result(), _shallow_result(), _html_result(), _js_result())
    rendered = render_deep_parameter_inventory_markdown(result)

    assert result.parameters == ()
    assert result.summary_counts.unique_parameters == 0
    for expected in (
        "## Deep Parameter Inventory",
        "### Summary",
        "### Parameters",
        "### Inventory Interpretation Notes",
        "### Safety Notes",
        "No network request was made.",
        "The Deep parameter-inventory stage did not retain parameter values.",
        "This stage produces static manual-review context only.",
    ):
        assert expected in rendered


def test_inputs_are_not_mutated_and_full_bodies_are_used_not_preview() -> None:
    source = _source_result(
        _source_item(
            body=b"<html>" + b"A" * 700 + b"<form><input name='lateSource' value='SECRET_VALUE'></form>",
            body_preview="<html>" + ("A" * 500),
        )
    )
    shallow = _shallow_result(
        _shallow_item(
            body=b"<html>" + b"B" * 700 + b"<form><input name='lateShallow' value='SECRET_VALUE2'></form>",
            body_preview="<html>" + ("B" * 500),
        )
    )
    before = (source, shallow)

    result = build_deep_parameter_inventory(source, shallow, _html_result(), _js_result())
    names = {param.name for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert (source, shallow) == before
    assert {"lateSource", "lateShallow"} <= names
    assert "SECRET_VALUE" not in public
    assert "SECRET_VALUE2" not in public


def test_html_source_selection_and_skip_counts_match_phase_92a_categories() -> None:
    result = build_deep_parameter_inventory(
        _source_result(
            _source_item(headers=(("Content-Type", "text/html"),), body=b"<html><form><input name='html'></form>"),
            _source_item(url="http://example.test/xhtml", headers=(("Content-Type", "application/xhtml+xml"),), body=b"<html><form><input name='xhtml'></form>"),
            _source_item(url="http://example.test/sniff", headers=(), body=b"<!doctype html><form><input name='sniff'></form>"),
            _source_item(url="http://example.test/octet", headers=(("Content-Type", "application/octet-stream"),), body=b"<html><form><input name='octet'></form>"),
            _source_item(url="http://example.test/sniff-skip", headers=(), body=b"plain"),
            _source_item(url="http://example.test/js", headers=(("Content-Type", "application/javascript"),), body=b"<html><form><input name='js'></form>"),
            _source_item(url="http://example.test/json", headers=(("Content-Type", "application/json"),), body=b"<html><form><input name='json'></form>"),
            _source_item(url="http://example.test/plain", headers=(("Content-Type", "text/plain"),), body=b"<html><form><input name='plain'></form>"),
            _source_item(url="http://example.test/empty", body=b""),
        ),
        _shallow_result(),
        _html_result(),
        _js_result(),
    )
    counts = result.summary_counts
    names = {param.name for param in result.parameters}

    assert counts.source_collection_responses_considered == 9
    assert counts.source_collection_html_responses_scanned == 4
    assert counts.empty_bodies_skipped == 1
    assert counts.sniffable_non_html_responses_skipped == 1
    assert counts.explicit_non_html_responses_skipped == 3
    assert {"html", "xhtml", "sniff", "octet"} <= names
    assert {"js", "json", "plain"} & names == set()


def test_form_controls_types_required_disabled_and_values_are_inventory_safe() -> None:
    html = b"""
    <html><form method="POST" enctype="multipart/form-data" target="SECRET_TARGET" action="/submit?act=SECRET_QUERY">
      <input name="username" required value="SECRET_VALUE">
      <input name="passwordName" type="PASSWORD" value="SECRET_PASSWORD">
      <input name="fileName" type="file" value="/SECRET/PATH">
      <input name="hiddenName" type="hidden" value="SECRET_HIDDEN">
      <input name="disabledName" disabled value="SECRET_DISABLED">
      <input name="unknownName" type="SECRET_TYPE">
      <select name="selectName"><option value="SECRET_OPTION">A</option></select>
      <textarea name="textareaName">SECRET_TEXTAREA</textarea>
      <button name="buttonName">SECRET_BUTTON_TEXT</button>
      <button name="otherButtonName" type="SECRET_BUTTON_TYPE"></button>
      <input value="unnamed">
    </form></html>
    """

    result = build_deep_parameter_inventory(_source_result(_source_item(body=html)), _shallow_result(), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert by_name["username"].required_occurrences == 1
    assert by_name["passwordName"].password_control_occurrences == 1
    assert by_name["fileName"].file_control_occurrences == 1
    assert by_name["hiddenName"].hidden_control_occurrences == 1
    assert by_name["disabledName"].disabled_occurrences == 1
    assert "other" in by_name["unknownName"].control_types
    assert "select" in by_name["selectName"].control_types
    assert "textarea" in by_name["textareaName"].control_types
    assert "submit" in by_name["buttonName"].control_types
    assert "other_button" in by_name["otherButtonName"].control_types
    assert result.summary_counts.unnamed_form_controls_ignored == 1
    assert result.summary_counts.form_action_query_name_observations == 1
    assert "act" in by_name
    for secret in (
        "SECRET_TARGET",
        "SECRET_QUERY",
        "SECRET_VALUE",
        "SECRET_PASSWORD",
        "/SECRET/PATH",
        "SECRET_HIDDEN",
        "SECRET_DISABLED",
        "SECRET_TYPE",
        "SECRET_OPTION",
        "SECRET_TEXTAREA",
        "SECRET_BUTTON_TEXT",
        "SECRET_BUTTON_TYPE",
    ):
        assert secret not in public


def test_duplicate_attributes_first_occurrence_and_ignored_regions_are_contained() -> None:
    html = b"""
    <html>
      <form action="/first" action="/SECRET_ACTION">
        <input name="firstName" name="SECRET_NAME" type="text" type="SECRET_TYPE" required required="SECRET_REQUIRED">
        <script><input name="SCRIPT_SECRET"></script>
        <style><input name="STYLE_SECRET"></style>
        <template></form><input name="TEMPLATE_SECRET"><template><input name="NESTED_SECRET"></template></template>
        <input name="afterTemplate">
      </form>
      <input name="OUTSIDE_SECRET">
    </html>
    """

    result = build_deep_parameter_inventory(_source_result(_source_item(body=html)), _shallow_result(), _html_result(), _js_result())
    names = {param.name for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert {"firstName", "afterTemplate"} <= names
    assert "SECRET_NAME" not in names
    assert result.summary_counts.controls_outside_forms_ignored == 1
    for secret in ("SECRET_ACTION", "SECRET_TYPE", "SECRET_REQUIRED", "SCRIPT_SECRET", "STYLE_SECRET", "TEMPLATE_SECRET", "NESTED_SECRET", "OUTSIDE_SECRET"):
        assert secret not in public


def test_actions_bases_queries_fragments_credentials_and_malformed_values_are_safe() -> None:
    html = b"""
    <html>
      <base href="javascript:void(0)">
      <base href="http://[invalid">
      <base href="https://cdn.example.test/base/">
      <form action="?view=SECRET_VIEW"><input name="a"></form>
      <form action="#SECRET_FRAGMENT"><input name="b"></form>
      <form action="https://user:pass@example.test/path?token=SECRET_TOKEN#SECRET_FRAG"><input name="c"></form>
      <form action="javascript:alert('SECRET_ACTION')"><input name="d"></form>
      <form action="http://[bad-secret"><input name="e"></form>
      <form><input name="f"></form>
      <form action=""><input name="g"></form>
    </html>
    """

    result = build_deep_parameter_inventory(_source_result(_source_item(body=html)), _shallow_result(), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert "view" in by_name
    assert by_name["a"].action_resolution_contexts == ("html_base_url",)
    assert by_name["b"].action_resolution_contexts == ("html_base_url",)
    assert by_name["c"].action_resolution_contexts == ("absolute_url",)
    assert by_name["d"].action_resolution_contexts == ("unsupported_scheme",)
    assert by_name["e"].action_resolution_contexts == ("malformed_action",)
    assert by_name["f"].action_resolution_contexts == ("document_url_default",)
    assert by_name["g"].action_resolution_contexts == ("document_url_default",)
    for secret in ("SECRET_VIEW", "SECRET_FRAGMENT", "user:pass", "SECRET_TOKEN", "SECRET_FRAG", "SECRET_ACTION", "bad-secret"):
        assert secret not in public


def test_routes_javascript_original_and_shallow_query_metadata_are_inventoried() -> None:
    source = _source_item(
        url="http://example.test/source?src=SECRET&repeat=1&repeat=2#frag",
        final_url="http://example.test/final?fin=SECRET#frag",
        body=b"<html></html>",
    )
    shallow = _shallow_item(
        final_url="http://example.test/followed?final=SECRET#frag",
        query_names=("observed",),
    )
    html_route = _html_route(query_names=("routeParam",), occurrence_count=3)
    js_candidate = _js_candidate(query_names=("jsParam",), occurrence_count=2)

    result = build_deep_parameter_inventory(
        _source_result(source),
        _shallow_result(shallow),
        _html_result(html_route),
        _js_result(js_candidate),
    )
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert by_name["src"].contexts == ("source_requested_url_query",)
    assert by_name["repeat"].occurrence_count == 1
    assert by_name["fin"].contexts == ("source_final_url_query",)
    assert by_name["observed"].contexts == ("shallow_observed_query",)
    assert by_name["final"].contexts == ("shallow_final_url_query",)
    assert by_name["routeParam"].occurrence_count == 3
    assert by_name["routeParam"].route_origin_relationships == ("cross_origin",)
    assert by_name["jsParam"].occurrence_count == 2
    assert by_name["jsParam"].javascript_resolution_contexts == ("execution_context_unknown",)
    for secret in ("SECRET", "#frag"):
        assert secret not in public


def test_raw_query_names_decode_once_and_repeated_names_count_once() -> None:
    source = _source_item(
        url="http://example.test/source?a%2Bb=1&first+last=1&a%252Bb=1&x%2526y=1&repeat=1&repeat=2",
        final_url="http://example.test/final",
        body=b"<html></html>",
    )

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}

    assert {"a+b", "first last", "a%2Bb", "x%26y", "repeat"} <= set(by_name)
    assert by_name["repeat"].occurrence_count == 1
    assert result.summary_counts.source_requested_url_observations == 5


def test_sanitised_metadata_names_decode_once_and_literal_plus_remains_plus() -> None:
    html_route = _html_route(query_names=("a%2Bb", "first%20last", "x%2526y", "literal+plus"))
    js_candidate = _js_candidate(query_names=("a%2Bb", "first%20last", "x%2526y", "literal+plus"))
    shallow = _shallow_item(query_names=("a%2Bb", "first%20last", "x%2526y", "literal+plus"))

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(shallow), _html_result(html_route), _js_result(js_candidate))
    names = {param.name for param in result.parameters}

    assert {"a+b", "first last", "x%26y", "literal+plus"} <= names
    assert "literal plus" not in names


def test_overlong_and_empty_query_names_are_skipped_across_contexts() -> None:
    overlong = "z" * (MAX_PARAMETER_NAME_CHARS + 1)
    source = _source_item(
        url=f"http://example.test/source?=empty&{overlong}=1&{overlong}=2",
        final_url=f"http://example.test/final?{overlong}=1",
        body=f"<html><form action='/submit?{overlong}=1&=empty'><input name='ok'></form></html>".encode(),
    )
    shallow = _shallow_item(final_url=f"http://example.test/follow?{overlong}=1", query_names=(overlong,))
    html_route = _html_route(query_names=(overlong,))
    js_candidate = _js_candidate(query_names=(overlong,))

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(shallow), _html_result(html_route), _js_result(js_candidate))
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert result.summary_counts.overlong_names_skipped >= 6
    assert result.summary_counts.empty_names_skipped >= 2
    assert overlong not in public


def test_invalid_shallow_requested_url_fails_closed_but_valid_final_url_can_anchor_html() -> None:
    body = b"<html><form action='relative?formName=SECRET'><input name='controlName'></form></html>"
    cases = (
        _shallow_item(url="http://example.test/request?bad=SECRET", final_url="http://example.test/final/", body=body, query_names=("observed",)),
        _shallow_item(request_id="DEEP-SHALLOW-REQ-0002", url="http://example.test/request#frag", final_url="http://example.test/final/", body=body, query_names=("observed2",)),
        _shallow_item(request_id="DEEP-SHALLOW-REQ-0003", url="http://user:pass@example.test/request", final_url="http://example.test/final/", body=body, query_names=("observed3",)),
        _shallow_item(request_id="DEEP-SHALLOW-REQ-0004", url="HTTP://EXAMPLE.TEST/request", final_url="http://example.test/final/", body=body, query_names=("observed4",)),
    )

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(*cases), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert result.summary_counts.source_requested_url_observations == 0
    assert sum(1 for item in result.skipped if item.reason == "invalid_source_url") == 4
    assert by_name["controlName"].safe_source_urls == ("http://example.test/final/",)
    assert {"observed", "observed2", "observed3", "observed4"} <= set(by_name)
    for secret in ("bad=SECRET", "#frag", "user:pass", "HTTP://EXAMPLE"):
        assert secret not in public


def test_invalid_shallow_requested_and_final_urls_do_not_enter_public_provenance() -> None:
    shallow = _shallow_item(
        url="http://user:pass@example.test/request?bad=SECRET",
        final_url="http://[bad-final",
        body=b"<html><form action='relative'><input name='structural'></form></html>",
        query_names=("observed",),
    )

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(shallow), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert "structural" in by_name
    assert by_name["structural"].safe_source_urls == ()
    assert by_name["structural"].safe_form_action_urls == ()
    assert by_name["observed"].safe_source_urls == ()
    for secret in ("user:pass", "bad=SECRET", "bad-final"):
        assert secret not in public


def test_valid_shallow_requested_url_falls_back_when_final_url_invalid() -> None:
    shallow = _shallow_item(
        url="http://example.test/base/page",
        final_url="http://[bad-final",
        body=b"<html><form action='relative?rel=SECRET'><input name='controlName'></form><form><input name='defaultName'></form></html>",
        query_names=("observed",),
    )

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(shallow), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert by_name["controlName"].safe_source_urls == ("http://example.test/base/page",)
    assert by_name["controlName"].safe_form_action_urls == ("http://example.test/base/relative?rel",)
    assert by_name["defaultName"].safe_form_action_urls == ("http://example.test/base/page",)
    assert by_name["observed"].safe_source_urls == ("http://example.test/base/page",)
    assert "rel=SECRET" not in public
    assert "bad-final" not in public


def test_invalid_shallow_requested_url_cannot_be_document_fallback() -> None:
    cases = (
        _shallow_item(url="http://example.test/base/page?bad=SECRET", final_url="http://[bad-final", body=b"<html><form action='relative'><input name='queryBad'></form></html>"),
        _shallow_item(request_id="DEEP-SHALLOW-REQ-0002", url="http://user:pass@example.test/base/page", final_url="http://[bad-final", body=b"<html><form action='relative'><input name='credentialBad'></form></html>"),
    )

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(*cases), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert by_name["queryBad"].safe_source_urls == ()
    assert by_name["queryBad"].safe_form_action_urls == ()
    assert by_name["credentialBad"].safe_source_urls == ()
    assert by_name["credentialBad"].safe_form_action_urls == ()
    for secret in ("bad=SECRET", "user:pass", "bad-final"):
        assert secret not in public


def test_url_observation_provenance_uses_requested_and_final_urls_exactly() -> None:
    source = _source_item(
        url="http://example.test/requested?req=1",
        final_url="http://example.test/final?fin=1",
        body=b"<html></html>",
    )
    shallow = _shallow_item(final_url="http://example.test/shallow-final?sfin=1", query_names=("observed",))

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(shallow), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}

    assert by_name["req"].safe_source_urls == ("http://example.test/requested?req",)
    assert by_name["fin"].safe_source_urls == ("http://example.test/final?fin",)
    assert by_name["sfin"].safe_source_urls == ("http://example.test/shallow-final?sfin",)
    assert by_name["observed"].safe_source_urls == ("http://example.test/follow",)


def test_resolved_form_action_query_names_include_fragment_inherited_queries() -> None:
    overlong = "q" * (MAX_PARAMETER_NAME_CHARS + 1)
    source = _source_item(
        url="https://example.test/page?mode=SECRET_VALUE&repeat=1&repeat=2",
        final_url="https://example.test/page?mode=SECRET_VALUE&repeat=1&repeat=2",
        body=f"""
        <html>
          <form action="#SECRET_FRAGMENT"><input name="fragDoc"></form>
          <base href="https://cdn.example.test/base/?baseMode=SECRET_BASE&{overlong}=1">
          <form action="#SECRET_BASE_FRAGMENT"><input name="fragBase"></form>
          <form action="?queryOnly=SECRET&queryOnly=AGAIN"><input name="queryOnlyControl"></form>
          <form><input name="missingAction"></form>
        </html>
        """.encode(),
    )

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert by_name["mode"].contexts == ("form_action_query", "source_requested_url_query", "source_final_url_query")
    assert by_name["repeat"].occurrence_count == 3
    assert by_name["baseMode"].contexts == ("form_action_query",)
    assert by_name["queryOnly"].occurrence_count == 1
    assert any(item.reason == "overlong_parameter_name" and item.context == "form_action_query" for item in result.skipped)
    for secret in ("SECRET_VALUE", "SECRET_FRAGMENT", "SECRET_BASE", "SECRET_BASE_FRAGMENT", "queryOnly=SECRET", overlong):
        assert secret not in public


def test_missing_action_still_uses_document_query_metadata() -> None:
    source = _source_item(
        url="http://example.test/page?docName=SECRET",
        final_url="http://example.test/page?docName=SECRET",
        body=b"<html><form><input name='control'></form><form action=''><input name='empty'></form></html>",
    )

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(), _html_result(), _js_result())
    by_name = {param.name: param for param in result.parameters}

    assert by_name["docName"].occurrence_count == 4
    assert "form_action_query" in by_name["docName"].contexts


def test_route_and_javascript_provenance_fields_are_distinct_from_form_actions() -> None:
    html_route = _html_route(query_names=("routeName",), occurrence_count=1)
    unknown_origin = DeepHtmlRouteReference(
        route_id="HTML-UNKNOWN",
        safe_resolved_url="http://example.test/unknown?unknownName",
        path="/unknown",
        query_parameter_names=("unknownName",),
        origin_relationship="same-site",
        reference_forms=("root_relative",),
        tag_attribute_sources=("a[href]",),
        source_response_ids=("SRC-X",),
        source_request_urls=("http://example.test/source",),
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("content_type",),
        occurrence_count=1,
        evidence_ids=("EVID-X",),
        interpretation="test",
    )
    js_resolved = _js_candidate(candidate_id="JS-RESOLVED", query_names=("jsResolved",))
    js_resolved = DeepJavaScriptRouteCandidate(
        **{**js_resolved.__dict__, "safe_resolved_url": "http://example.test/api?jsResolved", "safe_candidate": "/api?jsResolved"}
    )
    js_unresolved = _js_candidate(candidate_id="JS-UNRESOLVED", query_names=("jsUnresolved",))

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(), _html_result(html_route, unknown_origin), _js_result(js_resolved, js_unresolved))
    by_name = {param.name: param for param in result.parameters}

    assert by_name["routeName"].safe_route_urls == ("http://example.test/route?routeParam",)
    assert by_name["routeName"].safe_form_action_urls == ()
    assert by_name["unknownName"].route_origin_relationships == ("other",)
    assert by_name["jsResolved"].safe_route_urls == ("http://example.test/api?jsResolved",)
    assert by_name["jsResolved"].javascript_candidate_references == ("/api?jsResolved",)
    assert by_name["jsResolved"].safe_form_action_urls == ()
    assert by_name["jsUnresolved"].safe_route_urls == ()
    assert by_name["jsUnresolved"].javascript_candidate_references == ("/api?jsParam",)


def test_ascii_trimming_unicode_controls_and_exact_name_rendering() -> None:
    exact_bound = "b" * MAX_PARAMETER_NAME_CHARS
    overlong = "c" * (MAX_PARAMETER_NAME_CHARS + 1)
    html = (
        "<html><form>"
        "<input name>"
        "<input name=' \t\r\n '>"
        "<input name='&nbsp;'>"
        "<input name='first last'>"
        "<input name='first  last'>"
        "<input name='first   last'>"
        "<input name='line\nbreak'>"
        "<input name='carriage\rreturn'>"
        "<input name='tab\tname'>"
        "<input name='esc\x1bname'>"
        "<input name='c1\u0085name'>"
        "<input name='bidi\u202ename'>"
        "<input name='cafe\u0301'>"
        "<input name='items[]'>"
        "<input name='tick`name'>"
        "<input name='ticks``name'>"
        f"<input name='{exact_bound}'>"
        f"<input name='{overlong}'>"
        "</form></html>"
    ).encode()

    result = build_deep_parameter_inventory(_source_result(_source_item(body=html)), _shallow_result(), _html_result(), _js_result())
    names = {param.name for param in result.parameters}
    rendered = render_deep_parameter_inventory_markdown(result)
    public = repr(result) + rendered

    assert "\xa0" in names
    assert {"first last", "first  last", "first   last"} <= names
    assert {"line\\x0abreak", "carriage\\x0dreturn", "tab\\x09name", "esc\\x1bname", "c1\\x85name", "bidi\\u202ename", "café", "items[]"} <= names
    assert "####" in rendered
    assert "``tick`name``" in rendered
    assert "```ticks``name```" in rendered
    assert "first  last" in rendered
    assert "first   last" in rendered
    assert result.summary_counts.empty_names_skipped >= 2
    assert result.summary_counts.overlong_names_skipped >= 1
    assert overlong not in public


def test_parameter_name_markdown_code_span_fences_are_exact() -> None:
    cases = {
        "plain": "`plain`",
        "tick`name": "``tick`name``",
        "ticks``name": "```ticks``name```",
        "a`b``c```d": "````a`b``c```d````",
        "`leading": "`` `leading ``",
        "trailing`": "`` trailing` ``",
        "`both`": "`` `both` ``",
        "`": "`` ` ``",
        "```": "```` ``` ````",
        "first last": "`first last`",
        "first  last": "`first  last`",
        "first   last": "`first   last`",
    }

    for name, expected in cases.items():
        assert _format_parameter_name(name) == expected

    long_name = "n" * (MAX_RENDERED_VALUE_CHARS + 20)
    assert _format_parameter_name(long_name).startswith("`")
    assert _format_parameter_name(long_name).endswith("`")


def test_shallow_query_bearing_requested_url_fails_closed() -> None:
    shallow = _shallow_item(
        url="http://example.test/request?bad=SECRET",
        final_url="http://example.test/request",
        query_names=("observed",),
    )

    result = build_deep_parameter_inventory(_source_result(), _shallow_result(shallow), _html_result(), _js_result())

    assert any(item.reason == "invalid_source_url" for item in result.skipped)
    assert {param.name for param in result.parameters} == {"observed"}


def test_case_unicode_bracket_control_chars_and_overlong_names() -> None:
    exact_bound = "x" * MAX_PARAMETER_NAME_CHARS
    overlong = "y" * (MAX_PARAMETER_NAME_CHARS + 1)
    html = f"""
    <html><form>
      <input name="id">
      <input name="ID">
      <input name="items[]">
      <input name="cafe\u0301">
      <input name="line&#10;break">
      <input name="">
      <input name="   ">
      <input name="{exact_bound}">
      <input name="{overlong}">
    </form></html>
    """.encode()

    result = build_deep_parameter_inventory(_source_result(_source_item(body=html)), _shallow_result(), _html_result(), _js_result())
    names = {param.name for param in result.parameters}
    public = repr(result) + render_deep_parameter_inventory_markdown(result)

    assert {"id", "ID", "items[]", "café", "line\\x0abreak", exact_bound} <= names
    assert "Id" not in names
    assert result.summary_counts.empty_names_skipped == 2
    assert result.summary_counts.overlong_names_skipped == 1
    assert overlong not in public


def test_same_name_aggregates_across_all_contexts_and_prioritises_multi_context() -> None:
    source = _source_item(
        url="http://example.test/source?shared=1",
        final_url="http://example.test/final?shared=2",
        body=b"<html><form action='/submit?shared=3'><input type='password' name='shared'></form></html>",
        evidence=("EVID-B",),
    )
    shallow = _shallow_item(final_url="http://example.test/follow?shared=4", query_names=("shared",), evidence=("EVID-A",))
    html_route = _html_route(query_names=("shared",), occurrence_count=2)
    js_candidate = _js_candidate(query_names=("shared",), occurrence_count=2)

    result = build_deep_parameter_inventory(_source_result(source), _shallow_result(shallow), _html_result(html_route), _js_result(js_candidate))
    parameter = result.parameters[0]

    assert parameter.parameter_id == "DEEP-PARAM-0001"
    assert parameter.name == "shared"
    assert set(parameter.contexts) == {
        "form_control",
        "form_action_query",
        "html_route_query",
        "javascript_route_query",
        "source_requested_url_query",
        "source_final_url_query",
        "shallow_observed_query",
        "shallow_final_url_query",
    }
    assert parameter.occurrence_count == 10
    assert parameter.password_control_occurrences == 1
    assert parameter.evidence_ids == ("EVID-A", "EVID-B", "EVID-JS", "EVID-ROUTE")
    assert result.summary_counts.unique_parameters_observed_in_multiple_contexts == 1


def test_determinism_with_reversed_inputs_headers_evidence_and_form_order() -> None:
    source_a = _source_item(
        url="http://example.test/same",
        headers=(("X-Test", "b"), ("Content-Type", "text/html"), ("x-test", "a")),
        body=b"<html><form><input name='b'><input name='a'></form></html>",
        evidence=("EVID-B", "EVID-A"),
    )
    source_b = _source_item(
        url="http://example.test/same",
        headers=(("x-test", "a"), ("Content-Type", "text/html"), ("X-Test", "b")),
        body=b"<html><form><input name='a'><input name='b'></form></html>",
        evidence=("EVID-A", "EVID-B"),
    )
    html_a = _html_route(route_id="ROUTE-B", query_names=("r",), evidence=("EVID-R2", "EVID-R1"))
    html_b = _html_route(route_id="ROUTE-A", query_names=("r",), evidence=("EVID-R1", "EVID-R2"))
    js_a = _js_candidate(candidate_id="JS-B", query_names=("j",), evidence=("EVID-J2", "EVID-J1"))
    js_b = _js_candidate(candidate_id="JS-A", query_names=("j",), evidence=("EVID-J1", "EVID-J2"))

    normal = build_deep_parameter_inventory(_source_result(source_a, source_b), _shallow_result(), _html_result(html_a, html_b), _js_result(js_a, js_b))
    reversed_result = build_deep_parameter_inventory(_source_result(source_b, source_a), _shallow_result(), _html_result(html_b, html_a), _js_result(js_b, js_a))

    assert normal == reversed_result
    assert render_deep_parameter_inventory_markdown(normal) == render_deep_parameter_inventory_markdown(reversed_result)


def test_bare_route_and_script_paths_are_not_parameter_names() -> None:
    result = build_deep_parameter_inventory(
        _source_result(),
        _shallow_result(
            _shallow_item(query_names=("lp/", "lp/meta.js", "legitimate"))
        ),
        _html_result(
            _html_route(query_names=("yui/loader/loader-min.js", "routeKey"))
        ),
        _js_result(
            _js_candidate(query_names=("yui/yui/yui-min.js", "scriptKey"))
        ),
    )

    names = {parameter.name for parameter in result.parameters}
    assert names == {"legitimate", "routeKey", "scriptKey"}
    assert result.summary_counts.invalid_names_skipped == 4
    rendered = render_deep_parameter_inventory_markdown(result)
    assert "lp/" not in rendered
    assert "lp/meta.js" not in rendered
    assert "yui/loader/loader-min.js" not in rendered
    assert "yui/yui/yui-min.js" not in rendered


def test_legitimate_query_and_form_names_remain_inventoried() -> None:
    result = build_deep_parameter_inventory(
        _source_result(
            _source_item(
                url="http://example.test/page?filter.name=1&items%5B%5D=2",
                final_url="http://example.test/page?profile-id=3",
                headers=(("Content-Type", "text/html"),),
                body=b'<html><form><input name="user[email]"></form></html>',
            )
        ),
        _shallow_result(),
        _html_result(),
        _js_result(),
    )

    names = {parameter.name for parameter in result.parameters}
    assert {"filter.name", "items[]", "profile-id", "user[email]"}.issubset(names)


def test_renderer_safety_wording_prohibited_words_and_no_body_or_values() -> None:
    body = b"<html><form><input name='param' value='SECRET_VALUE'></form>FULL_BODY_SECRET</html>"
    result = build_deep_parameter_inventory(_source_result(_source_item(body=body)), _shallow_result(), _html_result(), _js_result())
    rendered = render_deep_parameter_inventory_markdown(result)
    public = repr(result) + rendered

    for expected in (
        "## Deep Parameter Inventory",
        "### Summary",
        "### Parameters",
        "### Inventory Interpretation Notes",
        "### Safety Notes",
        "The Deep parameter-inventory stage did not retain parameter values.",
        "The Deep parameter-inventory stage did not replay, guess, or invent parameter values.",
        "The Deep parameter-inventory stage did not mutate parameters.",
        "Names may be case-sensitive and were not case-folded.",
    ):
        assert expected in rendered
    for forbidden in (
        "vulnerable parameter",
        "injectable",
        "confirmed injection point",
        "exploitable",
        "SQL injection",
        "XSS",
        "command injection",
        "authentication bypass",
        "credential parameter",
        "attack",
        "no vulnerabilities found",
        "SECRET_VALUE",
        "FULL_BODY_SECRET",
    ):
        assert forbidden.lower() not in public.lower()


def test_module_adds_no_io_network_cli_parser_dependency_or_execution() -> None:
    source = inspect.getsource(inventory_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.",
        "httpx.",
        "socket.",
        "subprocess",
        "BeautifulSoup",
        "lxml",
        "urllib.request",
    ):
        assert forbidden not in source


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _source_result(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _source_item(
    *,
    url: str = "http://example.test/source",
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html></html>",
    body_preview: str = "",
    evidence: tuple[str, ...] = ("EVID-SOURCE",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=final_url or url,
        headers=headers,
        body_preview=body_preview or body[:500].decode("utf-8", errors="replace"),
        body_sha256=f"hash-{url}",
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="test",
        evidence_ids=evidence,
        body=body,
    )


def _shallow_result(*items: DeepShallowRouteFollowupCollectedItem) -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=tuple(items),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=len(items),
            responses_collected=len(items),
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )


def _shallow_item(
    *,
    request_id: str = "DEEP-SHALLOW-REQ-0001",
    url: str = "http://example.test/follow",
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html></html>",
    body_preview: str = "",
    query_names: tuple[str, ...] = (),
    evidence: tuple[str, ...] = ("EVID-SHALLOW",),
) -> DeepShallowRouteFollowupCollectedItem:
    return DeepShallowRouteFollowupCollectedItem(
        request_id=request_id,
        requested_url=url,
        method="GET",
        status_code=200,
        final_url=final_url or url,
        headers=headers,
        body_preview=body_preview or body[:500].decode("utf-8", errors="replace"),
        body_sha256=f"hash-{url}",
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source_model_kinds=("html_route",),
        source_route_candidate_ids=("H1",),
        query_parameter_names=query_names,
        evidence_ids=evidence,
        interpretation="test",
        body=body,
    )


def _html_result(*routes: DeepHtmlRouteReference) -> DeepHtmlRouteExtractionResult:
    return DeepHtmlRouteExtractionResult(
        routes=tuple(routes),
        summary_counts=DeepHtmlRouteExtractionSummaryCounts(
            total_collected_responses_considered=0,
            responses_selected_by_content_type=0,
            responses_selected_by_body_sniff=0,
            non_html_responses_skipped=0,
            html_bodies_parsed=0,
            total_allowed_attribute_references_observed=0,
            accepted_http_route_occurrences=0,
            unique_extracted_routes=len(routes),
            same_origin_routes=0,
            cross_origin_routes=0,
            not_comparable_routes=0,
            fragment_only_references_skipped=0,
            unsupported_scheme_references_skipped=0,
            empty_references_skipped=0,
            unresolved_references_skipped=0,
            duplicate_accepted_occurrences_aggregated=0,
            responses_using_valid_html_base_url=0,
        ),
        safety_notes=(),
    )


def _html_route(
    *,
    route_id: str = "HTML-ROUTE-1",
    query_names: tuple[str, ...] = ("routeParam",),
    occurrence_count: int = 1,
    evidence: tuple[str, ...] = ("EVID-ROUTE",),
) -> DeepHtmlRouteReference:
    return DeepHtmlRouteReference(
        route_id=route_id,
        safe_resolved_url="http://example.test/route?routeParam",
        path="/route",
        query_parameter_names=query_names,
        origin_relationship="cross_origin",
        reference_forms=("root_relative",),
        tag_attribute_sources=("a[href]",),
        source_response_ids=("SRC-1",),
        source_request_urls=("http://example.test/source",),
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("content_type",),
        occurrence_count=occurrence_count,
        evidence_ids=evidence,
        interpretation="test",
    )


def _js_result(*candidates: DeepJavaScriptRouteCandidate) -> DeepJavaScriptRouteExtractionResult:
    return DeepJavaScriptRouteExtractionResult(
        candidates=tuple(candidates),
        summary_counts=DeepJavaScriptRouteExtractionSummaryCounts(
            total_collected_responses_considered=0,
            javascript_responses_selected_by_content_type=0,
            javascript_responses_selected_by_extension_sniff=0,
            html_responses_selected_for_inline_scripts=0,
            non_javascript_non_html_responses_skipped=0,
            javascript_response_bodies_scanned=0,
            inline_script_blocks_considered=0,
            inline_javascript_blocks_scanned=0,
            total_complete_string_literals_observed=0,
            accepted_static_route_occurrences=0,
            unique_aggregated_candidates=len(candidates),
            candidates_with_safe_resolved_urls=0,
            unresolved_relative_candidates_retained=0,
            fragment_only_strings_skipped=0,
            unsupported_scheme_strings_skipped=0,
            not_route_like_strings_skipped=0,
            empty_strings_skipped=0,
            malformed_strings_skipped=0,
            dynamic_template_strings_skipped=0,
            dynamic_concatenation_strings_skipped=0,
            duplicate_accepted_occurrences_aggregated=0,
            html_responses_using_valid_base_url=0,
        ),
        safety_notes=(),
    )


def _js_candidate(
    *,
    candidate_id: str = "JS-CAND-1",
    query_names: tuple[str, ...] = ("jsParam",),
    occurrence_count: int = 1,
    evidence: tuple[str, ...] = ("EVID-JS",),
) -> DeepJavaScriptRouteCandidate:
    return DeepJavaScriptRouteCandidate(
        candidate_id=candidate_id,
        safe_candidate="/api?jsParam",
        safe_resolved_url=None,
        path="/api",
        query_parameter_names=query_names,
        candidate_forms=("query_relative",),
        resolution_contexts=("execution_context_unknown",),
        source_kinds=("html_inline_script",),
        source_response_ids=("JS-SRC-1",),
        source_request_urls=("http://example.test/source",),
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("javascript_content_type",),
        script_types=("classic",),
        occurrence_count=occurrence_count,
        evidence_ids=evidence,
        interpretation="test",
    )
