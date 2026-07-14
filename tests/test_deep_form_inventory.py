"""Tests for offline Deep form inventory."""

from __future__ import annotations

import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_form_inventory import (
    build_deep_form_inventory,
    render_deep_form_inventory_markdown,
)
import bugslyce.recon.deep_form_inventory as inventory_module
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
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
    result = build_deep_form_inventory(_source_result(), _shallow_result())
    rendered = render_deep_form_inventory_markdown(result)

    assert result.forms == ()
    assert result.summary_counts.forms_observed == 0
    for expected in (
        "## Deep Form Inventory",
        "### Summary",
        "### Forms",
        "### Inventory Interpretation Notes",
        "### Safety Notes",
        "No form was submitted.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered


def test_inputs_are_not_mutated_and_full_bodies_are_used_not_preview() -> None:
    source = _source_result(
        _source_item(
            body=(b"<html>" + b"A" * 700 + b"<form action='/late'><input name='secret_name'></form>"),
            body_preview="<html>" + ("A" * 500),
        )
    )
    shallow = _shallow_result(
        _shallow_item(
            body=(b"<html>" + b"B" * 700 + b"<form action='/late2'><input name='secret_name2'></form>"),
            body_preview="<html>" + ("B" * 500),
        )
    )
    before = (source, shallow)

    result = build_deep_form_inventory(source, shallow)
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert (source, shallow) == before
    assert {form.safe_resolved_action_url for form in result.forms} == {
        "http://example.test/late",
        "http://example.test/late2",
    }
    assert "secret_name" not in public
    assert "secret_name2" not in public


def test_html_source_selection_and_skips() -> None:
    result = build_deep_form_inventory(
        _source_result(
            _source_item(headers=(("Content-Type", "TEXT/HTML; charset=utf-8"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/xhtml", headers=(("Content-Type", "application/xhtml+xml"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/sniff", headers=(), body=b" <!doctype html><form></form>"),
            _source_item(url="http://example.test/octet", headers=(("Content-Type", "application/octet-stream"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/js", headers=(("Content-Type", "application/javascript"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/json", headers=(("Content-Type", "application/json"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/plain", headers=(("Content-Type", "text/plain"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/empty", body=b""),
        ),
        _shallow_result(),
    )

    counts = result.summary_counts
    assert counts.source_collection_responses_considered == 8
    assert counts.source_collection_html_responses_scanned == 4
    assert counts.explicit_non_html_responses_skipped == 3
    assert counts.empty_bodies_skipped == 1
    assert counts.forms_observed == 4


def test_html_selection_counts_empty_sniffable_and_explicit_non_html_paths() -> None:
    result = build_deep_form_inventory(
        _source_result(
            _source_item(url="http://example.test/empty", body=b""),
            _source_item(url="http://example.test/html", headers=(("Content-Type", "text/html"),), body=b"<html><form></form>"),
            _source_item(url="http://example.test/sniff", headers=(), body=b"<html><form></form>"),
            _source_item(url="http://example.test/not-sniff", headers=(), body=b"plain body"),
            _source_item(url="http://example.test/explicit", headers=(("Content-Type", "application/json"),), body=b"<html><form></form>"),
        ),
        _shallow_result(),
    )

    counts = result.summary_counts
    assert counts.empty_bodies_skipped == 1
    assert counts.source_collection_html_responses_scanned == 2
    assert counts.sniffable_non_html_responses_skipped == 1
    assert counts.explicit_non_html_responses_skipped == 1
    assert counts.forms_observed == 2


def test_methods_enctypes_targets_and_controls_are_canonicalised() -> None:
    html = b"""
    <html><form method="POST" enctype="multipart/form-data" target="MyFrame" action="/submit-target">
      <input NAME="SECRET_USERNAME_NAME" required value="SECRET_VALUE">
      <input name="SECRET_PASSWORD_NAME" type="PASSWORD">
      <input type="file" name="SECRET_UPLOAD_NAME">
      <input type="hidden" name="SECRET_CSRF_NAME" value="TOKEN_SECRET">
      <input type="unknown" disabled>
      <select name="choice"><option value="OPTION_SECRET">A</option></select>
      <textarea name="bio">TEXTAREA_SECRET</textarea>
      <button>Go SECRET_LABEL</button>
      <button type="weird">Other</button>
    </form></html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    form = result.forms[0]
    summary = form.control_summary
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert form.methods == ("post",)
    assert form.enctypes == ("multipart/form-data",)
    assert form.target_kinds == ("named",)
    assert summary.total_controls == 9
    assert summary.named_controls == 6
    assert summary.unnamed_controls == 3
    assert summary.required_controls == 1
    assert summary.disabled_controls == 1
    assert summary.password_controls == 1
    assert summary.file_controls == 1
    assert summary.hidden_controls == 1
    assert summary.submit_capable_controls == 1
    for sensitive in (
        "SECRET_USERNAME_NAME",
        "SECRET_PASSWORD_NAME",
        "SECRET_UPLOAD_NAME",
        "SECRET_CSRF_NAME",
        "SECRET_VALUE",
        "TOKEN_SECRET",
        "OPTION_SECRET",
        "TEXTAREA_SECRET",
        "SECRET_LABEL",
        "MyFrame",
    ):
        assert sensitive not in public


def test_default_and_unknown_method_enctype_target_forms() -> None:
    result = build_deep_form_inventory(
        _source_result(
            _source_item(body=b"<html><form action='/a'><input></form>"),
            _source_item(url="http://example.test/dialog", body=b"<html><form method='dialog' enctype='text/plain' target='_blank'></form>"),
            _source_item(url="http://example.test/other", body=b"<html><form method='TRACE' enctype='application/custom' target='_top'></form>"),
        ),
        _shallow_result(),
    )

    by_url = {form.safe_resolved_action_url: form for form in result.forms}
    assert by_url["http://example.test/a"].methods == ("get",)
    assert by_url["http://example.test/a"].enctypes == ("application/x-www-form-urlencoded",)
    assert by_url["http://example.test/a"].target_kinds == ("none",)
    assert "dialog" in {method for form in result.forms for method in form.methods}
    assert "other" in {method for form in result.forms for method in form.methods}
    assert "text/plain" in {enctype for form in result.forms for enctype in form.enctypes}
    assert "blank" in {target for form in result.forms for target in form.target_kinds}
    assert "top" in {target for form in result.forms for target in form.target_kinds}


def test_action_resolution_base_sanitisation_and_unsupported_actions() -> None:
    html = b"""
    <html>
      <base href="javascript:void(0)">
      <base href="http://[invalid">
      <base href="https://cdn.example.test/base/">
      <form action=""></form>
      <form action="/root?token=secret&state=value#frag"></form>
      <form action="./dot"></form>
      <form action="../parent"></form>
      <form action="path"></form>
      <form action="?view=secret"></form>
      <form action="//other.test/x?secret=value"></form>
      <form action="https://user:pass@[2001:db8::1]:8443/form?token=secret#frag"></form>
      <form action="javascript:alert('SECRET')"></form>
      <form action="http://[bad"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    public = repr(result) + render_deep_form_inventory_markdown(result)
    urls = {form.safe_resolved_action_url for form in result.forms if form.safe_resolved_action_url}
    refs = {form.safe_action_reference for form in result.forms}

    assert "http://example.test/source" in urls
    assert "https://cdn.example.test/root?state&token" in urls
    assert "https://cdn.example.test/base/dot" in urls
    assert "https://cdn.example.test/parent" in urls
    assert "https://cdn.example.test/base/path" in urls
    assert "https://cdn.example.test/base/?view" in urls
    assert "https://other.test/x?secret" in urls
    assert "https://[2001:db8::1]:8443/form?token" in urls
    assert "unsupported_scheme" in refs
    assert "malformed_action" in refs
    assert result.summary_counts.form_occurrences_using_valid_html_base_url >= 5
    for sensitive in ("user:pass", "pass@", "secret=value", "token=secret", "#frag", "alert"):
        assert sensitive not in public


def test_action_reference_query_fragment_and_default_sanitisation() -> None:
    html = b"""
    <html>
      <form action="?view=secret"></form>
      <form action="?a=1&b=2#frag-secret"></form>
      <form action="#secret-fragment"></form>
      <form></form>
      <form action=""></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    rendered = render_deep_form_inventory_markdown(result)
    public = repr(result) + rendered
    by_ref = {form.safe_action_reference: form for form in result.forms}

    assert "?view" in by_ref
    assert "??view" not in public
    assert "?a&b" in by_ref
    document_forms = [form for form in result.forms if form.safe_resolved_action_url == "http://example.test/source"]
    assert len(document_forms) == 1
    assert document_forms[0].occurrence_count == 3
    assert document_forms[0].action_resolution_contexts == ("document_url", "document_url_default")
    assert document_forms[0].safe_action_reference == "document_url_default"
    for secret in ("view=secret", "a=1", "b=2", "frag-secret", "#secret-fragment"):
        assert secret not in public


def test_action_resolution_contexts_count_only_actual_base_use() -> None:
    html = b"""
    <html>
      <base href="https://cdn.example.test/base/">
      <form action="relative"></form>
      <form action="https://other.example.test/absolute"></form>
      <form></form>
      <form action="?view=secret"></form>
      <form action="#fragment-secret"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    contexts_by_url = {
        form.safe_resolved_action_url: form.action_resolution_contexts
        for form in result.forms
        if form.safe_resolved_action_url
    }

    assert contexts_by_url["https://cdn.example.test/base/relative"] == ("html_base_url",)
    assert contexts_by_url["https://other.example.test/absolute"] == ("absolute_url",)
    assert contexts_by_url["http://example.test/source"] == ("document_url_default",)
    assert contexts_by_url["https://cdn.example.test/base/?view"] == ("html_base_url",)
    assert contexts_by_url["https://cdn.example.test/base/"] == ("html_base_url",)
    assert result.summary_counts.form_occurrences_using_valid_html_base_url == 3


def test_document_url_context_is_used_when_no_valid_base_exists() -> None:
    html = b"""
    <html>
      <base href="javascript:void(0)">
      <form action="?view=secret"></form>
      <form action="#frag-secret"></form>
      <form action="relative"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())

    assert result.summary_counts.form_occurrences_using_valid_html_base_url == 0
    assert {context for form in result.forms for context in form.action_resolution_contexts} == {"document_url"}


def test_script_style_and_template_regions_do_not_close_or_add_to_active_form() -> None:
    html = b"""
    <html>
      <form action="/outer">
        <input name="outer">
        <script><form action="/script"><input name="SCRIPT_SECRET"></form></script>
        <style><form action="/style"><input name="STYLE_SECRET"></form></style>
        <template>
          </form>
          <input name="TEMPLATE_SECRET">
          <template><input name="NESTED_TEMPLATE_SECRET"></template>
        </template>
        <input name="after">
      </form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert len(result.forms) == 1
    assert result.forms[0].safe_resolved_action_url == "http://example.test/outer"
    assert result.forms[0].control_summary.total_controls == 2
    assert result.summary_counts.controls_outside_forms_ignored == 0
    for secret in ("SCRIPT_SECRET", "STYLE_SECRET", "TEMPLATE_SECRET", "NESTED_TEMPLATE_SECRET"):
        assert secret not in public


def test_internal_repr_contains_no_full_body_or_raw_parser_state_secrets() -> None:
    body = (
        b"<html><form action='https://user:pass@example.test/path?token=SECRET_VALUE#SECRET_FRAGMENT' "
        b"method='SECRET_METHOD' enctype='SECRET_ENCTYPE' target='SECRET_TARGET'>"
        b"<input name='SECRET_NAME' value='SECRET_FIELD_VALUE'></form>FULL_BODY_MARKER</html>"
    )

    result = build_deep_form_inventory(_source_result(_source_item(body=body)), _shallow_result())
    public = repr(result) + render_deep_form_inventory_markdown(result)

    for secret in (
        "FULL_BODY_MARKER",
        "SECRET_VALUE",
        "SECRET_FRAGMENT",
        "SECRET_METHOD",
        "SECRET_ENCTYPE",
        "SECRET_TARGET",
        "SECRET_NAME",
        "SECRET_FIELD_VALUE",
        "user:pass",
    ):
        assert secret not in public


def test_canonical_document_url_fallback_and_provenance_are_safe() -> None:
    final_preferred = _source_item(
        url="http://example.test/requested",
        final_url="https://example.test/final?secret=SECRET_QUERY_VALUE#SECRET_FRAGMENT",
        body=b"<html><form></form>",
    )
    requested_fallback = _source_item(
        url="http://example.test/requested-fallback?secret=SECRET_QUERY_VALUE#SECRET_FRAGMENT",
        final_url="http://[bad",
        body=b"<html><form></form>",
    )
    both_bad = _source_item(
        url="http://[bad-requested",
        final_url="http://[bad-final",
        body=b"<html><form></form>",
    )

    result = build_deep_form_inventory(_source_result(final_preferred, requested_fallback, both_bad), _shallow_result())
    document_urls = {url for form in result.forms for url in form.safe_document_urls}
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert "https://example.test/final?secret" in document_urls
    assert "http://example.test/requested-fallback?secret" in document_urls
    assert "unresolved" not in document_urls
    assert all("://[" not in url for url in document_urls)
    for raw in ("SECRET_QUERY_VALUE", "SECRET_FRAGMENT", "bad-requested", "bad-final"):
        assert raw not in public


def test_malformed_and_nested_forms_and_controls_outside_forms() -> None:
    html = b"""
    <html>
      <input name="SECRET_OUTSIDE_NAME">
      </form>
      <form action="/one"><input name="a">
      <form action="/two"><input name="b"></form>
      <form action="/three"><input name="c">
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    flags = {flag for form in result.forms for flag in form.structural_flags}

    assert "nested_form_start" in flags
    assert "unterminated_form" in flags
    assert result.summary_counts.controls_outside_forms_ignored == 1
    assert result.summary_counts.nested_or_malformed_form_occurrences == 1
    assert result.summary_counts.unterminated_form_occurrences == 1
    assert "SECRET_OUTSIDE_NAME" not in repr(result)


def test_identical_forms_aggregate_and_distinct_forms_remain_distinct() -> None:
    result = build_deep_form_inventory(
        _source_result(
            _source_item(url="http://example.test/one", body=b"<html><form action='/login' method='post'><input type='password' name='p'></form><form action='/login' method='post'><input type='password' name='p2'></form>"),
            _source_item(url="http://example.test/two", body=b"<html><form action='/login' method='get'><input type='password' name='p'></form>"),
            _source_item(url="http://example.test/three", body=b"<html><form action='/other' method='post'><input type='password' name='p'></form>"),
        ),
        _shallow_result(),
    )

    assert result.summary_counts.forms_observed == 4
    assert result.summary_counts.unique_aggregated_forms == 3
    assert result.summary_counts.duplicate_form_occurrences_aggregated == 1
    assert max(form.occurrence_count for form in result.forms) == 2


def test_equivalent_resolved_action_references_aggregate_by_canonical_url() -> None:
    html = b"""
    <html>
      <form action="/login"><input name="a"></form>
      <form action="http://example.test/login"><input name="b"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    form = result.forms[0]

    assert len(result.forms) == 1
    assert form.safe_resolved_action_url == "http://example.test/login"
    assert form.action_resolution_contexts == ("absolute_url", "document_url")
    assert form.occurrence_count == 2
    assert result.summary_counts.forms_observed == 2
    assert result.summary_counts.unique_aggregated_forms == 1
    assert result.summary_counts.duplicate_form_occurrences_aggregated == 1


def test_path_relative_and_dot_relative_references_aggregate_with_deterministic_representative() -> None:
    html = b"""
    <html>
      <base href="http://example.test/app/">
      <form action="login"><input name="a"></form>
      <form action="./login"><input name="b"></form>
    </html>
    """
    reversed_html = b"""
    <html>
      <base href="http://example.test/app/">
      <form action="./login"><input name="b"></form>
      <form action="login"><input name="a"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    reversed_result = build_deep_form_inventory(_source_result(_source_item(body=reversed_html)), _shallow_result())

    assert result == reversed_result
    assert render_deep_form_inventory_markdown(result) == render_deep_form_inventory_markdown(reversed_result)
    form = result.forms[0]
    assert form.safe_resolved_action_url == "http://example.test/app/login"
    assert form.safe_action_reference == "./login"
    assert form.action_resolution_contexts == ("html_base_url",)
    assert form.occurrence_count == 2


def test_resolved_action_aggregation_is_deterministic_when_source_order_reverses() -> None:
    source_a = _source_item(
        url="http://example.test/a",
        body=b"<html><form action='/login'><input name='a'></form></html>",
        evidence=("EVID-B",),
    )
    source_b = _source_item(
        url="http://example.test/b",
        body=b"<html><form action='http://example.test/login'><input name='b'></form></html>",
        evidence=("EVID-A",),
    )

    normal = build_deep_form_inventory(_source_result(source_a, source_b), _shallow_result())
    reversed_result = build_deep_form_inventory(_source_result(source_b, source_a), _shallow_result())

    assert normal == reversed_result
    assert render_deep_form_inventory_markdown(normal) == render_deep_form_inventory_markdown(reversed_result)
    form = normal.forms[0]
    assert form.occurrence_count == 2
    assert form.action_resolution_contexts == ("absolute_url", "document_url")
    assert form.evidence_ids == ("EVID-A", "EVID-B")


def test_different_actions_methods_controls_and_unresolved_classifications_remain_distinct() -> None:
    html = b"""
    <html>
      <form action="/one"><input name="a"></form>
      <form action="/two"><input name="a"></form>
      <form action="/one" method="post"><input name="a"></form>
      <form action="/one"><input name="a"><input name="b"></form>
      <form action="javascript:alert('SECRET_ACTION')"><input name="a"></form>
      <form action="http://[bad-secret"><input name="a"></form>
    </html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    rendered = render_deep_form_inventory_markdown(result)
    public = repr(result) + rendered
    identities = {
        (
            form.safe_resolved_action_url,
            form.safe_action_reference,
            form.methods,
            form.control_summary.total_controls,
        )
        for form in result.forms
    }

    assert len(result.forms) == 6
    assert ("http://example.test/one", "/one", ("get",), 1) in identities
    assert ("http://example.test/two", "/two", ("get",), 1) in identities
    assert ("http://example.test/one", "/one", ("post",), 1) in identities
    assert ("http://example.test/one", "/one", ("get",), 2) in identities
    assert (None, "unsupported_scheme", ("get",), 1) in identities
    assert (None, "malformed_action", ("get",), 1) in identities
    for secret in ("SECRET_ACTION", "bad-secret"):
        assert secret not in public


def test_identical_forms_from_original_and_shallow_sources_aggregate_provenance() -> None:
    source = _source_item(body=b"<html><form action='/same' method='post'><input name='a'></form>")
    shallow = _shallow_item(body=b"<html><form action='/same' method='post'><input name='b'></form>")

    result = build_deep_form_inventory(_source_result(source), _shallow_result(shallow))
    form = result.forms[0]

    assert form.occurrence_count == 2
    assert form.source_kinds == ("shallow_route_followup", "source_route_collection")
    assert form.source_request_ids == ("DEEP-SHALLOW-REQ-0001",)
    assert form.source_route_candidate_ids == ("H1",)


def test_structurally_different_control_summaries_remain_distinct() -> None:
    result = build_deep_form_inventory(
        _source_result(
            _source_item(url="http://example.test/a", body=b"<html><form action='/same'><input name='a'></form>"),
            _source_item(url="http://example.test/b", body=b"<html><form action='/same'><input name='a'><input name='b'></form>"),
        ),
        _shallow_result(),
    )

    assert result.summary_counts.forms_observed == 2
    assert result.summary_counts.unique_aggregated_forms == 2


def test_malformed_utf8_form_without_controls_and_unmatched_close_are_safe() -> None:
    body = b"\xff\xfe<html></form><form action='/empty'></form>"

    result = build_deep_form_inventory(_source_result(_source_item(body=body)), _shallow_result())
    form = result.forms[0]

    assert form.safe_resolved_action_url == "http://example.test/empty"
    assert form.control_summary.total_controls == 0
    assert result.summary_counts.forms_observed == 1


def test_missing_unknown_input_button_select_textarea_and_boolean_counts() -> None:
    html = b"""
    <html><form action="/controls">
      <input name="a">
      <input type="SECRET_UNKNOWN_TYPE" required="false" disabled="false">
      <button></button>
      <button type="SECRET_BUTTON_TYPE"></button>
      <select name="s"></select>
      <textarea name="t">SECRET_TEXTAREA_VALUE</textarea>
    </form></html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    summary = result.forms[0].control_summary
    type_counts = dict(summary.control_type_counts)
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert summary.total_controls == 6
    assert summary.required_controls == 1
    assert summary.disabled_controls == 1
    assert type_counts["text"] == 1
    assert type_counts["other"] == 1
    assert type_counts["submit"] == 1
    assert type_counts["other_button"] == 1
    assert type_counts["select"] == 1
    assert type_counts["textarea"] == 1
    for secret in ("SECRET_UNKNOWN_TYPE", "SECRET_BUTTON_TYPE", "SECRET_TEXTAREA_VALUE"):
        assert secret not in public


def test_duplicate_attributes_use_first_occurrence_and_do_not_retain_later_values() -> None:
    html = b"""
    <html><form
      action="/first"
      action="/SECRET_LATER_ACTION"
      method="post"
      method="SECRET_METHOD"
      enctype="multipart/form-data"
      enctype="SECRET_ENCTYPE"
      target="_blank"
      target="SECRET_TARGET">
      <input type="password" type="SECRET_TYPE" name="first-name" name="SECRET_NAME" required required="SECRET_REQUIRED" disabled disabled="SECRET_DISABLED">
    </form></html>
    """

    result = build_deep_form_inventory(_source_result(_source_item(body=html)), _shallow_result())
    form = result.forms[0]
    public = repr(result) + render_deep_form_inventory_markdown(result)

    assert form.safe_resolved_action_url == "http://example.test/first"
    assert form.methods == ("post",)
    assert form.enctypes == ("multipart/form-data",)
    assert form.target_kinds == ("blank",)
    assert form.control_summary.password_controls == 1
    assert form.control_summary.named_controls == 1
    assert form.control_summary.required_controls == 1
    assert form.control_summary.disabled_controls == 1
    for secret in (
        "SECRET_LATER_ACTION",
        "SECRET_METHOD",
        "SECRET_ENCTYPE",
        "SECRET_TARGET",
        "SECRET_TYPE",
        "SECRET_NAME",
        "SECRET_REQUIRED",
        "SECRET_DISABLED",
        "first-name",
    ):
        assert secret not in public


def test_source_provenance_evidence_and_determinism_with_reversed_inputs() -> None:
    source_a = _source_item(url="http://example.test/a", body=b"<html><form action='/same'><input name='a'></form>", evidence=("EVID-B",))
    source_b = _source_item(url="http://example.test/b", body=b"<html><form action='/same'><input name='b'></form>", evidence=("EVID-A",))
    shallow = _shallow_item(body=b"<html><form action='/same'><input name='c'></form>", evidence=("EVID-C",))

    normal = build_deep_form_inventory(_source_result(source_a, source_b), _shallow_result(shallow))
    reversed_result = build_deep_form_inventory(_source_result(source_b, source_a), _shallow_result(shallow))

    assert normal == reversed_result
    form = normal.forms[0]
    assert form.form_id == "DEEP-FORM-0001"
    assert form.occurrence_count == 3
    assert form.source_kinds == ("shallow_route_followup", "source_route_collection")
    assert form.evidence_ids == ("EVID-A", "EVID-B", "EVID-C")


def test_source_ordering_uses_method_computed_body_metadata_headers_and_evidence() -> None:
    source_a = _source_item(
        url="http://example.test/same",
        body=b"<html><form action='/a'><input name='a'></form>",
        evidence=("EVID-B", "EVID-A"),
    )
    source_b = _source_item(
        url="http://example.test/same",
        body=b"<html><form action='/b'><input name='b'></form>",
        evidence=("EVID-D", "EVID-C"),
    )
    source_a = DeepSourceRouteCollectedItem(
        url=source_a.url,
        method="post",
        status_code=source_a.status_code,
        final_url=source_a.final_url,
        headers=(("X-Test", "b"), ("x-test", "a")),
        body_preview=source_a.body_preview,
        body_sha256="stale-same",
        body_bytes=1,
        elapsed_seconds=source_a.elapsed_seconds,
        source=source_a.source,
        reason=source_a.reason,
        evidence_ids=source_a.evidence_ids,
        body=source_a.body,
    )
    source_b = DeepSourceRouteCollectedItem(
        url=source_b.url,
        method="GET",
        status_code=source_b.status_code,
        final_url=source_b.final_url,
        headers=(("x-test", "a"), ("X-Test", "b")),
        body_preview=source_b.body_preview,
        body_sha256="stale-same",
        body_bytes=1,
        elapsed_seconds=source_b.elapsed_seconds,
        source=source_b.source,
        reason=source_b.reason,
        evidence_ids=source_b.evidence_ids,
        body=source_b.body,
    )

    normal = build_deep_form_inventory(_source_result(source_a, source_b), _shallow_result())
    reversed_result = build_deep_form_inventory(_source_result(source_b, source_a), _shallow_result())

    assert normal == reversed_result
    assert render_deep_form_inventory_markdown(normal) == render_deep_form_inventory_markdown(reversed_result)
    assert tuple(form.evidence_ids for form in normal.forms) == (("EVID-A", "EVID-B"), ("EVID-C", "EVID-D"))


def test_long_action_attributes_render_safely() -> None:
    long_path = "/long/" + ("a" * 220)
    result = build_deep_form_inventory(
        _source_result(_source_item(body=f"<html><form action='{long_path}'></form></html>".encode())),
        _shallow_result(),
    )
    rendered = render_deep_form_inventory_markdown(result)

    assert "[truncated]" in rendered
    assert "a" * 220 not in rendered


def test_renderer_safety_wording_and_prohibited_language() -> None:
    result = build_deep_form_inventory(
        _source_result(_source_item(body=b"<html><form action='/login'><input type='password' name='p'></form>")),
        _shallow_result(),
    )
    rendered = render_deep_form_inventory_markdown(result)

    for expected in (
        "## Deep Form Inventory",
        "### Summary",
        "### Forms",
        "### Inventory Interpretation Notes",
        "### Safety Notes",
        "No network request was made.",
        "No form was submitted.",
        "No form action was fetched.",
        "No JavaScript was executed.",
        "No field value was retained, replayed, or invented.",
        "Individual control names are deliberately deferred to Phase 92B.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered
    for forbidden in (
        "vulnerable form",
        "exploitable",
        "confirmed CSRF",
        "authentication bypass",
        "credential theft",
        "file upload vulnerability",
        "SQL injection",
        "XSS",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden.lower() not in rendered.lower()


def test_bodies_names_values_and_raw_malformed_values_are_not_public() -> None:
    body = b"<html><form action='http://[bad'><input name='SECRET_NAME' value='SECRET_VALUE'></form>FULL_BODY_SECRET</html>"

    result = build_deep_form_inventory(_source_result(_source_item(body=body)), _shallow_result())
    rendered = render_deep_form_inventory_markdown(result)
    public = repr(result) + rendered

    for secret in ("SECRET_NAME", "SECRET_VALUE", "FULL_BODY_SECRET", "http://[bad"):
        assert secret not in public


def test_module_adds_no_io_network_submission_cli_or_parser_dependency() -> None:
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


def _source_item(
    *,
    url: str = "http://example.test/source",
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html></html>",
    body_preview: str = "",
    evidence: tuple[str, ...] = ("EVID-1",),
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


def _shallow_item(
    *,
    request_id: str = "DEEP-SHALLOW-REQ-0001",
    url: str = "http://example.test/fol",
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html></html>",
    body_preview: str = "",
    evidence: tuple[str, ...] = ("EVID-1",),
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
        query_parameter_names=(),
        evidence_ids=evidence,
        interpretation="test",
        body=body,
    )
