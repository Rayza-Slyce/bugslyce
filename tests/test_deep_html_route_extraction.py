"""Tests for offline Deep HTML route extraction."""

from __future__ import annotations

from dataclasses import replace
import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_html_route_extraction import (
    ALLOWED_ROUTE_ATTRIBUTES,
    build_deep_html_route_extraction,
    render_deep_html_route_extraction_markdown,
)
import bugslyce.recon.deep_html_route_extraction as extraction_module
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


def test_empty_collection_result_produces_safe_empty_extraction() -> None:
    result = build_deep_html_route_extraction(_result())
    rendered = render_deep_html_route_extraction_markdown(result)

    assert result.routes == ()
    assert result.summary_counts.total_collected_responses_considered == 0
    assert result.summary_counts.unique_extracted_routes == 0
    assert rendered.startswith("## Deep HTML Route Extraction\n")
    for expected in (
        "### Summary",
        "### Extracted Static Routes",
        "### Extraction Interpretation Notes",
        "### Safety Notes",
        "No route was requested or followed.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered


def test_input_collection_result_is_not_mutated() -> None:
    collection = _result(_item(body=b"<html><a href='/admin'>x</a></html>"))
    before = collection

    build_deep_html_route_extraction(collection)

    assert collection == before


def test_full_stored_body_is_used_instead_of_bounded_preview() -> None:
    body = b"<html>" + b"A" * 700 + b"<a href='/after-preview'>late</a></html>"
    item = _item(body=body, body_preview="<html>" + "A" * 500)

    result = build_deep_html_route_extraction(_result(item))

    assert tuple(route.safe_resolved_url for route in result.routes) == (
        "http://example.test/after-preview",
    )
    assert "after-preview" not in item.body_preview


def test_html_selection_by_content_type_xhtml_and_body_sniff() -> None:
    result = build_deep_html_route_extraction(
        _result(
            _item(url="http://example.test/html", headers=(("Content-Type", "TEXT/HTML; charset=UTF-8"),), body=b"<p><a href='/a'>a</a>"),
            _item(url="http://example.test/xhtml", headers=(("Content-Type", "application/xhtml+xml"),), body=b"<html><a href='/b'>b</a>"),
            _item(url="http://example.test/sniff", headers=(), body=b"  <!doctype html><a href='/c'>c</a>"),
            _item(url="http://example.test/plain", headers=(), body=b"plain <a href='/no'>not html"),
        )
    )

    counts = result.summary_counts
    assert counts.responses_selected_by_content_type == 2
    assert counts.responses_selected_by_body_sniff == 1
    assert counts.non_html_responses_skipped == 1
    assert counts.html_bodies_parsed == 3
    assert "http://example.test/no" not in repr(result)


def test_every_allowlisted_tag_attribute_pair_is_extracted_case_insensitively() -> None:
    snippets = [
        "<A HREF='/a'>a</A>",
        "<area href='/area'></area>",
        "<link href='/link'></link>",
        "<SCRIPT SRC='/script.js'></SCRIPT>",
        "<img src='/img.png'></img>",
        "<iframe src='/iframe'></iframe>",
        "<frame src='/frame'></frame>",
        "<source src='/source'></source>",
        "<video src='/video'></video>",
        "<audio src='/audio'></audio>",
        "<object data='/object'></object>",
        "<embed src='/embed'></embed>",
    ]
    result = build_deep_html_route_extraction(
        _result(_item(body=("<html>" + "".join(snippets)).encode()))
    )

    assert len(result.routes) == len(ALLOWED_ROUTE_ATTRIBUTES)
    assert result.summary_counts.accepted_http_route_occurrences == len(ALLOWED_ROUTE_ATTRIBUTES)
    assert "script[src]" in {source for route in result.routes for source in route.tag_attribute_sources}


def test_deliberate_exclusions_are_not_extracted() -> None:
    html = b"""
    <html>
      <form action="/form"></form>
      <button formaction="/button"></button>
      <input formaction="/input">
      <a onclick="location='/event'" href="">x</a>
      <style>.x{background:url('/style.png')}</style>
      <div style="background:url('/inline-style.png')"></div>
      <meta http-equiv="refresh" content="0; url=/refresh">
      <img srcset="/small.png 1x, /large.png 2x">
      <!-- <a href="/comment"> -->
      text http://example.test/text
      <script>const path = "/js-string";</script>
    </html>
    """

    result = build_deep_html_route_extraction(_result(_item(body=html)))

    assert result.routes == ()
    for excluded in ("form", "button", "input", "event", "style", "refresh", "comment", "js-string"):
        assert excluded not in repr(result)


def test_html_entities_and_reference_forms_resolve() -> None:
    html = b"""
    <html>
      <a href="https://Other.test/Abs?x=1&amp;y=2#frag">abs</a>
      <a href="//cdn.example.test/app.js">cdn</a>
      <a href="/root">root</a>
      <a href="relative/page">rel</a>
      <a href="?view=compact">query</a>
    </html>
    """
    result = build_deep_html_route_extraction(_result(_item(body=html)))

    urls = tuple(route.safe_resolved_url for route in result.routes)
    assert "https://other.test/Abs?x&y" in urls
    assert "http://cdn.example.test/app.js" in urls
    assert "http://example.test/root" in urls
    assert "http://example.test/relative/page" in urls
    assert "http://example.test/source?view" in urls
    forms = {form for route in result.routes for form in route.reference_forms}
    assert {"absolute_https", "scheme_relative", "root_relative", "path_relative", "query_relative"} <= forms


def test_fragment_unsupported_empty_and_malformed_references_are_skipped() -> None:
    html = b"""
    <html>
      <a href="#section">fragment</a>
      <a href="javascript:void(0)">js</a>
      <a href="mailto:user@example.test">mail</a>
      <a href="   ">empty</a>
      <a href="//">bad</a>
    </html>
    """
    result = build_deep_html_route_extraction(_result(_item(body=html)))
    counts = result.summary_counts

    assert result.routes == ()
    assert counts.fragment_only_references_skipped == 1
    assert counts.unsupported_scheme_references_skipped == 2
    assert counts.empty_references_skipped == 1
    assert counts.unresolved_references_skipped == 1
    assert "section" not in repr(result)
    assert "user@example.test" not in repr(result)


def test_safe_urls_strip_sensitive_parts_ignore_empty_names_and_keep_ipv6() -> None:
    html = b"""
    <html>
      <a href="https://user:pass@[2001:db8::1]:8443/path?token=secret&state=value&=empty#frag-secret">ipv6</a>
    </html>
    """
    result = build_deep_html_route_extraction(_result(_item(body=html)))
    rendered = render_deep_html_route_extraction_markdown(result)
    public_text = repr(result) + rendered

    assert result.routes[0].safe_resolved_url == "https://[2001:db8::1]:8443/path?state&token"
    assert result.routes[0].query_parameter_names == ("state", "token")
    for sensitive in ("user", "pass", "secret", "state=value", "frag-secret", "=empty", "token=secret"):
        assert sensitive not in public_text


def test_origin_comparison_defaults_case_scheme_and_ports() -> None:
    result = build_deep_html_route_extraction(
        _result(
            _item(
                url="http://EXAMPLE.test/base",
                body=b"""
                <html>
                  <a href="http://example.test:80/a">same</a>
                  <a href="https://example.test/a">scheme</a>
                  <a href="http://example.test:8080/a">port</a>
                </html>
                """,
            ),
            _item(
                url="https://secure.test/base",
                body=b"<html><a href='https://secure.test:443/a'>same</a>",
            ),
        )
    )

    by_url = {route.safe_resolved_url: route.origin_relationship for route in result.routes}
    assert by_url["http://example.test:80/a"] == "same_origin"
    assert by_url["https://secure.test:443/a"] == "same_origin"
    assert by_url["https://example.test/a"] == "cross_origin"
    assert by_url["http://example.test:8080/a"] == "cross_origin"


def test_base_href_rules() -> None:
    valid_root = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='/app/'><a href='dashboard'>dash</a>"))
    )
    valid_cross = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='https://cdn.example.test/assets/'><script src='app.js'></script>"))
    )
    ignored = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='javascript:void(0)'><a href='local'>local</a>"))
    )
    invalid_then_valid = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='javascript:void(0)'><base href='/valid/'><a href='x'>x</a>"))
    )
    malformed_then_valid = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='://malformed'><base href='https://cdn.example.test/assets/'><script src='app.js'></script>"))
    )
    invalid_authority_then_valid = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='http://[invalid'><base href='/valid/'><a href='route'>route</a>"))
    )
    invalid_authority_fallback = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='https://[2001:db8::1'><a href='route'>route</a>"))
    )
    first_only = build_deep_html_route_extraction(
        _result(_item(body=b"<html><base href='/first/'><base href='/second/'><a href='x'>x</a>"))
    )

    assert valid_root.routes[0].safe_resolved_url == "http://example.test/app/dashboard"
    assert valid_root.summary_counts.responses_using_valid_html_base_url == 1
    assert valid_cross.routes[0].safe_resolved_url == "https://cdn.example.test/assets/app.js"
    assert valid_cross.routes[0].origin_relationship == "cross_origin"
    assert ignored.routes[0].safe_resolved_url == "http://example.test/local"
    assert invalid_then_valid.routes[0].safe_resolved_url == "http://example.test/valid/x"
    assert malformed_then_valid.routes[0].safe_resolved_url == "https://cdn.example.test/assets/app.js"
    assert invalid_authority_then_valid.routes[0].safe_resolved_url == "http://example.test/valid/route"
    assert invalid_authority_then_valid.summary_counts.responses_using_valid_html_base_url == 1
    assert invalid_authority_fallback.routes[0].safe_resolved_url == "http://example.test/route"
    assert invalid_authority_fallback.summary_counts.responses_using_valid_html_base_url == 0
    assert first_only.routes[0].safe_resolved_url == "http://example.test/first/x"
    assert all("base[" not in repr(route) for route in first_only.routes)


def test_duplicates_aggregate_across_body_and_responses_by_safe_url() -> None:
    result = build_deep_html_route_extraction(
        _result(
            _item(
                url="http://example.test/one",
                body=b"<html><a href='/account?token=first'></a><img src='/account?token=second'>",
                evidence_ids=("EVID-B",),
            ),
            _item(
                url="http://example.test/two",
                body=b"<html><script src='/account?token=third'></script>",
                evidence_ids=("EVID-A",),
            ),
        )
    )

    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.safe_resolved_url == "http://example.test/account?token"
    assert route.occurrence_count == 3
    assert route.tag_attribute_sources == ("a[href]", "img[src]", "script[src]")
    assert route.evidence_ids == ("EVID-A", "EVID-B")
    assert result.summary_counts.duplicate_accepted_occurrences_aggregated == 2


def test_route_ordering_ids_and_reversed_collection_input_are_deterministic() -> None:
    first = _item(
        url="http://example.test/source-b",
        body=b"<html><a href='/b'></a><a href='/a'></a>",
        evidence_ids=("EVID-B",),
    )
    second = _item(
        url="http://example.test/source-a",
        body=b"<html><a href='/c'></a><a href='/a'></a>",
        evidence_ids=("EVID-A",),
    )
    normal = build_deep_html_route_extraction(_result(first, second))
    reversed_result = build_deep_html_route_extraction(_result(second, first))

    assert reversed_result == normal
    assert tuple(route.route_id for route in normal.routes) == (
        "DEEP-HTML-ROUTE-0001",
        "DEEP-HTML-ROUTE-0002",
        "DEEP-HTML-ROUTE-0003",
    )
    assert tuple(route.safe_resolved_url for route in normal.routes) == (
        "http://example.test/a",
        "http://example.test/b",
        "http://example.test/c",
    )


def test_summary_counts_are_correct() -> None:
    result = build_deep_html_route_extraction(
        _result(
            _item(body=b"<html><a href='/a'></a><a href='#frag'></a><a href='javascript:void(0)'></a><a href=''></a>"),
            _item(url="http://other.test/source", body=b"<html><a href='http://example.test/a'></a>"),
            _item(url="http://example.test/plain", headers=(), body=b"plain"),
        )
    )
    counts = result.summary_counts

    assert counts.total_collected_responses_considered == 3
    assert counts.responses_selected_by_content_type == 2
    assert counts.non_html_responses_skipped == 1
    assert counts.html_bodies_parsed == 2
    assert counts.total_allowed_attribute_references_observed == 5
    assert counts.accepted_http_route_occurrences == 2
    assert counts.unique_extracted_routes == 2
    assert counts.same_origin_routes == 1
    assert counts.cross_origin_routes == 1
    assert counts.fragment_only_references_skipped == 1
    assert counts.unsupported_scheme_references_skipped == 1
    assert counts.empty_references_skipped == 1


def test_renderer_compacts_safety_wording_and_avoids_prohibited_language() -> None:
    result = build_deep_html_route_extraction(
        _result(
            _item(
                body=(
                    "<html>"
                    + "".join(f"<a href='/long-{index}-{'x' * 140}'></a>" for index in range(8))
                ).encode(),
                evidence_ids=tuple(f"EVID-{index}" for index in range(8)),
            )
        )
    )
    rendered = render_deep_html_route_extraction_markdown(result)

    for expected in (
        "## Deep HTML Route Extraction",
        "### Summary",
        "### Extracted Static Routes",
        "### Extraction Interpretation Notes",
        "### Safety Notes",
        "full HTML bodies already collected in memory",
        "No route was requested or followed.",
        "No network request was made.",
        "Query values, URL credentials, and fragment contents are not retained.",
        "Unsupported schemes are not executed.",
        "Forms are not inventoried in this phase.",
        "Inline JavaScript and JavaScript source contents are not analysed.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered
    assert "... [truncated]" in rendered
    for forbidden in (
        "confirmed endpoint",
        "confirmed hidden route",
        "vulnerability",
        "vulnerable",
        "exploitable",
        "insecure",
        "authentication bypass",
        "open redirect",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden not in rendered.lower()


def test_full_html_bodies_are_not_copied_into_public_model() -> None:
    body = b"<html><a href='/safe'></a>FULL_BODY_SECRET_SHOULD_NOT_APPEAR</html>"

    result = build_deep_html_route_extraction(_result(_item(body=body)))

    assert "FULL_BODY_SECRET_SHOULD_NOT_APPEAR" not in repr(result)


def test_builder_renderer_add_no_io_network_collectors_js_or_form_inventory() -> None:
    source = inspect.getsource(extraction_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.",
        "httpx.",
        "socket.",
        "collect_deep_source_routes_from_plan",
        "urllib_deep_http_fetcher",
        "follow_redirect",
        "form_inventory",
        "javascript_route",
    ):
        assert forbidden not in source


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _result(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _item(
    *,
    url: str = "http://example.test/source",
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html></html>",
    body_preview: str = "",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=headers,
        body_preview=body_preview or body[:500].decode("utf-8", errors="replace"),
        body_sha256=f"hash-{url}",
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="test",
        evidence_ids=evidence_ids,
        body=body,
    )
