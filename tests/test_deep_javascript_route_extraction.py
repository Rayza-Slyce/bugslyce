"""Tests for offline Deep JavaScript route extraction."""

from __future__ import annotations

import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_javascript_route_extraction import (
    JAVASCRIPT_MEDIA_TYPES,
    build_deep_javascript_route_extraction,
    render_deep_javascript_route_extraction_markdown,
)
import bugslyce.recon.deep_javascript_route_extraction as extraction_module
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
    result = build_deep_javascript_route_extraction(_result())
    rendered = render_deep_javascript_route_extraction_markdown(result)

    assert result.candidates == ()
    assert result.summary_counts.total_collected_responses_considered == 0
    assert rendered.startswith("## Deep JavaScript Route Extraction\n")
    for expected in (
        "### Summary",
        "### Extracted Static JavaScript Route Candidates",
        "### Extraction Interpretation Notes",
        "### Safety Notes",
        "No JavaScript was executed.",
        "This stage produces static manual-review context only.",
    ):
        assert expected in rendered


def test_input_collection_result_is_not_mutated() -> None:
    collection = _result(_js_item(body=b'const route = "/api/users";'))
    before = collection

    build_deep_javascript_route_extraction(collection)

    assert collection == before


def test_full_javascript_body_and_inline_html_body_are_used_not_preview() -> None:
    js_body = ("const pad = '" + ("a" * 700) + "'; const route = '/late-js';").encode()
    html_body = (
        "<html>"
        + (" " * 700)
        + "<script>const route = '/late-inline';</script></html>"
    ).encode()
    result = build_deep_javascript_route_extraction(
        _result(
            _js_item(url="http://example.test/app.js", body=js_body, body_preview="const pad = '" + ("a" * 500)),
            _html_item(url="http://example.test/page", body=html_body, body_preview="<html>" + (" " * 500)),
        )
    )

    urls = {candidate.safe_resolved_url for candidate in result.candidates}
    assert "http://example.test/late-js" in urls
    assert "http://example.test/late-inline" in urls


def test_javascript_source_selection_by_media_type_and_extension_sniff() -> None:
    items = [
        _js_item(
            url=f"http://example.test/type-{index}.txt",
            headers=(("Content-Type", f"{media}; charset=utf-8"),),
            body=f"const route = '/type-{index}';".encode(),
        )
        for index, media in enumerate(sorted(JAVASCRIPT_MEDIA_TYPES), start=1)
    ]
    items.extend(
        [
            _item(url="http://example.test/app.js", headers=(), body=b'const route = "/js-ext";'),
            _item(url="http://example.test/app.mjs", headers=(), body=b'export const route = "/mjs-ext";'),
            _item(url="http://example.test/app.cjs", headers=(), body=b'function x(){ return "/cjs-ext"; }'),
            _item(url="http://example.test/not-js.js", headers=(("Content-Type", "text/plain"),), body=b"<html><script>const route='/nope'</script>"),
            _item(url="http://example.test/plain", headers=(), body=b"plain"),
        ]
    )

    result = build_deep_javascript_route_extraction(_result(*items))
    counts = result.summary_counts
    rendered = repr(result)

    assert counts.javascript_responses_selected_by_content_type == len(JAVASCRIPT_MEDIA_TYPES)
    assert counts.javascript_responses_selected_by_extension_sniff == 3
    assert counts.non_javascript_non_html_responses_skipped == 2
    assert "nope" not in rendered


def test_inline_script_selection_and_exclusions() -> None:
    html = b"""
    <html>
      <script>const a = "/default";</script>
      <script type="module">const b = "/module";</script>
      <script type="application/javascript">const c = "/mime";</script>
      <script type="application/json">{"/json": true}</script>
      <script type="application/ld+json">{"/ld": true}</script>
      <script type="importmap">{"/imports": {}}</script>
      <script type="speculationrules">{}</script>
      <script type="text/template">/template</script>
      <script type="text/x-template">/x-template</script>
      <script src="/external.js">const d = "/src-body";</script>
      <script src="/self-closing.js" />
      ordinary /after-self-closing
      <button onclick="go('/event')"></button>
      <style>.x{background:url('/style')}</style>
      ordinary /text
    </html>
    """

    result = build_deep_javascript_route_extraction(_result(_html_item(body=html)))
    public_text = repr(result)

    assert {candidate.safe_resolved_url for candidate in result.candidates} == {
        "http://example.test/default",
        "http://example.test/module",
        "http://example.test/mime",
    }
    for excluded in (
        "/json",
        "/ld",
        "/imports",
        "/template",
        "/x-template",
        "src-body",
        "after-self-closing",
        "event",
        "style",
        "/text",
    ):
        assert excluded not in public_text
    assert result.summary_counts.inline_script_blocks_considered == 9
    assert result.summary_counts.inline_javascript_blocks_scanned == 3


def test_lexical_scanner_literals_escapes_comments_regex_and_dynamic_skips() -> None:
    body = br'''
    const a = '/single';
    const b = "/double";
    const c = `/static/app.js`;
    const d = '\/admin\/login';
    const e = "\x2fapi\x2fv1";
    const f = "\u002fportal";
    const skipTemplate = `/users/${userId}`;
    const skipConcatA = "/api/" + resource;
    const skipConcatB = basePath + "/users";
    // "/comment"
    /* '/block-comment' */
    if (/"/.test(value)) { const g = "/after-regex"; }
    const bad = "/unterminated
    const malformed = "\xZZ";
    '''

    result = build_deep_javascript_route_extraction(_result(_js_item(body=body)))
    urls = {candidate.safe_resolved_url for candidate in result.candidates}
    counts = result.summary_counts

    assert {
        "http://example.test/single",
        "http://example.test/double",
        "http://example.test/static/app.js",
        "http://example.test/admin/login",
        "http://example.test/api/v1",
        "http://example.test/portal",
        "http://example.test/after-regex",
    } <= urls
    assert "comment" not in repr(result)
    assert "block-comment" not in repr(result)
    assert counts.dynamic_template_strings_skipped == 1
    assert counts.dynamic_concatenation_strings_skipped == 2
    assert counts.malformed_strings_skipped >= 1


def test_mime_shaped_strings_are_not_route_like_but_route_controls_remain() -> None:
    body = b"""
    const mimeA = "application/json";
    const mimeB = "APPLICATION/JSON";
    const mimeC = "text/html";
    const mimeD = "image/svg+xml";
    const mimeE = "application/json; charset=utf-8";
    const routeA = "api/users";
    const routeB = "application/users/list";
    const routeC = "text/help/index.html";
    const routeD = "/application/json";
    const routeE = "./application/json";
    const routeF = "../application/json";
    """

    result = build_deep_javascript_route_extraction(_result(_js_item(body=body)))
    candidates = {candidate.safe_candidate for candidate in result.candidates}
    public_text = repr(result)

    assert {
        "api/users",
        "application/users/list",
        "text/help/index.html",
        "/application/json",
        "./application/json",
        "../application/json",
    } <= candidates
    for rejected in (
        "application/json",
        "APPLICATION/JSON",
        "text/html",
        "image/svg+xml",
        "application/json; charset=utf-8",
    ):
        assert rejected not in candidates
    assert "APPLICATION/JSON" not in public_text
    assert "image/svg+xml" not in public_text
    assert "application/json; charset=utf-8" not in public_text
    assert result.summary_counts.not_route_like_strings_skipped == 5


def test_unknown_and_incomplete_escapes_are_malformed_and_not_emitted() -> None:
    body = br'''
    const badA = "\q";
    const badB = "/api\qusers";
    const badC = "\x";
    const badD = "\x2";
    const badE = "\xZZ";
    const badF = "\u";
    const badG = "\u12";
    const badH = "\u12ZZ";
    const badI = "/line\
continued";
    const goodA = "\\";
    const goodB = "\/";
    const goodC = "\'";
    const goodD = "\"";
    const goodE = "\x2fapi\x2fgood";
    const goodF = "\u002fportal";
    '''

    result = build_deep_javascript_route_extraction(_result(_js_item(body=body)))
    public_text = repr(result)
    urls = {candidate.safe_resolved_url for candidate in result.candidates}

    assert "http://example.test/api/good" in urls
    assert "http://example.test/portal" in urls
    for rejected in ("apiqusers", "linecontinued", "\\q", "\\xZZ", "\\u12ZZ"):
        assert rejected not in public_text
    assert result.summary_counts.malformed_strings_skipped >= 9


def test_regex_literal_contexts_do_not_emit_route_like_quoted_text() -> None:
    body = br'''
    /"\/start-regex"/;
    function a() { return /"\/return-regex"/; }
    function b() { throw /'\/throw-regex'/; }
    switch (value) { case /"\/case-regex"/: break; }
    function* c() { yield /"\/yield-regex"/; }
    async function d() { await /'\/await-regex'/; }
    const fn = () => /'\/arrow-regex'/;
    const choice = value ? /"\/yes-regex"/ : /'\/no-regex'/;
    const classRegex = /["']\/class-regex["']/;
    const escapedSlash = /"\/escaped-regex"/;
    const ratio = total / count;
    const route = "/after-division";
    const after = "/after-regexes";
    '''

    result = build_deep_javascript_route_extraction(_result(_js_item(body=body)))
    public_text = repr(result)
    urls = {candidate.safe_resolved_url for candidate in result.candidates}

    assert "http://example.test/after-division" in urls
    assert "http://example.test/after-regexes" in urls
    for rejected in (
        "start-regex",
        "return-regex",
        "throw-regex",
        "case-regex",
        "yield-regex",
        "await-regex",
        "arrow-regex",
        "yes-regex",
        "no-regex",
        "class-regex",
        "escaped-regex",
    ):
        assert rejected not in public_text


def test_candidate_classification_resolution_and_query_sanitisation() -> None:
    body = b"""
    const abs = "https://alice:hunter2@[2001:db8::1]:8443/api?token=secret&state=value&=empty#frag-secret";
    const scheme = "//cdn.example.test/app.js?ver=secret";
    const root = "/api/v1/accounts?token=first";
    const emptyQueryName = "/ignored?=secret";
    const query = "?view=compact&debug=true";
    const emptyQueryRelative = "?=secret";
    const dot = "./local.js";
    const parent = "../admin/login";
    const path = "api/v2/list";
    const suffix = "status.json";
    const fragment = "#section";
    const js = "javascript:void(0)";
    const data = "data:text/plain,secret";
    const hello = "hello";
    const ui = "button-primary";
    """

    result = build_deep_javascript_route_extraction(_result(_js_item(url="http://example.test/assets/app.js", body=body)))
    public_text = repr(result) + render_deep_javascript_route_extraction_markdown(result)
    by_candidate = {candidate.safe_candidate: candidate for candidate in result.candidates}

    assert "https://[2001:db8::1]:8443/api?state&token" in by_candidate
    assert by_candidate["https://[2001:db8::1]:8443/api?state&token"].safe_resolved_url == "https://[2001:db8::1]:8443/api?state&token"
    assert by_candidate["//cdn.example.test/app.js?ver"].safe_resolved_url == "http://cdn.example.test/app.js?ver"
    assert by_candidate["/api/v1/accounts?token"].safe_resolved_url == "http://example.test/api/v1/accounts?token"
    assert "/ignored" in by_candidate
    assert by_candidate["?debug&view"].safe_resolved_url == "http://example.test/assets/app.js?debug&view"
    assert "?" not in by_candidate
    assert by_candidate["./local.js"].safe_resolved_url is None
    assert by_candidate["../admin/login"].resolution_contexts == ("execution_context_unknown",)
    assert by_candidate["api/v2/list"].safe_resolved_url is None
    assert by_candidate["status.json"].safe_resolved_url is None
    for sensitive in ("alice", "hunter2", "secret", "state=value", "frag-secret", "token=secret", "debug=true"):
        assert sensitive not in public_text
    assert result.summary_counts.fragment_only_strings_skipped == 1
    assert result.summary_counts.unsupported_scheme_strings_skipped == 2
    assert result.summary_counts.not_route_like_strings_skipped == 3
    assert result.summary_counts.unresolved_relative_candidates_retained >= 4


def test_inline_relative_resolution_and_base_href_rules() -> None:
    valid_base = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='/app/'><script>const r = 'api/users';</script>"))
    )
    cross_base = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='https://cdn.example.test/root/'><script>const r = './asset.js';</script>"))
    )
    ignored_base = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='javascript:void(0)'><script>const r = 'local.js';</script>"))
    )
    invalid_then_valid = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='javascript:void(0)'><base href='/valid/'><script>const r = 'x.js';</script>"))
    )
    malformed_then_valid = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='://malformed'><base href='https://cdn.example.test/assets/'><script>const r = 'x.js';</script>"))
    )
    invalid_authority_then_valid = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='//[invalid'><base href='https://cdn.example.test/assets/'><script>const route = 'app.js';</script>"))
    )
    invalid_authority_fallback = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='http://[invalid'><script>const route = 'app.js';</script>"))
    )
    first_only = build_deep_javascript_route_extraction(
        _result(_html_item(body=b"<html><base href='/first/'><base href='/second/'><script>const r = 'x.js';</script>"))
    )

    assert valid_base.candidates[0].safe_resolved_url == "http://example.test/app/api/users"
    assert valid_base.candidates[0].resolution_contexts == ("html_base_url",)
    assert cross_base.candidates[0].safe_resolved_url == "https://cdn.example.test/root/asset.js"
    assert ignored_base.candidates[0].safe_resolved_url == "http://example.test/local.js"
    assert invalid_then_valid.candidates[0].safe_resolved_url == "http://example.test/valid/x.js"
    assert malformed_then_valid.candidates[0].safe_resolved_url == "https://cdn.example.test/assets/x.js"
    assert invalid_authority_then_valid.candidates[0].safe_resolved_url == "https://cdn.example.test/assets/app.js"
    assert invalid_authority_then_valid.candidates[0].resolution_contexts == ("html_base_url",)
    assert invalid_authority_then_valid.summary_counts.html_responses_using_valid_base_url == 1
    assert invalid_authority_fallback.candidates[0].safe_resolved_url == "http://example.test/app.js"
    assert invalid_authority_fallback.candidates[0].resolution_contexts == ("html_document_url",)
    assert invalid_authority_fallback.summary_counts.html_responses_using_valid_base_url == 0
    assert first_only.candidates[0].safe_resolved_url == "http://example.test/first/x.js"
    assert first_only.summary_counts.html_responses_using_valid_base_url == 1


def test_protocol_relative_candidates_resolve_with_trusted_source_scheme() -> None:
    body = b'const same = "//example.test/api"; const cross = "//external.test/api";'

    result = build_deep_javascript_route_extraction(
        _result(_js_item(url="https://example.test/app.js", body=body))
    )

    by_candidate = {candidate.safe_candidate: candidate for candidate in result.candidates}
    assert by_candidate["//example.test/api"].safe_resolved_url == "https://example.test/api"
    assert by_candidate["//external.test/api"].safe_resolved_url == "https://external.test/api"


def test_aggregation_occurrence_counts_and_canonical_fields() -> None:
    result = build_deep_javascript_route_extraction(
        _result(
            _js_item(url="http://example.test/a.js", body=b'const a="/account?token=first"; const b="/account?token=second";', evidence_ids=("EVID-B",)),
            _js_item(url="http://example.test/b.js", body=b"const c='/account?token=third';", evidence_ids=("EVID-A",)),
        )
    )

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.safe_candidate == "/account?token"
    assert candidate.safe_resolved_url == "http://example.test/account?token"
    assert candidate.occurrence_count == 3
    assert candidate.evidence_ids == ("EVID-A", "EVID-B")
    assert candidate.source_kinds == ("javascript_response",)
    assert result.summary_counts.duplicate_accepted_occurrences_aggregated == 2


def test_candidate_ordering_ids_and_reversed_input_are_deterministic() -> None:
    first = _js_item(url="http://example.test/b.js", body=b'const b="/b"; const a="/a";', evidence_ids=("EVID-B",))
    second = _html_item(url="http://example.test/a", body=b"<html><script>const c='/c'; const a='/a';</script>", evidence_ids=("EVID-A",))

    normal = build_deep_javascript_route_extraction(_result(first, second))
    reversed_result = build_deep_javascript_route_extraction(_result(second, first))

    assert reversed_result == normal
    assert tuple(candidate.candidate_id for candidate in normal.candidates) == (
        "DEEP-JS-ROUTE-0001",
        "DEEP-JS-ROUTE-0002",
        "DEEP-JS-ROUTE-0003",
        "DEEP-JS-ROUTE-0004",
    )


def test_source_response_ids_are_deterministic_across_complete_sort_ties() -> None:
    javascript = _item(
        url="http://example.test/same",
        headers=(("Content-Type", "application/javascript"), ("X-Test", "one")),
        body=b'const route = "/stable";',
        evidence_ids=("EVID-B", "EVID-A"),
    )
    skipped = _item(
        url="http://example.test/same",
        headers=(("X-Test", "two"), ("Content-Type", "text/plain")),
        body=b'const route = "/skipped-route";',
        evidence_ids=("EVID-A", "EVID-B"),
    )

    normal = build_deep_javascript_route_extraction(_result(javascript, skipped))
    reversed_result = build_deep_javascript_route_extraction(_result(skipped, javascript))

    assert reversed_result == normal
    assert render_deep_javascript_route_extraction_markdown(reversed_result) == (
        render_deep_javascript_route_extraction_markdown(normal)
    )
    assert normal.candidates[0].source_response_ids == ("DEEP-JS-SRC-0001",)
    assert "skipped-route" not in repr(normal)


def test_summary_counts_are_correct() -> None:
    result = build_deep_javascript_route_extraction(
        _result(
            _js_item(body=b'const a="/a"; const b="#frag"; const c="javascript:void(0)"; const d="hello"; const e=`/x/${id}`; const f="/p/"+id;'),
            _html_item(body=b"<html><script>const g='/g';</script><script type='application/json'>{}</script>"),
            _item(url="http://example.test/plain", headers=(), body=b"plain"),
        )
    )
    counts = result.summary_counts

    assert counts.total_collected_responses_considered == 3
    assert counts.javascript_responses_selected_by_content_type == 1
    assert counts.html_responses_selected_for_inline_scripts == 1
    assert counts.non_javascript_non_html_responses_skipped == 1
    assert counts.javascript_response_bodies_scanned == 1
    assert counts.inline_script_blocks_considered == 2
    assert counts.inline_javascript_blocks_scanned == 1
    assert counts.accepted_static_route_occurrences == 2
    assert counts.unique_aggregated_candidates == 2
    assert counts.fragment_only_strings_skipped == 1
    assert counts.unsupported_scheme_strings_skipped == 1
    assert counts.not_route_like_strings_skipped == 1
    assert counts.dynamic_template_strings_skipped == 1
    assert counts.dynamic_concatenation_strings_skipped == 1


def test_renderer_sections_compaction_cautions_and_prohibited_wording() -> None:
    result = build_deep_javascript_route_extraction(
        _result(
            _js_item(
                body=(
                    "const routes = ["
                    + ",".join(f"'/long-{index}-{'x' * 140}'" for index in range(8))
                    + "];"
                ).encode(),
                evidence_ids=tuple(f"EVID-{index}" for index in range(8)),
            )
        )
    )
    rendered = render_deep_javascript_route_extraction_markdown(result)

    for expected in (
        "## Deep JavaScript Route Extraction",
        "### Summary",
        "### Extracted Static JavaScript Route Candidates",
        "### Extraction Interpretation Notes",
        "### Safety Notes",
        "offline lexical inspection of full JavaScript and inline-script bodies",
        "No JavaScript was executed.",
        "No expression was evaluated.",
        "No route was requested or followed.",
        "No network request was made.",
        "Query values, URL credentials, and fragment contents are not retained.",
        "Relative strings from JavaScript responses may lack reliable browser execution context.",
        "Forms are not inventoried.",
        "This stage produces static manual-review context only.",
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


def test_sensitive_values_and_full_bodies_never_enter_public_output() -> None:
    body = b"""
    const a = "https://alice:hunter2@example.test/api?token=secret#frag-secret";
    const b = "/safe";
    const notPublic = "FULL_JS_BODY_SECRET";
    """
    result = build_deep_javascript_route_extraction(_result(_js_item(body=body)))
    rendered = render_deep_javascript_route_extraction_markdown(result)
    public_text = repr(result) + rendered

    assert "https://example.test/api?token" in public_text
    for sensitive in ("alice", "hunter2", "secret", "frag-secret", "token=secret", "FULL_JS_BODY_SECRET"):
        assert sensitive not in public_text


def test_builder_renderer_add_no_io_network_execution_browser_or_form_inventory() -> None:
    source = inspect.getsource(extraction_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.",
        "httpx.",
        "socket.",
        "subprocess",
        "selenium",
        "playwright",
        "collect_deep_source_routes_from_plan",
        "urllib_deep_http_fetcher",
        "form_inventory",
    ):
        assert forbidden not in source


def test_source_route_export_remains_full_body_free() -> None:
    from bugslyce.recon.deep_source_route_collection_export import (
        deep_source_route_collection_result_to_dict,
    )

    result = _result(_js_item(body=(b"A" * 600) + b"FULL_BODY_EXPORT_SECRET"))
    payload = deep_source_route_collection_result_to_dict(result)

    assert "FULL_BODY_EXPORT_SECRET" not in repr(payload)
    assert "body" not in payload["collected"][0]


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _result(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _js_item(
    *,
    url: str = "http://example.test/app.js",
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/javascript"),),
    body: bytes = b"const route = '/api';",
    body_preview: str = "",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    return _item(
        url=url,
        headers=headers,
        body=body,
        body_preview=body_preview,
        evidence_ids=evidence_ids,
    )


def _html_item(
    *,
    url: str = "http://example.test/page",
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html><script>const route = '/api';</script></html>",
    body_preview: str = "",
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    return _item(
        url=url,
        headers=headers,
        body=body,
        body_preview=body_preview,
        evidence_ids=evidence_ids,
    )


def _item(
    *,
    url: str,
    headers: tuple[tuple[str, str], ...],
    body: bytes,
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
