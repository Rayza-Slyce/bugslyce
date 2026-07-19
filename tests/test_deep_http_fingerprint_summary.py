"""Tests for offline Deep HTTP fingerprint summaries."""

from __future__ import annotations

import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_http_fingerprint_summary import (
    EMPTY_BODY_SHA256,
    DeepHttpFingerprintSummaryCounts,
    build_deep_http_fingerprint_summary,
    render_deep_http_fingerprint_summary_markdown,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
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
import bugslyce.recon.deep_http_fingerprint_summary as fingerprint_module


def test_empty_inputs_produce_safe_empty_summary() -> None:
    metadata = _metadata_result()
    source = _source_result()

    summary = build_deep_http_fingerprint_summary(metadata, source)
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert summary.fingerprints == ()
    assert summary.repeated_body_groups == ()
    assert summary.summary_counts == DeepHttpFingerprintSummaryCounts(
        total_collected_responses=0,
        metadata_responses=0,
        source_route_responses=0,
        responses_2xx=0,
        responses_3xx=0,
        responses_4xx=0,
        responses_5xx=0,
        responses_other_status=0,
        responses_with_title_observed_in_bounded_preview=0,
        responses_setting_cookies=0,
        exact_repeated_non_empty_body_groups=0,
    )
    assert rendered.startswith("## Deep HTTP Fingerprint Summary\n")
    assert "### Summary" in rendered
    assert "### Response Fingerprints" in rendered
    assert "### Exact Repeated Body Hashes" in rendered
    assert "### Header Interpretation Notes" in rendered
    assert "### Safety Notes" in rendered
    assert "No collection or network activity is performed by this summary." in rendered
    assert "This stage produces static manual-review context only." in rendered


def test_input_results_are_not_mutated() -> None:
    metadata = _metadata_result(
        _metadata_item(
            url="http://example.test/robots.txt",
            headers=(("Content-Type", "text/plain"),),
        )
    )
    source = _source_result(
        _source_item(
            url="http://example.test/index.html",
            headers=(("Content-Type", "text/html"),),
        )
    )
    before = (metadata, source)

    build_deep_http_fingerprint_summary(metadata, source)

    assert (metadata, source) == before


def test_metadata_only_source_only_and_combined_counts() -> None:
    metadata_item = _metadata_item(
        url="http://example.test/robots.txt",
        status_code=200,
        headers=(("Content-Type", "text/plain"),),
    )
    source_item = _source_item(
        url="http://example.test/portal.php",
        status_code=302,
        headers=(("Location", "/login.php"),),
    )

    metadata_only = build_deep_http_fingerprint_summary(
        _metadata_result(metadata_item),
        _source_result(),
    )
    source_only = build_deep_http_fingerprint_summary(
        _metadata_result(),
        _source_result(source_item),
    )
    combined = build_deep_http_fingerprint_summary(
        _metadata_result(metadata_item),
        _source_result(source_item),
    )

    assert metadata_only.summary_counts.metadata_responses == 1
    assert metadata_only.summary_counts.source_route_responses == 0
    assert source_only.summary_counts.metadata_responses == 0
    assert source_only.summary_counts.source_route_responses == 1
    assert combined.summary_counts.total_collected_responses == 2
    assert combined.summary_counts.responses_2xx == 1
    assert combined.summary_counts.responses_3xx == 1


def test_fingerprints_are_sorted_deterministically_and_ids_follow_sort_order() -> None:
    metadata = _metadata_result(
        _metadata_item(
            url="http://example.test/z",
            status_code=200,
            body_sha256="hash-z",
        )
    )
    source = _source_result(
        _source_item(
            url="http://example.test/a",
            status_code=404,
            body_sha256="hash-a",
        ),
        _source_item(
            url="http://example.test/z",
            status_code=500,
            body_sha256="hash-z-source",
        ),
    )

    first = build_deep_http_fingerprint_summary(metadata, source)
    second = build_deep_http_fingerprint_summary(metadata, source)

    assert first == second
    assert tuple(fp.requested_url for fp in first.fingerprints) == (
        "http://example.test/a",
        "http://example.test/z",
        "http://example.test/z",
    )
    assert tuple(fp.collection_section for fp in first.fingerprints) == (
        "source_route_collection",
        "metadata_collection",
        "source_route_collection",
    )
    assert tuple(fp.fingerprint_id for fp in first.fingerprints) == (
        "DEEP-HTTP-FP-0001",
        "DEEP-HTTP-FP-0002",
        "DEEP-HTTP-FP-0003",
    )


def test_fingerprint_tie_breakers_do_not_depend_on_input_tuple_order() -> None:
    first_item = _metadata_item(
        url="http://example.test/same",
        status_code=200,
        final_url="http://example.test/same",
        headers=(("Server", "Zulu"),),
        body_sha256="same-hash",
        body_bytes=200,
        evidence_ids=("EVID-Z",),
    )
    second_item = _metadata_item(
        url="http://example.test/same",
        status_code=200,
        final_url="http://example.test/same",
        headers=(("Server", "Alpha"),),
        body_sha256="same-hash",
        body_bytes=100,
        evidence_ids=("EVID-A",),
    )

    normal = build_deep_http_fingerprint_summary(
        _metadata_result(first_item, second_item),
        _source_result(),
    )
    reversed_summary = build_deep_http_fingerprint_summary(
        _metadata_result(second_item, first_item),
        _source_result(),
    )

    normal_details = tuple(
        (fingerprint.fingerprint_id, fingerprint.server, fingerprint.body_bytes, fingerprint.evidence_ids)
        for fingerprint in normal.fingerprints
    )
    reversed_details = tuple(
        (fingerprint.fingerprint_id, fingerprint.server, fingerprint.body_bytes, fingerprint.evidence_ids)
        for fingerprint in reversed_summary.fingerprints
    )

    assert normal_details == reversed_details
    assert normal_details == (
        ("DEEP-HTTP-FP-0001", "Alpha", 100, ("EVID-A",)),
        ("DEEP-HTTP-FP-0002", "Zulu", 200, ("EVID-Z",)),
    )


def test_status_buckets_and_counts_cover_all_status_classes() -> None:
    summary = build_deep_http_fingerprint_summary(
        _metadata_result(
            _metadata_item(url="http://example.test/ok", status_code=200),
            _metadata_item(url="http://example.test/redirect", status_code=301),
            _metadata_item(url="http://example.test/client", status_code=403),
            _metadata_item(url="http://example.test/server", status_code=503),
            _metadata_item(url="http://example.test/odd", status_code=102),
        ),
        _source_result(),
    )

    assert tuple(fp.status_bucket for fp in summary.fingerprints) == (
        "4xx_client_error",
        "other_status",
        "2xx_success",
        "3xx_redirect",
        "5xx_server_error",
    )
    assert summary.summary_counts.responses_2xx == 1
    assert summary.summary_counts.responses_3xx == 1
    assert summary.summary_counts.responses_4xx == 1
    assert summary.summary_counts.responses_5xx == 1
    assert summary.summary_counts.responses_other_status == 1


def test_primary_headers_are_matched_case_insensitively() -> None:
    item = _source_item(
        url="https://example.test/redirect",
        status_code=302,
        headers=(
            ("content-type", "TEXT/HTML; Charset=UTF-8"),
            ("SERVER", "Apache"),
            ("lOcAtIoN", "/login.php"),
        ),
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(),
        _source_result(item),
    )
    fingerprint = summary.fingerprints[0]

    assert fingerprint.content_type == "TEXT/HTML; Charset=UTF-8"
    assert fingerprint.server == "Apache"
    assert fingerprint.redirect_location == "/login.php"


def test_complete_titles_are_extracted_and_normalised_from_bounded_preview() -> None:
    item = _metadata_item(
        url="http://example.test/index.html",
        headers=(("Content-Type", "text/html"),),
        body_preview="<html><head><title> Pickle&nbsp;Rick \n Admin </title></head>",
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(item),
        _source_result(),
    )
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert summary.fingerprints[0].title_observed_in_bounded_preview == (
        "Pickle Rick Admin"
    )
    assert summary.summary_counts.responses_with_title_observed_in_bounded_preview == 1
    assert "Title observed in bounded preview: `Pickle Rick Admin`" in rendered
    assert "Titles are extracted only when visible in bounded previews." in rendered


def test_incomplete_title_is_not_claimed() -> None:
    item = _metadata_item(
        url="http://example.test/truncated",
        headers=(("Content-Type", "text/html"),),
        body_preview="<html><head><title>Truncated",
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(item),
        _source_result(),
    )

    assert summary.fingerprints[0].title_observed_in_bounded_preview is None
    assert summary.summary_counts.responses_with_title_observed_in_bounded_preview == 0


def test_cookie_fingerprint_keeps_names_and_attributes_without_values() -> None:
    item = _source_item(
        url="http://example.test/portal.php",
        status_code=302,
        headers=(
            ("Set-Cookie", "PHPSESSID=secret-value; Path=/; HttpOnly"),
            ("set-cookie", "theme=dark; Secure"),
            ("Cookie", "client-secret=should-not-copy"),
            ("Authorization", "Bearer should-not-copy"),
        ),
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(),
        _source_result(item),
    )
    rendered = render_deep_http_fingerprint_summary_markdown(summary)
    fingerprint = summary.fingerprints[0]

    assert fingerprint.set_cookie_present is True
    assert fingerprint.set_cookie_count == 2
    assert fingerprint.cookie_names == ("PHPSESSID", "theme")
    assert fingerprint.cookie_summaries == (
        "PHPSESSID (Path=/; HttpOnly)",
        "theme (Secure)",
    )
    assert summary.summary_counts.responses_setting_cookies == 1
    assert "secret-value" not in repr(summary)
    assert "should-not-copy" not in repr(summary)
    assert "secret-value" not in rendered
    assert "Cookie names: `PHPSESSID`, `theme`" not in rendered
    assert rendered.count("PHPSESSID") == 1
    assert rendered.count("theme") == 1
    assert "PHPSESSID (Path=/; HttpOnly)" in rendered
    assert "theme (Secure)" in rendered
    assert "Raw collection evidence may retain complete Set-Cookie headers" in rendered
    assert "derived human summary omits cookie values" in rendered


def test_cookie_fingerprint_renders_names_only_when_no_attributes_exist() -> None:
    item = _source_item(
        url="http://example.test/session",
        headers=(("Set-Cookie", "session_id=retained-secret-value"),),
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(),
        _source_result(item),
    )
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert "Cookie names: `session_id`" in rendered
    assert "Cookie names and relevant attributes" not in rendered
    assert "retained-secret-value" not in rendered


def test_interesting_headers_are_allowlisted_bounded_and_normalised() -> None:
    long_cache = "private, " + "x" * 180
    item = _metadata_item(
        url="http://example.test/cache",
        headers=(
            ("Cache-Control", f" {long_cache}\n"),
            ("ETag", ' "abc" '),
            ("X-Unrelated-Debug", "do-not-copy"),
            ("Proxy-Authorization", "do-not-copy"),
        ),
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(item),
        _source_result(),
    )
    observations = summary.fingerprints[0].interesting_headers
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert tuple(observation.name for observation in observations) == (
        "Cache-Control",
        "ETag",
    )
    assert observations[0].value.startswith("private,")
    assert "[truncated]" in observations[0].value
    assert "\n" not in observations[0].value
    assert "do-not-copy" not in repr(summary)
    assert "do-not-copy" not in rendered


def test_headers_not_observed_are_contextual_and_cautious() -> None:
    html_http = _source_item(
        url="http://example.test/html",
        headers=(("Content-Type", "text/html"),),
        body_preview="<html><head></head>",
    )
    plain_http = _source_item(
        url="http://example.test/plain",
        headers=(("Content-Type", "text/plain"),),
        body_preview="plain text",
    )
    html_https = _source_item(
        url="https://example.test/html",
        headers=(("Content-Type", "text/html"),),
        body_preview="<html><head></head>",
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(),
        _source_result(html_http, plain_http, html_https),
    )
    by_url = {fingerprint.requested_url: fingerprint for fingerprint in summary.fingerprints}
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert "Content-Security-Policy" in by_url[
        "http://example.test/html"
    ].headers_not_observed
    assert "Strict-Transport-Security" not in by_url[
        "http://example.test/html"
    ].headers_not_observed
    assert by_url["http://example.test/plain"].headers_not_observed == ()
    assert "Strict-Transport-Security" in by_url[
        "https://example.test/html"
    ].headers_not_observed
    assert "not observed in collected response headers" in rendered
    assert "not a vulnerability finding" in rendered


def test_exact_repeated_non_empty_hashes_are_grouped_across_collection_sections() -> None:
    metadata = _metadata_item(
        url="http://example.test/robots.txt",
        body_sha256="same-hash",
        body_bytes=16,
    )
    source = _source_item(
        url="http://example.test/index.html",
        body_sha256="same-hash",
        body_bytes=16,
    )
    empty_one = _metadata_item(
        url="http://example.test/empty-a",
        body_sha256=EMPTY_BODY_SHA256,
        body_bytes=0,
    )
    empty_two = _source_item(
        url="http://example.test/empty-b",
        body_sha256=EMPTY_BODY_SHA256,
        body_bytes=0,
    )

    summary = build_deep_http_fingerprint_summary(
        _metadata_result(metadata, empty_one),
        _source_result(source, empty_two),
    )
    rendered = render_deep_http_fingerprint_summary_markdown(summary)

    assert len(summary.repeated_body_groups) == 1
    group = summary.repeated_body_groups[0]
    assert group.repeated_body_id == "DEEP-HTTP-REP-0001"
    assert group.body_sha256 == "same-hash"
    assert group.count == 2
    assert set(group.collection_sections) == {
        "metadata_collection",
        "source_route_collection",
    }
    assert summary.summary_counts.exact_repeated_non_empty_body_groups == 1
    assert "DEEP-HTTP-REP-0001" in rendered
    assert EMPTY_BODY_SHA256 not in tuple(group.body_sha256 for group in summary.repeated_body_groups)


def test_repeated_group_ordering_is_deterministic() -> None:
    summary = build_deep_http_fingerprint_summary(
        _metadata_result(
            _metadata_item(url="http://example.test/a", body_sha256="hash-b"),
            _metadata_item(url="http://example.test/b", body_sha256="hash-a"),
            _metadata_item(url="http://example.test/c", body_sha256="hash-b"),
            _metadata_item(url="http://example.test/d", body_sha256="hash-a"),
        ),
        _source_result(),
    )

    assert tuple(group.repeated_body_id for group in summary.repeated_body_groups) == (
        "DEEP-HTTP-REP-0001",
        "DEEP-HTTP-REP-0002",
    )
    assert tuple(group.body_sha256 for group in summary.repeated_body_groups) == (
        "hash-a",
        "hash-b",
    )


def test_renderer_compacts_long_values_and_lists() -> None:
    item = _metadata_item(
        url="http://example.test/" + "a" * 180,
        headers=(
            ("Content-Type", "text/html"),
            ("Vary", "Accept-Encoding " + "x" * 180),
        ),
        body_preview="<html><head><title>" + "Long title " * 30 + "</title></head>",
        evidence_ids=tuple(f"EVID-{index}" for index in range(8)),
    )

    rendered = render_deep_http_fingerprint_summary_markdown(
        build_deep_http_fingerprint_summary(
            _metadata_result(item),
            _source_result(),
        )
    )

    assert "... +2 more" in rendered
    assert "[truncated]" in rendered
    assert "Long title " * 20 not in rendered


def test_renderer_avoids_prohibited_exploitation_language() -> None:
    rendered = render_deep_http_fingerprint_summary_markdown(
        build_deep_http_fingerprint_summary(
            _metadata_result(_metadata_item(url="http://example.test/")),
            _source_result(),
        )
    ).lower()

    for forbidden in (
        "confirmed vulnerability",
        "confirmed exposure",
        "insecure",
        "exploitable",
        "authentication bypass",
        "weak headers",
        "missing security headers vulnerability",
        "credentials found",
        "session token",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden not in rendered


def test_builder_renderer_add_no_io_network_or_collector_execution() -> None:
    source = inspect.getsource(fingerprint_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.",
        "httpx.",
        "socket.",
        "collect_deep_metadata_from_plan",
        "collect_deep_source_routes_from_plan",
    ):
        assert forbidden not in source


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _metadata_result(
    *items: DeepMetadataCollectedItem,
) -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _source_result(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _metadata_item(
    *,
    url: str,
    method: str = "GET",
    status_code: int = 200,
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    body_preview: str = "preview",
    body_sha256: str = "body-hash",
    body_bytes: int = 64,
    evidence_ids: tuple[str, ...] = ("EVID-META",),
) -> DeepMetadataCollectedItem:
    return DeepMetadataCollectedItem(
        url=url,
        method=method,
        status_code=status_code,
        final_url=final_url or url,
        headers=headers,
        body_preview=body_preview,
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="metadata_coverage",
        reason="planned_uncollected_metadata",
        evidence_ids=evidence_ids,
    )


def _source_item(
    *,
    url: str,
    method: str = "GET",
    status_code: int = 200,
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    body_preview: str = "preview",
    body_sha256: str = "body-hash",
    body_bytes: int = 64,
    evidence_ids: tuple[str, ...] = ("EVID-SRC",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method=method,
        status_code=status_code,
        final_url=final_url or url,
        headers=headers,
        body_preview=body_preview,
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="discovered_unfetched_application_route",
        evidence_ids=evidence_ids,
    )
