"""Tests for offline Deep source/route collection review summaries."""

from __future__ import annotations

import json

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_source_route_collection_review import (
    build_deep_source_route_collection_review,
    render_deep_source_route_collection_review_markdown,
)
from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_from_dict,
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)
from bugslyce.recon.deep_structured_body_review import (
    render_configuration_excerpt_line,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_status_buckets_group_deterministically() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-200"),
            _collected("http://example.test/portal.php", 302, "hash-302"),
            _collected("http://example.test/server-status", 403, "hash-403"),
            _collected("http://example.test/missing", 404, "hash-404"),
            _collected("http://example.test/error", 500, "hash-500"),
            _collected("http://example.test/early", 102, "hash-102"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert tuple(bucket.name for bucket in summary.status_buckets) == (
        "2xx_success",
        "3xx_redirect",
        "403_forbidden",
        "4xx_client_error",
        "5xx_server_error",
        "other_status",
    )
    assert tuple(bucket.status_codes for bucket in summary.status_buckets) == (
        (200,),
        (302,),
        (403,),
        (404,),
        (500,),
        (102,),
    )
    assert tuple(bucket.count for bucket in summary.status_buckets) == (
        1,
        1,
        1,
        1,
        1,
        1,
    )


def test_portal_redirect_creates_redirect_login_cookie_and_auth_leads() -> None:
    result = _result(
        collected=(
            _collected(
                "http://example.test/portal.php",
                302,
                "hash-portal",
                headers=(
                    ("Location", "/login.php"),
                    ("Set-Cookie", "session=secret; HttpOnly"),
                    ("Content-Type", "text/html"),
                ),
                evidence_ids=("EVID-PORTAL",),
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}
    rendered = render_deep_source_route_collection_review_markdown(summary)

    assert "route_redirect" in categories
    assert "redirect_to_login" in categories
    assert "cookie_set_on_redirect" in categories
    assert "auth_route_response" in categories
    assert "location /login.php" in rendered
    assert "set-cookie present" in rendered
    assert "session=secret" not in rendered


def test_server_status_403_creates_forbidden_and_admin_leads() -> None:
    result = _result(
        collected=(
            _collected(
                "http://example.test/server-status",
                403,
                "hash-status",
                headers=(("Server", "Apache"),),
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}

    assert "403_forbidden" in {bucket.name for bucket in summary.status_buckets}
    assert "forbidden_admin_or_status_route" in categories
    assert "admin_status_route_response" in categories


def test_success_route_creates_route_success() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-index"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert summary.review_leads[0].category == "route_success"
    assert summary.review_leads[0].lead_id == "DEEP-SRC-REV-0001"


def test_valid_nested_json_promotes_only_new_relative_web_routes() -> None:
    body = json.dumps(
        {
            "catalogue": {
                "routes": [
                    "/v2/accounts",
                    {"openings": "/jobs/open"},
                    "/already-known/",
                ]
            },
            "noise": [
                "ordinary prose about a service",
                "550e8400-e29b-41d4-a716-446655440000",
                "/var/lib/application/state",
                "eyJhbGciOiJIUzI1NiJ9.example.signature",
                "https://external.example/reference",
            ],
        }
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/catalogue.json",
                200,
                "hash-json",
                headers=(("Content-Type", "application/json; charset=utf-8"),),
                evidence_ids=("EVID-JSON",),
                body=body,
            ),
            _collected(
                "https://example.test/already-known",
                200,
                "hash-known",
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    lead = next(
        item for item in summary.review_leads
        if item.category == "structured_json_routes"
    )
    rendered = render_deep_source_route_collection_review_markdown(summary)

    assert lead.observed_values == ("/v2/accounts", "/jobs/open")
    assert lead.urls == ("https://example.test/catalogue.json",)
    assert lead.evidence_ids == ("EVID-JSON",)
    assert lead.source_body_sha256 == "hash-json"
    assert lead.signals == ()
    assert "Directly observed values: `/v2/accounts`, `/jobs/open`" in rendered
    assert rendered.count("`/v2/accounts`") == 1
    assert "/already-known/" not in lead.observed_values
    assert "/var/lib/application/state" not in rendered
    assert "not requested by this review" in lead.reason


def test_json_shaped_plaintext_is_parsed_and_known_routes_are_origin_specific() -> None:
    body = json.dumps(
        {"links": ["/shared", "/new-route"]},
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://api.example.test/catalogue",
                200,
                "hash-catalogue",
                headers=(("Content-Type", "text/plain"),),
                evidence_ids=("EVID-CATALOGUE",),
                body=body,
            ),
            _collected(
                "https://other.example.test/shared",
                200,
                "hash-other",
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    lead = next(
        item
        for item in summary.review_leads
        if item.category == "structured_json_routes"
    )

    assert lead.observed_values == ("/shared", "/new-route")
    assert lead.urls == ("https://api.example.test/catalogue",)
    assert lead.evidence_ids == ("EVID-CATALOGUE",)
    assert summary.total_collected == result.total_collected
    assert result.collected[0].body == body


def test_small_json_disclosure_survives_collection_json_round_trip() -> None:
    body = json.dumps(
        {"navigation": {"routes": ["/service/accounts", "/service/activity"]}}
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/navigation.json",
                200,
                "hash-round-trip-json",
                headers=(("Content-Type", "application/json"),),
                evidence_ids=("EVID-ROUND-TRIP-JSON",),
                body=body,
            ),
        )
    )

    payload = deep_source_route_collection_result_to_dict(result)
    rebuilt = deep_source_route_collection_result_from_dict(payload)
    before = build_deep_source_route_collection_review(result)
    after = build_deep_source_route_collection_review(rebuilt)

    assert before == after
    assert rebuilt.collected[0].body == b""
    assert "body" not in payload["collected"][0]
    assert next(
        lead for lead in after.review_leads if lead.category == "structured_json_routes"
    ).observed_values == ("/service/accounts", "/service/activity")


def test_small_configuration_disclosure_survives_collection_json_round_trip() -> None:
    body = b"""Listen 8443
ServerName edge.example.test
DocumentRoot /srv/application/current
"""
    result = _result(
        collected=(
            _collected(
                "https://example.test/runtime.txt",
                200,
                "hash-round-trip-config",
                headers=(("Content-Type", "text/plain"),),
                evidence_ids=("EVID-ROUND-TRIP-CONFIG",),
                body=body,
            ),
        )
    )

    rebuilt = deep_source_route_collection_result_from_dict(
        deep_source_route_collection_result_to_dict(result)
    )
    before = build_deep_source_route_collection_review(result)
    after = build_deep_source_route_collection_review(rebuilt)

    assert before == after
    assert next(
        lead
        for lead in after.review_leads
        if lead.category == "structured_configuration_body"
    ).evidence_excerpt == (
        "Listen 8443",
        "ServerName edge.example.test",
        "DocumentRoot /srv/application/current",
    )


def test_route_beyond_retained_preview_is_not_promoted() -> None:
    body = json.dumps(
        {
            "retained_padding": "x" * 520,
            "routes": ["/outside-retained-preview"],
        }
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/large.json",
                200,
                "hash-large-json",
                headers=(("Content-Type", "application/json"),),
                body=body,
                body_preview=body[:500].decode(),
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert "/outside-retained-preview" not in repr(summary)
    assert "structured_json_routes" not in {
        lead.category for lead in summary.review_leads
    }


def test_malformed_or_non_route_json_does_not_invent_disclosures() -> None:
    malformed = b'{"routes": ["/would-be-route"'
    malformed_plaintext = b'{"settings": [\nserver_name = edge.example\ndocument_root = /srv/web\n'
    non_routes = json.dumps(
        {
            "message": "ordinary prose",
            "token": "aB3dE5fG7hJ9kL2mN4pQ6rS8tV0xYz",
            "identifier": "550e8400-e29b-41d4-a716-446655440000",
            "filesystem": "/etc/application/settings",
        }
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/broken.json",
                200,
                "hash-broken",
                headers=(("Content-Type", "application/json"),),
                body=malformed,
            ),
            _collected(
                "https://example.test/data.json",
                200,
                "hash-data",
                headers=(("Content-Type", "application/json"),),
                body=non_routes,
            ),
            _collected(
                "https://example.test/broken-plaintext",
                200,
                "hash-broken-plaintext",
                headers=(("Content-Type", "text/plain"),),
                body=malformed_plaintext,
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert "structured_json_routes" not in {
        lead.category for lead in summary.review_leads
    }
    assert "structured_configuration_body" not in {
        lead.category for lead in summary.review_leads
    }


def test_json_route_extraction_is_bounded_and_deterministic() -> None:
    body = json.dumps(
        {"routes": [f"/r/{index}" for index in range(40)]}
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/routes",
                200,
                "hash-routes",
                headers=(("Content-Type", "application/json"),),
                body=body,
            ),
        )
    )

    first = build_deep_source_route_collection_review(result)
    second = build_deep_source_route_collection_review(result)
    lead = next(
        item for item in first.review_leads
        if item.category == "structured_json_routes"
    )

    assert first == second
    assert len(lead.observed_values) == 32
    assert lead.observed_values[0] == "/r/0"
    assert lead.observed_values[-1] == "/r/31"


def test_coherent_configuration_plaintext_is_direct_evidence() -> None:
    body = b"""[application]
service_name = edge_gateway
listen_port = 8443
document_root = /srv/web/current
HandlerMap .action application/x-action
"""
    result = _result(
        collected=(
            _collected(
                "https://example.test/runtime.conf",
                200,
                "hash-config",
                headers=(("Content-Type", "text/plain"),),
                evidence_ids=("EVID-CONFIG",),
                body=body,
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    lead = next(
        item for item in summary.review_leads
        if item.category == "structured_configuration_body"
    )
    rendered = render_deep_source_route_collection_review_markdown(summary)

    assert lead.urls == ("https://example.test/runtime.conf",)
    assert lead.evidence_ids == ("EVID-CONFIG",)
    assert "document_root = /srv/web/current" in lead.evidence_excerpt
    assert lead.signals == ()
    assert rendered.count("`document_root = /srv/web/current`") == 1
    assert "Structured operational configuration observed" in rendered
    assert "not a vulnerability or exploitability conclusion" in lead.reason


def test_three_coherent_directive_lines_are_configuration_evidence() -> None:
    body = b"""Listen 8080
ServerName portal.example.test
DocumentRoot /srv/portal/current
"""
    summary = build_deep_source_route_collection_review(
        _result(
            collected=(
                _collected(
                    "https://example.test/service-settings",
                    200,
                    "hash-directives",
                    headers=(("Content-Type", "text/plain"),),
                    body=body,
                ),
            )
        )
    )

    lead = next(
        item
        for item in summary.review_leads
        if item.category == "structured_configuration_body"
    )
    assert lead.evidence_excerpt == (
        "Listen 8080",
        "ServerName portal.example.test",
        "DocumentRoot /srv/portal/current",
    )


def test_record_assignments_and_numbered_prose_are_not_configuration() -> None:
    bodies = (
        b"name = Alice\nage = 34\nscore = 100\n",
        b"The first report contains 12 rows.\nThe second contains 45 rows.\nThe total is 57 rows.\n",
    )
    result = _result(
        collected=tuple(
            _collected(
                f"https://example.test/text-{index}.txt",
                200,
                f"hash-text-{index}",
                headers=(("Content-Type", "text/plain"),),
                body=body,
            )
            for index, body in enumerate(bodies, start=1)
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert "structured_configuration_body" not in {
        lead.category for lead in summary.review_leads
    }


def test_secret_configuration_values_are_redacted_only_in_review_output() -> None:
    secret = "target-derived-secret-value-4821"
    body = (
        "server_name = edge.example.test\n"
        "listen_port = 8443\n"
        f"api_token = {secret}\n"
        "document_root = /srv/application/current\n"
    ).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/runtime-settings",
                200,
                "hash-secret-config",
                headers=(("Content-Type", "text/plain"),),
                body=body,
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    rendered = render_deep_source_route_collection_review_markdown(summary)
    lead = next(
        item
        for item in summary.review_leads
        if item.category == "structured_configuration_body"
    )

    assert secret in result.collected[0].body.decode()
    assert secret in result.collected[0].body_preview
    assert secret not in rendered
    assert secret not in repr(lead)
    assert "api_token = [REDACTED]" in lead.evidence_excerpt
    assert "document_root = /srv/application/current" in lead.evidence_excerpt


def test_configuration_redactor_handles_common_secret_key_shapes_and_markdown() -> None:
    lines = (
        "password = hidden-value",
        "PASSWD: hidden-value",
        "api key = hidden-value",
        "private_key=hidden-value",
        "Authorization: Bearer hidden-value",
        "cookie session-value",
        "session_token = hidden-value`injection",
    )

    rendered = tuple(render_configuration_excerpt_line(line) for line in lines)

    assert all("[REDACTED]" in line for line in rendered)
    assert all("hidden-value" not in line for line in rendered)
    assert all("`" not in line for line in rendered)


def test_structured_lead_preserves_requested_and_redirected_response_urls() -> None:
    body = json.dumps({"routes": ["/service/health"]}).encode()
    result = _result(
        collected=(
            _collected(
                "https://example.test/catalogue",
                200,
                "hash-redirect-json",
                final_url="https://example.test/catalogue/",
                headers=(("Content-Type", "application/json"),),
                body=body,
            ),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    rendered = render_deep_source_route_collection_review_markdown(summary)
    lead = next(
        item for item in summary.review_leads if item.category == "structured_json_routes"
    )

    assert lead.urls == ("https://example.test/catalogue",)
    assert lead.final_urls == ("https://example.test/catalogue/",)
    assert "Final response URLs: `https://example.test/catalogue/`" in rendered


def test_prose_default_html_and_static_source_are_not_configuration() -> None:
    values = (
        (
            "https://example.test/readme.txt",
            (("Content-Type", "text/plain"),),
            b"This service provides documentation.\nRead each section before use.\nNo settings are published here.",
        ),
        (
            "https://example.test/",
            (("Content-Type", "text/html"),),
            b"<html><title>Welcome</title><body>This is a default landing page.</body></html>",
        ),
        (
            "https://example.test/assets/site.css",
            (("Content-Type", "text/css"),),
            b"body { color: #222; }\nmain { display: block; }\na { text-decoration: none; }",
        ),
    )
    result = _result(
        collected=tuple(
            _collected(
                url,
                200,
                f"hash-{index}",
                headers=headers,
                body=body,
            )
            for index, (url, headers, body) in enumerate(values, start=1)
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert "structured_configuration_body" not in {
        lead.category for lead in summary.review_leads
    }


def test_high_signal_leads_are_ordered_before_generic_success() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/index.html", 200, "hash-index"),
            _collected(
                "http://example.test/portal.php",
                302,
                "hash-portal",
                headers=(
                    ("Location", "/login.php"),
                    ("Set-Cookie", "session=secret; HttpOnly"),
                ),
            ),
            _collected("http://example.test/server-status", 403, "hash-status"),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = tuple(lead.category for lead in summary.review_leads)
    success_index = categories.index("route_success")

    assert categories[:7] == (
        "redirect_to_login",
        "cookie_set_on_redirect",
        "auth_route_response",
        "forbidden_admin_or_status_route",
        "admin_status_route_response",
        "route_redirect",
        "route_success",
    )
    assert all(
        categories.index(category) < success_index
        for category in (
            "redirect_to_login",
            "cookie_set_on_redirect",
            "auth_route_response",
            "forbidden_admin_or_status_route",
            "admin_status_route_response",
            "route_redirect",
        )
    )
    assert tuple(lead.lead_id for lead in summary.review_leads[:7]) == (
        "DEEP-SRC-REV-0001",
        "DEEP-SRC-REV-0002",
        "DEEP-SRC-REV-0003",
        "DEEP-SRC-REV-0004",
        "DEEP-SRC-REV-0005",
        "DEEP-SRC-REV-0006",
        "DEEP-SRC-REV-0007",
    )


def test_repeated_non_empty_body_hash_creates_signature_and_lead() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/a", 200, "same-hash"),
            _collected("http://example.test/b", 200, "same-hash"),
            _collected("http://example.test/c", 200, "other-hash"),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert len(summary.body_signatures) == 1
    assert summary.body_signatures[0].body_sha256 == "same-hash"
    assert summary.body_signatures[0].count == 2
    assert summary.body_signatures[0].urls == (
        "http://example.test/a",
        "http://example.test/b",
    )
    assert "repeated_body_signature" in {
        lead.category for lead in summary.review_leads
    }


def test_empty_body_creates_lead_but_not_repeated_signature() -> None:
    result = _result(
        collected=(
            _collected("http://example.test/redirect-a", 302, "empty-hash", body_bytes=0),
            _collected("http://example.test/redirect-b", 302, "empty-hash", body_bytes=0),
        )
    )

    summary = build_deep_source_route_collection_review(result)

    assert summary.body_signatures == ()
    assert "empty_body_response" in {lead.category for lead in summary.review_leads}


def test_skip_reason_leads_and_counts_are_deterministic() -> None:
    result = _result(
        skipped=(
            _skipped("http://example.test/assets?C=N", "query_string_not_allowed"),
            _skipped("http://example.test/assets?C=M", "query_string_not_allowed"),
            _skipped("http://example.test/robots.txt", "metadata_request"),
            _skipped("https://other.test/admin", "policy_blocked"),
            _skipped("http://example.test/admin", "fetch_error"),
        )
    )

    summary = build_deep_source_route_collection_review(result)
    categories = {lead.category for lead in summary.review_leads}
    metadata_lead = next(
        lead for lead in summary.review_leads if lead.category == "metadata_request_skipped"
    )

    assert summary.skip_reasons == (
        ("query_string_not_allowed", 2),
        ("fetch_error", 1),
        ("metadata_request", 1),
        ("policy_blocked", 1),
    )
    assert "query_string_route_skipped" in categories
    assert "metadata_request_skipped" in categories
    assert "policy_blocked_skipped" in categories
    assert "fetch_error_skipped" in categories
    assert "metadata is handled by the Deep metadata collection path" in metadata_lead.reason


def test_renderer_sections_compact_urls_safety_and_no_full_body() -> None:
    result = _result(
        collected=tuple(
            _collected(
                f"http://example.test/route-{index}",
                200,
                f"hash-{index}",
                body_preview="FULL_BODY_CONTENT_SHOULD_NOT_RENDER",
            )
            for index in range(8)
        ),
        skipped=(_skipped("http://example.test/assets?C=N", "query_string_not_allowed"),),
    )
    summary = build_deep_source_route_collection_review(result)

    rendered = render_deep_source_route_collection_review_markdown(summary)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Source/Route Collection Review\n")
    assert "### Summary" in rendered
    assert "### Status Buckets" in rendered
    assert "### Review Leads" in rendered
    assert "### Repeated Body Signatures" in rendered
    assert "### Skip Reasons" in rendered
    assert "### Safety Notes" in rendered
    assert "... 2 more" in rendered
    assert "FULL_BODY_CONTENT_SHOULD_NOT_RENDER" not in rendered
    assert "|" not in rendered
    for required in (
        "Offline review only.",
        "No network requests were made by this review.",
        "No crawling was performed.",
        "No forms were submitted.",
        "No authentication was attempted.",
        "No payloads were injected.",
        "This stage produces static manual-review context only.",
    ):
        assert required in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit",
        "confirmed exposure",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
    ):
        assert forbidden not in lowered


def test_input_result_is_not_mutated() -> None:
    result = _result(
        collected=(_collected("http://example.test/index.html", 200, "hash-index"),),
        skipped=(_skipped("http://example.test/robots.txt", "metadata_request"),),
    )
    before = result

    build_deep_source_route_collection_review(result)

    assert result == before


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _result(
    *,
    collected: tuple[DeepSourceRouteCollectedItem, ...] = (),
    skipped: tuple[DeepSourceRouteSkippedItem, ...] = (),
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=collected,
        skipped=skipped,
        total_considered=len(collected) + len(skipped),
        total_collected=len(collected),
        total_skipped=len(skipped),
    )


def _collected(
    url: str,
    status_code: int,
    body_sha256: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body_bytes: int = 128,
    body_preview: str | None = None,
    evidence_ids: tuple[str, ...] = ("EVID-1",),
    body: bytes = b"",
    final_url: str | None = None,
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=final_url or url,
        headers=headers,
        body_preview=(
            body.decode("utf-8", errors="replace")[:500]
            if body_preview is None
            else body_preview
        ),
        body_sha256=body_sha256,
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="unit-test",
        evidence_ids=evidence_ids,
        body=body,
    )


def _skipped(
    url: str,
    reason: str,
    *,
    source: str = "source_route_coverage",
    evidence_ids: tuple[str, ...] = ("EVID-SKIP",),
) -> DeepSourceRouteSkippedItem:
    return DeepSourceRouteSkippedItem(
        url=url,
        method="GET",
        reason=reason,
        source=source,
        evidence_ids=evidence_ids,
    )
