"""Tests for bounded Deep shallow route follow-up planning and collection."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import math

import pytest

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
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.deep_shallow_route_followup import (
    DEFAULT_MAX_REQUESTS,
    DeepShallowRouteFollowupPlan,
    DeepShallowRouteFollowupPlanSummaryCounts,
    DeepShallowRouteFollowupRequest,
    build_deep_shallow_route_followup_plan,
    collect_deep_shallow_route_followups,
    render_deep_shallow_route_followup_plan_markdown,
    render_deep_shallow_route_followup_result_markdown,
)
import bugslyce.recon.deep_shallow_route_followup as followup_module
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_inputs_create_safe_empty_plan_and_result() -> None:
    plan = build_deep_shallow_route_followup_plan(_html_result(), _js_result())
    result = collect_deep_shallow_route_followups(plan, fetcher=_raising_fetcher)

    assert plan.requests == ()
    assert plan.summary_counts.requests_selected == 0
    assert result.collected == ()
    assert result.skipped == ()
    assert result.summary_counts.requests_planned == 0
    assert "## Deep Shallow Route Follow-up Plan" in render_deep_shallow_route_followup_plan_markdown(plan)
    assert "## Deep Shallow Route Follow-up Results" in render_deep_shallow_route_followup_result_markdown(result)


def test_planner_does_not_mutate_inputs_and_selects_same_origin_html() -> None:
    html = _html_result(_html_route(url="http://example.test/admin?token&state"))
    js = _js_result()
    before = (html, js)

    plan = build_deep_shallow_route_followup_plan(html, js)

    assert (html, js) == before
    assert len(plan.requests) == 1
    request = plan.requests[0]
    assert request.request_url == "http://example.test/admin"
    assert request.method == "GET"
    assert request.query_parameter_names == ("state", "token")
    assert request.source_model_kinds == ("html_route",)
    assert plan.summary_counts.requests_with_observed_query_parameter_names == 1


def test_html_cross_origin_not_comparable_malformed_and_static_are_skipped() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(
            _html_route(route_id="H1", url="http://other.test/x", origin="cross_origin"),
            _html_route(route_id="H2", url="unresolved", origin="not_comparable"),
            _html_route(route_id="H3", url="http://example.test/logo.png"),
            _html_route(route_id="H4", url="http://[invalid"),
        ),
        _js_result(),
    )

    assert plan.requests == ()
    reasons = {item.reason for item in plan.skipped}
    assert {"cross_origin", "not_comparable", "low_value_static_suffix", "invalid_url"} <= reasons
    assert plan.summary_counts.cross_origin_skipped == 1
    assert plan.summary_counts.not_comparable_skipped == 1
    assert plan.summary_counts.low_value_static_skipped == 1
    assert plan.summary_counts.invalid_url_skipped == 1


def test_unknown_html_origin_relationship_fails_closed() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/a", origin="same-site")),
        _js_result(),
    )

    assert plan.requests == ()
    assert plan.skipped[0].reason == "invalid_origin_relationship"
    assert plan.summary_counts.invalid_origin_relationship_skipped == 1


def test_javascript_same_origin_rules_and_no_reresolution() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(),
        _js_result(
            _js_candidate(candidate_id="J1", safe_resolved_url="http://example.test/api?token", source_urls=("http://example.test/app.js",)),
            _js_candidate(candidate_id="J2", safe_candidate="../admin", safe_resolved_url=None, contexts=("execution_context_unknown",)),
            _js_candidate(candidate_id="J3", safe_resolved_url="https://example.test/api", source_urls=("http://example.test/app.js",)),
            _js_candidate(candidate_id="J4", safe_resolved_url="http://example.test:8080/api", source_urls=("http://example.test/app.js",)),
            _js_candidate(candidate_id="J5", safe_resolved_url="http://[2001:db8::1]/v1", source_urls=("http://[2001:db8::1]/app.js",)),
        ),
    )

    assert {request.request_url for request in plan.requests} == {
        "http://example.test/api",
        "http://[2001:db8::1]/v1",
    }
    skipped = {(item.source_id, item.reason) for item in plan.skipped}
    assert ("J2", "unresolved_relative") in skipped
    assert ("J3", "cross_origin") in skipped
    assert ("J4", "cross_origin") in skipped
    assert all("../admin" not in request.request_url for request in plan.requests)


def test_javascript_provenance_invalid_cross_and_mixed_sources() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(),
        _js_result(
            _js_candidate(candidate_id="BAD", safe_resolved_url="http://example.test/bad", source_urls=("http://[invalid", "unresolved")),
            _js_candidate(candidate_id="CROSS", safe_resolved_url="http://example.test/cross", source_urls=("http://other.test/app.js",)),
            _js_candidate(
                candidate_id="MIXED",
                safe_resolved_url="http://example.test/mixed",
                source_urls=("http://[invalid", "http://other.test/app.js", "http://example.test/app.js?token=secret#frag"),
            ),
        ),
    )

    assert tuple(request.request_url for request in plan.requests) == ("http://example.test/mixed",)
    assert plan.requests[0].source_request_urls == ("http://example.test/app.js?token", "http://other.test/app.js")
    assert ("BAD", "invalid_url") in {(item.source_id, item.reason) for item in plan.skipped}
    assert ("CROSS", "cross_origin") in {(item.source_id, item.reason) for item in plan.skipped}
    assert "unresolved" not in repr(plan.requests[0])


def test_default_ports_compare_as_same_origin_and_mismatches_cross_origin() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(),
        _js_result(
            _js_candidate(candidate_id="HTTP", safe_resolved_url="http://example.test:80/a", source_urls=("http://example.test/source",)),
            _js_candidate(candidate_id="HTTPS", safe_resolved_url="https://example.test:443/a", source_urls=("https://example.test/source",)),
            _js_candidate(candidate_id="PORT", safe_resolved_url="https://example.test:8443/a", source_urls=("https://example.test/source",)),
        ),
    )

    assert "http://example.test:80/a" in {request.request_url for request in plan.requests}
    assert "https://example.test:443/a" in {request.request_url for request in plan.requests}
    assert ("PORT", "cross_origin") in {(item.source_id, item.reason) for item in plan.skipped}


def test_credentials_query_values_and_fragments_never_enter_public_plan() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(
            _html_route(
                url="https://user:pass@example.test/account?token=secret&state=value#frag",
                source_urls=("https://user:pass@example.test/source?x=secret#frag",),
            )
        ),
        _js_result(),
    )
    public = repr(plan) + render_deep_shallow_route_followup_plan_markdown(plan)

    assert plan.requests[0].request_url == "https://example.test/account"
    assert plan.requests[0].query_parameter_names == ("state", "token")
    for sensitive in ("hunter2", "secret", "frag", "token=secret", "state=value"):
        assert sensitive not in public


def test_html_and_javascript_evidence_for_same_path_aggregates() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/account?token", occurrences=2, evidence=("EVID-B",))),
        _js_result(_js_candidate(candidate_id="J1", safe_resolved_url="http://example.test/account?state", evidence=("EVID-A",))),
    )

    assert len(plan.requests) == 1
    request = plan.requests[0]
    assert request.request_url == "http://example.test/account"
    assert request.source_model_kinds == ("html_route", "javascript_route")
    assert request.source_route_candidate_ids == ("H1", "J1")
    assert request.query_parameter_names == ("state", "token")
    assert request.occurrence_count == 3
    assert request.evidence_ids == ("EVID-A", "EVID-B")
    assert plan.summary_counts.duplicates_aggregated == 1
    assert plan.summary_counts.requests_supported_by_both == 1


def test_static_suffix_exclusions_and_allowed_suffixes() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(
            _html_route(route_id="PNG", url="http://example.test/image.PNG"),
            _html_route(route_id="JS", url="http://example.test/app.js"),
            _html_route(route_id="JSON", url="http://example.test/data.json"),
            _html_route(route_id="PHP", url="http://example.test/login.php"),
            _html_route(route_id="NOEXT", url="http://example.test/admin"),
        ),
        _js_result(),
    )

    assert {request.request_url for request in plan.requests} == {
        "http://example.test/admin",
        "http://example.test/app.js",
        "http://example.test/data.json",
        "http://example.test/login.php",
    }
    assert ("PNG", "low_value_static_suffix") in {(item.source_id, item.reason) for item in plan.skipped}


def test_priority_bound_and_invalid_bounds() -> None:
    html_routes = tuple(
        _html_route(route_id=f"H{index}", url=f"http://example.test/path-{index}")
        for index in range(20)
    )

    plan = build_deep_shallow_route_followup_plan(_html_result(*html_routes), _js_result(), max_requests=3)

    assert len(plan.requests) == 3
    assert tuple(request.request_id for request in plan.requests) == (
        "DEEP-SHALLOW-REQ-0001",
        "DEEP-SHALLOW-REQ-0002",
        "DEEP-SHALLOW-REQ-0003",
    )
    assert plan.summary_counts.request_bound_overflow_skipped == 17
    for invalid in (0, DEFAULT_MAX_REQUESTS + 1, True, 1.5):
        with pytest.raises(ValueError):
            build_deep_shallow_route_followup_plan(_html_result(), _js_result(), max_requests=invalid)  # type: ignore[arg-type]


def test_prioritisation_prefers_both_then_html_then_javascript_then_suffixes() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(
            _html_route(route_id="H-BOTH", url="http://example.test/both"),
            _html_route(route_id="H-HTML", url="http://example.test/html-only"),
            _html_route(route_id="H-JSON", url="http://example.test/data.json"),
            _html_route(route_id="H-JS", url="http://example.test/app.js"),
        ),
        _js_result(
            _js_candidate(candidate_id="J-BOTH", safe_resolved_url="http://example.test/both"),
            _js_candidate(candidate_id="J-JS", safe_resolved_url="http://example.test/js-only"),
        ),
    )

    assert tuple(request.request_url for request in plan.requests)[:6] == (
        "http://example.test/both",
        "http://example.test/html-only",
        "http://example.test/data.json",
        "http://example.test/app.js",
        "http://example.test/js-only",
    )


def test_reversed_inputs_produce_identical_plan() -> None:
    html = _html_result(
        _html_route(route_id="H2", url="http://example.test/b"),
        _html_route(route_id="H1", url="http://example.test/a"),
    )
    html_reversed = _html_result(*reversed(html.routes))
    js = _js_result(
        _js_candidate(candidate_id="J2", safe_resolved_url="http://example.test/d"),
        _js_candidate(candidate_id="J1", safe_resolved_url="http://example.test/c"),
    )
    js_reversed = _js_result(*reversed(js.candidates))

    assert build_deep_shallow_route_followup_plan(html, js) == build_deep_shallow_route_followup_plan(html_reversed, js_reversed)


def test_plan_renderer_sections_safety_and_prohibited_wording() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/admin?token")),
        _js_result(),
    )
    rendered = render_deep_shallow_route_followup_plan_markdown(plan)

    for expected in (
        "## Deep Shallow Route Follow-up Plan",
        "### Summary",
        "### Planned Requests",
        "### Skipped Inputs",
        "### Planning Interpretation Notes",
        "### Safety Notes",
        "No network request was made by this planning/rendering step.",
        "No crawling occurred.",
        "No JavaScript was executed.",
        "No forms were submitted.",
        "No parameters were mutated.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered
    _assert_no_prohibited_wording(rendered)


def test_empty_plan_collection_invokes_fetcher_zero_times() -> None:
    calls: list[str] = []
    plan = build_deep_shallow_route_followup_plan(_html_result(), _js_result())

    result = collect_deep_shallow_route_followups(plan, fetcher=lambda request, bounds: calls.append(request.url))  # type: ignore[arg-type,func-returns-value]

    assert calls == []
    assert result.summary_counts.requests_planned == 0


def test_collector_rejects_invalid_manual_plans_before_fetching() -> None:
    valid_request = _manual_request("REQ-1", "http://example.test/a")
    too_many = tuple(
        _manual_request(f"REQ-{index}", f"http://example.test/{index}")
        for index in range(DEFAULT_MAX_REQUESTS + 1)
    )
    invalid_plans = (
        _manual_plan(too_many, max_requests=DEFAULT_MAX_REQUESTS),
        _manual_plan((valid_request, _manual_request("REQ-2", "http://example.test/b")), max_requests=1),
        _manual_plan((replace(valid_request, method="POST"),)),
        _manual_plan((replace(valid_request, request_url="http://example.test/a?token"),)),
        _manual_plan((valid_request, _manual_request("REQ-1", "http://example.test/b"))),
    )

    for plan in invalid_plans:
        calls = []

        def fake_fetcher(request, bounds):
            calls.append(request.url)
            return _ok_fetcher(request, bounds)

        with pytest.raises(ValueError):
            collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)
        assert calls == []


def test_fetcher_receives_phase_91c_bounds() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/a"), _html_route(route_id="H2", url="http://example.test/b")),
        _js_result(),
        max_requests=2,
    )
    captured = []

    def fake_fetcher(request, bounds):
        captured.append(bounds)
        return _ok_fetcher(request, bounds)

    collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)

    assert captured
    bounds = captured[0]
    assert bounds.max_total_requests == 2
    assert bounds.max_requests_per_origin == 2
    assert bounds.allowed_methods == ("GET",)
    assert bounds.allow_query_strings is False
    assert bounds.allow_cross_origin is False
    assert bounds.allow_form_submission is False
    assert bounds.allow_authentication is False
    assert bounds.allow_payloads is False
    assert bounds.allow_browser_execution is False


def test_collector_invokes_fetcher_once_per_request_get_only_and_preserves_order() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/a"), _html_route(route_id="H2", url="http://example.test/b")),
        _js_result(),
    )
    calls = []

    def fake_fetcher(request, bounds):
        calls.append((request.method, request.url, bounds.max_response_bytes))
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("X-Test", request.path), ("Content-Type", "text/html")),
            body=f"body for {request.path}".encode(),
            elapsed_seconds=0.25,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)

    assert [call[0] for call in calls] == ["GET", "GET"]
    assert [call[1] for call in calls] == [request.request_url for request in plan.requests]
    assert len(calls) == len(plan.requests) <= DEFAULT_MAX_REQUESTS
    assert tuple(item.request_id for item in result.collected) == tuple(request.request_id for request in plan.requests)
    assert result.skipped == ()


def test_redirect_metadata_is_retained_safely_without_second_call() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/login")),
        _js_result(),
    )
    calls = []

    def fake_fetcher(request, bounds):
        calls.append(request.url)
        return DeepHTTPResponse(
            url=request.url,
            final_url="https://user:pass@example.test/login?token=secret#frag",
            status_code=302,
            headers=(("Location", "/next?token=secret"),),
            body=b"",
            elapsed_seconds=0.01,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)
    public = repr(result) + render_deep_shallow_route_followup_result_markdown(result)

    assert calls == ["http://example.test/login"]
    assert result.collected[0].status_code == 302
    assert result.collected[0].final_url == "https://example.test/login?token"
    for sensitive in ("hunter2", "secret", "token=secret", "frag"):
        assert sensitive not in public


def test_collected_response_summary_body_containment_and_headers() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/body")),
        _js_result(),
    )
    body = b"visible preview" + b"A" * 600 + b"FULL_BODY_SECRET"

    def fake_fetcher(request, bounds):
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(("b", "2"), ("A", "1")),
            body=body,
            elapsed_seconds=0.5,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)
    item = result.collected[0]
    rendered = render_deep_shallow_route_followup_result_markdown(result)

    assert item.body == body
    assert item.body_sha256 == hashlib.sha256(body).hexdigest()
    assert item.body_bytes == len(body)
    assert item.headers == (("a", "1"), ("b", "2"))
    assert item.body_preview == body.decode()[:500]
    assert "FULL_BODY_SECRET" not in repr(item)
    assert "FULL_BODY_SECRET" not in repr(result)
    assert "FULL_BODY_SECRET" not in rendered


def test_fetcher_errors_continue_and_do_not_render_messages() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/a"), _html_route(route_id="H2", url="http://example.test/b")),
        _js_result(),
    )

    def fake_fetcher(request, bounds):
        if request.url.endswith("/a"):
            raise OSError("SECRET_EXCEPTION_MESSAGE")
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=204,
            headers=(),
            body=b"",
            elapsed_seconds=0.1,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)
    rendered = render_deep_shallow_route_followup_result_markdown(result)

    assert len(result.collected) == 1
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "fetch_error"
    assert result.skipped[0].error_category == "OSError"
    assert "SECRET_EXCEPTION_MESSAGE" not in rendered


def test_programming_errors_from_fetcher_propagate() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/a")),
        _js_result(),
    )

    def assertion_fetcher(request, bounds):
        raise AssertionError("programming error")

    def type_fetcher(request, bounds):
        raise TypeError("programming error")

    with pytest.raises(AssertionError):
        collect_deep_shallow_route_followups(plan, fetcher=assertion_fetcher)
    with pytest.raises(TypeError):
        collect_deep_shallow_route_followups(plan, fetcher=type_fetcher)


def test_oversized_response_is_skipped_without_retaining_body_and_collection_continues() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(route_id="H1", url="http://example.test/a"), _html_route(route_id="H2", url="http://example.test/b"), _html_route(route_id="H3", url="http://example.test/c")),
        _js_result(),
    )
    calls = []

    def fake_fetcher(request, bounds):
        calls.append(request.url)
        if request.url.endswith("/a"):
            body = b"A" * bounds.max_response_bytes
        elif request.url.endswith("/b"):
            body = b"B" * bounds.max_response_bytes + b"OVERSIZED_SECRET"
        else:
            body = b"ok"
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(),
            body=body,
            elapsed_seconds=0.1,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)
    public = repr(result) + render_deep_shallow_route_followup_result_markdown(result)

    assert calls == [request.request_url for request in plan.requests]
    assert len(result.collected) == 2
    assert result.skipped[0].reason == "response_too_large"
    assert result.summary_counts.responses_too_large == 1
    assert "OVERSIZED_SECRET" not in public


def test_invalid_fetch_response_is_skipped() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/a")),
        _js_result(),
    )

    def fake_fetcher(request, bounds):
        return object()

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)  # type: ignore[arg-type]

    assert result.collected == ()
    assert result.skipped[0].reason == "invalid_fetch_response"


@pytest.mark.parametrize(
    "response",
    (
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code="200", headers=(), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=True, headers=(), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=99, headers=(), body=b"ok", elapsed_seconds=0.1),
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=600, headers=(), body=b"ok", elapsed_seconds=0.1),
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(), body=b"ok", elapsed_seconds=-1),
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(), body=b"ok", elapsed_seconds=math.nan),
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(), body=b"ok", elapsed_seconds=math.inf),
        DeepHTTPResponse(url="u", final_url=123, status_code=200, headers=(), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://[invalid", status_code=200, headers=(), body=b"ok", elapsed_seconds=0.1),
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(("A",),), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=((1, "v"),), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(("A", 1),), body=b"ok", elapsed_seconds=0.1),  # type: ignore[arg-type]
        DeepHTTPResponse(url="u", final_url="http://example.test/a", status_code=200, headers=(), body=bytearray(b"ok"), elapsed_seconds=0.1),  # type: ignore[arg-type]
    ),
)
def test_strict_invalid_fetch_response_fields_are_rejected(response: DeepHTTPResponse) -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/a")),
        _js_result(),
    )

    result = collect_deep_shallow_route_followups(plan, fetcher=lambda request, bounds: response)

    assert result.collected == ()
    assert result.skipped[0].reason == "invalid_fetch_response"


def test_header_canonicalisation_and_location_resolution_use_final_url() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/a")),
        _js_result(),
    )

    def first_fetcher(request, bounds):
        return DeepHTTPResponse(
            url=request.url,
            final_url="https://user:pass@example.test/base/page?session=secret#frag",
            status_code=302,
            headers=(("B", "2"), ("a", "1"), ("LOCATION", "../next?token=secret#frag")),
            body=b"",
            elapsed_seconds=1,
        )

    def second_fetcher(request, bounds):
        return DeepHTTPResponse(
            url=request.url,
            final_url="https://example.test/base/page?session=other#frag",
            status_code=302,
            headers=(("a", "1"), ("LOCATION", "../next?token=different#frag"), ("B", "2")),
            body=b"",
            elapsed_seconds=1.0,
        )

    first = collect_deep_shallow_route_followups(plan, fetcher=first_fetcher)
    second = collect_deep_shallow_route_followups(plan, fetcher=second_fetcher)

    assert first.collected[0].headers == second.collected[0].headers
    assert first.collected[0].headers == (
        ("a", "1"),
        ("b", "2"),
        ("location", "https://example.test/next?token"),
    )
    public = repr(first) + render_deep_shallow_route_followup_result_markdown(first)
    for sensitive in ("hunter2", "secret", "different", "frag", "token=secret"):
        assert sensitive not in public


def test_mixed_collection_outcomes_preserve_relative_result_order() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(
            _html_route(route_id="H1", url="http://example.test/a"),
            _html_route(route_id="H2", url="http://example.test/b"),
            _html_route(route_id="H3", url="http://example.test/c"),
            _html_route(route_id="H4", url="http://example.test/d"),
        ),
        _js_result(),
    )

    def fake_fetcher(request, bounds):
        if request.url.endswith("/b"):
            raise OSError("transport")
        if request.url.endswith("/c"):
            body = b"x" * (bounds.max_response_bytes + 1)
        else:
            body = request.url.encode()
        return DeepHTTPResponse(
            url=request.url,
            final_url=request.url,
            status_code=200,
            headers=(),
            body=body,
            elapsed_seconds=0.1,
        )

    result = collect_deep_shallow_route_followups(plan, fetcher=fake_fetcher)

    assert tuple(item.request_id for item in result.collected) == ("DEEP-SHALLOW-REQ-0001", "DEEP-SHALLOW-REQ-0004")
    assert tuple(item.request_id for item in result.skipped) == ("DEEP-SHALLOW-REQ-0002", "DEEP-SHALLOW-REQ-0003")


def test_result_renderer_sections_safety_and_prohibited_wording() -> None:
    plan = build_deep_shallow_route_followup_plan(
        _html_result(_html_route(url="http://example.test/a")),
        _js_result(),
    )
    result = collect_deep_shallow_route_followups(plan, fetcher=_ok_fetcher)
    rendered = render_deep_shallow_route_followup_result_markdown(result)

    for expected in (
        "## Deep Shallow Route Follow-up Results",
        "### Summary",
        "### Collected Responses",
        "### Skipped or Failed Requests",
        "### Collection Interpretation Notes",
        "### Safety Notes",
        "Network access was limited to the supplied bounded fetcher and the selected plan requests.",
        "Redirects were not manually followed by this phase.",
        "Deep Recon full mode was not enabled.",
    ):
        assert expected in rendered
    _assert_no_prohibited_wording(rendered)


def test_module_source_has_no_direct_io_network_browser_or_recursive_extraction() -> None:
    source = inspect.getsource(followup_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.get",
        "requests.post",
        "httpx.",
        "urllib.request",
        "socket.",
        "subprocess",
        "selenium",
        "playwright",
        "build_deep_html_route_extraction(",
        "build_deep_javascript_route_extraction(",
    ):
        assert forbidden not in source


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _html_result(*routes: DeepHtmlRouteReference) -> DeepHtmlRouteExtractionResult:
    return DeepHtmlRouteExtractionResult(
        routes=tuple(routes),
        summary_counts=DeepHtmlRouteExtractionSummaryCounts(
            total_collected_responses_considered=len(routes),
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


def _js_result(*candidates: DeepJavaScriptRouteCandidate) -> DeepJavaScriptRouteExtractionResult:
    return DeepJavaScriptRouteExtractionResult(
        candidates=tuple(candidates),
        summary_counts=DeepJavaScriptRouteExtractionSummaryCounts(
            total_collected_responses_considered=len(candidates),
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


def _html_route(
    *,
    route_id: str = "H1",
    url: str = "http://example.test/admin",
    origin: str = "same_origin",
    occurrences: int = 1,
    source_urls: tuple[str, ...] = ("http://example.test/source",),
    evidence: tuple[str, ...] = ("EVID-1",),
) -> DeepHtmlRouteReference:
    return DeepHtmlRouteReference(
        route_id=route_id,
        safe_resolved_url=url,
        path="/admin",
        query_parameter_names=(),
        origin_relationship=origin,
        reference_forms=("root_relative",),
        tag_attribute_sources=("a[href]",),
        source_response_ids=("DEEP-HTML-SRC-0001",),
        source_request_urls=source_urls,
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("content_type",),
        occurrence_count=occurrences,
        evidence_ids=evidence,
        interpretation="test",
    )


def _js_candidate(
    *,
    candidate_id: str = "J1",
    safe_candidate: str = "/api",
    safe_resolved_url: str | None = "http://example.test/api",
    contexts: tuple[str, ...] = ("javascript_source_origin",),
    source_urls: tuple[str, ...] = ("http://example.test/app.js",),
    evidence: tuple[str, ...] = ("EVID-1",),
) -> DeepJavaScriptRouteCandidate:
    return DeepJavaScriptRouteCandidate(
        candidate_id=candidate_id,
        safe_candidate=safe_candidate,
        safe_resolved_url=safe_resolved_url,
        path="/api",
        query_parameter_names=(),
        candidate_forms=("root_relative",),
        resolution_contexts=contexts,
        source_kinds=("javascript_response",),
        source_response_ids=("DEEP-JS-SRC-0001",),
        source_request_urls=source_urls,
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("javascript_content_type",),
        script_types=("application/javascript",),
        occurrence_count=1,
        evidence_ids=evidence,
        interpretation="test",
    )


def _ok_fetcher(request, bounds):
    return DeepHTTPResponse(
        url=request.url,
        final_url=request.url,
        status_code=200,
        headers=(("Content-Type", "text/plain"),),
        body=b"ok",
        elapsed_seconds=0.01,
    )


def _manual_request(request_id: str, request_url: str) -> DeepShallowRouteFollowupRequest:
    return DeepShallowRouteFollowupRequest(
        request_id=request_id,
        request_url=request_url,
        method="GET",
        query_parameter_names=(),
        source_model_kinds=("html_route",),
        source_route_candidate_ids=(request_id,),
        source_response_ids=("DEEP-HTML-SRC-0001",),
        source_request_urls=("http://example.test/source",),
        source_collection_sections=("source_route_coverage",),
        source_selection_reasons=("content_type",),
        html_tag_attribute_sources=("a[href]",),
        javascript_candidate_forms=(),
        javascript_resolution_contexts=(),
        javascript_script_types=(),
        occurrence_count=1,
        evidence_ids=("EVID-1",),
        selection_reason="same_origin_static_route",
        interpretation="test",
    )


def _manual_plan(
    requests: tuple[DeepShallowRouteFollowupRequest, ...],
    *,
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> DeepShallowRouteFollowupPlan:
    return DeepShallowRouteFollowupPlan(
        requests=requests,
        skipped=(),
        summary_counts=DeepShallowRouteFollowupPlanSummaryCounts(
            html_routes_considered=len(requests),
            javascript_candidates_considered=0,
            eligible_same_origin_occurrences=len(requests),
            unique_path_only_targets_before_bound=len(requests),
            requests_selected=len(requests),
            total_skipped=0,
            cross_origin_skipped=0,
            not_comparable_skipped=0,
            unresolved_skipped=0,
            invalid_url_skipped=0,
            invalid_origin_relationship_skipped=0,
            low_value_static_skipped=0,
            duplicates_aggregated=0,
            request_bound_overflow_skipped=0,
            html_supported_requests=len(requests),
            javascript_supported_requests=0,
            requests_supported_by_both=0,
            requests_with_observed_query_parameter_names=0,
        ),
        max_requests=max_requests,
        safety_notes=(),
    )


def _raising_fetcher(request, bounds):
    raise AssertionError("fetcher should not be called")


def _assert_no_prohibited_wording(rendered: str) -> None:
    lowered = rendered.lower()
    for forbidden in (
        "confirmed hidden endpoint",
        "confirmed sensitive route",
        "vulnerability found",
        "vulnerable",
        "exploitable",
        "authentication bypass",
        "open redirect",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden not in lowered
