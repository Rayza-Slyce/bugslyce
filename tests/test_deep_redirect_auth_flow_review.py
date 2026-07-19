"""Tests for offline Deep redirect/auth-flow review."""

from __future__ import annotations

import inspect

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_http_fingerprint_summary import (
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_redirect_auth_flow_review import (
    DeepRedirectAuthFlowSummaryCounts,
    build_deep_redirect_auth_flow_review,
    render_deep_redirect_auth_flow_review_markdown,
)
import bugslyce.recon.deep_redirect_auth_flow_review as redirect_module
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


def test_empty_http_summary_produces_safe_empty_review() -> None:
    http_summary = _http_summary()

    review = build_deep_redirect_auth_flow_review(http_summary)
    rendered = render_deep_redirect_auth_flow_review_markdown(review)

    assert review.observations == ()
    assert review.summary_counts == DeepRedirectAuthFlowSummaryCounts(
        total_http_fingerprints_considered=0,
        redirect_status_responses=0,
        redirects_with_location_evidence=0,
        redirects_without_location_evidence=0,
        same_origin_redirect_targets=0,
        cross_origin_redirect_targets=0,
        targets_not_origin_comparable=0,
        redirects_to_auth_looking_paths=0,
        redirects_from_auth_looking_paths=0,
        auth_path_to_auth_path_redirects=0,
        redirects_setting_cookies=0,
        redirects_containing_query_parameter_names=0,
        redirects_with_userinfo_omitted=0,
    )
    assert rendered.startswith("## Deep Redirect/Auth-Flow Review\n")
    assert "### Summary" in rendered
    assert "### Redirect Flow Observations" in rendered
    assert "### Interpretation Notes" in rendered
    assert "### Safety Notes" in rendered
    assert "No redirects were followed." in rendered
    assert "No authentication was attempted." in rendered


def test_non_redirect_and_304_responses_do_not_create_observations() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://example.test/ok", 200, location="/login.php"),
            _item("http://example.test/cache", 304, location="/login.php"),
            _item("http://example.test/error", 500, location="/login.php"),
        )
    )

    assert review.observations == ()
    assert review.summary_counts.total_http_fingerprints_considered == 3
    assert review.summary_counts.redirect_status_responses == 0


def test_supported_redirect_statuses_are_recognised() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            *(
                _item(f"http://example.test/r{status}", status, location="/login")
                for status in (300, 301, 302, 303, 307, 308)
            )
        )
    )

    assert tuple(item.redirect_status_code for item in review.observations) == (
        300,
        301,
        302,
        303,
        307,
        308,
    )
    assert review.summary_counts.redirect_status_responses == 6
    assert review.summary_counts.redirects_with_location_evidence == 6


def test_redirect_without_location_creates_missing_location_observation() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(_item("http://example.test/redirect", 302))
    )
    observation = review.observations[0]

    assert observation.location_present is False
    assert observation.location_reference_form == "missing"
    assert observation.safe_resolved_target_url is None
    assert observation.origin_relationship == "not_comparable"
    assert "without Location evidence" in observation.interpretation_note
    assert review.summary_counts.redirects_without_location_evidence == 1


def test_whitespace_only_location_is_treated_as_missing() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(_item("http://example.test/redirect", 302, location="   "))
    )
    observation = review.observations[0]

    assert observation.location_present is False
    assert observation.location_reference_form == "missing"
    assert observation.safe_resolved_target_url is None
    assert observation.origin_relationship == "not_comparable"
    assert review.summary_counts.redirects_with_location_evidence == 0
    assert review.summary_counts.redirects_without_location_evidence == 1


def test_location_reference_forms_and_resolution() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://example.test/app/page", 302, location="/login.php"),
            _item("http://example.test/app/page", 303, location="next.php"),
            _item("https://example.test/app/page", 307, location="//id.example/login"),
            _item("http://example.test/app/page", 308, location="https://id.example/login"),
            _item("http://example.test/app/page", 301, location="http://id.example/login"),
            _item("http://example.test/app/page?old=1", 302, location="?next=/account"),
            _item("http://example.test/app/page", 302, location="#login"),
            _item("http://example.test/app/page", 302, location="javascript:alert(1)"),
            _item("http://example.test/app/page", 302, location="http:///login"),
        )
    )
    by_form: dict[str, list] = {}
    for item in review.observations:
        by_form.setdefault(item.location_reference_form, []).append(item)

    assert by_form["root_relative"][0].safe_resolved_target_url == "http://example.test/login.php"
    assert by_form["path_relative"][0].safe_resolved_target_url == "http://example.test/app/next.php"
    assert by_form["scheme_relative"][0].safe_resolved_target_url == "https://id.example/login"
    assert by_form["absolute_https"][0].safe_resolved_target_url == "https://id.example/login"
    assert any(
        item.safe_resolved_target_url == "http://id.example/login"
        for item in by_form["absolute_http"]
    )
    assert by_form["query_relative"][0].safe_resolved_target_url == "http://example.test/app/page?next"
    assert by_form["query_relative"][0].target_query_parameter_names == ("next",)
    assert by_form["fragment_relative"][0].safe_resolved_target_url == "http://example.test/app/page"
    assert by_form["fragment_relative"][0].fragment_present is True
    assert by_form["unsupported_scheme"][0].safe_resolved_target_url is None
    assert by_form["unsupported_scheme"][0].origin_relationship == "not_comparable"

    malformed = [
        item
        for item in review.observations
        if item.location_reference_form == "absolute_http"
        and item.safe_resolved_target_url is None
    ][0]
    assert malformed.origin_relationship == "not_comparable"


def test_origin_comparison_rules_are_neutral_and_port_aware() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://EXAMPLE.test/a", 302, location="http://example.test:80/b"),
            _item("https://example.test/a", 302, location="https://example.test:443/b"),
            _item("http://example.test/a", 302, location="https://example.test/a"),
            _item("https://example.test/a", 302, location="https://example.test:8443/a"),
        )
    )
    relationships = tuple(item.origin_relationship for item in review.observations)
    rendered = render_deep_redirect_auth_flow_review_markdown(review)

    assert relationships.count("same_origin") == 2
    assert relationships.count("cross_origin") == 2
    assert "Redirect target origin differs from the source origin." in rendered
    assert "malicious" not in rendered.lower()


def test_auth_path_transition_classification_and_tokenisation() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://example.test/portal.php", 302, location="/login.php"),
            _item("http://example.test/login", 302, location="/dashboard"),
            _item("http://example.test/sso/start", 302, location="/oauth/callback"),
            _item("http://example.test/author", 302, location="/authority"),
        )
    )
    by_source = {item.safe_source_url: item for item in review.observations}

    assert by_source[
        "http://example.test/portal.php"
    ].auth_path_transition == "redirect_to_auth_path"
    assert by_source[
        "http://example.test/login"
    ].auth_path_transition == "redirect_from_auth_path"
    assert by_source[
        "http://example.test/sso/start"
    ].auth_path_transition == "auth_path_to_auth_path"
    assert by_source[
        "http://example.test/author"
    ].auth_path_transition == "no_auth_path_signal"
    assert review.summary_counts.redirects_to_auth_looking_paths == 1
    assert review.summary_counts.redirects_from_auth_looking_paths == 1
    assert review.summary_counts.auth_path_to_auth_path_redirects == 1


def test_auth_path_component_tokens_are_not_standalone_matches() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://example.test/log", 302, location="/dashboard"),
            _item("http://example.test/in", 302, location="/dashboard"),
            _item("http://example.test/sign", 302, location="/dashboard"),
            _item("http://example.test/log-in", 302, location="/dashboard"),
            _item("http://example.test/sign_in", 302, location="/dashboard"),
            _item("http://example.test/author", 302, location="/authority"),
        )
    )
    by_source = {item.safe_source_url: item for item in review.observations}

    assert by_source[
        "http://example.test/log"
    ].auth_path_transition == "no_auth_path_signal"
    assert by_source[
        "http://example.test/in"
    ].auth_path_transition == "no_auth_path_signal"
    assert by_source[
        "http://example.test/sign"
    ].auth_path_transition == "no_auth_path_signal"
    assert by_source[
        "http://example.test/log-in"
    ].auth_path_transition == "redirect_from_auth_path"
    assert by_source[
        "http://example.test/sign_in"
    ].auth_path_transition == "redirect_from_auth_path"
    assert by_source[
        "http://example.test/author"
    ].auth_path_transition == "no_auth_path_signal"


def test_sensitive_redirect_values_are_omitted_from_model_and_rendering() -> None:
    secret_location = (
        "https://user:pass@id.example/login?code=secret-code&state=secret-state#token"
    )
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item(
                "https://example.test/portal?next=secret-next#source-token",
                302,
                location=secret_location,
            )
        )
    )
    observation = review.observations[0]
    rendered = render_deep_redirect_auth_flow_review_markdown(review)
    public_text = repr(review) + rendered

    assert observation.safe_source_url == "https://example.test/portal?next"
    assert observation.safe_resolved_target_url == "https://id.example/login?code&state"
    assert observation.source_query_parameter_names == ("next",)
    assert observation.target_query_parameter_names == ("code", "state")
    assert observation.fragment_present is True
    assert observation.userinfo_present_and_omitted is True
    assert review.summary_counts.redirects_containing_query_parameter_names == 1
    assert review.summary_counts.redirects_with_userinfo_omitted == 1
    for secret in (
        "user:pass",
        "secret-code",
        "secret-state",
        "secret-next",
        "source-token",
        "token",
    ):
        assert secret not in public_text


def test_cookie_on_redirect_uses_names_only_without_session_claims() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item(
                "http://example.test/portal",
                302,
                location="/login",
                headers=(
                    ("Location", "/login"),
                    ("Set-Cookie", "PHPSESSID=secret-value; Path=/; HttpOnly"),
                ),
            )
        )
    )
    observation = review.observations[0]
    rendered = render_deep_redirect_auth_flow_review_markdown(review)

    assert observation.set_cookie_present is True
    assert observation.set_cookie_count == 1
    assert observation.cookie_names == ("PHPSESSID",)
    assert review.summary_counts.redirects_setting_cookies == 1
    assert "secret-value" not in repr(review)
    assert "HttpOnly" not in repr(review)
    assert "secret-value" not in rendered
    assert "session established" not in rendered.lower()
    assert "Cookie-setting response observed alongside redirect evidence" in rendered


def test_ordering_and_ids_are_deterministic_independent_of_input_order() -> None:
    first = _item("http://example.test/z", 302, location="/login", evidence_ids=("EVID-Z",))
    second = _item("http://example.test/a", 302, location="/login", evidence_ids=("EVID-A",))

    normal = build_deep_redirect_auth_flow_review(_http_summary(first, second))
    reversed_review = build_deep_redirect_auth_flow_review(_http_summary(second, first))

    normal_details = tuple(
        (item.observation_id, item.safe_source_url, item.evidence_ids)
        for item in normal.observations
    )
    reversed_details = tuple(
        (item.observation_id, item.safe_source_url, item.evidence_ids)
        for item in reversed_review.observations
    )

    assert normal_details == reversed_details
    assert normal_details == (
        ("DEEP-REDIR-REV-0001", "http://example.test/a", ("EVID-A",)),
        ("DEEP-REDIR-REV-0002", "http://example.test/z", ("EVID-Z",)),
    )


def test_summary_counts_are_correct() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item("http://example.test/a", 302, location="/login"),
            _item("http://example.test/b", 302),
            _item("http://example.test/c", 302, location="https://other.test/login"),
            _item("http://example.test/d", 302, location="javascript:alert(1)"),
            _item(
                "http://example.test/e",
                302,
                location="/next?state=value",
                headers=(("Location", "/next?state=value"), ("Set-Cookie", "sid=value")),
            ),
        )
    )
    counts = review.summary_counts

    assert counts.total_http_fingerprints_considered == 5
    assert counts.redirect_status_responses == 5
    assert counts.redirects_with_location_evidence == 4
    assert counts.redirects_without_location_evidence == 1
    assert counts.same_origin_redirect_targets == 2
    assert counts.cross_origin_redirect_targets == 1
    assert counts.targets_not_origin_comparable == 2
    assert counts.redirects_to_auth_looking_paths == 2
    assert counts.redirects_setting_cookies == 1
    assert counts.redirects_containing_query_parameter_names == 1


def test_renderer_compacts_long_values_and_lists() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(
            _item(
                "http://example.test/" + "a" * 180,
                302,
                location="/target?" + "&".join(f"param{index}=secret" for index in range(8)),
                headers=tuple(("Set-Cookie", f"cookie{index}=secret") for index in range(8)),
                evidence_ids=tuple(f"EVID-{index}" for index in range(8)),
            )
        )
    )
    rendered = render_deep_redirect_auth_flow_review_markdown(review)

    assert "[truncated]" in rendered
    assert "... +2 more" in rendered
    assert "secret" not in rendered


def test_renderer_contains_required_cautions_and_no_prohibited_language() -> None:
    review = build_deep_redirect_auth_flow_review(
        _http_summary(_item("http://example.test/portal", 302, location="/login"))
    )
    rendered = render_deep_redirect_auth_flow_review_markdown(review)
    lowered = rendered.lower()

    for expected in (
        "offline one-hop interpretation of existing HTTP fingerprint evidence",
        "No redirects were followed.",
        "No network request was made.",
        "Origin comparison is based only on parsed source and Location evidence.",
        "Auth-related classification is lexical path evidence only.",
        "Query values, fragments, and URL userinfo are not retained.",
        "Raw collection evidence may retain Set-Cookie values; this derived review renders cookie names only.",
        "No authentication was attempted.",
        "This stage produces static manual-review context only.",
    ):
        assert expected in rendered
    for forbidden in (
        "confirmed authentication flow",
        "login succeeded",
        "login failed",
        "session established",
        "valid session",
        "authentication bypass",
        "account takeover",
        "credentials accepted",
        "malicious redirect",
        "open redirect vulnerability",
        "exploitable",
        "confirmed vulnerability",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden not in lowered


def test_builder_renderer_add_no_io_network_redirect_following_or_collectors() -> None:
    source = inspect.getsource(redirect_module)

    for forbidden in (
        "read_text",
        "write_text",
        "open(",
        "requests.",
        "httpx.",
        "socket.",
        "collect_deep_metadata_from_plan",
        "collect_deep_source_routes_from_plan",
        "urllib_deep_http_fetcher",
    ):
        assert forbidden not in source


def test_input_http_summary_is_not_mutated() -> None:
    http_summary = _http_summary(_item("http://example.test/portal", 302, location="/login"))
    before = http_summary

    build_deep_redirect_auth_flow_review(http_summary)

    assert http_summary == before


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _http_summary(*items: DeepSourceRouteCollectedItem):
    return build_deep_http_fingerprint_summary(
        DeepMetadataCollectionResult(
            collected=(),
            skipped=(),
            total_considered=0,
            total_collected=0,
            total_skipped=0,
        ),
        DeepSourceRouteCollectionResult(
            collected=tuple(items),
            skipped=(),
            total_considered=len(items),
            total_collected=len(items),
            total_skipped=0,
        ),
    )


def _item(
    url: str,
    status_code: int,
    *,
    location: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    response_headers = headers
    if location is not None and not any(name.lower() == "location" for name, _ in headers):
        response_headers = (("Location", location), *headers)
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=url,
        headers=response_headers,
        body_preview="",
        body_sha256=f"hash-{url}-{status_code}",
        body_bytes=0,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="discovered_unfetched_application_route",
        evidence_ids=evidence_ids,
    )
