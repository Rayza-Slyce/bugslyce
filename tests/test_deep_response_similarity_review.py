"""Tests for offline Deep response similarity review."""

from __future__ import annotations

from dataclasses import replace
from html import escape
import inspect
from urllib.parse import unquote, urlsplit

from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_http_fingerprint_summary import (
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_redirect_auth_flow_review import (
    build_deep_redirect_auth_flow_review,
)
from bugslyce.recon.deep_response_similarity_review import (
    MAX_UNIQUE_SUCCESS_RESPONSES,
    DeepResponseSimilaritySummaryCounts,
    build_deep_response_similarity_review,
    render_deep_response_similarity_review_markdown,
)
import bugslyce.recon.deep_response_similarity_review as similarity_module
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


def test_empty_inputs_produce_safe_empty_review() -> None:
    http_summary, redirect_review = _inputs()

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)

    assert review.groups == ()
    assert review.unique_success_responses == ()
    assert review.summary_counts == DeepResponseSimilaritySummaryCounts(
        total_http_fingerprints_considered=0,
        total_redirect_observations_considered=0,
        exact_body_hash_groups=0,
        redirect_pattern_groups=0,
        repeated_auth_looking_redirect_groups=0,
        candidate_default_template_groups=0,
        client_error_signature_groups=0,
        general_response_signature_groups=0,
        total_grouped_fingerprints=0,
        unique_ungrouped_2xx_responses=0,
        responses_in_multiple_retained_groups=0,
    )
    assert rendered.startswith("## Deep Response Similarity Review\n")
    assert "### Summary" in rendered
    assert "### Response Similarity Groups" in rendered
    assert "### Unique Ungrouped 2xx Responses" in rendered
    assert "### Grouping Interpretation Notes" in rendered
    assert "### Safety Notes" in rendered
    assert "No network requests were made." in rendered
    assert "This stage produces static manual-review context only." in rendered


def test_input_models_are_not_mutated() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, body_hash="a", body_bytes=100)
    )
    before = (http_summary, redirect_review)

    build_deep_response_similarity_review(http_summary, redirect_review)

    assert (http_summary, redirect_review) == before


def test_existing_repeated_body_groups_become_exact_body_similarity_groups() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, body_hash="same", body_bytes=32),
        _item("http://example.test/b", 200, body_hash="same", body_bytes=32),
        _item("http://example.test/empty-a", 200, body_hash=_EMPTY_SHA, body_bytes=0),
        _item("http://example.test/empty-b", 200, body_hash=_EMPTY_SHA, body_bytes=0),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert tuple(group.category for group in review.groups) == ("exact_body_hash_group",)
    group = review.groups[0]
    assert group.group_id == "DEEP-SIM-GRP-0001"
    assert group.source_repeated_body_group_ids == ("DEEP-HTTP-REP-0001",)
    assert group.body_hashes == ("same",)
    assert group.status_codes == (200,)
    assert group.body_size_bands == ("1-255",)
    assert review.summary_counts.exact_body_hash_groups == 1
    assert _EMPTY_SHA not in group.body_hashes


def test_redirect_observations_with_same_safe_signature_group_together() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/portal-a", 302, location="/login"),
        _item("http://example.test/portal-b", 302, location="/login"),
        _item("http://example.test/portal-c", 302, location="https://other.test/login"),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    groups = [group for group in review.groups if group.category == "redirect_pattern_group"]

    assert len(groups) == 1
    group = groups[0]
    assert len(group.fingerprint_ids) == 2
    assert group.redirect_observation_ids == (
        "DEEP-REDIR-REV-0001",
        "DEEP-REDIR-REV-0002",
    )
    assert group.redirect_origin_relationships == ("same_origin",)
    assert group.auth_path_transitions == ("redirect_to_auth_path",)
    assert review.summary_counts.redirect_pattern_groups == 1
    assert review.summary_counts.repeated_auth_looking_redirect_groups == 1


def test_redirect_groups_split_on_origin_relationship_and_auth_transition() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 302, location="/login"),
        _item("http://example.test/b", 302, location="https://other.test/login"),
        _item("http://example.test/login-a", 302, location="/dashboard"),
        _item("http://example.test/login-b", 302, location="/dashboard"),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    groups = [group for group in review.groups if group.category == "redirect_pattern_group"]

    assert len(groups) == 1
    assert groups[0].auth_path_transitions == ("redirect_from_auth_path",)
    assert all("https://other.test/login" not in group.requested_urls for group in groups)


def test_raw_redirect_query_values_do_not_enter_public_model() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "https://example.test/a",
            302,
            location="https://id.example/login?code=secret-code&state=secret-state#token",
        ),
        _item(
            "https://example.test/b",
            302,
            location="https://id.example/login?code=other-secret&state=other-state#token2",
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)
    public_text = repr(review) + rendered

    assert "code" in public_text
    assert "state" in public_text
    for secret in ("secret-code", "secret-state", "other-secret", "other-state", "token"):
        assert secret not in public_text


def test_general_response_signature_grouping_uses_meaningful_shared_fields() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/a",
            200,
            content_type="text/html; charset=UTF-8",
            server="Apache/2.4.41 (Ubuntu)",
            title="Shared Title",
            body_bytes=1200,
            body_hash="a",
        ),
        _item(
            "http://example.test/b",
            200,
            content_type="text/html",
            server="Apache/2.4.99",
            title=" shared   title ",
            body_bytes=1300,
            body_hash="b",
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    group = review.groups[0]

    assert group.category == "candidate_default_template_group"
    assert "text/html" in group.grouping_signature
    assert "apache" in group.grouping_signature
    assert "shared title" in group.grouping_signature
    assert group.content_types == ("text/html",)
    assert group.server_families == ("apache",)


def test_responses_sharing_only_status_code_do_not_group() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, body_hash="a", body_bytes=10),
        _item("http://example.test/b", 200, body_hash="b", body_bytes=20),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert review.groups == ()
    assert len(review.unique_success_responses) == 2


def test_server_families_and_body_size_bands_are_deterministic() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, server="nginx/1.24.0", body_bytes=256),
        _item("http://example.test/b", 200, server="nginx", body_bytes=1023),
        _item("http://example.test/c", 200, server="Microsoft-IIS/10.0", body_bytes=1024),
        _item("http://example.test/d", 200, server="gunicorn", body_bytes=65536),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    nginx_group = [
        group for group in review.groups if group.server_families == ("nginx",)
    ][0]

    assert nginx_group.body_size_bands == ("256-1023",)
    assert {unique.server for unique in review.unique_success_responses} == {
        "Microsoft-IIS/10.0",
        "gunicorn",
    }


def test_repeated_4xx_responses_create_client_error_group_not_soft_404() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/missing-a",
            404,
            content_type="text/html",
            server="Apache",
            title="Not Found",
            body_bytes=900,
            body_hash="missing-a",
        ),
        _item(
            "http://example.test/missing-b",
            404,
            content_type="text/html; charset=utf-8",
            server="Apache/2.4",
            title="not   found",
            body_bytes=950,
            body_hash="missing-b",
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)

    assert tuple(group.category for group in review.groups) == (
        "client_error_signature_group",
    )
    assert review.summary_counts.client_error_signature_groups == 1
    assert "soft 404" not in rendered.lower()
    assert "soft-404" not in rendered.lower()


def test_candidate_default_template_requires_multiple_distinct_urls() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/same",
            200,
            content_type="text/html",
            server="Apache",
            title="Default",
            body_bytes=500,
            body_hash="a",
        ),
        _item(
            "http://example.test/same",
            200,
            content_type="text/html",
            server="Apache",
            title="Default",
            body_bytes=500,
            body_hash="b",
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert all(group.category != "candidate_default_template_group" for group in review.groups)


def test_sensitive_requested_url_parts_never_enter_public_model_or_rendering() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "https://user:pass@example.test/exact?code=secret-code#token",
            200,
            body_hash="same",
            body_bytes=500,
        ),
        _item(
            "https://other:creds@example.test/other?state=secret-state#frag",
            200,
            body_hash="same",
            body_bytes=500,
        ),
        _item(
            "https://admin:pw@example.test/template?token=first#hidden",
            200,
            content_type="text/html",
            server="Apache",
            title="Template",
            body_hash="template-a",
            body_bytes=700,
        ),
        _item(
            "https://root:pw@example.test/template-2?token=second#hidden",
            200,
            content_type="text/html",
            server="Apache",
            title="Template",
            body_hash="template-b",
            body_bytes=700,
        ),
        _item(
            "https://unique:pw@example.test/unique?next=secret-next#unique-frag",
            200,
            body_hash="unique",
            body_bytes=50,
        ),
        _item(
            "ftp://user:pass@example.test/private?token=secret#frag",
            200,
            body_hash="unsupported",
            body_bytes=50,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)
    public_text = repr(review) + rendered

    exact_group = [
        group for group in review.groups if group.category == "exact_body_hash_group"
    ][0]
    candidate_group = [
        group
        for group in review.groups
        if group.category == "candidate_default_template_group"
    ][0]
    assert exact_group.requested_urls == (
        "https://example.test/exact?code",
        "https://example.test/other?state",
    )
    assert candidate_group.requested_urls == (
        "https://example.test/template-2?token",
        "https://example.test/template?token",
    )
    assert any(
        unique.requested_url == "https://example.test/unique?next"
        for unique in review.unique_success_responses
    )
    assert any(
        unique.requested_url == "unresolved"
        for unique in review.unique_success_responses
    )
    for sensitive in (
        "user",
        "pass",
        "secret-code",
        "secret-state",
        "secret-next",
        "token",
        "hidden",
        "unique-frag",
        "ftp://",
    ):
        if sensitive == "token":
            assert "token=first" not in public_text
            assert "token=second" not in public_text
            continue
        assert sensitive not in public_text


def test_query_value_differences_do_not_make_template_urls_distinct() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "https://example.test/page?token=first",
            200,
            content_type="text/html",
            server="Apache",
            title="Same",
            body_hash="a",
            body_bytes=500,
        ),
        _item(
            "https://example.test/page?token=second",
            200,
            content_type="text/html",
            server="Apache",
            title="Same",
            body_hash="b",
            body_bytes=500,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert all(group.category != "candidate_default_template_group" for group in review.groups)
    assert all("first" not in repr(group) and "second" not in repr(group) for group in review.groups)


def test_ipv6_requested_url_is_safely_reconstructed_with_brackets() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "https://user:pass@[2001:db8::1]:8443/path?token=secret#frag-secret",
            200,
            body_hash="ipv6",
            body_bytes=50,
        )
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)
    public_text = repr(review) + rendered

    assert review.unique_success_responses[0].requested_url == (
        "https://[2001:db8::1]:8443/path?token"
    )
    assert "https://2001:db8::1:8443/path?token" not in public_text
    for sensitive in ("user", "pass", "secret", "frag-secret", "token=secret"):
        assert sensitive not in public_text


def test_empty_query_parameter_names_are_ignored_in_safe_requested_urls() -> None:
    http_summary, redirect_review = _inputs(
        _item("https://example.test/path?=secret", 200, body_hash="empty-name", body_bytes=50),
        _item("https://example.test/with-name?token=secret", 200, body_hash="named", body_bytes=50),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert tuple(item.requested_url for item in review.unique_success_responses) == (
        "https://example.test/path",
        "https://example.test/with-name?token",
    )
    assert all("secret" not in repr(item) for item in review.unique_success_responses)


def test_generic_empty_responses_do_not_become_default_template_groups() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 204, body_hash=_EMPTY_SHA, body_bytes=0),
        _item("http://example.test/b", 204, body_hash=_EMPTY_SHA, body_bytes=0),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert review.groups == ()


def test_exact_body_precedence_suppresses_weaker_duplicate_groups() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/a",
            200,
            content_type="text/html",
            server="Apache",
            title="Same",
            body_hash="same",
            body_bytes=500,
        ),
        _item(
            "http://example.test/b",
            200,
            content_type="text/html",
            server="Apache",
            title="same",
            body_hash="same",
            body_bytes=500,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert tuple(group.category for group in review.groups) == ("exact_body_hash_group",)
    assert review.summary_counts.candidate_default_template_groups == 0
    assert review.summary_counts.general_response_signature_groups == 0


def test_redirect_groups_are_not_suppressed_by_response_groups() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/a",
            302,
            location="/login",
            content_type="text/html",
            server="Apache",
            body_bytes=500,
            body_hash="a",
        ),
        _item(
            "http://example.test/b",
            302,
            location="/login",
            content_type="text/html",
            server="Apache",
            body_bytes=500,
            body_hash="b",
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert {group.category for group in review.groups} == {
        "redirect_pattern_group",
        "candidate_default_template_group",
    }
    assert review.summary_counts.responses_in_multiple_retained_groups == 2


def test_unique_2xx_responses_exclude_grouped_fingerprints_and_are_bounded() -> None:
    grouped_a = _item(
        "http://example.test/group-a",
        200,
        content_type="text/html",
        server="Apache",
        title="Grouped",
        body_hash="same",
        body_bytes=500,
    )
    grouped_b = _item(
        "http://example.test/group-b",
        200,
        content_type="text/html",
        server="Apache",
        title="Grouped",
        body_hash="same",
        body_bytes=500,
    )
    uniques = tuple(
        _item(f"http://example.test/unique-{index:02d}", 200, body_hash=f"u-{index}", body_bytes=50)
        for index in range(MAX_UNIQUE_SUCCESS_RESPONSES + 3)
    )
    http_summary, redirect_review = _inputs(grouped_a, grouped_b, *uniques)

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert len(review.unique_success_responses) == MAX_UNIQUE_SUCCESS_RESPONSES
    assert all("group-" not in item.requested_url for item in review.unique_success_responses)
    assert tuple(item.unique_id for item in review.unique_success_responses) == tuple(
        f"DEEP-SIM-UNIQ-{index:04d}"
        for index in range(1, MAX_UNIQUE_SUCCESS_RESPONSES + 1)
    )


def test_group_ordering_and_ids_are_deterministic_for_reversed_inputs() -> None:
    first = _item("http://example.test/z", 200, content_type="text/html", server="Apache", body_bytes=600)
    second = _item("http://example.test/a", 200, content_type="text/html", server="Apache", body_bytes=600)

    normal_http, normal_redirect = _inputs(first, second)
    reversed_http, reversed_redirect = _inputs(second, first)
    normal = build_deep_response_similarity_review(normal_http, normal_redirect)
    reversed_review = build_deep_response_similarity_review(reversed_http, reversed_redirect)

    normal_details = tuple((group.group_id, group.category, group.requested_urls) for group in normal.groups)
    reversed_details = tuple((group.group_id, group.category, group.requested_urls) for group in reversed_review.groups)

    assert normal_details == reversed_details


def test_public_model_reversal_keeps_complete_review_identical() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/z", 200, content_type="text/html", server="Apache", body_hash="same", body_bytes=600, evidence_ids=("EVID-Z",)),
        _item("http://example.test/a", 200, content_type="text/html", server="Apache", body_hash="same", body_bytes=600, evidence_ids=("EVID-A",)),
        _item("http://example.test/redir-b", 302, location="/login", evidence_ids=("EVID-RB",)),
        _item("http://example.test/redir-a", 302, location="/login", evidence_ids=("EVID-RA",)),
    )
    reversed_repeated = tuple(
        replace(group, fingerprint_ids=tuple(reversed(group.fingerprint_ids)))
        for group in reversed(http_summary.repeated_body_groups)
    )
    reversed_http_summary = replace(
        http_summary,
        fingerprints=tuple(reversed(http_summary.fingerprints)),
        repeated_body_groups=reversed_repeated,
    )
    reversed_redirect_review = replace(
        redirect_review,
        observations=tuple(reversed(redirect_review.observations)),
    )

    normal = build_deep_response_similarity_review(http_summary, redirect_review)
    reversed_review = build_deep_response_similarity_review(
        reversed_http_summary,
        reversed_redirect_review,
    )

    assert reversed_review.groups == normal.groups
    assert reversed_review.unique_success_responses == normal.unique_success_responses
    assert reversed_review.summary_counts == normal.summary_counts


def test_request_reflecting_templates_form_one_traceable_family() -> None:
    items = tuple(
        _item(
            f"https://app.example.test/missing-{name}",
            500,
            content_type="text/html; charset=utf-8",
            body_preview=_reflected_template_body(
                f"https://app.example.test/missing-{name}"
            ),
            body_hash=f"raw-hash-{name}",
            body_bytes=2400 + index,
            evidence_ids=(f"EVID-{name.upper()}",),
        )
        for index, name in enumerate(("alpha", "beta", "gamma"), start=1)
    )
    http_summary, redirect_review = _inputs(*items)
    before = http_summary

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    families = [
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    ]
    assert len(families) == 1
    family = families[0]
    assert family.member_count == 3
    assert family.group_id.startswith("DEEP-RESP-FAM-")
    assert family.representative_requested_url == (
        "https://app.example.test/missing-alpha"
    )
    assert family.requested_urls == tuple(sorted(item.url for item in items))
    assert family.body_hashes == (
        "raw-hash-alpha",
        "raw-hash-beta",
        "raw-hash-gamma",
    )
    assert family.evidence_ids == ("EVID-ALPHA", "EVID-BETA", "EVID-GAMMA")
    assert "request-derived reflection replaced" in family.structural_signals
    assert review.summary_counts.request_reflecting_template_groups == 1
    rendered = render_deep_response_similarity_review_markdown(review)
    assert (
        "3 collected response records share one stable request-reflecting template "
        "across every pairwise safely comparable bounded region."
    ) in rendered
    assert "Representative request: `https://app.example.test/missing-alpha`" in rendered
    assert "Member count" not in rendered
    assert "Request-reflecting template groups: 1" in rendered
    for item in items:
        assert item.url in rendered
    assert http_summary == before


def test_fifty_reflected_templates_group_without_absorbing_distinct_responses() -> None:
    reflected = tuple(
        _item(
            f"https://app.example.test/missing-{index:02d}",
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                f"https://app.example.test/missing-{index:02d}"
            ),
            body_hash=f"reflected-{index:02d}",
            body_bytes=2300 + index,
        )
        for index in range(50)
    )
    distinct = _item(
        "https://app.example.test/account",
        500,
        content_type="text/html",
        body_preview=(
            "<html><head><title>Account service unavailable</title></head>"
            "<body><main><h1>Account service unavailable</h1>"
            "<p>This response has materially different structure and meaning.</p>"
            "</main></body></html>"
        ),
        body_hash="distinct-account",
        body_bytes=2325,
    )
    http_summary, redirect_review = _inputs(*reflected, distinct)

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    families = [
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    ]
    assert len(families) == 1
    assert families[0].member_count == 50
    assert "https://app.example.test/account" not in families[0].requested_urls


def test_request_reflection_variants_use_only_the_record_own_request_value() -> None:
    urls = (
        "https://app.example.test/missing-alpha",
        "https://app.example.test/missing-%62eta",
        "https://app.example.test/missing-gamma&mode=plain",
    )
    reflected_values = (
        urls[0],
        unquote(urlsplit(urls[1]).path),
        escape(urlsplit(urls[2]).path),
    )
    items = tuple(
        _item(
            url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(url, reflected_value=value),
            body_hash=f"variant-{index}",
            body_bytes=2400,
        )
        for index, (url, value) in enumerate(zip(urls, reflected_values, strict=True))
    )
    http_summary, redirect_review = _inputs(*items)

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    families = [
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    ]
    assert len(families) == 1
    assert families[0].member_count == 3


def test_request_reflecting_family_is_deterministic_for_reversed_inputs() -> None:
    items = tuple(
        _item(
            f"https://app.example.test/missing-{name}",
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                f"https://app.example.test/missing-{name}"
            ),
            body_hash=f"hash-{name}",
            body_bytes=2400,
            evidence_ids=(f"EVID-{name.upper()}",),
        )
        for name in ("gamma", "alpha", "beta")
    )
    normal_http, normal_redirect = _inputs(*items)
    reversed_http, reversed_redirect = _inputs(*reversed(items))

    normal = build_deep_response_similarity_review(normal_http, normal_redirect)
    reversed_review = build_deep_response_similarity_review(
        reversed_http,
        reversed_redirect,
    )

    assert reversed_review == normal
    family = next(
        group
        for group in normal.groups
        if group.category == "request_reflecting_template_group"
    )
    assert family.representative_requested_url.endswith("/missing-alpha")


def test_request_reflecting_family_false_merge_guards() -> None:
    same_length_unrelated = (
        _item(
            "https://app.example.test/alpha",
            500,
            content_type="text/html",
            body_preview="<html><head><title>Alpha report</title></head><body>" + "A" * 300,
            body_hash="unrelated-a",
            body_bytes=500,
        ),
        _item(
            "https://app.example.test/bravo",
            500,
            content_type="text/html",
            body_preview="<html><head><title>Bravo report</title></head><body>" + "B" * 300,
            body_hash="unrelated-b",
            body_bytes=500,
        ),
    )
    reflected_base = _item(
        "https://app.example.test/missing-alpha",
        500,
        content_type="text/html",
        body_preview=_reflected_template_body(
            "https://app.example.test/missing-alpha",
            unrelated_path="/public/documentation",
        ),
        body_hash="base",
        body_bytes=2400,
    )
    guards = (
        replace(
            reflected_base,
            url="https://portal.example.test:8443/missing-beta",
            final_url="https://portal.example.test:8443/missing-beta",
            body_preview=_reflected_template_body(
                "https://portal.example.test:8443/missing-beta",
                unrelated_path="/public/documentation",
            ),
            body_sha256="other-origin",
        ),
        replace(reflected_base, status_code=401, body_sha256="different-status"),
        replace(reflected_base, status_code=200, body_sha256="successful-document"),
        replace(
            reflected_base,
            body_preview="<html><title>/public/documentation</title></html>",
            body_sha256="insufficient",
            body_bytes=48,
        ),
    )
    http_summary, redirect_review = _inputs(
        *same_length_unrelated,
        reflected_base,
        *guards,
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_unrelated_path_like_content_is_not_normalised() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-beta"
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                first_url,
                unrelated_path="/public/alpha-guide",
            ),
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                second_url,
                unrelated_path="/public/beta-guide",
            ),
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_request_path_prefix_inside_unrelated_route_is_not_replaced() -> None:
    first_url = "https://app.example.test/api"
    second_url = "https://app.example.test/docs"
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                first_url,
                unrelated_path="/api/reference",
            ),
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(
                second_url,
                unrelated_path="/docs/reference",
            ),
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_different_content_after_shared_normalised_prefix_remains_separate() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-beta"
    common_padding = "Stable bounded template text. " * 16
    first_body = _late_difference_template(
        first_url,
        common_padding=common_padding,
        late_content="<section><p>First material conclusion.</p></section>",
    )
    second_body = _late_difference_template(
        second_url,
        common_padding=common_padding,
        late_content="<section><p>Second material conclusion.</p></section>",
    )
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=first_body,
            body_hash="late-difference-a",
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second_body,
            body_hash="late-difference-b",
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert len(first_body) > 320
    assert len(second_body) > 320
    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_different_structure_after_shared_normalised_prefix_remains_separate() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-beta"
    common_padding = "Stable bounded template text. " * 16
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=_late_difference_template(
                first_url,
                common_padding=common_padding,
                late_content="<section><p>Shared conclusion.</p></section>",
            ),
            body_hash="late-structure-a",
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=_late_difference_template(
                second_url,
                common_padding=common_padding,
                late_content="<aside><h2>Shared conclusion.</h2></aside>",
            ),
            body_hash="late-structure-b",
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_unequal_truncated_retained_boundaries_fail_closed() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-bravo"
    first_body = _fixed_boundary_reflected_template(first_url, retained_chars=456)
    second_prefix = _fixed_boundary_reflected_template(
        second_url,
        retained_chars=456,
    )

    for index, retained_suffix in enumerate(
        (
            "Materially different retained plain text after the shorter boundary.",
            "<section><h2>Materially different retained structure</h2></section>",
        ),
        start=1,
    ):
        second_body = second_prefix + retained_suffix
        http_summary, redirect_review = _inputs(
            _item(
                first_url,
                500,
                content_type="text/html",
                body_preview=first_body,
                body_hash=f"unequal-boundary-short-{index}",
                body_bytes=2400,
            ),
            _item(
                second_url,
                500,
                content_type="text/html",
                body_preview=second_body,
                body_hash=f"unequal-boundary-long-{index}",
                body_bytes=2400,
            ),
        )

        review = build_deep_response_similarity_review(http_summary, redirect_review)

        assert len(first_body) == 456
        assert len(second_body) > len(first_body)
        assert not any(
            group.category == "request_reflecting_template_group"
            for group in review.groups
        )


def test_unequal_boundary_safe_reference_path_remains_discriminating() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-bravo"
    first_body = _fixed_boundary_reflected_template(first_url, retained_chars=456)
    second_body = _fixed_boundary_reflected_template(
        second_url,
        retained_chars=456,
    ) + "<a href='/different/safe-path'>Different retained reference</a>"
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=first_body,
            body_hash="unequal-reference-short",
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second_body,
            body_hash="unequal-reference-long",
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_complete_previews_require_complete_normalised_equality() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-bravo"
    first_body = _fixed_boundary_reflected_template(first_url, retained_chars=456)
    second_body = _fixed_boundary_reflected_template(second_url, retained_chars=456)
    matching_http, matching_redirect = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=first_body,
            body_bytes=len(first_body.encode("utf-8")),
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second_body,
            body_bytes=len(second_body.encode("utf-8")),
        ),
    )
    different_http, different_redirect = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=first_body,
            body_bytes=len(first_body.encode("utf-8")),
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second_body[:-1] + "Y",
            body_bytes=len(second_body.encode("utf-8")),
        ),
    )

    matching = build_deep_response_similarity_review(
        matching_http,
        matching_redirect,
    )
    different = build_deep_response_similarity_review(
        different_http,
        different_redirect,
    )

    assert any(
        group.category == "request_reflecting_template_group"
        for group in matching.groups
    )
    assert not any(
        group.category == "request_reflecting_template_group"
        for group in different.groups
    )


def test_mixed_complete_and_truncated_previews_fail_closed() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-bravo"
    first_body = _fixed_boundary_reflected_template(first_url, retained_chars=456)
    second_body = _fixed_boundary_reflected_template(second_url, retained_chars=456)
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=first_body,
            body_bytes=len(first_body.encode("utf-8")),
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second_body,
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_replacement_decoded_boundary_preview_is_not_labelled_complete() -> None:
    urls = (
        "https://app.example.test/missing-alpha",
        "https://app.example.test/missing-bravo",
    )
    items = tuple(
        _item(
            url,
            500,
            content_type="text/html",
            body_preview=_replacement_boundary_template(url),
            body_hash=f"replacement-boundary-{index}",
            body_bytes=600,
            evidence_ids=(f"EVID-REPLACEMENT-{index}",),
        )
        for index, url in enumerate(urls, start=1)
    )
    http_summary, redirect_review = _inputs(*items)
    evidence = tuple(
        similarity_module._request_reflecting_evidence(fingerprint)
        for fingerprint in http_summary.fingerprints
    )

    assert all(item is not None for item in evidence)
    assert all(len(item.body_preview) == 500 for item in items)
    assert all(len(item.body_preview.encode("utf-8")) > 600 for item in items)
    assert all(item.preview_truncated for item in evidence if item is not None)

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    family = next(
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    )
    assert "retained_preview_boundary=truncated_chars=500" in family.grouping_signature
    assert "retained_preview_boundary=complete" not in family.grouping_signature
    assert "unavailable content beyond a truncated preview is not assumed identical" in (
        family.interpretation
    )


def test_exact_500_character_complete_body_is_conservatively_boundary_limited() -> None:
    url = "https://app.example.test/missing-alpha"
    preview = _fixed_boundary_reflected_template(url, retained_chars=500)
    http_summary, _redirect_review = _inputs(
        _item(
            url,
            500,
            content_type="text/html",
            body_preview=preview,
            body_bytes=len(preview.encode("utf-8")),
        )
    )

    evidence = similarity_module._request_reflecting_evidence(
        http_summary.fingerprints[0]
    )

    assert evidence is not None
    assert evidence.retained_preview_chars == 500
    assert evidence.preview_truncated


def test_short_complete_multibyte_previews_are_stable_under_reversal() -> None:
    urls = (
        "https://app.example.test/missing-alpha",
        "https://app.example.test/missing-bravo",
    )
    pending: list[DeepSourceRouteCollectedItem] = []
    for index, url in enumerate(urls, start=1):
        body = _complete_reflected_template(
            url,
            conclusion="Résumé content remains complete and deterministic.",
        )
        assert len(body) < 500
        pending.append(
            _item(
                url,
                500,
                content_type="text/html",
                body_preview=body,
                body_hash=f"multibyte-complete-{index}",
                body_bytes=len(body.encode("utf-8")),
                evidence_ids=(f"EVID-MULTIBYTE-{index}",),
            )
        )
    forward_http, forward_redirect = _inputs(*pending)
    reverse_http, reverse_redirect = _inputs(*reversed(pending))

    forward_evidence = tuple(
        similarity_module._request_reflecting_evidence(fingerprint)
        for fingerprint in forward_http.fingerprints
    )
    forward = build_deep_response_similarity_review(forward_http, forward_redirect)
    reverse = build_deep_response_similarity_review(reverse_http, reverse_redirect)

    assert all(item is not None for item in forward_evidence)
    assert all(
        not item.preview_truncated
        for item in forward_evidence
        if item is not None
    )
    assert reverse == forward


def test_shortest_member_does_not_hide_later_plain_text_differences() -> None:
    items = _shortest_member_false_merge_items(
        second_tail="Second retained plain-text conclusion.",
        third_tail="Third retained plain-text conclusion.",
    )
    http_summary, redirect_review = _inputs(*items)

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    families = tuple(
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    )

    assert len({len(item.body_preview) for item in items}) == 1
    assert not any(family.member_count == 3 for family in families)
    assert not any(
        items[1].url in family.requested_urls
        and items[2].url in family.requested_urls
        for family in families
    )


def test_shortest_member_does_not_hide_later_structure_differences() -> None:
    items = _shortest_member_false_merge_items(
        second_tail="<section><h2>Second retained structure</h2></section>",
        third_tail="<aside><p>Third retained structure</p></aside>",
    )
    http_summary, redirect_review = _inputs(*items)

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    families = tuple(
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    )

    assert not any(family.member_count == 3 for family in families)
    assert not any(
        items[1].url in family.requested_urls
        and items[2].url in family.requested_urls
        for family in families
    )


def test_same_coarse_outlier_does_not_suppress_valid_complete_family() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-bravo"
    outlier_url = "https://app.example.test/missing-charlie"
    shared = _complete_reflected_template(first_url, conclusion="Shared conclusion.")
    second = _complete_reflected_template(second_url, conclusion="Shared conclusion.")
    outlier = _complete_reflected_template(
        outlier_url,
        conclusion="Materially different conclusion.",
    )
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=shared,
            body_bytes=len(shared.encode("utf-8")),
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=second,
            body_bytes=len(second.encode("utf-8")),
        ),
        _item(
            outlier_url,
            500,
            content_type="text/html",
            body_preview=outlier,
            body_bytes=len(outlier.encode("utf-8")),
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    families = tuple(
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    )

    assert len(families) == 1
    assert families[0].requested_urls == (first_url, second_url)
    assert outlier_url not in families[0].requested_urls


def test_one_coarse_bucket_partitions_into_two_disjoint_families() -> None:
    urls = tuple(
        f"https://app.example.test/missing-{name}"
        for name in ("alpha", "bravo", "delta", "foxtrot")
    )
    conclusions = ("First family.", "First family.", "Second family.", "Second family.")
    pending_items: list[DeepSourceRouteCollectedItem] = []
    for index, (url, conclusion) in enumerate(
        zip(urls, conclusions, strict=True),
        start=1,
    ):
        body = _complete_reflected_template(url, conclusion=conclusion)
        pending_items.append(
            _item(
                url,
                500,
                content_type="text/html",
                body_preview=body,
                body_hash=f"partition-{index}",
                body_bytes=len(body.encode("utf-8")),
                evidence_ids=(f"EVID-PARTITION-{index}",),
            )
        )
    items = tuple(pending_items)
    forward_http, forward_redirect = _inputs(*items)
    reverse_http, reverse_redirect = _inputs(*reversed(items))

    forward = build_deep_response_similarity_review(forward_http, forward_redirect)
    reverse = build_deep_response_similarity_review(reverse_http, reverse_redirect)
    families = tuple(
        group
        for group in forward.groups
        if group.category == "request_reflecting_template_group"
    )

    assert reverse == forward
    assert len(families) == 2
    assert len({family.group_id for family in families}) == 2
    assert {family.requested_urls for family in families} == {
        (urls[0], urls[1]),
        (urls[2], urls[3]),
    }
    memberships = [
        fingerprint_id
        for family in families
        for fingerprint_id in family.fingerprint_ids
    ]
    assert len(memberships) == len(set(memberships)) == 4
    evidence_by_fingerprint_id = {
        evidence.fingerprint.fingerprint_id: evidence
        for evidence in (
            similarity_module._request_reflecting_evidence(fingerprint)
            for fingerprint in forward_http.fingerprints
        )
        if evidence is not None
    }
    for family in families:
        member_evidence = tuple(
            evidence_by_fingerprint_id[fingerprint_id]
            for fingerprint_id in family.fingerprint_ids
        )
        for index, left in enumerate(member_evidence):
            for right in member_evidence[index + 1 :]:
                assert (
                    similarity_module._pairwise_comparable_signature(left, right)
                    is not None
                )


def test_html_reference_signature_omits_query_values_fragments_and_credentials() -> None:
    urls = (
        "https://app.example.test/missing-alpha",
        "https://app.example.test/missing-beta",
    )
    references = (
        "/continue?token=secret-value&mode=review#private-section",
        "https://operator:password@app.example.test:443/next?code=private-code#account",
    )
    items = tuple(
        _item(
            url,
            500,
            content_type="text/html",
            body_preview=_reference_template_body(url, references),
            body_hash=f"reference-{index}",
            body_bytes=2400,
        )
        for index, url in enumerate(urls, start=1)
    )
    http_summary, redirect_review = _inputs(*items)

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    family = next(
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    )
    signature = "\n".join(family.grouping_signature)
    rendered = render_deep_response_similarity_review_markdown(review)

    for forbidden in (
        "secret-value",
        "private-section",
        "operator",
        "password",
        "private-code",
        "#account",
    ):
        assert forbidden not in signature
        assert forbidden not in rendered


def test_reference_query_values_fragments_and_credentials_do_not_split_family() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-beta"
    first_references = (
        "/continue?token=first-value&mode=review#first-fragment",
        "https://first-user:first-pass@app.example.test/next?code=first-code#one",
    )
    second_references = (
        "/continue?token=second-value&mode=review#second-fragment",
        "https://second-user:second-pass@app.example.test/next?code=second-code#two",
    )
    http_summary, redirect_review = _inputs(
        _item(
            first_url,
            500,
            content_type="text/html",
            body_preview=_reference_template_body(first_url, first_references),
            body_hash="safe-reference-a",
            body_bytes=2400,
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=_reference_template_body(second_url, second_references),
            body_hash="safe-reference-b",
            body_bytes=2400,
        ),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    families = [
        group
        for group in review.groups
        if group.category == "request_reflecting_template_group"
    ]
    assert len(families) == 1
    signature = "\n".join(families[0].grouping_signature)
    for forbidden in (
        "first-value",
        "second-value",
        "first-fragment",
        "second-fragment",
        "first-user",
        "second-user",
        "first-pass",
        "second-pass",
        "first-code",
        "second-code",
    ):
        assert forbidden not in signature


def test_insufficient_safely_comparable_previews_do_not_form_family() -> None:
    urls = (
        "https://app.example.test/missing-alpha",
        "https://app.example.test/missing-beta",
    )
    http_summary, redirect_review = _inputs(
        *(
            _item(
                url,
                500,
                content_type="text/html",
                body_preview=(
                    "<html><head>"
                    f"<title>Request failed for {urlsplit(url).path}</title>"
                    "</head><body>Insufficient retained structure.</body></html>"
                ),
                body_hash=f"short-{index}",
                body_bytes=2400,
            )
            for index, url in enumerate(urls, start=1)
        )
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)

    assert not any(
        group.category == "request_reflecting_template_group"
        for group in review.groups
    )


def test_missing_content_type_method_and_redirect_variants_fail_closed() -> None:
    first_url = "https://app.example.test/missing-alpha"
    second_url = "https://app.example.test/missing-beta"
    first = _item(
        first_url,
        500,
        content_type="text/html",
        body_preview=_reflected_template_body(first_url),
        body_bytes=2400,
    )
    variants = (
        replace(
            _item(
                second_url,
                500,
                body_preview=_reflected_template_body(second_url),
                body_bytes=2400,
            ),
            body_sha256="missing-content-type",
        ),
        _item(
            second_url,
            500,
            content_type="text/html",
            body_preview=_reflected_template_body(second_url),
            body_bytes=2400,
            method="HEAD",
        ),
        replace(
            _item(
                second_url,
                500,
                location="/error",
                content_type="text/html",
                body_preview=_reflected_template_body(second_url),
                body_bytes=2400,
            ),
            final_url="https://app.example.test/error",
            body_sha256="redirected",
        ),
    )

    for variant in variants:
        http_summary, redirect_review = _inputs(first, variant)
        review = build_deep_response_similarity_review(http_summary, redirect_review)
        assert not any(
            group.category == "request_reflecting_template_group"
            for group in review.groups
        )


def test_unique_success_evidence_ids_are_canonical_for_reversed_public_model() -> None:
    http_summary, redirect_review = _inputs(
        _item(
            "http://example.test/unique",
            200,
            body_hash="unique",
            body_bytes=50,
            evidence_ids=("EVID-B", "EVID-A", "EVID-A"),
        )
    )
    reversed_fingerprint = replace(
        http_summary.fingerprints[0],
        evidence_ids=tuple(reversed(http_summary.fingerprints[0].evidence_ids)),
    )
    reversed_http_summary = replace(
        http_summary,
        fingerprints=(reversed_fingerprint,),
    )

    normal = build_deep_response_similarity_review(http_summary, redirect_review)
    reversed_review = build_deep_response_similarity_review(
        reversed_http_summary,
        redirect_review,
    )

    assert normal.unique_success_responses == reversed_review.unique_success_responses
    assert normal.unique_success_responses[0].evidence_ids == ("EVID-A", "EVID-B")


def test_repeated_body_source_group_id_is_rendered() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, body_hash="same", body_bytes=500),
        _item("http://example.test/b", 200, body_hash="same", body_bytes=500),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    rendered = render_deep_response_similarity_review_markdown(review)

    assert review.groups[0].source_repeated_body_group_ids == ("DEEP-HTTP-REP-0001",)
    assert "Source repeated body groups: `DEEP-HTTP-REP-0001`" in rendered


def test_summary_counts_are_correct() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/exact-a", 200, body_hash="same", body_bytes=500),
        _item("http://example.test/exact-b", 200, body_hash="same", body_bytes=500),
        _item("http://example.test/redir-a", 302, location="/login"),
        _item("http://example.test/redir-b", 302, location="/login"),
        _item("http://example.test/missing-a", 404, content_type="text/html", server="Apache", body_bytes=900),
        _item("http://example.test/missing-b", 404, content_type="text/html", server="Apache", body_bytes=950),
        _item("http://example.test/unique", 200, body_hash="unique", body_bytes=42),
    )

    review = build_deep_response_similarity_review(http_summary, redirect_review)
    counts = review.summary_counts

    assert counts.total_http_fingerprints_considered == 7
    assert counts.total_redirect_observations_considered == 2
    assert counts.exact_body_hash_groups == 1
    assert counts.redirect_pattern_groups == 1
    assert counts.repeated_auth_looking_redirect_groups == 1
    assert counts.client_error_signature_groups == 1
    assert counts.total_grouped_fingerprints == 6
    assert counts.unique_ungrouped_2xx_responses == 1


def test_renderer_includes_required_sections_compaction_and_cautionary_wording() -> None:
    http_summary, redirect_review = _inputs(
        *(
            _item(
                f"http://example.test/path-{index}-" + "x" * 140,
                200,
                content_type="text/html",
                server="Apache",
                body_hash="same",
                body_bytes=500,
                evidence_ids=(f"EVID-{index}",),
            )
            for index in range(8)
        )
    )

    rendered = render_deep_response_similarity_review_markdown(
        build_deep_response_similarity_review(http_summary, redirect_review)
    )

    for expected in (
        "## Deep Response Similarity Review",
        "### Summary",
        "### Response Similarity Groups",
        "### Unique Ungrouped 2xx Responses",
        "### Grouping Interpretation Notes",
        "### Safety Notes",
        "offline deterministic grouping of existing HTTP fingerprint evidence",
        "No network requests were made.",
        "No responses were fetched.",
        "No redirects were followed.",
        "shared bounded evidence signatures",
        "review hypotheses only",
        "comparison context",
        "This stage produces static manual-review context only.",
    ):
        assert expected in rendered
    assert "... +2 more" in rendered
    assert "[truncated]" in rendered


def test_renderer_avoids_prohibited_wording() -> None:
    http_summary, redirect_review = _inputs(
        _item("http://example.test/a", 200, body_hash="same", body_bytes=500),
        _item("http://example.test/b", 200, body_hash="same", body_bytes=500),
    )

    rendered = render_deep_response_similarity_review_markdown(
        build_deep_response_similarity_review(http_summary, redirect_review)
    ).lower()

    for forbidden in (
        "confirmed default page",
        "confirmed soft 404",
        "identical application",
        "vulnerability",
        "insecure",
        "exploitable",
        "authentication bypass",
        "open redirect",
        "attack",
        "no vulnerabilities found",
    ):
        assert forbidden not in rendered


def test_builder_renderer_add_no_io_network_collectors_or_redirect_following() -> None:
    source = inspect.getsource(similarity_module)

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


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _inputs(*items: DeepSourceRouteCollectedItem):
    http_summary = build_deep_http_fingerprint_summary(
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
    return http_summary, build_deep_redirect_auth_flow_review(http_summary)


def _item(
    url: str,
    status_code: int,
    *,
    location: str | None = None,
    content_type: str | None = None,
    server: str | None = None,
    title: str | None = None,
    body_preview: str | None = None,
    body_hash: str | None = None,
    body_bytes: int = 100,
    evidence_ids: tuple[str, ...] = ("EVID-1",),
    method: str = "GET",
) -> DeepSourceRouteCollectedItem:
    headers: list[tuple[str, str]] = []
    if location is not None:
        headers.append(("Location", location))
    if content_type is not None:
        headers.append(("Content-Type", content_type))
    if server is not None:
        headers.append(("Server", server))
    rendered_body_preview = body_preview or ""
    if body_preview is None and title is not None:
        rendered_body_preview = f"<html><head><title>{title}</title></head>"
    return DeepSourceRouteCollectedItem(
        url=url,
        method=method,
        status_code=status_code,
        final_url=url,
        headers=tuple(headers),
        body_preview=rendered_body_preview,
        body_sha256=body_hash or f"hash-{url}-{status_code}",
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="test",
        evidence_ids=evidence_ids,
    )


def _reflected_template_body(
    request_url: str,
    *,
    reflected_value: str | None = None,
    unrelated_path: str = "/public/help",
) -> str:
    reflected = reflected_value or urlsplit(request_url).path
    body = (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {reflected}</title>"
        "<style>html,body{margin:0;padding:0}main{display:block}"
        ".message{font-family:sans-serif;color:#222}</style></head>"
        "<body><main><h1>Request could not be completed</h1>"
        f"<p class='message'>The requested resource {reflected} was not handled.</p>"
        f"<a href='{unrelated_path}'>Documentation</a>"
        "</main></body></html>"
    )
    return _collector_sized_preview(body)


def _late_difference_template(
    request_url: str,
    *,
    common_padding: str,
    late_content: str,
) -> str:
    path = urlsplit(request_url).path
    return (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title></head>"
        f"<body><main><p>The requested resource {path} was not handled.</p>"
        f"<div>{common_padding}</div>{late_content}</main></body></html>"
    )


def _fixed_boundary_reflected_template(
    request_url: str,
    *,
    retained_chars: int,
) -> str:
    path = urlsplit(request_url).path
    prefix = (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title></head>"
        "<body><main><h1>Request could not be completed</h1>"
        f"<p>The requested resource {path} was not handled.</p><div>"
    )
    assert len(prefix) < retained_chars
    return prefix + ("X" * (retained_chars - len(prefix)))


def _replacement_boundary_template(request_url: str) -> str:
    path = urlsplit(request_url).path
    prefix = (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title></head>"
        "<body><main><h1>Request could not be completed</h1>"
        f"<p>The requested resource {path} was not handled.</p><div>"
    )
    assert len(prefix) < 500
    return prefix + ("�" * (500 - len(prefix)))


def _reference_template_body(
    request_url: str,
    references: tuple[str, ...],
) -> str:
    path = urlsplit(request_url).path
    links = "".join(
        f"<a href='{reference}'>Continue</a>" for reference in references
    )
    body = (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title>"
        "</head>"
        "<body><main><h1>Request could not be completed</h1>"
        f"<p class='message'>The requested resource {path} was not handled.</p>"
        f"{links}</main></body></html>"
    )
    return _collector_sized_preview(body)


def _collector_sized_preview(body: str) -> str:
    assert len(body) <= 500
    return body + (" " * (500 - len(body)))


def _shortest_member_false_merge_items(
    *,
    second_tail: str,
    third_tail: str,
) -> tuple[DeepSourceRouteCollectedItem, ...]:
    urls = (
        "https://app.example.test/"
        + "long-reflected-request-value-"
        + ("x" * 35),
        "https://app.example.test/a",
        "https://app.example.test/b",
    )
    tails = ("Shortest member does not retain this suffix.", second_tail, third_tail)
    items: list[DeepSourceRouteCollectedItem] = []
    for index, (url, tail) in enumerate(zip(urls, tails, strict=True), start=1):
        path = urlsplit(url).path
        source = (
            "<html><head><meta charset='utf-8'>"
            f"<title>Request failed for {path}</title></head>"
            "<body><main><h1>Request could not be completed</h1>"
            f"<p>The requested resource {path} was not handled.</p>"
            "<div>"
            + ("X" * 285)
            + tail
            + ("Y" * 200)
            + "</div></main></body></html>"
        )
        preview = source[:500]
        assert len(preview) == 500
        items.append(
            _item(
                url,
                500,
                content_type="text/html",
                body_preview=preview,
                body_hash=f"shortest-member-{index}",
                body_bytes=2400,
                evidence_ids=(f"EVID-SHORTEST-{index}",),
            )
        )
    return tuple(items)


def _complete_reflected_template(request_url: str, *, conclusion: str) -> str:
    path = urlsplit(request_url).path
    return (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title>"
        "<style>main{display:block}.message{font-family:sans-serif}</style>"
        "</head><body><main><h1>Request could not be completed</h1>"
        f"<p>The requested resource {path} was not handled.</p>"
        f"<section><p>{conclusion}</p></section>"
        "<div>Stable complete retained comparison padding. "
        "Stable complete retained comparison padding.</div>"
        "</main></body></html>"
    )


_EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
