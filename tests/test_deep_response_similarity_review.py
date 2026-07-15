"""Tests for offline Deep response similarity review."""

from __future__ import annotations

from dataclasses import replace
import inspect

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
    body_hash: str | None = None,
    body_bytes: int = 100,
    evidence_ids: tuple[str, ...] = ("EVID-1",),
) -> DeepSourceRouteCollectedItem:
    headers: list[tuple[str, str]] = []
    if location is not None:
        headers.append(("Location", location))
    if content_type is not None:
        headers.append(("Content-Type", content_type))
    if server is not None:
        headers.append(("Server", server))
    body_preview = ""
    if title is not None:
        body_preview = f"<html><head><title>{title}</title></head>"
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=url,
        headers=tuple(headers),
        body_preview=body_preview,
        body_sha256=body_hash or f"hash-{url}-{status_code}",
        body_bytes=body_bytes,
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="test",
        evidence_ids=evidence_ids,
    )


_EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
