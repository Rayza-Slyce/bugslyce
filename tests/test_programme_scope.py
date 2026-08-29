"""Tests for canonical, pure programme target-scope evaluation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from itertools import permutations

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    DESTINATION_HOSTNAME,
    DESTINATION_HTTP_URL,
    DESTINATION_IPV4,
    OUTCOME_ALLOWED,
    OUTCOME_BLOCKED,
    OUTCOME_UNKNOWN,
    PROGRAMME_SCOPE_SCHEMA_VERSION,
    REASON_EXPLICIT_EXCLUSION,
    REASON_INCLUDED,
    REASON_INVALID_DESTINATION,
    REASON_NO_MATCHING_INCLUSION,
    REASON_RESOLVED_IP_EXCLUDED,
    REASON_RESOLVED_IP_REQUIRES_EXPLICIT_INCLUSION,
    REASON_UNSUPPORTED_DESTINATION,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    CanonicalHTTPOrigin,
    CanonicalHTTPURLDestination,
    CanonicalHostnameDestination,
    CanonicalIPv4Destination,
    ProgrammeScopePolicy,
    ProgrammeScopeRule,
    ScopeDecision,
    _resolved_ipv4_peer_requires_explicit_inclusion,
    build_programme_scope_policy,
    build_programme_scope_rule,
    canonicalise_hostname,
    canonicalise_hostname_destination,
    canonicalise_http_origin,
    canonicalise_http_path,
    canonicalise_http_url_destination,
    canonicalise_ipv4,
    canonicalise_ipv4_cidr,
    canonicalise_ipv4_destination,
    canonicalise_resolved_ipv4_peer,
    evaluate_programme_scope,
    evaluate_raw_scope_destination,
    evaluate_resolved_ipv4_peer,
    validate_http_query,
    validate_private_scope_text,
    validate_rule_id,
)


PRIVATE_NOTE = "private-note-sentinel-751902"
PRIVATE_SOURCE = "private-source-sentinel-751902"
FIXED_TIMESTAMP = "2026-07-29T10:30:00Z"
LEGACY_NUMERIC_HOSTNAMES = (
    "0x7f000001",
    "0X7F000001",
    "0x7f.0.0.1",
    "0X7F.1",
    "1.0x2.3",
    "1.2.3.0x4",
    "0177.0x0.0.1",
    "0xffffffff",
)


def _rule(
    rule_id: str,
    kind: str,
    value: str,
    *,
    action: str = ACTION_INCLUDE,
    private: bool = False,
) -> ProgrammeScopeRule:
    return build_programme_scope_rule(
        rule_id=rule_id,
        action=action,
        kind=kind,
        value=value,
        private_note=PRIVATE_NOTE if private else None,
        private_source_wording=PRIVATE_SOURCE if private else None,
    )


def _policy(*rules: ProgrammeScopeRule) -> ProgrammeScopePolicy:
    return build_programme_scope_policy(rules, updated_at=FIXED_TIMESTAMP)


def _decision(policy: ProgrammeScopePolicy, kind: str, value: str):
    return evaluate_raw_scope_destination(policy, kind, value)


def test_policy_model_is_versioned_deterministic_immutable_and_allows_empty_default_deny() -> None:
    policy = build_programme_scope_policy(
        [],
        clock=lambda: datetime(2026, 7, 29, 10, 30, tzinfo=timezone.utc),
    )

    assert policy.schema_version == PROGRAMME_SCOPE_SCHEMA_VERSION
    assert policy.engagement_context == "bug_bounty"
    assert policy.updated_at == FIXED_TIMESTAMP
    assert policy.rules == ()
    assert policy.to_dict() == {
        "engagement_context": "bug_bounty",
        "rules": [],
        "schema_version": PROGRAMME_SCOPE_SCHEMA_VERSION,
        "updated_at": FIXED_TIMESTAMP,
    }
    assert _decision(policy, DESTINATION_HOSTNAME, "example.test").outcome == OUTCOME_UNKNOWN
    with pytest.raises(FrozenInstanceError):
        policy.updated_at = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("schema", ["0.9", "2.0", "", None])
def test_policy_rejects_unsupported_schema(schema) -> None:
    with pytest.raises(ValueError, match="schema version"):
        build_programme_scope_policy([], schema_version=schema, updated_at=FIXED_TIMESTAMP)


@pytest.mark.parametrize("context", ["ctf_lab", "unknown", "internal_authorised", "", None])
def test_policy_requires_bug_bounty_context(context) -> None:
    with pytest.raises(ValueError, match="context"):
        build_programme_scope_policy(
            [], engagement_context=context, updated_at=FIXED_TIMESTAMP
        )


@pytest.mark.parametrize(
    "timestamp",
    ["", " 2026-07-29T10:30:00Z", "2026-07-29", "2026-07-29T10:30:00+00:00", "x" * 65],
)
def test_policy_rejects_noncanonical_timestamps(timestamp: str) -> None:
    with pytest.raises(ValueError, match="canonical UTC timestamp"):
        build_programme_scope_policy([], updated_at=timestamp)


def test_policy_sorts_rules_and_rejects_case_insensitive_duplicate_ids() -> None:
    later = _rule("scope-20", RULE_EXACT_HOSTNAME, "later.test")
    earlier = _rule("scope-10", RULE_EXACT_HOSTNAME, "earlier.test")
    policy = _policy(later, earlier)
    assert tuple(rule.rule_id for rule in policy.rules) == ("scope-10", "scope-20")

    with pytest.raises(ValueError, match="unique case-insensitively"):
        _policy(earlier, _rule("SCOPE-10", RULE_EXACT_HOSTNAME, "other.test"))


@pytest.mark.parametrize(
    "rule_id",
    ["", " has-space", "has space", "rule/one", "rule:one", "-leading", "x" * 65, "r\n1"],
)
def test_rule_id_uses_conservative_bounded_ascii_syntax(rule_id: str) -> None:
    with pytest.raises(ValueError, match="rule ID"):
        validate_rule_id(rule_id)


def test_rule_action_kind_and_canonical_direct_construction_are_strict() -> None:
    with pytest.raises(ValueError, match="action"):
        build_programme_scope_rule(
            rule_id="r1", action="allow", kind=RULE_EXACT_HOSTNAME, value="example.test"
        )
    with pytest.raises(ValueError, match="kind"):
        build_programme_scope_rule(
            rule_id="r1", action=ACTION_INCLUDE, kind="generic", value="example.test"
        )
    with pytest.raises(ValueError, match="not canonical"):
        ProgrammeScopeRule("r1", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "EXAMPLE.TEST")


@pytest.mark.parametrize("value", ["", "   ", "line\nbreak", "unsafe\u202evalue", "x" * 4097])
def test_private_scope_text_is_bounded_and_rejects_controls(value: str) -> None:
    with pytest.raises(ValueError):
        validate_private_scope_text(value, label="Private text")


def test_private_values_are_absent_from_repr_and_decisions() -> None:
    rule = _rule("private-rule", RULE_EXACT_HOSTNAME, "private.test", private=True)
    policy = _policy(rule)
    decision = _decision(policy, DESTINATION_HOSTNAME, "private.test")
    rendered = f"{rule!r}\n{policy!r}\n{decision!r}\n{decision.operator_safe_explanation}"

    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered
    assert decision.outcome == OUTCOME_ALLOWED
    with pytest.raises(FrozenInstanceError):
        rule.canonical_value = "changed.test"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("Example.TEST", "example.test"),
        ("example.test.", "example.test"),
        ("single-label", "single-label"),
    ],
)
def test_hostname_canonicalisation(raw: str, canonical: str) -> None:
    assert canonicalise_hostname(raw) == canonical


@pytest.mark.parametrize(
    "raw",
    [
        " example.test",
        "example.test ",
        "example..test",
        "example.test..",
        "-bad.example",
        "bad-.example",
        "bad_name.example",
        "bücher.example",
        "192.0.2.1",
        "127.1",
        "2130706433",
        "1.2.3",
        "xn--.example",
        "a" * 64 + ".example",
    ],
)
def test_hostname_rejects_ambiguous_or_invalid_input(raw: str) -> None:
    with pytest.raises(ValueError):
        canonicalise_hostname(raw)


@pytest.mark.parametrize("raw", LEGACY_NUMERIC_HOSTNAMES)
def test_hostname_rejects_legacy_numeric_ipv4_syntax(raw: str) -> None:
    with pytest.raises(ValueError, match="Ambiguous numeric hostname"):
        canonicalise_hostname(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "0x7f.example.test",
        "host0x7f.example.test",
        "0xgg.example.test",
        "example.0x7f.test",
        "deadbeef.example.test",
    ],
)
def test_hexadecimal_looking_dns_labels_remain_ordinary_hostnames(raw: str) -> None:
    assert canonicalise_hostname(raw) == raw


def test_legacy_numeric_hostname_is_rejected_at_every_scope_boundary() -> None:
    policy = _policy()

    with pytest.raises(ValueError, match="Ambiguous numeric hostname"):
        _rule("host", RULE_EXACT_HOSTNAME, "0x7f000001")
    with pytest.raises(ValueError, match="Ambiguous numeric hostname"):
        _rule("wild", RULE_WILDCARD_SUBDOMAIN, "*.0X7F.1")
    assert (
        evaluate_raw_scope_destination(
            policy,
            DESTINATION_HOSTNAME,
            "1.0x2.3",
        ).reason_code
        == REASON_INVALID_DESTINATION
    )
    with pytest.raises(ValueError, match="Ambiguous numeric hostname"):
        canonicalise_http_url_destination("https://1.2.3.0x4/path")
    with pytest.raises(ValueError, match="Ambiguous numeric hostname"):
        canonicalise_http_origin("https://0xffffffff/")


def test_dotted_decimal_ipv4_remains_an_ipv4_destination_only() -> None:
    with pytest.raises(ValueError, match="IPv4 literals"):
        canonicalise_hostname("192.0.2.4")
    assert canonicalise_ipv4_destination("192.0.2.4").canonical_value == "192.0.2.4"


@pytest.mark.parametrize(
    "raw",
    [
        "xn--bcher-kva.example",
        "XN--BCHER-KVA.example",
        "xn--fa-hia.de",
        "xn--ls8h.example",
    ],
)
def test_hostname_rejects_every_internationalised_ascii_alabel(raw: str) -> None:
    with pytest.raises(
        ValueError,
        match="Internationalised hostname scope is not supported",
    ):
        canonicalise_hostname(raw)


@pytest.mark.parametrize("raw", ["bücher.example", "faß.de", "💩.example"])
def test_hostname_rejects_unicode_ulabels(raw: str) -> None:
    with pytest.raises(
        ValueError,
        match="Internationalised hostname scope is not supported",
    ):
        canonicalise_hostname(raw)


def test_hostname_total_length_boundaries() -> None:
    valid = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
    assert len(valid) == 253
    assert canonicalise_hostname(valid) == valid
    with pytest.raises(ValueError, match="length"):
        canonicalise_hostname(f"{valid}e")


def test_exact_hostname_matches_apex_only() -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    assert _decision(policy, DESTINATION_HOSTNAME, "example.test").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HOSTNAME, "a.example.test").outcome == OUTCOME_UNKNOWN


def test_wildcard_matches_proper_descendants_at_any_depth_but_not_apex_or_lookalike() -> None:
    policy = _policy(_rule("wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test"))

    assert _decision(policy, DESTINATION_HOSTNAME, "a.example.test").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HOSTNAME, "b.a.example.test").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HOSTNAME, "example.test").outcome == OUTCOME_UNKNOWN
    assert _decision(policy, DESTINATION_HOSTNAME, "badexample.test").outcome == OUTCOME_UNKNOWN


def test_scheme_and_port_constrained_wildcard_http_scope_fails_closed() -> None:
    qualified_wildcard = build_programme_scope_rule(
        rule_id="qualified-wildcard",
        action=ACTION_INCLUDE,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.Example.TEST",
        scheme="https",
        port=443,
    )
    qualified_exclusion = build_programme_scope_rule(
        rule_id="qualified-exclusion",
        action=ACTION_EXCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="blocked.api.example.test",
        scheme="https",
        port=443,
    )
    policy = _policy(qualified_wildcard, qualified_exclusion)

    assert qualified_wildcard.canonical_value == "*.example.test"
    assert qualified_wildcard.scheme == "https"
    assert qualified_wildcard.port == 443
    assert qualified_wildcard.to_dict()["scheme"] == "https"
    assert qualified_wildcard.to_dict()["port"] == 443
    assert _decision(
        policy, DESTINATION_HTTP_URL, "https://api.example.test/"
    ).outcome == OUTCOME_ALLOWED
    assert _decision(
        policy, DESTINATION_HTTP_URL, "https://child.api.example.test/"
    ).outcome == OUTCOME_ALLOWED
    assert _decision(
        policy, DESTINATION_HTTP_URL, "http://api.example.test/"
    ).outcome == OUTCOME_UNKNOWN
    assert _decision(
        policy, DESTINATION_HTTP_URL, "https://api.example.test:8443/"
    ).outcome == OUTCOME_UNKNOWN
    assert _decision(
        policy, DESTINATION_HTTP_URL, "https://example.test/"
    ).outcome == OUTCOME_UNKNOWN
    assert _decision(
        policy, DESTINATION_HOSTNAME, "api.example.test"
    ).outcome == OUTCOME_UNKNOWN
    blocked = _decision(
        policy,
        DESTINATION_HTTP_URL,
        "https://blocked.api.example.test/",
    )
    assert blocked.outcome == OUTCOME_BLOCKED
    assert blocked.reason_code == REASON_EXPLICIT_EXCLUSION


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("exact_http_url", "https://example.test/"),
        ("http_path_prefix", "https://example.test/api/"),
        ("exact_ipv4", "192.0.2.10"),
        ("ipv4_cidr", "192.0.2.0/24"),
    ],
)
def test_http_qualifiers_are_rejected_for_non_hostname_scope_rules(
    kind: str,
    value: str,
) -> None:
    with pytest.raises(ValueError, match="qualifier|scheme|port"):
        build_programme_scope_rule(
            rule_id=f"invalid-{kind.replace('_', '-')}",
            action=ACTION_INCLUDE,
            kind=kind,
            value=value,
            scheme="https",
            port=443,
        )


@pytest.mark.parametrize(
    "wildcard",
    ["example.test", "*example.test", "*.*.example.test", "foo.*.example.test", "*.", "*.192.0.2.1"],
)
def test_wildcard_requires_one_leading_marker_and_valid_hostname_suffix(wildcard: str) -> None:
    with pytest.raises(ValueError):
        _rule("wild", RULE_WILDCARD_SUBDOMAIN, wildcard)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [("0.0.0.0", "0.0.0.0"), ("192.0.2.255", "192.0.2.255")],
)
def test_ipv4_canonicalisation(raw: str, canonical: str) -> None:
    assert canonicalise_ipv4(raw) == canonical


@pytest.mark.parametrize(
    "raw",
    [" 192.0.2.1", "192.0.2.1 ", "192.168.001.1", "127.1", "0x7f000001", "2130706433", "::1"],
)
def test_ipv4_rejects_ambiguous_noncanonical_and_ipv6_forms(raw: str) -> None:
    with pytest.raises(ValueError):
        canonicalise_ipv4(raw)


def test_ipv4_cidr_is_strict_network_aligned_and_ipv4_only() -> None:
    assert canonicalise_ipv4_cidr("192.0.2.0/24") == "192.0.2.0/24"
    for raw in ("192.0.2.1/24", "192.0.2.0/024", "192.0.2.0/33", "::1/128", " 192.0.2.0/24"):
        with pytest.raises(ValueError):
            canonicalise_ipv4_cidr(raw)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "0.255.255.255",
        "10.0.0.0",
        "10.255.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.0",
        "127.255.255.255",
        "169.254.0.0",
        "169.254.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.0.0.0",
        "192.0.0.9",
        "192.0.0.10",
        "192.0.0.255",
        "192.0.2.0",
        "192.0.2.255",
        "192.31.196.0",
        "192.31.196.255",
        "192.52.193.0",
        "192.52.193.255",
        "192.88.99.0",
        "192.88.99.255",
        "192.168.0.0",
        "192.168.255.255",
        "192.175.48.0",
        "192.175.48.255",
        "198.18.0.0",
        "198.19.255.255",
        "198.51.100.0",
        "198.51.100.255",
        "203.0.113.0",
        "203.0.113.255",
        "224.0.0.0",
        "239.255.255.255",
        "240.0.0.0",
        "255.255.255.255",
    ],
)
def test_special_purpose_or_multicast_ipv4_peer_requires_explicit_inclusion(
    address: str,
) -> None:
    assert _resolved_ipv4_peer_requires_explicit_inclusion(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "1.1.1.1",
        "8.8.8.8",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.255",
        "192.0.3.0",
        "192.31.195.255",
        "192.31.197.0",
        "192.52.192.255",
        "192.52.194.0",
        "192.88.98.255",
        "192.88.100.0",
        "192.167.255.255",
        "192.169.0.0",
        "192.175.47.255",
        "192.175.49.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "198.51.101.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",
    ],
)
def test_ipv4_outside_owned_special_purpose_table_does_not_require_explicit_inclusion(
    address: str,
) -> None:
    assert _resolved_ipv4_peer_requires_explicit_inclusion(address) is False


def test_ipv4_exact_and_cidr_boundaries_are_evaluated_without_hostname_inference() -> None:
    policy = _policy(
        _rule("cidr", RULE_IPV4_CIDR, "192.0.2.0/24"),
        _rule("exact", RULE_EXACT_IPV4, "198.51.100.4"),
    )

    assert _decision(policy, DESTINATION_IPV4, "192.0.2.0").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_IPV4, "192.0.2.255").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_IPV4, "192.0.3.0").outcome == OUTCOME_UNKNOWN
    assert _decision(policy, DESTINATION_IPV4, "198.51.100.4").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HOSTNAME, "host.example").outcome == OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("HTTP://Example.TEST", "http://example.test/"),
        ("http://example.test:80/", "http://example.test/"),
        ("https://example.test:443/path", "https://example.test/path"),
        ("https://example.test:8443/path", "https://example.test:8443/path"),
        ("http://192.0.2.4/path", "http://192.0.2.4/path"),
        ("https://example.test?", "https://example.test/?"),
    ],
)
def test_http_url_origin_and_default_port_canonicalisation(raw: str, canonical: str) -> None:
    assert canonicalise_http_url_destination(raw).canonical_value == canonical


def test_explicit_origin_canonicaliser_never_discards_path_or_query() -> None:
    assert canonicalise_http_origin("https://example.test").canonical_value == (
        "https://example.test"
    )
    assert canonicalise_http_origin("HTTPS://Example.TEST:443/").canonical_value == (
        "https://example.test"
    )
    assert canonicalise_http_origin("http://192.0.2.4:8080").canonical_value == (
        "http://192.0.2.4:8080"
    )
    with pytest.raises(ValueError, match="path or query"):
        canonicalise_http_origin("https://example.test/api")
    with pytest.raises(ValueError, match="path or query"):
        canonicalise_http_origin("https://example.test/?")


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.test/.",
        "https://example.test/%2e",
        "https://example.test/%2E",
        "https://example.test/a/..",
        "https://example.test/a/%2e%2e",
        "https://example.test//..",
        "https://example.test/./",
        "https://example.test/a/../",
    ],
)
def test_explicit_origin_rejects_raw_nonroot_paths_that_normalise_to_root(
    raw: str,
) -> None:
    with pytest.raises(ValueError, match="raw path"):
        canonicalise_http_origin(raw)


def test_ordinary_urls_and_rules_retain_dot_segment_canonicalisation() -> None:
    raw = "https://example.test/a/.."

    assert canonicalise_http_url_destination(raw).canonical_value == (
        "https://example.test/"
    )
    assert _rule("url", RULE_EXACT_HTTP_URL, raw).canonical_value == (
        "https://example.test/"
    )
    assert _rule("prefix", RULE_HTTP_PATH_PREFIX, raw).canonical_value == (
        "https://example.test/"
    )


@pytest.mark.parametrize(
    "raw",
    [
        "example.test/path",
        "/relative",
        "ftp://example.test/",
        "http://user:pass@example.test/",
        "http://example.test/#fragment",
        "http://example.test#",
        "http://example.test\\path",
        " http://example.test/",
        "http://example.test:bad/",
        "http://example.test:/",
        "http://[::1]/",
        "http://bücher.example/",
    ],
)
def test_http_url_rejects_unsupported_or_ambiguous_forms(raw: str) -> None:
    with pytest.raises(ValueError):
        canonicalise_http_url_destination(raw)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("", "/"),
        ("/", "/"),
        ("/a/./b", "/a/b"),
        ("/a/../b", "/b"),
        ("/a/.", "/a/"),
        ("/a/..", "/"),
        ("/%2e/a", "/a"),
        ("/a/%2E%2E/b", "/b"),
        ("/a//b", "/a//b"),
        ("/a//b/", "/a//b/"),
        ("/a;b//c", "/a;b//c"),
        ("/a%7eb", "/a~b"),
        ("/a%3fb", "/a%3Fb"),
    ],
)
def test_http_path_canonicalisation(raw: str, canonical: str) -> None:
    assert canonicalise_http_path(raw) == canonical


@pytest.mark.parametrize(
    "path",
    [
        "relative",
        "/a\\b",
        "/a b",
        "/a?b",
        "/a#b",
        "/%",
        "/%2",
        "/%GG",
        "/%2f",
        "/%2F",
        "/%5c",
        "/%5C",
        "/%252f",
        "/%252F",
        "/%255c",
        "/%255C",
        "/%25%32%66",
        "/%25%35%43",
        "/%252e%252e/secret",
        "/%00",
        "/%7f",
        "/%C3%A9",
    ],
)
def test_http_path_rejects_ambiguous_escapes_and_unsafe_characters(path: str) -> None:
    with pytest.raises(ValueError):
        canonicalise_http_path(path)


def test_query_preserves_order_duplicates_escape_case_and_empty_marker() -> None:
    first = canonicalise_http_url_destination(
        "https://example.test/search?b=2&a=1&a=3&encoded=%2f"
    )
    second = canonicalise_http_url_destination(
        "https://example.test/search?a=1&b=2&a=3&encoded=%2F"
    )
    absent = canonicalise_http_url_destination("https://example.test/search")
    empty = canonicalise_http_url_destination("https://example.test/search?")

    assert first.query == "b=2&a=1&a=3&encoded=%2f"
    assert first.canonical_value != second.canonical_value
    assert absent.query is None
    assert empty.query == ""
    assert absent.canonical_value != empty.canonical_value


def test_exact_url_distinguishes_absent_and_empty_query_markers() -> None:
    absent_policy = _policy(
        _rule("absent", RULE_EXACT_HTTP_URL, "https://example.test/search")
    )
    empty_policy = _policy(
        _rule("empty", RULE_EXACT_HTTP_URL, "https://example.test/search?")
    )

    assert _decision(absent_policy, DESTINATION_HTTP_URL, "https://example.test/search").outcome == OUTCOME_ALLOWED
    assert _decision(absent_policy, DESTINATION_HTTP_URL, "https://example.test/search?").outcome == OUTCOME_UNKNOWN
    assert _decision(empty_policy, DESTINATION_HTTP_URL, "https://example.test/search?").outcome == OUTCOME_ALLOWED
    assert _decision(empty_policy, DESTINATION_HTTP_URL, "https://example.test/search").outcome == OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    "query",
    [
        "bad=%",
        "bad=%2",
        "bad=%GG",
        "bad=%00",
        "bad=%0A",
        "bad=%7f",
        "line\nbreak",
        "slash\\value",
        "café",
    ],
)
def test_query_rejects_malformed_escapes_controls_and_non_ascii(query: str) -> None:
    with pytest.raises(ValueError):
        validate_http_query(query)


def test_exact_url_matches_scheme_port_path_and_query_exactly() -> None:
    policy = _policy(
        _rule(
            "exact-url",
            RULE_EXACT_HTTP_URL,
            "https://example.test:8443/a/../api?x=1&x=2",
        )
    )

    assert (
        _decision(policy, DESTINATION_HTTP_URL, "https://EXAMPLE.test:8443/api?x=1&x=2").outcome
        == OUTCOME_ALLOWED
    )
    for other in (
        "http://example.test:8443/api?x=1&x=2",
        "https://example.test/api?x=1&x=2",
        "https://example.test:8443/api/?x=1&x=2",
        "https://example.test:8443/api?x=2&x=1",
        "https://example.test:8443/api",
    ):
        assert _decision(policy, DESTINATION_HTTP_URL, other).outcome == OUTCOME_UNKNOWN


def test_path_prefix_boundaries_queries_and_root_semantics() -> None:
    api = _policy(_rule("api", RULE_HTTP_PATH_PREFIX, "https://example.test/api"))
    api_slash = _policy(
        _rule("api-slash", RULE_HTTP_PATH_PREFIX, "https://example.test/api/")
    )
    root = _policy(_rule("root", RULE_HTTP_PATH_PREFIX, "https://example.test/"))

    for url in ("https://example.test/api", "https://example.test/api/v1", "https://example.test/api?x=1"):
        assert _decision(api, DESTINATION_HTTP_URL, url).outcome == OUTCOME_ALLOWED
    assert _decision(api, DESTINATION_HTTP_URL, "https://example.test/apiv2").outcome == OUTCOME_UNKNOWN
    assert _decision(api_slash, DESTINATION_HTTP_URL, "https://example.test/api").outcome == OUTCOME_UNKNOWN
    assert _decision(api_slash, DESTINATION_HTTP_URL, "https://example.test/api/").outcome == OUTCOME_ALLOWED
    assert _decision(api_slash, DESTINATION_HTTP_URL, "https://example.test/api/v1").outcome == OUTCOME_ALLOWED
    assert _decision(root, DESTINATION_HTTP_URL, "https://example.test/anything").outcome == OUTCOME_ALLOWED
    for different_origin in (
        "http://example.test/api",
        "https://example.test:8443/api",
        "https://other.test/api",
    ):
        assert _decision(api, DESTINATION_HTTP_URL, different_origin).outcome == OUTCOME_UNKNOWN


def test_path_prefix_rule_rejects_query_or_fragment() -> None:
    with pytest.raises(ValueError, match="must not contain a query"):
        _rule("prefix", RULE_HTTP_PATH_PREFIX, "https://example.test/api?x=1")
    with pytest.raises(ValueError, match="fragments"):
        _rule("prefix", RULE_HTTP_PATH_PREFIX, "https://example.test/api#part")


def test_hostname_wildcard_and_ip_rules_apply_to_http_urls_by_host_type() -> None:
    policy = _policy(
        _rule("host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("wild", RULE_WILDCARD_SUBDOMAIN, "*.apps.test"),
        _rule("network", RULE_IPV4_CIDR, "192.0.2.0/24"),
    )

    assert _decision(policy, DESTINATION_HTTP_URL, "https://example.test/any").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HTTP_URL, "http://a.apps.test:8080/any").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HTTP_URL, "http://192.0.2.7/any").outcome == OUTCOME_ALLOWED
    assert _decision(policy, DESTINATION_HTTP_URL, "http://other.test/any").outcome == OUTCOME_UNKNOWN


def test_ip_exclusion_applies_to_an_ip_literal_http_url() -> None:
    policy = _policy(
        _rule("network", RULE_IPV4_CIDR, "192.0.2.0/24"),
        _rule("blocked-ip", RULE_EXACT_IPV4, "192.0.2.7", action=ACTION_EXCLUDE),
    )

    decision = _decision(policy, DESTINATION_HTTP_URL, "https://192.0.2.7/path")
    assert decision.outcome == OUTCOME_BLOCKED
    assert decision.matched_inclusion_rule_ids == ("network",)
    assert decision.matched_exclusion_rule_ids == ("blocked-ip",)


def test_exclusions_override_host_path_exact_url_and_ip_inclusions() -> None:
    hostname_policy = _policy(
        _rule("include-wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test"),
        _rule("exclude-host", RULE_EXACT_HOSTNAME, "admin.example.test", action=ACTION_EXCLUDE),
    )
    assert _decision(hostname_policy, DESTINATION_HTTP_URL, "https://admin.example.test/").outcome == OUTCOME_BLOCKED

    url_policy = _policy(
        _rule("include-host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("include-path", RULE_HTTP_PATH_PREFIX, "https://example.test/api"),
        _rule("exclude-url", RULE_EXACT_HTTP_URL, "https://example.test/api/private", action=ACTION_EXCLUDE),
    )
    decision = _decision(url_policy, DESTINATION_HTTP_URL, "https://example.test/api/private")
    assert decision.outcome == OUTCOME_BLOCKED
    assert decision.reason_code == REASON_EXPLICIT_EXCLUSION
    assert decision.matched_inclusion_rule_ids == ("include-host", "include-path")
    assert decision.matched_exclusion_rule_ids == ("exclude-url",)

    ip_policy = _policy(
        _rule("include-cidr", RULE_IPV4_CIDR, "192.0.2.0/24"),
        _rule("exclude-ip", RULE_EXACT_IPV4, "192.0.2.4", action=ACTION_EXCLUDE),
    )
    assert _decision(ip_policy, DESTINATION_IPV4, "192.0.2.4").outcome == OUTCOME_BLOCKED


def test_exclusion_precedence_and_matched_ids_are_rule_order_independent() -> None:
    rules = (
        _rule("z-include-host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("a-include-path", RULE_HTTP_PATH_PREFIX, "https://example.test/api"),
        _rule("z-exclude-host", RULE_EXACT_HOSTNAME, "example.test", action=ACTION_EXCLUDE),
        _rule("a-exclude-url", RULE_EXACT_HTTP_URL, "https://example.test/api", action=ACTION_EXCLUDE),
    )
    decisions = {
        _decision(_policy(*order), DESTINATION_HTTP_URL, "https://example.test/api")
        for order in permutations(rules)
    }

    assert len(decisions) == 1
    decision = decisions.pop()
    assert decision.outcome == OUTCOME_BLOCKED
    assert decision.matched_inclusion_rule_ids == ("a-include-path", "z-include-host")
    assert decision.matched_exclusion_rule_ids == ("a-exclude-url", "z-exclude-host")
    assert decision.primary_exclusion_rule_id == "a-exclude-url"
    assert decision.operator_safe_explanation == (
        "Destination is blocked by explicit programme scope rule a-exclude-url."
    )


def test_primary_rule_specificity_is_display_only_and_uses_lexical_tie_break() -> None:
    policy = _policy(
        _rule("z-host", RULE_EXACT_HOSTNAME, "a.example.test"),
        _rule("z-wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test"),
        _rule("z-prefix-short", RULE_HTTP_PATH_PREFIX, "https://a.example.test/api"),
        _rule("a-prefix-long", RULE_HTTP_PATH_PREFIX, "https://a.example.test/api/v1"),
        _rule("z-exact", RULE_EXACT_HTTP_URL, "https://a.example.test/api/v1/users"),
        _rule("a-exact", RULE_EXACT_HTTP_URL, "https://a.example.test/api/v1/users"),
    )
    decision = _decision(
        policy,
        DESTINATION_HTTP_URL,
        "https://a.example.test/api/v1/users",
    )

    assert decision.outcome == OUTCOME_ALLOWED
    assert decision.primary_inclusion_rule_id == "a-exact"
    assert decision.reason_code == REASON_INCLUDED
    assert decision.operator_safe_explanation == (
        "Destination is included by programme scope rule a-exact."
    )


def test_primary_wildcard_and_cidr_rules_use_longest_suffix_or_prefix() -> None:
    host_policy = _policy(
        _rule("broad-wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test"),
        _rule("narrow-wild", RULE_WILDCARD_SUBDOMAIN, "*.apps.example.test"),
    )
    ip_policy = _policy(
        _rule("broad-cidr", RULE_IPV4_CIDR, "192.0.2.0/24"),
        _rule("narrow-cidr", RULE_IPV4_CIDR, "192.0.2.128/25"),
    )

    host_decision = _decision(
        host_policy, DESTINATION_HOSTNAME, "api.apps.example.test"
    )
    ip_decision = _decision(ip_policy, DESTINATION_IPV4, "192.0.2.200")
    assert host_decision.primary_inclusion_rule_id == "narrow-wild"
    assert ip_decision.primary_inclusion_rule_id == "narrow-cidr"


def test_default_deny_invalid_and_unsupported_decisions_are_structured() -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    no_match = _decision(policy, DESTINATION_HOSTNAME, "other.test")
    invalid = evaluate_raw_scope_destination(policy, DESTINATION_HOSTNAME, "bad host")
    unsupported = evaluate_raw_scope_destination(policy, "dns_record", "example.test")
    direct_unsupported = evaluate_programme_scope(policy, object())

    assert (no_match.outcome, no_match.reason_code) == (
        OUTCOME_UNKNOWN,
        REASON_NO_MATCHING_INCLUSION,
    )
    assert (invalid.outcome, invalid.reason_code, invalid.canonical_destination) == (
        OUTCOME_UNKNOWN,
        REASON_INVALID_DESTINATION,
        None,
    )
    assert unsupported.reason_code == REASON_UNSUPPORTED_DESTINATION
    assert direct_unsupported.reason_code == REASON_UNSUPPORTED_DESTINATION


def test_evaluator_generated_decisions_use_exact_canonical_explanations() -> None:
    policy = _policy(
        _rule("include", RULE_EXACT_HOSTNAME, "included.test"),
        _rule(
            "exclude",
            RULE_EXACT_HOSTNAME,
            "blocked.test",
            action=ACTION_EXCLUDE,
        ),
    )
    decisions = (
        (
            _decision(policy, DESTINATION_HOSTNAME, "included.test"),
            "Destination is included by programme scope rule include.",
        ),
        (
            _decision(policy, DESTINATION_HOSTNAME, "blocked.test"),
            "Destination is blocked by explicit programme scope rule exclude.",
        ),
        (
            _decision(policy, DESTINATION_HOSTNAME, "unknown.test"),
            "Destination has no matching programme scope inclusion.",
        ),
        (
            _decision(policy, DESTINATION_HOSTNAME, "bad host"),
            "Destination is invalid and was not evaluated as authorised.",
        ),
        (
            evaluate_raw_scope_destination(policy, "unsupported", "target"),
            "Destination type is unsupported by programme scope evaluation.",
        ),
    )

    for decision, expected in decisions:
        assert decision.operator_safe_explanation == expected


@pytest.mark.parametrize(
    "destination_kind",
    [[], {}, set(), 7, None, object(), "unsupported"],
)
def test_malformed_raw_destination_kinds_return_structured_unknown(
    destination_kind: object,
) -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))

    decision = evaluate_raw_scope_destination(
        policy,
        destination_kind,
        "example.test",
    )

    assert decision.outcome == OUTCOME_UNKNOWN
    assert decision.reason_code == REASON_UNSUPPORTED_DESTINATION


def test_invalid_policy_is_not_hidden_by_an_unsupported_destination_kind() -> None:
    with pytest.raises(ValueError, match="canonical programme scope policy"):
        evaluate_raw_scope_destination(object(), [], "example.test")


def test_resolved_peer_without_exclusion_preserves_allowed_logical_decision() -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    logical_destination = canonicalise_hostname_destination("example.test")
    logical = evaluate_programme_scope(policy, logical_destination)
    peer = canonicalise_resolved_ipv4_peer(logical_destination, "8.8.8.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_ALLOWED
    assert resolved.reason_code == REASON_INCLUDED
    assert resolved.canonical_destination == logical_destination
    assert resolved.resolved_peer == canonicalise_ipv4_destination("8.8.8.8")
    assert resolved.matched_inclusion_rule_ids == ("host",)
    assert resolved.operator_safe_explanation == (
        "Destination is included by programme scope rule host."
    )


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "203.0.113.8",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
    ],
)
def test_resolved_special_purpose_or_multicast_peer_fails_closed_without_ip_authority(
    address: str,
) -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    destination = canonicalise_hostname_destination("example.test")
    logical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, address)

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_UNKNOWN
    assert (
        resolved.reason_code
        == REASON_RESOLVED_IP_REQUIRES_EXPLICIT_INCLUSION
    )
    assert resolved.matched_inclusion_rule_ids == ("host",)
    assert resolved.matched_exclusion_rule_ids == ()
    assert resolved.primary_inclusion_rule_id is None
    assert resolved.primary_exclusion_rule_id is None
    assert resolved.resolved_peer == canonicalise_ipv4_destination(address)
    assert resolved.operator_safe_explanation == (
        "Special-purpose or multicast resolved IPv4 peer requires explicit "
        "IPv4 programme scope inclusion."
    )


@pytest.mark.parametrize(
    ("peer_rule_kind", "peer_rule_value", "address"),
    [
        (RULE_EXACT_IPV4, "127.0.0.1", "127.0.0.1"),
        (RULE_IPV4_CIDR, "10.0.0.0/8", "10.20.30.40"),
        (RULE_IPV4_CIDR, "169.254.0.0/16", "169.254.169.254"),
        (RULE_IPV4_CIDR, "203.0.113.0/24", "203.0.113.8"),
    ],
)
def test_explicit_ipv4_scope_authorises_special_resolved_peer(
    peer_rule_kind: str,
    peer_rule_value: str,
    address: str,
) -> None:
    policy = _policy(
        _rule("host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("peer-include", peer_rule_kind, peer_rule_value),
    )
    destination = canonicalise_hostname_destination("example.test")
    logical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, address)

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_ALLOWED
    assert resolved.reason_code == REASON_INCLUDED
    assert resolved.primary_inclusion_rule_id == "host"
    assert resolved.primary_exclusion_rule_id is None
    assert resolved.matched_inclusion_rule_ids == ("host", "peer-include")
    assert resolved.resolved_peer == canonicalise_ipv4_destination(address)


@pytest.mark.parametrize(
    ("peer_rule_kind", "peer_rule_value"),
    [
        (RULE_EXACT_IPV4, "203.0.113.8"),
        (RULE_IPV4_CIDR, "203.0.113.0/24"),
    ],
)
def test_resolved_peer_inclusions_do_not_replace_logical_authority(
    peer_rule_kind: str,
    peer_rule_value: str,
) -> None:
    policy = _policy(
        _rule("z-logical-host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("a-peer-include", peer_rule_kind, peer_rule_value),
    )
    destination = canonicalise_hostname_destination("example.test")
    logical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == logical.outcome
    assert resolved.reason_code == logical.reason_code
    assert resolved.primary_inclusion_rule_id == logical.primary_inclusion_rule_id
    assert resolved.primary_exclusion_rule_id == logical.primary_exclusion_rule_id
    assert resolved.operator_safe_explanation == logical.operator_safe_explanation
    assert resolved.matched_inclusion_rule_ids == (
        "a-peer-include",
        "z-logical-host",
    )


@pytest.mark.parametrize(
    ("kind", "value"),
    [(RULE_EXACT_IPV4, "203.0.113.8"), (RULE_IPV4_CIDR, "203.0.113.0/24")],
)
def test_resolved_exact_ip_or_cidr_exclusion_blocks_allowed_hostname(kind: str, value: str) -> None:
    policy = _policy(
        _rule("host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("peer-block", kind, value, action=ACTION_EXCLUDE),
    )
    logical_destination = canonicalise_hostname_destination("example.test")
    logical = evaluate_programme_scope(policy, logical_destination)
    peer = canonicalise_resolved_ipv4_peer(logical_destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_BLOCKED
    assert resolved.reason_code == REASON_RESOLVED_IP_EXCLUDED
    assert resolved.matched_inclusion_rule_ids == ("host",)
    assert resolved.matched_exclusion_rule_ids == ("peer-block",)
    assert resolved.primary_exclusion_rule_id == "peer-block"
    assert resolved.operator_safe_explanation == (
        "Resolved IPv4 peer is blocked by explicit programme scope rule peer-block."
    )


def test_resolved_peer_inclusion_cannot_authorise_unknown_hostname() -> None:
    policy = _policy(_rule("peer-network", RULE_IPV4_CIDR, "203.0.113.0/24"))
    logical_destination = canonicalise_hostname_destination("unknown.test")
    logical = evaluate_programme_scope(policy, logical_destination)
    peer = canonicalise_resolved_ipv4_peer(logical_destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_UNKNOWN
    assert resolved.reason_code == REASON_NO_MATCHING_INCLUSION
    assert resolved.matched_inclusion_rule_ids == ("peer-network",)
    assert resolved.primary_inclusion_rule_id is None
    assert resolved.operator_safe_explanation == (
        "Destination has no matching programme scope inclusion."
    )


def test_resolved_peer_cannot_unblock_logically_excluded_destination() -> None:
    policy = _policy(
        _rule("blocked-host", RULE_EXACT_HOSTNAME, "blocked.test", action=ACTION_EXCLUDE),
        _rule("peer-network", RULE_IPV4_CIDR, "203.0.113.0/24"),
    )
    logical_destination = canonicalise_hostname_destination("blocked.test")
    logical = evaluate_programme_scope(policy, logical_destination)
    peer = canonicalise_resolved_ipv4_peer(logical_destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_BLOCKED
    assert resolved.reason_code == REASON_EXPLICIT_EXCLUSION
    assert resolved.matched_inclusion_rule_ids == ("peer-network",)
    assert resolved.matched_exclusion_rule_ids == ("blocked-host",)


def test_unknown_hostname_plus_excluded_peer_is_blocked_exclusion_first() -> None:
    policy = _policy(
        _rule(
            "peer-block",
            RULE_IPV4_CIDR,
            "203.0.113.0/24",
            action=ACTION_EXCLUDE,
        )
    )
    destination = canonicalise_hostname_destination("unknown.test")
    logical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_BLOCKED
    assert resolved.reason_code == REASON_RESOLVED_IP_EXCLUDED
    assert resolved.primary_exclusion_rule_id == "peer-block"
    assert "peer-block" in resolved.operator_safe_explanation


def test_logically_blocked_hostname_with_peer_exclusion_uses_peer_reason() -> None:
    policy = _policy(
        _rule(
            "logical-block",
            RULE_EXACT_HOSTNAME,
            "blocked.test",
            action=ACTION_EXCLUDE,
        ),
        _rule(
            "peer-block",
            RULE_EXACT_IPV4,
            "203.0.113.8",
            action=ACTION_EXCLUDE,
        ),
    )
    destination = canonicalise_hostname_destination("blocked.test")
    logical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    resolved = evaluate_resolved_ipv4_peer(policy, logical, peer)

    assert resolved.outcome == OUTCOME_BLOCKED
    assert resolved.reason_code == REASON_RESOLVED_IP_EXCLUDED
    assert resolved.matched_exclusion_rule_ids == ("logical-block", "peer-block")
    assert resolved.primary_exclusion_rule_id == "peer-block"
    assert "peer-block" in resolved.operator_safe_explanation


def test_resolved_peer_supports_hostname_based_http_logical_destination_only() -> None:
    logical_url = canonicalise_http_url_destination("https://example.test/api")
    peer = canonicalise_resolved_ipv4_peer(logical_url, "203.0.113.8")
    assert peer.logical_destination == logical_url

    ip_url = canonicalise_http_url_destination("https://192.0.2.4/api")
    with pytest.raises(ValueError, match="hostname origin"):
        canonicalise_resolved_ipv4_peer(ip_url, "203.0.113.8")


def test_resolved_peer_requires_the_same_logical_destination() -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    logical = evaluate_programme_scope(
        policy, canonicalise_hostname_destination("example.test")
    )
    mismatched = canonicalise_resolved_ipv4_peer(
        canonicalise_hostname_destination("other.test"), "203.0.113.8"
    )
    with pytest.raises(ValueError, match="does not match"):
        evaluate_resolved_ipv4_peer(policy, logical, mismatched)


def test_resolved_peer_rejects_a_logical_decision_from_another_policy() -> None:
    destination = canonicalise_hostname_destination("example.test")
    first_policy = _policy(_rule("first-host", RULE_EXACT_HOSTNAME, "example.test"))
    second_policy = _policy(_rule("second-host", RULE_EXACT_HOSTNAME, "example.test"))
    logical = evaluate_programme_scope(first_policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    with pytest.raises(ValueError, match="canonical logical scope decision"):
        evaluate_resolved_ipv4_peer(second_policy, logical, peer)


def test_resolved_peer_rejects_same_rule_id_with_different_value() -> None:
    destination = canonicalise_hostname_destination("example.test")
    first_policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    second_policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "other.test"))
    logical = evaluate_programme_scope(first_policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    with pytest.raises(ValueError, match="canonical logical scope decision"):
        evaluate_resolved_ipv4_peer(second_policy, logical, peer)


def test_resolved_peer_rejects_same_rule_id_and_value_with_different_action() -> None:
    destination = canonicalise_hostname_destination("example.test")
    first_policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    second_policy = _policy(
        _rule(
            "host",
            RULE_EXACT_HOSTNAME,
            "example.test",
            action=ACTION_EXCLUDE,
        )
    )
    logical = evaluate_programme_scope(first_policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    with pytest.raises(ValueError, match="canonical logical scope decision"):
        evaluate_resolved_ipv4_peer(second_policy, logical, peer)


def test_resolved_peer_rejects_manually_fabricated_allowed_decision() -> None:
    policy = _policy(_rule("host", RULE_EXACT_HOSTNAME, "example.test"))
    destination = canonicalise_hostname_destination("example.test")
    fabricated = ScopeDecision(
        outcome=OUTCOME_ALLOWED,
        canonical_destination=destination,
        reason_code=REASON_INCLUDED,
        matched_inclusion_rule_ids=("other-host",),
        matched_exclusion_rule_ids=(),
        primary_inclusion_rule_id="other-host",
        primary_exclusion_rule_id=None,
        operator_safe_explanation=(
            "Destination is included by programme scope rule other-host."
        ),
    )
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")

    with pytest.raises(ValueError, match="canonical logical scope decision"):
        evaluate_resolved_ipv4_peer(policy, fabricated, peer)


def test_resolved_peer_requires_every_logical_decision_field_to_be_canonical() -> None:
    policy = _policy(
        _rule("a-host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule("b-host", RULE_EXACT_HOSTNAME, "example.test"),
        _rule(
            "blocked-host",
            RULE_EXACT_HOSTNAME,
            "blocked.test",
            action=ACTION_EXCLUDE,
        ),
    )
    destination = canonicalise_hostname_destination("example.test")
    canonical = evaluate_programme_scope(policy, destination)
    peer = canonicalise_resolved_ipv4_peer(destination, "203.0.113.8")
    variants = (
        ScopeDecision(
            **{
                **canonical.__dict__,
                "matched_inclusion_rule_ids": ("a-host",),
                "primary_inclusion_rule_id": "a-host",
                "operator_safe_explanation": (
                    "Destination is included by programme scope rule a-host."
                ),
            }
        ),
        ScopeDecision(
            **{
                **canonical.__dict__,
                "primary_inclusion_rule_id": "b-host",
                "operator_safe_explanation": (
                    "Destination is included by programme scope rule b-host."
                ),
            }
        ),
        ScopeDecision(
            outcome=OUTCOME_BLOCKED,
            canonical_destination=destination,
            reason_code=REASON_EXPLICIT_EXCLUSION,
            matched_inclusion_rule_ids=("a-host", "b-host"),
            matched_exclusion_rule_ids=("blocked-host",),
            primary_inclusion_rule_id="a-host",
            primary_exclusion_rule_id="blocked-host",
            operator_safe_explanation=(
                "Destination is blocked by explicit programme scope rule "
                "blocked-host."
            ),
        ),
    )

    for variant in variants:
        with pytest.raises(ValueError, match="canonical logical scope decision"):
            evaluate_resolved_ipv4_peer(policy, variant, peer)


def test_scope_decision_accepts_canonical_direct_states() -> None:
    destination = canonicalise_hostname_destination("example.test")
    allowed = ScopeDecision(
        OUTCOME_ALLOWED,
        destination,
        REASON_INCLUDED,
        ("include",),
        (),
        "include",
        None,
        "Destination is included by programme scope rule include.",
    )
    unknown = ScopeDecision(
        OUTCOME_UNKNOWN,
        destination,
        REASON_NO_MATCHING_INCLUSION,
        (),
        (),
        None,
        None,
        "Destination has no matching programme scope inclusion.",
    )

    assert allowed.outcome == OUTCOME_ALLOWED
    assert unknown.outcome == OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    "values",
    [
        {
            "outcome": OUTCOME_ALLOWED,
            "canonical_destination": canonicalise_hostname_destination("example.test"),
            "reason_code": REASON_INCLUDED,
            "matched_inclusion_rule_ids": ("included-rule",),
            "matched_exclusion_rule_ids": (),
            "primary_inclusion_rule_id": "included-rule",
            "primary_exclusion_rule_id": None,
            "operator_safe_explanation": (
                "Destination is included by programme scope rule other-rule."
            ),
        },
        {
            "outcome": OUTCOME_ALLOWED,
            "canonical_destination": canonicalise_hostname_destination("example.test"),
            "reason_code": REASON_INCLUDED,
            "matched_inclusion_rule_ids": ("included-rule",),
            "matched_exclusion_rule_ids": (),
            "primary_inclusion_rule_id": "included-rule",
            "primary_exclusion_rule_id": None,
            "operator_safe_explanation": "Arbitrary safe explanation text.",
        },
        {
            "outcome": OUTCOME_BLOCKED,
            "canonical_destination": canonicalise_hostname_destination("example.test"),
            "reason_code": REASON_EXPLICIT_EXCLUSION,
            "matched_inclusion_rule_ids": (),
            "matched_exclusion_rule_ids": ("excluded-rule",),
            "primary_inclusion_rule_id": None,
            "primary_exclusion_rule_id": "excluded-rule",
            "operator_safe_explanation": (
                "Destination is blocked by explicit programme scope rule other-rule."
            ),
        },
        {
            "outcome": OUTCOME_BLOCKED,
            "canonical_destination": canonicalise_hostname_destination("example.test"),
            "reason_code": REASON_RESOLVED_IP_EXCLUDED,
            "matched_inclusion_rule_ids": ("host-rule",),
            "matched_exclusion_rule_ids": ("peer-rule",),
            "primary_inclusion_rule_id": "host-rule",
            "primary_exclusion_rule_id": "peer-rule",
            "operator_safe_explanation": (
                "Resolved IPv4 peer is blocked by explicit programme scope rule "
                "other-peer-rule."
            ),
            "resolved_peer": canonicalise_ipv4_destination("203.0.113.8"),
        },
        {
            "outcome": OUTCOME_UNKNOWN,
            "canonical_destination": canonicalise_hostname_destination("example.test"),
            "reason_code": REASON_NO_MATCHING_INCLUSION,
            "matched_inclusion_rule_ids": (),
            "matched_exclusion_rule_ids": (),
            "primary_inclusion_rule_id": None,
            "primary_exclusion_rule_id": None,
            "operator_safe_explanation": "No authority was found in some other way.",
        },
        {
            "outcome": OUTCOME_UNKNOWN,
            "canonical_destination": None,
            "reason_code": REASON_UNSUPPORTED_DESTINATION,
            "matched_inclusion_rule_ids": (),
            "matched_exclusion_rule_ids": (),
            "primary_inclusion_rule_id": None,
            "primary_exclusion_rule_id": None,
            "operator_safe_explanation": (
                "Destination is invalid and was not evaluated as authorised."
            ),
        },
        {
            "outcome": OUTCOME_UNKNOWN,
            "canonical_destination": None,
            "reason_code": REASON_INVALID_DESTINATION,
            "matched_inclusion_rule_ids": (),
            "matched_exclusion_rule_ids": (),
            "primary_inclusion_rule_id": None,
            "primary_exclusion_rule_id": None,
            "operator_safe_explanation": (
                "Destination type is unsupported by programme scope evaluation."
            ),
        },
    ],
)
def test_scope_decision_rejects_noncanonical_explanations(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="explanation"):
        ScopeDecision(**values)


def test_nonresolved_blocked_decision_requires_primary_for_matched_inclusions() -> None:
    with pytest.raises(ValueError, match="primary inclusion"):
        ScopeDecision(
            outcome=OUTCOME_BLOCKED,
            canonical_destination=canonicalise_hostname_destination("example.test"),
            reason_code=REASON_EXPLICIT_EXCLUSION,
            matched_inclusion_rule_ids=("include",),
            matched_exclusion_rule_ids=("exclude",),
            primary_inclusion_rule_id=None,
            primary_exclusion_rule_id="exclude",
            operator_safe_explanation=(
                "Destination is blocked by explicit programme scope rule exclude."
            ),
        )


@pytest.mark.parametrize(
    ("primary_field", "primary_value"),
    [
        ("primary_inclusion_rule_id", "include"),
        ("primary_exclusion_rule_id", "exclude"),
    ],
)
def test_scope_decision_rejects_primary_rule_for_empty_match_collection(
    primary_field: str,
    primary_value: str,
) -> None:
    values = {
        "outcome": OUTCOME_UNKNOWN,
        "canonical_destination": canonicalise_hostname_destination("example.test"),
        "reason_code": REASON_NO_MATCHING_INCLUSION,
        "matched_inclusion_rule_ids": (),
        "matched_exclusion_rule_ids": (),
        "primary_inclusion_rule_id": None,
        "primary_exclusion_rule_id": None,
        "operator_safe_explanation": (
            "Destination has no matching programme scope inclusion."
        ),
    }
    values[primary_field] = primary_value

    with pytest.raises(ValueError, match="not a matched rule"):
        ScopeDecision(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"reason_code": "invented"},
        {"operator_safe_explanation": ""},
        {"operator_safe_explanation": "unsafe\nexplanation"},
        {"operator_safe_explanation": "x" * 4097},
        {"matched_inclusion_rule_ids": ("include", "include")},
        {"matched_inclusion_rule_ids": ("z", "a"), "primary_inclusion_rule_id": "z"},
        {"primary_inclusion_rule_id": None},
        {"matched_exclusion_rule_ids": ("exclude",)},
        {"canonical_destination": None},
        {"outcome": OUTCOME_BLOCKED},
        {"reason_code": REASON_NO_MATCHING_INCLUSION},
    ],
)
def test_scope_decision_rejects_inconsistent_allowed_states(changes: dict[str, object]) -> None:
    values = {
        "outcome": OUTCOME_ALLOWED,
        "canonical_destination": canonicalise_hostname_destination("example.test"),
        "reason_code": REASON_INCLUDED,
        "matched_inclusion_rule_ids": ("include",),
        "matched_exclusion_rule_ids": (),
        "primary_inclusion_rule_id": "include",
        "primary_exclusion_rule_id": None,
        "operator_safe_explanation": (
            "Destination is included by programme scope rule include."
        ),
    }
    values.update(changes)
    with pytest.raises(ValueError):
        ScopeDecision(**values)


@pytest.mark.parametrize(
    "reason",
    [REASON_INVALID_DESTINATION, REASON_UNSUPPORTED_DESTINATION],
)
def test_invalid_and_unsupported_decisions_require_empty_unknown_state(reason: str) -> None:
    explanation = (
        "Destination is invalid and was not evaluated as authorised."
        if reason == REASON_INVALID_DESTINATION
        else "Destination type is unsupported by programme scope evaluation."
    )
    valid = ScopeDecision(
        OUTCOME_UNKNOWN,
        None,
        reason,
        (),
        (),
        None,
        None,
        explanation,
    )
    assert valid.canonical_destination is None

    with pytest.raises(ValueError):
        ScopeDecision(
            OUTCOME_UNKNOWN,
            canonicalise_hostname_destination("example.test"),
            reason,
            ("include",),
            (),
            "include",
            None,
            explanation,
        )


def test_resolved_peer_requires_hostname_logical_destination_in_decision() -> None:
    with pytest.raises(ValueError, match="resolved peer"):
        ScopeDecision(
            OUTCOME_ALLOWED,
            canonicalise_ipv4_destination("192.0.2.1"),
            REASON_INCLUDED,
            ("include",),
            (),
            "include",
            None,
            "Destination is included by programme scope rule include.",
            resolved_peer=canonicalise_ipv4_destination("203.0.113.8"),
        )


def test_direct_canonical_destination_models_reject_inconsistent_values() -> None:
    with pytest.raises(ValueError, match="not canonical"):
        CanonicalHostnameDestination("EXAMPLE.TEST")
    with pytest.raises(ValueError, match="IPv4"):
        CanonicalIPv4Destination("192.168.001.1")
    with pytest.raises(ValueError, match="scheme"):
        CanonicalHTTPOrigin("ftp", DESTINATION_HOSTNAME, "example.test", 21)
    with pytest.raises(ValueError, match="path"):
        CanonicalHTTPURLDestination(
            CanonicalHTTPOrigin("https", DESTINATION_HOSTNAME, "example.test", 443),
            "/a/../b",
            None,
        )
