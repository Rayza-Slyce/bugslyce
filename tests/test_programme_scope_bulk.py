"""WP3A RED contracts for pure structured programme-scope bulk capture."""

from __future__ import annotations

import importlib

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_HTTP_PATH_PREFIX,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_rule,
    validate_rule_id,
)


def _bulk_module():
    return importlib.import_module("bugslyce.core.programme_scope_bulk")


def _semantic_key(rule) -> tuple[object, ...]:
    return (
        rule.action,
        rule.kind,
        rule.canonical_value,
        rule.scheme,
        rule.port,
    )


def test_bulk_scope_input_builds_multiple_canonical_rules() -> None:
    text = """
    # Structured operator input; not authoritative free-form prose.
    include hostname App.Example.TEST
    include wildcard *.Example.TEST scheme=https port=443
    include url HTTPS://Accounts.Example.TEST:443/
    include path https://api.example.test/v1/
    exclude hostname admin.example.test
    exclude path https://example.test/internal/
    """

    draft = _bulk_module().build_programme_scope_bulk_draft(text)
    rules = draft.rules

    assert isinstance(rules, tuple)
    assert len(rules) == 6
    assert {
        (rule.action, rule.kind, rule.canonical_value)
        for rule in rules
    } == {
        (ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "app.example.test"),
        (ACTION_INCLUDE, RULE_WILDCARD_SUBDOMAIN, "*.example.test"),
        (ACTION_INCLUDE, RULE_EXACT_HTTP_URL, "https://accounts.example.test/"),
        (ACTION_INCLUDE, RULE_HTTP_PATH_PREFIX, "https://api.example.test/v1/"),
        (ACTION_EXCLUDE, RULE_EXACT_HOSTNAME, "admin.example.test"),
        (ACTION_EXCLUDE, RULE_HTTP_PATH_PREFIX, "https://example.test/internal/"),
    }
    wildcard = next(rule for rule in rules if rule.kind == RULE_WILDCARD_SUBDOMAIN)
    assert wildcard.scheme == "https"
    assert wildcard.port == 443
    assert all(validate_rule_id(rule.rule_id) == rule.rule_id for rule in rules)


def test_bulk_scope_input_rejects_invalid_batch_atomically() -> None:
    original = (
        build_programme_scope_rule(
            rule_id="existing",
            action=ACTION_INCLUDE,
            kind=RULE_EXACT_HOSTNAME,
            value="existing.example.test",
        ),
    )
    before = tuple(original)
    text = """
    include hostname valid.example.test
    this is arbitrary ambiguous programme prose
    exclude hostname admin.example.test
    """

    with pytest.raises(ValueError, match=r"line\s+3"):
        _bulk_module().build_programme_scope_bulk_draft(text)

    assert original == before


def test_bulk_scope_generated_ids_are_deterministic_and_semantic() -> None:
    first = """
    include hostname App.Example.TEST
    include hostname app.example.test.
    exclude hostname app.example.test
    include wildcard *.example.test scheme=https port=443
    """
    reordered = """
    include wildcard *.EXAMPLE.TEST scheme=https port=443
    exclude hostname APP.example.test.
    include hostname app.example.test
    include hostname App.Example.TEST.
    """

    first_draft = _bulk_module().build_programme_scope_bulk_draft(first)
    second_draft = _bulk_module().build_programme_scope_bulk_draft(reordered)
    first_ids = {_semantic_key(rule): rule.rule_id for rule in first_draft.rules}
    second_ids = {_semantic_key(rule): rule.rule_id for rule in second_draft.rules}

    assert len(first_draft.rules) == 3
    assert first_draft.duplicate_count == 1
    assert second_draft.duplicate_count == 1
    assert first_ids == second_ids
    assert len(set(first_ids.values())) == len(first_ids)
    assert all(validate_rule_id(rule_id) == rule_id for rule_id in first_ids.values())
    include_id = first_ids[
        (ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "app.example.test", None, None)
    ]
    exclude_id = first_ids[
        (ACTION_EXCLUDE, RULE_EXACT_HOSTNAME, "app.example.test", None, None)
    ]
    assert include_id != exclude_id
