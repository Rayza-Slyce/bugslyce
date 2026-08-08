"""Tests for pure programme-scope editing and private local rendering."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.programme_scope_management import (
    add_programme_scope_rule,
    build_changed_programme_scope_policy,
    programme_scope_rules_changed,
    remove_programme_scope_rule,
    render_programme_scope_local_summary,
    replace_programme_scope_rule,
    update_programme_scope_rule_private_fields,
)
from bugslyce.project_session import BugSlyceProject


ORIGINAL_TIME = "2026-07-30T09:15:00Z"
CHANGED_TIME = "2026-07-30T10:30:00Z"
PRIVATE_NOTE = "private-note-sentinel-7621"
PRIVATE_SOURCE = "private-source-wording-sentinel-7621"


def _rule(
    rule_id: str,
    kind: str = RULE_EXACT_HOSTNAME,
    value: str = "example.test",
    *,
    action: str = ACTION_INCLUDE,
    note: str | None = None,
    source: str | None = None,
):
    return build_programme_scope_rule(
        rule_id=rule_id,
        action=action,
        kind=kind,
        value=value,
        private_note=note,
        private_source_wording=source,
    )


def _policy(*rules):
    return build_programme_scope_policy(list(rules), updated_at=ORIGINAL_TIME)


def _project(context: str = "bug_bounty") -> BugSlyceProject:
    return BugSlyceProject(
        schema_version="1.1",
        name="scope-review",
        target="example.test",
        scope_file="/private/scope.md",
        output_dir="/private/output",
        created_by="bugslyce",
        default_profiles={},
        created_at=ORIGINAL_TIME,
        engagement_context=context,
        notes=["unrelated-project-private-sentinel"],
    )


def test_add_is_immutable_ordered_and_rejects_casefold_duplicate() -> None:
    original = (_rule("z-rule"),)
    added = add_programme_scope_rule(original, _rule("A-rule", action=ACTION_EXCLUDE))

    assert tuple(rule.rule_id for rule in added) == ("A-rule", "z-rule")
    assert original[0].rule_id == "z-rule"
    assert isinstance(added, tuple)
    with pytest.raises(ValueError, match="unique"):
        add_programme_scope_rule(added, _rule("a-RULE"))
    assert tuple(rule.rule_id for rule in added) == ("A-rule", "z-rule")


def test_replace_retains_id_and_does_not_mutate_after_failure() -> None:
    original = (_rule("host", note=PRIVATE_NOTE),)
    replacement = _rule(
        "host",
        RULE_EXACT_HTTP_URL,
        "HTTPS://Example.TEST:443/api",
        action=ACTION_EXCLUDE,
        source=PRIVATE_SOURCE,
    )

    changed = replace_programme_scope_rule(original, "HOST", replacement)

    assert changed[0].rule_id == "host"
    assert changed[0].canonical_value == "https://example.test/api"
    assert changed[0].private_source_wording == PRIVATE_SOURCE
    assert original[0].private_note == PRIVATE_NOTE
    with pytest.raises(ValueError, match="same rule ID"):
        replace_programme_scope_rule(original, "host", _rule("different"))
    with pytest.raises(ValueError, match="does not exist"):
        replace_programme_scope_rule(original, "missing", replacement)
    assert original == (_rule("host", note=PRIVATE_NOTE),)


def test_remove_supports_final_rule_and_rejects_missing_target() -> None:
    original = (_rule("host"),)
    assert remove_programme_scope_rule(original, "HOST") == ()
    with pytest.raises(ValueError, match="does not exist"):
        remove_programme_scope_rule(original, "missing")
    assert len(original) == 1


def test_private_field_updates_rebuild_rule_and_detect_exact_noop() -> None:
    original = (_rule("host", note=PRIVATE_NOTE, source=PRIVATE_SOURCE),)
    note_changed = update_programme_scope_rule_private_fields(
        original,
        "host",
        private_note="replacement note",
        private_source_wording=PRIVATE_SOURCE,
    )
    source_changed = update_programme_scope_rule_private_fields(
        original,
        "host",
        private_note=PRIVATE_NOTE,
        private_source_wording="replacement source",
    )
    cleared = update_programme_scope_rule_private_fields(
        original,
        "host",
        private_note=None,
        private_source_wording=None,
    )
    unchanged = update_programme_scope_rule_private_fields(
        original,
        "host",
        private_note=PRIVATE_NOTE,
        private_source_wording=PRIVATE_SOURCE,
    )

    assert note_changed[0].canonical_value == original[0].canonical_value
    assert source_changed[0].private_source_wording == "replacement source"
    assert cleared[0].private_note is None
    assert cleared[0].private_source_wording is None
    assert unchanged == original
    assert original[0].private_note == PRIVATE_NOTE


@pytest.mark.parametrize(
    ("rule_id", "kind", "value", "action"),
    (
        ("host", RULE_EXACT_HOSTNAME, "Example.TEST.", ACTION_INCLUDE),
        ("wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test", ACTION_EXCLUDE),
        ("url", RULE_EXACT_HTTP_URL, "https://example.test/api?b=2&a=1", ACTION_INCLUDE),
        ("path", RULE_HTTP_PATH_PREFIX, "https://example.test/api", ACTION_EXCLUDE),
        ("ip", RULE_EXACT_IPV4, "192.0.2.4", ACTION_INCLUDE),
        ("cidr", RULE_IPV4_CIDR, "198.51.100.0/24", ACTION_EXCLUDE),
    ),
)
def test_editing_accepts_every_canonical_rule_kind_and_action(
    rule_id: str,
    kind: str,
    value: str,
    action: str,
) -> None:
    added = add_programme_scope_rule((), _rule(rule_id, kind, value, action=action))
    assert added[0].kind == kind
    assert added[0].action == action


def test_noop_detection_precedes_timestamp_and_private_changes_count() -> None:
    original = _policy(_rule("host", note=PRIVATE_NOTE))
    equivalent = tuple(reversed(tuple(reversed(original.rules))))

    assert programme_scope_rules_changed(original, equivalent) is False
    assert build_changed_programme_scope_policy(original, equivalent) is original

    changed_rules = update_programme_scope_rule_private_fields(
        original.rules,
        "host",
        private_note="changed private note",
        private_source_wording=None,
    )
    assert programme_scope_rules_changed(original, changed_rules) is True
    with pytest.raises(ValueError, match="timestamp"):
        build_changed_programme_scope_policy(original, changed_rules)

    changed = build_changed_programme_scope_policy(
        original,
        changed_rules,
        updated_at=CHANGED_TIME,
    )
    assert changed.updated_at == CHANGED_TIME
    assert changed.schema_version == original.schema_version
    assert changed.engagement_context == original.engagement_context
    assert original.updated_at == ORIGINAL_TIME


def test_policy_and_rules_remain_frozen() -> None:
    policy = _policy(_rule("host"))
    with pytest.raises(FrozenInstanceError):
        policy.updated_at = CHANGED_TIME  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        policy.rules[0].action = ACTION_EXCLUDE  # type: ignore[misc]


def test_safe_summary_is_exact_deterministic_and_private() -> None:
    policy = _policy(
        _rule("z-url", RULE_EXACT_HTTP_URL, "https://example.test/api?x=1", note=PRIVATE_NOTE),
        _rule("a-host", RULE_EXACT_HOSTNAME, "example.test", source=PRIVATE_SOURCE),
        _rule("b-wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test", action=ACTION_EXCLUDE),
        _rule("c-path", RULE_HTTP_PATH_PREFIX, "https://example.test/api"),
        _rule("d-ip", RULE_EXACT_IPV4, "192.0.2.4", action=ACTION_EXCLUDE),
        _rule("e-cidr", RULE_IPV4_CIDR, "198.51.100.0/24"),
    )

    rendered = render_programme_scope_local_summary(_project(), policy)

    assert rendered == "\n".join(
        (
            "Programme scope - private local operator view",
            "Project: scope-review",
            "Engagement context: bug_bounty",
            "Schema version: 1.0",
            f"Updated at: {ORIGINAL_TIME}",
            "Rules: 6 total; 4 include; 2 exclude",
            "Rule counts by kind:",
            "- exact_hostname: 1",
            "- wildcard_subdomain: 1",
            "- exact_http_url: 1",
            "- http_path_prefix: 1",
            "- exact_ipv4: 1",
            "- ipv4_cidr: 1",
            "Canonical rules:",
            "- a-host | include | exact_hostname | example.test",
            "- b-wild | exclude | wildcard_subdomain | *.example.test",
            "- c-path | include | http_path_prefix | https://example.test/api",
            "- d-ip | exclude | exact_ipv4 | 192.0.2.4",
            "- e-cidr | include | ipv4_cidr | 198.51.100.0/24",
            "- z-url | include | exact_http_url | https://example.test/api?x=1",
            "Programme scope is default-deny: destinations without an inclusion "
            "are not authorised.",
            "Explicit exclusions override every inclusion.",
            "Runtime programme-scope enforcement is active for strict Standard and Deep project pipelines.",
            "Stored configuration authorises traffic only after engagement-policy readiness and target evaluation.",
        )
    )
    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered
    assert "private_note" not in rendered
    assert "private_source_wording" not in rendered
    assert "unrelated-project-private-sentinel" not in rendered
    assert "{" not in rendered
    assert "ProgrammeScope" not in rendered


def test_zero_rule_summary_and_wrong_context_refusal() -> None:
    rendered = render_programme_scope_local_summary(_project(), _policy())
    assert "Rules: 0 total; 0 include; 0 exclude" in rendered
    assert "Canonical rules: none" in rendered
    for kind in (
        RULE_EXACT_HOSTNAME,
        RULE_WILDCARD_SUBDOMAIN,
        RULE_EXACT_HTTP_URL,
        RULE_HTTP_PATH_PREFIX,
        RULE_EXACT_IPV4,
        RULE_IPV4_CIDR,
    ):
        assert f"- {kind}: 0" in rendered

    with pytest.raises(ValueError, match="bug bounty"):
        render_programme_scope_local_summary(_project("ctf_lab"), _policy())
