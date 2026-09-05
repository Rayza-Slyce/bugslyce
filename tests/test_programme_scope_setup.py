"""Tests for offline programme-scope CLI orchestration."""

from __future__ import annotations

from collections.abc import Iterator
import json
from pathlib import Path
import socket

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    DESTINATION_HTTP_URL,
    OUTCOME_ALLOWED,
    OUTCOME_UNKNOWN,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
    evaluate_raw_scope_destination,
)
from bugslyce.core.programme_scope_store import save_programme_scope_policy
from bugslyce.programme_scope_setup import (
    configure_project_programme_scope,
    review_and_save_programme_scope_proposal,
    show_project_programme_scope,
)
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeProposalUnresolvedItem,
    build_manual_programme_scope_proposal,
    build_programme_scope_proposal,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    load_project_programme_scope_policy,
    save_project_programme_scope_policy,
)
import bugslyce.programme_scope_setup as scope_setup_module


ORIGINAL_TIME = "2026-07-30T09:15:00Z"
CHANGED_TIME = "2026-07-30T10:30:00Z"
PRIVATE_NOTE = "private-note-sentinel-9182"
PRIVATE_SOURCE = "private-source-sentinel-9182"


def _project(tmp_path: Path, *, context: str = "bug_bounty") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n", encoding="utf-8")
    _project, path = initialize_project(
        "scope-cli",
        "example.test",
        scope,
        tmp_path / "project",
        engagement_context=context,
    )
    return path


def _policy(*, private: bool = False):
    rule = build_programme_scope_rule(
        rule_id="host",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="example.test",
        private_note=PRIVATE_NOTE if private else None,
        private_source_wording=PRIVATE_SOURCE if private else None,
    )
    return build_programme_scope_policy((rule,), updated_at=ORIGINAL_TIME)


def _inputs(*answers: str):
    values: Iterator[str] = iter(answers)
    return lambda _prompt: next(values)


def test_show_configured_policy_is_deterministic_and_private(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    output: list[str] = []
    errors: list[str] = []

    result = show_project_programme_scope(
        project_file,
        print_func=output.append,
        error_func=errors.append,
    )

    rendered = "\n".join(output)
    assert result == 0
    assert errors == []
    assert "Programme scope - private local operator view" in rendered
    assert f"Updated at: {ORIGINAL_TIME}" in rendered
    assert "host | include | exact_hostname | example.test" in rendered
    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered


def test_complete_external_proposal_uses_existing_review_confirmation_and_save_once(
    tmp_path: Path, monkeypatch
) -> None:
    project_file = _project(tmp_path)
    proposal = build_manual_programme_scope_proposal(_policy().rules)
    real_save = scope_setup_module.save_project_programme_scope_policy
    calls = 0

    def counted_save(path, policy):
        nonlocal calls
        calls += 1
        return real_save(path, policy)

    monkeypatch.setattr(scope_setup_module, "save_project_programme_scope_policy", counted_save)
    output: list[str] = []
    assert review_and_save_programme_scope_proposal(
        project_file,
        proposal,
        input_func=_inputs("YES"),
        print_func=output.append,
        error_func=pytest.fail,
        now_func=lambda: CHANGED_TIME,
    ) == 0
    assert calls == 1
    assert load_project_programme_scope_policy(load_project(project_file)) is not None
    assert "PROPOSED EXECUTABLE AUTHORITY" in "\n".join(output)


def test_external_proposal_refusal_eof_and_unresolved_never_save(
    tmp_path: Path, monkeypatch
) -> None:
    project_file = _project(tmp_path)
    proposal = build_manual_programme_scope_proposal(_policy().rules)
    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        lambda *_args, **_kwargs: pytest.fail("unconfirmed proposal must not save"),
    )
    assert review_and_save_programme_scope_proposal(
        project_file,
        proposal,
        input_func=_inputs("NO"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        now_func=lambda: pytest.fail("refusal must not request a timestamp"),
    ) == 0
    cancelled_output: list[str] = []
    assert review_and_save_programme_scope_proposal(
        project_file,
        proposal,
        input_func=_inputs("CANCEL"),
        print_func=cancelled_output.append,
        error_func=pytest.fail,
        now_func=lambda: pytest.fail("cancellation must not request a timestamp"),
    ) == 0
    assert "stored values are unchanged" in "\n".join(cancelled_output)
    errors: list[str] = []
    assert review_and_save_programme_scope_proposal(
        project_file,
        proposal,
        input_func=lambda _prompt: (_ for _ in ()).throw(EOFError),
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: pytest.fail("EOF must not request a timestamp"),
    ) == 2
    assert errors == ["Error: programme-scope input ended unexpectedly."]

    unresolved = build_programme_scope_proposal(
        source=proposal.source,
        rules=proposal.rules,
        unresolved_items=(
            ProgrammeScopeProposalUnresolvedItem(
                item_id="pending-row",
                description="Synthetic source row requires review.",
            ),
        ),
    )
    errors.clear()
    assert review_and_save_programme_scope_proposal(
        project_file,
        unresolved,
        input_func=pytest.fail,
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: pytest.fail("invalid proposal must not request a timestamp"),
    ) == 2
    assert errors == [
        "Error: Programme-scope proposal must be fully resolved before review and save."
    ]


def test_show_missing_policy_and_wrong_context_are_safe(tmp_path: Path) -> None:
    project_file = _project(tmp_path / "bug")
    output: list[str] = []
    errors: list[str] = []
    assert show_project_programme_scope(
        project_file, print_func=output.append, error_func=errors.append
    ) == 0
    assert "Programme scope is not configured." in output
    rendered_missing = " ".join(output)
    assert (
        "Live project reconnaissance remains unavailable until programme scope "
        "is configured and strict preflight succeeds."
    ) in rendered_missing
    assert "Standard" not in rendered_missing
    assert "Deep" not in rendered_missing
    assert errors == []

    wrong = _project(tmp_path / "ctf", context="ctf_lab")
    output.clear()
    assert show_project_programme_scope(
        wrong, print_func=output.append, error_func=errors.append
    ) == 2
    assert output == []
    assert "bug bounty" in errors[-1]


def test_show_unsafe_or_malformed_policy_returns_two_without_private_data(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy())
    policy_path = project_file.parent / "programme_scope.json"
    policy_path.write_text('{"private_note":"secret-sentinel"', encoding="utf-8")
    policy_path.chmod(0o600)
    errors: list[str] = []

    assert show_project_programme_scope(
        project_file, print_func=lambda _line: None, error_func=errors.append
    ) == 2
    assert "secret-sentinel" not in "\n".join(errors)


@pytest.mark.parametrize(
    ("rule_id", "action", "kind", "value", "canonical"),
    (
        ("host", ACTION_INCLUDE, RULE_EXACT_HOSTNAME, "Example.TEST.", "example.test"),
        ("wild", ACTION_EXCLUDE, RULE_WILDCARD_SUBDOMAIN, "*.example.test", "*.example.test"),
        ("url", ACTION_INCLUDE, RULE_EXACT_HTTP_URL, "HTTPS://Example.TEST:443/api", "https://example.test/api"),
        ("path", ACTION_EXCLUDE, RULE_HTTP_PATH_PREFIX, "https://example.test/api", "https://example.test/api"),
        ("ip", ACTION_INCLUDE, RULE_EXACT_IPV4, "192.0.2.4", "192.0.2.4"),
        ("cidr", ACTION_EXCLUDE, RULE_IPV4_CIDR, "198.51.100.0/24", "198.51.100.0/24"),
    ),
)
def test_create_supports_every_rule_kind_and_both_actions(
    tmp_path: Path,
    rule_id: str,
    action: str,
    kind: str,
    value: str,
    canonical: str,
) -> None:
    project_file = _project(tmp_path)
    output: list[str] = []
    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "1", rule_id, action, kind, value, PRIVATE_NOTE, PRIVATE_SOURCE,
            "3", "YES",
        ),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    )

    policy = load_project_programme_scope_policy(load_project(project_file))
    assert result == 0
    assert policy is not None
    assert policy.updated_at == CHANGED_TIME
    assert policy.rules[0].canonical_value == canonical
    rendered = "\n".join(output)
    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered


def test_new_rule_flow_explains_rule_id_and_every_scope_kind_without_writing(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    before = project_file.read_bytes()
    output: list[str] = []

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs("1", "CANCEL"),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("guidance must not request a timestamp"),
    )

    rendered = "\n".join(output)
    assert result == 0
    assert "Rule ID is a local operator label" in rendered
    assert "target-ip" in rendered and "api-prefix" in rendered
    assert "exact_hostname" in rendered and "app.example.com" in rendered
    assert "wildcard_subdomain" in rendered and "*.example.com" in rendered
    assert "exact_http_url" in rendered
    assert "http_path_prefix" in rendered
    assert "https://example.com/api/" in rendered
    assert "http://127.0.0.1:8080/" in rendered
    assert "not an IPv4 rule" in rendered
    assert "exact_ipv4" in rendered and "127.0.0.1" in rendered
    assert "ipv4_cidr" in rendered and "192.0.2.0/24" in rendered
    assert "Programme scope is enforced during live project reconnaissance." in rendered
    assert "strict preflight" in rendered
    assert "engagement policy" in rendered
    assert "project target" in rendered
    assert "Standard" not in rendered
    assert "Deep" not in rendered
    assert project_file.read_bytes() == before
    assert not (project_file.parent / "programme_scope.json").exists()


def test_replacement_flow_displays_equivalent_scope_kind_guidance_without_writing(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    project_before = project_file.read_bytes()
    policy_path = project_file.parent / "programme_scope.json"
    policy_before = policy_path.read_bytes()
    output: list[str] = []

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs("3", "CANCEL"),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("guidance must not request a timestamp"),
    )

    rendered = "\n".join(output)
    for kind in (
        "exact_hostname",
        "wildcard_subdomain",
        "exact_http_url",
        "http_path_prefix",
        "exact_ipv4",
        "ipv4_cidr",
    ):
        assert kind in rendered
    assert "Rule ID is a local operator label" in rendered
    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered
    assert result == 0
    assert project_file.read_bytes() == project_before
    assert policy_path.read_bytes() == policy_before


def test_creation_rejects_duplicate_and_invalid_rule_without_mutating_draft(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    errors: list[str] = []
    answers = _inputs(
        "1", "host", "include", "exact_hostname", "example.test", "", "",
        "1", "HOST", "include", "exact_hostname", "other.test", "", "",
        "1", "bad", "include", "exact_hostname", "bad host", "", "",
        "3", "YES",
    )
    assert configure_project_programme_scope(
        project_file,
        input_func=answers,
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: CHANGED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert tuple(rule.rule_id for rule in policy.rules) == ("host",)
    assert any("unique" in error for error in errors)
    assert any("hostname" in error.lower() for error in errors)


def test_creation_saves_once_and_uses_canonical_multi_rule_order(
    tmp_path: Path, monkeypatch
) -> None:
    project_file = _project(tmp_path)
    real_save = scope_setup_module.save_project_programme_scope_policy
    calls = 0

    def counted_save(path, policy):
        nonlocal calls
        calls += 1
        return real_save(path, policy)

    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        counted_save,
    )
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "1", "z-rule", "include", "exact_hostname", "z.example.test", "", "",
            "1", "A-rule", "exclude", "exact_hostname", "a.example.test", "", "",
            "3", "YES",
        ),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert tuple(rule.rule_id for rule in policy.rules) == ("A-rule", "z-rule")
    assert calls == 1


def test_bulk_scope_review_requires_one_explicit_save(
    tmp_path: Path, monkeypatch
) -> None:
    project_file = _project(tmp_path)
    output: list[str] = []
    real_save = scope_setup_module.save_project_programme_scope_policy
    calls = 0

    def counted_save(path, policy):
        nonlocal calls
        calls += 1
        return real_save(path, policy)

    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        counted_save,
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("bulk scope setup must remain offline"),
    )

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "5",
            "include hostname app.example.test",
            "include wildcard *.example.test scheme=https port=443",
            "exclude path https://example.test/internal/",
            "END",
            "2",
            "3",
            "YES",
        ),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    )

    policy = load_project_programme_scope_policy(load_project(project_file))
    assert result == 0
    assert policy is not None
    assert len(policy.rules) == 3
    assert calls == 1
    rendered = "\n".join(output)
    saved_at = rendered.index("Programme scope saved privately")
    review = rendered[:saved_at]
    assert "Source: Structured manual entry" in review
    assert "PROPOSED EXECUTABLE AUTHORITY" in review
    assert "INCLUDE" in review
    assert "EXCLUDE" in review
    assert "UNRESOLVED / REQUIRES REVIEW\n- none" in review
    assert "NON-AUTHORITY CONTEXT\n- none" in review
    assert "Default: DENY" in review
    assert "Exclusions override inclusions" in review
    assert (
        "Runtime programme-scope enforcement is active for live project "
        "reconnaissance."
    ) in review
    assert "engagement-policy readiness and target evaluation" in review
    assert "Standard" not in review
    assert "Deep" not in review
    assert all(rule.rule_id in review for rule in policy.rules)
    assert "*.example.test" in review
    assert "https" in review and "443" in review
    assert "No reconnaissance was executed." in rendered
    assert (
        "Live project reconnaissance remains subject to strict engagement-policy, "
        "programme-scope and target preflight."
    ) in rendered


def test_bulk_scope_save_refusal_preserves_stored_policy(
    tmp_path: Path, monkeypatch
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy())
    project_before = project_file.read_bytes()
    policy_path = project_file.parent / "programme_scope.json"
    policy_before = policy_path.read_bytes()
    output: list[str] = []
    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        lambda *_args, **_kwargs: pytest.fail("refused bulk draft must not save"),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("bulk scope setup must remain offline"),
    )

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "8",
            "include hostname new.example.test",
            "END",
            "1",
            "6",
            "",
        ),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("refused bulk draft must not request time"),
    )

    rendered = "\n".join(output)
    assert result == 0
    assert "new.example.test" in rendered
    assert "Programme-scope save cancelled" in rendered
    assert project_file.read_bytes() == project_before
    assert policy_path.read_bytes() == policy_before


def test_empty_creation_requires_exact_confirmation(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    calls = 0

    def now() -> str:
        nonlocal calls
        calls += 1
        return CHANGED_TIME

    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs("3", "SAVE EMPTY POLICY"),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=now,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None and policy.rules == ()
    assert calls == 1


def test_new_unsaved_draft_review_uses_not_saved_timestamp_without_writes(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    project_before = project_file.read_bytes()
    output: list[str] = []

    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs("2", "4"),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("draft review must not request time"),
    ) == 0

    rendered = "\n".join(output)
    assert "Updated at: not saved yet" in rendered
    assert "Updated at: 1970-01-01T00:00:00Z" not in rendered
    assert project_file.read_bytes() == project_before
    assert not (project_file.parent / "programme_scope.json").exists()


def test_existing_policy_add_replace_remove_and_private_update_are_transactional(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy())
    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "2", "z-ip", "exclude", "exact_ipv4", "192.0.2.8", "", "",
            "3", "host", "exclude", "exact_http_url", "https://example.test/private", "CHANGE",
            "5", "host", PRIVATE_NOTE, PRIVATE_SOURCE,
            "4", "z-ip", "REMOVE",
            "6", "YES",
        ),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    )
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert result == 0
    assert policy is not None
    assert policy.updated_at == CHANGED_TIME
    assert len(policy.rules) == 1
    assert policy.rules[0].action == ACTION_EXCLUDE
    assert policy.rules[0].kind == RULE_EXACT_HTTP_URL
    assert policy.rules[0].private_note == PRIVATE_NOTE


def test_replacing_public_value_preserves_private_fields_without_private_prompts(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    answers = iter(
        (
            "3",
            "host",
            "include",
            "exact_http_url",
            "https://example.test/replacement",
            "6",
            "YES",
        )
    )
    prompts: list[str] = []

    def strict_input(prompt: str) -> str:
        prompts.append(prompt)
        assert "private note" not in prompt.lower()
        assert "private source" not in prompt.lower()
        return next(answers)

    output: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=strict_input,
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    ) == 0

    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert policy.rules[0].canonical_value == "https://example.test/replacement"
    assert policy.rules[0].private_note == PRIVATE_NOTE
    assert policy.rules[0].private_source_wording == PRIVATE_SOURCE
    assert PRIVATE_NOTE not in "\n".join(output)
    assert PRIVATE_SOURCE not in "\n".join(output)
    assert all("private note" not in prompt.lower() for prompt in prompts)
    assert all("private source" not in prompt.lower() for prompt in prompts)


def test_replacing_qualified_rule_preserves_fail_closed_http_authority(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    current_rule = build_programme_scope_rule(
        rule_id="qualified-wildcard",
        action=ACTION_INCLUDE,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.example.test",
        scheme="https",
        port=443,
    )
    current_policy = build_programme_scope_policy(
        (current_rule,),
        updated_at=ORIGINAL_TIME,
    )
    before_http = evaluate_raw_scope_destination(
        current_policy,
        DESTINATION_HTTP_URL,
        "http://api.example.test/",
    )
    save_project_programme_scope_policy(project_file, current_policy)

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "3",
            "qualified-wildcard",
            "include",
            "wildcard_subdomain",
            "*.example.test",
            "6",
            "YES",
        ),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    )

    replacement_policy = load_project_programme_scope_policy(load_project(project_file))
    assert replacement_policy is not None
    replacement = replacement_policy.rules[0]
    after_http = evaluate_raw_scope_destination(
        replacement_policy,
        DESTINATION_HTTP_URL,
        "http://api.example.test/",
    )
    after_https = evaluate_raw_scope_destination(
        replacement_policy,
        DESTINATION_HTTP_URL,
        "https://api.example.test/",
    )
    after_wrong_port = evaluate_raw_scope_destination(
        replacement_policy,
        DESTINATION_HTTP_URL,
        "https://api.example.test:8443/",
    )

    assert result == 0
    assert current_rule.scheme == "https"
    assert current_rule.port == 443
    assert before_http.outcome == OUTCOME_UNKNOWN
    assert replacement.scheme == "https"
    assert replacement.port == 443
    assert after_http.outcome == OUTCOME_UNKNOWN
    assert after_https.outcome == OUTCOME_ALLOWED
    assert after_wrong_port.outcome == OUTCOME_UNKNOWN


def test_canonically_unchanged_replacement_is_noop_and_preserves_private_fields(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    project_before = project_file.read_bytes()
    policy_path = project_file.parent / "programme_scope.json"
    policy_before = policy_path.read_bytes()
    answers = iter(
        (
            "3",
            "host",
            "include",
            "exact_hostname",
            "Example.TEST.",
            "6",
        )
    )

    def strict_input(prompt: str) -> str:
        assert "private note" not in prompt.lower()
        assert "private source" not in prompt.lower()
        return next(answers)

    output: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=strict_input,
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("no-op replacement must not request time"),
    ) == 0

    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy == _policy(private=True)
    assert "No programme-scope changes to save." in output
    assert project_file.read_bytes() == project_before
    assert policy_path.read_bytes() == policy_before


def test_private_fields_can_be_cleared_without_disclosing_presence(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    output: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs("5", "host", "", "", "6", "YES"),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert policy.rules[0].private_note is None
    assert policy.rules[0].private_source_wording is None
    assert PRIVATE_NOTE not in "\n".join(output)
    assert PRIVATE_SOURCE not in "\n".join(output)


def test_removing_final_inclusion_and_final_rule_requires_all_confirmations(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy())
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "4", "host", "REMOVE", "SAVE WITHOUT INCLUSIONS", "REMOVE FINAL RULE",
            "6", "SAVE EMPTY POLICY",
        ),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=lambda: CHANGED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None and policy.rules == ()


def test_noop_and_cancel_do_not_write_or_request_time(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy())
    before_project = project_file.read_bytes()
    before_policy = (project_file.parent / "programme_scope.json").read_bytes()

    def forbidden_now() -> str:
        raise AssertionError("no-op or cancellation must not request time")

    output: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs("6"),
        print_func=output.append,
        error_func=lambda _line: None,
        now_func=forbidden_now,
    ) == 0
    assert "No programme-scope changes to save." in output
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs("2", "CANCEL"),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=forbidden_now,
    ) == 0
    assert project_file.read_bytes() == before_project
    assert (project_file.parent / "programme_scope.json").read_bytes() == before_policy


@pytest.mark.parametrize(
    "answers",
    (
        ("7",),
        ("2", "CANCEL"),
        ("3", "CANCEL"),
        ("4", "CANCEL"),
        ("5", "CANCEL"),
        (
            "2", "new", "include", "exact_hostname", "new.example.test", "", "",
            "6", "CANCEL",
        ),
    ),
)
def test_cancellation_at_each_existing_policy_stage_never_writes(
    tmp_path: Path, answers: tuple[str, ...]
) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    before_project = project_file.read_bytes()
    before_policy = (project_file.parent / "programme_scope.json").read_bytes()
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(*answers),
        print_func=lambda _line: None,
        error_func=lambda _line: None,
        now_func=lambda: pytest.fail("cancel must not request a timestamp"),
    ) == 0
    assert project_file.read_bytes() == before_project
    assert (project_file.parent / "programme_scope.json").read_bytes() == before_policy


def test_unconfirmed_action_change_leaves_draft_unchanged(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    save_project_programme_scope_policy(project_file, _policy(private=True))
    errors: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "3", "host", "exclude", "exact_hostname", "other.test", "NO",
            "6",
        ),
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: pytest.fail("unchanged draft must not request time"),
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy == _policy(private=True)
    assert policy.rules[0].private_note == PRIVATE_NOTE
    assert policy.rules[0].private_source_wording == PRIVATE_SOURCE
    assert any("not confirmed" in error for error in errors)


def test_eof_is_an_error_and_never_writes(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    errors: list[str] = []

    def eof(_prompt: str) -> str:
        raise EOFError

    assert configure_project_programme_scope(
        project_file,
        input_func=eof,
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: CHANGED_TIME,
    ) == 2
    assert errors == ["Error: programme-scope input ended unexpectedly."]
    assert load_project(project_file).programme_scope_file is None


@pytest.mark.parametrize("context", ("ctf_lab", "authorised_lab", "internal_authorised", "unknown"))
def test_configure_rejects_wrong_context_before_policy_access(
    tmp_path: Path, context: str
) -> None:
    project_file = _project(tmp_path, context=context)
    errors: list[str] = []
    assert configure_project_programme_scope(
        project_file,
        input_func=lambda _prompt: pytest.fail("must not prompt"),
        print_func=lambda _line: pytest.fail("must not print"),
        error_func=errors.append,
        now_func=lambda: CHANGED_TIME,
    ) == 2
    assert "bug bounty" in errors[0]
    assert not (project_file.parent / "programme_scope.json").exists()


def test_failed_save_returns_two_without_private_output(tmp_path: Path, monkeypatch) -> None:
    project_file = _project(tmp_path)
    output: list[str] = []
    errors: list[str] = []

    def fail_save(*_args, **_kwargs):
        raise OSError("private-save-failure")

    monkeypatch.setattr("bugslyce.programme_scope_setup.save_project_programme_scope_policy", fail_save)
    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "1", "host", "include", "exact_hostname", "example.test", PRIVATE_NOTE, PRIVATE_SOURCE,
            "3", "YES",
        ),
        print_func=output.append,
        error_func=errors.append,
        now_func=lambda: CHANGED_TIME,
    ) == 2
    combined = "\n".join((*output, *errors))
    assert PRIVATE_NOTE not in combined
    assert PRIVATE_SOURCE not in combined
    assert "could not be saved safely" in combined


def test_invalid_proposal_fails_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_file = _project(tmp_path)
    errors: list[str] = []

    def invalid_proposal(_rules):
        raise ValueError("invalid proposal")

    monkeypatch.setattr(
        scope_setup_module,
        "build_manual_programme_scope_proposal",
        invalid_proposal,
    )
    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        lambda *_args, **_kwargs: pytest.fail("invalid proposal must not save"),
    )

    result = configure_project_programme_scope(
        project_file,
        input_func=_inputs("3"),
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: pytest.fail("invalid proposal must not request time"),
    )

    assert result == 2
    assert errors == ["Error: invalid proposal"]
    assert load_project(project_file).programme_scope_file is None


def test_legacy_extension_upgrade_refusal_is_safe_and_non_mutating(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = "1.0"
    payload["legacy_extension"] = "extension-private-sentinel-4412"
    project_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    before = project_file.read_bytes()
    errors: list[str] = []

    assert configure_project_programme_scope(
        project_file,
        input_func=_inputs(
            "1", "host", "include", "exact_hostname", "example.test", "", "",
            "3", "YES",
        ),
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: CHANGED_TIME,
    ) == 2
    assert "cannot be upgraded automatically" in errors[0]
    assert "extension-private-sentinel-4412" not in errors[0]
    assert project_file.read_bytes() == before
    assert not (project_file.parent / "programme_scope.json").exists()
