"""Contracts for the non-authoritative programme-scope proposal boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import socket
import subprocess

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_HTTP_PATH_PREFIX,
    build_programme_scope_rule,
)
from bugslyce.core.programme_scope_bulk import build_programme_scope_bulk_draft
from bugslyce.programme_scope_proposal import (
    MANUAL_PROPOSAL_SOURCE_ID,
    PROPOSAL_SOURCE_MANUAL,
    ProgrammeScopeNonAuthorityContext,
    ProgrammeScopeProposalUnresolvedItem,
    build_manual_programme_scope_proposal,
    build_programme_scope_proposal,
    build_programme_scope_proposal_source,
    render_programme_scope_proposal_review,
)


PRIVATE_NOTE = "private-note-sentinel-3819"
PRIVATE_SOURCE = "private-source-sentinel-3819"


def _rule(
    rule_id: str,
    *,
    action: str = ACTION_INCLUDE,
    kind: str = RULE_EXACT_HOSTNAME,
    value: str = "example.test",
):
    return build_programme_scope_rule(
        rule_id=rule_id,
        action=action,
        kind=kind,
        value=value,
        private_note=PRIVATE_NOTE,
        private_source_wording=PRIVATE_SOURCE,
    )


def _rule_semantics(rule) -> tuple[object, ...]:
    return (
        rule.action,
        rule.kind,
        rule.canonical_value,
        rule.scheme,
        rule.port,
    )


def test_manual_proposal_is_immutable_deterministic_and_source_identified() -> None:
    first = build_manual_programme_scope_proposal(
        (
            _rule("z-rule", value="z.example.test"),
            _rule("A-rule", action=ACTION_EXCLUDE, value="a.example.test"),
        )
    )
    reversed_input = build_manual_programme_scope_proposal(tuple(reversed(first.rules)))

    assert first == reversed_input
    assert tuple(rule.rule_id for rule in first.rules) == ("A-rule", "z-rule")
    assert first.source.source_type == PROPOSAL_SOURCE_MANUAL
    assert first.source.source_id == MANUAL_PROPOSAL_SOURCE_ID
    assert first.unresolved_items == ()
    assert first.non_authority_context == ()
    with pytest.raises(FrozenInstanceError):
        first.source.source_id = "changed"  # type: ignore[misc]


def test_single_and_bulk_manual_inputs_produce_equivalent_rule_semantics() -> None:
    single = build_manual_programme_scope_proposal(
        (
            build_programme_scope_rule(
                rule_id="operator-host",
                action=ACTION_INCLUDE,
                kind=RULE_EXACT_HOSTNAME,
                value="Example.TEST.",
            ),
        )
    )
    bulk = build_manual_programme_scope_proposal(
        build_programme_scope_bulk_draft(
            "include hostname Example.TEST."
        ).rules
    )

    assert tuple(map(_rule_semantics, single.rules)) == tuple(
        map(_rule_semantics, bulk.rules)
    )


def test_categories_are_typed_separate_and_deterministically_ordered() -> None:
    source = build_programme_scope_proposal_source(
        source_type="synthetic_review",
        source_id="synthetic-review-1",
        display_name="Synthetic review",
    )
    unresolved = (
        ProgrammeScopeProposalUnresolvedItem("z-item", "Resolve the final row"),
        ProgrammeScopeProposalUnresolvedItem("a-item", "Resolve the first row"),
    )
    context = (
        ProgrammeScopeNonAuthorityContext("z-context", "Submission eligible", "yes"),
        ProgrammeScopeNonAuthorityContext("a-context", "Bounty eligible", "no"),
    )

    proposal = build_programme_scope_proposal(
        source=source,
        rules=(_rule("host"),),
        unresolved_items=unresolved,
        non_authority_context=context,
    )

    assert tuple(item.item_id for item in proposal.unresolved_items) == (
        "a-item",
        "z-item",
    )
    assert tuple(item.item_id for item in proposal.non_authority_context) == (
        "a-context",
        "z-context",
    )
    assert all(
        isinstance(item, ProgrammeScopeProposalUnresolvedItem)
        for item in proposal.unresolved_items
    )
    assert all(
        isinstance(item, ProgrammeScopeNonAuthorityContext)
        for item in proposal.non_authority_context
    )


@pytest.mark.parametrize(
    ("unresolved", "context"),
    (
        ((object(),), ()),
        ((), (object(),)),
        (
            (),
            (ProgrammeScopeProposalUnresolvedItem("wrong", "Wrong category"),),
        ),
        (
            (ProgrammeScopeNonAuthorityContext("wrong", "Wrong", "category"),),
            (),
        ),
        (
            (ProgrammeScopeProposalUnresolvedItem("same", "Needs review"),),
            (ProgrammeScopeNonAuthorityContext("SAME", "Metadata", "value"),),
        ),
    ),
)
def test_invalid_or_cross_category_ambiguous_items_fail_closed(
    unresolved: tuple[object, ...],
    context: tuple[object, ...],
) -> None:
    with pytest.raises(ValueError):
        build_programme_scope_proposal(
            source=build_programme_scope_proposal_source(
                source_type="synthetic_review",
                source_id="synthetic-review-1",
                display_name="Synthetic review",
            ),
            rules=(),
            unresolved_items=unresolved,
            non_authority_context=context,
        )


def test_preview_separates_categories_states_authority_and_redacts_rules() -> None:
    proposal = build_programme_scope_proposal(
        source=build_programme_scope_proposal_source(
            source_type="synthetic_review",
            source_id="synthetic-review-1",
            display_name="Synthetic review",
        ),
        rules=(
            _rule("include-host"),
            _rule(
                "exclude-path",
                action=ACTION_EXCLUDE,
                kind=RULE_HTTP_PATH_PREFIX,
                value="https://example.test/private/",
            ),
        ),
        unresolved_items=(
            ProgrammeScopeProposalUnresolvedItem("unresolved-1", "Resolve source row"),
        ),
        non_authority_context=(
            ProgrammeScopeNonAuthorityContext(
                "metadata-1",
                "Submission eligible",
                "yes",
            ),
        ),
    )

    rendered = render_programme_scope_proposal_review(proposal)

    assert "PROPOSED EXECUTABLE AUTHORITY" in rendered
    assert "INCLUDE" in rendered and "include-host" in rendered
    assert "EXCLUDE" in rendered and "exclude-path" in rendered
    assert "UNRESOLVED / REQUIRES REVIEW" in rendered
    assert "Resolve source row" in rendered
    assert "NON-AUTHORITY CONTEXT" in rendered
    assert "Submission eligible: yes" in rendered
    assert "Default: DENY" in rendered
    assert (
        "Narrower explicit scope rules may override broader rules; exclusions "
        "win equal or incomparable overlaps" in rendered
    )
    assert PRIVATE_NOTE not in rendered
    assert PRIVATE_SOURCE not in rendered


def test_proposal_construction_has_no_file_network_subprocess_or_runtime_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("proposal must not use network"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("proposal must not run subprocesses"),
    )

    proposal = build_manual_programme_scope_proposal((_rule("host"),))

    assert proposal.rules[0].canonical_value == "example.test"
    assert list(tmp_path.iterdir()) == []
