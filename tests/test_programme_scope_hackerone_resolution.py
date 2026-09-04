"""Pure HackerOne programme-scope resolution contracts."""

from __future__ import annotations

import csv
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import socket
import subprocess

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopeRule,
    build_programme_scope_rule,
)
from bugslyce.programme_scope_hackerone_csv import (
    ASSET_GOOGLE_PLAY_APP_ID,
    ASSET_OTHER,
    ASSET_SOURCE_CODE,
    ASSET_URL,
    ASSET_WILDCARD,
    CATEGORY_EXECUTABLE,
    CATEGORY_NON_AUTHORITY,
    CATEGORY_UNRESOLVED,
    HACKERONE_CSV_HEADERS,
    REASON_AMBIGUOUS_BARE_HOSTNAME,
    REASON_AMBIGUOUS_OTHER_ASSET,
    REASON_AMBIGUOUS_SCHEMELESS_URL,
    REASON_CANONICAL_HTTP_URL,
    REASON_CANONICAL_WILDCARD,
    REASON_INSTRUCTION_REVIEW_REQUIRED,
    REASON_NON_WEB_ASSET_TYPE,
    REASON_NONCANONICAL_HTTP_URL,
    REASON_URL_ASSET_WILDCARD_MISMATCH,
    build_hackerone_programme_scope_proposal,
)
from bugslyce.programme_scope_hackerone_resolution import (
    NON_AUTHORITY_EXPLICIT_INCLUDE,
    NON_AUTHORITY_EXPLICIT_NON_WEB,
    NON_AUTHORITY_P2A_TYPED,
    ROW_STATE_AUTOMATIC_RULE,
    ROW_STATE_EXPLICIT_NON_AUTHORITY,
    ROW_STATE_EXPLICIT_RULE,
    ROW_STATE_TYPED_NON_AUTHORITY,
    ROW_STATE_UNRESOLVED,
    HackerOneScopeResolutionSession,
    acknowledge_hackerone_scope_instruction,
    build_hackerone_scope_resolution_session,
    build_hackerone_scope_review_candidate,
    classify_hackerone_scope_row_as_non_web,
    finalize_hackerone_scope_resolution,
    get_hackerone_scope_resolution,
    reset_hackerone_scope_row,
    resolve_hackerone_scope_group_with_source_rule,
    resolve_hackerone_scope_include_as_non_authority,
    resolve_hackerone_scope_row_with_rule,
)
from bugslyce.programme_scope_proposal import ProgrammeScopeProposal


def _row(**overrides: str) -> dict[str, str]:
    row = {
        "identifier": "https://example.test/service",
        "asset_type": ASSET_URL,
        "instruction": "",
        "eligible_for_bounty": "true",
        "eligible_for_submission": "true",
        "availability_requirement": "high",
        "confidentiality_requirement": "high",
        "integrity_requirement": "high",
        "max_severity": "critical",
        "system_tags": "",
        "created_at": "2026-09-01 12:00:00 UTC",
        "updated_at": "2026-09-02 12:00:00 UTC",
    }
    row.update(overrides)
    return row


def _build(tmp_path: Path, *rows: dict[str, str], name: str = "scope.csv"):
    path = tmp_path / name
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(HACKERONE_CSV_HEADERS)
        for row in rows:
            writer.writerow(tuple(row[header] for header in HACKERONE_CSV_HEADERS))
    return build_hackerone_programme_scope_proposal(path)


def _session(tmp_path: Path, *rows: dict[str, str]) -> HackerOneScopeResolutionSession:
    return build_hackerone_scope_resolution_session(_build(tmp_path, *rows))


def _resolution(session: HackerOneScopeResolutionSession, index: int = 0):
    return get_hackerone_scope_resolution(
        session,
        session.source_result.document.rows[index].row_id,
    )


def _acknowledge(session: HackerOneScopeResolutionSession, index: int = 0):
    resolution = _resolution(session, index)
    assert resolution.instruction_sha256 is not None
    return acknowledge_hackerone_scope_instruction(
        session,
        resolution.row_id,
        source_sha256=session.source_sha256,
        instruction_sha256=resolution.instruction_sha256,
    )


def test_session_identity_rows_immutability_and_groups_are_deterministic(
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(identifier="example.test"),
        _row(identifier="other.test"),
        _row(identifier="third.test", instruction="Review this row."),
        _row(
            identifier="com.example.app",
            asset_type=ASSET_GOOGLE_PLAY_APP_ID,
        ),
    )

    first = build_hackerone_scope_resolution_session(result)
    second = build_hackerone_scope_resolution_session(result)

    assert first == second
    assert first.source_sha256 == result.document.source_sha256
    assert first.source_result.proposal.source is result.proposal.source
    assert tuple(item.row_id for item in first.resolutions) == tuple(
        row.row_id for row in result.document.rows
    )
    assert len(first.resolutions) == len(result.document.rows) == 4
    group_keys = tuple(
        (
            group.reason,
            group.asset_type,
            group.proposed_action,
            group.instruction_present,
        )
        for group in first.groups
    )
    assert group_keys == tuple(sorted(group_keys))
    assert {
        (group.reason, group.asset_type, group.proposed_action, group.instruction_present)
        for group in first.groups
    } == {
        (REASON_AMBIGUOUS_BARE_HOSTNAME, ASSET_URL, ACTION_INCLUDE, False),
        (REASON_AMBIGUOUS_BARE_HOSTNAME, ASSET_URL, ACTION_INCLUDE, True),
        (
            REASON_NON_WEB_ASSET_TYPE,
            ASSET_GOOGLE_PLAY_APP_ID,
            ACTION_INCLUDE,
            False,
        ),
    }
    with pytest.raises(FrozenInstanceError):
        first.source_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        first.resolutions[0].state = ROW_STATE_EXPLICIT_RULE  # type: ignore[misc]


def test_session_rejects_missing_duplicate_and_foreign_row_material(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path, _row(identifier="one.test"), _row(identifier="two.test"))
    other = _build(tmp_path, _row(identifier="foreign.test"), name="other.csv")

    with pytest.raises(ValueError, match="exactly once"):
        replace(session, resolutions=session.resolutions[:-1])
    with pytest.raises(ValueError, match="exactly once"):
        replace(session, resolutions=(session.resolutions[0], session.resolutions[0]))
    with pytest.raises(ValueError, match="source|row"):
        replace(session, source_result=other)
    with pytest.raises(ValueError, match="does not exist"):
        get_hackerone_scope_resolution(session, other.document.rows[0].row_id)


def test_session_retains_only_p2a_automatic_rules_without_new_conversion(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://example.test/exact"),
        _row(identifier="ambiguous.example.test"),
        _row(identifier="*.example.test", asset_type=ASSET_WILDCARD),
    )

    assert tuple(item.state for item in session.resolutions) == (
        ROW_STATE_AUTOMATIC_RULE,
        ROW_STATE_UNRESOLVED,
        ROW_STATE_AUTOMATIC_RULE,
    )
    assert tuple(len(item.rules) for item in session.resolutions) == (1, 0, 1)
    assert session.resolutions[0].source_category == CATEGORY_EXECUTABLE
    assert session.resolutions[1].source_category == CATEGORY_UNRESOLVED


def test_bare_hostname_include_requires_explicit_hostname_or_complete_url(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path, _row(identifier="api.example.test"))
    row_id = session.resolutions[0].row_id

    assert _resolution(session).state == ROW_STATE_UNRESOLVED
    hostname = resolve_hackerone_scope_row_with_rule(
        session,
        row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="api.example.test",
    )
    hostname_rule = _resolution(hostname).rules[0]
    assert hostname_rule.kind == RULE_EXACT_HOSTNAME
    assert hostname_rule.action == ACTION_INCLUDE
    assert hostname_rule.canonical_value == "api.example.test"

    url = resolve_hackerone_scope_row_with_rule(
        session,
        row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://api.example.test/v1",
    )
    url_rule = _resolution(url).rules[0]
    assert url_rule.kind == RULE_EXACT_HTTP_URL
    assert url_rule.canonical_value == "https://api.example.test/v1"


def test_bare_hostname_exclude_requires_canonical_exclusion_closure(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="admin.example.test", eligible_for_submission="false"),
    )
    row_id = session.resolutions[0].row_id

    with pytest.raises(ValueError, match="proposed exclude|web"):
        resolve_hackerone_scope_include_as_non_authority(session, row_id)
    with pytest.raises(ValueError, match="proposed exclude|web"):
        classify_hackerone_scope_row_as_non_web(session, row_id)
    with pytest.raises(ValueError, match="unresolved|exclusion"):
        finalize_hackerone_scope_resolution(session)

    resolved = resolve_hackerone_scope_row_with_rule(
        session,
        row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="admin.example.test",
    )
    proposal = finalize_hackerone_scope_resolution(resolved)
    assert len(proposal.rules) == 1
    assert proposal.rules[0].action == ACTION_EXCLUDE


def test_schemeless_url_and_url_wildcard_require_explicit_safe_decisions(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="example.test/service"),
        _row(identifier="*.example.test", asset_type=ASSET_URL),
    )
    scheme_row, wildcard_row = session.resolutions
    assert scheme_row.reason == REASON_AMBIGUOUS_SCHEMELESS_URL
    assert wildcard_row.reason == REASON_URL_ASSET_WILDCARD_MISMATCH

    with pytest.raises(ValueError, match="exact HTTP"):
        resolve_hackerone_scope_row_with_rule(
            session,
            scheme_row.row_id,
            kind=RULE_EXACT_HOSTNAME,
            value="example.test",
        )
    with pytest.raises(ValueError, match="HTTP"):
        resolve_hackerone_scope_row_with_rule(
            session,
            scheme_row.row_id,
            kind=RULE_EXACT_HTTP_URL,
            value="example.test/service",
        )
    resolved = resolve_hackerone_scope_row_with_rule(
        session,
        scheme_row.row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://example.test/service",
    )
    resolved = resolve_hackerone_scope_row_with_rule(
        resolved,
        wildcard_row.row_id,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.example.test",
    )
    assert tuple(item.state for item in resolved.resolutions) == (
        ROW_STATE_EXPLICIT_RULE,
        ROW_STATE_EXPLICIT_RULE,
    )


@pytest.mark.parametrize(
    ("identifier", "kind", "value", "message"),
    (
        (
            "example.test/service",
            RULE_EXACT_HOSTNAME,
            "example.test",
            "exact HTTP",
        ),
        (
            "example.test",
            RULE_WILDCARD_SUBDOMAIN,
            "*.example.test",
            "hostname or exact HTTP",
        ),
    ),
)
def test_direct_row_construction_rejects_reason_rule_kind_bypass(
    tmp_path: Path,
    identifier: str,
    kind: str,
    value: str,
    message: str,
) -> None:
    session = _session(tmp_path, _row(identifier=identifier))
    resolution = _resolution(session)
    invalid_rule = build_programme_scope_rule(
        rule_id="direct-bypass",
        action=resolution.proposed_action,
        kind=kind,
        value=value,
    )

    with pytest.raises(ValueError, match=message):
        resolve_hackerone_scope_row_with_rule(
            session,
            resolution.row_id,
            kind=kind,
            value=value,
        )
    with pytest.raises(ValueError, match=message):
        replace(
            resolution,
            state=ROW_STATE_EXPLICIT_RULE,
            rules=(invalid_rule,),
            non_authority_basis=None,
        )


@pytest.mark.parametrize(
    "state",
    (ROW_STATE_AUTOMATIC_RULE, ROW_STATE_EXPLICIT_RULE),
)
def test_direct_row_construction_cannot_promote_p2a_non_authority(
    tmp_path: Path,
    state: str,
) -> None:
    session = _session(
        tmp_path,
        _row(
            identifier="com.example.app",
            asset_type=ASSET_GOOGLE_PLAY_APP_ID,
        ),
    )
    resolution = _resolution(session)
    invalid_rule = build_programme_scope_rule(
        rule_id="direct-non-authority-bypass",
        action=resolution.proposed_action,
        kind=RULE_EXACT_HOSTNAME,
        value="com.example.app",
    )

    with pytest.raises(ValueError, match="typed non-authority"):
        resolve_hackerone_scope_row_with_rule(
            session,
            resolution.row_id,
            kind=RULE_EXACT_HOSTNAME,
            value="com.example.app",
        )
    with pytest.raises(ValueError, match="typed non-authority"):
        replace(
            resolution,
            state=state,
            rules=(invalid_rule,),
            non_authority_basis=None,
        )


def test_supported_rule_kinds_and_non_authority_review_states_remain_valid(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="api.example.test"),
        _row(identifier="example.test/service"),
        _row(identifier="https://Example.TEST:443/service"),
        _row(identifier="com.example.app", asset_type=ASSET_GOOGLE_PLAY_APP_ID),
        _row(identifier="context", asset_type=ASSET_OTHER),
    )
    bare_row, scheme_row, canonical_row, non_web_row, other_row = session.resolutions

    hostname = resolve_hackerone_scope_row_with_rule(
        session,
        bare_row.row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="api.example.test",
    )
    full_url = resolve_hackerone_scope_row_with_rule(
        session,
        bare_row.row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://api.example.test/",
    )
    scheme_url = resolve_hackerone_scope_row_with_rule(
        session,
        scheme_row.row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://example.test/service",
    )
    canonical_url = resolve_hackerone_scope_row_with_rule(
        session,
        canonical_row.row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://example.test/service",
    )

    assert _resolution(hostname).rules[0].kind == RULE_EXACT_HOSTNAME
    assert _resolution(full_url).rules[0].kind == RULE_EXACT_HTTP_URL
    assert get_hackerone_scope_resolution(
        scheme_url,
        scheme_row.row_id,
    ).rules[0].kind == RULE_EXACT_HTTP_URL
    assert get_hackerone_scope_resolution(
        canonical_url,
        canonical_row.row_id,
    ).rules[0].kind == RULE_EXACT_HTTP_URL
    assert non_web_row.state == ROW_STATE_TYPED_NON_AUTHORITY
    reset = reset_hackerone_scope_row(session, non_web_row.row_id)
    assert get_hackerone_scope_resolution(reset, non_web_row.row_id).state == (
        ROW_STATE_UNRESOLVED
    )
    reviewed = classify_hackerone_scope_row_as_non_web(session, other_row.row_id)
    assert get_hackerone_scope_resolution(reviewed, other_row.row_id).state == (
        ROW_STATE_EXPLICIT_NON_AUTHORITY
    )


def test_automatic_state_requires_the_exact_p2a_rule(tmp_path: Path) -> None:
    session = _session(
        tmp_path,
        _row(identifier="*.example.test", asset_type=ASSET_WILDCARD),
    )
    resolution = _resolution(session)
    replacement_rule = build_programme_scope_rule(
        rule_id="different-automatic-rule",
        action=resolution.proposed_action,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.example.test",
    )

    with pytest.raises(ValueError, match="exact P2A rule"):
        replace(
            session,
            resolutions=(replace(resolution, rules=(replacement_rule,)),),
        )


def test_noncanonical_url_candidate_is_exposed_without_applying_it(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://Example.TEST:443/service"),
    )
    resolution = _resolution(session)
    assert resolution.reason == REASON_NONCANONICAL_HTTP_URL

    candidate = build_hackerone_scope_review_candidate(session, resolution.row_id)

    assert candidate is not None
    assert candidate.kind == RULE_EXACT_HTTP_URL
    assert candidate.canonical_value == "https://example.test/service"
    assert _resolution(session).state == ROW_STATE_UNRESOLVED
    accepted = resolve_hackerone_scope_row_with_rule(
        session,
        resolution.row_id,
        kind=candidate.kind,
        value=candidate.canonical_value,
    )
    assert _resolution(accepted).state == ROW_STATE_EXPLICIT_RULE


def test_other_requires_explicit_rule_or_distinct_non_web_classification(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(
            identifier="https://example.test/looks-web",
            asset_type=ASSET_OTHER,
            eligible_for_submission="false",
        ),
    )
    row_id = session.resolutions[0].row_id
    assert _resolution(session).reason == REASON_AMBIGUOUS_OTHER_ASSET
    assert _resolution(session).rules == ()

    classified = classify_hackerone_scope_row_as_non_web(session, row_id)
    resolution = _resolution(classified)
    assert resolution.state == ROW_STATE_EXPLICIT_NON_AUTHORITY
    assert resolution.non_authority_basis == NON_AUTHORITY_EXPLICIT_NON_WEB
    assert finalize_hackerone_scope_resolution(classified).rules == ()

    canonical = resolve_hackerone_scope_row_with_rule(
        session,
        row_id,
        kind=RULE_EXACT_HTTP_URL,
        value="https://example.test/looks-web",
    )
    assert finalize_hackerone_scope_resolution(canonical).rules[0].action == ACTION_EXCLUDE


def test_instruction_acknowledgement_is_orthogonal_and_bound_to_exact_identity(
    tmp_path: Path,
) -> None:
    instruction = "Review this exact instruction.\nIt remains source context."
    session = _session(
        tmp_path,
        _row(identifier="*.example.test", asset_type=ASSET_WILDCARD, instruction=instruction),
    )
    row_id = session.resolutions[0].row_id
    resolution = _resolution(session)
    assert resolution.reason == REASON_INSTRUCTION_REVIEW_REQUIRED
    assert resolution.instruction_sha256 == hashlib.sha256(
        instruction.encode("utf-8")
    ).hexdigest()

    resolved = resolve_hackerone_scope_row_with_rule(
        session,
        row_id,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.example.test",
    )
    with pytest.raises(ValueError, match="instruction"):
        finalize_hackerone_scope_resolution(resolved)
    with pytest.raises(ValueError, match="source"):
        acknowledge_hackerone_scope_instruction(
            resolved,
            row_id,
            source_sha256="0" * 64,
            instruction_sha256=resolution.instruction_sha256,
        )
    with pytest.raises(ValueError, match="digest"):
        acknowledge_hackerone_scope_instruction(
            resolved,
            row_id,
            source_sha256=resolved.source_sha256,
            instruction_sha256="0" * 64,
        )

    acknowledged = _acknowledge(resolved)
    assert _resolution(acknowledged).instruction_acknowledged is True
    assert finalize_hackerone_scope_resolution(acknowledged).rules

    changed_source = _session(
        tmp_path,
        _row(
            identifier="*.example.test",
            asset_type=ASSET_WILDCARD,
            instruction=instruction,
        ),
        _row(identifier="changed-source.example.test"),
    )
    original_with_second_row = _session(
        tmp_path,
        _row(
            identifier="*.example.test",
            asset_type=ASSET_WILDCARD,
            instruction=instruction,
        ),
        _row(identifier="original-source.example.test"),
    )
    acknowledged_original = _acknowledge(original_with_second_row)
    with pytest.raises(ValueError, match="source"):
        replace(
            changed_source,
            resolutions=(
                acknowledged_original.resolutions[0],
                changed_source.resolutions[1],
            ),
        )


def test_automatic_exclusion_closes_only_while_retained(tmp_path: Path) -> None:
    session = _session(
        tmp_path,
        _row(
            identifier="*.example.test",
            asset_type=ASSET_WILDCARD,
            eligible_for_submission="false",
        ),
    )
    resolution = _resolution(session)
    assert resolution.state == ROW_STATE_AUTOMATIC_RULE
    assert resolution.reason == REASON_CANONICAL_WILDCARD
    assert finalize_hackerone_scope_resolution(session).rules[0].action == ACTION_EXCLUDE

    reset = reset_hackerone_scope_row(session, resolution.row_id)
    with pytest.raises(ValueError, match="unresolved|exclusion"):
        finalize_hackerone_scope_resolution(reset)


def test_include_non_authority_is_explicit_rule_free_and_traceable(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path, _row(identifier="optional.example.test"))
    row_id = session.resolutions[0].row_id

    dismissed = resolve_hackerone_scope_include_as_non_authority(session, row_id)
    resolution = _resolution(dismissed)
    assert resolution.state == ROW_STATE_EXPLICIT_NON_AUTHORITY
    assert resolution.non_authority_basis == NON_AUTHORITY_EXPLICIT_INCLUDE
    assert resolution.rules == ()

    proposal = finalize_hackerone_scope_resolution(dismissed)
    assert proposal.rules == ()
    rendered_context = "\n".join(item.value for item in proposal.non_authority_context)
    assert row_id in rendered_context
    assert NON_AUTHORITY_EXPLICIT_INCLUDE in rendered_context


def test_typed_non_web_exclude_never_manufactures_authority_and_requires_instruction(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(
            identifier="https://code.example.test/repository",
            asset_type=ASSET_SOURCE_CODE,
            instruction="Source-specific restriction.",
            eligible_for_submission="false",
        ),
    )
    resolution = _resolution(session)
    assert resolution.source_category == CATEGORY_NON_AUTHORITY
    assert resolution.state == ROW_STATE_TYPED_NON_AUTHORITY
    assert resolution.non_authority_basis == NON_AUTHORITY_P2A_TYPED
    assert resolution.rules == ()
    with pytest.raises(ValueError, match="instruction"):
        finalize_hackerone_scope_resolution(session)

    proposal = finalize_hackerone_scope_resolution(_acknowledge(session))
    assert proposal.rules == ()
    assert len(proposal.non_authority_context) == 1


def test_selected_group_members_can_use_source_values_and_be_overridden(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="a.example.test"),
        _row(identifier="b.example.test"),
        _row(identifier="c.example.test"),
    )
    group = session.groups[0]
    selected = (session.resolutions[0].row_id, session.resolutions[2].row_id)

    changed = resolve_hackerone_scope_group_with_source_rule(
        session,
        group.group_id,
        row_ids=selected,
        kind=RULE_EXACT_HOSTNAME,
    )

    assert tuple(item.state for item in changed.resolutions) == (
        ROW_STATE_EXPLICIT_RULE,
        ROW_STATE_UNRESOLVED,
        ROW_STATE_EXPLICIT_RULE,
    )
    assert tuple(_resolution(changed, index).rules[0].canonical_value for index in (0, 2)) == (
        "a.example.test",
        "c.example.test",
    )
    overridden = resolve_hackerone_scope_row_with_rule(
        changed,
        selected[0],
        kind=RULE_EXACT_HTTP_URL,
        value="https://a.example.test/specific",
    )
    assert _resolution(overridden).rules[0].kind == RULE_EXACT_HTTP_URL
    assert _resolution(session).state == ROW_STATE_UNRESOLVED


def test_complete_session_deduplicates_equivalent_rules_and_rejects_conflicts(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="first", asset_type=ASSET_OTHER),
        _row(identifier="second", asset_type=ASSET_OTHER),
    )
    for resolution in session.resolutions:
        session = resolve_hackerone_scope_row_with_rule(
            session,
            resolution.row_id,
            kind=RULE_EXACT_HTTP_URL,
            value="https://example.test/shared",
        )
    first = finalize_hackerone_scope_resolution(session)
    second = finalize_hackerone_scope_resolution(session)
    assert first == second
    assert isinstance(first, ProgrammeScopeProposal)
    assert first.unresolved_items == ()
    assert first.source is session.source_result.proposal.source
    assert len(first.rules) == 1
    assert len(first.non_authority_context) == 2
    assert all(first.rules[0].rule_id in item.value for item in first.non_authority_context)

    conflict = _session(
        tmp_path,
        _row(identifier="first", asset_type=ASSET_OTHER),
        _row(
            identifier="second",
            asset_type=ASSET_OTHER,
            eligible_for_submission="false",
        ),
    )
    for resolution in conflict.resolutions:
        conflict = resolve_hackerone_scope_row_with_rule(
            conflict,
            resolution.row_id,
            kind=RULE_EXACT_HTTP_URL,
            value="https://example.test/shared",
        )
    with pytest.raises(ValueError, match="conflicting"):
        finalize_hackerone_scope_resolution(conflict)


def test_resolved_rule_and_group_ids_are_deterministic(tmp_path: Path) -> None:
    result = _build(tmp_path, _row(identifier="api.example.test"))
    first = build_hackerone_scope_resolution_session(result)
    second = build_hackerone_scope_resolution_session(result)
    row_id = first.resolutions[0].row_id

    first = resolve_hackerone_scope_row_with_rule(
        first,
        row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="api.example.test",
    )
    second = resolve_hackerone_scope_row_with_rule(
        second,
        row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="api.example.test",
    )
    assert first.groups == second.groups
    assert _resolution(first).rules == _resolution(second).rules
    assert _resolution(first).rules[0].rule_id.startswith("h1-resolved-")


def test_resolution_is_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _build(tmp_path, _row(identifier="api.example.test"))
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("resolution must not use network"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("resolution must not run subprocesses"),
    )

    session = build_hackerone_scope_resolution_session(result)
    session = resolve_hackerone_scope_row_with_rule(
        session,
        session.resolutions[0].row_id,
        kind=RULE_EXACT_HOSTNAME,
        value="api.example.test",
    )
    proposal = finalize_hackerone_scope_resolution(session)

    assert isinstance(proposal.rules[0], ProgrammeScopeRule)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert result.outcomes[0].category == CATEGORY_UNRESOLVED
    assert result.proposal.rules == ()
    assert result.proposal.unresolved_items
