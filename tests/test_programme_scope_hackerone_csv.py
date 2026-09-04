"""Contracts for strict, non-authoritative HackerOne scope CSV ingestion."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import socket
import subprocess

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HTTP_URL,
    RULE_WILDCARD_SUBDOMAIN,
)
from bugslyce.programme_scope_hackerone_csv import (
    ASSET_API,
    ASSET_APPLE_STORE_APP_ID,
    ASSET_DOWNLOADABLE_EXECUTABLES,
    ASSET_GOOGLE_PLAY_APP_ID,
    ASSET_HARDWARE,
    ASSET_OTHER,
    ASSET_SOURCE_CODE,
    ASSET_URL,
    ASSET_WILDCARD,
    ASSET_WINDOWS_APP_STORE_APP_ID,
    CATEGORY_EXECUTABLE,
    CATEGORY_NON_AUTHORITY,
    CATEGORY_UNRESOLVED,
    HACKERONE_CSV_HEADERS,
    HACKERONE_PROPOSAL_SOURCE_TYPE,
    MAX_HACKERONE_CSV_BYTES,
    REASON_AMBIGUOUS_BARE_HOSTNAME,
    REASON_AMBIGUOUS_OTHER_ASSET,
    REASON_AMBIGUOUS_SCHEMELESS_URL,
    REASON_CANONICAL_HTTP_URL,
    REASON_CANONICAL_WILDCARD,
    REASON_INSTRUCTION_REVIEW_REQUIRED,
    REASON_MALFORMED_WILDCARD,
    REASON_NON_WEB_ASSET_TYPE,
    REASON_UNSUPPORTED_ASSET_TYPE,
    REASON_UNSUPPORTED_URL_IDENTIFIER,
    REASON_URL_ASSET_WILDCARD_MISMATCH,
    build_hackerone_programme_scope_proposal,
    load_hackerone_scope_csv,
)
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeNonAuthorityContext,
    ProgrammeScopeProposal,
    ProgrammeScopeProposalUnresolvedItem,
    render_programme_scope_proposal_review,
)
import bugslyce.programme_scope_hackerone_csv as hackerone_module


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


def _write_csv(
    tmp_path: Path,
    rows: tuple[dict[str, str], ...],
    *,
    headers: tuple[str, ...] = HACKERONE_CSV_HEADERS,
    name: str = "synthetic-hackerone-scope.csv",
) -> Path:
    path = tmp_path / name
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(headers)
        for row in rows:
            writer.writerow(tuple(row.get(header, "") for header in headers))
    return path


def _build(tmp_path: Path, *rows: dict[str, str]):
    return build_hackerone_programme_scope_proposal(
        _write_csv(tmp_path, tuple(rows))
    )


def test_exact_schema_accepts_quoted_comma_and_multiline_instruction(
    tmp_path: Path,
) -> None:
    instruction = "Review this value, including commas.\nRetain the second line."
    path = _write_csv(tmp_path, (_row(instruction=instruction),))

    document = load_hackerone_scope_csv(path)

    assert document.headers == HACKERONE_CSV_HEADERS
    assert len(document.rows) == 1
    assert document.rows[0].instruction == instruction
    assert document.rows[0].row_number == 1


@pytest.mark.parametrize("change", ("missing", "extra", "reordered"))
def test_header_contract_fails_closed(change: str, tmp_path: Path) -> None:
    headers = list(HACKERONE_CSV_HEADERS)
    if change == "missing":
        headers.pop()
    elif change == "extra":
        headers.append("unexpected")
    else:
        headers[0], headers[1] = headers[1], headers[0]

    path = _write_csv(tmp_path, (_row(),), headers=tuple(headers))

    with pytest.raises(ValueError, match="header"):
        load_hackerone_scope_csv(path)


@pytest.mark.parametrize("field", ("eligible_for_bounty", "eligible_for_submission"))
@pytest.mark.parametrize("value", ("True", "FALSE", "1", "yes", ""))
def test_eligibility_booleans_are_strict(
    field: str,
    value: str,
    tmp_path: Path,
) -> None:
    path = _write_csv(tmp_path, (_row(**{field: value}),))

    with pytest.raises(ValueError, match=field):
        load_hackerone_scope_csv(path)


@pytest.mark.parametrize(
    ("submission", "bounty", "expected_action"),
    (
        ("true", "true", ACTION_INCLUDE),
        ("true", "false", ACTION_INCLUDE),
        ("false", "true", ACTION_EXCLUDE),
        ("false", "false", ACTION_EXCLUDE),
    ),
)
def test_submission_sets_only_proposed_disposition_and_bounty_is_metadata(
    submission: str,
    bounty: str,
    expected_action: str,
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(
            eligible_for_submission=submission,
            eligible_for_bounty=bounty,
        ),
    )

    assert result.outcomes[0].category == CATEGORY_EXECUTABLE
    assert result.outcomes[0].proposed_action == expected_action
    assert result.proposal.rules[0].action == expected_action
    metadata = "\n".join(
        item.value for item in result.proposal.non_authority_context
    )
    assert f"eligible_for_bounty={bounty}" in metadata
    assert f"eligible_for_submission={submission}" in metadata


def test_proper_canonical_wildcard_maps_without_changing_semantics(
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(identifier="*.example.test", asset_type=ASSET_WILDCARD),
    )

    rule = result.proposal.rules[0]
    assert rule.kind == RULE_WILDCARD_SUBDOMAIN
    assert rule.canonical_value == "*.example.test"
    assert result.outcomes[0].reason == REASON_CANONICAL_WILDCARD


@pytest.mark.parametrize("identifier", ("example.test", "*example.test", "*.Example.TEST"))
def test_malformed_or_noncanonical_wildcard_is_unresolved(
    identifier: str,
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(identifier=identifier, asset_type=ASSET_WILDCARD),
    )

    assert result.proposal.rules == ()
    assert result.outcomes[0].category == CATEGORY_UNRESOLVED
    assert result.outcomes[0].reason == REASON_MALFORMED_WILDCARD


def test_canonical_absolute_url_maps_only_to_exact_http_url(tmp_path: Path) -> None:
    result = _build(
        tmp_path,
        _row(identifier="https://example.test/service?part=1", asset_type=ASSET_URL),
    )

    rule = result.proposal.rules[0]
    assert rule.kind == RULE_EXACT_HTTP_URL
    assert rule.canonical_value == "https://example.test/service?part=1"
    assert result.outcomes[0].reason == REASON_CANONICAL_HTTP_URL


@pytest.mark.parametrize(
    ("identifier", "reason"),
    (
        ("example.test", REASON_AMBIGUOUS_BARE_HOSTNAME),
        ("example.test/service", REASON_AMBIGUOUS_SCHEMELESS_URL),
        ("*.example.test", REASON_URL_ASSET_WILDCARD_MISMATCH),
        ("not a URL", REASON_UNSUPPORTED_URL_IDENTIFIER),
    ),
)
def test_ambiguous_url_shapes_never_gain_hostname_or_inferred_scheme_authority(
    identifier: str,
    reason: str,
    tmp_path: Path,
) -> None:
    result = _build(tmp_path, _row(identifier=identifier, asset_type=ASSET_URL))

    assert result.proposal.rules == ()
    assert result.outcomes[0].category == CATEGORY_UNRESOLVED
    assert result.outcomes[0].reason == reason


@pytest.mark.parametrize(
    ("identifier", "category", "reason"),
    (
        ("https://api.example.test/v1", CATEGORY_EXECUTABLE, REASON_CANONICAL_HTTP_URL),
        ("api.example.test", CATEGORY_UNRESOLVED, REASON_AMBIGUOUS_BARE_HOSTNAME),
        (
            "api.example.test/v1",
            CATEGORY_UNRESOLVED,
            REASON_AMBIGUOUS_SCHEMELESS_URL,
        ),
    ),
)
def test_api_mapping_is_conservative(
    identifier: str,
    category: str,
    reason: str,
    tmp_path: Path,
) -> None:
    result = _build(tmp_path, _row(identifier=identifier, asset_type=ASSET_API))

    assert result.outcomes[0].category == category
    assert result.outcomes[0].reason == reason
    assert bool(result.proposal.rules) is (category == CATEGORY_EXECUTABLE)


@pytest.mark.parametrize(
    ("asset_type", "identifier"),
    (
        (ASSET_SOURCE_CODE, "https://code.example.test/team/repository"),
        (ASSET_DOWNLOADABLE_EXECUTABLES, "example.test"),
        (ASSET_HARDWARE, "example.test"),
        (ASSET_APPLE_STORE_APP_ID, "123456789"),
        (ASSET_GOOGLE_PLAY_APP_ID, "com.example.app"),
        (ASSET_WINDOWS_APP_STORE_APP_ID, "example.test"),
    ),
)
def test_non_web_asset_types_never_become_web_authority(
    asset_type: str,
    identifier: str,
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(identifier=identifier, asset_type=asset_type),
    )

    assert result.proposal.rules == ()
    assert result.proposal.unresolved_items == ()
    assert result.outcomes[0].category == CATEGORY_NON_AUTHORITY
    assert result.outcomes[0].reason == REASON_NON_WEB_ASSET_TYPE


@pytest.mark.parametrize(
    ("asset_type", "reason"),
    (
        (ASSET_OTHER, REASON_AMBIGUOUS_OTHER_ASSET),
        ("FUTURE_ASSET", REASON_UNSUPPORTED_ASSET_TYPE),
    ),
)
def test_other_and_unknown_url_looking_assets_are_explicitly_unresolved(
    asset_type: str,
    reason: str,
    tmp_path: Path,
) -> None:
    result = _build(
        tmp_path,
        _row(identifier="https://example.test/service", asset_type=asset_type),
    )

    assert result.proposal.rules == ()
    assert len(result.proposal.unresolved_items) == 1
    assert result.outcomes[0].category == CATEGORY_UNRESOLVED
    assert result.outcomes[0].reason == reason


@pytest.mark.parametrize("asset_type", (ASSET_WILDCARD, ASSET_URL, ASSET_API))
def test_instruction_blocks_otherwise_executable_row_without_exposing_body(
    asset_type: str,
    tmp_path: Path,
) -> None:
    identifier = (
        "*.example.test"
        if asset_type == ASSET_WILDCARD
        else "https://example.test/service"
    )
    instruction = "private instruction sentinel, with detail\nand another line"
    result = _build(
        tmp_path,
        _row(identifier=identifier, asset_type=asset_type, instruction=instruction),
    )

    assert result.document.rows[0].instruction == instruction
    assert result.proposal.rules == ()
    assert result.outcomes[0].reason == REASON_INSTRUCTION_REVIEW_REQUIRED
    assert result.outcomes[0].instruction_present is True
    rendered = render_programme_scope_proposal_review(result.proposal)
    assert "instruction review required" in rendered.lower()
    assert instruction not in rendered
    assert "instruction_present=true" in rendered


def test_blank_identifier_fails_before_any_row_can_disappear(tmp_path: Path) -> None:
    path = _write_csv(tmp_path, (_row(identifier="   "),))

    with pytest.raises(ValueError, match="identifier"):
        build_hackerone_programme_scope_proposal(path)


def test_malformed_quote_fails_before_proposal_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "malformed.csv"
    path.write_text(
        ",".join(HACKERONE_CSV_HEADERS) + '\n"unterminated',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        hackerone_module,
        "build_programme_scope_proposal",
        lambda **_kwargs: pytest.fail("malformed CSV must not create a proposal"),
    )

    with pytest.raises(ValueError, match="CSV"):
        build_hackerone_programme_scope_proposal(path)


def test_source_hash_identity_row_order_and_rule_ids_are_deterministic(
    tmp_path: Path,
) -> None:
    path = _write_csv(
        tmp_path,
        (
            _row(identifier="https://example.test/one"),
            _row(identifier="*.example.test", asset_type=ASSET_WILDCARD),
            _row(identifier="https://example.test/one"),
        ),
        name="review-scope.csv",
    )

    first = build_hackerone_programme_scope_proposal(path)
    second = build_hackerone_programme_scope_proposal(path)
    expected_sha = hashlib.sha256(path.read_bytes()).hexdigest()

    assert first == second
    assert first.document.source_sha256 == expected_sha
    assert first.proposal.source.source_type == HACKERONE_PROPOSAL_SOURCE_TYPE
    assert first.proposal.source.source_id == f"hackerone-csv-{expected_sha}"
    assert "review-scope.csv" in first.proposal.source.display_name
    assert expected_sha in first.proposal.source.display_name
    assert tuple(row.row_number for row in first.document.rows) == (1, 2, 3)
    assert len({row.row_id for row in first.document.rows}) == 3
    assert len({rule.rule_id for rule in first.proposal.rules}) == 3
    assert tuple(rule.rule_id for rule in first.proposal.rules) == tuple(
        sorted(rule.rule_id for rule in first.proposal.rules)
    )


def test_parser_rejects_non_regular_or_symlink_input(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular local file"):
        load_hackerone_scope_csv(tmp_path)

    target = _write_csv(tmp_path, (_row(),), name="target.csv")
    link = tmp_path / "link.csv"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="regular local file"):
        load_hackerone_scope_csv(link)


def test_parser_rejects_invalid_utf8_and_oversized_input(tmp_path: Path) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.csv"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="UTF-8"):
        load_hackerone_scope_csv(invalid_utf8)

    oversized = tmp_path / "oversized.csv"
    with oversized.open("wb") as handle:
        handle.truncate(MAX_HACKERONE_CSV_BYTES + 1)
    with pytest.raises(ValueError, match="file-size limit"):
        load_hackerone_scope_csv(oversized)


def test_adapter_is_pure_and_result_satisfies_p1_invariants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_csv(
        tmp_path,
        (
            _row(identifier="https://example.test/include"),
            _row(identifier="example.test", eligible_for_bounty="false"),
            _row(identifier="com.example.app", asset_type=ASSET_GOOGLE_PLAY_APP_ID),
        ),
    )
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("CSV adapter must not use network"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("CSV adapter must not run subprocesses"),
    )

    result = build_hackerone_programme_scope_proposal(path)

    assert isinstance(result.proposal, ProgrammeScopeProposal)
    assert len(result.document.rows) == len(result.outcomes) == 3
    assert tuple(outcome.category for outcome in result.outcomes) == (
        CATEGORY_EXECUTABLE,
        CATEGORY_UNRESOLVED,
        CATEGORY_NON_AUTHORITY,
    )
    assert all(
        isinstance(item, ProgrammeScopeProposalUnresolvedItem)
        for item in result.proposal.unresolved_items
    )
    assert all(
        isinstance(item, ProgrammeScopeNonAuthorityContext)
        for item in result.proposal.non_authority_context
    )
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == before
