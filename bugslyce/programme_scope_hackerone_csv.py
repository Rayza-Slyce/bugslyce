"""Strict, local, non-authoritative HackerOne scope CSV ingestion."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HTTP_URL,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopeRule,
    build_programme_scope_rule,
    canonicalise_hostname,
)
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeNonAuthorityContext,
    ProgrammeScopeProposal,
    ProgrammeScopeProposalUnresolvedItem,
    build_programme_scope_proposal,
    build_programme_scope_proposal_source,
)


HACKERONE_CSV_HEADERS = (
    "identifier",
    "asset_type",
    "instruction",
    "eligible_for_bounty",
    "eligible_for_submission",
    "availability_requirement",
    "confidentiality_requirement",
    "integrity_requirement",
    "max_severity",
    "system_tags",
    "created_at",
    "updated_at",
)

HACKERONE_PROPOSAL_SOURCE_TYPE = "hackerone_csv"

ASSET_URL = "URL"
ASSET_WILDCARD = "WILDCARD"
ASSET_API = "API"
ASSET_SOURCE_CODE = "SOURCE_CODE"
ASSET_DOWNLOADABLE_EXECUTABLES = "DOWNLOADABLE_EXECUTABLES"
ASSET_HARDWARE = "HARDWARE"
ASSET_APPLE_STORE_APP_ID = "APPLE_STORE_APP_ID"
ASSET_GOOGLE_PLAY_APP_ID = "GOOGLE_PLAY_APP_ID"
ASSET_WINDOWS_APP_STORE_APP_ID = "WINDOWS_APP_STORE_APP_ID"
ASSET_OTHER = "OTHER"

CATEGORY_EXECUTABLE = "executable_proposal_rule"
CATEGORY_UNRESOLVED = "unresolved"
CATEGORY_NON_AUTHORITY = "non_authority_context"

REASON_CANONICAL_WILDCARD = "canonical_wildcard"
REASON_CANONICAL_HTTP_URL = "canonical_http_url"
REASON_INSTRUCTION_REVIEW_REQUIRED = "instruction_review_required"
REASON_MALFORMED_WILDCARD = "malformed_or_noncanonical_wildcard"
REASON_AMBIGUOUS_BARE_HOSTNAME = "ambiguous_bare_hostname"
REASON_AMBIGUOUS_SCHEMELESS_URL = "ambiguous_schemeless_url"
REASON_URL_ASSET_WILDCARD_MISMATCH = "url_asset_wildcard_mismatch"
REASON_NONCANONICAL_HTTP_URL = "noncanonical_http_url"
REASON_UNSUPPORTED_URL_IDENTIFIER = "unsupported_url_identifier"
REASON_UNSUPPORTED_API_IDENTIFIER = "unsupported_api_identifier"
REASON_NON_WEB_ASSET_TYPE = "non_web_asset_type"
REASON_AMBIGUOUS_OTHER_ASSET = "ambiguous_other_asset"
REASON_UNSUPPORTED_ASSET_TYPE = "unsupported_asset_type"

MAX_HACKERONE_CSV_BYTES = 4 * 1024 * 1024
MAX_HACKERONE_CSV_ROWS = 10_000
MAX_HACKERONE_CSV_FIELD_CHARS = 64 * 1024

_NON_WEB_ASSET_TYPES = frozenset(
    {
        ASSET_SOURCE_CODE,
        ASSET_DOWNLOADABLE_EXECUTABLES,
        ASSET_HARDWARE,
        ASSET_APPLE_STORE_APP_ID,
        ASSET_GOOGLE_PLAY_APP_ID,
        ASSET_WINDOWS_APP_STORE_APP_ID,
    }
)
_ASSET_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ROW_CATEGORIES = frozenset(
    {CATEGORY_EXECUTABLE, CATEGORY_UNRESOLVED, CATEGORY_NON_AUTHORITY}
)


@dataclass(frozen=True)
class HackerOneScopeCsvRow:
    """One exact logical CSV record with typed eligibility booleans."""

    row_number: int
    row_id: str
    identifier: str
    asset_type: str
    instruction: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    availability_requirement: str
    confidentiality_requirement: str
    integrity_requirement: str
    max_severity: str
    system_tags: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.row_number, bool)
            or not isinstance(self.row_number, int)
            or self.row_number < 1
        ):
            raise ValueError("HackerOne CSV row number is invalid.")
        if not isinstance(self.row_id, str) or not self.row_id:
            raise ValueError("HackerOne CSV row identity is invalid.")
        if (
            not isinstance(self.identifier, str)
            or not self.identifier.strip()
            or "\n" in self.identifier
            or "\r" in self.identifier
        ):
            raise ValueError("HackerOne CSV identifier is invalid.")
        if not isinstance(self.asset_type, str) or _ASSET_TYPE.fullmatch(
            self.asset_type
        ) is None:
            raise ValueError("HackerOne CSV asset_type is invalid.")
        for label, value in self._text_fields():
            _validate_csv_field(value, label=label)
        if not isinstance(self.eligible_for_bounty, bool) or not isinstance(
            self.eligible_for_submission,
            bool,
        ):
            raise ValueError("HackerOne CSV eligibility values must be boolean.")

    @property
    def instruction_present(self) -> bool:
        return bool(self.instruction.strip())

    def _text_fields(self) -> tuple[tuple[str, str], ...]:
        return (
            ("identifier", self.identifier),
            ("instruction", self.instruction),
            ("availability_requirement", self.availability_requirement),
            ("confidentiality_requirement", self.confidentiality_requirement),
            ("integrity_requirement", self.integrity_requirement),
            ("max_severity", self.max_severity),
            ("system_tags", self.system_tags),
            ("created_at", self.created_at),
            ("updated_at", self.updated_at),
        )


@dataclass(frozen=True)
class HackerOneScopeCsvDocument:
    """One bounded local HackerOne CSV decoded without changing source data."""

    source_filename: str
    source_sha256: str
    headers: tuple[str, ...]
    rows: tuple[HackerOneScopeCsvRow, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_filename, str)
            or not self.source_filename
            or self.source_filename != self.source_filename.strip()
            or not self.source_filename.isprintable()
        ):
            raise ValueError("HackerOne CSV source filename is invalid.")
        if not isinstance(self.source_sha256, str) or _SHA256.fullmatch(
            self.source_sha256
        ) is None:
            raise ValueError("HackerOne CSV source SHA-256 is invalid.")
        if self.headers != HACKERONE_CSV_HEADERS:
            raise ValueError("HackerOne CSV header contract is invalid.")
        if not isinstance(self.rows, tuple) or any(
            not isinstance(row, HackerOneScopeCsvRow) for row in self.rows
        ):
            raise ValueError("HackerOne CSV rows are invalid.")
        if tuple(row.row_number for row in self.rows) != tuple(
            range(1, len(self.rows) + 1)
        ):
            raise ValueError("HackerOne CSV rows are not in source-record order.")
        row_ids = tuple(row.row_id for row in self.rows)
        if len(row_ids) != len(set(row_ids)):
            raise ValueError("HackerOne CSV row identities must be unique.")


@dataclass(frozen=True)
class HackerOneScopeRowOutcome:
    """Explicit non-authoritative classification of one source record."""

    row_number: int
    row_id: str
    category: str
    reason: str
    proposed_action: str
    instruction_present: bool
    rule_id: str | None
    unresolved_item_id: str | None
    context_item_id: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.row_number, bool)
            or not isinstance(self.row_number, int)
            or self.row_number < 1
        ):
            raise ValueError("HackerOne row outcome number is invalid.")
        if not all(
            isinstance(value, str) and value
            for value in (
                self.row_id,
                self.reason,
                self.proposed_action,
                self.context_item_id,
            )
        ):
            raise ValueError("HackerOne row outcome identity is invalid.")
        if self.category not in _ROW_CATEGORIES:
            raise ValueError("HackerOne row outcome category is invalid.")
        if self.proposed_action not in {ACTION_INCLUDE, ACTION_EXCLUDE}:
            raise ValueError("HackerOne row proposed action is invalid.")
        if not isinstance(self.instruction_present, bool):
            raise ValueError("HackerOne row instruction state is invalid.")
        if self.category == CATEGORY_EXECUTABLE:
            if not self.rule_id or self.unresolved_item_id is not None:
                raise ValueError("Executable HackerOne row outcome shape is invalid.")
        elif self.category == CATEGORY_UNRESOLVED:
            if self.rule_id is not None or not self.unresolved_item_id:
                raise ValueError("Unresolved HackerOne row outcome shape is invalid.")
        elif self.rule_id is not None or self.unresolved_item_id is not None:
            raise ValueError("Non-authority HackerOne row outcome shape is invalid.")


@dataclass(frozen=True)
class HackerOneProgrammeScopeProposalResult:
    """Parsed source, explicit classifications and the P1 review proposal."""

    document: HackerOneScopeCsvDocument
    outcomes: tuple[HackerOneScopeRowOutcome, ...]
    proposal: ProgrammeScopeProposal

    def __post_init__(self) -> None:
        if not isinstance(self.document, HackerOneScopeCsvDocument):
            raise ValueError("HackerOne proposal result document is invalid.")
        if not isinstance(self.outcomes, tuple) or any(
            not isinstance(outcome, HackerOneScopeRowOutcome)
            for outcome in self.outcomes
        ):
            raise ValueError("HackerOne proposal row outcomes are invalid.")
        if not isinstance(self.proposal, ProgrammeScopeProposal):
            raise ValueError("HackerOne proposal result is invalid.")
        if tuple(outcome.row_id for outcome in self.outcomes) != tuple(
            row.row_id for row in self.document.rows
        ):
            raise ValueError("Every HackerOne CSV row requires one ordered outcome.")
        expected_source_id = f"hackerone-csv-{self.document.source_sha256}"
        if (
            self.proposal.source.source_type != HACKERONE_PROPOSAL_SOURCE_TYPE
            or self.proposal.source.source_id != expected_source_id
        ):
            raise ValueError("HackerOne proposal source identity is inconsistent.")
        rule_ids = {rule.rule_id for rule in self.proposal.rules}
        outcome_rule_ids = {
            outcome.rule_id
            for outcome in self.outcomes
            if outcome.category == CATEGORY_EXECUTABLE
        }
        if rule_ids != outcome_rule_ids:
            raise ValueError("HackerOne executable row outcomes are inconsistent.")
        unresolved_ids = {item.item_id for item in self.proposal.unresolved_items}
        outcome_unresolved_ids = {
            outcome.unresolved_item_id
            for outcome in self.outcomes
            if outcome.category == CATEGORY_UNRESOLVED
        }
        if unresolved_ids != outcome_unresolved_ids:
            raise ValueError("HackerOne unresolved row outcomes are inconsistent.")
        context_ids = {item.item_id for item in self.proposal.non_authority_context}
        if context_ids != {outcome.context_item_id for outcome in self.outcomes}:
            raise ValueError("HackerOne row metadata context is inconsistent.")


def load_hackerone_scope_csv(path: Path) -> HackerOneScopeCsvDocument:
    """Strictly parse one bounded local HackerOne CSV without side effects."""

    if not isinstance(path, Path):
        raise ValueError("HackerOne CSV path must be a local path.")
    content = _read_regular_local_file(path)
    digest = hashlib.sha256(content).hexdigest()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("HackerOne CSV must be valid UTF-8.") from None
    rows = _parse_csv_rows(text)
    return HackerOneScopeCsvDocument(
        source_filename=path.name,
        source_sha256=digest,
        headers=HACKERONE_CSV_HEADERS,
        rows=rows,
    )


def build_hackerone_programme_scope_proposal(
    path: Path,
) -> HackerOneProgrammeScopeProposalResult:
    """Classify every source row and build a proposal that is not authority."""

    document = load_hackerone_scope_csv(path)
    rules: list[ProgrammeScopeRule] = []
    unresolved: list[ProgrammeScopeProposalUnresolvedItem] = []
    context: list[ProgrammeScopeNonAuthorityContext] = []
    outcomes: list[HackerOneScopeRowOutcome] = []

    for row in document.rows:
        classification = _classify_row(row, source_sha256=document.source_sha256)
        if classification.rule is not None:
            rules.append(classification.rule)
        if classification.unresolved_item is not None:
            unresolved.append(classification.unresolved_item)
        context.append(classification.context_item)
        outcomes.append(classification.outcome)

    source = build_programme_scope_proposal_source(
        source_type=HACKERONE_PROPOSAL_SOURCE_TYPE,
        source_id=f"hackerone-csv-{document.source_sha256}",
        display_name=(
            f"HackerOne CSV: {document.source_filename} "
            f"(SHA-256: {document.source_sha256})"
        ),
    )
    proposal = build_programme_scope_proposal(
        source=source,
        rules=rules,
        unresolved_items=unresolved,
        non_authority_context=context,
    )
    return HackerOneProgrammeScopeProposalResult(
        document=document,
        outcomes=tuple(outcomes),
        proposal=proposal,
    )


@dataclass(frozen=True)
class _RowClassification:
    rule: ProgrammeScopeRule | None
    unresolved_item: ProgrammeScopeProposalUnresolvedItem | None
    context_item: ProgrammeScopeNonAuthorityContext
    outcome: HackerOneScopeRowOutcome


def _classify_row(
    row: HackerOneScopeCsvRow,
    *,
    source_sha256: str,
) -> _RowClassification:
    action = ACTION_INCLUDE if row.eligible_for_submission else ACTION_EXCLUDE
    rule: ProgrammeScopeRule | None = None
    category: str
    reason: str

    if row.asset_type == ASSET_WILDCARD:
        rule = _canonical_rule(
            row,
            source_sha256=source_sha256,
            action=action,
            kind=RULE_WILDCARD_SUBDOMAIN,
        )
        if rule is None or rule.canonical_value != row.identifier:
            rule = None
            category = CATEGORY_UNRESOLVED
            reason = REASON_MALFORMED_WILDCARD
        elif row.instruction_present:
            rule = None
            category = CATEGORY_UNRESOLVED
            reason = REASON_INSTRUCTION_REVIEW_REQUIRED
        else:
            category = CATEGORY_EXECUTABLE
            reason = REASON_CANONICAL_WILDCARD
    elif row.asset_type in {ASSET_URL, ASSET_API}:
        rule = _canonical_rule(
            row,
            source_sha256=source_sha256,
            action=action,
            kind=RULE_EXACT_HTTP_URL,
        )
        if rule is not None and rule.canonical_value == row.identifier:
            if row.instruction_present:
                rule = None
                category = CATEGORY_UNRESOLVED
                reason = REASON_INSTRUCTION_REVIEW_REQUIRED
            else:
                category = CATEGORY_EXECUTABLE
                reason = REASON_CANONICAL_HTTP_URL
        else:
            rule = None
            category = CATEGORY_UNRESOLVED
            reason = _web_identifier_reason(row)
    elif row.asset_type in _NON_WEB_ASSET_TYPES:
        category = CATEGORY_NON_AUTHORITY
        reason = REASON_NON_WEB_ASSET_TYPE
    elif row.asset_type == ASSET_OTHER:
        category = CATEGORY_UNRESOLVED
        reason = REASON_AMBIGUOUS_OTHER_ASSET
    else:
        category = CATEGORY_UNRESOLVED
        reason = REASON_UNSUPPORTED_ASSET_TYPE

    unresolved_item = (
        _unresolved_item(row, reason=reason, action=action)
        if category == CATEGORY_UNRESOLVED
        else None
    )
    context_item = _context_item(row, category=category, action=action)
    outcome = HackerOneScopeRowOutcome(
        row_number=row.row_number,
        row_id=row.row_id,
        category=category,
        reason=reason,
        proposed_action=action,
        instruction_present=row.instruction_present,
        rule_id=None if rule is None else rule.rule_id,
        unresolved_item_id=(
            None if unresolved_item is None else unresolved_item.item_id
        ),
        context_item_id=context_item.item_id,
    )
    return _RowClassification(
        rule=rule,
        unresolved_item=unresolved_item,
        context_item=context_item,
        outcome=outcome,
    )


def _canonical_rule(
    row: HackerOneScopeCsvRow,
    *,
    source_sha256: str,
    action: str,
    kind: str,
) -> ProgrammeScopeRule | None:
    rule_id = _semantic_id(
        "h1-rule",
        row,
        source_sha256,
        action,
        kind,
    )
    try:
        return build_programme_scope_rule(
            rule_id=rule_id,
            action=action,
            kind=kind,
            value=row.identifier,
        )
    except ValueError:
        return None


def _web_identifier_reason(row: HackerOneScopeCsvRow) -> str:
    identifier = row.identifier
    if row.asset_type == ASSET_URL and identifier.startswith("*."):
        return REASON_URL_ASSET_WILDCARD_MISMATCH
    if _is_hostname(identifier):
        return REASON_AMBIGUOUS_BARE_HOSTNAME
    if "://" not in identifier and "/" in identifier:
        return REASON_AMBIGUOUS_SCHEMELESS_URL
    if _canonicalizable_http_url(identifier):
        return REASON_NONCANONICAL_HTTP_URL
    return (
        REASON_UNSUPPORTED_API_IDENTIFIER
        if row.asset_type == ASSET_API
        else REASON_UNSUPPORTED_URL_IDENTIFIER
    )


def _is_hostname(value: str) -> bool:
    try:
        canonicalise_hostname(value)
    except ValueError:
        return False
    return True


def _canonicalizable_http_url(value: str) -> bool:
    try:
        build_programme_scope_rule(
            rule_id="h1-url-shape",
            action=ACTION_INCLUDE,
            kind=RULE_EXACT_HTTP_URL,
            value=value,
        )
    except ValueError:
        return False
    return True


def _unresolved_item(
    row: HackerOneScopeCsvRow,
    *,
    reason: str,
    action: str,
) -> ProgrammeScopeProposalUnresolvedItem:
    description = (
        f"HackerOne row {row.row_number} | {row.asset_type} | "
        f"{_identifier_preview(row.identifier)} | {_reason_text(reason)} | "
        f"proposed disposition: {action}"
    )
    return ProgrammeScopeProposalUnresolvedItem(
        item_id=_semantic_id("h1-unresolved", row),
        description=description,
    )


def _context_item(
    row: HackerOneScopeCsvRow,
    *,
    category: str,
    action: str,
) -> ProgrammeScopeNonAuthorityContext:
    label = (
        "HackerOne non-authority asset"
        if category == CATEGORY_NON_AUTHORITY
        else "HackerOne row metadata"
    )
    value = "; ".join(
        (
            f"row={row.row_number}",
            f"asset_type={row.asset_type}",
            f"identifier={_identifier_preview(row.identifier)}",
            f"eligible_for_bounty={_boolean_text(row.eligible_for_bounty)}",
            f"eligible_for_submission={_boolean_text(row.eligible_for_submission)}",
            f"proposed_disposition={action}",
            f"instruction_present={_boolean_text(row.instruction_present)}",
        )
    )
    return ProgrammeScopeNonAuthorityContext(
        item_id=_semantic_id("h1-context", row),
        label=label,
        value=value,
    )


def _reason_text(reason: str) -> str:
    return {
        REASON_INSTRUCTION_REVIEW_REQUIRED: (
            "instruction review required before proposing authority"
        ),
        REASON_MALFORMED_WILDCARD: "wildcard is malformed or noncanonical",
        REASON_AMBIGUOUS_BARE_HOSTNAME: (
            "bare hostname does not establish URL scheme, port or path authority"
        ),
        REASON_AMBIGUOUS_SCHEMELESS_URL: (
            "scheme-less URL does not establish HTTP authority"
        ),
        REASON_URL_ASSET_WILDCARD_MISMATCH: (
            "URL asset uses wildcard syntax and requires source-type review"
        ),
        REASON_NONCANONICAL_HTTP_URL: (
            "HTTP URL is not in canonical exact form"
        ),
        REASON_UNSUPPORTED_URL_IDENTIFIER: "URL identifier is unsupported",
        REASON_UNSUPPORTED_API_IDENTIFIER: "API identifier is unsupported",
        REASON_AMBIGUOUS_OTHER_ASSET: "OTHER asset requires operator resolution",
        REASON_UNSUPPORTED_ASSET_TYPE: "asset type is unsupported",
    }[reason]


def _parse_csv_rows(text: str) -> tuple[HackerOneScopeCsvRow, ...]:
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader)
    except StopIteration:
        raise ValueError("HackerOne CSV is empty.") from None
    except csv.Error:
        raise ValueError("HackerOne CSV is malformed.") from None
    if tuple(header) != HACKERONE_CSV_HEADERS:
        raise ValueError("HackerOne CSV header must match the exact ordered schema.")

    rows: list[HackerOneScopeCsvRow] = []
    try:
        for record in reader:
            if len(rows) >= MAX_HACKERONE_CSV_ROWS:
                raise ValueError("HackerOne CSV exceeds the row limit.")
            if len(record) != len(HACKERONE_CSV_HEADERS):
                raise ValueError("HackerOne CSV row does not match the header schema.")
            rows.append(_build_row(len(rows) + 1, tuple(record)))
    except csv.Error:
        raise ValueError("HackerOne CSV is malformed.") from None
    return tuple(rows)


def _build_row(row_number: int, values: tuple[str, ...]) -> HackerOneScopeCsvRow:
    for header, value in zip(HACKERONE_CSV_HEADERS, values, strict=True):
        _validate_csv_field(value, label=header)
    identifier, asset_type, instruction, bounty, submission, *remaining = values
    if not identifier.strip() or "\n" in identifier or "\r" in identifier:
        raise ValueError(f"HackerOne CSV row {row_number} identifier is invalid.")
    if _ASSET_TYPE.fullmatch(asset_type) is None:
        raise ValueError(f"HackerOne CSV row {row_number} asset_type is invalid.")
    return HackerOneScopeCsvRow(
        row_number=row_number,
        row_id=_row_id(row_number, values),
        identifier=identifier,
        asset_type=asset_type,
        instruction=instruction,
        eligible_for_bounty=_parse_boolean(
            bounty,
            field="eligible_for_bounty",
            row_number=row_number,
        ),
        eligible_for_submission=_parse_boolean(
            submission,
            field="eligible_for_submission",
            row_number=row_number,
        ),
        availability_requirement=remaining[0],
        confidentiality_requirement=remaining[1],
        integrity_requirement=remaining[2],
        max_severity=remaining[3],
        system_tags=remaining[4],
        created_at=remaining[5],
        updated_at=remaining[6],
    )


def _read_regular_local_file(path: Path) -> bytes:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("HackerOne CSV must be a regular local file.")
        if metadata.st_size > MAX_HACKERONE_CSV_BYTES:
            raise ValueError("HackerOne CSV exceeds the file-size limit.")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            content = handle.read(MAX_HACKERONE_CSV_BYTES + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError("HackerOne CSV must be a readable regular local file.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(content) > MAX_HACKERONE_CSV_BYTES:
        raise ValueError("HackerOne CSV exceeds the file-size limit.")
    return content


def _parse_boolean(value: str, *, field: str, row_number: int) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(
        f"HackerOne CSV row {row_number} {field} must be exactly true or false."
    )


def _validate_csv_field(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_HACKERONE_CSV_FIELD_CHARS
        or "\x00" in value
    ):
        raise ValueError(f"HackerOne CSV {label} field is invalid.")
    return value


def _row_id(row_number: int, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256(_canonical_json(values).encode("utf-8")).hexdigest()[:20]
    return f"h1-row-{row_number:06d}-{digest}"


def _semantic_id(prefix: str, row: HackerOneScopeCsvRow, *values: str) -> str:
    material = (row.row_id, *values)
    digest = hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{row.row_number:06d}-{digest}"


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _identifier_preview(value: str) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) <= 160:
        return collapsed
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{collapsed[:140]}... [sha256:{digest}]"


def _boolean_text(value: bool) -> str:
    return "true" if value else "false"
