"""Pure resolution of non-authoritative HackerOne scope proposals."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import re

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
    ASSET_API,
    ASSET_URL,
    ASSET_WILDCARD,
    CATEGORY_EXECUTABLE,
    CATEGORY_NON_AUTHORITY,
    CATEGORY_UNRESOLVED,
    REASON_AMBIGUOUS_BARE_HOSTNAME,
    REASON_AMBIGUOUS_SCHEMELESS_URL,
    REASON_INSTRUCTION_REVIEW_REQUIRED,
    REASON_NONCANONICAL_HTTP_URL,
    HackerOneProgrammeScopeProposalResult,
    HackerOneScopeCsvRow,
    HackerOneScopeRowOutcome,
)
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeNonAuthorityContext,
    ProgrammeScopeProposal,
    build_programme_scope_proposal,
)


ROW_STATE_UNRESOLVED = "unresolved"
ROW_STATE_AUTOMATIC_RULE = "automatic_rule"
ROW_STATE_EXPLICIT_RULE = "explicit_rule"
ROW_STATE_EXPLICIT_NON_AUTHORITY = "explicit_non_authority"
ROW_STATE_TYPED_NON_AUTHORITY = "typed_non_authority"

NON_AUTHORITY_EXPLICIT_INCLUDE = "explicit_include_non_authority"
NON_AUTHORITY_EXPLICIT_NON_WEB = "explicit_non_web_classification"
NON_AUTHORITY_P2A_TYPED = "p2a_typed_non_authority"

_ROW_STATES = frozenset(
    {
        ROW_STATE_UNRESOLVED,
        ROW_STATE_AUTOMATIC_RULE,
        ROW_STATE_EXPLICIT_RULE,
        ROW_STATE_EXPLICIT_NON_AUTHORITY,
        ROW_STATE_TYPED_NON_AUTHORITY,
    }
)
_NON_AUTHORITY_BASES = frozenset(
    {
        NON_AUTHORITY_EXPLICIT_INCLUDE,
        NON_AUTHORITY_EXPLICIT_NON_WEB,
        NON_AUTHORITY_P2A_TYPED,
    }
)
_WEB_ASSET_TYPES = frozenset({ASSET_URL, ASSET_API, ASSET_WILDCARD})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class HackerOneScopeInstructionRequirement:
    """Exact instruction identity requiring separate operator acknowledgement."""

    source_sha256: str
    row_id: str
    instruction_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.source_sha256, label="Instruction source SHA-256")
        _require_text(self.row_id, label="Instruction row identity")
        _require_sha256(
            self.instruction_sha256,
            label="Instruction digest",
        )


@dataclass(frozen=True)
class HackerOneScopeResolutionGroup:
    """Deterministic navigation group that grants no authority."""

    group_id: str
    reason: str
    asset_type: str
    proposed_action: str
    instruction_present: bool
    row_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.group_id, label="HackerOne resolution group ID")
        _require_text(self.reason, label="HackerOne resolution group reason")
        _require_text(self.asset_type, label="HackerOne resolution asset type")
        if self.proposed_action not in {ACTION_INCLUDE, ACTION_EXCLUDE}:
            raise ValueError("HackerOne resolution group action is invalid.")
        if not isinstance(self.instruction_present, bool):
            raise ValueError("HackerOne resolution instruction state is invalid.")
        if (
            not isinstance(self.row_ids, tuple)
            or not self.row_ids
            or any(not isinstance(row_id, str) or not row_id for row_id in self.row_ids)
            or len(self.row_ids) != len(set(self.row_ids))
        ):
            raise ValueError("HackerOne resolution group rows are invalid.")


@dataclass(frozen=True)
class HackerOneScopeRowResolution:
    """One immutable source-row resolution and orthogonal instruction state."""

    row_number: int
    row_id: str
    source_category: str
    reason: str
    asset_type: str
    proposed_action: str
    instruction_sha256: str | None
    instruction_acknowledgement: HackerOneScopeInstructionRequirement | None
    state: str
    rules: tuple[ProgrammeScopeRule, ...]
    non_authority_basis: str | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.row_number, bool)
            or not isinstance(self.row_number, int)
            or self.row_number < 1
        ):
            raise ValueError("HackerOne resolution row number is invalid.")
        for label, value in (
            ("row identity", self.row_id),
            ("reason", self.reason),
            ("asset type", self.asset_type),
        ):
            _require_text(value, label=f"HackerOne resolution {label}")
        if self.source_category not in {
            CATEGORY_EXECUTABLE,
            CATEGORY_UNRESOLVED,
            CATEGORY_NON_AUTHORITY,
        }:
            raise ValueError("HackerOne resolution source category is invalid.")
        if self.proposed_action not in {ACTION_INCLUDE, ACTION_EXCLUDE}:
            raise ValueError("HackerOne resolution proposed action is invalid.")
        if self.instruction_sha256 is not None:
            _require_sha256(self.instruction_sha256, label="Instruction digest")
        if self.instruction_acknowledgement is not None and not isinstance(
            self.instruction_acknowledgement,
            HackerOneScopeInstructionRequirement,
        ):
            raise ValueError("HackerOne instruction acknowledgement is invalid.")
        if self.instruction_sha256 is None and self.instruction_acknowledgement:
            raise ValueError("A row without an instruction cannot be acknowledged.")
        if self.instruction_acknowledgement is not None and (
            self.instruction_acknowledgement.row_id != self.row_id
            or self.instruction_acknowledgement.instruction_sha256
            != self.instruction_sha256
        ):
            raise ValueError("HackerOne instruction acknowledgement identity is invalid.")
        if self.state not in _ROW_STATES:
            raise ValueError("HackerOne resolution row state is invalid.")
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, ProgrammeScopeRule) for rule in self.rules
        ):
            raise ValueError("HackerOne resolution rules must be canonical rules.")
        if len({rule.rule_id.casefold() for rule in self.rules}) != len(self.rules):
            raise ValueError("HackerOne resolution rule IDs must be unique.")
        if any(rule.action != self.proposed_action for rule in self.rules):
            raise ValueError("HackerOne resolution must preserve proposed disposition.")
        if self.state in {ROW_STATE_AUTOMATIC_RULE, ROW_STATE_EXPLICIT_RULE}:
            if len(self.rules) != 1 or self.non_authority_basis is not None:
                raise ValueError("Executable HackerOne resolution shape is invalid.")
            _validate_executable_rule_contract(
                self,
                tuple(rule.kind for rule in self.rules),
            )
        elif self.rules:
            raise ValueError("Non-executable HackerOne resolution cannot contain rules.")
        if self.state in {
            ROW_STATE_EXPLICIT_NON_AUTHORITY,
            ROW_STATE_TYPED_NON_AUTHORITY,
        }:
            if self.non_authority_basis not in _NON_AUTHORITY_BASES:
                raise ValueError("HackerOne non-authority resolution basis is invalid.")
        elif self.non_authority_basis is not None:
            raise ValueError("Unresolved HackerOne row cannot have a resolution basis.")
        if (
            self.state == ROW_STATE_TYPED_NON_AUTHORITY
            and (
                self.source_category != CATEGORY_NON_AUTHORITY
                or self.non_authority_basis != NON_AUTHORITY_P2A_TYPED
            )
        ):
            raise ValueError("Typed HackerOne non-authority state is inconsistent.")
        if (
            self.non_authority_basis == NON_AUTHORITY_EXPLICIT_INCLUDE
            and self.proposed_action != ACTION_INCLUDE
        ):
            raise ValueError("Only a proposed include may use include dismissal.")
        if (
            self.non_authority_basis == NON_AUTHORITY_EXPLICIT_NON_WEB
            and self.asset_type in _WEB_ASSET_TYPES
        ):
            raise ValueError("A web asset cannot be classified as non-web authority.")

    @property
    def instruction_required(self) -> bool:
        return self.instruction_sha256 is not None

    @property
    def instruction_acknowledged(self) -> bool:
        return self.instruction_acknowledgement is not None

    @property
    def terminal(self) -> bool:
        return self.state != ROW_STATE_UNRESOLVED

    @property
    def complete(self) -> bool:
        return self.terminal and (
            not self.instruction_required or self.instruction_acknowledged
        )


@dataclass(frozen=True)
class HackerOneScopeResolutionSession:
    """Complete immutable resolution state for one exact P2A result."""

    source_result: HackerOneProgrammeScopeProposalResult
    resolutions: tuple[HackerOneScopeRowResolution, ...]
    groups: tuple[HackerOneScopeResolutionGroup, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_result, HackerOneProgrammeScopeProposalResult):
            raise ValueError("HackerOne resolution requires an exact P2A result.")
        if not isinstance(self.resolutions, tuple) or any(
            not isinstance(item, HackerOneScopeRowResolution)
            for item in self.resolutions
        ):
            raise ValueError("HackerOne resolution rows are invalid.")
        expected_row_ids = tuple(
            row.row_id for row in self.source_result.document.rows
        )
        actual_row_ids = tuple(item.row_id for item in self.resolutions)
        if actual_row_ids != expected_row_ids or len(actual_row_ids) != len(
            set(actual_row_ids)
        ):
            raise ValueError(
                "Every HackerOne source row must appear exactly once in resolution state."
            )
        for row, outcome, resolution in zip(
            self.source_result.document.rows,
            self.source_result.outcomes,
            self.resolutions,
            strict=True,
        ):
            _validate_resolution_source(row, outcome, resolution)
            if (
                resolution.instruction_acknowledgement is not None
                and resolution.instruction_acknowledgement.source_sha256
                != self.source_result.document.source_sha256
            ):
                raise ValueError(
                    "HackerOne instruction acknowledgement source is inconsistent."
                )
            if resolution.state == ROW_STATE_AUTOMATIC_RULE:
                source_rule = _source_rule(self.source_result, outcome)
                if source_rule is None or resolution.rules != (source_rule,):
                    raise ValueError(
                        "Automatic HackerOne resolution must retain its exact P2A rule."
                    )
        expected_groups = _build_groups(self.source_result)
        if self.groups != expected_groups:
            raise ValueError("HackerOne resolution groups are inconsistent.")

    @property
    def source_sha256(self) -> str:
        return self.source_result.document.source_sha256

    @property
    def instruction_requirements(
        self,
    ) -> tuple[HackerOneScopeInstructionRequirement, ...]:
        return tuple(
            HackerOneScopeInstructionRequirement(
                source_sha256=self.source_sha256,
                row_id=item.row_id,
                instruction_sha256=item.instruction_sha256,
            )
            for item in self.resolutions
            if item.instruction_sha256 is not None
        )


def build_hackerone_scope_resolution_session(
    source_result: HackerOneProgrammeScopeProposalResult,
) -> HackerOneScopeResolutionSession:
    """Build initial pure resolution state without creating new authority."""

    if not isinstance(source_result, HackerOneProgrammeScopeProposalResult):
        raise ValueError("HackerOne resolution requires an exact P2A result.")
    resolutions = tuple(
        _initial_resolution(source_result, row, outcome)
        for row, outcome in zip(
            source_result.document.rows,
            source_result.outcomes,
            strict=True,
        )
    )
    return HackerOneScopeResolutionSession(
        source_result=source_result,
        resolutions=resolutions,
        groups=_build_groups(source_result),
    )


def get_hackerone_scope_resolution(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeRowResolution:
    """Return one exact row resolution or fail closed."""

    _require_session(session)
    for resolution in session.resolutions:
        if resolution.row_id == row_id:
            return resolution
    raise ValueError("HackerOne resolution row does not exist.")


def acknowledge_hackerone_scope_instruction(
    session: HackerOneScopeResolutionSession,
    row_id: str,
    *,
    source_sha256: str,
    instruction_sha256: str,
) -> HackerOneScopeResolutionSession:
    """Acknowledge one exact instruction independently of its rule decision."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    if resolution.instruction_sha256 is None:
        raise ValueError("HackerOne row has no instruction requiring acknowledgement.")
    if source_sha256 != session.source_sha256:
        raise ValueError("HackerOne instruction acknowledgement source is inconsistent.")
    if instruction_sha256 != resolution.instruction_sha256:
        raise ValueError("HackerOne instruction acknowledgement digest is inconsistent.")
    return _replace_resolution(
        session,
        replace(
            resolution,
            instruction_acknowledgement=HackerOneScopeInstructionRequirement(
                source_sha256=source_sha256,
                row_id=row_id,
                instruction_sha256=instruction_sha256,
            ),
        ),
    )


def resolve_hackerone_scope_row_with_rule(
    session: HackerOneScopeResolutionSession,
    row_id: str,
    *,
    kind: str,
    value: str,
    scheme: str | None = None,
    port: int | None = None,
) -> HackerOneScopeResolutionSession:
    """Resolve one row with a fully explicit canonical rule decision."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    _validate_executable_rule_contract(resolution, (kind,))
    rule = _build_explicit_rule(
        session,
        resolution,
        kind=kind,
        value=value,
        scheme=scheme,
        port=port,
    )
    return _replace_resolution(
        session,
        replace(
            resolution,
            state=ROW_STATE_EXPLICIT_RULE,
            rules=(rule,),
            non_authority_basis=None,
        ),
    )


def resolve_hackerone_scope_group_with_source_rule(
    session: HackerOneScopeResolutionSession,
    group_id: str,
    *,
    row_ids: tuple[str, ...],
    kind: str,
    scheme: str | None = None,
    port: int | None = None,
) -> HackerOneScopeResolutionSession:
    """Apply one explicit kind to selected group rows using exact source values."""

    _require_session(session)
    group = _group(session, group_id)
    if (
        not isinstance(row_ids, tuple)
        or not row_ids
        or len(row_ids) != len(set(row_ids))
    ):
        raise ValueError("Selected HackerOne resolution rows are invalid.")
    if not set(row_ids).issubset(group.row_ids):
        raise ValueError("Selected rows do not belong to the HackerOne group.")
    selected = set(row_ids)
    changed = session
    for row in session.source_result.document.rows:
        if row.row_id in selected:
            changed = resolve_hackerone_scope_row_with_rule(
                changed,
                row.row_id,
                kind=kind,
                value=row.identifier,
                scheme=scheme,
                port=port,
            )
    return changed


def resolve_hackerone_scope_include_as_non_authority(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeResolutionSession:
    """Explicitly close one proposed include without creating authority."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    if resolution.proposed_action != ACTION_INCLUDE:
        raise ValueError(
            "A proposed exclude cannot use include non-authority dismissal."
        )
    return _replace_resolution(
        session,
        replace(
            resolution,
            state=ROW_STATE_EXPLICIT_NON_AUTHORITY,
            rules=(),
            non_authority_basis=NON_AUTHORITY_EXPLICIT_INCLUDE,
        ),
    )


def classify_hackerone_scope_row_as_non_web(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeResolutionSession:
    """Deliberately classify an OTHER/unsupported row outside web/IP authority."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    if resolution.asset_type in _WEB_ASSET_TYPES:
        raise ValueError(
            "A web proposed exclude cannot be closed as non-web authority."
        )
    return _replace_resolution(
        session,
        replace(
            resolution,
            state=ROW_STATE_EXPLICIT_NON_AUTHORITY,
            rules=(),
            non_authority_basis=NON_AUTHORITY_EXPLICIT_NON_WEB,
        ),
    )


def reset_hackerone_scope_row(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeResolutionSession:
    """Remove one rule/context decision while retaining valid instruction review."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    return _replace_resolution(
        session,
        replace(
            resolution,
            state=ROW_STATE_UNRESOLVED,
            rules=(),
            non_authority_basis=None,
        ),
    )


def build_hackerone_scope_review_candidate(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> ProgrammeScopeRule | None:
    """Build, but never apply, a canonical candidate already implied by P2A."""

    _require_session(session)
    resolution = get_hackerone_scope_resolution(session, row_id)
    row = _row(session, row_id)
    kind: str | None = None
    if resolution.reason == REASON_NONCANONICAL_HTTP_URL:
        kind = RULE_EXACT_HTTP_URL
    elif resolution.reason == REASON_INSTRUCTION_REVIEW_REQUIRED:
        if resolution.asset_type == ASSET_WILDCARD:
            kind = RULE_WILDCARD_SUBDOMAIN
        elif resolution.asset_type in {ASSET_URL, ASSET_API}:
            kind = RULE_EXACT_HTTP_URL
    if kind is None:
        return None
    return _build_explicit_rule(
        session,
        resolution,
        kind=kind,
        value=row.identifier,
        scheme=None,
        port=None,
    )


def finalize_hackerone_scope_resolution(
    session: HackerOneScopeResolutionSession,
) -> ProgrammeScopeProposal:
    """Create a fully resolved P1 proposal without persistence or authority use."""

    _require_session(session)
    for resolution in session.resolutions:
        if not resolution.terminal:
            raise ValueError(
                "HackerOne scope resolution contains an unresolved source row."
            )
        if resolution.instruction_required and not resolution.instruction_acknowledged:
            raise ValueError(
                "HackerOne scope resolution requires instruction acknowledgement."
            )
        if resolution.proposed_action == ACTION_EXCLUDE and not resolution.rules:
            if not _closed_non_authority_exclusion(resolution):
                raise ValueError(
                    "HackerOne web/recon exclusion lacks canonical exclusion closure."
                )

    rules, retained_ids = _deduplicate_rules(session.resolutions)
    contexts = _resolved_contexts(session, retained_ids)
    return build_programme_scope_proposal(
        source=session.source_result.proposal.source,
        rules=rules,
        unresolved_items=(),
        non_authority_context=contexts,
    )


def _initial_resolution(
    source_result: HackerOneProgrammeScopeProposalResult,
    row: HackerOneScopeCsvRow,
    outcome: HackerOneScopeRowOutcome,
) -> HackerOneScopeRowResolution:
    instruction_sha256 = (
        hashlib.sha256(row.instruction.encode("utf-8")).hexdigest()
        if row.instruction_present
        else None
    )
    rule = _source_rule(source_result, outcome)
    if outcome.category == CATEGORY_EXECUTABLE:
        state = ROW_STATE_AUTOMATIC_RULE
        rules = (rule,) if rule is not None else ()
        basis = None
    elif outcome.category == CATEGORY_NON_AUTHORITY:
        state = ROW_STATE_TYPED_NON_AUTHORITY
        rules = ()
        basis = NON_AUTHORITY_P2A_TYPED
    else:
        state = ROW_STATE_UNRESOLVED
        rules = ()
        basis = None
    return HackerOneScopeRowResolution(
        row_number=row.row_number,
        row_id=row.row_id,
        source_category=outcome.category,
        reason=outcome.reason,
        asset_type=row.asset_type,
        proposed_action=outcome.proposed_action,
        instruction_sha256=instruction_sha256,
        instruction_acknowledgement=None,
        state=state,
        rules=rules,
        non_authority_basis=basis,
    )


def _build_groups(
    source_result: HackerOneProgrammeScopeProposalResult,
) -> tuple[HackerOneScopeResolutionGroup, ...]:
    grouped: dict[tuple[str, str, str, bool], list[HackerOneScopeCsvRow]] = {}
    for row, outcome in zip(
        source_result.document.rows,
        source_result.outcomes,
        strict=True,
    ):
        key = (
            outcome.reason,
            row.asset_type,
            outcome.proposed_action,
            outcome.instruction_present,
        )
        grouped.setdefault(key, []).append(row)
    groups = []
    for key, rows in grouped.items():
        reason, asset_type, action, instruction_present = key
        groups.append(
            HackerOneScopeResolutionGroup(
                group_id=_group_id(source_result.document.source_sha256, key),
                reason=reason,
                asset_type=asset_type,
                proposed_action=action,
                instruction_present=instruction_present,
                row_ids=tuple(
                    row.row_id
                    for row in sorted(rows, key=lambda item: (item.row_number, item.row_id))
                ),
            )
        )
    return tuple(
        sorted(
            groups,
            key=lambda item: (
                item.reason,
                item.asset_type,
                item.proposed_action,
                item.instruction_present,
                item.group_id,
            ),
        )
    )


def _validate_resolution_source(
    row: HackerOneScopeCsvRow,
    outcome: HackerOneScopeRowOutcome,
    resolution: HackerOneScopeRowResolution,
) -> None:
    expected_instruction = (
        hashlib.sha256(row.instruction.encode("utf-8")).hexdigest()
        if row.instruction_present
        else None
    )
    if (
        resolution.row_number != row.row_number
        or resolution.row_id != row.row_id
        or resolution.source_category != outcome.category
        or resolution.reason != outcome.reason
        or resolution.asset_type != row.asset_type
        or resolution.proposed_action != outcome.proposed_action
        or resolution.instruction_sha256 != expected_instruction
    ):
        raise ValueError("HackerOne resolution row is inconsistent with its source.")


def _source_rule(
    source_result: HackerOneProgrammeScopeProposalResult,
    outcome: HackerOneScopeRowOutcome,
) -> ProgrammeScopeRule | None:
    if outcome.rule_id is None:
        return None
    for rule in source_result.proposal.rules:
        if rule.rule_id == outcome.rule_id:
            return rule
    raise ValueError("HackerOne executable outcome rule is missing.")


def _validate_executable_rule_contract(
    resolution: HackerOneScopeRowResolution,
    rule_kinds: tuple[str, ...],
) -> None:
    if resolution.source_category == CATEGORY_NON_AUTHORITY:
        raise ValueError(
            "A P2A typed non-authority asset cannot become executable authority."
        )
    for kind in rule_kinds:
        if (
            resolution.reason == REASON_AMBIGUOUS_BARE_HOSTNAME
            and kind not in {RULE_EXACT_HOSTNAME, RULE_EXACT_HTTP_URL}
        ):
            raise ValueError(
                "An ambiguous bare hostname requires explicit hostname or exact "
                "HTTP URL authority."
            )
        if (
            resolution.reason == REASON_AMBIGUOUS_SCHEMELESS_URL
            and kind != RULE_EXACT_HTTP_URL
        ):
            raise ValueError("A scheme-less URL requires an explicit exact HTTP URL.")
        if (
            resolution.reason == REASON_NONCANONICAL_HTTP_URL
            and kind != RULE_EXACT_HTTP_URL
        ):
            raise ValueError("A noncanonical HTTP URL requires exact HTTP URL review.")


def _build_explicit_rule(
    session: HackerOneScopeResolutionSession,
    resolution: HackerOneScopeRowResolution,
    *,
    kind: str,
    value: str,
    scheme: str | None,
    port: int | None,
) -> ProgrammeScopeRule:
    candidate = build_programme_scope_rule(
        rule_id="h1-resolution-candidate",
        action=resolution.proposed_action,
        kind=kind,
        value=value,
        scheme=scheme,
        port=port,
    )
    rule_id = _resolved_rule_id(session.source_sha256, resolution, candidate)
    return build_programme_scope_rule(
        rule_id=rule_id,
        action=candidate.action,
        kind=candidate.kind,
        value=candidate.canonical_value,
        scheme=candidate.scheme,
        port=candidate.port,
    )


def _resolved_rule_id(
    source_sha256: str,
    resolution: HackerOneScopeRowResolution,
    candidate: ProgrammeScopeRule,
) -> str:
    material = (
        source_sha256,
        resolution.row_id,
        candidate.action,
        candidate.kind,
        candidate.canonical_value,
        candidate.scheme,
        candidate.port,
    )
    digest = hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()[:20]
    return f"h1-resolved-{resolution.row_number:06d}-{digest}"


def _group_id(
    source_sha256: str,
    key: tuple[str, str, str, bool],
) -> str:
    digest = hashlib.sha256(
        _canonical_json((source_sha256, *key)).encode("utf-8")
    ).hexdigest()[:20]
    return f"h1-group-{digest}"


def _replace_resolution(
    session: HackerOneScopeResolutionSession,
    changed: HackerOneScopeRowResolution,
) -> HackerOneScopeResolutionSession:
    if changed.row_id not in {item.row_id for item in session.resolutions}:
        raise ValueError("HackerOne resolution row does not exist.")
    resolutions = tuple(
        changed if item.row_id == changed.row_id else item
        for item in session.resolutions
    )
    return replace(session, resolutions=resolutions)


def _row(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeCsvRow:
    for row in session.source_result.document.rows:
        if row.row_id == row_id:
            return row
    raise ValueError("HackerOne resolution row does not exist.")


def _group(
    session: HackerOneScopeResolutionSession,
    group_id: str,
) -> HackerOneScopeResolutionGroup:
    for group in session.groups:
        if group.group_id == group_id:
            return group
    raise ValueError("HackerOne resolution group does not exist.")


def _closed_non_authority_exclusion(
    resolution: HackerOneScopeRowResolution,
) -> bool:
    if resolution.non_authority_basis == NON_AUTHORITY_P2A_TYPED:
        return resolution.source_category == CATEGORY_NON_AUTHORITY
    if resolution.non_authority_basis == NON_AUTHORITY_EXPLICIT_NON_WEB:
        return resolution.asset_type not in _WEB_ASSET_TYPES
    return False


def _deduplicate_rules(
    resolutions: tuple[HackerOneScopeRowResolution, ...],
) -> tuple[tuple[ProgrammeScopeRule, ...], dict[str, str]]:
    rules = tuple(rule for resolution in resolutions for rule in resolution.rules)
    by_id: dict[str, ProgrammeScopeRule] = {}
    for rule in rules:
        folded = rule.rule_id.casefold()
        current = by_id.get(folded)
        if current is not None and current != rule:
            raise ValueError("HackerOne resolved rule ID collision is conflicting.")
        by_id[folded] = rule

    actions_by_target: dict[tuple[object, ...], set[str]] = {}
    by_semantics: dict[tuple[object, ...], list[ProgrammeScopeRule]] = {}
    for rule in rules:
        target = _rule_target_key(rule)
        actions_by_target.setdefault(target, set()).add(rule.action)
        by_semantics.setdefault((rule.action, *target), []).append(rule)
    if any(len(actions) > 1 for actions in actions_by_target.values()):
        raise ValueError("HackerOne resolved rules contain conflicting semantics.")

    retained: list[ProgrammeScopeRule] = []
    retained_ids: dict[str, str] = {}
    for equivalent in by_semantics.values():
        selected = min(
            equivalent,
            key=lambda item: (item.rule_id.casefold(), item.rule_id),
        )
        retained.append(selected)
        for rule in equivalent:
            retained_ids[rule.rule_id] = selected.rule_id
    retained.sort(key=lambda item: (item.rule_id.casefold(), item.rule_id))
    return tuple(retained), retained_ids


def _rule_target_key(rule: ProgrammeScopeRule) -> tuple[object, ...]:
    return (
        rule.kind,
        rule.canonical_value,
        rule.scheme,
        rule.port,
    )


def _resolved_contexts(
    session: HackerOneScopeResolutionSession,
    retained_ids: dict[str, str],
) -> tuple[ProgrammeScopeNonAuthorityContext, ...]:
    source_context = {
        item.item_id: item
        for item in session.source_result.proposal.non_authority_context
    }
    contexts = []
    for outcome, resolution in zip(
        session.source_result.outcomes,
        session.resolutions,
        strict=True,
    ):
        base = source_context.get(outcome.context_item_id)
        if base is None:
            raise ValueError("HackerOne source row context is missing.")
        final_rule_ids = tuple(
            retained_ids[rule.rule_id] for rule in resolution.rules
        )
        resolution_value = (
            f"resolution={resolution.state}; "
            f"source_row_id={resolution.row_id}; "
            f"canonical_rule_ids={','.join(final_rule_ids) or 'none'}; "
            f"non_authority_basis={resolution.non_authority_basis or 'none'}"
        )
        contexts.append(
            ProgrammeScopeNonAuthorityContext(
                item_id=base.item_id,
                label=(
                    "HackerOne resolved row context"
                    if final_rule_ids
                    else "HackerOne non-authority resolution"
                ),
                value=f"{base.value}; {resolution_value}",
            )
        )
    return tuple(contexts)


def _require_session(session: object) -> HackerOneScopeResolutionSession:
    if not isinstance(session, HackerOneScopeResolutionSession):
        raise ValueError("HackerOne scope resolution requires a resolution session.")
    return session


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid.")
    return value


def _require_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid.")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
