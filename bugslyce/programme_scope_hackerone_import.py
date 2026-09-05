"""Grouped local HackerOne scope import ending at the shared P1 save boundary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys
import unicodedata

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopePolicy,
    ProgrammeScopeRule,
)
from bugslyce.programme_scope_hackerone_csv import (
    CATEGORY_EXECUTABLE,
    CATEGORY_NON_AUTHORITY,
    REASON_AMBIGUOUS_BARE_HOSTNAME,
    REASON_AMBIGUOUS_OTHER_ASSET,
    REASON_AMBIGUOUS_SCHEMELESS_URL,
    REASON_CANONICAL_HTTP_URL,
    REASON_CANONICAL_WILDCARD,
    REASON_INSTRUCTION_REVIEW_REQUIRED,
    REASON_MALFORMED_WILDCARD,
    REASON_NON_WEB_ASSET_TYPE,
    REASON_NONCANONICAL_HTTP_URL,
    REASON_UNSUPPORTED_API_IDENTIFIER,
    REASON_UNSUPPORTED_ASSET_TYPE,
    REASON_UNSUPPORTED_URL_IDENTIFIER,
    REASON_URL_ASSET_WILDCARD_MISMATCH,
    HackerOneScopeCsvRow,
    build_hackerone_programme_scope_proposal,
)
from bugslyce.programme_scope_hackerone_resolution import (
    NON_AUTHORITY_EXPLICIT_INCLUDE,
    NON_AUTHORITY_EXPLICIT_NON_WEB,
    NON_AUTHORITY_P2A_TYPED,
    ROW_STATE_AUTOMATIC_RULE,
    ROW_STATE_EXPLICIT_RULE,
    ROW_STATE_TYPED_NON_AUTHORITY,
    ROW_STATE_UNRESOLVED,
    HackerOneScopeResolutionGroup,
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
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeNonAuthorityContext,
    ProgrammeScopeProposal,
    build_programme_scope_proposal,
)
from bugslyce.programme_scope_setup import (
    review_and_save_programme_scope_proposal,
)
from bugslyce.project_session import (
    load_project,
    load_project_programme_scope_policy,
)
from bugslyce.time_utils import utc_now_iso


InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]
NowFunc = Callable[[], str]

HACKERONE_IMPORT_MODE_NEW = "NEW"
HACKERONE_IMPORT_MODE_MERGE = "MERGE"
HACKERONE_IMPORT_MODE_REPLACE = "REPLACE"

INSTRUCTION_PAGE_LINES = 20

_CANCEL = "CANCEL"
_BACK = "BACK"
class HackerOneImportCancelled(Exception):
    """Internal typed cancellation before any authority persistence."""


@dataclass(frozen=True)
class HackerOneImportCompleteness:
    """Human review counts derived from one immutable resolution session."""

    unresolved_include_rows: tuple[int, ...]
    unresolved_exclude_rows: tuple[int, ...]
    unacknowledged_instruction_rows: tuple[int, ...]
    unacknowledged_instruction_groups: int
    automatic_rules: int
    explicit_rules: int
    explicit_non_authority_includes: int
    typed_or_explicit_non_web_rows: int

    @property
    def complete(self) -> bool:
        return not (
            self.unresolved_include_rows
            or self.unresolved_exclude_rows
            or self.unacknowledged_instruction_rows
        )


def import_hackerone_programme_scope(
    project_path: Path,
    csv_path: Path,
    *,
    input_func: InputFunc = input,
    print_func: PrintFunc = print,
    error_func: PrintFunc | None = None,
    now_func: NowFunc = utc_now_iso,
) -> int:
    """Resolve one local CSV interactively and invoke the shared P1 save once."""

    errors = error_func or _stderr_print
    try:
        project = load_project(Path(project_path))
        if project.engagement_context != BUG_BOUNTY_CONTEXT:
            raise ValueError("HackerOne scope import requires a bug bounty project.")
        stored = load_project_programme_scope_policy(project)
        source_result = build_hackerone_programme_scope_proposal(Path(csv_path))
        session = build_hackerone_scope_resolution_session(source_result)
        print_func(render_hackerone_import_summary(session))
        if _prompt(input_func, "Type CONTINUE to review this import, or CANCEL: ") != "CONTINUE":
            raise HackerOneImportCancelled

        mode = _select_import_mode(
            stored,
            input_func=input_func,
            print_func=print_func,
            error_func=errors,
        )
        session = review_hackerone_instruction_dossier(
            session,
            input_func=input_func,
            print_func=print_func,
            error_func=errors,
        )
        session, resolved = _run_resolution_loop(
            session,
            input_func=input_func,
            print_func=print_func,
            error_func=errors,
        )
        return _review_resolved_hackerone_import(
            Path(project_path),
            session=session,
            resolved=resolved,
            stored=stored,
            mode=mode,
            input_func=input_func,
            print_func=print_func,
            error_func=errors,
            now_func=now_func,
        )
    except HackerOneImportCancelled:
        print_func(
            "HackerOne programme-scope import cancelled; stored values are unchanged."
        )
        return 0
    except EOFError:
        errors("Error: HackerOne programme-scope input ended unexpectedly.")
        return 2
    except ValueError as exc:
        errors(f"Error: {exc}")
        return 2
    except (OSError, UnicodeError):
        errors("Error: HackerOne programme scope could not be read or saved safely.")
        return 2


def render_hackerone_import_summary(
    session: HackerOneScopeResolutionSession,
) -> str:
    """Render bounded source/classification counts without instruction bodies."""

    _require_session(session)
    outcomes = session.source_result.outcomes
    automatic_include = _count_outcomes(
        outcomes,
        CATEGORY_EXECUTABLE,
        ACTION_INCLUDE,
    )
    automatic_exclude = _count_outcomes(
        outcomes,
        CATEGORY_EXECUTABLE,
        ACTION_EXCLUDE,
    )
    unresolved_include = sum(
        item.source_category != CATEGORY_EXECUTABLE
        and item.source_category != CATEGORY_NON_AUTHORITY
        and item.proposed_action == ACTION_INCLUDE
        for item in session.resolutions
    )
    unresolved_exclude = sum(
        item.source_category != CATEGORY_EXECUTABLE
        and item.source_category != CATEGORY_NON_AUTHORITY
        and item.proposed_action == ACTION_EXCLUDE
        for item in session.resolutions
    )
    non_authority_include = _count_outcomes(
        outcomes, CATEGORY_NON_AUTHORITY, ACTION_INCLUDE
    )
    non_authority_exclude = _count_outcomes(
        outcomes, CATEGORY_NON_AUTHORITY, ACTION_EXCLUDE
    )
    return "\n".join(
        (
            "HackerOne programme-scope import - non-authoritative review",
            f"Source: {session.source_result.document.source_filename}",
            f"SHA-256: {session.source_sha256}",
            f"Source rows: {len(session.resolutions)}",
            f"Automatic rules: {automatic_include} include; {automatic_exclude} exclude",
            f"Unresolved: {unresolved_include} include; {unresolved_exclude} exclude",
            (
                "Typed non-authority: "
                f"{non_authority_include} include; {non_authority_exclude} exclude"
            ),
            (
                "Instruction-required rows: "
                f"{sum(item.instruction_required for item in session.resolutions)}"
            ),
            f"Resolution groups: {len(session.groups)}",
            "No authority is persisted before complete review and final confirmation.",
        )
    )


def render_hackerone_import_groups(
    session: HackerOneScopeResolutionSession,
) -> str:
    """Render deterministic semantic groups and completion counts."""

    _require_session(session)
    lines = ["HackerOne semantic resolution groups"]
    for number, group in enumerate(session.groups, start=1):
        resolutions = tuple(
            get_hackerone_scope_resolution(session, row_id)
            for row_id in group.row_ids
        )
        lines.append(
            "Group "
            f"{number:02d}: {_reason_label(group.reason)} | {group.asset_type} | "
            f"{group.proposed_action.upper()} | "
            f"instruction={'yes' if group.instruction_present else 'no'} | "
            f"rows={len(group.row_ids)} | "
            f"complete={sum(item.complete for item in resolutions)}/{len(resolutions)}"
        )
    return "\n".join(lines)


def parse_hackerone_group_selection(
    value: str,
    *,
    session: HackerOneScopeResolutionSession,
    group: HackerOneScopeResolutionGroup,
) -> tuple[str, ...] | None:
    """Parse `all`, source-row lists/ranges, or `back` for one exact group."""

    _require_session(session)
    if group not in session.groups:
        raise ValueError("HackerOne resolution group does not belong to this session.")
    if not isinstance(value, str):
        raise ValueError("HackerOne row selection must be text.")
    candidate = value.strip()
    if candidate.casefold() == "back":
        return None
    if candidate.casefold() == "all":
        return group.row_ids
    if not candidate:
        raise ValueError("Select source rows with all, a list, or an ascending range.")

    allowed = {
        resolution.row_number: resolution.row_id
        for resolution in session.resolutions
        if resolution.row_id in group.row_ids
    }
    selected: set[int] = set()
    for part in candidate.split(","):
        token = part.strip()
        if not token:
            raise ValueError("HackerOne row selection is malformed.")
        if "-" in token:
            if token.count("-") != 1:
                raise ValueError("HackerOne row range is malformed.")
            start_text, end_text = token.split("-", 1)
            if not start_text.isdecimal() or not end_text.isdecimal():
                raise ValueError("HackerOne row range is malformed.")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError("HackerOne row ranges must be ascending.")
            numbers = range(start, end + 1)
        else:
            if not token.isdecimal():
                raise ValueError("HackerOne row selection is malformed.")
            numbers = (int(token),)
        for number in numbers:
            if number not in allowed:
                raise ValueError("Selected source row does not belong to this group.")
            if number in selected:
                raise ValueError("HackerOne row selection contains a duplicate.")
            selected.add(number)
    return tuple(allowed[number] for number in sorted(selected))


def sanitise_hackerone_instruction_text(value: str) -> str:
    """Make external instruction text inert while preserving visible line structure."""

    if not isinstance(value, str):
        raise ValueError("HackerOne instruction text must be text.")
    output: list[str] = []
    for character in value:
        if character == "\n":
            output.append(character)
        elif character == "\t":
            output.append("    ")
        elif unicodedata.category(character) in {"Cc", "Cf", "Cs"} or character in {
            "\u2028",
            "\u2029",
        }:
            codepoint = ord(character)
            output.append(
                f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}"
            )
        else:
            output.append(character)
    return "".join(output)


def review_hackerone_instruction_dossier(
    session: HackerOneScopeResolutionSession,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
) -> HackerOneScopeResolutionSession:
    """Review a complete instruction dossier before one all-or-nothing acknowledgement."""

    _require_session(session)
    grouped = []
    for digest, instruction, row_ids in _instruction_groups(session):
        pending = tuple(
            row_id
            for row_id in row_ids
            if not get_hackerone_scope_resolution(session, row_id).instruction_acknowledged
        )
        if not pending:
            continue
        grouped.append((digest, instruction, pending))
    if not grouped:
        return session

    print_func("Programme instructions")
    print_func(
        f"{len(grouped)} distinct instructions affect "
        f"{sum(len(row_ids) for _digest, _instruction, row_ids in grouped)} scope rows."
    )
    _display_complete_instruction_dossier(
        session,
        tuple(grouped),
        input_func=input_func,
        print_func=print_func,
        error_func=error_func,
    )
    while True:
        action = _prompt(
            input_func,
            "Type ACKNOWLEDGE ALL to confirm every displayed programme instruction "
            "was reviewed, DEFER, or CANCEL: ",
        ).upper()
        if action == "DEFER":
            return session
        if action != "ACKNOWLEDGE ALL":
            error_func("Error: choose ACKNOWLEDGE ALL, DEFER, or CANCEL.")
            continue
        changed = session
        for digest, _instruction, row_ids in grouped:
            for row_id in row_ids:
                changed = acknowledge_hackerone_scope_instruction(
                    changed,
                    row_id,
                    source_sha256=changed.source_sha256,
                    instruction_sha256=digest,
                )
        return changed


def view_hackerone_instruction_dossier(
    session: HackerOneScopeResolutionSession,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
    row_ids: tuple[str, ...] | None = None,
) -> HackerOneScopeResolutionSession:
    """Display exact source instructions read-only, including acknowledged rows."""

    _require_session(session)
    selected = None if row_ids is None else frozenset(row_ids)
    if selected is not None:
        for row_id in selected:
            _row(session, row_id)
    grouped_items: list[tuple[str, str, tuple[str, ...]]] = []
    for digest, instruction, members in _instruction_groups(session):
        filtered = (
            members
            if selected is None
            else tuple(row_id for row_id in members if row_id in selected)
        )
        if filtered:
            grouped_items.append((digest, instruction, filtered))
    grouped = tuple(grouped_items)
    if not grouped:
        print_func("No programme instructions are associated with this selection.")
        return session
    print_func("Programme instructions (read-only)")
    print_func(
        f"{len(grouped)} distinct instructions affect "
        f"{sum(len(members) for _digest, _instruction, members in grouped)} scope rows."
    )
    _display_complete_instruction_dossier(
        session,
        grouped,
        input_func=input_func,
        print_func=print_func,
        error_func=error_func,
    )
    return session


def build_hackerone_import_completeness(
    session: HackerOneScopeResolutionSession,
) -> HackerOneImportCompleteness:
    """Return every outstanding condition instead of one finalization error."""

    _require_session(session)
    unresolved_include = tuple(
        item.row_number
        for item in session.resolutions
        if item.state == ROW_STATE_UNRESOLVED
        and item.proposed_action == ACTION_INCLUDE
    )
    unresolved_exclude = tuple(
        item.row_number
        for item in session.resolutions
        if item.state == ROW_STATE_UNRESOLVED
        and item.proposed_action == ACTION_EXCLUDE
    )
    instruction_rows = tuple(
        item.row_number
        for item in session.resolutions
        if item.instruction_required and not item.instruction_acknowledged
    )
    pending_digests = {
        item.instruction_sha256
        for item in session.resolutions
        if item.instruction_required and not item.instruction_acknowledged
    }
    return HackerOneImportCompleteness(
        unresolved_include_rows=unresolved_include,
        unresolved_exclude_rows=unresolved_exclude,
        unacknowledged_instruction_rows=instruction_rows,
        unacknowledged_instruction_groups=len(pending_digests),
        automatic_rules=sum(
            item.state == ROW_STATE_AUTOMATIC_RULE for item in session.resolutions
        ),
        explicit_rules=sum(
            item.state == ROW_STATE_EXPLICIT_RULE for item in session.resolutions
        ),
        explicit_non_authority_includes=sum(
            item.non_authority_basis == NON_AUTHORITY_EXPLICIT_INCLUDE
            for item in session.resolutions
        ),
        typed_or_explicit_non_web_rows=sum(
            item.non_authority_basis
            in {NON_AUTHORITY_P2A_TYPED, NON_AUTHORITY_EXPLICIT_NON_WEB}
            for item in session.resolutions
        ),
    )


def render_hackerone_import_completeness(
    completeness: HackerOneImportCompleteness,
) -> str:
    """Render all outstanding and completed resolution categories."""

    if not isinstance(completeness, HackerOneImportCompleteness):
        raise ValueError("HackerOne import completeness state is invalid.")
    return "\n".join(
        (
            "HackerOne import completeness",
            "Unresolved include rows: " + _row_numbers(completeness.unresolved_include_rows),
            "Unresolved exclusion rows: " + _row_numbers(completeness.unresolved_exclude_rows),
            (
                "Unacknowledged instructions: "
                f"{completeness.unacknowledged_instruction_groups} group(s); rows "
                f"{_row_numbers(completeness.unacknowledged_instruction_rows)}"
            ),
            f"Automatic rules: {completeness.automatic_rules}",
            f"Explicit rules: {completeness.explicit_rules}",
            (
                "Explicit non-authority includes: "
                f"{completeness.explicit_non_authority_includes}"
            ),
            (
                "Typed/explicit non-web rows: "
                f"{completeness.typed_or_explicit_non_web_rows}"
            ),
            f"Save available: {'yes' if completeness.complete else 'no'}",
        )
    )


def prepare_hackerone_import_proposal(
    resolved: ProgrammeScopeProposal,
    *,
    existing_policy: ProgrammeScopePolicy | None,
    mode: str,
) -> ProgrammeScopeProposal:
    """Prepare NEW/MERGE/REPLACE rules without persistence or stricter overlap policy."""

    if not isinstance(resolved, ProgrammeScopeProposal) or resolved.unresolved_items:
        raise ValueError("HackerOne import requires a fully resolved proposal.")
    if existing_policy is None:
        if mode != HACKERONE_IMPORT_MODE_NEW:
            raise ValueError("A new programme policy requires NEW import mode.")
        return resolved
    if not isinstance(existing_policy, ProgrammeScopePolicy):
        raise ValueError("HackerOne import existing policy is invalid.")
    if mode not in {HACKERONE_IMPORT_MODE_MERGE, HACKERONE_IMPORT_MODE_REPLACE}:
        raise ValueError("An existing policy requires explicit MERGE, REPLACE or CANCEL.")
    if mode == HACKERONE_IMPORT_MODE_REPLACE:
        return resolved

    existing_by_id = {rule.rule_id.casefold(): rule for rule in existing_policy.rules}
    existing_by_semantics: dict[tuple[object, ...], ProgrammeScopeRule] = {}
    for rule in existing_policy.rules:
        existing_by_semantics.setdefault(_rule_semantics(rule), rule)
    additions: list[ProgrammeScopeRule] = []
    deduplicated: list[tuple[ProgrammeScopeRule, ProgrammeScopeRule]] = []
    for rule in resolved.rules:
        same_id = existing_by_id.get(rule.rule_id.casefold())
        if same_id is not None and _rule_semantics(same_id) != _rule_semantics(rule):
            raise ValueError("HackerOne merge has an incompatible rule ID collision.")
        equivalent = existing_by_semantics.get(_rule_semantics(rule))
        if same_id is not None or equivalent is not None:
            deduplicated.append((rule, same_id or equivalent))
            continue
        additions.append(rule)

    context = list(resolved.non_authority_context)
    for imported, retained in deduplicated:
        digest = hashlib.sha256(
            f"{imported.rule_id}\0{retained.rule_id}".encode("utf-8")
        ).hexdigest()[:20]
        context.append(
            ProgrammeScopeNonAuthorityContext(
                item_id=f"h1-merge-dedup-{digest}",
                label="HackerOne merge deduplication",
                value=(
                    f"Imported canonical rule {imported.rule_id} is represented by "
                    f"retained existing rule {retained.rule_id}."
                ),
            )
        )
    return build_programme_scope_proposal(
        source=resolved.source,
        rules=(*existing_policy.rules, *additions),
        unresolved_items=(),
        non_authority_context=context,
    )


def _review_resolved_hackerone_import(
    project_path: Path,
    *,
    session: HackerOneScopeResolutionSession,
    resolved: ProgrammeScopeProposal,
    stored: ProgrammeScopePolicy | None,
    mode: str,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
    now_func: NowFunc,
) -> int:
    """Offer save, amendment, or read-only instruction review before P1 confirmation."""

    changed = session
    resolved_proposal = resolved
    while True:
        candidate = prepare_hackerone_import_proposal(
            resolved_proposal,
            existing_policy=stored,
            mode=mode,
        )
        _render_existing_policy_mode(
            mode,
            stored,
            resolved_proposal,
            candidate,
            print_func=print_func,
        )
        print_func(_render_final_import_review(changed, candidate, mode=mode))
        action = _prompt(
            input_func,
            "Final imported scope [SAVE/CHANGE/INSTRUCTIONS/CANCEL]: ",
        ).upper()
        if action == "CANCEL":
            raise HackerOneImportCancelled
        if action == "INSTRUCTIONS":
            view_hackerone_instruction_dossier(
                changed,
                input_func=input_func,
                print_func=print_func,
                error_func=error_func,
            )
            continue
        if action == "CHANGE":
            changed, resolved_proposal = _run_resolution_loop(
                changed,
                input_func=input_func,
                print_func=print_func,
                error_func=error_func,
            )
            continue
        if action != "SAVE":
            error_func("Error: choose SAVE, CHANGE, INSTRUCTIONS, or CANCEL.")
            continue
        if mode == HACKERONE_IMPORT_MODE_REPLACE:
            confirmation = _prompt(
                input_func,
                "Type REPLACE EXISTING POLICY to acknowledge replacement: ",
            )
            if confirmation != "REPLACE EXISTING POLICY":
                raise HackerOneImportCancelled
        return review_and_save_programme_scope_proposal(
            project_path,
            candidate,
            input_func=input_func,
            print_func=print_func,
            error_func=error_func,
            now_func=now_func,
        )


def _run_resolution_loop(
    session: HackerOneScopeResolutionSession,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
) -> tuple[HackerOneScopeResolutionSession, ProgrammeScopeProposal]:
    changed = session
    while True:
        print_func(render_hackerone_import_groups(changed))
        selection = _prompt(
            input_func,
            "Select a group number, INSTRUCTIONS, REVIEW, or CANCEL: ",
        ).upper()
        if selection == "INSTRUCTIONS":
            if build_hackerone_import_completeness(changed).unacknowledged_instruction_rows:
                changed = review_hackerone_instruction_dossier(
                    changed,
                    input_func=input_func,
                    print_func=print_func,
                    error_func=error_func,
                )
            else:
                view_hackerone_instruction_dossier(
                    changed,
                    input_func=input_func,
                    print_func=print_func,
                    error_func=error_func,
                )
            continue
        if selection == "REVIEW":
            completeness = build_hackerone_import_completeness(changed)
            print_func(render_hackerone_import_completeness(completeness))
            if not completeness.complete:
                continue
            try:
                return changed, finalize_hackerone_scope_resolution(changed)
            except ValueError as exc:
                error_func(f"Error: {exc}")
                continue
        if not selection.isdecimal() or not 1 <= int(selection) <= len(changed.groups):
            error_func("Error: select a listed group, INSTRUCTIONS, REVIEW, or CANCEL.")
            continue
        changed = _review_group(
            changed,
            changed.groups[int(selection) - 1],
            input_func=input_func,
            print_func=print_func,
            error_func=error_func,
        )


def _review_group(
    session: HackerOneScopeResolutionSession,
    group: HackerOneScopeResolutionGroup,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
) -> HackerOneScopeResolutionSession:
    changed = session
    if group.reason == REASON_AMBIGUOUS_BARE_HOSTNAME:
        print_func(
            "Warning: exact_hostname authorises the hostname under BugSlyce hostname "
            "scope semantics and is broader than accepting one exact URL."
        )
    if group.reason == REASON_URL_ASSET_WILDCARD_MISMATCH:
        print_func(
            "Warning: wildcard subdomain authority covers descendants and does not "
            "include the apex."
        )
    if (
        group.reason in {REASON_AMBIGUOUS_OTHER_ASSET, REASON_UNSUPPORTED_ASSET_TYPE}
        and group.proposed_action == ACTION_EXCLUDE
    ):
        print_func(
            "Warning: NON-WEB is a deliberate assertion that the source asset is "
            "outside BugSlyce executable web/IP reconnaissance authority."
        )
    while True:
        actions = _group_actions(group)
        action = _prompt(
            input_func,
            "Group action [" + "/".join(actions) + "]: ",
        ).upper()
        if action in {_BACK, "DEFER"}:
            return changed
        if action == "INSPECT":
            print_func(_render_group_members(changed, group))
            continue
        if action == "VIEW-INSTRUCTION":
            view_hackerone_instruction_dossier(
                changed,
                row_ids=group.row_ids,
                input_func=input_func,
                print_func=print_func,
                error_func=error_func,
            )
            continue
        if action not in actions:
            error_func("Error: that action is not available for this resolution group.")
            continue
        row_ids = _prompt_group_selection(
            changed,
            group,
            input_func=input_func,
            error_func=error_func,
        )
        if row_ids is None:
            return changed
        try:
            candidate = _apply_group_action(
                changed,
                group,
                action,
                row_ids,
                input_func=input_func,
                print_func=print_func,
            )
        except ValueError as exc:
            error_func(f"Error: {exc}")
            continue
        return candidate


def _apply_group_action(
    session: HackerOneScopeResolutionSession,
    group: HackerOneScopeResolutionGroup,
    action: str,
    row_ids: tuple[str, ...],
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
) -> HackerOneScopeResolutionSession:
    if (
        group.reason in {REASON_AMBIGUOUS_OTHER_ASSET, REASON_UNSUPPORTED_ASSET_TYPE}
        and action in {"CANONICAL", "NON-WEB"}
        and len(row_ids) != 1
    ):
        raise ValueError("OTHER/unsupported source rows must be reviewed individually.")
    if action == "HOSTNAME":
        return resolve_hackerone_scope_group_with_source_rule(
            session,
            group.group_id,
            row_ids=row_ids,
            kind=RULE_EXACT_HOSTNAME,
        )
    if action == "WILDCARD":
        return resolve_hackerone_scope_group_with_source_rule(
            session,
            group.group_id,
            row_ids=row_ids,
            kind=RULE_WILDCARD_SUBDOMAIN,
        )
    if action == "NON-AUTHORITY":
        changed = session
        for row_id in row_ids:
            changed = resolve_hackerone_scope_include_as_non_authority(changed, row_id)
        return changed
    if action == "NON-WEB":
        changed = session
        for row_id in row_ids:
            changed = classify_hackerone_scope_row_as_non_web(changed, row_id)
        return changed
    if action == "RESET":
        changed = session
        for row_id in row_ids:
            changed = reset_hackerone_scope_row(changed, row_id)
        return changed
    if action == "URL":
        changed = session
        for row_id in row_ids:
            row = _row(session, row_id)
            value = _prompt(
                input_func,
                f"Complete HTTP(S) URL for source row {row.row_number}: ",
            )
            changed = resolve_hackerone_scope_row_with_rule(
                changed,
                row_id,
                kind=RULE_EXACT_HTTP_URL,
                value=value,
            )
        return changed
    if action == "ACCEPT-CANONICAL":
        candidates: list[tuple[str, ProgrammeScopeRule]] = []
        for row_id in row_ids:
            row = _row(session, row_id)
            candidate = build_hackerone_scope_review_candidate(session, row_id)
            if candidate is None:
                raise ValueError("This source row has no canonical review candidate.")
            print_func(f"SOURCE: {_safe_identifier(row.identifier)}")
            label = (
                "CANONICAL EXACT URL"
                if candidate.kind == RULE_EXACT_HTTP_URL
                else "CANONICAL RULE"
            )
            print_func(f"{label}: {candidate.canonical_value}")
            candidates.append((row_id, candidate))
        if (
            _prompt(
                input_func,
                "Type ACCEPT CANONICAL RULES to use the displayed canonical rule(s): ",
            )
            != "ACCEPT CANONICAL RULES"
        ):
            raise ValueError("Canonical rule candidates were not accepted.")
        changed = session
        for row_id, candidate in candidates:
            changed = resolve_hackerone_scope_row_with_rule(
                changed,
                row_id,
                kind=candidate.kind,
                value=candidate.canonical_value,
                scheme=candidate.scheme,
                port=candidate.port,
            )
        return changed
    if action == "CANONICAL":
        changed = session
        for row_id in row_ids:
            row = _row(session, row_id)
            kind = _prompt(
                input_func,
                f"Canonical rule kind for source row {row.row_number}: ",
            )
            value = _prompt(input_func, "Complete canonical rule value: ")
            scheme_value = _prompt(
                input_func,
                "Optional scheme qualifier (blank for none): ",
            )
            port_value = _prompt(
                input_func,
                "Optional port qualifier (blank for none): ",
            )
            if port_value and not port_value.isdecimal():
                raise ValueError("Optional port qualifier must be an integer.")
            changed = resolve_hackerone_scope_row_with_rule(
                changed,
                row_id,
                kind=kind,
                value=value,
                scheme=scheme_value or None,
                port=int(port_value) if port_value else None,
            )
        return changed
    raise ValueError("HackerOne group action is unsupported.")


def _group_actions(group: HackerOneScopeResolutionGroup) -> tuple[str, ...]:
    common = ["INSPECT"]
    if group.instruction_present:
        common.append("VIEW-INSTRUCTION")
    if group.reason == REASON_AMBIGUOUS_BARE_HOSTNAME:
        common.extend(("HOSTNAME", "URL"))
    elif group.reason == REASON_CANONICAL_HTTP_URL:
        common.append("URL")
    elif group.reason == REASON_CANONICAL_WILDCARD:
        common.append("WILDCARD")
    elif group.reason in {
        REASON_AMBIGUOUS_SCHEMELESS_URL,
        REASON_UNSUPPORTED_URL_IDENTIFIER,
        REASON_UNSUPPORTED_API_IDENTIFIER,
    }:
        common.append("URL")
    elif group.reason in {
        REASON_URL_ASSET_WILDCARD_MISMATCH,
        REASON_MALFORMED_WILDCARD,
    }:
        common.extend(("WILDCARD", "CANONICAL"))
    elif group.reason in {
        REASON_NONCANONICAL_HTTP_URL,
        REASON_INSTRUCTION_REVIEW_REQUIRED,
    }:
        common.extend(("ACCEPT-CANONICAL", "CANONICAL"))
    elif group.reason in {
        REASON_AMBIGUOUS_OTHER_ASSET,
        REASON_UNSUPPORTED_ASSET_TYPE,
    }:
        common.extend(("CANONICAL", "NON-WEB"))
    elif group.reason == REASON_NON_WEB_ASSET_TYPE:
        common.append("NON-WEB")
    if group.proposed_action == ACTION_INCLUDE and group.reason not in {
        REASON_AMBIGUOUS_OTHER_ASSET,
        REASON_UNSUPPORTED_ASSET_TYPE,
    }:
        common.append("NON-AUTHORITY")
    common.extend(("RESET", "DEFER", "BACK", "CANCEL"))
    return tuple(common)


def _prompt_group_selection(
    session: HackerOneScopeResolutionSession,
    group: HackerOneScopeResolutionGroup,
    *,
    input_func: InputFunc,
    error_func: PrintFunc,
) -> tuple[str, ...] | None:
    while True:
        value = _prompt(input_func, "Source rows [all, 1,3,5-8, or back]: ")
        try:
            return parse_hackerone_group_selection(value, session=session, group=group)
        except ValueError as exc:
            error_func(f"Error: {exc}")


def _render_group_members(
    session: HackerOneScopeResolutionSession,
    group: HackerOneScopeResolutionGroup,
) -> str:
    lines = ["Group members"]
    for row_id in group.row_ids:
        row = _row(session, row_id)
        resolution = get_hackerone_scope_resolution(session, row_id)
        lines.append(
            f"- row {row.row_number} | {resolution.state} | "
            f"{_safe_identifier(row.identifier)}"
        )
    return "\n".join(lines)


def _display_complete_instruction_dossier(
    session: HackerOneScopeResolutionSession,
    grouped: tuple[tuple[str, str, tuple[str, ...]], ...],
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
) -> None:
    lines: list[str] = []
    total = len(grouped)
    for number, (_digest, instruction, row_ids) in enumerate(grouped, start=1):
        rows = tuple(_row(session, row_id) for row_id in row_ids)
        lines.extend(
            (
                f"Instruction {number} of {total}",
                f"Affected source rows: {len(rows)}",
                "Rows: " + ", ".join(str(row.row_number) for row in rows),
            )
        )
        for row in rows:
            resolution = get_hackerone_scope_resolution(session, row.row_id)
            lines.append(
                f"- row {row.row_number} | {row.asset_type} | "
                f"{resolution.proposed_action.upper()} | {_safe_identifier(row.identifier)}"
            )
        lines.append("----- BEGIN HACKERONE INSTRUCTION -----")
        lines.extend(sanitise_hackerone_instruction_text(instruction).split("\n"))
        lines.append("----- END HACKERONE INSTRUCTION -----")

    for offset in range(0, len(lines), INSTRUCTION_PAGE_LINES):
        for line in lines[offset : offset + INSTRUCTION_PAGE_LINES]:
            print_func(line)
        if offset + INSTRUCTION_PAGE_LINES < len(lines):
            while True:
                value = _prompt(
                    input_func,
                    "Press Enter to continue programme instructions, or type CANCEL: ",
                )
                if not value:
                    break
                error_func("Error: press Enter to display the complete dossier.")


def _instruction_groups(
    session: HackerOneScopeResolutionSession,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    grouped: dict[tuple[str, str], list[str]] = {}
    instruction_by_digest: dict[str, str] = {}
    for row, resolution in zip(
        session.source_result.document.rows,
        session.resolutions,
        strict=True,
    ):
        if resolution.instruction_sha256 is None:
            continue
        current = instruction_by_digest.setdefault(
            resolution.instruction_sha256,
            row.instruction,
        )
        if current != row.instruction:
            raise ValueError("HackerOne instruction digest collision is inconsistent.")
        grouped.setdefault((resolution.instruction_sha256, row.instruction), []).append(
            row.row_id
        )
    return tuple(
        (digest, instruction, tuple(row_ids))
        for (digest, instruction), row_ids in sorted(grouped.items())
    )


def _select_import_mode(
    stored: ProgrammeScopePolicy | None,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
) -> str:
    if stored is None:
        return HACKERONE_IMPORT_MODE_NEW
    print_func(
        f"An existing programme policy contains {len(stored.rules)} canonical rule(s)."
    )
    while True:
        mode = _prompt(input_func, "Choose MERGE, REPLACE, or CANCEL: ").upper()
        if mode in {HACKERONE_IMPORT_MODE_MERGE, HACKERONE_IMPORT_MODE_REPLACE}:
            return mode
        error_func("Error: choose MERGE, REPLACE, or CANCEL.")


def _render_existing_policy_mode(
    mode: str,
    stored: ProgrammeScopePolicy | None,
    imported: ProgrammeScopeProposal,
    candidate: ProgrammeScopeProposal,
    *,
    print_func: PrintFunc,
) -> None:
    print_func(f"Existing-policy mode: {mode}")
    if stored is None:
        return
    if mode == HACKERONE_IMPORT_MODE_REPLACE:
        print_func(f"Existing rules that will disappear: {len(stored.rules)}")
        for rule in stored.rules:
            print_func(f"- {_safe_rule(rule)}")
        return
    imported_semantics = {_rule_semantics(rule) for rule in imported.rules}
    existing_semantics = {_rule_semantics(rule) for rule in stored.rules}
    print_func(f"Retained existing rules: {len(stored.rules)}")
    for rule in stored.rules:
        print_func(f"- {_safe_rule(rule)}")
    additions = tuple(
        rule
        for rule in candidate.rules
        if _rule_semantics(rule) in imported_semantics - existing_semantics
    )
    print_func(f"Imported additions: {len(additions)}")
    for rule in additions:
        print_func(f"- {_safe_rule(rule)}")


def _render_final_import_review(
    session: HackerOneScopeResolutionSession,
    proposal: ProgrammeScopeProposal,
    *,
    mode: str,
) -> str:
    include_count = sum(rule.action == ACTION_INCLUDE for rule in proposal.rules)
    exclude_count = sum(rule.action == ACTION_EXCLUDE for rule in proposal.rules)
    dismissed_includes = sum(
        item.non_authority_basis == NON_AUTHORITY_EXPLICIT_INCLUDE
        for item in session.resolutions
    )
    non_web_count = sum(
        item.non_authority_basis
        in {NON_AUTHORITY_P2A_TYPED, NON_AUTHORITY_EXPLICIT_NON_WEB}
        for item in session.resolutions
    )
    acknowledged = sum(item.instruction_acknowledged for item in session.resolutions)
    return "\n".join(
        (
            "Resolved HackerOne import review",
            f"Source: {session.source_result.document.source_filename}",
            f"SHA-256: {session.source_sha256}",
            f"Source rows: {len(session.resolutions)}",
            f"Final canonical rules: {include_count} include; {exclude_count} exclude",
            f"Rows deliberately non-authoritative: {dismissed_includes}",
            f"Typed/explicit non-web rows: {non_web_count}",
            f"Instruction acknowledgements: {acknowledged}",
            f"Existing-policy mode: {mode}",
            "No reconnaissance has been executed by this import.",
        )
    )


def _count_outcomes(outcomes, category: str, action: str) -> int:
    return sum(
        outcome.category == category and outcome.proposed_action == action
        for outcome in outcomes
    )


def _row(
    session: HackerOneScopeResolutionSession,
    row_id: str,
) -> HackerOneScopeCsvRow:
    for row in session.source_result.document.rows:
        if row.row_id == row_id:
            return row
    raise ValueError("HackerOne source row does not exist.")


def _reason_label(reason: str) -> str:
    return reason.replace("_", " ")


def _rule_semantics(rule: ProgrammeScopeRule) -> tuple[object, ...]:
    return (rule.action, rule.kind, rule.canonical_value, rule.scheme, rule.port)


def _safe_rule(rule: ProgrammeScopeRule) -> str:
    qualifiers = []
    if rule.scheme is not None:
        qualifiers.append(f"scheme={rule.scheme}")
    if rule.port is not None:
        qualifiers.append(f"port={rule.port}")
    suffix = "" if not qualifiers else " | " + " | ".join(qualifiers)
    return (
        f"{rule.rule_id} | {rule.action} | {rule.kind} | "
        f"{rule.canonical_value}{suffix}"
    )


def _safe_identifier(value: str) -> str:
    collapsed = " ".join(sanitise_hackerone_instruction_text(value).split())
    if len(collapsed) <= 160:
        return collapsed
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{collapsed[:140]}... [sha256:{digest}]"


def _row_numbers(values: tuple[int, ...]) -> str:
    return ", ".join(str(value) for value in values) if values else "none"


def _prompt(input_func: InputFunc, prompt: str) -> str:
    value = input_func(prompt).strip()
    if value.upper() == _CANCEL:
        raise HackerOneImportCancelled
    return value


def _require_session(value: object) -> HackerOneScopeResolutionSession:
    if not isinstance(value, HackerOneScopeResolutionSession):
        raise ValueError("HackerOne import requires a resolution session.")
    return value


def _stderr_print(message: str) -> None:
    print(message, file=sys.stderr)
