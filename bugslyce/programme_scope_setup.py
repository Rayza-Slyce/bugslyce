"""Offline programme-scope show and configure orchestration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import sys

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE,
    PROGRAMME_SCOPE_SCHEMA_VERSION,
    ProgrammeScopePolicy,
    ProgrammeScopeRule,
    build_programme_scope_policy,
    build_programme_scope_rule,
    validate_rule_id,
)
from bugslyce.core.programme_scope_bulk import build_programme_scope_bulk_draft
from bugslyce.programme_scope_management import (
    add_programme_scope_rule,
    build_changed_programme_scope_policy,
    programme_scope_rules_changed,
    remove_programme_scope_rule,
    render_programme_scope_local_summary,
    replace_programme_scope_rule,
    update_programme_scope_rule_private_fields,
)
from bugslyce.programme_scope_proposal import (
    ProgrammeScopeProposal,
    build_manual_programme_scope_proposal,
    render_programme_scope_proposal_review,
)
from bugslyce.project_session import (
    BugSlyceProject,
    load_project,
    load_project_programme_scope_policy,
    save_project_programme_scope_policy,
)
from bugslyce.time_utils import utc_now_iso


InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]
NowFunc = Callable[[], str]

_CANCEL = "CANCEL"


class _Cancelled(Exception):
    pass


def _stderr_print(message: str) -> None:
    print(message, file=sys.stderr)


def show_project_programme_scope(
    project_path: Path,
    *,
    print_func: PrintFunc = print,
    error_func: PrintFunc = _stderr_print,
) -> int:
    """Show one project's explicit private local programme-scope summary."""

    try:
        project = _load_bug_bounty_project(project_path)
        policy = load_project_programme_scope_policy(project)
        if policy is None:
            print_func("Programme scope is not configured.")
            print_func(
                "Live project reconnaissance remains unavailable until programme "
                "scope is configured and strict preflight succeeds."
            )
            return 0
        print_func(render_programme_scope_local_summary(project, policy))
        return 0
    except ValueError as exc:
        error_func(f"Error: {exc}")
        return 2
    except (OSError, UnicodeError):
        error_func("Error: programme scope could not be read safely.")
        return 2


def configure_project_programme_scope(
    project_path: Path,
    *,
    input_func: InputFunc = input,
    print_func: PrintFunc = print,
    error_func: PrintFunc = _stderr_print,
    now_func: NowFunc = utc_now_iso,
) -> int:
    """Create or edit one programme-scope policy with a single final save."""

    try:
        project = _load_bug_bounty_project(project_path)
        stored = load_project_programme_scope_policy(project)
        _render_initial_screen(project, stored, print_func)
        return _configure_loop(
            Path(project_path),
            project,
            stored,
            input_func=input_func,
            print_func=print_func,
            error_func=error_func,
            now_func=now_func,
        )
    except _Cancelled:
        print_func("Programme-scope configuration cancelled; stored values are unchanged.")
        return 0
    except EOFError:
        error_func("Error: programme-scope input ended unexpectedly.")
        return 2
    except ValueError as exc:
        error_func(f"Error: {exc}")
        return 2
    except (OSError, UnicodeError):
        error_func("Error: programme scope could not be read or saved safely.")
        return 2


def _load_bug_bounty_project(project_path: Path) -> BugSlyceProject:
    project = load_project(Path(project_path))
    if project.engagement_context != BUG_BOUNTY_CONTEXT:
        raise ValueError("Programme-scope configuration requires a bug bounty project.")
    return project


def _render_initial_screen(
    project: BugSlyceProject,
    policy: ProgrammeScopePolicy | None,
    print_func: PrintFunc,
) -> None:
    print_func("Programme scope configuration - private local operator workflow")
    print_func(f"Project: {project.name}")
    print_func(f"Engagement context: {project.engagement_context}")
    print_func(f"Programme scope configured: {'yes' if policy is not None else 'no'}")
    print_func("Copy rules manually from the current authorised programme brief.")
    print_func("Programme scope is enforced during live project reconnaissance.")
    print_func(
        "Stored configuration alone does not authorise traffic; strict preflight "
        "must also validate engagement policy and the project target."
    )
    if policy is not None:
        print_func("")
        print_func(render_programme_scope_local_summary(project, policy))


def _configure_loop(
    project_path: Path,
    project: BugSlyceProject,
    stored: ProgrammeScopePolicy | None,
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
    now_func: NowFunc,
) -> int:
    rules = () if stored is None else stored.rules
    while True:
        if stored is None:
            print_func(
                "1. Add rule\n2. Review rules\n3. Review and save\n4. Cancel\n"
                "5. Add structured bulk rules"
            )
            choice = _prompt(input_func, "Select an option: ")
            actions = {
                "1": "add",
                "2": "review",
                "3": "save",
                "4": "cancel",
                "5": "bulk",
            }
        else:
            print_func(
                "1. List/review rules\n2. Add rule\n3. Replace rule\n"
                "4. Remove rule\n5. Change private fields\n6. Review and save\n"
                "7. Cancel\n8. Add structured bulk rules"
            )
            choice = _prompt(input_func, "Select an option: ")
            actions = {
                "1": "review", "2": "add", "3": "replace", "4": "remove",
                "5": "private", "6": "save", "7": "cancel", "8": "bulk",
            }
        action = actions.get(choice)
        if action is None:
            error_func("Error: select one of the listed programme-scope options.")
            continue
        if action == "cancel":
            raise _Cancelled
        if action == "review":
            print_func(_render_draft(project, stored, rules))
            continue
        if action == "save":
            return _review_and_save(
                project_path, project, stored, rules,
                input_func=input_func, print_func=print_func,
                error_func=error_func, now_func=now_func,
            )
        try:
            if action == "add":
                _render_rule_entry_guidance(print_func)
                new_rule = _collect_rule(input_func)
                rules = add_programme_scope_rule(rules, new_rule)
                print_func(f"Rule added: {_safe_rule(new_rule)}")
            elif action == "bulk":
                bulk_draft = _collect_bulk_draft(input_func, print_func)
                changed = rules
                for rule in bulk_draft.rules:
                    changed = add_programme_scope_rule(changed, rule)
                rules = changed
                print_func(
                    f"Bulk rules added: {len(bulk_draft.rules)}; exact duplicates "
                    f"collapsed: {bulk_draft.duplicate_count}."
                )
                print_func(_render_draft(project, stored, rules))
            elif action == "replace":
                rules = _replace_rule(rules, input_func, print_func)
            elif action == "remove":
                rules = _remove_rule(rules, input_func, print_func)
            elif action == "private":
                rules = _change_private_fields(rules, input_func)
        except _Cancelled:
            raise
        except ValueError as exc:
            error_func(f"Error: {exc}")


def _collect_rule(
    input_func: InputFunc,
    *,
    rule_id: str | None = None,
) -> ProgrammeScopeRule:
    selected_id = rule_id or _prompt(input_func, "Rule ID: ")
    action = _prompt(input_func, "Action [include/exclude]: ")
    kind = _prompt(
        input_func,
        "Rule kind [exact_hostname/wildcard_subdomain/exact_http_url/"
        "http_path_prefix/exact_ipv4/ipv4_cidr]: ",
    )
    value = _prompt(input_func, "Literal programme scope value: ")
    private_note = _optional_private(_prompt(input_func, "Optional private note: "))
    private_source = _optional_private(
        _prompt(input_func, "Optional private source wording: ")
    )
    return build_programme_scope_rule(
        rule_id=selected_id,
        action=action,
        kind=kind,
        value=value,
        private_note=private_note,
        private_source_wording=private_source,
    )


def _replace_rule(
    rules: tuple[ProgrammeScopeRule, ...],
    input_func: InputFunc,
    print_func: PrintFunc,
) -> tuple[ProgrammeScopeRule, ...]:
    _render_rule_entry_guidance(print_func)
    rule_id = _prompt(input_func, "Existing rule ID: ")
    current = _find_rule(rules, rule_id)
    print_func(f"Current rule: {_safe_rule(current)}")
    replacement = _collect_public_replacement(input_func, current)
    if replacement.action != current.action:
        confirmation = _prompt(
            input_func,
            "Type CHANGE to confirm the include/exclude action change: ",
        )
        if confirmation != "CHANGE":
            raise ValueError("Rule action change was not confirmed.")
    changed = replace_programme_scope_rule(rules, current.rule_id, replacement)
    print_func(f"Rule replaced: {_safe_rule(replacement)}")
    return changed


def _render_rule_entry_guidance(print_func: PrintFunc) -> None:
    print_func(
        "Rule ID is a local operator label (for example target-ip or api-prefix); "
        "it does not define scope."
    )
    print_func("Rule kinds:")
    print_func("- exact_hostname: one exact hostname, e.g. app.example.com")
    print_func(
        "- wildcard_subdomain: subdomains covered by a programme wildcard, "
        "e.g. *.example.com"
    )
    print_func("- exact_http_url: one exact HTTP/HTTPS URL")
    print_func(
        "- http_path_prefix: an HTTP/HTTPS origin/path prefix, e.g. "
        "https://example.com/api/"
    )
    print_func(
        "  http://127.0.0.1:8080/ is an http_path_prefix entry, not an IPv4 rule."
    )
    print_func("- exact_ipv4: one IPv4 address, e.g. 127.0.0.1")
    print_func("- ipv4_cidr: an IPv4 network/range, e.g. 192.0.2.0/24")


def _collect_bulk_draft(input_func: InputFunc, print_func: PrintFunc):
    print_func("Enter one structured scope rule per line.")
    print_func(
        "Grammar: include|exclude hostname|wildcard|url|path|ipv4|cidr value "
        "[scheme=http|https] [port=1-65535]"
    )
    print_func("Type END on its own line to finish the in-memory bulk draft.")
    lines: list[str] = []
    while True:
        line = _prompt(input_func, "Bulk scope rule (END finishes): ")
        if line == "END":
            break
        lines.append(line)
    return build_programme_scope_bulk_draft("\n".join(lines))


def _collect_public_replacement(
    input_func: InputFunc,
    current: ProgrammeScopeRule,
) -> ProgrammeScopeRule:
    action = _prompt(input_func, "Replacement action [include/exclude]: ")
    kind = _prompt(
        input_func,
        "Replacement rule kind [exact_hostname/wildcard_subdomain/"
        "exact_http_url/http_path_prefix/exact_ipv4/ipv4_cidr]: ",
    )
    value = _prompt(input_func, "Replacement literal programme scope value: ")
    return build_programme_scope_rule(
        rule_id=current.rule_id,
        action=action,
        kind=kind,
        value=value,
        scheme=current.scheme,
        port=current.port,
        private_note=current.private_note,
        private_source_wording=current.private_source_wording,
    )


def _remove_rule(
    rules: tuple[ProgrammeScopeRule, ...],
    input_func: InputFunc,
    print_func: PrintFunc,
) -> tuple[ProgrammeScopeRule, ...]:
    rule_id = _prompt(input_func, "Existing rule ID: ")
    current = _find_rule(rules, rule_id)
    print_func(f"Rule selected: {_safe_rule(current)}")
    if _prompt(input_func, "Type REMOVE to remove this rule: ") != "REMOVE":
        raise ValueError("Rule removal was not confirmed.")
    inclusions = tuple(rule for rule in rules if rule.action == ACTION_INCLUDE)
    if current.action == ACTION_INCLUDE and len(inclusions) == 1:
        if _prompt(
            input_func,
            "Type SAVE WITHOUT INCLUSIONS to remove the final inclusion rule: ",
        ) != "SAVE WITHOUT INCLUSIONS":
            raise ValueError("Removal of the final inclusion rule was not confirmed.")
    if len(rules) == 1:
        if _prompt(
            input_func,
            "Type REMOVE FINAL RULE to leave an empty local policy: ",
        ) != "REMOVE FINAL RULE":
            raise ValueError("Removal of the final rule was not confirmed.")
    return remove_programme_scope_rule(rules, current.rule_id)


def _change_private_fields(
    rules: tuple[ProgrammeScopeRule, ...], input_func: InputFunc
) -> tuple[ProgrammeScopeRule, ...]:
    rule_id = _prompt(input_func, "Existing rule ID: ")
    current = _find_rule(rules, rule_id)
    note = _optional_private(
        _prompt(input_func, "Replacement private note (blank clears it): ")
    )
    source = _optional_private(
        _prompt(input_func, "Replacement private source wording (blank clears it): ")
    )
    return update_programme_scope_rule_private_fields(
        rules,
        current.rule_id,
        private_note=note,
        private_source_wording=source,
    )


def _review_and_save(
    project_path: Path,
    project: BugSlyceProject,
    stored: ProgrammeScopePolicy | None,
    rules: tuple[ProgrammeScopeRule, ...],
    *,
    input_func: InputFunc,
    print_func: PrintFunc,
    error_func: PrintFunc,
    now_func: NowFunc,
) -> int:
    proposal = build_manual_programme_scope_proposal(rules)
    print_func(_render_proposal_draft(project, stored, proposal))
    if stored is not None and not programme_scope_rules_changed(
        stored,
        proposal.rules,
    ):
        print_func("No programme-scope changes to save.")
        return 0
    required = "SAVE EMPTY POLICY" if not proposal.rules else "YES"
    confirmation = _prompt(
        input_func,
        f"Type {required} to save this private local policy: ",
    )
    if confirmation != required:
        print_func("Programme-scope save cancelled; stored values are unchanged.")
        return 0
    timestamp = now_func()
    policy = (
        build_programme_scope_policy(
            proposal.rules,
            schema_version=PROGRAMME_SCOPE_SCHEMA_VERSION,
            engagement_context=BUG_BOUNTY_CONTEXT,
            updated_at=timestamp,
        )
        if stored is None
        else build_changed_programme_scope_policy(
            stored,
            proposal.rules,
            updated_at=timestamp,
        )
    )
    try:
        updated_project, policy_path = save_project_programme_scope_policy(
            project_path, policy
        )
    except ValueError as exc:
        error_func(f"Error: {exc}")
        return 2
    except (OSError, UnicodeError):
        error_func("Error: programme scope could not be saved safely.")
        return 2
    print_func(render_programme_scope_local_summary(updated_project, policy))
    print_func(f"Programme scope saved privately: {policy_path.name} (mode 0600).")
    print_func(
        "No reconnaissance was executed. Live project reconnaissance remains subject "
        "to strict engagement-policy, programme-scope and target preflight."
    )
    return 0


def _render_draft(
    project: BugSlyceProject,
    stored: ProgrammeScopePolicy | None,
    rules: tuple[ProgrammeScopeRule, ...],
) -> str:
    return _render_proposal_draft(
        project,
        stored,
        build_manual_programme_scope_proposal(rules),
    )


def _render_proposal_draft(
    project: BugSlyceProject,
    stored: ProgrammeScopePolicy | None,
    proposal: ProgrammeScopeProposal,
) -> str:
    updated_at = "not saved yet" if stored is None else stored.updated_at
    return "\n".join(
        (
            f"Project: {project.name}",
            f"Engagement context: {project.engagement_context}",
            f"Schema version: {PROGRAMME_SCOPE_SCHEMA_VERSION}",
            f"Updated at: {updated_at}",
            render_programme_scope_proposal_review(proposal),
            (
                "Runtime programme-scope enforcement is active for live project "
                "reconnaissance."
            ),
            (
                "Stored configuration authorises traffic only after engagement-policy "
                "readiness and target evaluation."
            ),
        )
    )


def _find_rule(
    rules: tuple[ProgrammeScopeRule, ...], rule_id: str
) -> ProgrammeScopeRule:
    validated = validate_rule_id(rule_id)
    for rule in rules:
        if rule.rule_id.casefold() == validated.casefold():
            return rule
    raise ValueError("Programme scope rule does not exist.")


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


def _prompt(input_func: InputFunc, prompt: str) -> str:
    value = input_func(prompt).strip()
    if value == _CANCEL:
        raise _Cancelled
    return value


def _optional_private(value: str) -> str | None:
    return value or None
