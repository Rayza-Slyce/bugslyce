"""Pure programme-scope editing and private local rendering."""

from __future__ import annotations

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    PROGRAMME_SCOPE_SCHEMA_VERSION,
    ProgrammeScopePolicy,
    ProgrammeScopeRule,
    build_programme_scope_policy,
    build_programme_scope_rule,
    validate_rule_id,
)
from bugslyce.project_session import BugSlyceProject


_CANONICALISATION_TIMESTAMP = "1970-01-01T00:00:00Z"
PROGRAMME_SCOPE_RULE_KIND_ORDER = (
    RULE_EXACT_HOSTNAME,
    RULE_WILDCARD_SUBDOMAIN,
    RULE_EXACT_HTTP_URL,
    RULE_HTTP_PATH_PREFIX,
    RULE_EXACT_IPV4,
    RULE_IPV4_CIDR,
)


def add_programme_scope_rule(
    rules: tuple[ProgrammeScopeRule, ...],
    rule: ProgrammeScopeRule,
) -> tuple[ProgrammeScopeRule, ...]:
    """Return a canonical tuple containing one additional rule."""

    canonical = _canonical_rules(rules)
    _require_rule(rule)
    if any(existing.rule_id.casefold() == rule.rule_id.casefold() for existing in canonical):
        raise ValueError("Programme scope rule IDs must be unique case-insensitively.")
    return _canonical_rules((*canonical, rule))


def replace_programme_scope_rule(
    rules: tuple[ProgrammeScopeRule, ...],
    rule_id: str,
    replacement: ProgrammeScopeRule,
) -> tuple[ProgrammeScopeRule, ...]:
    """Replace one rule while retaining its stable rule ID."""

    canonical = _canonical_rules(rules)
    index = _rule_index(canonical, rule_id)
    _require_rule(replacement)
    if replacement.rule_id != canonical[index].rule_id:
        raise ValueError("Replacement must retain the same rule ID.")
    changed = list(canonical)
    changed[index] = replacement
    return _canonical_rules(tuple(changed))


def remove_programme_scope_rule(
    rules: tuple[ProgrammeScopeRule, ...],
    rule_id: str,
) -> tuple[ProgrammeScopeRule, ...]:
    """Remove one rule, including the final rule, without mutating the source."""

    canonical = _canonical_rules(rules)
    index = _rule_index(canonical, rule_id)
    return _canonical_rules(canonical[:index] + canonical[index + 1 :])


def update_programme_scope_rule_private_fields(
    rules: tuple[ProgrammeScopeRule, ...],
    rule_id: str,
    *,
    private_note: str | None,
    private_source_wording: str | None,
) -> tuple[ProgrammeScopeRule, ...]:
    """Rebuild one rule with changed private fields through the canonical builder."""

    canonical = _canonical_rules(rules)
    index = _rule_index(canonical, rule_id)
    current = canonical[index]
    replacement = build_programme_scope_rule(
        rule_id=current.rule_id,
        action=current.action,
        kind=current.kind,
        value=current.canonical_value,
        scheme=current.scheme,
        port=current.port,
        private_note=private_note,
        private_source_wording=private_source_wording,
    )
    if replacement == current:
        return canonical
    changed = list(canonical)
    changed[index] = replacement
    return _canonical_rules(tuple(changed))


def programme_scope_rules_changed(
    original_policy: ProgrammeScopePolicy,
    candidate_rules: tuple[ProgrammeScopeRule, ...],
) -> bool:
    """Compare every public and private canonical rule field."""

    _require_policy(original_policy)
    return original_policy.rules != _canonical_rules(candidate_rules)


def build_changed_programme_scope_policy(
    original_policy: ProgrammeScopePolicy,
    candidate_rules: tuple[ProgrammeScopeRule, ...],
    *,
    updated_at: str | None = None,
) -> ProgrammeScopePolicy:
    """Build a changed policy, or return the original object for an exact no-op."""

    _require_policy(original_policy)
    canonical = _canonical_rules(candidate_rules)
    if canonical == original_policy.rules:
        return original_policy
    if updated_at is None:
        raise ValueError(
            "A canonical timestamp is required for a changed programme scope policy."
        )
    return build_programme_scope_policy(
        canonical,
        schema_version=PROGRAMME_SCOPE_SCHEMA_VERSION,
        engagement_context=original_policy.engagement_context,
        updated_at=updated_at,
    )


def render_programme_scope_local_summary(
    project: BugSlyceProject,
    policy: ProgrammeScopePolicy,
) -> str:
    """Render canonical scope values for a private local operator review."""

    if not isinstance(project, BugSlyceProject):
        raise ValueError("Programme scope summary requires a canonical project.")
    if project.engagement_context != BUG_BOUNTY_CONTEXT:
        raise ValueError("Programme scope policies are configured for bug bounty projects.")
    _require_policy(policy)

    include_count = sum(rule.action == ACTION_INCLUDE for rule in policy.rules)
    exclude_count = sum(rule.action == ACTION_EXCLUDE for rule in policy.rules)
    kind_counts = {
        kind: sum(rule.kind == kind for rule in policy.rules)
        for kind in PROGRAMME_SCOPE_RULE_KIND_ORDER
    }
    lines = [
        "Programme scope - private local operator view",
        f"Project: {project.name}",
        f"Engagement context: {project.engagement_context}",
        f"Schema version: {policy.schema_version}",
        f"Updated at: {policy.updated_at}",
        (
            f"Rules: {len(policy.rules)} total; {include_count} include; "
            f"{exclude_count} exclude"
        ),
        "Rule counts by kind:",
    ]
    lines.extend(f"- {kind}: {kind_counts[kind]}" for kind in PROGRAMME_SCOPE_RULE_KIND_ORDER)
    if policy.rules:
        lines.append("Canonical rules:")
        lines.extend(f"- {_safe_rule(rule)}" for rule in policy.rules)
    else:
        lines.append("Canonical rules: none")
    lines.extend(
        (
            "Programme scope is default-deny: destinations without an inclusion "
            "are not authorised.",
            "Explicit exclusions override every inclusion.",
            "Runtime programme-scope enforcement is active for strict Standard and Deep project pipelines.",
            "Stored configuration authorises traffic only after engagement-policy readiness and target evaluation.",
        )
    )
    return "\n".join(lines)


def _canonical_rules(
    rules: tuple[ProgrammeScopeRule, ...],
) -> tuple[ProgrammeScopeRule, ...]:
    if not isinstance(rules, tuple):
        raise ValueError("Programme scope rules must be an immutable tuple.")
    for rule in rules:
        _require_rule(rule)
    return build_programme_scope_policy(
        rules,
        updated_at=_CANONICALISATION_TIMESTAMP,
    ).rules


def _rule_index(rules: tuple[ProgrammeScopeRule, ...], rule_id: str) -> int:
    canonical_id = validate_rule_id(rule_id)
    for index, rule in enumerate(rules):
        if rule.rule_id.casefold() == canonical_id.casefold():
            return index
    raise ValueError("Programme scope rule does not exist.")


def _require_rule(rule: ProgrammeScopeRule) -> None:
    if not isinstance(rule, ProgrammeScopeRule):
        raise ValueError("Programme scope edits require canonical rule objects.")


def _require_policy(policy: ProgrammeScopePolicy) -> None:
    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("Programme scope management requires a canonical policy.")


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
