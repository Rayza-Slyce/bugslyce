"""Pure structured bulk capture for canonical programme-scope rule drafts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopeRule,
    build_programme_scope_rule,
)


MAX_BULK_SCOPE_INPUT_CHARS = 1024 * 1024
MAX_BULK_SCOPE_LINES = 10_000

_TYPE_TO_KIND = {
    "hostname": RULE_EXACT_HOSTNAME,
    "wildcard": RULE_WILDCARD_SUBDOMAIN,
    "url": RULE_EXACT_HTTP_URL,
    "path": RULE_HTTP_PATH_PREFIX,
    "ipv4": RULE_EXACT_IPV4,
    "cidr": RULE_IPV4_CIDR,
}
_ACTIONS = frozenset({ACTION_INCLUDE, ACTION_EXCLUDE})
_OPTIONS = frozenset({"scheme", "port"})
_ID_COMPONENT = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class ProgrammeScopeBulkDraft:
    """One immutable, canonical, unsaved programme-scope bulk draft."""

    rules: tuple[ProgrammeScopeRule, ...]
    duplicate_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, ProgrammeScopeRule) for rule in self.rules
        ):
            raise ValueError("Bulk programme-scope draft rules must be canonical.")
        if (
            isinstance(self.duplicate_count, bool)
            or not isinstance(self.duplicate_count, int)
            or self.duplicate_count < 0
        ):
            raise ValueError("Bulk programme-scope duplicate count is invalid.")


def build_programme_scope_bulk_draft(text: object) -> ProgrammeScopeBulkDraft:
    """Parse explicit structured lines into one atomic canonical draft."""

    if not isinstance(text, str):
        raise ValueError("Bulk programme-scope input must be text.")
    if len(text) > MAX_BULK_SCOPE_INPUT_CHARS:
        raise ValueError("Bulk programme-scope input exceeds the technical size limit.")
    lines = text.splitlines()
    if len(lines) > MAX_BULK_SCOPE_LINES:
        raise ValueError("Bulk programme-scope input exceeds the technical line limit.")

    canonical_by_semantics: dict[tuple[object, ...], ProgrammeScopeRule] = {}
    duplicate_count = 0
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            candidate = _parse_rule_line(line)
        except ValueError as exc:
            raise ValueError(
                f"Bulk programme-scope line {line_number} is invalid: {exc}"
            ) from None
        semantics = _semantic_key(candidate)
        if semantics in canonical_by_semantics:
            duplicate_count += 1
            continue
        canonical_by_semantics[semantics] = candidate

    rules = tuple(
        _rule_with_generated_id(canonical_by_semantics[semantics], semantics)
        for semantics in sorted(canonical_by_semantics, key=_semantic_sort_key)
    )
    _require_unique_generated_ids(rules)
    return ProgrammeScopeBulkDraft(
        rules=tuple(sorted(rules, key=lambda rule: (rule.rule_id.casefold(), rule.rule_id))),
        duplicate_count=duplicate_count,
    )


def _parse_rule_line(line: str) -> ProgrammeScopeRule:
    tokens = line.split()
    if len(tokens) < 3:
        raise ValueError(
            "expected: include|exclude type value [scheme=http|https] [port=1-65535]."
        )
    action, type_name, value, *option_tokens = tokens
    if action not in _ACTIONS:
        raise ValueError("action must be include or exclude.")
    kind = _TYPE_TO_KIND.get(type_name)
    if kind is None:
        raise ValueError("rule type is unsupported.")

    options: dict[str, object] = {}
    for token in option_tokens:
        if token.count("=") != 1:
            raise ValueError("options must use one explicit name=value token.")
        name, option_value = token.split("=", 1)
        if name not in _OPTIONS:
            raise ValueError("option is unsupported.")
        if name in options:
            raise ValueError("option must not be repeated.")
        if not option_value:
            raise ValueError("option value must not be empty.")
        if name == "port":
            if not option_value.isascii() or not option_value.isdecimal():
                raise ValueError("port option must be an integer within 1-65535.")
            options[name] = int(option_value)
        else:
            options[name] = option_value

    return build_programme_scope_rule(
        rule_id="bulk-candidate",
        action=action,
        kind=kind,
        value=value,
        scheme=options.get("scheme"),
        port=options.get("port"),
    )


def _semantic_key(rule: ProgrammeScopeRule) -> tuple[object, ...]:
    return (
        rule.action,
        rule.kind,
        rule.canonical_value,
        rule.scheme,
        rule.port,
    )


def _semantic_sort_key(semantics: tuple[object, ...]) -> tuple[str, ...]:
    return tuple("" if value is None else str(value) for value in semantics)


def _rule_with_generated_id(
    candidate: ProgrammeScopeRule,
    semantics: tuple[object, ...],
) -> ProgrammeScopeRule:
    return build_programme_scope_rule(
        rule_id=_generated_rule_id(candidate, semantics),
        action=candidate.action,
        kind=candidate.kind,
        value=candidate.canonical_value,
        scheme=candidate.scheme,
        port=candidate.port,
    )


def _generated_rule_id(
    rule: ProgrammeScopeRule,
    semantics: tuple[object, ...],
) -> str:
    action = "inc" if rule.action == ACTION_INCLUDE else "exc"
    kind = _ID_COMPONENT.sub("-", rule.kind.lower()).strip("-")[:20]
    encoded = json.dumps(
        semantics,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    return f"scope-{action}-{kind}-{digest}"


def _require_unique_generated_ids(rules: tuple[ProgrammeScopeRule, ...]) -> None:
    ids: dict[str, tuple[object, ...]] = {}
    for rule in rules:
        folded = rule.rule_id.casefold()
        semantics = _semantic_key(rule)
        previous = ids.get(folded)
        if previous is not None and previous != semantics:
            raise ValueError(
                "Generated programme-scope rule ID collision requires explicit review."
            )
        ids[folded] = semantics
