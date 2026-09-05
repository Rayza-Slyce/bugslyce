"""Pure, non-authoritative programme-scope proposal composition."""

from __future__ import annotations

from dataclasses import dataclass
import re

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    ProgrammeScopeRule,
    build_programme_scope_policy,
)


PROPOSAL_SOURCE_MANUAL = "manual"
MANUAL_PROPOSAL_SOURCE_ID = "structured-manual-entry"

_CANONICALISATION_TIMESTAMP = "1970-01-01T00:00:00Z"
_SOURCE_TYPE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_DISPLAY_TEXT = 4096


@dataclass(frozen=True)
class ProgrammeScopeProposalSource:
    """Identity of input used to prepare a proposal, not collection authority."""

    source_type: str
    source_id: str
    display_name: str

    def __post_init__(self) -> None:
        _validate_source_type(self.source_type)
        _validate_identifier(self.source_id, label="Proposal source ID")
        _validate_display_text(self.display_name, label="Proposal source name")


@dataclass(frozen=True)
class ProgrammeScopeProposalUnresolvedItem:
    """One source item that cannot become authority without further review."""

    item_id: str
    description: str

    def __post_init__(self) -> None:
        _validate_identifier(self.item_id, label="Unresolved proposal item ID")
        _validate_display_text(
            self.description,
            label="Unresolved proposal item description",
        )


@dataclass(frozen=True)
class ProgrammeScopeNonAuthorityContext:
    """Operator context deliberately separated from executable scope rules."""

    item_id: str
    label: str
    value: str

    def __post_init__(self) -> None:
        _validate_identifier(self.item_id, label="Non-authority context item ID")
        _validate_display_text(self.label, label="Non-authority context label")
        _validate_display_text(self.value, label="Non-authority context value")


@dataclass(frozen=True)
class ProgrammeScopeProposal:
    """Immutable review input that is not persisted programme authority."""

    source: ProgrammeScopeProposalSource
    rules: tuple[ProgrammeScopeRule, ...]
    unresolved_items: tuple[ProgrammeScopeProposalUnresolvedItem, ...]
    non_authority_context: tuple[ProgrammeScopeNonAuthorityContext, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, ProgrammeScopeProposalSource):
            raise ValueError("Programme scope proposal source is invalid.")
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, ProgrammeScopeRule) for rule in self.rules
        ):
            raise ValueError("Programme scope proposal rules must be canonical.")
        if self.rules != _canonical_rules(self.rules):
            raise ValueError("Programme scope proposal rules are not deterministic.")
        if not isinstance(self.unresolved_items, tuple) or any(
            not isinstance(item, ProgrammeScopeProposalUnresolvedItem)
            for item in self.unresolved_items
        ):
            raise ValueError("Programme scope unresolved items are invalid.")
        if self.unresolved_items != _ordered_items(self.unresolved_items):
            raise ValueError("Programme scope unresolved items are not deterministic.")
        if not isinstance(self.non_authority_context, tuple) or any(
            not isinstance(item, ProgrammeScopeNonAuthorityContext)
            for item in self.non_authority_context
        ):
            raise ValueError("Programme scope non-authority context is invalid.")
        if self.non_authority_context != _ordered_items(self.non_authority_context):
            raise ValueError(
                "Programme scope non-authority context is not deterministic."
            )
        _require_unique_review_item_ids(
            self.unresolved_items,
            self.non_authority_context,
        )


def build_programme_scope_proposal_source(
    *,
    source_type: object,
    source_id: object,
    display_name: object,
) -> ProgrammeScopeProposalSource:
    """Build one validated, non-authoritative proposal source identity."""

    if not all(isinstance(value, str) for value in (source_type, source_id, display_name)):
        raise ValueError("Programme scope proposal source fields must be text.")
    return ProgrammeScopeProposalSource(
        source_type=source_type,
        source_id=source_id,
        display_name=display_name,
    )


def build_programme_scope_proposal(
    *,
    source: ProgrammeScopeProposalSource,
    rules: tuple[ProgrammeScopeRule, ...] | list[ProgrammeScopeRule],
    unresolved_items: (
        tuple[ProgrammeScopeProposalUnresolvedItem, ...]
        | list[ProgrammeScopeProposalUnresolvedItem]
    ) = (),
    non_authority_context: (
        tuple[ProgrammeScopeNonAuthorityContext, ...]
        | list[ProgrammeScopeNonAuthorityContext]
    ) = (),
) -> ProgrammeScopeProposal:
    """Build one deterministic proposal without creating or persisting authority."""

    if not isinstance(source, ProgrammeScopeProposalSource):
        raise ValueError("Programme scope proposal source is invalid.")
    canonical_rules = _canonical_rules(_require_collection(rules, label="rules"))
    unresolved = _require_collection(unresolved_items, label="unresolved items")
    context = _require_collection(
        non_authority_context,
        label="non-authority context",
    )
    if any(
        not isinstance(item, ProgrammeScopeProposalUnresolvedItem)
        for item in unresolved
    ):
        raise ValueError("Programme scope unresolved items are invalid.")
    if any(not isinstance(item, ProgrammeScopeNonAuthorityContext) for item in context):
        raise ValueError("Programme scope non-authority context is invalid.")
    return ProgrammeScopeProposal(
        source=source,
        rules=canonical_rules,
        unresolved_items=_ordered_items(unresolved),
        non_authority_context=_ordered_items(context),
    )


def build_manual_programme_scope_proposal(
    rules: tuple[ProgrammeScopeRule, ...] | list[ProgrammeScopeRule],
) -> ProgrammeScopeProposal:
    """Adapt existing structured manual rules to the shared proposal boundary."""

    return build_programme_scope_proposal(
        source=build_programme_scope_proposal_source(
            source_type=PROPOSAL_SOURCE_MANUAL,
            source_id=MANUAL_PROPOSAL_SOURCE_ID,
            display_name="Structured manual entry",
        ),
        rules=rules,
    )


def render_programme_scope_proposal_review(
    proposal: ProgrammeScopeProposal,
) -> str:
    """Render a privacy-safe authority proposal for explicit human review."""

    if not isinstance(proposal, ProgrammeScopeProposal):
        raise ValueError("Programme scope proposal review requires a proposal.")
    inclusions = tuple(rule for rule in proposal.rules if rule.action == ACTION_INCLUDE)
    exclusions = tuple(rule for rule in proposal.rules if rule.action == ACTION_EXCLUDE)
    lines = [
        "Programme scope proposal - private local operator review",
        f"Source: {proposal.source.display_name}",
        f"Source type: {proposal.source.source_type}",
        f"Source identity: {proposal.source.source_id}",
        (
            f"Rules: {len(proposal.rules)} total; {len(inclusions)} include; "
            f"{len(exclusions)} exclude"
        ),
        "PROPOSED EXECUTABLE AUTHORITY",
        "INCLUDE",
    ]
    lines.extend(_render_rules(inclusions))
    lines.append("EXCLUDE")
    lines.extend(_render_rules(exclusions))
    lines.append("UNRESOLVED / REQUIRES REVIEW")
    lines.extend(
        (f"- {item.item_id}: {item.description}" for item in proposal.unresolved_items),
    )
    if not proposal.unresolved_items:
        lines.append("- none")
    lines.append("NON-AUTHORITY CONTEXT")
    lines.extend(
        (
            f"- {item.item_id} | {item.label}: {item.value}"
            for item in proposal.non_authority_context
        ),
    )
    if not proposal.non_authority_context:
        lines.append("- none")
    lines.extend(
        (
            "Default: DENY",
            "Narrower explicit scope rules may override broader rules; exclusions "
            "win equal or incomparable overlaps",
            "This proposal is not authority until explicitly confirmed and saved.",
        )
    )
    return "\n".join(lines)


def _canonical_rules(
    rules: tuple[ProgrammeScopeRule, ...],
) -> tuple[ProgrammeScopeRule, ...]:
    if any(not isinstance(rule, ProgrammeScopeRule) for rule in rules):
        raise ValueError("Programme scope proposal rules must be canonical.")
    return build_programme_scope_policy(
        rules,
        updated_at=_CANONICALISATION_TIMESTAMP,
    ).rules


def _ordered_items(items: tuple[object, ...]) -> tuple[object, ...]:
    return tuple(sorted(items, key=lambda item: (item.item_id.casefold(), item.item_id)))


def _require_collection(value: object, *, label: str) -> tuple:
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"Programme scope proposal {label} must be a collection.")
    return tuple(value)


def _require_unique_review_item_ids(
    unresolved: tuple[ProgrammeScopeProposalUnresolvedItem, ...],
    context: tuple[ProgrammeScopeNonAuthorityContext, ...],
) -> None:
    folded = tuple(item.item_id.casefold() for item in (*unresolved, *context))
    if len(folded) != len(set(folded)):
        raise ValueError(
            "Programme scope proposal review item IDs must be unique across categories."
        )


def _render_rules(rules: tuple[ProgrammeScopeRule, ...]) -> tuple[str, ...]:
    if not rules:
        return ("- none",)
    return tuple(f"- {_safe_rule(rule)}" for rule in rules)


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


def _validate_source_type(value: object) -> str:
    if not isinstance(value, str) or _SOURCE_TYPE.fullmatch(value) is None:
        raise ValueError("Programme scope proposal source type is invalid.")
    return value


def _validate_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid.")
    return value


def _validate_display_text(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_DISPLAY_TEXT
        or not value.isprintable()
    ):
        raise ValueError(f"{label} is invalid.")
    return value
