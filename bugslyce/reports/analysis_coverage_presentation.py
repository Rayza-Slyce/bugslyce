"""Presentation-only labels for immutable C2 analysis-coverage items."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace

from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionNote,
    AnalysisCoverageItem,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnknownReason,
    AnalysisCoverageView,
)


@dataclass(frozen=True)
class AnalysisCoveragePresentationItem:
    """One renderer-ready projection of an existing C2 coverage item."""

    item: AnalysisCoverageItem
    state_label: str
    unknown_reason_label: str | None
    execution_note_label: str | None

    @property
    def finding_count_label(self) -> str | None:
        count = self.item.finding_count
        if (
            self.item.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
            and count is not None
        ):
            noun = "finding" if count == 1 else "findings"
            return f"{count} {noun}"
        return None


@dataclass(frozen=True)
class AnalysisCoveragePresentationGroup:
    """Human synthesis of items sharing one exact epistemic state."""

    items: tuple[AnalysisCoveragePresentationItem, ...]
    capability: str
    source_role: str
    state: AnalysisCoverageState
    outcome: AnalysisCoverageOutcome | None
    unknown_reason: AnalysisCoverageUnknownReason | None
    execution_note: AnalysisCoverageExecutionNote | None
    capability_label: str
    state_label: str
    unknown_reason_label: str | None
    execution_note_label: str | None
    human_summary: str

    @property
    def source_count(self) -> int:
        return len(self.items)

    @property
    def total_finding_count(self) -> int | None:
        values = tuple(item.item.finding_count for item in self.items)
        if any(value is None for value in values):
            return None
        return sum(value for value in values if value is not None)


def build_analysis_coverage_presentation(
    view: AnalysisCoverageView,
) -> tuple[AnalysisCoveragePresentationItem, ...]:
    """Project supplied C2 items in their existing deterministic order."""

    return tuple(_present(item) for item in view.items)


def build_analysis_coverage_grouped_presentation(
    view: AnalysisCoverageView,
) -> tuple[AnalysisCoveragePresentationGroup, ...]:
    """Group only records with identical capability and epistemic state."""

    grouped: dict[tuple[object, ...], list[AnalysisCoveragePresentationItem]] = (
        defaultdict(list)
    )
    for item in build_analysis_coverage_presentation(view):
        value = item.item
        grouped[
            (
                value.unit.capability,
                value.unit.source_role,
                value.state,
                value.outcome,
                value.unknown_reason,
                value.execution_note,
            )
        ].append(item)

    results = []
    for key, items in grouped.items():
        capability, source_role, state, outcome, unknown_reason, execution_note = key
        ordered = tuple(sorted(items, key=lambda item: item.item.unit.source_id))
        first = ordered[0]
        group = AnalysisCoveragePresentationGroup(
            items=ordered,
            capability=capability,
            source_role=source_role,
            state=state,
            outcome=outcome,
            unknown_reason=unknown_reason,
            execution_note=execution_note,
            capability_label=_capability_label(capability),
            state_label=first.state_label,
            unknown_reason_label=first.unknown_reason_label,
            execution_note_label=first.execution_note_label,
            human_summary="",
        )
        results.append(replace(group, human_summary=_group_summary(group)))
    return tuple(sorted(results, key=_group_sort_key))


def _group_summary(group: AnalysisCoveragePresentationGroup) -> str:
    count = group.source_count
    if (
        group.capability == "deep_javascript_route_extraction"
        and group.source_role == "deep_source_response"
        and group.state is AnalysisCoverageState.ANALYSED
        and group.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
        and group.total_finding_count is not None
    ):
        source = "source was" if count == 1 else "sources were"
        finding_count = group.total_finding_count
        finding = "finding" if finding_count == 1 else "findings"
        return (
            f"{count} retained JavaScript {source} analysed and produced "
            f"{finding_count} source-attributed route {finding}."
        )
    source = "source" if count == 1 else "sources"
    return (
        f"{count} {_human_label(group.source_role)} {source}: "
        f"{group.state_label}."
    )


def _group_sort_key(group: AnalysisCoveragePresentationGroup) -> tuple[str, ...]:
    return (
        group.capability,
        group.source_role,
        group.state.value,
        group.outcome.value if group.outcome is not None else "",
        group.unknown_reason.value if group.unknown_reason is not None else "",
        group.execution_note.value if group.execution_note is not None else "",
    )


def _human_label(value: str) -> str:
    return value.replace("_", " ").strip().capitalize()


def _capability_label(value: str) -> str:
    if value == "deep_javascript_route_extraction":
        return "JavaScript route analysis"
    return _human_label(value)


def _present(item: AnalysisCoverageItem) -> AnalysisCoveragePresentationItem:
    return AnalysisCoveragePresentationItem(
        item=item,
        state_label=_state_label(item),
        unknown_reason_label=_unknown_reason_label(item.unknown_reason),
        execution_note_label=_execution_note_label(item.execution_note),
    )


def _state_label(item: AnalysisCoverageItem) -> str:
    labels = {
        (AnalysisCoverageState.ANALYSED, AnalysisCoverageOutcome.FINDING_PRESENT): (
            "Analysed · Finding present"
        ),
        (AnalysisCoverageState.ANALYSED, AnalysisCoverageOutcome.NO_FINDING): (
            "Analysed · No finding"
        ),
        (AnalysisCoverageState.NOT_RUN, AnalysisCoverageOutcome.UNSUPPORTED): (
            "Not run · Unsupported"
        ),
        (AnalysisCoverageState.NOT_RUN, AnalysisCoverageOutcome.BOUNDED_SKIPPED): (
            "Not run · Bounded skip"
        ),
        (AnalysisCoverageState.NOT_RUN, AnalysisCoverageOutcome.NOT_COLLECTED): (
            "Not run · Input not collected"
        ),
        (AnalysisCoverageState.NOT_RUN, AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE): (
            "Not run · Not applicable"
        ),
        (AnalysisCoverageState.INCOMPLETE, AnalysisCoverageOutcome.PARTIAL_FAILED): (
            "Incomplete · Partial/failed"
        ),
        (AnalysisCoverageState.UNKNOWN, None): "Unknown",
    }
    return labels.get(
        (item.state, item.outcome),
        "Unrecognised coverage state",
    )


def _unknown_reason_label(
    reason: AnalysisCoverageUnknownReason | None,
) -> str | None:
    labels = {
        AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF: (
            "Exact execution proof unavailable"
        ),
        AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF: (
            "Conflicting exact execution proof"
        ),
    }
    if reason is None:
        return None
    return labels.get(reason, f"Unrecognised unknown reason: {reason.value}")


def _execution_note_label(
    note: AnalysisCoverageExecutionNote | None,
) -> str | None:
    labels = {
        AnalysisCoverageExecutionNote.REUSED_COMPLETED_RESULT: (
            "Reused completed result"
        ),
    }
    if note is None:
        return None
    return labels.get(note, f"Unrecognised execution note: {note.value}")
