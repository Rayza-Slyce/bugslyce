"""Presentation-only labels for immutable C2 analysis-coverage items."""

from __future__ import annotations

from dataclasses import dataclass

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


def build_analysis_coverage_presentation(
    view: AnalysisCoverageView,
) -> tuple[AnalysisCoveragePresentationItem, ...]:
    """Project supplied C2 items in their existing deterministic order."""

    return tuple(_present(item) for item in view.items)


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
