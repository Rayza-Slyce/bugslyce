"""Immutable, report-only analysis-coverage derivation from explicit proofs.

This module deliberately does not infer execution from missing output or an
aggregate count.  Callers may supply explicit execution evidence and narrow
adapters for current result models whose positive provenance is attributable.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteExtractionResult,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteExtractionResult,
)
from bugslyce.recon.deep_parameter_inventory import DeepParameterInventoryResult
from bugslyce.recon.deep_post_followup_javascript_route_extraction import (
    DeepPostFollowupJavaScriptRouteExtractionResult,
)


class AnalysisCoverageState(str, Enum):
    """Top-level coverage state with no implied finding significance."""

    ANALYSED = "analysed"
    NOT_RUN = "not_run"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


class AnalysisCoverageOutcome(str, Enum):
    """Qualified outcome or explicit reason for a coverage state."""

    FINDING_PRESENT = "finding_present"
    NO_FINDING = "no_finding"
    UNSUPPORTED = "unsupported"
    BOUNDED_SKIPPED = "bounded_skipped"
    NOT_COLLECTED = "not_collected"
    NO_OP_NOT_APPLICABLE = "no_op_not_applicable"
    PARTIAL_FAILED = "partial_failed"


class AnalysisCoverageExecutionNote(str, Enum):
    """Optional execution provenance that does not change coverage state."""

    REUSED_COMPLETED_RESULT = "reused_completed_result"


class AnalysisCoverageUnknownReason(str, Enum):
    """Small fail-closed explanation for an otherwise unqualified unknown."""

    MISSING_EXACT_EXECUTION_PROOF = "missing_exact_execution_proof"
    CONFLICTING_EXACT_EXECUTION_PROOF = "conflicting_exact_execution_proof"


@dataclass(frozen=True)
class AnalysisCoverageUnit:
    """One current, report-only analyser/source identity.

    The identity is supplied from existing model identifiers.  It is not an
    execution record and it does not mint a persisted identifier.
    """

    capability: str
    source_role: str
    source_id: str

    def __post_init__(self) -> None:
        if not all((self.capability.strip(), self.source_role.strip(), self.source_id.strip())):
            raise ValueError("Analysis coverage units require capability, source role, and source ID.")


@dataclass(frozen=True)
class AnalysisCoverageExecutionEvidence:
    """Explicit, already-known execution proof for one report-only unit.

    This value is intentionally separate from authoritative recon models.  It
    permits adapters to express only proof already present in those models and
    lets a caller preserve an explicit pipeline no-op or partial failure without
    treating absence as evidence.
    """

    unit: AnalysisCoverageUnit
    input_membership_proven: bool = False
    invocation_proven: bool = False
    completed: bool = False
    finding_count: int | None = None
    finding_identity: str = ""
    not_run_outcome: AnalysisCoverageOutcome | None = None
    attempted: bool = False
    partial_failure: bool = False
    reused_completed_result: bool = False

    def __post_init__(self) -> None:
        if self.finding_count is not None and self.finding_count < 0:
            raise ValueError("Analysis coverage finding counts cannot be negative.")
        if self.not_run_outcome not in {
            None,
            AnalysisCoverageOutcome.UNSUPPORTED,
            AnalysisCoverageOutcome.BOUNDED_SKIPPED,
            AnalysisCoverageOutcome.NOT_COLLECTED,
            AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
        }:
            raise ValueError("Only explicit not-run outcomes are valid here.")
        if self.finding_count and not self.finding_identity.strip():
            raise ValueError("Positive finding coverage requires an exact finding identity.")
        if self.not_run_outcome is not None and any(
            (
                self.invocation_proven,
                self.completed,
                self.finding_count is not None,
                self.attempted,
                self.partial_failure,
                self.reused_completed_result,
            )
        ):
            raise ValueError("Not-run coverage cannot also claim execution evidence.")
        if self.partial_failure and (
            not self.attempted
            or self.completed
            or self.finding_count is not None
            or self.reused_completed_result
        ):
            raise ValueError("Partial-failed coverage requires attempted incomplete execution.")
        if self.reused_completed_result and not (
            self.input_membership_proven
            and self.invocation_proven
            and self.completed
            and self.finding_count is not None
        ):
            raise ValueError("Reuse provenance requires a completed exact result.")


@dataclass(frozen=True)
class AnalysisCoverageItem:
    """One immutable coverage result derived from current structured proof."""

    unit: AnalysisCoverageUnit
    state: AnalysisCoverageState
    outcome: AnalysisCoverageOutcome | None = None
    finding_count: int | None = None
    execution_note: AnalysisCoverageExecutionNote | None = None
    unknown_reason: AnalysisCoverageUnknownReason | None = None

    def __post_init__(self) -> None:
        if self.state is AnalysisCoverageState.ANALYSED:
            if self.outcome not in {
                AnalysisCoverageOutcome.FINDING_PRESENT,
                AnalysisCoverageOutcome.NO_FINDING,
            }:
                raise ValueError("Analysed coverage requires a finding outcome.")
            if self.finding_count is None or self.finding_count < 0:
                raise ValueError("Analysed coverage requires an exact finding count.")
            if (
                self.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
                and self.finding_count == 0
            ):
                raise ValueError("Finding-present coverage requires a positive count.")
            if (
                self.outcome is AnalysisCoverageOutcome.NO_FINDING
                and self.finding_count != 0
            ):
                raise ValueError("No-finding coverage requires a zero count.")
            if self.unknown_reason is not None:
                raise ValueError("Analysed coverage cannot carry an unknown reason.")
            return
        if self.state is AnalysisCoverageState.NOT_RUN:
            if self.outcome not in {
                AnalysisCoverageOutcome.UNSUPPORTED,
                AnalysisCoverageOutcome.BOUNDED_SKIPPED,
                AnalysisCoverageOutcome.NOT_COLLECTED,
                AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
            }:
                raise ValueError("Not-run coverage requires an explicit not-run outcome.")
        elif self.state is AnalysisCoverageState.INCOMPLETE:
            if self.outcome is not AnalysisCoverageOutcome.PARTIAL_FAILED:
                raise ValueError("Incomplete coverage requires partial-failed outcome.")
        elif self.state is AnalysisCoverageState.UNKNOWN:
            if self.outcome is not None or self.unknown_reason is None:
                raise ValueError("Unknown coverage requires no outcome and an unknown reason.")
        else:
            raise ValueError("Unsupported analysis coverage state.")
        if self.finding_count is not None or self.execution_note is not None:
            raise ValueError("Only analysed coverage may carry findings or reuse provenance.")


@dataclass(frozen=True)
class AnalysisCoverageView:
    """Sparse, deterministic report-only analysis coverage rows."""

    items: tuple[AnalysisCoverageItem, ...]


def build_analysis_coverage(
    evidence: Iterable[AnalysisCoverageExecutionEvidence],
) -> AnalysisCoverageView:
    """Derive sparse coverage only from exact structured execution proof.

    Records for the same unit are combined only when their definitive outcomes
    agree.  Exact duplicate proof is ignored.  Conflict fails closed to
    ``UNKNOWN`` rather than asserting a clean result.
    """

    grouped: dict[AnalysisCoverageUnit, set[AnalysisCoverageExecutionEvidence]] = (
        defaultdict(set)
    )
    for item in evidence:
        grouped[item.unit].add(item)
    return AnalysisCoverageView(
        items=tuple(
            sorted(
                (_coverage_item(unit, proofs) for unit, proofs in grouped.items()),
                key=_item_sort_key,
            )
        )
    )


def coverage_evidence_from_deep_javascript_routes(
    result: DeepJavaScriptRouteExtractionResult,
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    """Return attributable positive coverage from existing Deep JS candidates.

    A candidate's source-response IDs prove that source produced an accepted
    route.  The result does not retain per-source zero-result invocation logs,
    so this adapter deliberately emits no clean coverage rows.
    """

    findings: list[AnalysisCoverageExecutionEvidence] = []
    for candidate in result.candidates:
        for source_id in candidate.source_response_ids:
            findings.append(
                _finding_evidence(
                    "deep_javascript_route_extraction",
                    "deep_source_response",
                    source_id,
                    candidate.candidate_id,
                )
            )
    return _ordered_evidence(findings)


def coverage_evidence_from_initial_retained_javascript_routes(
    result: DeepInitialRetainedJavaScriptRouteExtractionResult,
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    """Return attributable positive coverage for retained initial HTML only."""

    findings: list[AnalysisCoverageExecutionEvidence] = []
    for candidate in result.candidates:
        for source in candidate.source_observations:
            findings.append(
                _finding_evidence(
                    "deep_initial_retained_javascript_route_extraction",
                    source.source_role,
                    source.source_id,
                    candidate.candidate_id,
                )
            )
    return _ordered_evidence(findings)


def coverage_evidence_from_post_followup_javascript_routes(
    result: DeepPostFollowupJavaScriptRouteExtractionResult,
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    """Return attributable positive coverage for retained shallow responses."""

    findings: list[AnalysisCoverageExecutionEvidence] = []
    for candidate in result.candidates:
        for source in candidate.source_observations:
            findings.append(
                _finding_evidence(
                    "deep_post_followup_javascript_route_extraction",
                    "deep_shallow_response",
                    source.shallow_request_id,
                    candidate.candidate_id,
                )
            )
    return _ordered_evidence(findings)


def coverage_evidence_from_deep_parameter_inventory(
    result: DeepParameterInventoryResult,
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    """Return positive parameter coverage from authoritative observations.

    Parameter observations preserve the exact source relationship.  Each row
    therefore reflects a represented parameter observation only; a parameter
    absent from the aggregate is never treated as a clean source result.
    """

    findings: list[AnalysisCoverageExecutionEvidence] = []
    for parameter in result.parameters:
        for observation in parameter.observations:
            for source_role, source_id in _parameter_observation_units(observation):
                findings.append(
                    _finding_evidence(
                        "deep_parameter_inventory",
                        source_role,
                        source_id,
                        _parameter_finding_identity(
                            observation,
                            source_role,
                            source_id,
                        ),
                    )
                )
    return _ordered_evidence(findings)


def coverage_evidence_from_pipeline_steps(
    steps: Iterable[object],
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    """Return only explicit no-op and failed pipeline-stage coverage.

    Current pipeline records make a failed step and a policy-approved no-op
    attributable to their exact stage.  A completed stage alone does not expose
    a per-source finding result, and dependency-skipped or reused stages do not
    establish one of the approved not-run outcomes, so they are intentionally
    omitted here.
    """

    evidence: list[AnalysisCoverageExecutionEvidence] = []
    for step in steps:
        step_id = getattr(step, "step_id", "")
        command_kind = getattr(step, "command_kind", "")
        status = getattr(step, "status", "")
        if not isinstance(step_id, str) or not isinstance(command_kind, str):
            continue
        if not step_id or not command_kind:
            continue
        unit = AnalysisCoverageUnit("project_pipeline_step", command_kind, step_id)
        if status == "failed":
            evidence.append(
                AnalysisCoverageExecutionEvidence(
                    unit=unit,
                    attempted=True,
                    partial_failure=True,
                )
            )
        elif status == "noop":
            evidence.append(
                AnalysisCoverageExecutionEvidence(
                    unit=unit,
                    not_run_outcome=AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
                )
            )
    return _ordered_evidence(evidence)


def _coverage_item(
    unit: AnalysisCoverageUnit,
    proofs: set[AnalysisCoverageExecutionEvidence],
) -> AnalysisCoverageItem:
    definitive = tuple(
        sorted(
            (_definitive_item(item) for item in proofs),
            key=_definitive_sort_key,
        )
    )
    non_unknown = tuple(
        item for item in definitive if item.state is not AnalysisCoverageState.UNKNOWN
    )
    if not non_unknown:
        return AnalysisCoverageItem(
            unit=unit,
            state=AnalysisCoverageState.UNKNOWN,
            unknown_reason=AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF,
        )
    states = {(item.state, item.outcome) for item in non_unknown}
    if len(states) != 1:
        return AnalysisCoverageItem(
            unit=unit,
            state=AnalysisCoverageState.UNKNOWN,
            unknown_reason=AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF,
        )
    first = non_unknown[0]
    if first.state is not AnalysisCoverageState.ANALYSED:
        return first
    if (
        first.outcome is AnalysisCoverageOutcome.FINDING_PRESENT
        and _has_conflicting_finding_counts(proofs)
    ):
        return AnalysisCoverageItem(
            unit=unit,
            state=AnalysisCoverageState.UNKNOWN,
            unknown_reason=AnalysisCoverageUnknownReason.CONFLICTING_EXACT_EXECUTION_PROOF,
        )
    finding_count = _merged_finding_count(proofs, first.outcome)
    return AnalysisCoverageItem(
        unit=unit,
        state=AnalysisCoverageState.ANALYSED,
        outcome=first.outcome,
        finding_count=finding_count,
        execution_note=(
            AnalysisCoverageExecutionNote.REUSED_COMPLETED_RESULT
            if any(item.reused_completed_result for item in proofs)
            else None
        ),
    )


def _definitive_item(
    item: AnalysisCoverageExecutionEvidence,
) -> AnalysisCoverageItem:
    if item.not_run_outcome is not None:
        return AnalysisCoverageItem(
            unit=item.unit,
            state=AnalysisCoverageState.NOT_RUN,
            outcome=item.not_run_outcome,
        )
    if item.partial_failure and item.attempted:
        return AnalysisCoverageItem(
            unit=item.unit,
            state=AnalysisCoverageState.INCOMPLETE,
            outcome=AnalysisCoverageOutcome.PARTIAL_FAILED,
        )
    if (
        item.input_membership_proven
        and item.invocation_proven
        and item.completed
        and item.finding_count is not None
    ):
        return AnalysisCoverageItem(
            unit=item.unit,
            state=AnalysisCoverageState.ANALYSED,
            outcome=(
                AnalysisCoverageOutcome.FINDING_PRESENT
                if item.finding_count > 0
                else AnalysisCoverageOutcome.NO_FINDING
            ),
            finding_count=item.finding_count,
            execution_note=(
                AnalysisCoverageExecutionNote.REUSED_COMPLETED_RESULT
                if item.reused_completed_result
                else None
            ),
        )
    return AnalysisCoverageItem(
        unit=item.unit,
        state=AnalysisCoverageState.UNKNOWN,
        unknown_reason=AnalysisCoverageUnknownReason.MISSING_EXACT_EXECUTION_PROOF,
    )


def _merged_finding_count(
    proofs: Iterable[AnalysisCoverageExecutionEvidence],
    outcome: AnalysisCoverageOutcome | None,
) -> int:
    if outcome is AnalysisCoverageOutcome.NO_FINDING:
        return 0
    findings = {
        (item.finding_identity, item.finding_count)
        for item in proofs
        if (
            item.input_membership_proven
            and item.invocation_proven
            and item.completed
            and item.finding_count is not None
            and item.finding_count > 0
        )
    }
    return sum(count for _identity, count in findings)


def _has_conflicting_finding_counts(
    proofs: Iterable[AnalysisCoverageExecutionEvidence],
) -> bool:
    counts_by_identity: dict[str, set[int]] = defaultdict(set)
    for item in proofs:
        if (
            item.input_membership_proven
            and item.invocation_proven
            and item.completed
            and item.finding_count is not None
            and item.finding_count > 0
        ):
            counts_by_identity[item.finding_identity].add(item.finding_count)
    return any(len(counts) > 1 for counts in counts_by_identity.values())


def _finding_evidence(
    capability: str,
    source_role: str,
    source_id: str,
    finding_identity: str,
) -> AnalysisCoverageExecutionEvidence:
    return AnalysisCoverageExecutionEvidence(
        unit=AnalysisCoverageUnit(capability, source_role, source_id),
        input_membership_proven=True,
        invocation_proven=True,
        completed=True,
        finding_count=1,
        finding_identity=finding_identity,
    )


def _parameter_observation_units(observation) -> tuple[tuple[str, str], ...]:
    post_source = observation.post_followup_source_observation
    if post_source is not None and post_source.shallow_request_id:
        return (("deep_shallow_response", post_source.shallow_request_id),)
    initial_source = observation.initial_retained_source_observation
    if initial_source is not None and initial_source.source_id:
        return ((initial_source.source_role, initial_source.source_id),)
    if observation.source_response_ids:
        source_role = (
            "deep_source_response"
            if observation.source_kind in {"javascript_route", "html_route"}
            else observation.source_kind or observation.context
        )
        return tuple(
            (source_role, source_id)
            for source_id in observation.source_response_ids
            if source_id
        )
    if observation.source_id:
        return ((observation.source_kind or observation.context, observation.source_id),)
    return ()


def _parameter_finding_identity(
    observation,
    source_role: str,
    source_id: str,
) -> str:
    return "\x00".join(
        (
            observation.context,
            source_role,
            source_id,
            observation.safe_route_url,
            observation.javascript_candidate_reference,
            observation.post_followup_candidate_id,
            observation.initial_retained_candidate_id,
            observation.name,
        )
    )


def _ordered_evidence(
    evidence: Sequence[AnalysisCoverageExecutionEvidence],
) -> tuple[AnalysisCoverageExecutionEvidence, ...]:
    return tuple(sorted(set(evidence), key=_execution_sort_key))


def _execution_identity(item: AnalysisCoverageExecutionEvidence) -> tuple[object, ...]:
    return (
        item.unit,
        item.input_membership_proven,
        item.invocation_proven,
        item.completed,
        item.finding_count,
        item.finding_identity,
        item.not_run_outcome,
        item.attempted,
        item.partial_failure,
        item.reused_completed_result,
    )


def _item_sort_key(item: AnalysisCoverageItem) -> tuple[str, str, str]:
    return (item.unit.capability, item.unit.source_role, item.unit.source_id)


def _execution_sort_key(item: AnalysisCoverageExecutionEvidence) -> tuple[object, ...]:
    return (
        item.unit.capability,
        item.unit.source_role,
        item.unit.source_id,
        item.finding_identity,
        item.finding_count if item.finding_count is not None else -1,
        item.not_run_outcome.value if item.not_run_outcome is not None else "",
        item.attempted,
        item.partial_failure,
        item.reused_completed_result,
    )


def _definitive_sort_key(item: AnalysisCoverageItem) -> tuple[str, str, int]:
    return (
        item.state.value,
        item.outcome.value if item.outcome is not None else "",
        item.finding_count if item.finding_count is not None else -1,
    )
