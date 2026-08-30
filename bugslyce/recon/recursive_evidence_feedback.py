"""Bounded depth-one collection from retained semantic route evidence.

This module adapts already-retained sitemap, HTML, and semantic JavaScript
evidence into one deterministic second-pass plan.  It does not crawl, infer
authority, persist artefacts, or provide an independent HTTP boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from bugslyce.core.models import Evidence, ProjectState
from bugslyce.core.programme_scope import (
    DESTINATION_HTTP_URL,
    OUTCOME_ALLOWED,
    OUTCOME_BLOCKED,
    canonicalise_http_url_destination,
    evaluate_raw_scope_destination,
)
from bugslyce.recon.content_run import (
    BASELINE_MAXIMUM_RESPONSE_BYTES,
    BASELINE_REQUEST_TIMEOUT_SECONDS,
)
from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult,
    DeepHtmlRouteReference,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteCandidate,
    DeepJavaScriptRouteExtractionResult,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.http_enforcement import (
    InternalHTTPExecutor,
    PeerBoundHTTPTransport,
    build_http_enforcement_configuration,
    internal_http_executors_share_enforcement_state,
)
from bugslyce.recon.javascript_semantic_context import (
    ACCEPTED_ROUTE_CONTEXTS,
    REQUEST_CALL,
    ROUTE_CONFIGURATION,
)
from bugslyce.recon.native_content_discovery import (
    MAXIMUM_NATIVE_CANDIDATE_REQUESTS,
    NativeContentDiscoveryPlan,
    NativeContentDiscoveryRequest,
    build_native_content_discovery_http_executor,
)
from bugslyce.recon.programme_orchestration import (
    ProgrammeOrchestrationPlan,
    require_programme_orchestration_plan_binding,
)
from bugslyce.recon.project_runtime import BugBountyProjectRuntime


SELECTION_SITEMAP_DECLARED = "sitemap_declared"
SELECTION_JAVASCRIPT_REQUEST_CALL = "javascript_request_call"
SELECTION_JAVASCRIPT_ROUTE_CONFIGURATION = "javascript_route_configuration"
SELECTION_HTML_ROUTE_REFERENCE = "html_route_reference"
SELECTION_PRIORITY = (
    SELECTION_SITEMAP_DECLARED,
    SELECTION_JAVASCRIPT_REQUEST_CALL,
    SELECTION_JAVASCRIPT_ROUTE_CONFIGURATION,
    SELECTION_HTML_ROUTE_REFERENCE,
)
_SELECTION_PRIORITY_INDEX = {
    value: index for index, value in enumerate(SELECTION_PRIORITY)
}

OUTCOME_SELECTED = "selected"
OUTCOME_SUPPRESSED = "suppressed"
REASON_SELECTED = "selected_for_bounded_second_pass"
REASON_DEPTH_EXHAUSTED = "depth_exhausted"
REASON_ALREADY_COLLECTED = "already_collected"
REASON_QUERY_NOT_ALLOWED = "query_string_not_allowed"
REASON_MISSING_EVIDENCE = "missing_evidence_provenance"
REASON_EVIDENCE_NOT_RETAINED = "evidence_not_retained"
REASON_SCOPE_BLOCKED = "programme_scope_blocked"
REASON_SCOPE_UNKNOWN = "programme_scope_unknown"
REASON_UNMATERIALISED_ORIGIN = "unmaterialised_origin"
REASON_PER_ORIGIN_LIMIT = "per_origin_limit_exceeded"
REASON_TOTAL_LIMIT = "total_request_limit_exceeded"


@dataclass(frozen=True)
class RecursiveEvidenceFeedbackLimits:
    """One coherent depth-one request budget across all evidence sources."""

    maximum_total_candidate_requests: int
    maximum_candidate_requests_per_origin: int
    maximum_depth: int

    def __post_init__(self) -> None:
        for value in (
            self.maximum_total_candidate_requests,
            self.maximum_candidate_requests_per_origin,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= MAXIMUM_NATIVE_CANDIDATE_REQUESTS
            ):
                raise ValueError("Recursive evidence feedback request budget is invalid.")
        if (
            isinstance(self.maximum_depth, bool)
            or not isinstance(self.maximum_depth, int)
            or self.maximum_depth != 1
        ):
            raise ValueError("Recursive evidence feedback maximum depth must equal 1.")


@dataclass(frozen=True)
class RecursiveEvidenceFeedbackDecision:
    """One machine-readable canonical candidate disposition."""

    url: str
    canonical_origin: str
    depth: int
    outcome: str
    reason: str
    evidence_ids: tuple[str, ...]
    selection_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url:
            raise ValueError("Recursive evidence feedback decision URL is invalid.")
        if not isinstance(self.canonical_origin, str) or not self.canonical_origin:
            raise ValueError("Recursive evidence feedback decision origin is invalid.")
        if isinstance(self.depth, bool) or not isinstance(self.depth, int) or self.depth < 0:
            raise ValueError("Recursive evidence feedback decision depth is invalid.")
        if self.outcome not in {OUTCOME_SELECTED, OUTCOME_SUPPRESSED}:
            raise ValueError("Recursive evidence feedback decision outcome is invalid.")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("Recursive evidence feedback decision reason is invalid.")
        _require_canonical_strings(self.evidence_ids, label="evidence IDs")
        _require_selection_reasons(self.selection_reasons)


@dataclass(frozen=True)
class RecursiveEvidenceFeedbackPlan:
    """Immutable canonical plan for one bounded recursive decision pass."""

    limits: RecursiveEvidenceFeedbackLimits
    maximum_depth: int
    source_depth: int
    baseline_requests_per_origin: int
    recursive_requests_planned: int
    budget_consumed: int
    budget_remaining: int
    requests: tuple[NativeContentDiscoveryRequest, ...]
    decisions: tuple[RecursiveEvidenceFeedbackDecision, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.limits, RecursiveEvidenceFeedbackLimits):
            raise ValueError("Recursive evidence feedback limits are invalid.")
        if self.maximum_depth != self.limits.maximum_depth:
            raise ValueError("Recursive evidence feedback maximum depth is inconsistent.")
        if (
            isinstance(self.source_depth, bool)
            or not isinstance(self.source_depth, int)
            or self.source_depth < 0
        ):
            raise ValueError("Recursive evidence feedback source depth is invalid.")
        if self.baseline_requests_per_origin != 0:
            raise ValueError("Recursive evidence feedback does not use baseline probes.")
        if (
            not isinstance(self.requests, tuple)
            or any(not isinstance(item, NativeContentDiscoveryRequest) for item in self.requests)
        ):
            raise ValueError("Recursive evidence feedback requests are invalid.")
        if (
            not isinstance(self.decisions, tuple)
            or any(
                not isinstance(item, RecursiveEvidenceFeedbackDecision)
                for item in self.decisions
            )
        ):
            raise ValueError("Recursive evidence feedback decisions are invalid.")
        if (
            isinstance(self.recursive_requests_planned, bool)
            or not isinstance(self.recursive_requests_planned, int)
            or self.recursive_requests_planned != len(self.requests)
        ):
            raise ValueError("Recursive evidence feedback request count is invalid.")
        if (
            isinstance(self.budget_consumed, bool)
            or not isinstance(self.budget_consumed, int)
            or self.budget_consumed != len(self.requests)
        ):
            raise ValueError("Recursive evidence feedback consumed budget is invalid.")
        if (
            isinstance(self.budget_remaining, bool)
            or not isinstance(self.budget_remaining, int)
            or self.budget_remaining
            != self.limits.maximum_total_candidate_requests - self.budget_consumed
        ):
            raise ValueError("Recursive evidence feedback remaining budget is invalid.")


@dataclass(frozen=True)
class RecursiveEvidenceFeedbackCollectedResponse:
    """One bounded response retaining its exact recursive request provenance."""

    request: NativeContentDiscoveryRequest
    status_code: int
    final_url: str
    headers: tuple[tuple[str, str], ...]
    body_bytes: int
    body_sha256: str
    elapsed_seconds: float
    evidence_ids: tuple[str, ...]
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class RecursiveEvidenceFeedbackResult:
    """In-memory depth-one collection result with no external commands."""

    external_commands_started: int
    requests_attempted: int
    budget_consumed: int
    budget_remaining: int
    collected: tuple[RecursiveEvidenceFeedbackCollectedResponse, ...]
    decisions: tuple[RecursiveEvidenceFeedbackDecision, ...]


@dataclass(frozen=True)
class _CandidateContribution:
    raw_url: str
    selection_reason: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class _AggregatedCandidate:
    url: str
    canonical_origin: str
    selection_reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    @property
    def primary_selection_reason(self) -> str:
        return self.selection_reasons[0]


def build_recursive_evidence_feedback_plan(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
    *,
    root_plan: NativeContentDiscoveryPlan,
    metadata_collection: DeepMetadataCollectionResult,
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
    source_depth: int,
    limits: RecursiveEvidenceFeedbackLimits,
) -> RecursiveEvidenceFeedbackPlan:
    """Build one deterministic depth-one plan without performing contact."""

    bound_orchestration = require_programme_orchestration_plan_binding(
        runtime,
        orchestration_plan,
        project_state=project_state,
    )
    if not isinstance(root_plan, NativeContentDiscoveryPlan):
        raise ValueError("Recursive evidence feedback root plan is invalid.")
    if not isinstance(limits, RecursiveEvidenceFeedbackLimits):
        raise ValueError("Recursive evidence feedback limits are invalid.")
    if (
        isinstance(source_depth, bool)
        or not isinstance(source_depth, int)
        or source_depth < 0
    ):
        raise ValueError("Recursive evidence feedback source depth is invalid.")
    _require_source_models(metadata_collection, html_extraction, javascript_extraction)

    retained_evidence_ids = _retained_project_evidence_ids(project_state)
    materialised_origins = frozenset(
        item.canonical_origin for item in bound_orchestration.http_work_items
    )
    already_collected = frozenset(
        _canonical_root_request_url(request) for request in root_plan.requests
    )
    candidates = _aggregate_candidates(
        metadata_collection,
        html_extraction,
        javascript_extraction,
    )

    requests: list[NativeContentDiscoveryRequest] = []
    decisions: list[RecursiveEvidenceFeedbackDecision] = []
    per_origin: dict[str, int] = {}
    candidate_depth = source_depth + 1
    for candidate in candidates:
        reason = _non_budget_stop_reason(
            candidate,
            candidate_depth=candidate_depth,
            limits=limits,
            retained_evidence_ids=retained_evidence_ids,
            already_collected=already_collected,
            programme_scope_policy=runtime.programme_scope_policy,
            materialised_origins=materialised_origins,
        )
        if reason is None:
            origin_count = per_origin.get(candidate.canonical_origin, 0)
            if origin_count >= limits.maximum_candidate_requests_per_origin:
                reason = REASON_PER_ORIGIN_LIMIT
            elif len(requests) >= limits.maximum_total_candidate_requests:
                reason = REASON_TOTAL_LIMIT

        if reason is not None:
            decisions.append(
                _decision(
                    candidate,
                    depth=candidate_depth,
                    outcome=OUTCOME_SUPPRESSED,
                    reason=reason,
                )
            )
            continue

        request = NativeContentDiscoveryRequest(
            url=candidate.url,
            canonical_origin=candidate.canonical_origin,
            depth=candidate_depth,
            selection_reason=candidate.primary_selection_reason,
            evidence_ids=candidate.evidence_ids,
        )
        requests.append(request)
        per_origin[candidate.canonical_origin] = (
            per_origin.get(candidate.canonical_origin, 0) + 1
        )
        decisions.append(
            _decision(
                candidate,
                depth=candidate_depth,
                outcome=OUTCOME_SELECTED,
                reason=REASON_SELECTED,
            )
        )

    return RecursiveEvidenceFeedbackPlan(
        limits=limits,
        maximum_depth=limits.maximum_depth,
        source_depth=source_depth,
        baseline_requests_per_origin=0,
        recursive_requests_planned=len(requests),
        budget_consumed=len(requests),
        budget_remaining=limits.maximum_total_candidate_requests - len(requests),
        requests=tuple(requests),
        decisions=tuple(decisions),
    )


def run_recursive_evidence_feedback(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
    plan: RecursiveEvidenceFeedbackPlan,
    *,
    root_plan: NativeContentDiscoveryPlan,
    metadata_collection: DeepMetadataCollectionResult,
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
    http_executor: InternalHTTPExecutor | None = None,
) -> RecursiveEvidenceFeedbackResult:
    """Execute an exactly reconstructed depth-one plan through shared HTTP state."""

    require_programme_orchestration_plan_binding(
        runtime,
        orchestration_plan,
        project_state=project_state,
    )
    if not isinstance(plan, RecursiveEvidenceFeedbackPlan):
        raise ValueError("Recursive evidence feedback plan is not canonical.")
    expected_plan = build_recursive_evidence_feedback_plan(
        runtime,
        project_state,
        orchestration_plan,
        root_plan=root_plan,
        metadata_collection=metadata_collection,
        html_extraction=html_extraction,
        javascript_extraction=javascript_extraction,
        source_depth=plan.source_depth,
        limits=plan.limits,
    )
    if plan != expected_plan:
        raise ValueError(
            "Recursive evidence feedback plan is not canonical for retained evidence."
        )

    owns_executor = http_executor is None
    executor = http_executor or build_native_content_discovery_http_executor(
        runtime,
        project_state,
        orchestration_plan,
    )
    try:
        _require_compatible_executor(runtime, orchestration_plan, executor)
        collected: list[RecursiveEvidenceFeedbackCollectedResponse] = []
        for request in plan.requests:
            response = executor.request(
                request.url,
                method="GET",
                timeout_seconds=BASELINE_REQUEST_TIMEOUT_SECONDS,
                maximum_response_bytes=BASELINE_MAXIMUM_RESPONSE_BYTES,
                allow_query_strings=False,
            )
            collected.append(
                RecursiveEvidenceFeedbackCollectedResponse(
                    request=request,
                    status_code=response.status_code,
                    final_url=response.final_url,
                    headers=response.headers,
                    body_bytes=len(response.body),
                    body_sha256=sha256(response.body).hexdigest(),
                    elapsed_seconds=response.elapsed_seconds,
                    evidence_ids=request.evidence_ids,
                    body=response.body,
                )
            )
        return RecursiveEvidenceFeedbackResult(
            external_commands_started=0,
            requests_attempted=len(collected),
            budget_consumed=plan.budget_consumed,
            budget_remaining=plan.budget_remaining,
            collected=tuple(collected),
            decisions=plan.decisions,
        )
    finally:
        if owns_executor:
            executor.close()


def _aggregate_candidates(
    metadata_collection: DeepMetadataCollectionResult,
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
) -> tuple[_AggregatedCandidate, ...]:
    contributions: list[_CandidateContribution] = []
    for item in metadata_collection.collected:
        for route in item.sitemap_route_references:
            contributions.append(
                _CandidateContribution(
                    raw_url=route,
                    selection_reason=SELECTION_SITEMAP_DECLARED,
                    evidence_ids=_normalise_strings(item.evidence_ids),
                )
            )
    for candidate in javascript_extraction.candidates:
        for context in candidate.semantic_contexts:
            selection_reason = _javascript_selection_reason(context)
            if selection_reason is None or candidate.safe_resolved_url is None:
                continue
            contributions.append(
                _CandidateContribution(
                    raw_url=candidate.safe_resolved_url,
                    selection_reason=selection_reason,
                    evidence_ids=_normalise_strings(candidate.evidence_ids),
                )
            )
    for route in html_extraction.routes:
        contributions.append(
            _CandidateContribution(
                raw_url=route.safe_resolved_url,
                selection_reason=SELECTION_HTML_ROUTE_REFERENCE,
                evidence_ids=_normalise_strings(route.evidence_ids),
            )
        )

    pending: dict[str, dict[str, set[str]]] = {}
    origins: dict[str, str] = {}
    for contribution in contributions:
        destination = _canonical_candidate_destination(contribution.raw_url)
        canonical_url = destination.canonical_value
        origins[canonical_url] = destination.origin.canonical_value
        aggregate = pending.setdefault(
            canonical_url,
            {"reasons": set(), "evidence": set()},
        )
        aggregate["reasons"].add(contribution.selection_reason)
        aggregate["evidence"].update(contribution.evidence_ids)

    candidates = tuple(
        _AggregatedCandidate(
            url=url,
            canonical_origin=origins[url],
            selection_reasons=tuple(
                reason for reason in SELECTION_PRIORITY if reason in values["reasons"]
            ),
            evidence_ids=tuple(sorted(values["evidence"])),
        )
        for url, values in pending.items()
    )
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                _SELECTION_PRIORITY_INDEX[item.primary_selection_reason],
                item.url,
            ),
        )
    )


def _non_budget_stop_reason(
    candidate: _AggregatedCandidate,
    *,
    candidate_depth: int,
    limits: RecursiveEvidenceFeedbackLimits,
    retained_evidence_ids: frozenset[str],
    already_collected: frozenset[str],
    programme_scope_policy,
    materialised_origins: frozenset[str],
) -> str | None:
    destination = canonicalise_http_url_destination(candidate.url)
    if candidate_depth > limits.maximum_depth:
        return REASON_DEPTH_EXHAUSTED
    if destination.query is not None:
        return REASON_QUERY_NOT_ALLOWED
    if not candidate.evidence_ids:
        return REASON_MISSING_EVIDENCE
    if not set(candidate.evidence_ids).issubset(retained_evidence_ids):
        return REASON_EVIDENCE_NOT_RETAINED
    if candidate.url in already_collected:
        return REASON_ALREADY_COLLECTED
    decision = evaluate_raw_scope_destination(
        programme_scope_policy,
        DESTINATION_HTTP_URL,
        candidate.url,
    )
    if decision.outcome == OUTCOME_BLOCKED:
        return REASON_SCOPE_BLOCKED
    if decision.outcome != OUTCOME_ALLOWED:
        return REASON_SCOPE_UNKNOWN
    if candidate.canonical_origin not in materialised_origins:
        return REASON_UNMATERIALISED_ORIGIN
    return None


def _decision(
    candidate: _AggregatedCandidate,
    *,
    depth: int,
    outcome: str,
    reason: str,
) -> RecursiveEvidenceFeedbackDecision:
    return RecursiveEvidenceFeedbackDecision(
        url=candidate.url,
        canonical_origin=candidate.canonical_origin,
        depth=depth,
        outcome=outcome,
        reason=reason,
        evidence_ids=candidate.evidence_ids,
        selection_reasons=candidate.selection_reasons,
    )


def _require_compatible_executor(
    runtime: BugBountyProjectRuntime,
    orchestration_plan: ProgrammeOrchestrationPlan,
    executor: object,
) -> None:
    if not isinstance(executor, InternalHTTPExecutor):
        raise ValueError("Recursive evidence feedback HTTP executor is invalid.")
    if not internal_http_executors_share_enforcement_state(
        runtime.http_executor,
        executor,
    ):
        raise ValueError("Recursive evidence feedback HTTP executor binding is invalid.")
    expected_origins = tuple(
        item.canonical_origin for item in orchestration_plan.http_work_items
    )
    expected_configuration = build_http_enforcement_configuration(
        runtime.policy,
        approved_origins=expected_origins,
    )
    if executor.configuration != expected_configuration:
        raise ValueError("Recursive evidence feedback HTTP origin binding is invalid.")
    if executor._programme_scope_policy != runtime.programme_scope_policy:
        raise ValueError("Recursive evidence feedback programme policy binding is invalid.")
    if executor._ipv4_resolver is not runtime.http_executor._ipv4_resolver:
        raise ValueError("Recursive evidence feedback resolver binding is invalid.")
    if not isinstance(executor.transport, PeerBoundHTTPTransport):
        raise ValueError("Recursive evidence feedback requires peer-bound HTTP transport.")


def _require_source_models(
    metadata_collection: object,
    html_extraction: object,
    javascript_extraction: object,
) -> None:
    if not isinstance(metadata_collection, DeepMetadataCollectionResult) or any(
        not isinstance(item, DeepMetadataCollectedItem)
        for item in metadata_collection.collected
    ):
        raise ValueError("Recursive sitemap evidence is invalid.")
    if not isinstance(html_extraction, DeepHtmlRouteExtractionResult) or any(
        not isinstance(item, DeepHtmlRouteReference) for item in html_extraction.routes
    ):
        raise ValueError("Recursive HTML evidence is invalid.")
    if not isinstance(
        javascript_extraction,
        DeepJavaScriptRouteExtractionResult,
    ) or any(
        not isinstance(item, DeepJavaScriptRouteCandidate)
        for item in javascript_extraction.candidates
    ):
        raise ValueError("Recursive JavaScript evidence is invalid.")


def _canonical_candidate_destination(raw_url: object):
    try:
        destination = canonicalise_http_url_destination(raw_url)
    except (TypeError, ValueError):
        raise ValueError("Recursive evidence contains an invalid HTTP URL.") from None
    if destination.canonical_value != raw_url:
        raise ValueError("Recursive evidence HTTP URL is not canonical.")
    return destination


def _canonical_root_request_url(request: object) -> str:
    if not isinstance(request, NativeContentDiscoveryRequest) or request.depth != 0:
        raise ValueError("Recursive evidence feedback root request is invalid.")
    destination = _canonical_candidate_destination(request.url)
    if destination.origin.canonical_value != request.canonical_origin:
        raise ValueError("Recursive evidence feedback root origin is invalid.")
    return destination.canonical_value


def _retained_project_evidence_ids(project_state: ProjectState) -> frozenset[str]:
    if not isinstance(project_state, ProjectState) or any(
        not isinstance(item, Evidence) for item in project_state.evidence
    ):
        raise ValueError("Recursive evidence feedback project evidence is invalid.")
    identifiers = tuple(item.id for item in project_state.evidence)
    if any(not isinstance(value, str) or not value for value in identifiers):
        raise ValueError("Recursive evidence feedback project evidence ID is invalid.")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Recursive evidence feedback project evidence IDs are ambiguous.")
    return frozenset(identifiers)


def _javascript_selection_reason(context: object) -> str | None:
    if context not in ACCEPTED_ROUTE_CONTEXTS:
        return None
    if context == REQUEST_CALL:
        return SELECTION_JAVASCRIPT_REQUEST_CALL
    if context == ROUTE_CONFIGURATION:
        return SELECTION_JAVASCRIPT_ROUTE_CONFIGURATION
    return None


def _normalise_strings(values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise ValueError("Recursive evidence IDs are invalid.")
    return tuple(sorted(set(values)))


def _require_canonical_strings(values: object, *, label: str) -> None:
    if (
        not isinstance(values, tuple)
        or any(not isinstance(value, str) or not value for value in values)
        or tuple(sorted(set(values))) != values
    ):
        raise ValueError(f"Recursive evidence feedback {label} are invalid.")


def _require_selection_reasons(values: object) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError("Recursive evidence feedback selection reasons are invalid.")
    expected = tuple(reason for reason in SELECTION_PRIORITY if reason in values)
    if values != expected or len(values) != len(set(values)):
        raise ValueError("Recursive evidence feedback selection reasons are invalid.")
