"""Programme-bound, BugSlyce-native bounded root content discovery."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Callable
from urllib.parse import urljoin, urlparse

from bugslyce.core.engagement_context import (
    CTF_LAB_CONTEXT,
    INTERNAL_AUTHORISED_CONTEXT,
)
from bugslyce.core.models import ProjectState
from bugslyce.recon.content_plan import (
    discover_content_plan_origins,
    get_content_discovery_profile,
)
from bugslyce.recon.content_run import (
    BASELINE_ARTIFACT_NAME,
    BASELINE_CLASSIFICATION_CONVENTIONAL,
    BASELINE_CLASSIFICATION_STABLE_FALLBACK,
    BASELINE_CLASSIFICATION_STABLE_REDIRECT,
    BASELINE_MAXIMUM_RESPONSE_BYTES,
    BASELINE_POLICY_REFUSE,
    BASELINE_REQUEST_COUNT,
    BASELINE_REQUEST_TIMEOUT_SECONDS,
    INTERNAL_COMPARATOR_ARTIFACT_TYPE,
    ContentBaselineDecision,
    collect_content_discovery_baseline,
    render_content_discovery_baseline_artifact,
    response_comparison_signature,
    write_content_discovery_baseline_artifact,
)
from bugslyce.recon.http_enforcement import (
    HTTPExecutorClosed,
    HTTPProgrammeScopeRefused,
    HTTPRateRejected,
    HTTPReceivedResponse,
    HTTPTransportFailure,
    ISOLATED_HTTP_ENVIRONMENT_FAILURE_CATEGORIES,
    InternalHTTPResponse,
    InternalHTTPExecutor,
    PeerBoundHTTPTransport,
    build_http_enforcement_configuration,
    internal_http_executors_share_enforcement_state,
)
from bugslyce.recon.native_observation_store import (
    ATTEMPT_FAILURE_CATEGORIES,
    FATAL_HTTP_EXECUTION_STOP_CATEGORIES,
    LIVE_NATIVE_OBSERVATION_BODY_BYTE_ALLOWANCE,
    LIVE_NATIVE_OBSERVATION_METADATA_BYTE_ALLOWANCE,
    MAXIMUM_NATIVE_OBSERVATION_CANDIDATES,
    NATIVE_OBSERVATION_STORE_PROJECT_PATH,
    BodyReservation,
    CandidateMetadataReservation,
    NativeAttemptFailure,
    NativeCandidateObservation,
    NativeFatalHTTPExecutionStop,
    NativeObservationBodyBudgetExceeded,
    NativeObservationMetadataBudgetExceeded,
    NativeObservationStore,
    NativeProgrammeScopeRefusal,
    NativeRateRejection,
    NativeReceivedExchange,
    NativeReceivedExchangeTerminalFailure,
    NativeRedirectRefusal,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.programme_orchestration import (
    ProgrammeOrchestrationPlan,
    build_programme_orchestration_http_executor,
    require_programme_orchestration_plan_binding,
)
from bugslyce.recon.project_runtime import BugBountyProjectRuntime
from bugslyce.recon.runner import ContentDiscoveryProgressEvent


PROFILE_WORDLIST_SELECTION_REASON = "profile_wordlist"
NATIVE_CONVENTIONAL_NEGATIVE_POLICY = "native_conventional_negative"
NATIVE_CONTENT_BASELINE_CREATED_BY = "bugslyce-native-content-baseline"
NATIVE_CONTENT_COVERAGE_ARTIFACT_NAME = "content_discovery_native_coverage.json"
NATIVE_CONTENT_COVERAGE_CREATED_BY = "bugslyce-native-content-coverage"
NATIVE_CONTENT_COVERAGE_SCHEMA_VERSION = "1.0"
ISOLATED_CANDIDATE_TRANSPORT_FAILURE_CATEGORIES = (
    ISOLATED_HTTP_ENVIRONMENT_FAILURE_CATEGORIES
)
MAXIMUM_NATIVE_TOTAL_CANDIDATE_REQUESTS = MAXIMUM_NATIVE_OBSERVATION_CANDIDATES
MAXIMUM_NATIVE_CANDIDATE_REQUESTS_PER_ORIGIN = 4_096
MAXIMUM_NATIVE_WORDLIST_ENTRIES = 4_096
MAXIMUM_NATIVE_WORDLIST_BYTES = 1_000_000
_MAXIMUM_PROGRESS_INTERVALS_PER_ORIGIN = 20
_NATIVE_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class NativeContentDiscoveryEvidenceBudgetExhausted(RuntimeError):
    """Raised before transmission when durable candidate evidence cannot fit."""

    def __init__(self, capacity_kind: str) -> None:
        if capacity_kind not in {"body", "metadata"}:
            raise ValueError("Native evidence capacity kind is invalid.")
        self.capacity_kind = capacity_kind
        super().__init__(
            f"Native candidate {capacity_kind} evidence capacity is exhausted."
        )


@dataclass(frozen=True)
class NativeContentDiscoveryLimits:
    """Explicit candidate-request ceilings, excluding baseline probes."""

    maximum_total_candidate_requests: int
    maximum_candidate_requests_per_origin: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_total_candidate_requests, bool)
            or not isinstance(self.maximum_total_candidate_requests, int)
            or not 1
            <= self.maximum_total_candidate_requests
            <= MAXIMUM_NATIVE_TOTAL_CANDIDATE_REQUESTS
        ):
            raise ValueError("Native content discovery total request budget is invalid.")
        if (
            isinstance(self.maximum_candidate_requests_per_origin, bool)
            or not isinstance(self.maximum_candidate_requests_per_origin, int)
            or not 1
            <= self.maximum_candidate_requests_per_origin
            <= MAXIMUM_NATIVE_CANDIDATE_REQUESTS_PER_ORIGIN
        ):
            raise ValueError("Native content discovery per-origin budget is invalid.")


@dataclass(frozen=True)
class NativeContentDiscoveryRequest:
    """One canonical HTTP request selected for bounded native discovery."""

    url: str
    canonical_origin: str
    depth: int
    selection_reason: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        origin = http_origin_from_url(self.url)
        canonical = http_origin_from_url(self.canonical_origin)
        if origin is None or canonical is None:
            raise ValueError("Native content discovery requires an HTTP URL and origin.")
        if canonical.origin_url != self.canonical_origin:
            raise ValueError("Native content discovery canonical origin is invalid.")
        if origin != canonical:
            raise ValueError("Native content discovery request escaped its exact origin.")
        if (
            isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or self.depth < 0
        ):
            raise ValueError("Native content discovery request depth is invalid.")
        if not isinstance(self.selection_reason, str) or not self.selection_reason:
            raise ValueError("Native content discovery selection reason is invalid.")
        if (
            not isinstance(self.evidence_ids, tuple)
            or any(not isinstance(value, str) or not value for value in self.evidence_ids)
            or tuple(sorted(set(self.evidence_ids))) != self.evidence_ids
        ):
            raise ValueError("Native content discovery evidence IDs are invalid.")


@dataclass(frozen=True)
class NativeContentDiscoveryOriginAllocation:
    """One origin's eligible capacity and fair share of the total budget."""

    canonical_origin: str
    candidate_requests_eligible: int
    candidate_requests_planned: int

    def __post_init__(self) -> None:
        origin = http_origin_from_url(self.canonical_origin)
        if origin is None or origin.origin_url != self.canonical_origin:
            raise ValueError("Native content discovery allocation origin is invalid.")
        if (
            isinstance(self.candidate_requests_eligible, bool)
            or not isinstance(self.candidate_requests_eligible, int)
            or self.candidate_requests_eligible < 0
            or isinstance(self.candidate_requests_planned, bool)
            or not isinstance(self.candidate_requests_planned, int)
            or not 0
            <= self.candidate_requests_planned
            <= self.candidate_requests_eligible
        ):
            raise ValueError("Native content discovery allocation count is invalid.")

    @property
    def candidate_requests_omitted_by_total_limit(self) -> int:
        return self.candidate_requests_eligible - self.candidate_requests_planned


@dataclass(frozen=True)
class NativeContentDiscoveryPlan:
    """Immutable deterministic root-request plan for one approved profile."""

    profile: str
    limits: NativeContentDiscoveryLimits
    baseline_requests_per_origin: int
    candidate_requests_planned: int
    requests: tuple[NativeContentDiscoveryRequest, ...]
    origin_allocations: tuple[NativeContentDiscoveryOriginAllocation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or not self.profile:
            raise ValueError("Native content discovery profile is invalid.")
        if not isinstance(self.limits, NativeContentDiscoveryLimits):
            raise ValueError("Native content discovery limits are invalid.")
        if self.baseline_requests_per_origin != BASELINE_REQUEST_COUNT:
            raise ValueError("Native content discovery baseline count is invalid.")
        if (
            isinstance(self.candidate_requests_planned, bool)
            or not isinstance(self.candidate_requests_planned, int)
            or self.candidate_requests_planned != len(self.requests)
        ):
            raise ValueError("Native content discovery candidate count is invalid.")
        if (
            not isinstance(self.requests, tuple)
            or any(
                not isinstance(request, NativeContentDiscoveryRequest)
                for request in self.requests
            )
        ):
            raise ValueError("Native content discovery requests are invalid.")
        if (
            not isinstance(self.origin_allocations, tuple)
            or any(
                not isinstance(item, NativeContentDiscoveryOriginAllocation)
                for item in self.origin_allocations
            )
            or (not self.origin_allocations and self.candidate_requests_planned != 0)
        ):
            raise ValueError("Native content discovery origin allocations are invalid.")
        allocation_origins = tuple(
            item.canonical_origin for item in self.origin_allocations
        )
        if len(set(allocation_origins)) != len(allocation_origins):
            raise ValueError("Native content discovery allocation origins are invalid.")
        request_counts = {origin: 0 for origin in allocation_origins}
        for request in self.requests:
            if request.canonical_origin not in request_counts:
                raise ValueError(
                    "Native content discovery request has no origin allocation."
                )
            request_counts[request.canonical_origin] += 1
        if any(
            request_counts[item.canonical_origin] != item.candidate_requests_planned
            for item in self.origin_allocations
        ):
            raise ValueError("Native content discovery allocation does not match requests.")
        if (
            sum(item.candidate_requests_planned for item in self.origin_allocations)
            != self.candidate_requests_planned
            or self.candidate_requests_planned
            > self.limits.maximum_total_candidate_requests
            or any(
                item.candidate_requests_eligible
                > self.limits.maximum_candidate_requests_per_origin
                for item in self.origin_allocations
            )
        ):
            raise ValueError("Native content discovery allocation exceeds its limits.")

    @property
    def candidate_requests_eligible(self) -> int:
        return sum(
            item.candidate_requests_eligible for item in self.origin_allocations
        )

    @property
    def candidate_requests_omitted_by_total_limit(self) -> int:
        return self.candidate_requests_eligible - self.candidate_requests_planned


@dataclass(frozen=True)
class NativeContentDiscoveryArtifact:
    """One parser-compatible retained native discovery artefact."""

    artifact_type: str
    canonical_origin: str
    profile: str
    selection_reason: str
    path: Path


@dataclass(frozen=True)
class NativeContentDiscoveryCandidateFailure:
    """One attempted candidate for which no HTTP response was obtained."""

    request_url: str
    category: str

    def __post_init__(self) -> None:
        if http_origin_from_url(self.request_url) is None:
            raise ValueError("Native candidate failure request URL is invalid.")
        if self.category not in ISOLATED_CANDIDATE_TRANSPORT_FAILURE_CATEGORIES:
            raise ValueError("Native candidate failure category is invalid.")


@dataclass(frozen=True)
class NativeContentDiscoveryRedirectFollowupFailure:
    """One candidate response whose permitted redirect follow-up failed."""

    request_url: str
    source_url: str
    destination_url: str
    status_code: int
    category: str

    def __post_init__(self) -> None:
        if any(
            http_origin_from_url(value) is None
            for value in (self.request_url, self.source_url, self.destination_url)
        ):
            raise ValueError("Native redirect follow-up failure URL is invalid.")
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or self.status_code not in _NATIVE_REDIRECT_STATUSES
        ):
            raise ValueError("Native redirect follow-up failure status is invalid.")
        if self.category not in ISOLATED_CANDIDATE_TRANSPORT_FAILURE_CATEGORIES:
            raise ValueError("Native redirect follow-up failure category is invalid.")


@dataclass(frozen=True)
class NativeContentDiscoveryOriginResult:
    """One origin's truthful baseline and candidate disposition."""

    canonical_origin: str
    baseline_decision: ContentBaselineDecision
    suppressed_candidate_count: int
    retained_candidate_count: int
    failed_candidates: tuple[NativeContentDiscoveryCandidateFailure, ...] = ()
    redirect_followup_failures: tuple[
        NativeContentDiscoveryRedirectFollowupFailure,
        ...,
    ] = ()

    def __post_init__(self) -> None:
        origin = http_origin_from_url(self.canonical_origin)
        if origin is None or origin.origin_url != self.canonical_origin:
            raise ValueError("Native origin result canonical origin is invalid.")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                self.suppressed_candidate_count,
                self.retained_candidate_count,
            )
        ):
            raise ValueError("Native origin result candidate counts are invalid.")
        if (
            not isinstance(self.failed_candidates, tuple)
            or any(
                not isinstance(item, NativeContentDiscoveryCandidateFailure)
                for item in self.failed_candidates
            )
            or len({item.request_url for item in self.failed_candidates})
            != len(self.failed_candidates)
            or any(
                http_origin_from_url(item.request_url) != origin
                for item in self.failed_candidates
            )
        ):
            raise ValueError("Native origin result candidate failures are invalid.")
        if (
            not isinstance(self.redirect_followup_failures, tuple)
            or any(
                not isinstance(
                    item,
                    NativeContentDiscoveryRedirectFollowupFailure,
                )
                for item in self.redirect_followup_failures
            )
            or len(
                {item.request_url for item in self.redirect_followup_failures}
            )
            != len(self.redirect_followup_failures)
            or any(
                http_origin_from_url(item.request_url) != origin
                for item in self.redirect_followup_failures
            )
        ):
            raise ValueError(
                "Native origin result redirect follow-up failures are invalid."
            )

    @property
    def failed_candidate_count(self) -> int:
        return len(self.failed_candidates)

    @property
    def redirect_followup_failure_count(self) -> int:
        return len(self.redirect_followup_failures)


@dataclass(frozen=True)
class NativeContentDiscoveryResult:
    """Deterministic native execution result; no external commands are involved."""

    external_commands_started: int
    origin_results: tuple[NativeContentDiscoveryOriginResult, ...]
    artifacts: tuple[NativeContentDiscoveryArtifact, ...]
    baseline_artifact_path: Path
    coverage_artifact_path: Path


class NativeContentDiscoveryBaselineRefused(ValueError):
    """Typed refusal retaining the native baseline decisions that stopped work."""

    def __init__(
        self,
        baseline_artifact_path: Path,
        decisions: tuple[ContentBaselineDecision, ...],
    ) -> None:
        if not isinstance(baseline_artifact_path, Path):
            raise ValueError("Native baseline refusal artefact path is invalid.")
        if (
            not isinstance(decisions, tuple)
            or not decisions
            or any(
                not isinstance(decision, ContentBaselineDecision)
                for decision in decisions
            )
        ):
            raise ValueError("Native baseline refusal decisions are invalid.")
        self.baseline_artifact_path = baseline_artifact_path
        self.decisions = decisions
        super().__init__(
            "Native content discovery refused an incomplete or unstable baseline."
        )


@dataclass(frozen=True)
class _NativeArtifactTarget:
    canonical_origin: str
    path: Path


@dataclass(frozen=True)
class _NativeOutputTransaction:
    destination: Path
    targets: tuple[_NativeArtifactTarget, ...]
    baseline_artifact_path: Path
    coverage_artifact_path: Path


@dataclass(frozen=True)
class _StagedNativeArtifact:
    final_path: Path
    temporary_path: Path
    device: int
    inode: int


@dataclass
class _CandidateEvidenceReservations:
    metadata: CandidateMetadataReservation | None
    bodies: list[BodyReservation]


class _NativeObservationRecorder:
    """Own pre-request reservations and the sole HTTP-to-store translation seam."""

    def __init__(
        self,
        root: Path,
        executor: InternalHTTPExecutor,
    ) -> None:
        self.store = NativeObservationStore(
            root / NATIVE_OBSERVATION_STORE_PROJECT_PATH,
            LIVE_NATIVE_OBSERVATION_BODY_BYTE_ALLOWANCE,
            metadata_byte_allowance=LIVE_NATIVE_OBSERVATION_METADATA_BYTE_ALLOWANCE,
        )
        self.maximum_redirect_hops = (
            executor.configuration.maximum_redirect_hops
            if executor.configuration is not None
            else 0
        )

    def reserve(self, candidate_index: int) -> _CandidateEvidenceReservations:
        metadata: CandidateMetadataReservation | None = None
        bodies: list[BodyReservation] = []
        try:
            metadata = self.store.reserve_candidate_metadata(
                candidate_index,
                maximum_redirect_hops=self.maximum_redirect_hops,
            )
            for _index in range(self.maximum_redirect_hops + 1):
                bodies.append(
                    self.store.reserve_body_bytes(BASELINE_MAXIMUM_RESPONSE_BYTES)
                )
        except NativeObservationMetadataBudgetExceeded as exc:
            self._release_reservations(metadata, bodies)
            raise NativeContentDiscoveryEvidenceBudgetExhausted("metadata") from exc
        except NativeObservationBodyBudgetExceeded as exc:
            self._release_reservations(metadata, bodies)
            raise NativeContentDiscoveryEvidenceBudgetExhausted("body") from exc
        except BaseException:
            self._release_reservations(metadata, bodies)
            raise
        return _CandidateEvidenceReservations(metadata, bodies)

    def release(self, reservations: _CandidateEvidenceReservations) -> None:
        self._release_reservations(reservations.metadata, reservations.bodies)
        reservations.metadata = None
        reservations.bodies.clear()

    def publish(
        self,
        candidate_index: int,
        request_url: str,
        outcome: (
            InternalHTTPResponse
            | HTTPTransportFailure
            | HTTPRateRejected
            | HTTPProgrammeScopeRefused
        ),
        reservations: _CandidateEvidenceReservations,
    ) -> bool:
        """Translate and immediately publish one representable candidate outcome."""

        try:
            return self._publish_reserved(
                candidate_index,
                request_url,
                outcome,
                reservations,
            )
        except BaseException:
            self._release_body_reservations(reservations.bodies)
            if reservations.metadata is not None:
                try:
                    self.store.release_candidate_metadata(reservations.metadata)
                except ValueError:
                    pass
                reservations.metadata = None
            raise

    def _publish_reserved(
        self,
        candidate_index: int,
        request_url: str,
        outcome: (
            InternalHTTPResponse
            | HTTPTransportFailure
            | HTTPRateRejected
            | HTTPProgrammeScopeRefused
        ),
        reservations: _CandidateEvidenceReservations,
    ) -> bool:

        exchanges_source = outcome.received_exchanges
        exchanges = self._commit_exchanges(exchanges_source, reservations.bodies)
        failure = None
        refused_redirect = None
        terminal_failure = None
        rate_rejection = None
        programme_scope_refusal = None
        fatal_execution_stop = None

        if isinstance(outcome, InternalHTTPResponse):
            if outcome.refused_redirect is not None:
                refusal = outcome.refused_redirect
                refused_redirect = NativeRedirectRefusal(
                    refusal.source_url,
                    refusal.destination_url,
                    refusal.reason,
                )
            elif outcome.redirect_followup_failure is not None:
                followup = outcome.redirect_followup_failure
                if exchanges and exchanges[-1].request_url == followup.destination_url:
                    terminal_failure = NativeReceivedExchangeTerminalFailure(
                        followup.destination_url,
                        followup.category,
                    )
                else:
                    failure = NativeAttemptFailure(
                        followup.destination_url,
                        followup.category,
                    )
        elif isinstance(outcome, HTTPRateRejected):
            if not exchanges:
                self.release(reservations)
                return False
            rate_rejection = NativeRateRejection(
                exchanges[-1].request_url,
                outcome.retry_after,
            )
        elif isinstance(outcome, HTTPProgrammeScopeRefused):
            programme_scope_refusal = NativeProgrammeScopeRefusal(
                outcome.stage,
                outcome.reason_code,
                outcome.operator_safe_explanation,
            )
        elif isinstance(outcome, HTTPTransportFailure):
            if outcome.category in FATAL_HTTP_EXECUTION_STOP_CATEGORIES:
                if not exchanges:
                    self.release(reservations)
                    return False
                fatal_execution_stop = NativeFatalHTTPExecutionStop(outcome.category)
            elif outcome.category in ATTEMPT_FAILURE_CATEGORIES:
                if exchanges:
                    terminal_failure = NativeReceivedExchangeTerminalFailure(
                        exchanges[-1].request_url,
                        outcome.category,
                    )
                else:
                    failure = NativeAttemptFailure(request_url, outcome.category)
            else:
                self.release(reservations)
                return False

        observation = NativeCandidateObservation(
            candidate_index=candidate_index,
            request_url=request_url,
            exchanges=exchanges,
            failure=failure,
            refused_redirect=refused_redirect,
            terminal_failure=terminal_failure,
            rate_rejection=rate_rejection,
            programme_scope_refusal=programme_scope_refusal,
            fatal_execution_stop=fatal_execution_stop,
        )
        self._release_body_reservations(reservations.bodies)
        if reservations.metadata is None:
            raise ValueError("Native candidate metadata reservation is absent.")
        self.store.publish_observation(observation, reservations.metadata)
        reservations.metadata = None
        return True

    def publish_index(self, store_state: str) -> None:
        self.store.publish_index(store_state)

    def _commit_exchanges(
        self,
        received: tuple[HTTPReceivedResponse, ...],
        reservations: list[BodyReservation],
    ) -> tuple[NativeReceivedExchange, ...]:
        converted: list[NativeReceivedExchange] = []
        if len(received) > len(reservations):
            raise ValueError("Native response evidence exceeds its body reservations.")
        for item in received:
            capture = item.capture
            body_reference = None
            body_sha256 = None
            captured_bytes = 0
            if capture.body is not None:
                reservation = reservations.pop(0)
                body_reference = self.store.commit_body(reservation, capture.body)
                body_sha256 = body_reference.sha256
                captured_bytes = body_reference.captured_bytes
            else:
                self.store.release_reservation(reservations.pop(0))
            converted.append(
                NativeReceivedExchange(
                    request_url=item.request_url,
                    status_code=item.status_code,
                    headers=capture.headers,
                    capture_state=capture.body_capture_state,
                    captured_bytes=captured_bytes,
                    body_sha256=body_sha256,
                    body=body_reference,
                    incomplete_reason=capture.body_incomplete_reason,
                    headers_capture_state=capture.headers_capture_state,
                    headers_incomplete_reason=capture.headers_incomplete_reason,
                )
            )
        return tuple(converted)

    def _release_body_reservations(self, bodies: list[BodyReservation]) -> None:
        while bodies:
            self.store.release_reservation(bodies.pop())

    def _release_reservations(
        self,
        metadata: CandidateMetadataReservation | None,
        bodies: list[BodyReservation],
    ) -> None:
        self._release_body_reservations(bodies)
        if metadata is not None:
            self.store.release_candidate_metadata(metadata)


def build_native_content_discovery_http_executor(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
) -> InternalHTTPExecutor:
    """Build an exact-origin view of the runtime's aggregate HTTP enforcement."""

    return build_programme_orchestration_http_executor(
        runtime,
        project_state,
        orchestration_plan,
    )


def build_native_content_discovery_plan(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
    *,
    profile: str,
    limits: NativeContentDiscoveryLimits,
) -> NativeContentDiscoveryPlan:
    """Build bounded depth-zero requests from an approved profile wordlist."""

    bound_plan = require_programme_orchestration_plan_binding(
        runtime,
        orchestration_plan,
        project_state=project_state,
    )
    return _build_native_content_discovery_plan_for_origins(
        tuple(item.canonical_origin for item in bound_plan.http_work_items),
        profile=profile,
        limits=limits,
    )


def build_runtime_less_native_content_discovery_plan(
    project_state: ProjectState,
    target: str,
    scope_file: Path,
    *,
    profile: str,
    limits: NativeContentDiscoveryLimits,
) -> NativeContentDiscoveryPlan:
    """Build a bounded native plan for an authorised non-bounty project."""

    canonical_target = _require_runtime_less_project_binding(
        project_state,
        target,
        scope_file,
    )
    origins = tuple(discover_content_plan_origins(project_state, canonical_target))
    if not origins:
        raise ValueError(
            "Runtime-less native content discovery requires a target-backed HTTP origin."
        )
    canonical_origins = tuple(
        origin_identity.origin_url
        for origin in origins
        if (origin_identity := http_origin_from_url(origin)) is not None
    )
    if len(canonical_origins) != len(origins):
        raise ValueError("Runtime-less native content discovery origin is invalid.")
    return _build_native_content_discovery_plan_for_origins(
        canonical_origins,
        profile=profile,
        limits=limits,
    )


def _build_native_content_discovery_plan_for_origins(
    origins: tuple[str, ...],
    *,
    profile: str,
    limits: NativeContentDiscoveryLimits,
) -> NativeContentDiscoveryPlan:
    if not isinstance(limits, NativeContentDiscoveryLimits):
        raise ValueError("Native content discovery limits are invalid.")
    profile_definition = get_content_discovery_profile(profile)
    entries = _load_profile_entries(profile_definition.wordlist)

    eligible_urls_by_origin: list[tuple[str, tuple[str, ...]]] = []
    for origin in origins:
        seen_urls: set[str] = set()
        eligible_urls: list[str] = []
        for entry in entries:
            candidate_url = _profile_candidate_url(origin, entry)
            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)
            if len(eligible_urls) >= limits.maximum_candidate_requests_per_origin:
                break
            eligible_urls.append(candidate_url)
        eligible_urls_by_origin.append((origin, tuple(eligible_urls)))

    planned_counts = [0] * len(eligible_urls_by_origin)
    remaining = min(
        limits.maximum_total_candidate_requests,
        sum(len(urls) for _origin, urls in eligible_urls_by_origin),
    )
    while remaining:
        allocated_this_round = False
        for index, (_origin, urls) in enumerate(eligible_urls_by_origin):
            if planned_counts[index] >= len(urls):
                continue
            planned_counts[index] += 1
            remaining -= 1
            allocated_this_round = True
            if remaining == 0:
                break
        if not allocated_this_round:
            raise ValueError("Native content discovery allocation could not progress.")

    planned: list[NativeContentDiscoveryRequest] = []
    allocations: list[NativeContentDiscoveryOriginAllocation] = []
    for (origin, eligible_urls), planned_count in zip(
        eligible_urls_by_origin,
        planned_counts,
        strict=True,
    ):
        allocations.append(
            NativeContentDiscoveryOriginAllocation(
                canonical_origin=origin,
                candidate_requests_eligible=len(eligible_urls),
                candidate_requests_planned=planned_count,
            )
        )
        for candidate_url in eligible_urls[:planned_count]:
            planned.append(
                NativeContentDiscoveryRequest(
                    url=candidate_url,
                    canonical_origin=origin,
                    depth=0,
                    selection_reason=PROFILE_WORDLIST_SELECTION_REASON,
                    evidence_ids=(),
                )
            )

    return NativeContentDiscoveryPlan(
        profile=profile_definition.name,
        limits=limits,
        baseline_requests_per_origin=BASELINE_REQUEST_COUNT,
        candidate_requests_planned=len(planned),
        requests=tuple(planned),
        origin_allocations=tuple(allocations),
    )


def run_runtime_less_native_content_discovery(
    project_state: ProjectState,
    target: str,
    scope_file: Path,
    plan: NativeContentDiscoveryPlan,
    *,
    http_executor: InternalHTTPExecutor | None = None,
    output_dir: Path,
    token_factory=None,
    progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None = None,
) -> NativeContentDiscoveryResult:
    """Execute a canonical bounded plan for an authorised non-bounty project."""

    if not isinstance(plan, NativeContentDiscoveryPlan):
        raise ValueError("Runtime-less native content discovery plan is not canonical.")
    expected_plan = build_runtime_less_native_content_discovery_plan(
        project_state,
        target,
        scope_file,
        profile=plan.profile,
        limits=plan.limits,
    )
    if plan != expected_plan:
        raise ValueError(
            "Runtime-less native content discovery plan or request binding is not canonical."
        )
    owns_executor = http_executor is None
    executor = http_executor or InternalHTTPExecutor(None)
    try:
        _require_runtime_less_compatible_executor(executor)
        output_transaction = _prepare_output_transaction(plan, output_dir)
        return _execute_native_plan(
            plan,
            executor,
            output_transaction=output_transaction,
            token_factory=token_factory,
            progress_callback=progress_callback,
        )
    finally:
        if owns_executor:
            executor.close()


def _require_runtime_less_project_binding(
    project_state: ProjectState,
    target: str,
    scope_file: Path,
) -> str:
    if not isinstance(project_state, ProjectState):
        raise ValueError(
            "Runtime-less native content discovery requires validated ProjectState evidence."
        )
    if project_state.engagement_context not in {
        CTF_LAB_CONTEXT,
        INTERNAL_AUTHORISED_CONTEXT,
    }:
        raise ValueError(
            "Runtime-less native content discovery is limited to CTF/lab and "
            "internal-authorised projects."
        )
    canonical_target = validate_explicit_nmap_target_scope(target, scope_file)
    manifest = project_state.recon_manifest
    if manifest is None or manifest.target != canonical_target:
        raise ValueError(
            "Runtime-less native content discovery manifest target is not canonical."
        )
    return canonical_target


def _require_runtime_less_compatible_executor(executor: object) -> None:
    if not isinstance(executor, InternalHTTPExecutor):
        raise ValueError(
            "Runtime-less native content discovery requires InternalHTTPExecutor."
        )
    if executor.configuration is not None or getattr(
        executor,
        "_programme_scope_policy",
        None,
    ) is not None:
        raise ValueError(
            "Runtime-less native content discovery HTTP executor is not canonical."
        )


def run_native_content_discovery(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
    plan: NativeContentDiscoveryPlan,
    *,
    http_executor: InternalHTTPExecutor | None = None,
    output_dir: Path,
    token_factory=None,
    progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None = None,
) -> NativeContentDiscoveryResult:
    """Execute a canonical native plan through the central HTTP boundary."""

    require_programme_orchestration_plan_binding(
        runtime,
        orchestration_plan,
        project_state=project_state,
    )
    if not isinstance(plan, NativeContentDiscoveryPlan):
        raise ValueError("Native content discovery plan is not canonical.")
    expected_plan = build_native_content_discovery_plan(
        runtime,
        project_state,
        orchestration_plan,
        profile=plan.profile,
        limits=plan.limits,
    )
    if plan != expected_plan:
        raise ValueError("Native content discovery plan or request binding is not canonical.")

    expected_origins = tuple(
        item.canonical_origin for item in orchestration_plan.http_work_items
    )
    owns_executor = http_executor is None
    executor = http_executor or build_native_content_discovery_http_executor(
        runtime,
        project_state,
        orchestration_plan,
    )
    try:
        _require_compatible_executor(runtime, executor, expected_origins)
        output_transaction = _prepare_output_transaction(plan, output_dir)
        return _execute_native_plan(
            plan,
            executor,
            output_transaction=output_transaction,
            token_factory=token_factory,
            progress_callback=progress_callback,
        )
    finally:
        if owns_executor:
            executor.close()


def _execute_native_plan(
    plan: NativeContentDiscoveryPlan,
    executor: InternalHTTPExecutor,
    *,
    output_transaction: _NativeOutputTransaction,
    token_factory,
    progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None,
) -> NativeContentDiscoveryResult:
    requests_by_origin: dict[str, list[tuple[int, NativeContentDiscoveryRequest]]] = {
        allocation.canonical_origin: [] for allocation in plan.origin_allocations
    }
    for candidate_index, request in enumerate(plan.requests):
        requests_by_origin[request.canonical_origin].append((candidate_index, request))

    baselines: dict[str, ContentBaselineDecision] = {}
    for origin in requests_by_origin:
        progress_started = time.monotonic()
        _emit_native_progress(
            progress_callback,
            origin=origin,
            completed=0,
            total=len(requests_by_origin[origin]),
            started_at=progress_started,
        )
        baseline = collect_content_discovery_baseline(
            f"{origin}/",
            executor,
            token_factory=token_factory,
            retain_refused_redirect_response=True,
        )
        if baseline.classification == BASELINE_CLASSIFICATION_CONVENTIONAL:
            baseline = replace(
                baseline,
                selected_policy=NATIVE_CONVENTIONAL_NEGATIVE_POLICY,
            )
        elif (
            baseline.selected_policy != BASELINE_POLICY_REFUSE
            and baseline.classification not in {
                BASELINE_CLASSIFICATION_STABLE_FALLBACK,
                BASELINE_CLASSIFICATION_STABLE_REDIRECT,
            }
        ):
            raise ValueError("Native content discovery baseline is unsupported.")
        baselines[origin] = baseline
    baseline_decisions = tuple(baselines.values())
    if baseline_decisions and all(
        decision.selected_policy == BASELINE_POLICY_REFUSE
        for decision in baseline_decisions
    ):
        write_content_discovery_baseline_artifact(
            output_transaction.baseline_artifact_path,
            baseline_decisions,
            created_by=NATIVE_CONTENT_BASELINE_CREATED_BY,
        )
        raise NativeContentDiscoveryBaselineRefused(
            output_transaction.baseline_artifact_path,
            baseline_decisions,
        )

    staged_baseline = _stage_new_artifact(
        output_transaction.baseline_artifact_path,
        render_content_discovery_baseline_artifact(
            baseline_decisions,
            created_by=NATIVE_CONTENT_BASELINE_CREATED_BY,
        ),
    )
    observation_recorder = _NativeObservationRecorder(
        output_transaction.destination,
        executor,
    )
    try:
        origin_results, retained_content = _collect_native_candidates(
            requests_by_origin,
            baselines,
            executor,
            observation_recorder,
            progress_callback=progress_callback,
        )
        observation_recorder.publish_index("complete")
    except BaseException as exc:
        try:
            observation_recorder.publish_index("partial")
        except (OSError, ValueError) as persistence_error:
            exc.add_note(
                "Native observation-store partial publication also failed: "
                f"{type(persistence_error).__name__}: {persistence_error}"
            )
        try:
            _publish_staged_artifacts((staged_baseline,))
        except (OSError, ValueError) as persistence_error:
            exc.add_note(
                "Native baseline persistence also failed: "
                f"{type(persistence_error).__name__}: {persistence_error}"
            )
        raise
    else:
        _remove_temporary_artifact(staged_baseline.temporary_path)

    _commit_new_artifacts(
        (
            (
                output_transaction.baseline_artifact_path,
                render_content_discovery_baseline_artifact(
                    tuple(result.baseline_decision for result in origin_results),
                    created_by=NATIVE_CONTENT_BASELINE_CREATED_BY,
                ),
            ),
            (
                output_transaction.coverage_artifact_path,
                render_native_content_discovery_coverage_artifact(
                    plan,
                    tuple(origin_results),
                ),
            ),
            *tuple(
                (target.path, retained_content[target.canonical_origin])
                for target in output_transaction.targets
                if target.canonical_origin in retained_content
            ),
        )
    )
    artifacts = tuple(
        NativeContentDiscoveryArtifact(
            artifact_type=INTERNAL_COMPARATOR_ARTIFACT_TYPE,
            canonical_origin=target.canonical_origin,
            profile=plan.profile,
            selection_reason=PROFILE_WORDLIST_SELECTION_REASON,
            path=target.path,
        )
        for target in output_transaction.targets
        if target.canonical_origin in retained_content
    )

    return NativeContentDiscoveryResult(
        external_commands_started=0,
        origin_results=tuple(origin_results),
        artifacts=artifacts,
        baseline_artifact_path=output_transaction.baseline_artifact_path,
        coverage_artifact_path=output_transaction.coverage_artifact_path,
    )


def _collect_native_candidates(
    requests_by_origin: dict[
        str,
        list[tuple[int, NativeContentDiscoveryRequest]],
    ],
    baselines: dict[str, ContentBaselineDecision],
    executor: InternalHTTPExecutor,
    observation_recorder: _NativeObservationRecorder,
    *,
    progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None,
) -> tuple[list[NativeContentDiscoveryOriginResult], dict[str, str]]:
    origin_results: list[NativeContentDiscoveryOriginResult] = []
    retained_content: dict[str, str] = {}
    for origin, requests in requests_by_origin.items():
        progress_started = time.monotonic()
        baseline = baselines[origin]
        if baseline.selected_policy == BASELINE_POLICY_REFUSE:
            origin_results.append(
                NativeContentDiscoveryOriginResult(
                    canonical_origin=origin,
                    baseline_decision=baseline,
                    suppressed_candidate_count=0,
                    retained_candidate_count=0,
                )
            )
            continue
        suppressed = 0
        retained = 0
        failed_candidates: list[NativeContentDiscoveryCandidateFailure] = []
        redirect_followup_failures: list[
            NativeContentDiscoveryRedirectFollowupFailure
        ] = []
        retained_lines: list[str] = []
        progress_interval = max(
            1,
            (len(requests) + _MAXIMUM_PROGRESS_INTERVALS_PER_ORIGIN - 1)
            // _MAXIMUM_PROGRESS_INTERVALS_PER_ORIGIN,
        )
        next_progress_completed = progress_interval
        for candidate_index, request in requests:
            reservations = observation_recorder.reserve(candidate_index)
            try:
                response = executor.request_retaining_refused_redirect(
                    request.url,
                    method="GET",
                    timeout_seconds=BASELINE_REQUEST_TIMEOUT_SECONDS,
                    maximum_response_bytes=BASELINE_MAXIMUM_RESPONSE_BYTES,
                    allow_query_strings=False,
                    retain_redirect_followup_failure=True,
                )
            except HTTPTransportFailure as exc:
                observation_recorder.publish(
                    candidate_index,
                    request.url,
                    exc,
                    reservations,
                )
                if exc.category not in ISOLATED_CANDIDATE_TRANSPORT_FAILURE_CATEGORIES:
                    raise
                failed_candidates.append(
                    NativeContentDiscoveryCandidateFailure(
                        request_url=request.url,
                        category=exc.category,
                    )
                )
            except (HTTPRateRejected, HTTPProgrammeScopeRefused) as exc:
                observation_recorder.publish(
                    candidate_index,
                    request.url,
                    exc,
                    reservations,
                )
                raise
            except HTTPExecutorClosed:
                observation_recorder.release(reservations)
                raise
            except BaseException:
                observation_recorder.release(reservations)
                raise
            else:
                observation_recorder.publish(
                    candidate_index,
                    request.url,
                    response,
                    reservations,
                )
                followup_failure = response.redirect_followup_failure
                if followup_failure is not None:
                    redirect_followup_failures.append(
                        NativeContentDiscoveryRedirectFollowupFailure(
                            request_url=request.url,
                            source_url=followup_failure.source_url,
                            destination_url=followup_failure.destination_url,
                            status_code=response.status_code,
                            category=followup_failure.category,
                        )
                    )
                if _matches_negative_baseline(baseline, response):
                    suppressed += 1
                else:
                    retained += 1
                    retained_lines.append(_artifact_line(request.url, response))
            completed = suppressed + retained + len(failed_candidates)
            if completed >= next_progress_completed or completed == len(requests):
                _emit_native_progress(
                    progress_callback,
                    origin=origin,
                    completed=completed,
                    total=len(requests),
                    started_at=progress_started,
                )
                next_progress_completed += progress_interval

        retained_content[origin] = "".join(retained_lines)
        updated_baseline = replace(
            baseline,
            baseline_equivalent_candidates=suppressed,
            retained_candidates=retained,
        )
        origin_results.append(
            NativeContentDiscoveryOriginResult(
                canonical_origin=origin,
                baseline_decision=updated_baseline,
                suppressed_candidate_count=suppressed,
                retained_candidate_count=retained,
                failed_candidates=tuple(failed_candidates),
                redirect_followup_failures=tuple(redirect_followup_failures),
            )
        )
    return origin_results, retained_content


def render_native_content_discovery_coverage_artifact(
    plan: NativeContentDiscoveryPlan,
    origin_results: tuple[NativeContentDiscoveryOriginResult, ...],
) -> str:
    """Render deterministic candidate coverage and response-less failures."""

    if not isinstance(plan, NativeContentDiscoveryPlan):
        raise ValueError("Native content discovery coverage plan is invalid.")
    planned_by_origin: dict[str, list[NativeContentDiscoveryRequest]] = {
        allocation.canonical_origin: [] for allocation in plan.origin_allocations
    }
    for request in plan.requests:
        planned_by_origin[request.canonical_origin].append(request)
    if (
        not isinstance(origin_results, tuple)
        or tuple(item.canonical_origin for item in origin_results)
        != tuple(planned_by_origin)
    ):
        raise ValueError("Native content discovery coverage origins are invalid.")

    origin_payloads: list[dict[str, object]] = []
    total_attempted = 0
    total_observed = 0
    total_failed = 0
    total_redirect_followup_failed = 0
    total_unattempted = 0
    total_eligible = 0
    total_omitted_by_total_limit = 0
    allocations_by_origin = {
        item.canonical_origin: item for item in plan.origin_allocations
    }
    for result in origin_results:
        allocation = allocations_by_origin[result.canonical_origin]
        planned_requests = planned_by_origin[result.canonical_origin]
        planned_urls = {request.url for request in planned_requests}
        if any(
            failure.request_url not in planned_urls
            for failure in result.failed_candidates
        ):
            raise ValueError(
                "Native content discovery failure is not backed by its canonical plan."
            )
        if any(
            failure.request_url not in planned_urls
            for failure in result.redirect_followup_failures
        ):
            raise ValueError(
                "Native redirect follow-up failure is not backed by its canonical plan."
            )
        if {
            failure.request_url for failure in result.failed_candidates
        }.intersection(
            failure.request_url for failure in result.redirect_followup_failures
        ):
            raise ValueError(
                "Native candidate cannot be both response-less and response-observed."
            )
        planned = len(planned_requests)
        failed = result.failed_candidate_count
        observed = (
            result.suppressed_candidate_count + result.retained_candidate_count
        )
        attempted = observed + failed
        unattempted = planned - attempted
        if unattempted < 0:
            raise ValueError("Native content discovery coverage counts are invalid.")
        if (
            result.baseline_decision.selected_policy == BASELINE_POLICY_REFUSE
            and attempted != 0
        ):
            raise ValueError("Refused native origin contains attempted candidates.")
        if result.redirect_followup_failure_count > observed:
            raise ValueError(
                "Native redirect follow-up failures exceed observed responses."
            )
        origin_payloads.append(
            {
                "canonical_origin": result.canonical_origin,
                "selected_baseline_policy": result.baseline_decision.selected_policy,
                "candidate_requests_eligible": allocation.candidate_requests_eligible,
                "candidate_requests_planned": planned,
                "candidate_requests_omitted_by_total_limit": (
                    allocation.candidate_requests_omitted_by_total_limit
                ),
                "candidate_requests_attempted": attempted,
                "candidate_responses_observed": observed,
                "suppressed_candidate_count": result.suppressed_candidate_count,
                "retained_candidate_count": result.retained_candidate_count,
                "failed_candidate_count": failed,
                "redirect_followup_failure_count": (
                    result.redirect_followup_failure_count
                ),
                "candidate_requests_unattempted": unattempted,
                "failed_candidates": [
                    {
                        "request_url": failure.request_url,
                        "category": failure.category,
                    }
                    for failure in result.failed_candidates
                ],
                "redirect_followup_failures": [
                    {
                        "request_url": failure.request_url,
                        "source_url": failure.source_url,
                        "destination_url": failure.destination_url,
                        "status_code": failure.status_code,
                        "category": failure.category,
                    }
                    for failure in result.redirect_followup_failures
                ],
            }
        )
        total_attempted += attempted
        total_observed += observed
        total_failed += failed
        total_redirect_followup_failed += result.redirect_followup_failure_count
        total_unattempted += unattempted
        total_eligible += allocation.candidate_requests_eligible
        total_omitted_by_total_limit += (
            allocation.candidate_requests_omitted_by_total_limit
        )

    payload = {
        "schema_version": NATIVE_CONTENT_COVERAGE_SCHEMA_VERSION,
        "created_by": NATIVE_CONTENT_COVERAGE_CREATED_BY,
        "profile": plan.profile,
        "candidate_requests_eligible": plan.candidate_requests_eligible,
        "candidate_requests_planned": plan.candidate_requests_planned,
        "candidate_requests_omitted_by_total_limit": (
            plan.candidate_requests_omitted_by_total_limit
        ),
        "candidate_requests_attempted": total_attempted,
        "candidate_responses_observed": total_observed,
        "failed_candidate_count": total_failed,
        "redirect_followup_failure_count": total_redirect_followup_failed,
        "candidate_requests_unattempted": total_unattempted,
        "origins": origin_payloads,
    }
    if total_attempted + total_unattempted != plan.candidate_requests_planned:
        raise ValueError("Native content discovery aggregate coverage is invalid.")
    if (
        total_eligible != plan.candidate_requests_eligible
        or total_omitted_by_total_limit
        != plan.candidate_requests_omitted_by_total_limit
        or total_eligible
        != plan.candidate_requests_planned + total_omitted_by_total_limit
    ):
        raise ValueError("Native content discovery planning coverage is invalid.")
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _emit_native_progress(
    callback: Callable[[ContentDiscoveryProgressEvent], None] | None,
    *,
    origin: str,
    completed: int,
    total: int,
    started_at: float,
) -> None:
    if callback is None or total <= 0:
        return
    callback(
        ContentDiscoveryProgressEvent(
            origin=origin,
            completed=completed,
            total=total,
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            trusted=True,
        )
    )


def _prepare_output_transaction(
    plan: NativeContentDiscoveryPlan,
    output_dir: Path,
) -> _NativeOutputTransaction:
    destination = _prepare_output_directory(output_dir)
    origins = tuple(dict.fromkeys(request.canonical_origin for request in plan.requests))
    targets = tuple(
        _NativeArtifactTarget(
            canonical_origin=origin,
            path=destination / _artifact_filename(origin),
        )
        for origin in origins
    )
    baseline_artifact_path = destination / BASELINE_ARTIFACT_NAME
    coverage_artifact_path = destination / NATIVE_CONTENT_COVERAGE_ARTIFACT_NAME
    paths = (
        *tuple(target.path for target in targets),
        baseline_artifact_path,
        coverage_artifact_path,
    )
    if len(set(paths)) != len(paths):
        raise ValueError("Native content discovery artefact identities collide.")
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise ValueError(
                "Native content discovery artefact path is unsafe."
            ) from None
        raise ValueError("Native content discovery artefact path already exists.")
    _probe_output_directory(destination)
    return _NativeOutputTransaction(
        destination=destination,
        targets=targets,
        baseline_artifact_path=baseline_artifact_path,
        coverage_artifact_path=coverage_artifact_path,
    )


def _probe_output_directory(destination: Path) -> None:
    descriptor, probe_name = tempfile.mkstemp(
        prefix=".bugslyce-native-preflight.",
        suffix=".tmp",
        dir=destination,
    )
    probe_path = Path(probe_name)
    try:
        os.close(descriptor)
    finally:
        _remove_temporary_artifact(probe_path)


def _commit_new_artifacts(items: tuple[tuple[Path, str], ...]) -> None:
    staged: list[_StagedNativeArtifact] = []
    try:
        for path, content in items:
            staged.append(_stage_new_artifact(path, content))
    except BaseException:
        for artifact in staged:
            _remove_temporary_artifact(artifact.temporary_path)
        raise
    _publish_staged_artifacts(tuple(staged))


def _publish_staged_artifacts(
    staged: tuple[_StagedNativeArtifact, ...],
) -> None:
    created: list[_StagedNativeArtifact] = []
    try:
        for artifact in staged:
            try:
                os.link(
                    artifact.temporary_path,
                    artifact.final_path,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise ValueError(
                    "Native content discovery artefact path already exists."
                ) from None
            created.append(artifact)
    except BaseException:
        for artifact in reversed(created):
            _remove_created_artifact(artifact)
        raise
    finally:
        for artifact in staged:
            _remove_temporary_artifact(artifact.temporary_path)


def _stage_new_artifact(path: Path, content: str) -> _StagedNativeArtifact:
    if not isinstance(path, Path) or not isinstance(content, str):
        raise ValueError("Native content discovery artefact is invalid.")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        metadata = temporary_path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Native content discovery staging file is not regular.")
        return _StagedNativeArtifact(
            final_path=path,
            temporary_path=temporary_path,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    except BaseException:
        _remove_temporary_artifact(temporary_path)
        raise


def _remove_created_artifact(artifact: _StagedNativeArtifact) -> None:
    try:
        metadata = artifact.final_path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_dev == artifact.device
        and metadata.st_ino == artifact.inode
    ):
        artifact.final_path.unlink()


def _remove_temporary_artifact(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _write_new_artifact(path: Path, content: str) -> None:
    _commit_new_artifacts(((path, content),))


def _artifact_line(candidate_url: str, response) -> str:
    parsed = urlparse(candidate_url)
    path = parsed.path or "/"
    if response.redirect_followup_failure is not None:
        failure = response.redirect_followup_failure
        return (
            f"{path} (Status: {response.status_code}) "
            f"[Size: {len(response.body)}] "
            f"[redirect follow-up failed: {failure.category} "
            f"--> {failure.destination_url}]\n"
        )
    if (
        response.refused_redirect is not None
        and response.refused_redirect.destination_url is None
    ):
        redirect = f" [redirect refused: {response.refused_redirect.reason}]"
        return (
            f"{path} (Status: {response.status_code}) "
            f"[Size: {len(response.body)}]{redirect}\n"
        )
    redirect_target = (
        response.refused_redirect.destination_url
        if response.refused_redirect is not None
        else response.final_url
    )
    redirect = (
        f" [--> {redirect_target}]"
        if response.refused_redirect is not None or redirect_target != candidate_url
        else ""
    )
    return (
        f"{path} (Status: {response.status_code}) "
        f"[Size: {len(response.body)}]{redirect}\n"
    )


def _artifact_filename(origin: str) -> str:
    parsed = urlparse(origin)
    safe_scheme = "".join(
        character if character.isalnum() else "-"
        for character in parsed.scheme.lower()
    ).strip("-") or "http"
    safe_host = "".join(
        character if character.isalnum() or character in ".-" else "-"
        for character in (parsed.hostname or "host").lower()
    ).strip(".-") or "host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (
        f"content-discovery-internal-{safe_scheme}-{safe_host}-{port}-root.txt"
    )


def _load_profile_entries(wordlist: Path) -> tuple[str, ...]:
    if not isinstance(wordlist, Path) or wordlist.is_symlink() or not wordlist.is_file():
        raise ValueError("Approved native content discovery wordlist is invalid.")
    try:
        if wordlist.stat().st_size > MAXIMUM_NATIVE_WORDLIST_BYTES:
            raise ValueError("Approved native content discovery wordlist exceeds bounds.")
        entries = tuple(
            line.strip()
            for line in wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    except (OSError, UnicodeError):
        raise ValueError("Approved native content discovery wordlist is unreadable.") from None
    if not entries or len(entries) > MAXIMUM_NATIVE_WORDLIST_ENTRIES:
        raise ValueError("Approved native content discovery wordlist exceeds bounds.")
    return entries


def _profile_candidate_url(origin: str, entry: str) -> str:
    parsed_entry = urlparse(entry)
    if (
        parsed_entry.scheme
        or parsed_entry.netloc
        or parsed_entry.params
        or parsed_entry.query
        or parsed_entry.fragment
        or any(part == ".." for part in parsed_entry.path.split("/"))
    ):
        raise ValueError("Approved native content discovery wordlist entry is unsafe.")
    candidate = urljoin(f"{origin}/", entry.lstrip("/"))
    candidate_origin = http_origin_from_url(candidate)
    expected_origin = http_origin_from_url(origin)
    if candidate_origin is None or candidate_origin != expected_origin:
        raise ValueError("Native content discovery candidate escaped its exact origin.")
    return candidate


def _require_compatible_executor(
    runtime: BugBountyProjectRuntime,
    executor: object,
    expected_origins: tuple[str, ...],
) -> None:
    if not isinstance(executor, InternalHTTPExecutor):
        raise ValueError("Native content discovery requires InternalHTTPExecutor.")
    expected_configuration = build_http_enforcement_configuration(
        runtime.policy,
        approved_origins=expected_origins,
    )
    if executor.configuration != expected_configuration:
        raise ValueError("Native content discovery HTTP executor is not canonical.")
    if getattr(executor, "_programme_scope_policy", None) != runtime.programme_scope_policy:
        raise ValueError("Native content discovery HTTP programme scope is not canonical.")
    if getattr(executor, "_ipv4_resolver", None) is not getattr(
        runtime.http_executor,
        "_ipv4_resolver",
        None,
    ):
        raise ValueError("Native content discovery HTTP peer resolver is not canonical.")
    if not isinstance(executor.transport, PeerBoundHTTPTransport):
        raise ValueError("Native content discovery requires peer-bound HTTP transport.")
    if not internal_http_executors_share_enforcement_state(
        runtime.http_executor,
        executor,
    ):
        raise ValueError(
            "Native content discovery HTTP executor does not share runtime "
            "aggregate enforcement state."
        )


def _matches_negative_baseline(baseline, response) -> bool:
    if baseline.classification == BASELINE_CLASSIFICATION_CONVENTIONAL:
        statuses = {
            observation.terminal_http_status
            for observation in baseline.observations
            if observation.observation_status == "complete"
        }
        return len(statuses) == 1 and response.status_code in statuses
    return response_comparison_signature(response) == baseline.comparison_signature


def _prepare_output_directory(output_dir: Path) -> Path:
    if not isinstance(output_dir, Path):
        raise ValueError("Native content discovery output directory is invalid.")
    requested = output_dir.expanduser()
    if requested.is_symlink():
        raise ValueError("Native content discovery output directory is unsafe.")
    if requested.exists():
        if not requested.is_dir():
            raise ValueError("Native content discovery output directory is unsafe.")
    else:
        requested.mkdir(parents=True, exist_ok=False)
    if requested.is_symlink() or not requested.is_dir():
        raise ValueError("Native content discovery output directory is unsafe.")
    descriptor = _open_output_directory_identity(requested)
    try:
        expected = os.fstat(descriptor)
        destination = requested.resolve(strict=True)
        actual = destination.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(actual.st_mode)
            or actual.st_dev != expected.st_dev
            or actual.st_ino != expected.st_ino
        ):
            raise ValueError("Native content discovery output directory identity changed.")
        return destination
    except OSError:
        raise ValueError("Native content discovery output directory is unsafe.") from None
    finally:
        os.close(descriptor)


def _open_output_directory_identity(requested: Path) -> int:
    flags = os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_PATH", os.O_RDONLY)
    try:
        descriptor = os.open(requested, flags)
    except OSError:
        raise ValueError("Native content discovery output directory is unsafe.") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Native content discovery output directory is unsafe.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise
