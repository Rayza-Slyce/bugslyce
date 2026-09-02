"""Execute only approved root discovery steps from a BugSlyce content plan."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import time
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.engagement_policy import enforce_r0b2_bug_bounty_live_block
from bugslyce.core.models import (
    ContentDiscoveryOriginDecision,
    ContentDiscoveryPlan,
    ContentDiscoveryStep,
    ReconContentDiscoveryExecutionResult,
    ReconPlannedArtifact,
)
from bugslyce.core.programme_scope import ProgrammeScopePolicy
from bugslyce.core.project import build_project_state
from bugslyce.project_session import (
    PROJECT_FILENAME,
    load_project,
    load_project_engagement_policy,
    load_project_programme_scope_policy,
)
from bugslyce.recon.content_commands import build_live_content_discovery_command
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_CREATED_BY,
    CONTENT_DISCOVERY_PROFILE,
    CONTENT_DISCOVERY_SCHEMA_VERSION,
    GOBUSTER_REQUEST_TIMEOUT_SECONDS,
    MAX_CONTENT_PLAN_ORIGINS,
    discover_content_plan_origins,
    get_content_discovery_profile,
)
from bugslyce.recon.nmap_profiles import validate_explicit_nmap_target_scope
from bugslyce.recon.http_enforcement import (
    HTTPEnforcementConfiguration,
    HTTPExecutorClosed,
    HTTPProgrammeScopeRefused,
    HTTPRateRejected,
    HTTPRedirectRefused,
    HTTPTransportFailure,
    InternalHTTPExecutionError,
    InternalHTTPExecutor,
    InternalHTTPResponse,
    build_http_enforcement_configuration,
)
from bugslyce.recon.runner import (
    ContentDiscoveryProgressEvent,
    LiveContentDiscoveryRunner,
    render_content_discovery_progress,
)
from bugslyce.reports.markdown import write_project_outputs
from bugslyce.triage.candidates import generate_candidates


class ContentDiscoveryExecutionIncomplete(ValueError):
    """Raised after an honest partial execution result has been assembled."""

    def __init__(self, message: str, result: ReconContentDiscoveryExecutionResult) -> None:
        super().__init__(message)
        self.result = result


class ContentDiscoveryBaselineRefused(ValueError):
    """Raised after baseline evidence proves discovery cannot proceed safely."""

    def __init__(
        self,
        baseline_artifact_path: Path,
        decisions: tuple[ContentBaselineDecision, ...],
    ) -> None:
        super().__init__(
            "Content discovery stopped because a negative-response baseline "
            "was unstable or incomplete. No content discovery was attempted."
        )
        self.baseline_artifact_path = baseline_artifact_path
        self.decisions = decisions


class ContentDiscoveryComparatorIncomplete(ValueError):
    """Raised after a stable-baseline comparison stops before completion."""

    def __init__(
        self,
        baseline_artifact_path: Path,
        decision: ContentBaselineDecision,
    ) -> None:
        super().__init__(
            "Content discovery stopped because internal exact-body comparison "
            "did not complete. Updated baseline evidence was retained."
        )
        self.baseline_artifact_path = baseline_artifact_path
        self.decision = decision


BASELINE_REQUEST_COUNT = 3
BASELINE_REQUEST_TIMEOUT_SECONDS = 10
BASELINE_MAXIMUM_RESPONSE_BYTES = 1_000_000
BASELINE_ARTIFACT_NAME = "content_discovery_baseline.json"
BASELINE_CLASSIFICATION_CONVENTIONAL = "conventional_negative"
BASELINE_CLASSIFICATION_STABLE_FALLBACK = "stable_fallback"
BASELINE_CLASSIFICATION_STABLE_REDIRECT = "stable_redirect_fallback"
BASELINE_CLASSIFICATION_UNSTABLE = "unstable"
BASELINE_CLASSIFICATION_FAILED = "failed"
BASELINE_POLICY_GOBUSTER = "gobuster"
BASELINE_POLICY_INTERNAL_COMPARATOR = "internal_exact_body_comparator"
BASELINE_POLICY_REFUSE = "refuse"
INTERNAL_COMPARATOR_ARTIFACT_TYPE = "content_discovery_internal"
INTERNAL_COMPARATOR_TAG = "internal_exact_body_comparator"
COMPARATOR_PROGRESS_INTERVAL_SECONDS = 12.0
MAX_INTERNAL_COMPARATOR_CANDIDATES = 4096
COMPARATOR_FIXED_ALLOWANCE_SECONDS = 60
COMPARATOR_PER_CANDIDATE_ALLOWANCE_SECONDS = 1
MAX_COMPARATOR_RUNTIME_SECONDS = 2 * 60 * 60
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
LEGACY_CONTENT_BASELINE_CREATED_BY = "bugslyce-r2-content-baseline"


@dataclass(frozen=True)
class ContentBaselineObservation:
    """One body-bounded negative-path observation without retained content."""

    request_url: str
    observation_status: str
    terminal_http_status: int | None
    response_bytes: int | None
    body_sha256: str | None
    final_url: str | None
    redirect_hops: tuple[tuple[int, str], ...]
    refused_redirect: tuple[int, str, str, str] | None
    failure_reason: str | None

    @classmethod
    def complete(
        cls,
        request_url: str,
        response: InternalHTTPResponse,
    ) -> ContentBaselineObservation:
        refused_redirect = response.refused_redirect
        return cls(
            request_url=request_url,
            observation_status="complete",
            terminal_http_status=response.status_code,
            response_bytes=len(response.body),
            body_sha256=hashlib.sha256(response.body).hexdigest(),
            final_url=response.final_url,
            redirect_hops=tuple(
                (hop.status_code, hop.destination_url) for hop in response.redirects
            ),
            refused_redirect=(
                (
                    refused_redirect.status_code,
                    refused_redirect.source_url,
                    refused_redirect.destination_url,
                    refused_redirect.reason,
                )
                if refused_redirect is not None
                else None
            ),
            failure_reason=None,
        )

    @classmethod
    def failed(cls, request_url: str, reason: str) -> ContentBaselineObservation:
        return cls(
            request_url=request_url,
            observation_status="failed",
            terminal_http_status=None,
            response_bytes=None,
            body_sha256=None,
            final_url=None,
            redirect_hops=(),
            refused_redirect=None,
            failure_reason=reason,
        )


ContentComparisonSignature = tuple[
    int,
    int,
    str,
    str,
    tuple[tuple[int, str], ...],
    tuple[int, str, str, str] | None,
]


@dataclass(frozen=True)
class ContentBaselineDecision:
    """Deterministic policy selected from one origin's negative baseline."""

    origin: str
    classification: str
    selected_policy: str
    required_observations: int
    completed_observations: int
    observations: tuple[ContentBaselineObservation, ...]
    failure_or_instability_reason: str | None
    limitations: tuple[str, ...]
    comparison_signature: ContentComparisonSignature | None = None
    baseline_equivalent_candidates: int = 0
    retained_candidates: int = 0
    comparator_runtime_budget_seconds: int | None = None


@dataclass(frozen=True)
class _ContentArtifactSource:
    step_id: str
    path: Path
    partial: bool
    artifact_type: str
    description: str
    tags: tuple[str, ...]


class _ComparatorStopped(Exception):
    def __init__(self, decision: ContentBaselineDecision) -> None:
        super().__init__("Internal exact-body comparison stopped.")
        self.decision = decision


def collect_content_discovery_baseline(
    origin: str,
    executor: InternalHTTPExecutor,
    *,
    token_factory: Callable[[], str] | None = None,
    retain_refused_redirect_response: bool = False,
) -> ContentBaselineDecision:
    """Collect exactly three bounded negative paths through the enforced executor."""

    request_urls = _negative_request_urls(origin, token_factory or _default_token)
    observations: list[ContentBaselineObservation] = []
    request = (
        executor.request_retaining_refused_redirect
        if retain_refused_redirect_response
        else executor.request
    )
    for request_url in request_urls:
        try:
            response = request(
                request_url,
                method="GET",
                timeout_seconds=BASELINE_REQUEST_TIMEOUT_SECONDS,
                maximum_response_bytes=BASELINE_MAXIMUM_RESPONSE_BYTES,
                allow_query_strings=False,
            )
        except InternalHTTPExecutionError as exc:
            observations.append(
                ContentBaselineObservation.failed(
                    request_url,
                    _baseline_failure_reason(exc),
                )
            )
        else:
            observations.append(ContentBaselineObservation.complete(request_url, response))
    return classify_content_discovery_baseline(origin, tuple(observations))


def classify_content_discovery_baseline(
    origin: str,
    observations: tuple[ContentBaselineObservation, ...],
) -> ContentBaselineDecision:
    """Select conventional, exact-comparator, or fail-closed discovery."""

    completed = sum(item.observation_status == "complete" for item in observations)
    if len(observations) != BASELINE_REQUEST_COUNT or completed != BASELINE_REQUEST_COUNT:
        return ContentBaselineDecision(
            origin=origin,
            classification=BASELINE_CLASSIFICATION_FAILED,
            selected_policy=BASELINE_POLICY_REFUSE,
            required_observations=BASELINE_REQUEST_COUNT,
            completed_observations=completed,
            observations=observations,
            failure_or_instability_reason="One or more required baseline observations failed.",
            limitations=(
                "No content discovery was attempted because the negative baseline was incomplete.",
            ),
        )

    statuses = {item.terminal_http_status for item in observations}
    if (
        len(statuses) == 1
        and next(iter(statuses)) in {404, 410}
        and all(not item.redirect_hops for item in observations)
    ):
        return ContentBaselineDecision(
            origin=origin,
            classification=BASELINE_CLASSIFICATION_CONVENTIONAL,
            selected_policy=BASELINE_POLICY_GOBUSTER,
            required_observations=BASELINE_REQUEST_COUNT,
            completed_observations=completed,
            observations=observations,
            failure_or_instability_reason=None,
            limitations=(
                "Conventional 404/410 responses may contain request-specific body content.",
            ),
        )

    signatures = {_observation_comparison_signature(item) for item in observations}
    if len(signatures) == 1:
        signature = next(iter(signatures))
        has_redirect = any(
            item.redirect_hops or item.refused_redirect is not None
            for item in observations
        )
        return ContentBaselineDecision(
            origin=origin,
            classification=(
                BASELINE_CLASSIFICATION_STABLE_REDIRECT
                if has_redirect
                else BASELINE_CLASSIFICATION_STABLE_FALLBACK
            ),
            selected_policy=BASELINE_POLICY_INTERNAL_COMPARATOR,
            required_observations=BASELINE_REQUEST_COUNT,
            completed_observations=completed,
            observations=observations,
            failure_or_instability_reason=None,
            limitations=(
                "Exact baseline equivalence is indistinguishable from a catch-all response; "
                "suppression is not evidence that a path is absent.",
            ),
            comparison_signature=signature,
        )

    return ContentBaselineDecision(
        origin=origin,
        classification=BASELINE_CLASSIFICATION_UNSTABLE,
        selected_policy=BASELINE_POLICY_REFUSE,
        required_observations=BASELINE_REQUEST_COUNT,
        completed_observations=completed,
        observations=observations,
        failure_or_instability_reason=(
            "Successful baseline observations varied in status, length, body hash, "
            "final URL, or redirect sequence."
        ),
        limitations=(
            "No content discovery was attempted because the negative baseline was unstable.",
        ),
    )


def response_comparison_signature(
    response: InternalHTTPResponse,
) -> ContentComparisonSignature:
    """Return the complete body-bounded signature used for exact suppression."""

    return (
        response.status_code,
        len(response.body),
        hashlib.sha256(response.body).hexdigest(),
        _relative_final_url_marker(response.requested_url, response.final_url),
        tuple((hop.status_code, hop.destination_url) for hop in response.redirects),
        (
            (
                response.refused_redirect.status_code,
                _relative_final_url_marker(
                    response.requested_url,
                    response.refused_redirect.source_url,
                ),
                response.refused_redirect.destination_url,
                response.refused_redirect.reason,
            )
            if response.refused_redirect is not None
            else None
        ),
    )


def calculate_content_comparator_runtime_budget(
    candidate_count: int,
    requests_per_second: Decimal | None,
) -> int:
    """Return a deterministic per-origin comparator safety ceiling."""

    if (
        isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or not 1 <= candidate_count <= MAX_INTERNAL_COMPARATOR_CANDIDATES
    ):
        raise ValueError("Content comparator candidate count is outside bounds.")
    pacing_allowance = 0
    if requests_per_second is not None:
        if (
            isinstance(requests_per_second, bool)
            or not isinstance(requests_per_second, Decimal)
            or not requests_per_second.is_finite()
            or requests_per_second <= 0
        ):
            raise ValueError("Content comparator request rate is invalid.")
        pacing_allowance = int(
            (Decimal(candidate_count) / requests_per_second).to_integral_value(
                rounding=ROUND_CEILING
            )
        )
    calculated = (
        COMPARATOR_FIXED_ALLOWANCE_SECONDS
        + candidate_count * COMPARATOR_PER_CANDIDATE_ALLOWANCE_SECONDS
        + pacing_allowance
    )
    return min(calculated, MAX_COMPARATOR_RUNTIME_SECONDS)


def load_content_discovery_plan(path: Path) -> ContentDiscoveryPlan:
    """Load and strictly validate a BugSlyce content discovery plan."""

    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Content discovery plan does not exist: {path}")
    if path.name != "content_discovery_plan.json":
        raise ValueError("Live content discovery requires content_discovery_plan.json.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse content discovery plan {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Content discovery plan must contain a JSON object.")

    schema_version = payload.get("schema_version")
    if schema_version not in {None, CONTENT_DISCOVERY_SCHEMA_VERSION}:
        raise ValueError(f"Unsupported content discovery plan schema: {schema_version}.")
    created_by = payload.get("created_by")
    if created_by not in {None, CONTENT_DISCOVERY_CREATED_BY}:
        raise ValueError("Content discovery plan provenance is not recognised.")

    target = _required_text(payload, "target")
    profile = _required_text(payload, "profile")
    profile_definition = get_content_discovery_profile(profile)
    input_dir = Path(_required_text(payload, "input_dir")).expanduser().resolve()
    output_dir = Path(_required_text(payload, "output_dir")).expanduser().resolve()
    scope_file = _required_text(payload, "scope_file")
    if output_dir != path.parent:
        raise ValueError("Content discovery plan must remain in its planned output directory.")
    if not input_dir.is_dir():
        raise ValueError(f"Original recon input directory does not exist: {input_dir}")
    if not _safe_output_dir(input_dir):
        raise ValueError("Original recon input directory is not an approved local recon path.")
    if not _safe_output_dir(output_dir):
        raise ValueError("Content discovery plan output directory is not an approved local path.")

    raw_origins = payload.get("origins")
    if not isinstance(raw_origins, list) or any(not isinstance(item, str) for item in raw_origins):
        raise ValueError("Content discovery plan origins must be a list of strings.")
    origins = list(dict.fromkeys(raw_origins))

    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("Content discovery plan must contain at least one planned step.")
    if len(raw_steps) > MAX_CONTENT_PLAN_ORIGINS:
        raise ValueError(
            f"Content discovery plan exceeds the {MAX_CONTENT_PLAN_ORIGINS}-origin limit."
        )
    steps = [
        _parse_step(item, index, target, output_dir, profile_definition)
        for index, item in enumerate(raw_steps, start=1)
    ]
    step_origins = [step.origin for step in steps]
    if origins != step_origins:
        raise ValueError("Content discovery plan origins do not match its planned steps.")
    if len(origins) != len(set(origins)):
        raise ValueError("Content discovery plan contains duplicate origins.")
    if payload.get("no_commands_executed") is not True:
        raise ValueError("Content discovery plan is not marked as non-executing.")

    warnings = _string_list(payload.get("warnings"), "warnings")
    safety_notes = _string_list(payload.get("safety_notes"), "safety_notes")
    return ContentDiscoveryPlan(
        schema_version=CONTENT_DISCOVERY_SCHEMA_VERSION,
        created_by=CONTENT_DISCOVERY_CREATED_BY,
        target=target,
        profile=profile,
        input_dir=str(input_dir),
        scope_file=scope_file,
        output_dir=str(output_dir),
        origins=origins,
        steps=steps,
        warnings=warnings,
        safety_notes=safety_notes,
        no_commands_executed=True,
    )


def run_content_discovery_workflow(
    plan_path: Path,
    scope_file: Path,
    runner: LiveContentDiscoveryRunner | None = None,
    wordlist_check: Callable[[Path], bool] | None = None,
    step_id: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
    http_executor: InternalHTTPExecutor | None = None,
    token_factory: Callable[[], str] | None = None,
    comparator_monotonic: Callable[[], float] = time.monotonic,
    comparator_progress_callback: Callable[[str], None] | None = None,
    comparator_progress_interval_seconds: float = COMPARATOR_PROGRESS_INTERVAL_SECONDS,
    gobuster_progress_callback: (
        Callable[[ContentDiscoveryProgressEvent], None] | None
    ) = None,
    project_runtime=None,
) -> ReconContentDiscoveryExecutionResult:
    """Execute exact root discovery commands from one validated plan."""

    plan_path = plan_path.expanduser().resolve()
    plan = load_content_discovery_plan(plan_path)
    target = validate_explicit_nmap_target_scope(plan.target, scope_file)
    input_dir = Path(plan.input_dir)
    output_dir = Path(plan.output_dir)
    selected_steps = _select_steps(plan, step_id)

    state_before = build_project_state(input_dir)
    if project_runtime is None:
        enforce_r0b2_bug_bounty_live_block(state_before.engagement_context)
    else:
        from bugslyce.recon.project_runtime import require_project_runtime_binding

        require_project_runtime_binding(
            project_runtime,
            input_dir,
            scope_file,
            target,
            runner,
            "gobuster",
            http_executor=http_executor,
        )
    if (
        state_before.recon_manifest is None
        or state_before.recon_manifest.target.strip().lower() != target
    ):
        raise ValueError("Original recon manifest target does not match the content plan.")
    current_origins = set(
        discover_content_plan_origins(
            state_before,
            target,
            max_origins=max(MAX_CONTENT_PLAN_ORIGINS, len(state_before.http_services)),
        )
    )
    if any(step.origin not in current_origins for step in selected_steps):
        raise ValueError(
            "Content discovery plan contains an origin not present in current BugSlyce evidence."
        )

    profile_definition = get_content_discovery_profile(plan.profile)
    checker = wordlist_check or Path.is_file
    if not checker(profile_definition.wordlist):
        raise ValueError(
            f"Approved content discovery wordlist does not exist: {profile_definition.wordlist}"
        )

    owns_executor = http_executor is None
    enforced_executor = http_executor or _build_project_http_executor(
        input_dir=input_dir,
        scope_file=scope_file,
        target=target,
        engagement_context=state_before.engagement_context,
        approved_origins=tuple(step.origin for step in selected_steps),
    )
    try:
        return _execute_content_discovery(
            plan_path=plan_path,
            plan=plan,
            scope_file=scope_file,
            target=target,
            input_dir=input_dir,
            output_dir=output_dir,
            selected_steps=selected_steps,
            profile_definition=profile_definition,
            enforced_executor=enforced_executor,
            token_factory=token_factory,
            comparator_monotonic=comparator_monotonic,
            comparator_progress_callback=comparator_progress_callback,
            comparator_progress_interval_seconds=comparator_progress_interval_seconds,
            runner=runner,
            step_id=step_id,
            progress_callback=progress_callback,
            gobuster_progress_callback=gobuster_progress_callback,
        )
    finally:
        if owns_executor:
            enforced_executor.close()


def _execute_content_discovery(
    *,
    plan_path: Path,
    plan: ContentDiscoveryPlan,
    scope_file: Path,
    target: str,
    input_dir: Path,
    output_dir: Path,
    selected_steps: list[ContentDiscoveryStep],
    profile_definition,
    enforced_executor: InternalHTTPExecutor,
    token_factory: Callable[[], str] | None,
    comparator_monotonic: Callable[[], float],
    comparator_progress_callback: Callable[[str], None] | None,
    comparator_progress_interval_seconds: float,
    runner: LiveContentDiscoveryRunner | None,
    step_id: str | None,
    progress_callback: Callable[[str], None] | None,
    gobuster_progress_callback: Callable[[ContentDiscoveryProgressEvent], None] | None,
) -> ReconContentDiscoveryExecutionResult:
    baseline_decisions = tuple(
        collect_content_discovery_baseline(
            step.origin,
            enforced_executor,
            token_factory=token_factory,
        )
        for step in selected_steps
    )
    baseline_artifact_path = input_dir / BASELINE_ARTIFACT_NAME
    write_content_discovery_baseline_artifact(
        baseline_artifact_path,
        baseline_decisions,
    )
    if any(decision.selected_policy == BASELINE_POLICY_REFUSE for decision in baseline_decisions):
        raise ContentDiscoveryBaselineRefused(
            baseline_artifact_path,
            baseline_decisions,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    decision_by_origin = {decision.origin: decision for decision in baseline_decisions}
    conventional_steps = [
        step
        for step in selected_steps
        if decision_by_origin[step.origin].selected_policy == BASELINE_POLICY_GOBUSTER
    ]
    live_runner = runner
    if conventional_steps and live_runner is None:
        live_runner = LiveContentDiscoveryRunner(
            output_dir,
            target,
            {step.origin for step in conventional_steps},
            plan.profile,
        )
    command_results = []
    artifact_sources: list[_ContentArtifactSource] = []
    discovery_started_origins: set[str] = set()
    total_steps = len(selected_steps)
    for index, step in enumerate(selected_steps, start=1):
        decision = decision_by_origin[step.origin]
        if decision.selected_policy == BASELINE_POLICY_INTERNAL_COMPARATOR:
            try:
                artifact_source, decision = _run_internal_exact_body_comparator(
                    step,
                    profile_definition.wordlist,
                    output_dir,
                    enforced_executor,
                    decision,
                    monotonic=comparator_monotonic,
                    progress_callback=comparator_progress_callback,
                    progress_interval_seconds=comparator_progress_interval_seconds,
                    on_first_request=lambda origin=step.origin: discovery_started_origins.add(
                        origin
                    ),
                )
            except _ComparatorStopped as stopped:
                decision_by_origin[step.origin] = stopped.decision
                updated_decisions = tuple(
                    decision_by_origin[item.origin] for item in selected_steps
                )
                write_content_discovery_baseline_artifact(
                    baseline_artifact_path,
                    updated_decisions,
                )
                raise ContentDiscoveryComparatorIncomplete(
                    baseline_artifact_path,
                    stopped.decision,
                ) from None
            artifact_sources.append(artifact_source)
            decision_by_origin[step.origin] = decision
            write_content_discovery_baseline_artifact(
                baseline_artifact_path,
                tuple(decision_by_origin[item.origin] for item in selected_steps),
            )
            continue

        command = build_live_content_discovery_command(step, plan)
        _emit_progress(
            progress_callback,
            "\n".join(
                [
                    "BugSlyce content discovery step starting",
                    f"Step: {step.step_id}",
                    f"Progress: {index}/{total_steps}",
                    f"Origin: {step.origin}",
                    f"Profile: {plan.profile}",
                ]
            ),
        )
        started = time.monotonic()
        assert live_runner is not None
        discovery_started_origins.add(step.origin)

        def forward_gobuster_progress(event: ContentDiscoveryProgressEvent) -> None:
            if gobuster_progress_callback is not None:
                gobuster_progress_callback(event)
            _emit_progress(
                progress_callback,
                render_content_discovery_progress(
                    origin=event.origin,
                    completed=event.completed,
                    total=event.total,
                    elapsed_seconds=event.elapsed_seconds,
                    trusted=event.trusted,
                ),
            )

        result = (
            live_runner.run(command, progress_callback=forward_gobuster_progress)
            if isinstance(live_runner, LiveContentDiscoveryRunner)
            else live_runner.run(command)
        )
        elapsed = max(0.0, time.monotonic() - started)
        if result.executed:
            command_results.append(result)
        if _is_timeout_result(result):
            partial_sources = list(artifact_sources)
            output_path = Path(result.output_file)
            if output_path.is_file() and output_path.stat().st_size > 0:
                partial_sources.append(_gobuster_artifact_source(step, output_path, True))
            execution_result = _finalize_execution(
                plan_path,
                plan,
                scope_file,
                command_results,
                partial_sources,
                timed_out_result=result,
                selected_step_id=step_id,
                baseline_artifact_path=baseline_artifact_path,
                baseline_decisions=tuple(
                    decision_by_origin[item.origin] for item in selected_steps
                ),
                discovery_started_origins=[
                    item.origin
                    for item in selected_steps
                    if item.origin in discovery_started_origins
                ],
            )
            partial_imported = any(
                Path(path).name == Path(result.output_file).name
                for path in execution_result.artifact_paths
            )
            _emit_progress(
                progress_callback,
                "\n".join(
                    [
                        "BugSlyce content discovery step timed out",
                        f"Step: {step.step_id}",
                        f"Origin: {step.origin}",
                        f"Elapsed seconds: {elapsed:.2f}",
                        f"Partial output imported: {str(partial_imported).lower()}",
                    ]
                ),
            )
            raise ContentDiscoveryExecutionIncomplete(result.error or "Content discovery timed out.", execution_result)
        if result.error or result.exit_code != 0:
            _emit_progress(
                progress_callback,
                "\n".join(
                    [
                        "BugSlyce content discovery step failed",
                        f"Step: {step.step_id}",
                        f"Origin: {step.origin}",
                        f"Elapsed seconds: {elapsed:.2f}",
                    ]
                ),
            )
            raise ValueError(result.error or "Content discovery did not complete successfully.")
        output_path = Path(result.output_file)
        if not output_path.is_file():
            raise ValueError(
                "Content discovery completed without creating its expected output file."
            )
        _emit_progress(
            progress_callback,
            "\n".join(
                [
                    "BugSlyce content discovery step complete",
                    f"Step: {step.step_id}",
                    f"Elapsed seconds: {elapsed:.2f}",
                    f"Artefact: {output_path}",
                ]
            ),
        )
        artifact_sources.append(_gobuster_artifact_source(step, output_path, False))

    final_decisions = tuple(
        decision_by_origin[step.origin] for step in selected_steps
    )
    write_content_discovery_baseline_artifact(
        baseline_artifact_path,
        final_decisions,
    )
    return _finalize_execution(
        plan_path,
        plan,
        scope_file,
        command_results,
        artifact_sources,
        timed_out_result=None,
        selected_step_id=step_id,
        baseline_artifact_path=baseline_artifact_path,
        baseline_decisions=final_decisions,
        discovery_started_origins=[
            item.origin
            for item in selected_steps
            if item.origin in discovery_started_origins
        ],
    )


def _build_project_http_executor(
    *,
    input_dir: Path,
    scope_file: Path,
    target: str,
    engagement_context: str,
    approved_origins: tuple[str, ...],
) -> InternalHTTPExecutor:
    if engagement_context != BUG_BOUNTY_CONTEXT:
        return InternalHTTPExecutor(None)

    project = load_project(input_dir / PROJECT_FILENAME)
    if Path(project.output_dir).expanduser().resolve() != input_dir.resolve():
        raise ValueError("Project output directory does not match the content plan.")
    if Path(project.scope_file).expanduser().resolve() != scope_file.expanduser().resolve():
        raise ValueError("Project scope file does not match the content workflow.")
    if project.target != target:
        raise ValueError("Project target does not match the content plan.")
    engagement_policy = load_project_engagement_policy(project)
    if engagement_policy is None:
        raise ValueError("Programme-scoped content discovery requires engagement policy.")
    programme_scope_policy = load_project_programme_scope_policy(project)
    if programme_scope_policy is None:
        raise ValueError("Programme-scoped content discovery requires programme scope.")
    configuration = build_http_enforcement_configuration(
        engagement_policy,
        approved_origins=approved_origins,
    )
    return _create_project_http_executor(configuration, programme_scope_policy)


def _create_project_http_executor(
    configuration: HTTPEnforcementConfiguration,
    programme_scope_policy: ProgrammeScopePolicy,
) -> InternalHTTPExecutor:
    return InternalHTTPExecutor(
        configuration,
        programme_scope_policy=programme_scope_policy,
    )


def write_content_discovery_execution_result(
    result: ReconContentDiscoveryExecutionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and Markdown metadata for controlled root discovery."""

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(result), indent=2, sort_keys=True) + "\n"
    markdown = render_content_discovery_execution_markdown(result)

    legacy_json_path = output_dir / "content_discovery_execution.json"
    legacy_markdown_path = output_dir / "content_discovery_execution.md"
    legacy_json_path.write_text(payload, encoding="utf-8")
    legacy_markdown_path.write_text(markdown, encoding="utf-8")

    input_dir = Path(result.input_dir).expanduser().resolve()
    input_dir.mkdir(parents=True, exist_ok=True)
    json_path = input_dir / "recon_execution.json"
    markdown_path = input_dir / "recon_execution.md"
    phase_json_path = input_dir / "recon_execution_content_run.json"
    phase_markdown_path = input_dir / "recon_execution_content_run.md"
    for path in (json_path, phase_json_path):
        path.write_text(payload, encoding="utf-8")
    for path in (markdown_path, phase_markdown_path):
        path.write_text(markdown, encoding="utf-8")
    return json_path, markdown_path


def render_content_discovery_execution_markdown(
    result: ReconContentDiscoveryExecutionResult,
) -> str:
    """Render controlled content discovery execution metadata."""

    return "\n".join(
        [
            "# BugSlyce Content Discovery Execution",
            "",
            f"- Target: `{result.target}`",
            f"- Profile: `{result.profile}`",
            f"- Plan path: `{result.plan_path}`",
            f"- Original recon directory: `{result.input_dir}`",
            f"- Plan output directory: `{result.output_dir}`",
            f"- Origins executed: {len(result.origins)}",
            f"- Selected step ID: `{result.selected_step_id or 'all planned steps'}`",
            f"- Selected origin: `{result.selected_origin or 'all planned origins'}`",
            f"- Commands started: {result.commands_started}",
            f"- Commands completed: {result.commands_completed}",
            f"- Commands timed out: {result.commands_timed_out}",
            f"- Timed-out step ID: `{result.timed_out_step_id or 'none'}`",
            f"- Timed-out origin: `{result.timed_out_origin or 'none'}`",
            f"- Content discovery artefacts written: {len(result.artifact_paths)}",
            f"- Baseline artefact: `{result.baseline_artifact_path or 'none'}`",
            f"- Partial artefacts imported: {result.partial_artifacts_imported}",
            f"- Completed artefacts imported: {result.completed_artifacts_imported}",
            f"- Report: `{result.report_path}`",
            f"- Project state: `{result.project_state_path}`",
            "",
            (
                "Root content discovery timed out after starting."
                if result.commands_timed_out
                else "Bounded root content discovery was executed."
            ),
            "No recursion, dynamic Gobuster extension expansion (`-x`), brute force, exploitation, or form submission was run.",
            "",
        ]
    )


def render_content_discovery_execution_summary(
    result: ReconContentDiscoveryExecutionResult,
) -> str:
    """Render concise CLI output for controlled root discovery."""

    return "\n".join(
        [
            "BugSlyce content discovery complete",
            f"Target: {result.target}",
            f"Profile: {result.profile}",
            f"Plan path: {result.plan_path}",
            f"Original recon directory: {result.input_dir}",
            f"Planned/executed origins: {len(result.origins)}",
            f"Selected step ID: {result.selected_step_id or 'all planned steps'}",
            f"Selected origin: {result.selected_origin or 'all planned origins'}",
            f"Commands started: {result.commands_started}",
            f"Commands completed: {result.commands_completed}",
            f"Commands timed out: {result.commands_timed_out}",
            f"Timed-out step ID: {result.timed_out_step_id or 'none'}",
            f"Timed-out origin: {result.timed_out_origin or 'none'}",
            f"Content discovery artefacts written: {len(result.artifact_paths)}",
            f"Baseline artefact: {result.baseline_artifact_path or 'none'}",
            f"Partial artefacts imported: {result.partial_artifacts_imported}",
            f"Completed artefacts imported: {result.completed_artifacts_imported}",
            f"Report path: {result.report_path}",
            f"JSON path: {result.project_state_path}",
            (
                "Root content discovery timed out after starting."
                if result.commands_timed_out
                else "Bounded root content discovery was executed."
            ),
            "No recursion, dynamic Gobuster extension expansion (`-x`), brute force, exploitation, or form submission was run.",
        ]
    )


def _negative_request_urls(
    origin: str,
    token_factory: Callable[[], str],
) -> tuple[str, ...]:
    parsed_origin = urlparse(origin)
    if (
        parsed_origin.scheme not in {"http", "https"}
        or not parsed_origin.hostname
        or parsed_origin.path != "/"
        or parsed_origin.params
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise ValueError("Content baseline requires a canonical HTTP root origin.")
    tokens = tuple(token_factory() for _ in range(BASELINE_REQUEST_COUNT))
    if len(set(tokens)) != BASELINE_REQUEST_COUNT:
        raise ValueError("Content baseline token factory must produce distinct tokens.")
    if any(
        not isinstance(token, str)
        or not token
        or len(token) > 128
        or _TOKEN_PATTERN.fullmatch(token) is None
        for token in tokens
    ):
        raise ValueError("Content baseline token factory produced an unsafe token.")
    return tuple(
        urljoin(origin, f".bugslyce-negative-{token}") for token in tokens
    )


def _default_token() -> str:
    return secrets.token_hex(16)


def _baseline_failure_reason(exc: InternalHTTPExecutionError) -> str:
    if isinstance(exc, HTTPProgrammeScopeRefused):
        return f"programme_scope_refused:{exc.reason_code}"
    if isinstance(exc, HTTPTransportFailure):
        return f"transport_failure:{exc.category}"
    if isinstance(exc, HTTPRedirectRefused):
        return "redirect_refused"
    if isinstance(exc, HTTPRateRejected):
        return "rate_rejected"
    if isinstance(exc, HTTPExecutorClosed):
        return "executor_closed"
    return "internal_http_failure"


def _observation_comparison_signature(
    observation: ContentBaselineObservation,
) -> ContentComparisonSignature:
    if (
        observation.observation_status != "complete"
        or observation.terminal_http_status is None
        or observation.response_bytes is None
        or observation.body_sha256 is None
        or observation.final_url is None
    ):
        raise ValueError("Incomplete content baseline observation has no signature.")
    return (
        observation.terminal_http_status,
        observation.response_bytes,
        observation.body_sha256,
        _relative_final_url_marker(observation.request_url, observation.final_url),
        observation.redirect_hops,
        (
            (
                observation.refused_redirect[0],
                _relative_final_url_marker(
                    observation.request_url,
                    observation.refused_redirect[1],
                ),
                observation.refused_redirect[2],
                observation.refused_redirect[3],
            )
            if observation.refused_redirect is not None
            else None
        ),
    )


def _relative_final_url_marker(request_url: str, final_url: str) -> str:
    return "requested_url" if final_url == request_url else final_url


def write_content_discovery_baseline_artifact(
    path: Path,
    decisions: tuple[ContentBaselineDecision, ...],
    *,
    created_by: str = LEGACY_CONTENT_BASELINE_CREATED_BY,
) -> None:
    if not isinstance(created_by, str) or _TOKEN_PATTERN.fullmatch(created_by) is None:
        raise ValueError("Content baseline producer must be a non-blank token.")
    payload = {
        "schema_version": "1.0",
        "created_by": created_by,
        "required_observations_per_origin": BASELINE_REQUEST_COUNT,
        "origins": [_baseline_decision_payload(decision) for decision in decisions],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _baseline_decision_payload(decision: ContentBaselineDecision) -> dict[str, object]:
    return {
        "origin": decision.origin,
        "generated_negative_request_urls": [
            observation.request_url for observation in decision.observations
        ],
        "observations": [
            _baseline_observation_payload(observation)
            for observation in decision.observations
        ],
        "classification": decision.classification,
        "selected_policy": decision.selected_policy,
        "required_observations": decision.required_observations,
        "completed_observations": decision.completed_observations,
        "failure_or_instability_reason": decision.failure_or_instability_reason,
        "limitations": list(decision.limitations),
        "baseline_equivalent_candidate_count": decision.baseline_equivalent_candidates,
        "retained_candidate_count": decision.retained_candidates,
        "comparator_runtime_budget_seconds": (
            decision.comparator_runtime_budget_seconds
        ),
    }


def _baseline_observation_payload(
    observation: ContentBaselineObservation,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "request_url": observation.request_url,
        "observation_status": observation.observation_status,
        "terminal_http_status": observation.terminal_http_status,
        "response_bytes": observation.response_bytes,
        "body_sha256": observation.body_sha256,
        "final_url": observation.final_url,
        "redirect_hops": [
            {"status_code": status, "destination_url": destination}
            for status, destination in observation.redirect_hops
        ],
        "failure_reason": observation.failure_reason,
    }
    if observation.refused_redirect is not None:
        payload["refused_redirect"] = {
            "status_code": observation.refused_redirect[0],
            "source_url": observation.refused_redirect[1],
            "destination_url": observation.refused_redirect[2],
            "reason": observation.refused_redirect[3],
        }
    return payload


def _run_internal_exact_body_comparator(
    step: ContentDiscoveryStep,
    wordlist: Path,
    output_dir: Path,
    executor: InternalHTTPExecutor,
    baseline: ContentBaselineDecision,
    *,
    monotonic: Callable[[], float],
    progress_callback: Callable[[str], None] | None,
    progress_interval_seconds: float,
    on_first_request: Callable[[], None],
) -> tuple[_ContentArtifactSource, ContentBaselineDecision]:
    if baseline.comparison_signature is None:
        raise ValueError("Stable fallback baseline lacks a comparison signature.")
    entries = _load_internal_comparator_entries(wordlist)
    configuration = getattr(executor, "configuration", None)
    requests_per_second = (
        getattr(configuration, "maximum_request_starts_per_second", None)
        if configuration is not None
        else None
    )
    runtime_budget_seconds = calculate_content_comparator_runtime_budget(
        len(entries),
        requests_per_second,
    )
    baseline = replace(
        baseline,
        comparator_runtime_budget_seconds=runtime_budget_seconds,
    )
    retained_lines: list[str] = []
    suppressed = 0
    retained = 0
    if progress_interval_seconds <= 0:
        raise ValueError("Content comparator progress interval must be positive.")
    started_at = monotonic()
    deadline = started_at + runtime_budget_seconds
    next_progress_at = started_at + progress_interval_seconds
    progress_emitted = False
    last_progress_completed = 0
    request_started = False
    for entry in entries:
        remaining_timeout = min(
            BASELINE_REQUEST_TIMEOUT_SECONDS,
            int(deadline - monotonic()),
        )
        if remaining_timeout <= 0:
            stopped = replace(
                baseline,
                baseline_equivalent_candidates=suppressed,
                retained_candidates=retained,
                failure_or_instability_reason=(
                    "Internal exact-body comparison reached its "
                    f"{runtime_budget_seconds}-second aggregate runtime budget "
                    "before completing the approved wordlist."
                ),
                limitations=tuple(
                    dict.fromkeys(
                        (
                            *baseline.limitations,
                            "Candidate comparison is not complete; no comparator "
                            "artefact was imported.",
                        )
                    )
                ),
            )
            raise _ComparatorStopped(stopped)
        candidate_url = _wordlist_candidate_url(step.origin, entry)
        if not request_started:
            on_first_request()
            request_started = True
        try:
            response = executor.request(
                candidate_url,
                method="GET",
                timeout_seconds=remaining_timeout,
                maximum_response_bytes=BASELINE_MAXIMUM_RESPONSE_BYTES,
                allow_query_strings=False,
            )
        except InternalHTTPExecutionError as exc:
            reason = _baseline_failure_reason(exc)
            stopped = replace(
                baseline,
                baseline_equivalent_candidates=suppressed,
                retained_candidates=retained,
                failure_or_instability_reason=(
                    "Internal exact-body comparison stopped before completing the "
                    f"approved wordlist: {reason}."
                ),
                limitations=tuple(
                    dict.fromkeys(
                        (
                            *baseline.limitations,
                            "Candidate comparison is not complete; no comparator "
                            "artefact was imported.",
                        )
                    )
                ),
            )
            raise _ComparatorStopped(stopped) from None
        if response_comparison_signature(response) == baseline.comparison_signature:
            suppressed += 1
        else:
            retained += 1
            retained_lines.append(_comparator_output_line(candidate_url, response))
        if progress_callback is not None:
            now = monotonic()
            if now >= next_progress_at:
                completed = suppressed + retained
                progress_callback(
                    _render_comparator_progress(
                        completed=completed,
                        total=len(entries),
                        retained=retained,
                        suppressed=suppressed,
                        elapsed_seconds=now - started_at,
                    )
                )
                progress_emitted = True
                last_progress_completed = completed
                next_progress_at = now + progress_interval_seconds

    completed = suppressed + retained
    if (
        progress_callback is not None
        and progress_emitted
        and completed > last_progress_completed
    ):
        progress_callback(
            _render_comparator_progress(
                completed=completed,
                total=len(entries),
                retained=retained,
                suppressed=suppressed,
                elapsed_seconds=monotonic() - started_at,
            )
        )

    output_path = output_dir / _internal_comparator_filename(step.origin)
    output_path.write_text("".join(retained_lines), encoding="utf-8")
    updated = replace(
        baseline,
        baseline_equivalent_candidates=suppressed,
        retained_candidates=retained,
    )
    return (
        _ContentArtifactSource(
            step_id=step.step_id,
            path=output_path,
            partial=False,
            artifact_type=INTERNAL_COMPARATOR_ARTIFACT_TYPE,
            description=(
                "Bounded content discovery using the internal exact-body comparator"
            ),
            tags=(INTERNAL_COMPARATOR_TAG,),
        ),
        updated,
    )


def _render_comparator_progress(
    *,
    completed: int,
    total: int,
    retained: int,
    suppressed: int,
    elapsed_seconds: float,
) -> str:
    return (
        f"{completed}/{total} candidates checked; {retained} retained; "
        f"{suppressed} baseline-equivalent; elapsed {int(max(0.0, elapsed_seconds))}s"
    )


def _load_internal_comparator_entries(wordlist: Path) -> tuple[str, ...]:
    try:
        entries = tuple(
            line.strip()
            for line in wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    except (OSError, UnicodeError) as exc:
        raise ValueError("Approved content discovery wordlist could not be read.") from exc
    if not entries or len(entries) > MAX_INTERNAL_COMPARATOR_CANDIDATES:
        raise ValueError("Approved content discovery wordlist is outside comparator bounds.")
    return entries


def _wordlist_candidate_url(origin: str, entry: str) -> str:
    parsed_entry = urlparse(entry)
    if (
        parsed_entry.scheme
        or parsed_entry.netloc
        or parsed_entry.params
        or parsed_entry.query
        or parsed_entry.fragment
        or any(part == ".." for part in parsed_entry.path.split("/"))
    ):
        raise ValueError("Approved content discovery wordlist contains an unsafe entry.")
    candidate = urljoin(origin, entry.lstrip("/"))
    parsed_origin = urlparse(origin)
    parsed_candidate = urlparse(candidate)
    if (
        parsed_candidate.scheme != parsed_origin.scheme
        or parsed_candidate.netloc != parsed_origin.netloc
    ):
        raise ValueError("Content comparator candidate escaped its planned origin.")
    return candidate


def _comparator_output_line(
    candidate_url: str,
    response: InternalHTTPResponse,
) -> str:
    parsed = urlparse(candidate_url)
    path = parsed.path or "/"
    redirect = (
        f" [--> {response.final_url}]"
        if response.final_url != candidate_url
        else ""
    )
    return (
        f"{path} (Status: {response.status_code}) "
        f"[Size: {len(response.body)}]{redirect}\n"
    )


def _internal_comparator_filename(origin: str) -> str:
    parsed = urlparse(origin)
    safe_host = "".join(
        character if character.isalnum() or character in ".-" else "-"
        for character in (parsed.hostname or "host").lower()
    ).strip(".-") or "host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"content-discovery-internal-{safe_host}-{port}-root.txt"


def _gobuster_artifact_source(
    step: ContentDiscoveryStep,
    path: Path,
    partial: bool,
) -> _ContentArtifactSource:
    return _ContentArtifactSource(
        step_id=step.step_id,
        path=path,
        partial=partial,
        artifact_type="gobuster",
        description=(
            "Partial gobuster output from timed-out approved content discovery command"
            if partial
            else "Bounded root content discovery from approved BugSlyce content plan"
        ),
        tags=("partial", "timed_out") if partial else (),
    )


def _parse_step(
    value: object,
    index: int,
    target: str,
    output_dir: Path,
    profile_definition,
) -> ContentDiscoveryStep:
    if not isinstance(value, dict):
        raise ValueError(f"Content discovery step #{index} must be an object.")
    step_id = _required_text(value, "step_id")
    if step_id != f"CONTENT-STEP-{index:03d}":
        raise ValueError(f"Content discovery step #{index} has an invalid step ID.")
    origin = _required_text(value, "origin")
    parsed = urlparse(origin)
    normalized_origin = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname != target
        or origin != normalized_origin
    ):
        raise ValueError(f"Content discovery step #{index} is not a target root origin.")

    if value.get("allowed_tool") != "gobuster":
        raise ValueError(f"Content discovery step #{index} must allow only gobuster.")
    if value.get("risk_level") != "moderate":
        raise ValueError(f"Content discovery step #{index} has an invalid risk level.")
    for key, expected in (
        ("requires_confirmation", True),
        ("scope_sensitive", True),
        ("recursive_discovery", False),
        ("ready_for_execution", False),
        ("no_commands_executed", True),
    ):
        if value.get(key, False if expected is False else None) is not expected:
            raise ValueError(f"Content discovery step #{index} has invalid {key}.")
    extensions = value.get("extensions", [])
    if extensions != []:
        raise ValueError(f"Content discovery step #{index} must not include extensions.")

    expected_artifact_value = value.get("expected_artifact")
    if not isinstance(expected_artifact_value, dict):
        raise ValueError(f"Content discovery step #{index} lacks an expected artifact.")
    expected_file = _required_text(expected_artifact_value, "file")
    if Path(expected_file).name != expected_file:
        raise ValueError(f"Content discovery step #{index} has an unsafe artefact filename.")
    expected_artifact = ReconPlannedArtifact(
        type=_required_text(expected_artifact_value, "type"),
        file=expected_file,
        url=_optional_text(expected_artifact_value, "url"),
        base_url=_optional_text(expected_artifact_value, "base_url"),
        description=_optional_text(expected_artifact_value, "description"),
    )
    if expected_artifact.type != "gobuster" or expected_artifact.base_url != origin:
        raise ValueError(f"Content discovery step #{index} has invalid artifact context.")

    command_preview = value.get("command_preview")
    if not isinstance(command_preview, list) or any(
        not isinstance(item, str) for item in command_preview
    ):
        raise ValueError(f"Content discovery step #{index} command preview must be argv.")
    expected_argv = [
        "gobuster",
        "dir",
        "-u",
        origin,
        "-w",
        str(profile_definition.wordlist),
        "-t",
        str(profile_definition.threads),
        "--timeout",
        f"{GOBUSTER_REQUEST_TIMEOUT_SECONDS}s",
        "--no-color",
        "-o",
        str(output_dir / expected_file),
    ]
    if command_preview != expected_argv:
        raise ValueError(
            f"Content discovery step #{index} does not match the approved command shape."
        )

    return ContentDiscoveryStep(
        step_id=step_id,
        origin=origin,
        command_preview=command_preview,
        expected_artifact=expected_artifact,
        risk_level="moderate",
        requires_confirmation=True,
        scope_sensitive=True,
        allowed_tool="gobuster",
        recursive_discovery=False,
        extensions=[],
        ready_for_execution=False,
        no_commands_executed=True,
    )


def _load_manifest_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Original recon manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse original recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Original recon manifest must contain a JSON object.")
    return payload


def _updated_manifest(
    manifest: dict[str, object],
    plan: ContentDiscoveryPlan,
    artifacts_to_import: list[tuple[ContentDiscoveryStep, _ContentArtifactSource]],
) -> dict[str, object]:
    payload = dict(manifest)
    existing = payload.get("artifacts")
    artifacts = list(existing) if isinstance(existing, list) else []
    generated_names = {source.path.name for _step, source in artifacts_to_import}
    artifacts = [
        artifact
        for artifact in artifacts
        if not (
            isinstance(artifact, dict)
            and artifact.get("file") in generated_names
        )
    ]
    for step, source in artifacts_to_import:
        artifacts.append(
            {
                "type": source.artifact_type,
                "file": source.path.name,
                "base_url": step.origin,
                "description": source.description,
                "tags": list(source.tags),
            }
        )
    if artifacts_to_import:
        original_profile = payload.get("profile")
        suffix = "-plus-content-discovery"
        if isinstance(original_profile, str) and original_profile:
            profile = (
                original_profile
                if original_profile.endswith(suffix)
                else f"{original_profile}{suffix}"
            )
        else:
            profile = f"{plan.profile}-plus-content-discovery"
        payload["profile"] = profile
    payload["artifacts"] = artifacts
    return payload


def _finalize_execution(
    plan_path: Path,
    plan: ContentDiscoveryPlan,
    scope_file: Path,
    command_results,
    artifact_sources: list[_ContentArtifactSource],
    timed_out_result,
    selected_step_id: str | None,
    baseline_artifact_path: Path,
    baseline_decisions: tuple[ContentBaselineDecision, ...],
    discovery_started_origins: list[str],
) -> ReconContentDiscoveryExecutionResult:
    input_dir = Path(plan.input_dir)
    output_dir = Path(plan.output_dir)
    step_by_id = {step.step_id: step for step in plan.steps}
    copied: list[tuple[ContentDiscoveryStep, _ContentArtifactSource]] = []
    for artifact_source in artifact_sources:
        source = artifact_source.path.resolve()
        step = step_by_id[artifact_source.step_id]
        destination = (input_dir / source.name).resolve()
        try:
            destination.relative_to(input_dir.resolve())
        except ValueError as exc:
            raise ValueError("Content discovery artifact destination escaped the recon directory.") from exc
        if source != destination:
            shutil.copy2(source, destination)
        copied.append((step, replace(artifact_source, path=destination)))

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest_payload(manifest_path)
    updated_manifest = _updated_manifest(manifest, plan, copied)
    manifest_path.write_text(
        json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    project_state = build_project_state(input_dir)
    candidates = generate_candidates(project_state)
    report_path, project_state_path = write_project_outputs(project_state, candidates, input_dir)

    completed = sum(result.exit_code == 0 and not result.error for result in command_results)
    timed_out = 1 if timed_out_result is not None else 0
    return ReconContentDiscoveryExecutionResult(
        mode="content-run",
        plan_path=str(plan_path),
        target=plan.target,
        profile=plan.profile,
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        origins=discovery_started_origins,
        artifact_paths=[str(source.path) for _step, source in copied],
        manifest_path=str(manifest_path),
        report_path=str(report_path),
        project_state_path=str(project_state_path),
        execution_count=len(command_results),
        commands_started=len(command_results),
        commands_completed=completed,
        commands_timed_out=timed_out,
        selected_step_id=selected_step_id,
        selected_origin=(
            step_by_id[selected_step_id].origin
            if selected_step_id is not None
            else None
        ),
        partial_artifacts_imported=sum(source.partial for _step, source in copied),
        completed_artifacts_imported=sum(
            not source.partial for _step, source in copied
        ),
        timed_out_step_id=timed_out_result.command_id if timed_out_result else None,
        timed_out_origin=(
            step_by_id[timed_out_result.command_id].origin
            if timed_out_result and timed_out_result.command_id in step_by_id
            else None
        ),
        command_results=command_results,
        no_recursion=True,
        no_extensions=True,
        no_arbitrary_urls=True,
        no_exploitation=True,
        warnings=project_state.warnings,
        baseline_artifact_path=str(baseline_artifact_path),
        origin_decisions=[
            ContentDiscoveryOriginDecision(
                origin=decision.origin,
                classification=decision.classification,
                selected_policy=decision.selected_policy,
                baseline_equivalent_candidates=decision.baseline_equivalent_candidates,
                retained_candidates=decision.retained_candidates,
            )
            for decision in baseline_decisions
        ],
        baseline_limitations=list(
            dict.fromkeys(
                limitation
                for decision in baseline_decisions
                for limitation in decision.limitations
            )
        ),
    )


def _select_steps(
    plan: ContentDiscoveryPlan,
    step_id: str | None,
) -> list[ContentDiscoveryStep]:
    if step_id is None:
        return list(plan.steps)
    matches = [step for step in plan.steps if step.step_id == step_id]
    if not matches:
        raise ValueError(
            f"Content discovery step '{step_id}' is not present in the approved plan."
        )
    return matches


def _emit_progress(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _is_timeout_result(result) -> bool:
    return (
        result.executed
        and result.exit_code is None
        and bool(result.error)
        and "started and exceeded" in result.error
    )


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Content discovery plan field '{key}' is required.")
    return value.strip()


def _optional_text(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Content discovery plan {name} must be a list of strings.")
    return list(value)


def _safe_output_dir(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(Path("/tmp"))
        return True
    except ValueError:
        return any(
            part in {"private_recon", "raw-recon", "bugslyce-output"}
            for part in resolved.parts
        )
