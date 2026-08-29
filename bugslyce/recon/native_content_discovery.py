"""Programme-bound, BugSlyce-native bounded root content discovery."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import stat
import tempfile
from urllib.parse import urljoin, urlparse

from bugslyce.core.models import ProjectState
from bugslyce.recon.content_plan import get_content_discovery_profile
from bugslyce.recon.content_run import (
    BASELINE_CLASSIFICATION_CONVENTIONAL,
    BASELINE_CLASSIFICATION_STABLE_FALLBACK,
    BASELINE_CLASSIFICATION_STABLE_REDIRECT,
    BASELINE_MAXIMUM_RESPONSE_BYTES,
    BASELINE_POLICY_REFUSE,
    BASELINE_REQUEST_COUNT,
    BASELINE_REQUEST_TIMEOUT_SECONDS,
    INTERNAL_COMPARATOR_ARTIFACT_TYPE,
    MAX_INTERNAL_COMPARATOR_CANDIDATES,
    ContentBaselineDecision,
    collect_content_discovery_baseline,
    response_comparison_signature,
)
from bugslyce.recon.http_enforcement import (
    InternalHTTPExecutor,
    PeerBoundHTTPTransport,
    build_http_enforcement_configuration,
    build_internal_http_executor_view,
    internal_http_executors_share_enforcement_state,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.programme_orchestration import (
    ProgrammeOrchestrationPlan,
    require_programme_orchestration_plan_binding,
)
from bugslyce.recon.project_runtime import BugBountyProjectRuntime


PROFILE_WORDLIST_SELECTION_REASON = "profile_wordlist"
NATIVE_CONVENTIONAL_NEGATIVE_POLICY = "native_conventional_negative"
MAXIMUM_NATIVE_CANDIDATE_REQUESTS = MAX_INTERNAL_COMPARATOR_CANDIDATES
MAXIMUM_NATIVE_WORDLIST_BYTES = 1_000_000


@dataclass(frozen=True)
class NativeContentDiscoveryLimits:
    """Explicit candidate-request ceilings, excluding baseline probes."""

    maximum_total_candidate_requests: int
    maximum_candidate_requests_per_origin: int

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
                raise ValueError("Native content discovery request budget is invalid.")


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
class NativeContentDiscoveryPlan:
    """Immutable deterministic root-request plan for one approved profile."""

    profile: str
    limits: NativeContentDiscoveryLimits
    baseline_requests_per_origin: int
    candidate_requests_planned: int
    requests: tuple[NativeContentDiscoveryRequest, ...]

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


@dataclass(frozen=True)
class NativeContentDiscoveryArtifact:
    """One parser-compatible retained native discovery artefact."""

    artifact_type: str
    canonical_origin: str
    profile: str
    selection_reason: str
    path: Path


@dataclass(frozen=True)
class NativeContentDiscoveryOriginResult:
    """One origin's truthful baseline and candidate disposition."""

    canonical_origin: str
    baseline_decision: ContentBaselineDecision
    suppressed_candidate_count: int
    retained_candidate_count: int


@dataclass(frozen=True)
class NativeContentDiscoveryResult:
    """Deterministic native execution result; no external commands are involved."""

    external_commands_started: int
    origin_results: tuple[NativeContentDiscoveryOriginResult, ...]
    artifacts: tuple[NativeContentDiscoveryArtifact, ...]


class NativeContentDiscoveryBaselineRefused(ValueError):
    """Typed refusal retaining the native baseline decisions that stopped work."""

    def __init__(self, decisions: tuple[ContentBaselineDecision, ...]) -> None:
        if (
            not isinstance(decisions, tuple)
            or not decisions
            or any(
                not isinstance(decision, ContentBaselineDecision)
                for decision in decisions
            )
        ):
            raise ValueError("Native baseline refusal decisions are invalid.")
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


@dataclass(frozen=True)
class _StagedNativeArtifact:
    final_path: Path
    temporary_path: Path
    device: int
    inode: int


def build_native_content_discovery_http_executor(
    runtime: BugBountyProjectRuntime,
    project_state: ProjectState,
    orchestration_plan: ProgrammeOrchestrationPlan,
) -> InternalHTTPExecutor:
    """Build an exact-origin view of the runtime's aggregate HTTP enforcement."""

    bound_plan = require_programme_orchestration_plan_binding(
        runtime,
        orchestration_plan,
        project_state=project_state,
    )
    origins = tuple(item.canonical_origin for item in bound_plan.http_work_items)
    if not origins:
        raise ValueError("Native content discovery requires authorised HTTP work items.")
    source_executor = runtime.http_executor
    if not isinstance(source_executor, InternalHTTPExecutor):
        raise ValueError("Native content discovery requires a bound HTTP runtime.")
    return build_internal_http_executor_view(
        source_executor,
        approved_origins=origins,
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
    if not isinstance(limits, NativeContentDiscoveryLimits):
        raise ValueError("Native content discovery limits are invalid.")
    profile_definition = get_content_discovery_profile(profile)
    entries = _load_profile_entries(profile_definition.wordlist)

    planned: list[NativeContentDiscoveryRequest] = []
    total = 0
    for work_item in bound_plan.http_work_items:
        if total >= limits.maximum_total_candidate_requests:
            break
        origin = work_item.canonical_origin
        seen_urls: set[str] = set()
        per_origin = 0
        for entry in entries:
            candidate_url = _profile_candidate_url(origin, entry)
            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)
            if per_origin >= limits.maximum_candidate_requests_per_origin:
                break
            if total >= limits.maximum_total_candidate_requests:
                break
            planned.append(
                NativeContentDiscoveryRequest(
                    url=candidate_url,
                    canonical_origin=origin,
                    depth=0,
                    selection_reason=PROFILE_WORDLIST_SELECTION_REASON,
                    evidence_ids=(),
                )
            )
            per_origin += 1
            total += 1

    return NativeContentDiscoveryPlan(
        profile=profile_definition.name,
        limits=limits,
        baseline_requests_per_origin=BASELINE_REQUEST_COUNT,
        candidate_requests_planned=len(planned),
        requests=tuple(planned),
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
) -> NativeContentDiscoveryResult:
    requests_by_origin: dict[str, list[NativeContentDiscoveryRequest]] = {}
    for request in plan.requests:
        requests_by_origin.setdefault(request.canonical_origin, []).append(request)

    baselines: dict[str, ContentBaselineDecision] = {}
    for origin in requests_by_origin:
        baseline = collect_content_discovery_baseline(
            f"{origin}/",
            executor,
            token_factory=token_factory,
        )
        if baseline.selected_policy == BASELINE_POLICY_REFUSE:
            raise NativeContentDiscoveryBaselineRefused((baseline,))
        elif baseline.classification == BASELINE_CLASSIFICATION_CONVENTIONAL:
            baseline = replace(
                baseline,
                selected_policy=NATIVE_CONVENTIONAL_NEGATIVE_POLICY,
            )
        elif baseline.classification not in {
            BASELINE_CLASSIFICATION_STABLE_FALLBACK,
            BASELINE_CLASSIFICATION_STABLE_REDIRECT,
        }:
            raise ValueError("Native content discovery baseline is unsupported.")
        baselines[origin] = baseline

    origin_results: list[NativeContentDiscoveryOriginResult] = []
    retained_content: dict[str, str] = {}
    for origin, requests in requests_by_origin.items():
        baseline = baselines[origin]
        suppressed = 0
        retained = 0
        retained_lines: list[str] = []
        for request in requests:
            response = executor.request(
                request.url,
                method="GET",
                timeout_seconds=BASELINE_REQUEST_TIMEOUT_SECONDS,
                maximum_response_bytes=BASELINE_MAXIMUM_RESPONSE_BYTES,
                allow_query_strings=False,
            )
            if _matches_negative_baseline(baseline, response):
                suppressed += 1
            else:
                retained += 1
                retained_lines.append(_artifact_line(request.url, response))

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
            )
        )
    _commit_new_artifacts(
        tuple(
            (target.path, retained_content[target.canonical_origin])
            for target in output_transaction.targets
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
    )

    return NativeContentDiscoveryResult(
        external_commands_started=0,
        origin_results=tuple(origin_results),
        artifacts=artifacts,
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
    paths = tuple(target.path for target in targets)
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
    return _NativeOutputTransaction(destination=destination, targets=targets)


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
    created: list[_StagedNativeArtifact] = []
    try:
        for path, content in items:
            staged.append(_stage_new_artifact(path, content))
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
    redirect = (
        f" [--> {response.final_url}]"
        if response.final_url != candidate_url
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
    if not entries or len(entries) > MAXIMUM_NATIVE_CANDIDATE_REQUESTS:
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
    if getattr(executor, "_ipv4_resolver", None) is not runtime.ipv4_resolver:
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
