"""Private strict runtime for one authorised bug-bounty project pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import subprocess

from bugslyce.core.engagement_policy import (
    READINESS_FUTURE_ENFORCEMENT,
    SERVICE_VERSION_PERMITTED,
    TCP_SKIP,
    EngagementPolicy,
    EngagementPolicyAssessment,
    assess_engagement_policy,
)
from bugslyce.core.models import ReconCommand, ReconCommandResult
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE,
    CanonicalHostnameDestination,
    CanonicalIPv4Destination,
    DESTINATION_HOSTNAME,
    DESTINATION_IPV4,
    OUTCOME_ALLOWED,
    ProgrammeScopePolicy,
    RULE_EXACT_HTTP_URL,
    RULE_HTTP_PATH_PREFIX,
    ScopeDecision,
    canonicalise_http_url_destination,
    evaluate_programme_scope,
    evaluate_raw_scope_destination,
)
from bugslyce.project_session import (
    BugSlyceProject,
    load_project_engagement_policy,
    load_project_programme_scope_policy,
)
from bugslyce.recon.external_enforcement import (
    COMPONENT_SUPPORTED,
    BugBountyExternalEnforcementSession,
    BugBountyExternalToolRuntime,
    SafeSubprocessRunner,
    ToolCapabilities,
    assess_tool_capabilities,
)
from bugslyce.recon.content_commands import gobuster_request_timeout_seconds
from bugslyce.recon.http_enforcement import (
    InternalHTTPExecutor,
    IPv4Resolver,
    build_http_enforcement_configuration,
)
from bugslyce.recon.modes import DEEP_RECON_PROFILE, STANDARD_RECON_PROFILE
from bugslyce.parsers.nmap import parse_nmap_normal
from bugslyce.time_utils import format_utc_iso, utc_now


SUPPORTED_BUG_BOUNTY_PROJECT_PROFILES = (STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE)


def _probe_capabilities(tool: str) -> ToolCapabilities:
    argv = {
        "curl": ("curl", "--help", "all"),
        "gobuster": ("gobuster", "dir", "--help"),
        "nmap": ("nmap", "--help"),
    }[tool]
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return assess_tool_capabilities(tool, None, available=False)
    text = f"{completed.stdout}\n{completed.stderr}"
    return assess_tool_capabilities(tool, text, available=completed.returncode == 0)


@dataclass
class BugBountyProjectRuntime:
    """One fail-closed policy and execution binding for a project run."""

    project: BugSlyceProject
    profile: str
    policy: EngagementPolicy
    assessment: EngagementPolicyAssessment
    programme_scope_policy: ProgrammeScopePolicy
    target_decision: ScopeDecision
    initial_http_origins: tuple[str, ...]
    capabilities: dict[str, ToolCapabilities]
    ipv4_resolver: IPv4Resolver | None = None
    process_runner: object | None = None
    _nmap_session: BugBountyExternalEnforcementSession = field(init=False, repr=False)
    _nmap_runtime: BugBountyExternalToolRuntime = field(init=False, repr=False)
    _http_session: BugBountyExternalEnforcementSession | None = field(
        default=None, init=False, repr=False
    )
    _http_runtime: BugBountyExternalToolRuntime | None = field(default=None, init=False, repr=False)
    _http_executor: InternalHTTPExecutor | None = field(default=None, init=False, repr=False)
    _approved_origins: tuple[str, ...] = field(default=(), init=False)
    _observed_open_ports: tuple[int, ...] = field(default=(), init=False)
    _observed_target_ipv4: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.profile not in SUPPORTED_BUG_BOUNTY_PROJECT_PROFILES:
            raise ValueError(
                "Bug-bounty project execution supports Standard and Deep profiles only."
            )
        if self.assessment.readiness_state != READINESS_FUTURE_ENFORCEMENT:
            raise ValueError("Engagement policy is incomplete for project execution.")
        if self.target_decision.outcome != OUTCOME_ALLOWED:
            raise ValueError("Project target is not authorised by programme scope.")
        expected_http_origins = (
            _explicit_http_seed_origins(
                self.programme_scope_policy,
                self.target_decision,
            )
            if self.tcp_discovery_skipped
            else ()
        )
        if self.initial_http_origins != expected_http_origins:
            raise ValueError(
                "Initial HTTP origins do not match canonical programme-scope authority."
            )
        self._nmap_session = self._new_session((), nmap_only=True)
        self._nmap_runtime = BugBountyExternalToolRuntime(
            self._nmap_session, SafeSubprocessRunner(self.process_runner)
        )

    @property
    def service_version_permitted(self) -> bool:
        return self.policy.service_version_detection == SERVICE_VERSION_PERMITTED

    @property
    def tcp_discovery_skipped(self) -> bool:
        return self.policy.tcp_discovery_policy == TCP_SKIP

    @property
    def approved_http_origins(self) -> tuple[str, ...]:
        return self._approved_origins

    @property
    def http_executor(self) -> InternalHTTPExecutor:
        if self._http_executor is None:
            raise ValueError("HTTP origins have not been bound to the project runtime.")
        return self._http_executor

    def bind_http_origins(self, origins: tuple[str, ...]) -> None:
        canonical = tuple(sorted(set(origins)))
        if not canonical:
            raise ValueError("Strict project HTTP runtime requires discovered origins.")
        if self._http_session is not None:
            if canonical != self._approved_origins:
                raise ValueError("Strict project HTTP origins changed after binding.")
            return
        configuration = build_http_enforcement_configuration(
            self.policy, approved_origins=canonical
        )
        self._http_executor = InternalHTTPExecutor(
            configuration,
            programme_scope_policy=self.programme_scope_policy,
            ipv4_resolver=self.ipv4_resolver,
        )
        self._http_session = self._new_session(
            canonical, http_executor=self._http_executor
        )
        self._http_runtime = BugBountyExternalToolRuntime(
            self._http_session, SafeSubprocessRunner(self.process_runner)
        )
        self._approved_origins = canonical

    def require_workflow(self, input_dir: Path, scope_file: Path, target: str) -> None:
        if Path(self.project.output_dir).resolve() != input_dir.resolve():
            raise ValueError("Strict project runtime output directory mismatch.")
        if Path(self.project.scope_file).resolve() != scope_file.resolve():
            raise ValueError("Strict project runtime scope file mismatch.")
        if self.project.target != target:
            raise ValueError("Strict project runtime target mismatch.")

    def nmap_discovery_runner(self):
        runtime = self
        class Runner:
            def __init__(self) -> None:
                self._bugslyce_project_runtime = runtime
                self._bugslyce_runner_kind = "nmap_discovery"

            def run(self, command: ReconCommand) -> ReconCommandResult:
                plan = runtime._nmap_session.build_nmap_plan(
                    target=runtime.project.target,
                    output_file=Path(command.output_file),
                    timeout_seconds=command.timeout_seconds,
                )
                result = runtime._nmap_runtime.run(plan)
                converted = _result(
                    command,
                    result,
                    Path(runtime.project.output_dir),
                )
                if converted.exit_code == 0 and not converted.error:
                    (
                        runtime._observed_open_ports,
                        runtime._observed_target_ipv4,
                    ) = runtime._nmap_session.nmap_discovery_observations
                return converted
        return Runner()

    def nmap_service_runner(self):
        runtime = self
        class Runner:
            def __init__(self) -> None:
                self._bugslyce_project_runtime = runtime
                self._bugslyce_runner_kind = "nmap_service"

            def run(self, command: ReconCommand) -> ReconCommandResult:
                if not runtime._observed_open_ports:
                    runtime._restore_discovery_observations()
                requested = tuple(
                    sorted(
                        int(value)
                        for value in command.argv[
                            command.argv.index("-p") + 1
                        ].split(",")
                    )
                )
                if requested != runtime._observed_open_ports:
                    raise ValueError(
                        "Service/version ports do not match strict discovery observations."
                    )
                plan = runtime._nmap_session.build_nmap_service_plan(
                    target=runtime.project.target,
                    output_file=Path(command.output_file),
                    timeout_seconds=command.timeout_seconds,
                )
                if plan.private_argv[-1] != runtime._observed_target_ipv4:
                    raise ValueError(
                        "Service/version target peer does not match strict discovery."
                    )
                return _result(
                    command,
                    runtime._nmap_runtime.run(plan),
                    Path(runtime.project.output_dir),
                )
        return Runner()

    def curl_runner(self):
        runtime = self
        class Runner:
            def __init__(self) -> None:
                self._bugslyce_project_runtime = runtime
                self._bugslyce_runner_kind = "curl"

            def run(self, command: ReconCommand) -> ReconCommandResult:
                if runtime._http_session is None or runtime._http_runtime is None:
                    raise ValueError("Strict HTTP runtime is not initialised.")
                method = "HEAD" if "-I" in command.argv else "GET"
                url = command.argv[-1]
                response_headers_file = Path(
                    command.output_file + ".strict-response-headers"
                )
                plan = runtime._http_session.build_curl_plan(
                    url=url,
                    method=method,
                    output_file=Path(command.output_file),
                    response_headers_file=response_headers_file,
                    timeout_seconds=command.timeout_seconds,
                    purpose=command.phase,
                )
                try:
                    result = runtime._http_runtime.run(plan)
                finally:
                    try:
                        response_headers_file.unlink(missing_ok=True)
                    except OSError:
                        raise ValueError(
                            "Strict curl temporary response headers could not be removed."
                        ) from None
                return _result(
                    command,
                    result,
                    Path(runtime.project.output_dir),
                )
        return Runner()

    def gobuster_runner(self):
        runtime = self
        class Runner:
            def __init__(self) -> None:
                self._bugslyce_project_runtime = runtime
                self._bugslyce_runner_kind = "gobuster"

            def run(self, command: ReconCommand) -> ReconCommandResult:
                if runtime._http_session is None or runtime._http_runtime is None:
                    raise ValueError("Strict HTTP runtime is not initialised.")
                plan = runtime._http_session.build_gobuster_plan(
                    origin=command.argv[3],
                    wordlist=Path(command.argv[5]),
                    output_file=Path(command.output_file),
                    timeout_seconds=gobuster_request_timeout_seconds(command.argv),
                )
                if plan.compatibility_status != COMPONENT_SUPPORTED:
                    raise ValueError(plan.reason)
                return _result(
                    command,
                    runtime._http_runtime.run(plan),
                    Path(runtime.project.output_dir),
                )
        return Runner()

    def require_runner(self, runner: object, kind: str) -> None:
        if (
            getattr(runner, "_bugslyce_project_runtime", None) is not self
            or getattr(runner, "_bugslyce_runner_kind", None) != kind
        ):
            raise ValueError("Network runner is not bound to this strict project runtime.")

    def _new_session(
        self,
        origins: tuple[str, ...],
        *,
        nmap_only: bool = False,
        http_executor: InternalHTTPExecutor | None = None,
    ) -> BugBountyExternalEnforcementSession:
        return BugBountyExternalEnforcementSession(
            policy=self.policy,
            approved_origins=origins,
            profile=self.profile,
            curl_capabilities=self.capabilities["curl"],
            gobuster_capabilities=self.capabilities["gobuster"],
            nmap_capabilities=self.capabilities["nmap"],
            programme_scope_policy=self.programme_scope_policy,
            ipv4_resolver=self.ipv4_resolver,
            http_executor=http_executor,
            nmap_only=nmap_only,
        )

    def _restore_discovery_observations(self) -> None:
        output_dir = Path(self.project.output_dir).resolve()
        manifest_path = output_dir / "recon_manifest.json"
        discovery_path = output_dir / "nmap-allports.txt"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Strict service/version detection lacks trusted discovery provenance."
            ) from exc
        artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != "1.0"
            or manifest.get("target") != self.project.target
            or manifest.get("created_by") != "bugslyce-nmap-discover"
            or manifest.get("profile") != "bug-bounty-policy-tcp"
            or not isinstance(artifacts, list)
            or not any(
                isinstance(item, dict)
                and item.get("type") == "nmap"
                and item.get("file") == discovery_path.name
                for item in artifacts
            )
            or discovery_path.is_symlink()
            or not discovery_path.is_file()
        ):
            raise ValueError(
                "Strict service/version detection lacks trusted discovery provenance."
            )
        records = parse_nmap_normal(discovery_path, self.project.target)
        peers = {item.host for item in records if item.host}
        try:
            peer = next(iter(peers))
            canonical_peer = str(ipaddress.IPv4Address(peer))
        except (StopIteration, ValueError):
            raise ValueError(
                "Strict discovery evidence does not identify one IPv4 target peer."
            ) from None
        if len(peers) != 1 or peer != canonical_peer:
            raise ValueError(
                "Strict discovery evidence does not identify one IPv4 target peer."
            )
        ports = tuple(sorted({
            item.port
            for item in records
            if item.host == canonical_peer
            and item.protocol == "tcp"
            and item.state == "open"
        }))
        if not ports:
            raise ValueError(
                "Strict service/version detection lacks trusted open-port observations."
            )
        self._nmap_session._restore_nmap_discovery_evidence(
            discovery_path,
            canonical_peer,
        )
        (
            self._observed_open_ports,
            self._observed_target_ipv4,
        ) = self._nmap_session.nmap_discovery_observations


def build_bug_bounty_project_runtime(
    project: BugSlyceProject,
    profile: str,
    *,
    capabilities: dict[str, ToolCapabilities] | None = None,
    ipv4_resolver: IPv4Resolver | None = None,
    process_runner: object | None = None,
) -> BugBountyProjectRuntime:
    policy = load_project_engagement_policy(project)
    if policy is None:
        raise ValueError("Engagement policy is missing.")
    assessment = assess_engagement_policy(policy)
    if assessment.readiness_state != READINESS_FUTURE_ENFORCEMENT:
        raise ValueError(
            "Engagement policy is not ready. "
            + " ".join(assessment.not_ready_reasons)
        )
    programme_scope = load_project_programme_scope_policy(project)
    if programme_scope is None:
        raise ValueError("Programme scope policy is missing.")
    try:
        ipaddress.IPv4Address(project.target)
    except ValueError:
        kind = DESTINATION_HOSTNAME
    else:
        kind = DESTINATION_IPV4
    decision = evaluate_raw_scope_destination(programme_scope, kind, project.target)
    if decision.outcome != OUTCOME_ALLOWED:
        raise ValueError(
            "Project target is not authorised by programme scope "
            f"({decision.reason_code})."
        )
    initial_http_origins = (
        _explicit_http_seed_origins(programme_scope, decision)
        if policy.tcp_discovery_policy == TCP_SKIP
        else ()
    )
    if policy.tcp_discovery_policy == TCP_SKIP and not initial_http_origins:
        raise ValueError(
            "TCP-skip project execution requires explicit allowed root HTTP "
            "programme scope for the project target."
        )
    selected_capabilities = capabilities or {
        tool: _probe_capabilities(tool) for tool in ("curl", "gobuster", "nmap")
    }
    runtime = BugBountyProjectRuntime(
        project=project,
        profile=profile,
        policy=policy,
        assessment=assessment,
        programme_scope_policy=programme_scope,
        target_decision=decision,
        initial_http_origins=initial_http_origins,
        capabilities=selected_capabilities,
        ipv4_resolver=ipv4_resolver,
        process_runner=process_runner,
    )
    if initial_http_origins:
        runtime.bind_http_origins(initial_http_origins)
    return runtime


def _explicit_http_seed_origins(
    policy: ProgrammeScopePolicy,
    target_decision: ScopeDecision,
) -> tuple[str, ...]:
    """Derive root origins only from explicit HTTP inclusions allowed in full scope."""

    target = target_decision.canonical_destination
    if isinstance(target, CanonicalHostnameDestination):
        target_kind = DESTINATION_HOSTNAME
        target_value = target.hostname
    elif isinstance(target, CanonicalIPv4Destination):
        target_kind = DESTINATION_IPV4
        target_value = target.address
    else:
        return ()

    origins: set[str] = set()
    for rule in policy.rules:
        if rule.action != ACTION_INCLUDE or rule.kind not in {
            RULE_EXACT_HTTP_URL,
            RULE_HTTP_PATH_PREFIX,
        }:
            continue
        destination = canonicalise_http_url_destination(rule.canonical_value)
        if (
            destination.origin.host_kind != target_kind
            or destination.origin.host != target_value
        ):
            continue
        root = canonicalise_http_url_destination(
            f"{destination.origin.canonical_value}/"
        )
        if evaluate_programme_scope(policy, root).outcome == OUTCOME_ALLOWED:
            origins.add(root.canonical_value)
    return tuple(sorted(origins))


def require_project_runtime_binding(
    project_runtime: object,
    input_dir: Path,
    scope_file: Path,
    target: str,
    runner: object,
    runner_kind: str,
    *,
    http_executor: object | None = None,
) -> BugBountyProjectRuntime:
    """Validate one supported workflow call against its exact runtime adapters."""

    if not isinstance(project_runtime, BugBountyProjectRuntime):
        raise ValueError("Bug-bounty workflow requires a canonical project runtime.")
    project_runtime.require_workflow(input_dir, scope_file, target)
    project_runtime.require_runner(runner, runner_kind)
    if http_executor is not None and http_executor is not project_runtime.http_executor:
        raise ValueError("HTTP executor is not bound to this strict project runtime.")
    return project_runtime


def _result(
    command: ReconCommand,
    result,
    project_root: Path,
) -> ReconCommandResult:
    now = utc_now()
    stderr_path = _retain_failed_process_stderr(
        command,
        result,
        project_root,
    )
    return ReconCommandResult(
        command_id=command.id,
        tool=command.tool,
        exit_code=result.return_code,
        stdout_path=None,
        stderr_path=stderr_path,
        output_file=command.output_file,
        started_at=format_utc_iso(now),
        ended_at=format_utc_iso(now),
        duration_seconds=0.0,
        executed=result.started,
        simulated=False,
        error=result.error,
        http_status_code=(
            int(result.stdout.strip())
            if result.stdout.strip().isdigit() and len(result.stdout.strip()) == 3
            else None
        ),
    )


def _retain_failed_process_stderr(
    command: ReconCommand,
    result,
    project_root: Path,
) -> str | None:
    """Retain only already-safe stderr from a started failed process."""

    if (
        result.started is not True
        or not result.stderr
        or (result.return_code == 0 and not result.error)
    ):
        return None

    try:
        root = project_root.expanduser().resolve(strict=True)
        output_candidate = Path(command.output_file).expanduser()
        if not output_candidate.is_absolute():
            output_candidate = root / output_candidate
        if output_candidate.is_symlink():
            return None
        output_path = output_candidate.resolve(strict=False)
        output_path.relative_to(root)
        stderr_path = output_path.with_suffix(
            output_path.suffix + ".stderr.log"
        )
        stderr_path.relative_to(root)
        if stderr_path.is_symlink():
            return None
        with stderr_path.open("x", encoding="utf-8") as handle:
            handle.write(result.stderr)
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return None
    return str(stderr_path)
