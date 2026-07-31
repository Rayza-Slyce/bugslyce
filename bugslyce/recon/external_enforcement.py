"""Policy-aware command planning and execution for external network tools.

The strict bug bounty paths in this module are deliberately separate from the
existing authorised-lab command builders. R0B2 keeps every live bug bounty CLI
entry point blocked; R0B3 will decide whether these plans pass controlled
capture acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import ipaddress
import os
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence
import unicodedata
from urllib.parse import urlparse

from bugslyce.core.engagement_policy import (
    CONFIRMED,
    READINESS_FUTURE_ENFORCEMENT,
    TCP_CONSERVATIVE,
    TCP_CUSTOM,
    TCP_FULL,
    TCP_SKIP,
    EngagementPolicy,
    IdentificationHeader,
    assess_engagement_policy,
    policy_from_dict,
    validate_identification_header_name,
    validate_identification_value,
)
from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    DESTINATION_HTTP_URL,
    OUTCOME_ALLOWED,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_HTTP_PATH_PREFIX,
    RULE_WILDCARD_SUBDOMAIN,
    CanonicalHTTPURLDestination,
    ProgrammeScopePolicy,
    canonicalise_http_url_destination,
    evaluate_raw_scope_destination,
)
from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.http_enforcement import (
    HTTPEnforcementConfiguration,
    HTTPProgrammeScopeRefused,
    HTTPRateRejected,
    HTTPRedirectRefused,
    IPv4Resolver,
    InternalHTTPExecutor,
    _canonical_programme_scope_policy,
    _system_ipv4_resolver,
    build_http_enforcement_configuration,
    resolve_policy_redirect,
    select_programme_scope_ipv4_peer,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
)


COMPONENT_SUPPORTED = "supported"
COMPONENT_OMITTED = "safely_omitted"
COMPONENT_INCOMPATIBLE = "required_but_incompatible"

MAXIMUM_NMAP_PACKET_RATE = 50
NMAP_MAX_RETRIES = 2
GO_MAX_DURATION_NANOSECONDS = 9_223_372_036_854_775_807
MAXIMUM_PROCESS_DIAGNOSTIC_CHARS = 16_384
GOBUSTER_STARTUP_FINALISATION_ALLOWANCE_SECONDS = 30
MAXIMUM_GOBUSTER_PROCESS_TIMEOUT_SECONDS = 14_400
MAXIMUM_GOBUSTER_WORDLIST_BYTES = 1_048_576
MAXIMUM_GOBUSTER_WORDLIST_ENTRIES = 4_096
GOBUSTER_STARTUP_DISCLOSURE = (
    "Gobuster uses one thread and a policy-derived delay for normal wordlist "
    "enumeration. Compatible Gobuster versions may issue a small bounded startup "
    "validation sequence before delayed enumeration begins."
)

# One central conservative set for bug bounty TCP port-state discovery. It is
# intentionally small and does not alter the existing authorised-lab profiles.
BUG_BOUNTY_COMMON_WEB_PORTS = (
    80,
    443,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9090,
    9443,
)

_CURL_REQUIRED_OPTIONS = frozenset(
    {
        "--disable",
        "--connect-timeout",
        "--dump-header",
        "--globoff",
        "--header",
        "--head",
        "--max-redirs",
        "--max-time",
        "--noproxy",
        "--output",
        "--proto",
        "--resolve",
        "--silent",
        "--show-error",
        "--user-agent",
        "--write-out",
    }
)
_GOBUSTER_REQUIRED_OPTIONS = frozenset(
    {
        "dir",
        "--delay",
        "--headers",
        "--follow-redirect",
        "--output",
        "--threads",
        "--timeout",
        "--url",
        "--useragent",
        "--wordlist",
    }
)
_NMAP_REQUIRED_OPTIONS = frozenset(
    {"-sT", "-Pn", "-n", "-p", "--max-rate", "--max-retries", "-oN"}
)


@dataclass(frozen=True)
class ToolCapabilities:
    """Redacted capability facts derived from injected help output."""

    tool: str
    available: bool
    supported_options: frozenset[str]
    repeated_headers_supported: bool = False
    redirect_following_opt_in: bool = False
    diagnostic: str = ""

    def supports(self, required: frozenset[str]) -> bool:
        return self.available and required.issubset(self.supported_options)


@dataclass(frozen=True)
class ExternalCommandPlan:
    """A private argv plus the only display-safe representation."""

    tool: str
    purpose: str
    compatibility_status: str
    redacted_argv: tuple[str, ...]
    process_timeout_seconds: int
    expected_artefacts: tuple[str, ...]
    request_timeout_seconds: int | None = None
    reason: str = ""
    _private_argv: tuple[str, ...] = field(default_factory=tuple, repr=False)
    _redaction_values: tuple[str, ...] = field(default_factory=tuple, repr=False)
    _provenance_token: object | None = field(default=None, repr=False, compare=False)

    @property
    def timeout_seconds(self) -> int:
        """Compatibility view of the bounded whole-process timeout."""

        return self.process_timeout_seconds

    @property
    def private_argv(self) -> tuple[str, ...]:
        """Return private in-memory argv for the strict runner only."""

        if self.compatibility_status != COMPONENT_SUPPORTED or not self._private_argv:
            raise ValueError("External command plan is not executable.")
        return self._private_argv


@dataclass(frozen=True)
class ExternalProcessResult:
    """Deterministic, redacted subprocess outcome."""

    tool: str
    return_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    started: bool
    error: str | None
    produced_artefacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class CurlRedirectChain:
    """Immutable controller state for explicitly scheduled curl redirect hops."""

    current_url: str
    visited_urls: tuple[str, ...]
    redirect_count: int


@dataclass(frozen=True)
class ComponentAssessment:
    """One non-sensitive preflight component decision."""

    component: str
    status: str
    required: bool
    reason: str


@dataclass(frozen=True)
class ExternalExecutionPreflight:
    """Complete external capability decision made before target traffic."""

    profile: str
    components: tuple[ComponentAssessment, ...]
    aggregate_http_rate: str
    http_concurrency: int
    identity_header_names: tuple[str, ...]
    custom_identity_configured: bool
    tcp_discovery_mode: str
    selected_tcp_port_count: int
    ready: bool
    _provenance_token: object | None = field(default=None, repr=False, compare=False)


class ProcessRunner(Protocol):
    """Injectable argv-only subprocess boundary with controlled environment."""

    def run(
        self,
        argv: Sequence[str],
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> object: ...


def build_strict_external_subprocess_environment() -> Mapping[str, str]:
    """Return a fresh proxy-neutral environment for strict external tools."""

    proxy_names = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.casefold() not in proxy_names
    }
    environment["NO_PROXY"] = "*"
    environment["no_proxy"] = "*"
    return MappingProxyType(environment)


class SafeSubprocessRunner:
    """Execute argv without a shell and return only redacted diagnostics."""

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner

    def run(self, plan: ExternalCommandPlan) -> ExternalProcessResult:
        if plan.compatibility_status != COMPONENT_SUPPORTED:
            raise ValueError("External command plan is not executable.")
        artefact_snapshots = _artefact_snapshots(plan)
        environment = build_strict_external_subprocess_environment()
        try:
            if self._runner is None:
                completed = subprocess.run(
                    plan.private_argv,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=plan.process_timeout_seconds,
                    check=False,
                    shell=False,
                    env=environment,
                )
            else:
                completed = self._runner.run(
                    plan.private_argv,
                    plan.process_timeout_seconds,
                    environment,
                )
        except subprocess.TimeoutExpired:
            result = ExternalProcessResult(
                tool=plan.tool,
                return_code=None,
                stdout="",
                stderr="",
                timed_out=True,
                started=True,
                error=f"{plan.tool} exceeded its bounded timeout.",
            )
        except OSError:
            result = ExternalProcessResult(
                tool=plan.tool,
                return_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                started=False,
                error=f"{plan.tool} could not start.",
            )
        except Exception:
            # Unexpected injected or operating-system runner failures are
            # classified without exposing private argv.
            result = ExternalProcessResult(
                tool=plan.tool,
                return_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                started=False,
                error=f"{plan.tool} execution failed unexpectedly.",
            )
        except BaseException:
            # Target-controlled output may have been written before an
            # interruption. Redact every changed expected artefact before
            # preserving the original control-flow exception.
            try:
                _finalise_expected_artefacts(plan, artefact_snapshots)
            except ValueError:
                pass
            raise
        else:
            return_code = getattr(completed, "returncode", None)
            stdout = _redact_text(str(getattr(completed, "stdout", "") or ""), plan)
            stderr = _redact_text(str(getattr(completed, "stderr", "") or ""), plan)
            if not isinstance(return_code, int) or isinstance(return_code, bool):
                result = ExternalProcessResult(
                    tool=plan.tool,
                    return_code=None,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=False,
                    started=True,
                    error=f"{plan.tool} returned an invalid process result.",
                )
            else:
                result = ExternalProcessResult(
                    tool=plan.tool,
                    return_code=return_code,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=False,
                    started=True,
                    error=(
                        None
                        if return_code == 0
                        else f"{plan.tool} exited with code {return_code}."
                    ),
                )
        produced = _finalise_expected_artefacts(plan, artefact_snapshots)
        if (
            result.return_code == 0
            and plan.expected_artefacts
            and len(produced) != len(plan.expected_artefacts)
        ):
            result = ExternalProcessResult(
                tool=result.tool,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=result.timed_out,
                started=result.started,
                error=f"{plan.tool} did not produce every expected artefact.",
                produced_artefacts=produced,
            )
        elif produced:
            result = ExternalProcessResult(
                tool=result.tool,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=result.timed_out,
                started=result.started,
                error=result.error,
                produced_artefacts=produced,
            )
        return result


class BugBountyExternalEnforcementSession:
    """Private in-memory binding for one policy, preflight and HTTP runtime."""

    def __init__(
        self,
        *,
        policy: EngagementPolicy,
        approved_origins: tuple[str, ...],
        profile: str,
        curl_capabilities: ToolCapabilities,
        gobuster_capabilities: ToolCapabilities,
        nmap_capabilities: ToolCapabilities,
        programme_scope_policy: ProgrammeScopePolicy | None = None,
        ipv4_resolver: IPv4Resolver | None = None,
        http_executor: InternalHTTPExecutor | None = None,
    ) -> None:
        self._token = object()
        self.policy = policy_from_dict(policy.to_dict())
        self.configuration = build_http_enforcement_configuration(
            self.policy,
            approved_origins=approved_origins,
        )
        self.preflight = build_bug_bounty_external_preflight(
            policy=self.policy,
            profile=profile,
            curl_capabilities=curl_capabilities,
            gobuster_capabilities=gobuster_capabilities,
            nmap_capabilities=nmap_capabilities,
            _provenance_token=self._token,
        )
        if not self.preflight.ready:
            raise ValueError("External-tool preflight refused required network components.")
        self.curl_capabilities = curl_capabilities
        self.gobuster_capabilities = gobuster_capabilities
        self.nmap_capabilities = nmap_capabilities
        canonical_programme_scope_policy = (
            None
            if programme_scope_policy is None
            else _canonical_programme_scope_policy(programme_scope_policy)
        )
        if ipv4_resolver is not None and not callable(ipv4_resolver):
            raise ValueError("Strict curl IPv4 resolver is invalid.")
        self._programme_scope_policy = canonical_programme_scope_policy
        self._ipv4_resolver = ipv4_resolver or _system_ipv4_resolver
        self.http_executor = http_executor or InternalHTTPExecutor(self.configuration)
        self._registered_plans: dict[int, ExternalCommandPlan] = {}
        self._registered_plan_states: dict[int, tuple[object, ...]] = {}
        if self.http_executor.configuration != self.configuration:
            raise ValueError("HTTP executor does not match the policy-derived configuration.")

    def build_curl_plan(self, **kwargs: object) -> ExternalCommandPlan:
        if self._programme_scope_policy is None:
            raise ValueError("Strict curl planning requires programme scope policy.")
        return self._register_plan(build_bug_bounty_curl_plan(
            configuration=self.configuration,
            capabilities=self.curl_capabilities,
            programme_scope_policy=self._programme_scope_policy,
            ipv4_resolver=self._ipv4_resolver,
            _provenance_token=self._token,
            **kwargs,
        ))

    def build_gobuster_plan(self, **kwargs: object) -> ExternalCommandPlan:
        if self._programme_scope_policy is None:
            raise ValueError("Strict Gobuster planning requires programme scope policy.")
        return self._register_plan(build_bug_bounty_gobuster_plan(
            configuration=self.configuration,
            capabilities=self.gobuster_capabilities,
            programme_scope_policy=self._programme_scope_policy,
            ipv4_resolver=self._ipv4_resolver,
            _provenance_token=self._token,
            **kwargs,
        ))

    def build_nmap_plan(self, **kwargs: object) -> ExternalCommandPlan:
        return self._register_plan(build_bug_bounty_nmap_plan(
            policy=self.policy,
            capabilities=self.nmap_capabilities,
            _provenance_token=self._token,
            **kwargs,
        ))

    def _register_plan(self, plan: ExternalCommandPlan) -> ExternalCommandPlan:
        """Keep a strong reference to the exact in-memory plan instance."""

        self._registered_plans[id(plan)] = plan
        self._registered_plan_states[id(plan)] = _external_plan_state(plan)
        return plan

    def _require_plan(self, plan: ExternalCommandPlan) -> None:
        if self._registered_plans.get(id(plan)) is not plan:
            raise ValueError("External command plan is not the registered session plan.")
        if self._registered_plan_states.get(id(plan)) != _external_plan_state(plan):
            raise ValueError("External command plan changed after registration.")
        if plan._provenance_token is not self._token:
            raise ValueError("External command plan is not bound to this enforcement session.")
        component = next(
            (item for item in self.preflight.components if item.component == plan.tool),
            None,
        )
        if component is None or component.status != COMPONENT_SUPPORTED:
            raise ValueError("External command component was not approved by preflight.")
        if plan.tool == "curl":
            _validate_bound_curl_plan(plan, self.configuration)
        elif plan.tool == "gobuster":
            _validate_bound_gobuster_plan(plan, self.configuration)
        elif plan.tool == "nmap":
            _validate_bound_nmap_plan(plan, policy=self.policy)
        else:
            raise ValueError("External command plan uses an unsupported tool.")


def _external_plan_state(plan: ExternalCommandPlan) -> tuple[object, ...]:
    return (
        plan.tool,
        plan.purpose,
        plan.compatibility_status,
        plan.redacted_argv,
        plan.process_timeout_seconds,
        plan.expected_artefacts,
        plan.request_timeout_seconds,
        plan.reason,
        plan._private_argv,
        plan._redaction_values,
        plan._provenance_token,
    )


class BugBountyExternalToolRuntime:
    """Run only plans bound to a complete in-memory enforcement session."""

    def __init__(self, session: BugBountyExternalEnforcementSession, runner: SafeSubprocessRunner) -> None:
        if not isinstance(session, BugBountyExternalEnforcementSession):
            raise ValueError("External-tool runtime requires a bound enforcement session.")
        self.session = session
        self.preflight = session.preflight
        self.http_executor = session.http_executor
        self.runner = runner

    def run(self, plan: ExternalCommandPlan) -> ExternalProcessResult:
        self.session._require_plan(plan)
        if plan.tool == "curl":
            return run_bug_bounty_curl(plan, self.http_executor, self.runner)
        if plan.tool == "gobuster":
            return run_bug_bounty_gobuster(plan, self.http_executor, self.runner)
        if plan.tool == "nmap":
            return self.runner.run(plan)
        raise ValueError("External command plan uses an unsupported tool.")


def assess_tool_capabilities(
    tool: str,
    help_text: str | None,
    *,
    available: bool = True,
) -> ToolCapabilities:
    """Parse an injected help fixture without invoking a real executable."""

    if tool not in {"curl", "gobuster", "nmap"}:
        raise ValueError("Unsupported external capability probe.")
    if not available:
        return ToolCapabilities(tool, False, frozenset(), diagnostic="executable_absent")
    if not isinstance(help_text, str) or not help_text.strip():
        return ToolCapabilities(tool, True, frozenset(), diagnostic="help_output_unusable")
    required = {
        "curl": _CURL_REQUIRED_OPTIONS,
        "gobuster": _GOBUSTER_REQUIRED_OPTIONS,
        "nmap": _NMAP_REQUIRED_OPTIONS,
    }[tool]
    supported = frozenset(
        option for option in required if _help_mentions_option(help_text, option)
    )
    repeatable = tool == "gobuster" and _gobuster_repeatable_headers_supported(
        help_text
    )
    redirect_opt_in = tool == "gobuster" and re.search(
        r"follow-redirect.{0,80}(default\s*[:=]?\s*false|disabled by default)",
        help_text,
        re.IGNORECASE,
    ) is not None
    diagnostic = "compatible" if supported == required else "required_options_missing"
    if tool == "gobuster" and supported == required and not repeatable:
        diagnostic = "repeatable_headers_unproven"
    return ToolCapabilities(
        tool=tool,
        available=True,
        supported_options=supported,
        repeated_headers_supported=repeatable,
        redirect_following_opt_in=redirect_opt_in,
        diagnostic=diagnostic,
    )


def build_bug_bounty_curl_plan(
    *,
    url: str,
    method: str,
    output_file: Path,
    response_headers_file: Path,
    timeout_seconds: int,
    configuration: HTTPEnforcementConfiguration,
    capabilities: ToolCapabilities,
    programme_scope_policy: ProgrammeScopePolicy,
    ipv4_resolver: IPv4Resolver,
    purpose: str,
    additional_headers: tuple[tuple[str, str], ...] = (),
    _provenance_token: object | None = None,
) -> ExternalCommandPlan:
    """Build one strict, single-exchange curl command."""

    parsed = urlparse(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("Strict curl target URL is not an approved HTTP origin.")
    normalised_method = method.upper().strip() if isinstance(method, str) else ""
    if normalised_method not in {"GET", "HEAD"}:
        raise ValueError("Strict curl method must be GET or HEAD.")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ValueError("Strict curl timeout must be a positive integer.")
    canonical_programme_scope_policy = _canonical_programme_scope_policy(
        programme_scope_policy
    )
    decision = evaluate_raw_scope_destination(
        canonical_programme_scope_policy,
        DESTINATION_HTTP_URL,
        url,
    )
    if decision.outcome != OUTCOME_ALLOWED:
        raise HTTPProgrammeScopeRefused("initial", decision)
    origin = http_origin_from_url(url)
    if origin not in configuration.approved_origins:
        raise ValueError("Strict curl target URL is not an approved HTTP origin.")
    selected_ipv4 = select_programme_scope_ipv4_peer(
        canonical_programme_scope_policy,
        decision,
        ipv4_resolver,
    )
    destination = decision.canonical_destination
    if not isinstance(destination, CanonicalHTTPURLDestination):
        raise ValueError("Strict curl target URL is not canonical.")
    resolve_mapping = (
        f"{parsed.hostname}:"
        f"{destination.origin.effective_port}:{selected_ipv4}"
    )
    required_options = (
        _CURL_REQUIRED_OPTIONS
        if normalised_method == "HEAD"
        else _CURL_REQUIRED_OPTIONS - {"--head"}
    )
    reason = _capability_reason(capabilities, "curl", required_options)
    if reason:
        return _unsupported_plan("curl", purpose, COMPONENT_INCOMPATIBLE, reason)
    headers = _effective_external_headers(configuration, additional_headers)
    _require_safe_local_path(output_file, label="Strict curl output path")
    _require_safe_local_path(
        response_headers_file,
        label="Strict curl response-header path",
    )
    argv = [
        "curl",
        "--disable",
        "--globoff",
        "--silent",
        "--show-error",
        "--proto",
        "=http,https",
        "--noproxy",
        "*",
        "--max-redirs",
        "0",
        "--connect-timeout",
        str(min(timeout_seconds, 5)),
        "--max-time",
        str(timeout_seconds),
        "--resolve",
        resolve_mapping,
        "--user-agent",
        configuration.user_agent,
    ]
    redacted = [*argv[:-1], "configured"]
    redactions = [configuration.user_agent]
    for name, value in headers:
        argv.extend(("--header", f"{name}: {value}"))
        redacted.extend(("--header", f"{name}: configured"))
        redactions.append(value)
    argv.extend(
        (
            "--dump-header",
            str(response_headers_file),
            "--write-out",
            "%{http_code}",
        )
    )
    redacted.extend(argv[len(redacted) :])
    if normalised_method == "HEAD":
        argv.append("--head")
        redacted.append("--head")
    argv.extend(("--output", str(output_file), "--", url))
    redacted.extend(("--output", str(output_file), "--", url))
    _validate_strict_curl_argv(tuple(argv), configuration)
    return ExternalCommandPlan(
        tool="curl",
        purpose=purpose,
        compatibility_status=COMPONENT_SUPPORTED,
        redacted_argv=tuple(redacted),
        process_timeout_seconds=timeout_seconds,
        expected_artefacts=(str(output_file), str(response_headers_file)),
        _private_argv=tuple(argv),
        _redaction_values=tuple(dict.fromkeys(redactions)),
        _provenance_token=_provenance_token,
    )


def run_bug_bounty_curl(
    plan: ExternalCommandPlan,
    executor: InternalHTTPExecutor,
    runner: SafeSubprocessRunner,
) -> ExternalProcessResult:
    """Run one curl exchange under the shared R0B1 HTTP permit."""

    if plan.tool != "curl":
        raise ValueError("Strict curl execution requires a curl plan.")
    with executor.external_request_permit():
        result = runner.run(plan)
        status = _curl_status(result.stdout)
        if status == 429:
            headers = _load_bounded_curl_headers(Path(plan.expected_artefacts[1]))
            raise executor.record_external_rate_rejection(headers)
        return result


def resolve_bug_bounty_curl_redirect(
    current_url: str,
    location: str,
    configuration: HTTPEnforcementConfiguration,
    *,
    allow_query_strings: bool = False,
) -> str:
    """Resolve one curl redirect without transmitting to a refused destination."""

    return resolve_policy_redirect(
        current_url,
        location,
        approved_origins=configuration.approved_origins,
        allow_query_strings=allow_query_strings,
    )


def begin_curl_redirect_chain(
    initial_url: str,
    configuration: HTTPEnforcementConfiguration,
) -> CurlRedirectChain:
    """Start controlled curl redirect state from one approved URL."""

    parsed = urlparse(initial_url)
    origin = http_origin_from_url(initial_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or parsed.fragment
        or origin not in configuration.approved_origins
    ):
        raise HTTPRedirectRefused("origin_not_approved")
    return CurlRedirectChain(initial_url, (initial_url,), 0)


def advance_curl_redirect_chain(
    chain: CurlRedirectChain,
    location: str,
    configuration: HTTPEnforcementConfiguration,
    *,
    allow_query_strings: bool = False,
) -> CurlRedirectChain:
    """Validate one redirect before a separately permitted curl exchange."""

    if chain.redirect_count >= configuration.maximum_redirect_hops:
        raise HTTPRedirectRefused("redirect_hop_limit")
    destination = resolve_bug_bounty_curl_redirect(
        chain.current_url,
        location,
        configuration,
        allow_query_strings=allow_query_strings,
    )
    if destination in chain.visited_urls:
        raise HTTPRedirectRefused("redirect_loop")
    return CurlRedirectChain(
        current_url=destination,
        visited_urls=(*chain.visited_urls, destination),
        redirect_count=chain.redirect_count + 1,
    )


def gobuster_delay_for_rate(rate: Decimal) -> str:
    """Convert a request rate to a conservative representable Go duration."""

    if not isinstance(rate, Decimal) or not rate.is_finite() or rate <= 0:
        raise ValueError("Gobuster request rate must be a positive finite Decimal.")
    nanoseconds = max(_ceil_positive_decimal_ratio(1_000_000_000, rate), 1)
    if nanoseconds > GO_MAX_DURATION_NANOSECONDS:
        raise ValueError("Gobuster delay exceeds the representable Go duration.")
    return f"{nanoseconds}ns"


def build_bug_bounty_gobuster_plan(
    *,
    origin: str,
    wordlist: Path,
    output_file: Path,
    timeout_seconds: int,
    configuration: HTTPEnforcementConfiguration,
    capabilities: ToolCapabilities,
    programme_scope_policy: ProgrammeScopePolicy,
    ipv4_resolver: IPv4Resolver,
    _provenance_token: object | None = None,
) -> ExternalCommandPlan:
    """Build an optional strict one-thread Gobuster plan."""

    reason = _capability_reason(capabilities, "gobuster", _GOBUSTER_REQUIRED_OPTIONS)
    if not reason and not capabilities.repeated_headers_supported:
        reason = "Gobuster repeatable custom-header support could not be proven."
    if not reason and not capabilities.redirect_following_opt_in:
        reason = "Gobuster disabled-by-default redirect behaviour could not be proven."
    try:
        delay = gobuster_delay_for_rate(configuration.maximum_request_starts_per_second)
    except ValueError as exc:
        reason = str(exc)
    if reason:
        return _unsupported_plan("gobuster", "content_discovery", COMPONENT_OMITTED, reason)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ValueError("Strict Gobuster timeout must be a positive integer.")
    parsed = urlparse(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Strict Gobuster base URL is not an approved root or path HTTP destination."
        )
    canonical_programme_scope_policy = _canonical_programme_scope_policy(
        programme_scope_policy
    )
    decision = evaluate_raw_scope_destination(
        canonical_programme_scope_policy,
        DESTINATION_HTTP_URL,
        origin,
    )
    if decision.outcome != OUTCOME_ALLOWED:
        raise HTTPProgrammeScopeRefused("initial", decision)
    destination = decision.canonical_destination
    if not isinstance(destination, CanonicalHTTPURLDestination):
        raise ValueError("Strict Gobuster base URL is not canonical.")
    if http_origin_from_url(origin) not in configuration.approved_origins:
        raise ValueError(
            "Strict Gobuster base URL is not an approved root or path HTTP destination."
        )
    _require_gobuster_namespace_authority(
        canonical_programme_scope_policy,
        decision.matched_inclusion_rule_ids,
        destination,
    )
    select_programme_scope_ipv4_peer(
        canonical_programme_scope_policy,
        decision,
        ipv4_resolver,
    )
    if not wordlist.is_file():
        raise ValueError("Strict Gobuster wordlist does not exist.")
    _require_safe_local_path(wordlist, label="Strict Gobuster wordlist path")
    _require_safe_local_path(output_file, label="Strict Gobuster output path")
    try:
        wordlist_entries = _bounded_wordlist_entry_count(wordlist)
        process_timeout_seconds = _gobuster_process_timeout_seconds(
            wordlist_entries,
            configuration.maximum_request_starts_per_second,
            timeout_seconds,
        )
    except ValueError as exc:
        return _unsupported_plan(
            "gobuster", "content_discovery", COMPONENT_OMITTED, str(exc)
        )
    argv = [
        "gobuster",
        "dir",
        "--url",
        origin,
        "--wordlist",
        str(wordlist),
        "--threads",
        "1",
        "--delay",
        delay,
        "--useragent",
        configuration.user_agent,
    ]
    redacted = [*argv[:-1], "configured"]
    redactions = [configuration.user_agent]
    for header in configuration.identification_headers:
        argv.extend(("--headers", f"{header.name}: {header.value}"))
        redacted.extend(("--headers", f"{header.name}: configured"))
        redactions.append(header.value)
    argv.extend(
        (
            "--timeout",
            f"{timeout_seconds}s",
            "--output",
            str(output_file),
        )
    )
    redacted.extend(argv[len(redacted) :])
    _validate_strict_gobuster_argv(tuple(argv), configuration)
    return ExternalCommandPlan(
        tool="gobuster",
        purpose="content_discovery",
        compatibility_status=COMPONENT_SUPPORTED,
        redacted_argv=tuple(redacted),
        process_timeout_seconds=process_timeout_seconds,
        expected_artefacts=(str(output_file),),
        request_timeout_seconds=timeout_seconds,
        _private_argv=tuple(argv),
        _redaction_values=tuple(dict.fromkeys(redactions)),
        _provenance_token=_provenance_token,
    )


def _require_gobuster_namespace_authority(
    policy: ProgrammeScopePolicy,
    matched_inclusion_rule_ids: tuple[str, ...],
    base: CanonicalHTTPURLDestination,
) -> None:
    """Require broad authority and reject exclusions Gobuster cannot intercept."""

    matched_ids = {rule_id.casefold() for rule_id in matched_inclusion_rule_ids}
    broad_kinds = {
        RULE_EXACT_HOSTNAME,
        RULE_WILDCARD_SUBDOMAIN,
        RULE_HTTP_PATH_PREFIX,
    }
    if not any(
        rule.action == ACTION_INCLUDE
        and rule.kind in broad_kinds
        and rule.rule_id.casefold() in matched_ids
        for rule in policy.rules
    ):
        raise ValueError(
            "Strict Gobuster base lacks generated-namespace authority."
        )

    for rule in policy.rules:
        if rule.action != ACTION_EXCLUDE or rule.kind not in {
            RULE_EXACT_HTTP_URL,
            RULE_HTTP_PATH_PREFIX,
        }:
            continue
        excluded = canonicalise_http_url_destination(rule.canonical_value)
        if excluded.origin != base.origin:
            continue
        if rule.kind == RULE_EXACT_HTTP_URL and excluded.query is not None:
            continue
        if _path_is_equal_or_beneath(base.path, excluded.path):
            raise ValueError(
                "Strict Gobuster base has an intersecting exclusion."
            )


def _path_is_equal_or_beneath(base_path: str, candidate_path: str) -> bool:
    if base_path == "/":
        return True
    if base_path.endswith("/"):
        return candidate_path.startswith(base_path)
    return candidate_path == base_path or candidate_path.startswith(f"{base_path}/")


def run_bug_bounty_gobuster(
    plan: ExternalCommandPlan,
    executor: InternalHTTPExecutor,
    runner: SafeSubprocessRunner,
) -> ExternalProcessResult:
    """Run Gobuster exclusively with shared first-request and post-tool pacing."""

    if plan.tool != "gobuster":
        raise ValueError("Strict Gobuster execution requires a Gobuster plan.")
    with executor.exclusive_external_http_tool():
        return runner.run(plan)


def build_bug_bounty_nmap_plan(
    *,
    target: str,
    output_file: Path,
    policy: EngagementPolicy,
    capabilities: ToolCapabilities,
    timeout_seconds: int = 1800,
    _provenance_token: object | None = None,
) -> ExternalCommandPlan:
    """Build strict TCP port-state discovery from canonical policy facts."""

    canonical = policy_from_dict(policy.to_dict())
    assessment = assess_engagement_policy(canonical)
    if assessment.readiness_state != READINESS_FUTURE_ENFORCEMENT:
        raise ValueError("Engagement policy is incomplete for strict Nmap planning.")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ValueError("Strict Nmap timeout must be a positive integer.")
    mode = canonical.tcp_discovery_policy
    if mode == TCP_SKIP:
        return _unsupported_plan(
            "nmap",
            "tcp_port_state_discovery",
            COMPONENT_SUPPORTED,
            "TCP discovery is deliberately skipped by policy.",
        )
    reason = _capability_reason(capabilities, "nmap", _NMAP_REQUIRED_OPTIONS)
    if reason:
        return _unsupported_plan(
            "nmap", "tcp_port_state_discovery", COMPONENT_INCOMPATIBLE, reason
        )
    normalised_target = _normalise_target(target)
    _require_safe_local_path(output_file, label="Strict Nmap output path")
    if mode == TCP_CONSERVATIVE:
        port_specification = ",".join(str(port) for port in BUG_BOUNTY_COMMON_WEB_PORTS)
    elif mode == TCP_CUSTOM:
        if canonical.custom_tcp_ports is None:
            raise ValueError("Custom TCP policy is missing its validated port set.")
        port_specification = canonical.custom_tcp_ports
    elif mode == TCP_FULL:
        if canonical.tcp_policy_confirmed != CONFIRMED:
            raise ValueError("Full TCP discovery lacks explicit programme confirmation.")
        port_specification = "1-65535"
    else:
        raise ValueError("Unsupported bug bounty TCP discovery policy.")
    argv = (
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "-p",
        port_specification,
        "--max-rate",
        str(MAXIMUM_NMAP_PACKET_RATE),
        "--max-retries",
        str(NMAP_MAX_RETRIES),
        "-oN",
        str(output_file),
        normalised_target,
    )
    _validate_strict_nmap_argv(argv, policy=canonical)
    return ExternalCommandPlan(
        tool="nmap",
        purpose="tcp_port_state_discovery",
        compatibility_status=COMPONENT_SUPPORTED,
        redacted_argv=argv,
        process_timeout_seconds=timeout_seconds,
        expected_artefacts=(str(output_file),),
        _private_argv=argv,
        _provenance_token=_provenance_token,
    )


def build_bug_bounty_external_preflight(
    *,
    policy: EngagementPolicy,
    profile: str,
    curl_capabilities: ToolCapabilities,
    gobuster_capabilities: ToolCapabilities,
    nmap_capabilities: ToolCapabilities,
    _provenance_token: object | None = None,
) -> ExternalExecutionPreflight:
    """Assess every selected component before any target process can start."""

    if profile not in {
        QUICK_RECON_PROFILE,
        STANDARD_RECON_PROFILE,
        DEEP_RECON_PROFILE,
    }:
        raise ValueError("Unsupported bug bounty preflight profile.")
    canonical = policy_from_dict(policy.to_dict())
    assessment = assess_engagement_policy(canonical)
    if assessment.readiness_state != READINESS_FUTURE_ENFORCEMENT:
        raise ValueError("Engagement policy is incomplete for external-tool preflight.")

    try:
        build_http_enforcement_configuration(
            canonical,
            approved_origins=("https://preflight.invalid/",),
        )
    except ValueError:
        http_runtime_available = False
    else:
        http_runtime_available = True

    components = [
        ComponentAssessment(
            "internal_python_http",
            COMPONENT_SUPPORTED if http_runtime_available else COMPONENT_INCOMPATIBLE,
            profile == DEEP_RECON_PROFILE,
            (
                "Strict internal HTTP ignores ambient proxy environment variables. "
                "Proxy routing is not enabled unless explicitly supported and "
                "configured by BugSlyce."
                if http_runtime_available
                else "Policy identity cannot configure the internal HTTP transport."
            ),
        )
    ]
    curl_reason = _capability_reason(curl_capabilities, "curl", _CURL_REQUIRED_OPTIONS)
    if not http_runtime_available:
        curl_reason = "Shared policy-derived HTTP enforcement configuration is unavailable."
    components.append(
        ComponentAssessment(
            "curl",
            COMPONENT_INCOMPATIBLE if curl_reason else COMPONENT_SUPPORTED,
            True,
            curl_reason or "Strict curl identity, protocol and redirect controls are available.",
        )
    )
    gobuster_reason = _capability_reason(
        gobuster_capabilities, "gobuster", _GOBUSTER_REQUIRED_OPTIONS
    )
    if not gobuster_reason and not gobuster_capabilities.repeated_headers_supported:
        gobuster_reason = "Gobuster repeatable custom-header support could not be proven."
    if not gobuster_reason and not gobuster_capabilities.redirect_following_opt_in:
        gobuster_reason = "Gobuster disabled-by-default redirect behaviour could not be proven."
    if not http_runtime_available:
        gobuster_reason = "Shared policy-derived HTTP enforcement configuration is unavailable."
    if not gobuster_reason:
        try:
            gobuster_delay_for_rate(
                Decimal(canonical.maximum_http_requests_per_second)
            )
        except ValueError as exc:
            gobuster_reason = str(exc)
    components.append(
        ComponentAssessment(
            "gobuster",
            COMPONENT_OMITTED if gobuster_reason else COMPONENT_SUPPORTED,
            False,
            gobuster_reason
            or GOBUSTER_STARTUP_DISCLOSURE,
        )
    )
    if canonical.tcp_discovery_policy == TCP_SKIP:
        nmap_status = COMPONENT_SUPPORTED
        nmap_reason = "TCP discovery is deliberately skipped by policy."
        nmap_required = False
    else:
        nmap_reason = _capability_reason(nmap_capabilities, "nmap", _NMAP_REQUIRED_OPTIONS)
        nmap_status = COMPONENT_INCOMPATIBLE if nmap_reason else COMPONENT_SUPPORTED
        nmap_reason = nmap_reason or "Strict TCP port-state discovery controls are available."
        nmap_required = True
    components.append(
        ComponentAssessment("nmap", nmap_status, nmap_required, nmap_reason)
    )
    selected_port_count = _selected_tcp_port_count(canonical)
    ready = not any(
        component.required and component.status == COMPONENT_INCOMPATIBLE
        for component in components
    )
    return ExternalExecutionPreflight(
        profile=profile,
        components=tuple(components),
        aggregate_http_rate=canonical.maximum_http_requests_per_second,
        http_concurrency=canonical.maximum_http_concurrency,
        identity_header_names=tuple(
            header.name for header in canonical.identification_headers
        ),
        custom_identity_configured=bool(
            canonical.identification_headers or canonical.custom_user_agent
        ),
        tcp_discovery_mode=canonical.tcp_discovery_policy,
        selected_tcp_port_count=selected_port_count,
        ready=ready,
        _provenance_token=_provenance_token,
    )


def render_external_preflight(preflight: ExternalExecutionPreflight) -> str:
    """Render a deterministic policy-safe preflight summary."""

    lines = [
        "BugSlyce bug bounty external-tool preflight",
        f"Profile: {preflight.profile}",
        f"Aggregate HTTP rate: {preflight.aggregate_http_rate} requests per second",
        f"HTTP concurrency: {preflight.http_concurrency}",
        "Custom identity: "
        + ("configured" if preflight.custom_identity_configured else "not configured"),
        "Identification header names: "
        + (", ".join(preflight.identity_header_names) or "none"),
        f"TCP discovery mode: {preflight.tcp_discovery_mode}",
        f"Selected TCP port count: {preflight.selected_tcp_port_count}",
        "Components:",
    ]
    lines.extend(
        f"- {item.component}: {item.status} - {item.reason}"
        for item in preflight.components
    )
    lines.append(
        "Preflight result: "
        + ("supported for controlled capture planning" if preflight.ready else "refused")
    )
    lines.append(
        "Live bug bounty reconnaissance remains blocked pending R0B3 controlled capture acceptance."
    )
    return "\n".join(lines)


def _effective_external_headers(
    configuration: HTTPEnforcementConfiguration,
    additional_headers: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    headers = [(item.name, item.value) for item in configuration.identification_headers]
    seen = {name.casefold() for name, _value in headers} | {"user-agent"}
    for item in additional_headers:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("Functional curl headers must be name/value pairs.")
        name, value = item
        try:
            validated_name = validate_identification_header_name(name)
            validated_value = validate_identification_value(
                value, label="Functional curl header value"
            )
        except ValueError:
            raise ValueError("Functional curl header is invalid or conflicts with identity.") from None
        folded = validated_name.casefold()
        if folded in seen:
            raise ValueError("Functional curl header conflicts with the effective identity.")
        seen.add(folded)
        headers.append((validated_name, validated_value))
    return tuple(headers)


def _capability_reason(
    capabilities: ToolCapabilities,
    tool: str,
    required: frozenset[str],
) -> str:
    if capabilities.tool != tool:
        return f"{tool} capability information is mismatched."
    if not capabilities.available:
        return f"{tool} executable is unavailable."
    missing = tuple(sorted(required - capabilities.supported_options))
    if missing:
        return f"{tool} required capabilities could not be proven: {', '.join(missing)}."
    return ""


def _unsupported_plan(
    tool: str,
    purpose: str,
    status: str,
    reason: str,
) -> ExternalCommandPlan:
    return ExternalCommandPlan(
        tool=tool,
        purpose=purpose,
        compatibility_status=status,
        redacted_argv=(),
        process_timeout_seconds=0,
        expected_artefacts=(),
        reason=reason,
    )


def _normalise_target(target: str) -> str:
    if not isinstance(target, str):
        raise ValueError("Strict Nmap target is invalid.")
    value = target.strip().lower().rstrip(".")
    if (
        not value
        or value != target.lower().rstrip(".")
        or value.startswith("-")
        or any(character.isspace() for character in value)
        or "/" in value
        or scope_entry_target(value) != value
    ):
        raise ValueError("Strict Nmap target must be one hostname or IP address.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in value.split(".")
        ):
            raise ValueError(
                "Strict Nmap target must be one hostname or IPv4 address."
            ) from None
    else:
        if address.version != 4:
            raise ValueError(
                "Strict Nmap target requires unsupported IPv6 capability."
            )
    return value


def _validate_strict_curl_argv(
    argv: tuple[str, ...],
    configuration: HTTPEnforcementConfiguration,
) -> None:
    prohibited = (
        "--config",
        "-K",
        "--next",
        "--parallel",
        "--retry",
        "--location",
        "--location-trusted",
        "-L",
        "--no-globoff",
        "--proxy",
        "-x",
        "--preproxy",
        "--connect-to",
        "--proxy-user",
        "--proxy-header",
    )
    if len(argv) < 4 or argv[:3] != ("curl", "--disable", "--globoff"):
        raise ValueError("Strict curl plan must disable default configuration and URL globbing first.")
    if any(
        value == option or value.startswith(f"{option}=")
        for value in argv
        for option in prohibited
        if option.startswith("--")
    ) or any(value == option for value in argv for option in {"-K", "-L", "-x"}):
        raise ValueError("Strict curl plan contains a prohibited transfer option.")
    if argv.count("--globoff") != 1:
        raise ValueError("Strict curl plan must disable URL globbing exactly once.")
    if argv.count("--") != 1:
        raise ValueError("Strict curl plan must delimit exactly one URL operand.")
    separator = argv.index("--")
    if separator != len(argv) - 2:
        raise ValueError("Strict curl plan must contain exactly one URL operand.")
    url = argv[-1]
    parsed = urlparse(url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or http_origin_from_url(url) not in configuration.approved_origins
    ):
        raise ValueError("Strict curl plan target is not approved.")
    if "--max-redirs" not in argv or argv[argv.index("--max-redirs") + 1] != "0":
        raise ValueError("Strict curl plan must disable automatic redirects.")
    if "--proto" not in argv or argv[argv.index("--proto") + 1] != "=http,https":
        raise ValueError("Strict curl plan must restrict target protocols.")
    if "--noproxy" not in argv or argv[argv.index("--noproxy") + 1] != "*":
        raise ValueError("Strict curl plan must disable proxy routing.")
    if argv.count("--resolve") != 1:
        raise ValueError("Strict curl plan must bind exactly one resolved IPv4 peer.")
    mapping = argv[argv.index("--resolve") + 1]
    if mapping.count(":") != 2 or any(value in mapping for value in {",", "*"}):
        raise ValueError("Strict curl plan resolved peer binding is invalid.")
    mapping_host, mapping_port, mapping_ipv4 = mapping.split(":")
    parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        canonical_ipv4 = str(ipaddress.IPv4Address(mapping_ipv4))
    except ipaddress.AddressValueError:
        raise ValueError("Strict curl plan resolved peer binding is invalid.") from None
    if (
        not parsed.hostname
        or mapping_host != parsed.hostname
        or mapping_port != str(parsed_port)
        or mapping_ipv4 != canonical_ipv4
    ):
        raise ValueError("Strict curl plan resolved peer binding is invalid.")
    if "--user-agent" not in argv or argv[argv.index("--user-agent") + 1] != configuration.user_agent:
        raise ValueError("Strict curl plan identity does not match the enforcement configuration.")
    names = [value.split(":", 1)[0].casefold() for index, value in enumerate(argv) if index and argv[index - 1] == "--header"]
    expected = [item.name.casefold() for item in configuration.identification_headers]
    if names[: len(expected)] != expected:
        raise ValueError("Strict curl plan identification headers do not match the enforcement configuration.")
    options_with_value = {
        "--proto",
        "--noproxy",
        "--max-redirs",
        "--connect-timeout",
        "--max-time",
        "--resolve",
        "--user-agent",
        "--header",
        "--dump-header",
        "--write-out",
        "--output",
    }
    flags = {"--disable", "--globoff", "--silent", "--show-error", "--head"}
    index = 1
    while index < separator:
        option = argv[index]
        if option in flags:
            index += 1
        elif option in options_with_value and index + 1 < separator:
            index += 2
        else:
            raise ValueError("Strict curl plan contains an unexpected transfer operand.")


def _validate_strict_gobuster_argv(
    argv: tuple[str, ...],
    configuration: HTTPEnforcementConfiguration,
) -> None:
    if len(argv) < 2 or argv[:2] != ("gobuster", "dir"):
        raise ValueError("Strict Gobuster plan must use directory mode.")
    required_values = {
        "--threads": "1",
        "--useragent": configuration.user_agent,
    }
    for option, expected in required_values.items():
        if option not in argv or argv[argv.index(option) + 1] != expected:
            raise ValueError("Strict Gobuster plan does not match the enforcement configuration.")
    if "--delay" not in argv or "--timeout" not in argv or "--follow-redirect" in argv or "-r" in argv:
        raise ValueError("Strict Gobuster plan lacks required safety controls.")
    if "--url" not in argv:
        raise ValueError("Strict Gobuster plan lacks an approved root origin.")
    root_url = argv[argv.index("--url") + 1]
    if http_origin_from_url(root_url) not in configuration.approved_origins:
        raise ValueError("Strict Gobuster plan root origin is not approved.")
    names = [value.split(":", 1)[0].casefold() for index, value in enumerate(argv) if index and argv[index - 1] == "--headers"]
    expected = [item.name.casefold() for item in configuration.identification_headers]
    if names != expected:
        raise ValueError("Strict Gobuster plan identification headers do not match the enforcement configuration.")


def _validate_strict_nmap_argv(
    argv: tuple[str, ...],
    *,
    policy: EngagementPolicy,
) -> None:
    prohibited = {
        "-sV",
        "-sC",
        "--script",
        "-A",
        "-O",
        "--traceroute",
        "-sU",
        "-T4",
        "-T5",
        "--min-rate",
        "-p-",
    }
    if any(value in prohibited or value.startswith("--script=") for value in argv):
        raise ValueError("Strict bug bounty Nmap plan contains a prohibited flag.")
    required = {"nmap", "-sT", "-Pn", "-n", "-p", "--max-rate", "--max-retries", "-oN"}
    if not required.issubset(argv) or len(argv) != 13:
        raise ValueError("Strict bug bounty Nmap plan lacks required controls.")
    if "--max-rate" not in argv:
        raise ValueError("Strict bug bounty Nmap plan requires a maximum packet rate.")
    rate = int(argv[argv.index("--max-rate") + 1])
    if rate > MAXIMUM_NMAP_PACKET_RATE:
        raise ValueError("Strict bug bounty Nmap maximum packet rate is too high.")
    expected_ports = (
        ",".join(str(port) for port in BUG_BOUNTY_COMMON_WEB_PORTS)
        if policy.tcp_discovery_policy == TCP_CONSERVATIVE
        else policy.custom_tcp_ports
        if policy.tcp_discovery_policy == TCP_CUSTOM
        else "1-65535"
        if policy.tcp_discovery_policy == TCP_FULL
        else None
    )
    if expected_ports is None or argv[argv.index("-p") + 1] != expected_ports:
        raise ValueError("Strict bug bounty Nmap ports do not match the engagement policy.")
    if argv[-1] != _normalise_target(argv[-1]):
        raise ValueError("Strict bug bounty Nmap target is invalid.")
    _require_safe_local_path(Path(argv[argv.index("-oN") + 1]), label="Strict Nmap output path")


def _validate_bound_curl_plan(
    plan: ExternalCommandPlan,
    configuration: HTTPEnforcementConfiguration,
) -> None:
    argv = plan.private_argv
    _validate_strict_curl_argv(argv, configuration)
    _require_exact_option_counts(
        argv,
        {
            "--disable": 1,
            "--globoff": 1,
            "--silent": 1,
            "--show-error": 1,
            "--proto": 1,
            "--noproxy": 1,
            "--max-redirs": 1,
            "--connect-timeout": 1,
            "--max-time": 1,
            "--resolve": 1,
            "--user-agent": 1,
            "--dump-header": 1,
            "--write-out": 1,
            "--output": 1,
        },
    )
    headers = tuple(
        value for index, value in enumerate(argv) if index and argv[index - 1] == "--header"
    )
    identity_count = len(configuration.identification_headers)
    identity_headers = tuple(
        f"{item.name}: {item.value}" for item in configuration.identification_headers
    )
    if headers[:identity_count] != identity_headers:
        raise ValueError("Strict curl plan identification headers do not match the enforcement configuration.")
    functional_headers: list[tuple[str, str]] = []
    for header in headers[identity_count:]:
        if ": " not in header:
            raise ValueError("Strict curl plan functional headers are invalid.")
        name, value = header.split(": ", 1)
        functional_headers.append((name, value))
    try:
        expected_headers = tuple(
            f"{name}: {value}"
            for name, value in _effective_external_headers(
                configuration,
                tuple(functional_headers),
            )
        )
    except ValueError:
        raise ValueError("Strict curl plan functional headers are invalid.") from None
    if headers != expected_headers:
        raise ValueError("Strict curl plan functional headers are invalid.")
    if (
        plan.request_timeout_seconds is not None
        or argv[argv.index("--max-time") + 1] != str(plan.process_timeout_seconds)
        or argv.count("--head") > 1
    ):
        raise ValueError("Strict curl plan metadata is invalid.")
    if len(plan.expected_artefacts) != 2:
        raise ValueError("Strict curl plan artefact metadata is invalid.")
    if argv[argv.index("--output") + 1] != plan.expected_artefacts[0]:
        raise ValueError("Strict curl output does not match the registered artefact metadata.")
    if argv[argv.index("--dump-header") + 1] != plan.expected_artefacts[1]:
        raise ValueError("Strict curl header output does not match the registered artefact metadata.")
    _validate_redacted_argv(plan)


def _validate_bound_gobuster_plan(
    plan: ExternalCommandPlan,
    configuration: HTTPEnforcementConfiguration,
) -> None:
    argv = plan.private_argv
    _validate_strict_gobuster_argv(argv, configuration)
    _require_exact_option_counts(
        argv,
        {
            "--url": 1,
            "--wordlist": 1,
            "--threads": 1,
            "--delay": 1,
            "--useragent": 1,
            "--timeout": 1,
            "--output": 1,
        },
    )
    headers = tuple(
        value for index, value in enumerate(argv) if index and argv[index - 1] == "--headers"
    )
    expected_identity = tuple(
        f"{item.name}: {item.value}" for item in configuration.identification_headers
    )
    if headers != expected_identity:
        raise ValueError("Strict Gobuster identification headers do not match the enforcement configuration.")
    if (
        plan.request_timeout_seconds is None
        or argv[argv.index("--timeout") + 1] != f"{plan.request_timeout_seconds}s"
        or len(plan.expected_artefacts) != 1
        or argv[argv.index("--output") + 1] != plan.expected_artefacts[0]
    ):
        raise ValueError("Strict Gobuster plan metadata is invalid.")
    try:
        expected_delay = gobuster_delay_for_rate(
            configuration.maximum_request_starts_per_second
        )
        expected_process_timeout = _gobuster_process_timeout_seconds(
            _bounded_wordlist_entry_count(Path(argv[argv.index("--wordlist") + 1])),
            configuration.maximum_request_starts_per_second,
            plan.request_timeout_seconds,
        )
    except ValueError:
        raise ValueError("Strict Gobuster plan metadata is invalid.") from None
    if (
        argv[argv.index("--delay") + 1] != expected_delay
        or plan.process_timeout_seconds != expected_process_timeout
    ):
        raise ValueError("Strict Gobuster plan metadata is invalid.")
    _validate_redacted_argv(plan)


def _validate_bound_nmap_plan(
    plan: ExternalCommandPlan,
    *,
    policy: EngagementPolicy,
) -> None:
    argv = plan.private_argv
    _validate_strict_nmap_argv(argv, policy=policy)
    _require_exact_option_counts(
        argv,
        {
            "-sT": 1,
            "-Pn": 1,
            "-n": 1,
            "-p": 1,
            "--max-rate": 1,
            "--max-retries": 1,
            "-oN": 1,
        },
    )
    if (
        argv[argv.index("--max-rate") + 1] != str(MAXIMUM_NMAP_PACKET_RATE)
        or argv[argv.index("--max-retries") + 1] != str(NMAP_MAX_RETRIES)
        or len(plan.expected_artefacts) != 1
        or argv[argv.index("-oN") + 1] != plan.expected_artefacts[0]
    ):
        raise ValueError("Strict Nmap plan metadata is invalid.")
    _validate_redacted_argv(plan)


def _require_exact_option_counts(
    argv: tuple[str, ...],
    expected: dict[str, int],
) -> None:
    for option, count in expected.items():
        if argv.count(option) != count:
            raise ValueError("Strict external command contains duplicate or missing controls.")


def _validate_redacted_argv(plan: ExternalCommandPlan) -> None:
    expected: list[str] = []
    for index, value in enumerate(plan.private_argv):
        previous = plan.private_argv[index - 1] if index else ""
        if previous in {"--user-agent", "--useragent"}:
            expected.append("configured")
        elif previous in {"--header", "--headers"}:
            name = value.split(":", 1)[0]
            expected.append(f"{name}: configured")
        else:
            expected.append(value)
    if tuple(expected) != plan.redacted_argv:
        raise ValueError("Strict external command redacted representation is invalid.")


def _bounded_wordlist_entry_count(wordlist: Path) -> int:
    try:
        metadata = wordlist.stat()
        if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_GOBUSTER_WORDLIST_BYTES:
            raise ValueError
        count = 0
        with wordlist.open("rb") as handle:
            for line in handle:
                if len(line) > 16_384:
                    raise ValueError
                if line.strip():
                    count += 1
                    if count > MAXIMUM_GOBUSTER_WORDLIST_ENTRIES:
                        raise ValueError
    except (OSError, ValueError):
        raise ValueError("Gobuster wordlist is unreadable or exceeds bounded planning limits.") from None
    if count == 0:
        raise ValueError("Gobuster wordlist has no usable bounded entries.")
    return count


def _gobuster_process_timeout_seconds(
    entry_count: int,
    rate: Decimal,
    request_timeout_seconds: int,
) -> int:
    if not isinstance(request_timeout_seconds, int) or isinstance(request_timeout_seconds, bool) or request_timeout_seconds <= 0:
        raise ValueError("Strict Gobuster timeout must be a positive integer.")
    delay_seconds = _ceil_positive_decimal_ratio(entry_count, rate)
    minimum = delay_seconds + GOBUSTER_STARTUP_FINALISATION_ALLOWANCE_SECONDS
    # The per-request timeout is an independent Gobuster control. The process
    # deadline must cover the bounded delay schedule plus setup/finalisation.
    timeout = max(minimum, request_timeout_seconds + GOBUSTER_STARTUP_FINALISATION_ALLOWANCE_SECONDS)
    if timeout > MAXIMUM_GOBUSTER_PROCESS_TIMEOUT_SECONDS:
        raise ValueError("Gobuster bounded process duration exceeds the supported limit.")
    return timeout


def _ceil_positive_decimal_ratio(numerator: int, denominator: Decimal) -> int:
    """Return ceil(numerator / denominator) without Decimal-context rounding."""

    if (
        isinstance(numerator, bool)
        or not isinstance(numerator, int)
        or numerator <= 0
        or not isinstance(denominator, Decimal)
        or not denominator.is_finite()
        or denominator <= 0
    ):
        raise ValueError("Strict Gobuster rate calculation is invalid.")
    parts = denominator.as_tuple()
    coefficient = int("".join(str(digit) for digit in parts.digits))
    if coefficient <= 0:
        raise ValueError("Strict Gobuster rate calculation is invalid.")
    if parts.exponent >= 0:
        denominator_numerator = coefficient * (10 ** parts.exponent)
        denominator_denominator = 1
    else:
        denominator_numerator = coefficient
        denominator_denominator = 10 ** (-parts.exponent)
    dividend = numerator * denominator_denominator
    return (dividend + denominator_numerator - 1) // denominator_numerator


def _selected_tcp_port_count(policy: EngagementPolicy) -> int:
    if policy.tcp_discovery_policy == TCP_SKIP:
        return 0
    if policy.tcp_discovery_policy == TCP_CONSERVATIVE:
        return len(BUG_BOUNTY_COMMON_WEB_PORTS)
    if policy.tcp_discovery_policy == TCP_FULL:
        return 65535
    if policy.custom_tcp_ports is None:
        return 0
    count = 0
    for item in policy.custom_tcp_ports.split(","):
        if "-" in item:
            start, end = (int(value) for value in item.split("-", 1))
            count += end - start + 1
        else:
            count += 1
    return count


def _curl_status(stdout: str) -> int | None:
    compact = stdout.strip()
    if len(compact) != 3 or not compact.isdecimal():
        return None
    value = int(compact)
    return value if 100 <= value <= 599 else None


def _load_bounded_curl_headers(path: Path) -> tuple[tuple[str, str], ...]:
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            return ()
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    headers: list[tuple[str, str]] = []
    for line in content.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip() and value.strip():
            headers.append((name.strip(), value.strip()))
    return tuple(headers)


def _redact_text(value: str, plan: ExternalCommandPlan) -> str:
    redacted = value
    for sensitive in sorted(plan._redaction_values, key=len, reverse=True):
        if sensitive:
            redacted = redacted.replace(sensitive, "[configured value redacted]")
    redacted = redacted[: MAXIMUM_PROCESS_DIAGNOSTIC_CHARS * 2]
    safe = "".join(
        character
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else "[unsafe control omitted]"
        for character in redacted
    )
    if len(safe) > MAXIMUM_PROCESS_DIAGNOSTIC_CHARS:
        return safe[: MAXIMUM_PROCESS_DIAGNOSTIC_CHARS - 3] + "..."
    return safe


def _artefact_snapshots(
    plan: ExternalCommandPlan,
) -> dict[Path, tuple[int, int, int] | None]:
    snapshots: dict[Path, tuple[int, int, int] | None] = {}
    for value in plan.expected_artefacts:
        path = Path(value)
        try:
            metadata = path.stat()
        except OSError:
            snapshots[path] = None
        else:
            snapshots[path] = (
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            )
    return snapshots


def _finalise_expected_artefacts(
    plan: ExternalCommandPlan,
    snapshots: dict[Path, tuple[int, int, int] | None],
) -> tuple[str, ...]:
    """Redact and return only expected artefacts changed by this invocation."""

    replacements: list[tuple[bytes, bytes]] = []
    replacement = b"[configured value redacted]"
    for value in plan._redaction_values:
        for encoding in ("utf-8", "latin-1"):
            try:
                encoded = value.encode(encoding)
            except UnicodeEncodeError:
                continue
            if encoded and (encoded, replacement) not in replacements:
                replacements.append((encoded, replacement))
    produced: list[str] = []
    for artefact in plan.expected_artefacts:
        path = Path(artefact)
        try:
            if not path.is_file():
                continue
            metadata = path.stat()
            current = (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            if snapshots.get(path) == current:
                continue
            produced.append(str(path))
            content = path.read_bytes()
            redacted = content
            for sensitive, marker in replacements:
                redacted = redacted.replace(sensitive, marker)
            if redacted != content:
                path.write_bytes(redacted)
        except OSError:
            try:
                if snapshots.get(path) != _artefact_metadata(path):
                    path.unlink(missing_ok=True)
            except OSError:
                pass
            raise ValueError(
                f"{plan.tool} output could not be redacted safely."
            ) from None
    return tuple(produced)


def _artefact_metadata(path: Path) -> tuple[int, int, int] | None:
    try:
        metadata = path.stat()
    except OSError:
        return None
    return (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _help_mentions_option(help_text: str, option: str) -> bool:
    direct_match = re.search(
        rf"(?<![0-9A-Za-z_-]){re.escape(option)}(?=$|[\s,=/:<])",
        help_text,
    )
    if direct_match is not None:
        return True
    if len(option) != 3 or not option.startswith("-"):
        return False
    stem, variant = option[1], option[2]
    return re.search(
        rf"(?<![0-9A-Za-z_-])-{re.escape(stem)}[A-Za-z0-9](?:/{re.escape(stem)}[A-Za-z0-9])*/{re.escape(stem)}{re.escape(variant)}(?=$|[\s,=/:<])",
        help_text,
    ) is not None


def _gobuster_repeatable_headers_supported(help_text: str) -> bool:
    """Require option-local structural proof that Gobuster accepts repeated headers."""

    header_option = re.compile(
        r"(?<![0-9A-Za-z_-])(?:--headers|-H)(?![0-9A-Za-z_-])",
    )
    header_string_array = re.compile(
        r"(?<![0-9A-Za-z_-])(?:--headers|-H)(?![0-9A-Za-z_-])\s+stringArray\b",
    )
    for line in help_text.splitlines():
        if header_option.search(line) is None:
            continue
        if header_string_array.search(line) is not None:
            return True
        for bracketed in re.finditer(r"\[([^\]\r\n]{0,512})\]", line):
            outside = line[: bracketed.start()] + line[bracketed.end() :]
            if header_option.search(outside) and header_option.search(bracketed.group(1)):
                return True
    return False


def _require_safe_local_path(path: Path, *, label: str) -> None:
    value = str(path)
    if not value or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in value
    ):
        raise ValueError(f"{label} is invalid.")
