"""Focused R0B2 tests for strict external-tool planning and execution."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace

import pytest

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IDENTIFICATION_NONE,
    NOT_YET_CONFIRMED,
    TCP_CONSERVATIVE,
    TCP_CUSTOM,
    TCP_FULL,
    TCP_SKIP,
    IdentificationHeader,
    build_bug_bounty_policy,
    enforce_r0b2_bug_bounty_live_block,
)
from bugslyce.recon.external_enforcement import (
    BUG_BOUNTY_COMMON_WEB_PORTS,
    COMPONENT_INCOMPATIBLE,
    COMPONENT_OMITTED,
    COMPONENT_SUPPORTED,
    GOBUSTER_STARTUP_DISCLOSURE,
    MAXIMUM_NMAP_PACKET_RATE,
    BugBountyExternalEnforcementSession,
    BugBountyExternalToolRuntime,
    ExternalCommandPlan,
    SafeSubprocessRunner,
    advance_curl_redirect_chain,
    assess_tool_capabilities,
    begin_curl_redirect_chain,
    build_bug_bounty_curl_plan,
    build_bug_bounty_external_preflight,
    build_bug_bounty_gobuster_plan,
    build_bug_bounty_nmap_plan,
    gobuster_delay_for_rate,
    render_external_preflight,
    resolve_bug_bounty_curl_redirect,
    run_bug_bounty_curl,
    run_bug_bounty_gobuster,
    _gobuster_process_timeout_seconds,
    _validate_strict_curl_argv,
)
from bugslyce.recon.http_enforcement import (
    HTTPExecutorClosed,
    HTTPRateRejected,
    HTTPRedirectRefused,
    HTTPTransportResponse,
    InternalHTTPExecutor,
    build_http_enforcement_configuration,
)
from bugslyce.recon.user_agent import built_in_user_agent
from bugslyce.recon.modes import DEEP_RECON_PROFILE
from bugslyce.recon.content_plan import (
    DEEP_BOUNDED_CORE_WORDLIST,
    STANDARD_BOUNDED_CORE_WORDLIST,
)
from bugslyce.recon.nmap_services import run_nmap_service_workflow


HEADER_SECRET = "external-private-header-4729"
USER_AGENT_SECRET = "ExternalPrivateAgent/4729"

CURL_HELP = " ".join(
    (
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
        "--silent",
        "--show-error",
        "--user-agent",
        "--write-out",
    )
)
GOBUSTER_HELP = """
dir
--url --wordlist --threads --delay --useragent --headers stringArray
--timeout --output --follow-redirect (default false)
"""
GOBUSTER_382_HELP = """
Usage:
  gobuster dir [flags]

Flags:
      --url string
      --wordlist string
      --threads int
      --delay duration
      --useragent string
      --headers value, -H value [ --headers value, -H value ]
            Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
      --timeout duration
      --output string
      --follow-redirect (default false)
            Follow redirects
"""
NMAP_HELP = "-sT -Pn -n -p --max-rate --max-retries -oN"
COMPACT_NMAP_HELP = """
-sS/sT/sA/sW/sM: TCP scan techniques
-Pn: Treat all hosts as online
-n/-R: Never or always perform DNS resolution
-p <port ranges>
--max-rate <number>
--max-retries <tries>
-oN/-oX/-oS/-oG <file>
"""


class _FakeTime:
    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleeps: list[Decimal] = []

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        delay = Decimal(str(seconds))
        self.sleeps.append(delay)
        self.now += delay


class _Transport:
    def __init__(self, clock: _FakeTime) -> None:
        self.clock = clock
        self.starts: list[Decimal] = []

    def __call__(self, _request):
        self.starts.append(self.clock.now)
        return HTTPTransportResponse(200, (), b"ok")


class _ProcessRunner:
    def __init__(
        self,
        clock: _FakeTime | None = None,
        *,
        returncode: int = 0,
        stdout: str = "200",
        stderr: str = "",
        error: BaseException | None = None,
    ) -> None:
        self.clock = clock
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.calls: list[tuple[tuple[str, ...], int, object]] = []
        self.starts: list[Decimal] = []

    def run(self, argv, timeout_seconds, environment):
        self.calls.append((tuple(argv), timeout_seconds, environment))
        if self.clock is not None:
            self.starts.append(self.clock.now)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


class _GateTime:
    def __init__(self) -> None:
        self.now = Decimal("0")
        self.sleep_entered = threading.Event()
        self.release_sleep = threading.Event()

    def monotonic(self) -> float:
        return float(self.now)

    def sleep(self, seconds: float) -> None:
        self.sleep_entered.set()
        if not self.release_sleep.wait(timeout=2):
            raise AssertionError("test limiter sleep was not released")
        self.now += Decimal(str(seconds))


class _BlockingFirstProcess:
    def __init__(self, *, first_status: str = "200") -> None:
        self.first_status = first_status
        self.first_entered = threading.Event()
        self.release_first = threading.Event()
        self.calls = 0

    def run(self, _argv, _timeout_seconds, _environment):
        self.calls += 1
        if self.calls != 1:
            raise AssertionError("queued curl reached the process runner")
        self.first_entered.set()
        if not self.release_first.wait(timeout=2):
            raise AssertionError("test curl process was not released")
        return SimpleNamespace(returncode=0, stdout=self.first_status, stderr="")


class _ArtefactWritingProcess(_ProcessRunner):
    def __init__(self, paths: tuple[str, ...], content: str) -> None:
        super().__init__()
        self.paths = paths
        self.content = content

    def run(self, argv, timeout_seconds, environment):
        for value in self.paths:
            Path(value).write_text(self.content, encoding="utf-8")
        return super().run(argv, timeout_seconds, environment)


class _EnvironmentObservingRunner:
    def __init__(self) -> None:
        self.environments: list[object] = []

    def run(self, _argv, _timeout_seconds, environment):
        self.environments.append(environment)
        return SimpleNamespace(returncode=0, stdout="200", stderr="")


class _DelayedArtefactProcess:
    """Simulate target-visible curl arrival after variable process start-up."""

    def __init__(self, clock: _FakeTime, delays: tuple[Decimal, ...]) -> None:
        self.clock = clock
        self.delays = iter(delays)
        self.permit_starts: list[Decimal] = []
        self.arrivals: list[Decimal] = []
        self.calls = 0

    def run(self, argv, _timeout_seconds, _environment):
        delay = next(self.delays)
        self.permit_starts.append(self.clock.now)
        self.clock.now += delay
        self.arrivals.append(self.clock.now)
        for option in ("--output", "--dump-header"):
            Path(argv[argv.index(option) + 1]).write_text("safe", encoding="utf-8")
        self.calls += 1
        return SimpleNamespace(returncode=0, stdout="200", stderr="")


class _DelayedInternalTransport:
    """Simulate target-visible arrival after internal transport start-up."""

    def __init__(self, clock: _FakeTime, delays: tuple[Decimal, ...]) -> None:
        self.clock = clock
        self.delays = iter(delays)
        self.starts: list[Decimal] = []
        self.arrivals: list[Decimal] = []

    def __call__(self, _request):
        self.starts.append(self.clock.now)
        self.clock.now += next(self.delays)
        self.arrivals.append(self.clock.now)
        return HTTPTransportResponse(200, (), b"ok")


def test_curl_and_internal_http_share_one_steady_limiter(tmp_path: Path) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    plan = _curl_plan(tmp_path)
    process = _ProcessRunner(clock)

    executor.request("https://example.test/")
    run_bug_bounty_curl(plan, executor, SafeSubprocessRunner(process))
    executor.request("https://example.test/again")

    assert transport.starts == [Decimal("0"), Decimal("1.0")]
    assert process.starts == [Decimal("0.5")]
    assert executor.total_request_attempts == 3


def test_internal_completion_barrier_prevents_target_arrival_compression(
    tmp_path: Path,
) -> None:
    clock = _FakeTime()
    transport = _DelayedInternalTransport(clock, (Decimal("0.4"),))
    executor = _executor(clock, transport=transport)
    session = _session(clock, executor=executor)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = _DelayedArtefactProcess(clock, (Decimal("0"),))

    executor.request("https://example.test/internal")
    BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert transport.arrivals == [Decimal("0.4")]
    assert process.permit_starts == [Decimal("0.9")]
    assert process.arrivals == [Decimal("0.9")]
    assert process.arrivals[0] - transport.arrivals[0] == Decimal("0.5")
    assert executor.total_request_attempts == 2


def test_variable_curl_launch_delays_do_not_compress_target_arrivals(
    tmp_path: Path,
) -> None:
    clock = _FakeTime()
    session = _session(clock)
    plans = tuple(
        session.build_curl_plan(
            url="https://example.test/value",
            method="GET",
            output_file=tmp_path / f"body-{index}.html",
            response_headers_file=tmp_path / f"headers-{index}.txt",
            timeout_seconds=10,
            purpose="test_exchange",
        )
        for index in range(3)
    )
    process = _DelayedArtefactProcess(
        clock,
        (Decimal("0.4"), Decimal("0"), Decimal("0")),
    )
    runtime = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process))

    for plan in plans:
        runtime.run(plan)

    assert process.permit_starts == [Decimal("0"), Decimal("0.9"), Decimal("1.4")]
    assert process.arrivals == [Decimal("0.4"), Decimal("0.9"), Decimal("1.4")]
    assert [
        right - left for left, right in zip(process.arrivals, process.arrivals[1:])
    ] == [Decimal("0.5"), Decimal("0.5")]
    assert max(
        sum(window_start <= arrival < window_start + Decimal(1) for arrival in process.arrivals)
        for window_start in process.arrivals
    ) == 2
    assert session.http_executor.total_request_attempts == 3


def test_curl_completion_barrier_applies_to_following_internal_http(
    tmp_path: Path,
) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    session = _session(clock, executor=executor)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = _DelayedArtefactProcess(clock, (Decimal("0.4"),))

    BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)
    executor.request("https://example.test/after-curl")

    assert process.arrivals == [Decimal("0.4")]
    assert transport.starts == [Decimal("0.9")]
    assert executor.total_request_attempts == 2


def test_internal_http_then_curl_still_uses_the_shared_limiter(tmp_path: Path) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    session = _session(clock, executor=executor)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = _DelayedArtefactProcess(clock, (Decimal("0"),))

    executor.request("https://example.test/before-curl")
    BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert transport.starts == [Decimal("0")]
    assert process.permit_starts == [Decimal("0.5")]
    assert executor.total_request_attempts == 2


@pytest.mark.parametrize(
    ("outcome", "raises"),
    [
        ("success", None),
        ("non_zero", None),
        ("timeout", None),
        ("exception", None),
        ("keyboard_interrupt", KeyboardInterrupt),
        ("system_exit", SystemExit),
    ],
)
def test_curl_completion_barrier_runs_for_every_process_outcome(
    tmp_path: Path,
    outcome: str,
    raises: type[BaseException] | None,
) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    session = _session(clock, executor=executor)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = {
        "success": _ProcessRunner(),
        "non_zero": _ProcessRunner(returncode=7),
        "timeout": _ProcessRunner(error=subprocess.TimeoutExpired(("curl",), 10)),
        "exception": _ProcessRunner(error=RuntimeError("unexpected fake failure")),
        "keyboard_interrupt": _ProcessRunner(error=KeyboardInterrupt()),
        "system_exit": _ProcessRunner(error=SystemExit(7)),
    }[outcome]
    runtime = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process))

    if raises is None:
        runtime.run(plan)
    else:
        with pytest.raises(raises):
            runtime.run(plan)
    executor.request("https://example.test/after-curl")

    assert transport.starts == [Decimal("0.5")]
    assert executor.total_request_attempts == 2


def test_rejected_plan_does_not_consume_a_permit_or_install_a_barrier(
    tmp_path: Path,
) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    session = _session(clock, executor=executor)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    runtime = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(_ProcessRunner()))

    with pytest.raises(ValueError, match="registered session plan"):
        runtime.run(replace(plan))
    executor.request("https://example.test/no-barrier")

    assert transport.starts == [Decimal("0")]
    assert executor.total_request_attempts == 1


def test_curl_then_internal_http_has_no_stage_boundary_burst(tmp_path: Path) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    process = _ProcessRunner(clock)

    run_bug_bounty_curl(_curl_plan(tmp_path), executor, SafeSubprocessRunner(process))
    executor.request("https://example.test/after-curl")

    assert process.starts == [Decimal("0")]
    assert transport.starts == [Decimal("0.5")]


@pytest.mark.parametrize(
    ("process", "expected_error", "started"),
    [
        (_ProcessRunner(returncode=0), None, True),
        (_ProcessRunner(returncode=7), "curl exited with code 7.", True),
        (
            _ProcessRunner(error=subprocess.TimeoutExpired(("curl",), 10)),
            "curl exceeded its bounded timeout.",
            True,
        ),
        (
            _ProcessRunner(error=RuntimeError("private argv must not escape")),
            "curl execution failed unexpectedly.",
            False,
        ),
    ],
)
def test_curl_releases_concurrency_on_every_runner_outcome(
    tmp_path: Path,
    process: _ProcessRunner,
    expected_error: str | None,
    started: bool,
) -> None:
    clock = _FakeTime()
    executor = _executor(clock)
    result = run_bug_bounty_curl(
        _curl_plan(tmp_path), executor, SafeSubprocessRunner(process)
    )

    expected = (
        "curl did not produce every expected artefact."
        if expected_error is None
        else expected_error
    )
    assert result.error == expected
    assert result.started is started
    executor.request("https://example.test/after-failure")
    assert executor.total_request_attempts == 2


def test_curl_429_sets_shared_terminal_state_without_long_sleep(
    tmp_path: Path,
) -> None:
    plan = _curl_plan(tmp_path)
    Path(plan.expected_artefacts[1]).write_text(
        "HTTP/1.1 429 Too Many Requests\nRetry-After: 7\n",
        encoding="utf-8",
    )
    executor = _executor(_FakeTime())

    with pytest.raises(HTTPRateRejected, match="Retry-After: 7"):
        run_bug_bounty_curl(
            plan,
            executor,
            SafeSubprocessRunner(_ProcessRunner(stdout="429")),
        )
    with pytest.raises(HTTPRateRejected):
        executor.request("https://example.test/stopped")
    assert executor.total_request_attempts == 1


def test_queued_external_permit_observes_close_and_does_not_run(
    tmp_path: Path,
) -> None:
    executor = _executor(_FakeTime())
    executor.close()
    process = _ProcessRunner()

    with pytest.raises(HTTPExecutorClosed):
        run_bug_bounty_curl(
            _curl_plan(tmp_path), executor, SafeSubprocessRunner(process)
        )

    assert process.calls == []
    assert executor.total_request_attempts == 0


@pytest.mark.parametrize("terminal", ["close", "429"])
def test_queued_curl_permit_is_interrupted_before_a_second_process(
    tmp_path: Path,
    terminal: str,
) -> None:
    clock = _GateTime()
    executor = InternalHTTPExecutor(
        _configuration(concurrency=2),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    process = _BlockingFirstProcess(first_status="429" if terminal == "429" else "200")
    runner = SafeSubprocessRunner(process)
    plan = _curl_plan(tmp_path)
    errors: list[Exception] = []

    def run_curl() -> None:
        try:
            run_bug_bounty_curl(plan, executor, runner)
        except Exception as exc:  # noqa: BLE001 - asserts typed terminal state
            errors.append(exc)

    first = threading.Thread(target=run_curl)
    second = threading.Thread(target=run_curl)
    first.start()
    assert process.first_entered.wait(timeout=1)
    second.start()
    assert clock.sleep_entered.wait(timeout=1)
    if terminal == "close":
        executor.close()
    process.release_first.set()
    first.join(timeout=2)
    clock.release_sleep.set()
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert process.calls == 1
    assert executor.total_request_attempts == 1
    expected_type = HTTPExecutorClosed if terminal == "close" else HTTPRateRejected
    assert any(isinstance(error, expected_type) for error in errors)


def test_curl_plan_applies_identity_protocol_and_no_redirects(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    private = plan.private_argv

    assert private[:7] == (
        "curl",
        "--disable",
        "--globoff",
        "--silent",
        "--show-error",
        "--proto",
        "=http,https",
    )
    assert private[private.index("--max-redirs") + 1] == "0"
    assert "-L" not in private
    assert "--location" not in private
    assert private[private.index("--noproxy") + 1] == "*"
    assert private[private.index("--user-agent") + 1] == USER_AGENT_SECRET
    assert f"X-Researcher-ID: {HEADER_SECRET}" in private
    assert USER_AGENT_SECRET not in repr(plan)
    assert HEADER_SECRET not in repr(plan)
    assert USER_AGENT_SECRET not in " ".join(plan.redacted_argv)
    assert HEADER_SECRET not in " ".join(plan.redacted_argv)
    assert "X-Researcher-ID: configured" in plan.redacted_argv


def test_curl_plan_uses_versioned_builtin_user_agent_when_custom_is_absent(
    tmp_path: Path,
) -> None:
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        identification_requirement=IDENTIFICATION_NONE,
        updated_at="2026-07-28T10:00:00Z",
    )
    configuration = build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test/",),
    )
    plan = build_bug_bounty_curl_plan(
        url="https://example.test/",
        method="HEAD",
        output_file=tmp_path / "headers.txt",
        response_headers_file=tmp_path / "response.headers",
        timeout_seconds=10,
        configuration=configuration,
        capabilities=_capabilities("curl"),
        purpose="headers",
    )

    assert plan.private_argv[plan.private_argv.index("--user-agent") + 1] == built_in_user_agent()
    assert "BugSlyce/0.3" not in plan.private_argv


@pytest.mark.parametrize(
    ("help_text", "available", "method", "missing"),
    [
        (CURL_HELP.replace("--header", ""), True, "GET", "--header"),
        (CURL_HELP.replace("--head", ""), True, "HEAD", "--head"),
        (None, False, "GET", "unavailable"),
    ],
)
def test_required_curl_capability_failure_is_incompatible(
    tmp_path: Path,
    help_text: str | None,
    available: bool,
    method: str,
    missing: str,
) -> None:
    plan = build_bug_bounty_curl_plan(
        url="https://example.test/",
        method=method,
        output_file=tmp_path / "output",
        response_headers_file=tmp_path / "headers",
        timeout_seconds=10,
        configuration=_configuration(),
        capabilities=assess_tool_capabilities("curl", help_text, available=available),
        purpose="capability_test",
    )

    assert plan.compatibility_status == COMPONENT_INCOMPATIBLE
    assert missing in plan.reason


@pytest.mark.parametrize("scheme", ["ftp", "file", "data", "javascript"])
def test_curl_plan_rejects_non_http_protocols(tmp_path: Path, scheme: str) -> None:
    with pytest.raises(ValueError, match="approved HTTP origin"):
        _curl_plan(tmp_path, url=f"{scheme}://example.test/value")


def test_curl_identity_collision_is_refused_without_secret_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="effective identity") as caught:
        _curl_plan(
            tmp_path,
            additional_headers=(("X-Researcher-ID", "other-private-value"),),
        )

    assert "other-private-value" not in str(caught.value)


def test_curl_redirect_resolution_is_shared_and_same_origin_only() -> None:
    configuration = _configuration()

    assert resolve_bug_bounty_curl_redirect(
        "https://example.test/start", "/next", configuration
    ) == "https://example.test/next"
    with pytest.raises(HTTPRedirectRefused, match="origin_not_approved"):
        resolve_bug_bounty_curl_redirect(
            "https://example.test/start",
            "https://other.test/next",
            configuration,
        )
    with pytest.raises(HTTPRedirectRefused, match="https_downgrade"):
        resolve_bug_bounty_curl_redirect(
            "https://example.test/start",
            "http://example.test/next",
            configuration,
        )


def test_explicit_curl_redirect_hop_gets_a_second_shared_permit(tmp_path: Path) -> None:
    clock = _FakeTime()
    executor = _executor(clock)
    process = _ProcessRunner(clock, stdout="302")
    first = _curl_plan(tmp_path, url="https://example.test/start")
    destination = resolve_bug_bounty_curl_redirect(
        "https://example.test/start", "/next", _configuration()
    )
    second = _curl_plan(tmp_path, url=destination)

    run_bug_bounty_curl(first, executor, SafeSubprocessRunner(process))
    process.stdout = "200"
    run_bug_bounty_curl(second, executor, SafeSubprocessRunner(process))

    assert process.starts == [Decimal("0"), Decimal("0.5")]
    assert executor.total_request_attempts == 2


def test_curl_redirect_chain_refuses_loops_and_hop_overflow() -> None:
    configuration = _configuration()
    chain = begin_curl_redirect_chain("https://example.test/start", configuration)
    chain = advance_curl_redirect_chain(chain, "/one", configuration)

    with pytest.raises(HTTPRedirectRefused, match="redirect_loop"):
        advance_curl_redirect_chain(chain, "/start", configuration)

    limited = type(configuration)(
        maximum_request_starts_per_second=configuration.maximum_request_starts_per_second,
        maximum_concurrent_requests=configuration.maximum_concurrent_requests,
        user_agent=configuration.user_agent,
        identification_headers=configuration.identification_headers,
        approved_origins=configuration.approved_origins,
        maximum_redirect_hops=1,
    )
    limited_chain = begin_curl_redirect_chain(
        "https://example.test/start", limited
    )
    limited_chain = advance_curl_redirect_chain(limited_chain, "/one", limited)
    with pytest.raises(HTTPRedirectRefused, match="redirect_hop_limit"):
        advance_curl_redirect_chain(limited_chain, "/two", limited)


def test_subprocess_diagnostics_redact_identity_values(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    process = _ProcessRunner(
        stdout=f"reflected {HEADER_SECRET}",
        stderr=f"argv included {USER_AGENT_SECRET}",
    )

    result = SafeSubprocessRunner(process).run(plan)

    assert HEADER_SECRET not in result.stdout
    assert USER_AGENT_SECRET not in result.stderr
    assert "configured value redacted" in result.stdout
    assert "configured value redacted" in result.stderr
    assert HEADER_SECRET not in repr(result)


def test_subprocess_diagnostics_omit_unicode_controls(tmp_path: Path) -> None:
    result = SafeSubprocessRunner(
        _ProcessRunner(stdout="safe\u202ehidden", stderr="value\ud800")
    ).run(_curl_plan(tmp_path))

    assert "\u202e" not in result.stdout
    assert "\ud800" not in result.stderr
    assert "unsafe control omitted" in result.stdout


def test_external_output_artefacts_redact_exact_identity_values(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    content = f"target reflected {HEADER_SECRET} and {USER_AGENT_SECRET}"

    SafeSubprocessRunner(
        _ArtefactWritingProcess(plan.expected_artefacts, content)
    ).run(plan)

    combined = b"".join(Path(path).read_bytes() for path in plan.expected_artefacts)
    assert HEADER_SECRET.encode() not in combined
    assert USER_AGENT_SECRET.encode() not in combined
    assert b"configured value redacted" in combined


def test_strict_curl_disables_default_configuration_first(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)

    assert plan.private_argv[:2] == ("curl", "--disable")


def test_strict_nmap_disables_dns_resolution(tmp_path: Path) -> None:
    plan = build_bug_bounty_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap.txt",
        policy=_policy(),
        capabilities=_capabilities("nmap"),
    )

    assert "-n" in plan.private_argv


@pytest.mark.parametrize(
    "origin",
    [
        f"https://{HEADER_SECRET}@example.test/",
        f"https://operator:{HEADER_SECRET}@example.test/",
    ],
)
def test_gobuster_rejects_userinfo_in_root_origin(tmp_path: Path, origin: str) -> None:
    with pytest.raises(ValueError, match="approved root"):
        build_bug_bounty_gobuster_plan(
            origin=origin,
            wordlist=_wordlist(tmp_path),
            output_file=tmp_path / "gobuster.txt",
            timeout_seconds=10,
            configuration=_configuration(),
            capabilities=_capabilities("gobuster"),
        )


def test_gobuster_process_timeout_covers_bounded_delay_schedule(tmp_path: Path) -> None:
    wordlist = tmp_path / "deep-sized.txt"
    wordlist.write_text("route\n" * 1753, encoding="utf-8")
    plan = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=wordlist,
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
        configuration=_configuration(rate="2"),
        capabilities=_capabilities("gobuster"),
    )

    assert plan.timeout_seconds >= 877


class _InterruptingArtefactProcess(_ArtefactWritingProcess):
    def run(self, argv, timeout_seconds, environment):
        for value in self.paths:
            Path(value).write_text(self.content, encoding="utf-8")
        raise KeyboardInterrupt()


class _TimeoutArtefactProcess(_ArtefactWritingProcess):
    def run(self, argv, timeout_seconds, environment):
        for value in self.paths:
            Path(value).write_text(self.content, encoding="utf-8")
        raise subprocess.TimeoutExpired(("curl",), timeout_seconds)


def test_keyboard_interrupt_still_redacts_produced_artefacts(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)

    with pytest.raises(KeyboardInterrupt):
        SafeSubprocessRunner(
            _InterruptingArtefactProcess(
                plan.expected_artefacts,
                f"reflected {HEADER_SECRET} {USER_AGENT_SECRET}",
            )
        ).run(plan)

    combined = b"".join(Path(path).read_bytes() for path in plan.expected_artefacts)
    assert HEADER_SECRET.encode() not in combined
    assert USER_AGENT_SECRET.encode() not in combined


def test_success_without_expected_artefacts_is_not_complete_success(tmp_path: Path) -> None:
    result = SafeSubprocessRunner(_ProcessRunner()).run(_curl_plan(tmp_path))

    assert result.error is not None


def test_strict_curl_capability_requires_disable_support(tmp_path: Path) -> None:
    capabilities = assess_tool_capabilities(
        "curl", CURL_HELP.replace("--disable", ""), available=True
    )
    plan = build_bug_bounty_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "response.headers",
        timeout_seconds=10,
        configuration=_configuration(),
        capabilities=capabilities,
        purpose="test_exchange",
    )

    assert plan.compatibility_status == COMPONENT_INCOMPATIBLE
    assert "--disable" in plan.reason


def test_preflight_refuses_required_curl_without_disable_support() -> None:
    preflight = _preflight(
        curl=assess_tool_capabilities(
            "curl", CURL_HELP.replace("--disable", ""), available=True
        )
    )

    curl = next(item for item in preflight.components if item.component == "curl")
    assert curl.status == COMPONENT_INCOMPATIBLE
    assert "--disable" in curl.reason


def test_nmap_capability_requires_dns_disable_support(tmp_path: Path) -> None:
    plan = build_bug_bounty_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap.txt",
        policy=_policy(),
        capabilities=assess_tool_capabilities("nmap", NMAP_HELP.replace("-n", "")),
    )

    assert plan.compatibility_status == COMPONENT_INCOMPATIBLE
    assert "-n" in plan.reason


@pytest.mark.parametrize("forbidden", ["--config", "-K", "--next", "--parallel", "--retry", "--location", "-L"])
def test_bound_runtime_rejects_forged_curl_transfer_options(
    tmp_path: Path, forbidden: str
) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "response.headers",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    forged = replace(plan, _private_argv=(*plan.private_argv[:-2], forbidden, "--", plan.private_argv[-1]))
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_bound_runtime_refuses_cross_policy_nmap_plan_before_runner(tmp_path: Path) -> None:
    clock = _FakeTime()
    conservative = _session(clock)
    full = _session(
        _FakeTime(),
        policy=_policy(tcp_mode=TCP_FULL, tcp_confirmed=CONFIRMED),
    )
    plan = full.build_nmap_plan(target="example.test", output_file=tmp_path / "full.txt")
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(conservative, SafeSubprocessRunner(process)).run(plan)

    assert process.calls == []


def test_session_rejects_mismatched_http_executor_before_runner() -> None:
    with pytest.raises(ValueError, match="does not match"):
        BugBountyExternalEnforcementSession(
            policy=_policy(),
            approved_origins=("https://example.test/",),
            profile=DEEP_RECON_PROFILE,
            curl_capabilities=_capabilities("curl"),
            gobuster_capabilities=_capabilities("gobuster"),
            nmap_capabilities=_capabilities("nmap"),
            http_executor=InternalHTTPExecutor(
                _configuration(rate="2.5"), transport=_Transport(_FakeTime())
            ),
        )


def test_bound_runtime_refuses_forged_nmap_service_detection_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(target="example.test", output_file=tmp_path / "nmap.txt")
    forged = replace(plan, _private_argv=("nmap", "-sV", *plan.private_argv[1:]))
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_bound_runtime_refuses_omitted_component_before_runner(tmp_path: Path) -> None:
    session = _session(
        _FakeTime(), gobuster=assess_tool_capabilities("gobuster", None, available=False)
    )
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="not bound|not approved"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls == []


def test_sealed_replaced_curl_identity_value_is_refused_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    altered = "altered-header-value-8431"
    forged = replace(
        plan,
        _private_argv=tuple(
            f"X-Researcher-ID: {altered}"
            if value == f"X-Researcher-ID: {HEADER_SECRET}"
            else value
            for value in plan.private_argv
        ),
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan") as caught:
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert forged._provenance_token is plan._provenance_token
    assert process.calls == []
    assert altered not in str(caught.value)


def test_sealed_duplicate_curl_user_agent_is_refused_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    separator = plan.private_argv.index("--")
    altered = "altered-agent-8431"
    forged = replace(
        plan,
        _private_argv=(
            *plan.private_argv[:separator],
            "--user-agent",
            altered,
            *plan.private_argv[separator:],
        ),
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_sealed_replaced_gobuster_identity_value_is_refused_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    altered = "altered-header-value-8431"
    forged = replace(
        plan,
        _private_argv=tuple(
            f"X-Researcher-ID: {altered}"
            if value == f"X-Researcher-ID: {HEADER_SECRET}"
            else value
            for value in plan.private_argv
        ),
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_sealed_replaced_nmap_retries_is_refused_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(target="example.test", output_file=tmp_path / "nmap.txt")
    retries = plan.private_argv.index("--max-retries") + 1
    argv = list(plan.private_argv)
    argv[retries] = "99"
    forged = replace(plan, _private_argv=tuple(argv))
    process = _ProcessRunner(stdout="")

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_sealed_replaced_expected_artefacts_cannot_bypass_redaction(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    body = tmp_path / "body.html"
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=body,
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    forged = replace(plan, expected_artefacts=())
    process = _ArtefactWritingProcess((str(body),), HEADER_SECRET)

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert not body.exists()
    assert process.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"process_timeout_seconds": 99_999},
        {"redacted_argv": ("identity-leak-8431",)},
        {"_redaction_values": ()},
        {"purpose": "altered-purpose"},
        {"request_timeout_seconds": 999},
    ],
)
def test_sealed_curl_metadata_replacements_are_refused_before_runner(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(
            replace(plan, **changes)
        )

    assert process.calls == []


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--threads", "2"),
        ("--delay", "1ns"),
        ("--timeout", "999s"),
        ("--useragent", "altered-agent-8431"),
        ("--output", "/tmp/altered-gobuster.txt"),
        ("--wordlist", "/tmp/altered-wordlist.txt"),
    ],
)
def test_sealed_gobuster_control_replacements_are_refused_before_runner(
    tmp_path: Path, option: str, value: str
) -> None:
    session = _session(_FakeTime())
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    argv = list(plan.private_argv)
    argv[argv.index(option) + 1] = value
    forged = replace(plan, _private_argv=tuple(argv))
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(forged)

    assert process.calls == []


def test_sealed_gobuster_expected_artefact_is_refused_before_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    process = _ProcessRunner()

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(
            replace(plan, expected_artefacts=("/tmp/altered-gobuster.txt",))
        )

    assert process.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"process_timeout_seconds": 99_999},
        {"expected_artefacts": ("/tmp/unrelated-nmap.txt",)},
    ],
)
def test_sealed_nmap_metadata_replacements_are_refused_before_runner(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(target="example.test", output_file=tmp_path / "nmap.txt")
    process = _ProcessRunner(stdout="")

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(
            replace(plan, **changes)
        )

    assert process.calls == []


def test_sealed_nmap_output_argument_replacement_is_refused_before_runner(
    tmp_path: Path,
) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(target="example.test", output_file=tmp_path / "nmap.txt")
    argv = list(plan.private_argv)
    argv[argv.index("-oN") + 1] = "/tmp/altered-nmap.txt"
    process = _ProcessRunner(stdout="")

    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(
            replace(plan, _private_argv=tuple(argv))
        )

    assert process.calls == []


def test_sealed_runtime_refuses_copied_reconstructed_and_manual_plans(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    reconstructed = ExternalCommandPlan(
        tool=plan.tool,
        purpose=plan.purpose,
        compatibility_status=plan.compatibility_status,
        redacted_argv=plan.redacted_argv,
        process_timeout_seconds=plan.process_timeout_seconds,
        expected_artefacts=plan.expected_artefacts,
        request_timeout_seconds=plan.request_timeout_seconds,
        _private_argv=plan.private_argv,
        _redaction_values=plan._redaction_values,
        _provenance_token=plan._provenance_token,
    )
    process = _ProcessRunner()
    runtime = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process))

    manual = ExternalCommandPlan(
        tool=plan.tool,
        purpose=plan.purpose,
        compatibility_status=plan.compatibility_status,
        redacted_argv=plan.redacted_argv,
        process_timeout_seconds=plan.process_timeout_seconds,
        expected_artefacts=plan.expected_artefacts,
        request_timeout_seconds=plan.request_timeout_seconds,
        _private_argv=plan.private_argv,
        _redaction_values=plan._redaction_values,
    )

    for forged in (replace(plan), reconstructed, manual):
        with pytest.raises(ValueError, match="registered session plan"):
            runtime.run(forged)

    assert process.calls == []


def test_standalone_plan_remains_testable_but_has_no_session_runtime_authority(
    tmp_path: Path,
) -> None:
    session = _session(_FakeTime())
    standalone = _curl_plan(tmp_path)
    process = _ProcessRunner()

    assert standalone.private_argv[:2] == ("curl", "--disable")
    with pytest.raises(ValueError, match="registered session plan"):
        BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(
            standalone
        )

    assert process.calls == []


def test_exact_session_plan_runs_with_existing_permit_accounting(tmp_path: Path) -> None:
    clock = _FakeTime()
    session = _session(clock)
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    process = _ArtefactWritingProcess(plan.expected_artefacts, HEADER_SECRET)

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls
    assert session.http_executor.total_request_attempts == 1
    assert result.produced_artefacts == plan.expected_artefacts
    assert HEADER_SECRET not in b"".join(Path(path).read_bytes() for path in plan.expected_artefacts).decode()


def test_exact_session_gobuster_plan_reaches_fake_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    process = _ArtefactWritingProcess(plan.expected_artefacts, "gobuster output")

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls
    assert result.produced_artefacts == plan.expected_artefacts


def test_exact_session_curl_functional_header_reaches_fake_runner(
    tmp_path: Path,
) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
        additional_headers=(("Accept", "application/json"),),
    )
    process = _ArtefactWritingProcess(plan.expected_artefacts, "curl output")

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls
    assert result.produced_artefacts == plan.expected_artefacts


def test_strict_curl_glob_url_has_explicit_glob_safety_controls(
    tmp_path: Path,
) -> None:
    plan = _curl_plan(tmp_path, url="https://example.test/item{1,2}")

    assert plan.private_argv[:3] == ("curl", "--disable", "--globoff")
    assert plan.private_argv.count("--globoff") == 1
    assert plan.private_argv[plan.private_argv.index("--noproxy") + 1] == "*"


def test_strict_curl_accepts_bracket_url_with_globbing_disabled(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path, url="https://example.test/item[1-2]")

    assert plan.private_argv[-1] == "https://example.test/item[1-2]"
    assert "--globoff" in plan.private_argv


@pytest.mark.parametrize(
    "replacement",
    [(), ("--globoff", "--globoff"), ("--no-globoff",)],
)
def test_strict_curl_validator_requires_exact_globbing_controls(
    tmp_path: Path,
    replacement: tuple[str, ...],
) -> None:
    plan = _curl_plan(tmp_path)
    argv = list(plan.private_argv)
    globoff_index = argv.index("--globoff")
    argv[globoff_index : globoff_index + 1] = replacement

    with pytest.raises(ValueError):
        _validate_strict_curl_argv(tuple(argv), _configuration())


def test_curl_capability_requires_globoff_and_noproxy() -> None:
    for option in ("--globoff", "--noproxy"):
        plan = build_bug_bounty_curl_plan(
            url="https://example.test/value",
            method="GET",
            output_file=Path("/tmp/unused-body.html"),
            response_headers_file=Path("/tmp/unused-headers.txt"),
            timeout_seconds=10,
            configuration=_configuration(),
            capabilities=assess_tool_capabilities("curl", CURL_HELP.replace(option, "")),
            purpose="test_exchange",
        )
        assert plan.compatibility_status == COMPONENT_INCOMPATIBLE


def test_strict_curl_proxy_environment_is_explicit_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(_FakeTime())
    plan = session.build_curl_plan(
        url="https://example.test/item{1,2}",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
    )
    sentinel = "http://proxy-sentinel.invalid:8431"
    for name in ("http_proxy", "HTTPS_PROXY", "AlL_PrOxY", "NO_PROXY"):
        monkeypatch.setenv(name, sentinel)
    captured: dict[str, object] = {}

    def fake_subprocess_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="200", stderr="")

    monkeypatch.setattr("bugslyce.recon.external_enforcement.subprocess.run", fake_subprocess_run)

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner()).run(plan)

    environment = captured["kwargs"]["env"]
    assert environment["NO_PROXY"] == "*"
    assert environment["no_proxy"] == "*"
    assert "PATH" in environment
    assert all(name.casefold() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} for name in environment if name not in {"NO_PROXY", "no_proxy"})
    assert sentinel not in repr(environment)
    assert sentinel not in repr(result)


def test_strict_gobuster_proxy_environment_is_explicit_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(_FakeTime())
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=10,
    )
    sentinel = "http://proxy-sentinel.invalid:8431"
    for name in ("HTTP_PROXY", "https_proxy", "aLl_PrOxY", "No_PrOxY"):
        monkeypatch.setenv(name, sentinel)
    captured: dict[str, object] = {}

    def fake_subprocess_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="200", stderr="")

    monkeypatch.setattr("bugslyce.recon.external_enforcement.subprocess.run", fake_subprocess_run)

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner()).run(plan)

    environment = captured["kwargs"]["env"]
    assert environment["NO_PROXY"] == "*"
    assert environment["no_proxy"] == "*"
    assert "PATH" in environment
    assert all(name.casefold() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} for name in environment if name not in {"NO_PROXY", "no_proxy"})
    assert sentinel not in repr(environment)
    assert sentinel not in repr(result)


def test_injected_runner_receives_immutable_controlled_environment(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap.txt",
    )
    runner = _EnvironmentObservingRunner()

    runtime = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(runner))
    result = runtime.run(plan)

    assert runner.environments
    assert result.started is True
    with pytest.raises(TypeError):
        runner.environments[0]["HTTP_PROXY"] = "proxy-sentinel-8431"
    assert "proxy-sentinel-8431" not in repr(runner.environments[0])
    runtime.run(plan)
    assert len(runner.environments) == 2
    assert runner.environments[0] is not runner.environments[1]


def test_gobuster_rounding_uses_the_exact_mathematical_ceiling() -> None:
    assert gobuster_delay_for_rate(
        Decimal("999999999.9999999999999999999999999999")
    ) == "2ns"
    assert _gobuster_process_timeout_seconds(
        1,
        Decimal("0.9999999999999999999999999999999999"),
        1,
    ) == 32


def test_compact_nmap_help_is_compatible() -> None:
    capabilities = assess_tool_capabilities("nmap", COMPACT_NMAP_HELP)

    assert capabilities.supports(
        frozenset({"-sT", "-Pn", "-n", "-p", "--max-rate", "--max-retries", "-oN"})
    )


def test_exact_session_nmap_plan_reaches_fake_runner(tmp_path: Path) -> None:
    session = _session(_FakeTime())
    plan = session.build_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap.txt",
    )
    process = _ArtefactWritingProcess(plan.expected_artefacts, "nmap output")

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls
    assert result.produced_artefacts == plan.expected_artefacts


def test_exact_session_curl_multiple_functional_headers_remain_redacted(
    tmp_path: Path,
) -> None:
    session = _session(_FakeTime())
    accept_value = "application/json"
    requested_with = "bugslyce-local-review"
    plan = session.build_curl_plan(
        url="https://example.test/value",
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "headers.txt",
        timeout_seconds=10,
        purpose="test_exchange",
        additional_headers=(
            ("Accept", accept_value),
            ("X-Requested-With", requested_with),
        ),
    )
    process = _ArtefactWritingProcess(plan.expected_artefacts, "curl output")

    result = BugBountyExternalToolRuntime(session, SafeSubprocessRunner(process)).run(plan)

    assert process.calls
    assert result.produced_artefacts == plan.expected_artefacts
    assert accept_value not in repr(plan)
    assert requested_with not in repr(plan)
    assert accept_value not in plan.redacted_argv
    assert requested_with not in plan.redacted_argv
    assert "Accept: configured" in plan.redacted_argv
    assert "X-Requested-With: configured" in plan.redacted_argv


@pytest.mark.parametrize(
    "additional_headers",
    [
        (("x-researcher-id", "collision-8431"),),
        (("User-Agent", "collision-8431"),),
        (("Bad Header", "value-8431"),),
    ],
)
def test_functional_curl_headers_reject_collisions_and_malformed_names(
    tmp_path: Path,
    additional_headers: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(ValueError) as caught:
        _ = _curl_plan(tmp_path, additional_headers=additional_headers)

    assert "collision-8431" not in str(caught.value)
    assert "value-8431" not in str(caught.value)


@pytest.mark.parametrize(
    ("rate", "expected"),
    [
        (Decimal("2"), "500000000ns"),
        (Decimal("2.5"), "400000000ns"),
        (Decimal("2e-10"), "5000000000000000000ns"),
    ],
)
def test_gobuster_exact_rounding_keeps_ordinary_and_go_boundary_rates(
    rate: Decimal,
    expected: str,
) -> None:
    assert gobuster_delay_for_rate(rate) == expected


def test_gobuster_rate_beyond_go_duration_boundary_is_refused() -> None:
    with pytest.raises(ValueError, match="representable Go duration"):
        gobuster_delay_for_rate(Decimal("1e-10"))


@pytest.mark.parametrize(
    "help_text",
    [
        "-nonsense -Pnx -ports --max-rates --max-retries-count -oName",
        COMPACT_NMAP_HELP.replace("-n/-R", "-R"),
        COMPACT_NMAP_HELP.replace("-sS/sT/sA/sW/sM", "-sS/sA/sW/sM"),
        COMPACT_NMAP_HELP.replace("-oN/-oX/-oS/-oG", "-oX/-oS/-oG"),
    ],
)
def test_nmap_help_parser_rejects_near_matches_and_missing_required_options(
    help_text: str,
) -> None:
    capabilities = assess_tool_capabilities("nmap", help_text)

    assert capabilities.supports(
        frozenset({"-sT", "-Pn", "-n", "-p", "--max-rate", "--max-retries", "-oN"})
    ) is False


def test_compact_nmap_help_allows_complete_preflight() -> None:
    preflight = _preflight(nmap=assess_tool_capabilities("nmap", COMPACT_NMAP_HELP))

    assert preflight.ready is True


def test_gobuster_packaged_wordlists_fit_conservative_process_deadline(tmp_path: Path) -> None:
    standard = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=STANDARD_BOUNDED_CORE_WORDLIST,
        output_file=tmp_path / "standard.txt",
        timeout_seconds=10,
        configuration=_configuration(),
        capabilities=_capabilities("gobuster"),
    )
    deep = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=DEEP_BOUNDED_CORE_WORDLIST,
        output_file=tmp_path / "deep.txt",
        timeout_seconds=10,
        configuration=_configuration(),
        capabilities=_capabilities("gobuster"),
    )

    assert standard.request_timeout_seconds == 10
    assert standard.process_timeout_seconds >= 140
    assert deep.request_timeout_seconds == 10
    assert deep.process_timeout_seconds >= 907


class _SystemExitArtefactProcess(_InterruptingArtefactProcess):
    def run(self, argv, timeout_seconds, environment):
        for value in self.paths:
            Path(value).write_text(self.content, encoding="utf-8")
        raise SystemExit(7)


def test_system_exit_still_redacts_produced_artefacts(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)

    with pytest.raises(SystemExit):
        SafeSubprocessRunner(
            _SystemExitArtefactProcess(plan.expected_artefacts, HEADER_SECRET)
        ).run(plan)

    assert all(HEADER_SECRET not in Path(path).read_text(encoding="utf-8") for path in plan.expected_artefacts)


def test_timeout_finalises_partial_artefacts_without_identity_leak(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    result = SafeSubprocessRunner(
        _TimeoutArtefactProcess(
            plan.expected_artefacts,
            f"partial {HEADER_SECRET} {USER_AGENT_SECRET}",
        )
    ).run(plan)

    assert result.timed_out is True
    assert set(result.produced_artefacts) == set(plan.expected_artefacts)
    combined = b"".join(Path(path).read_bytes() for path in plan.expected_artefacts)
    assert HEADER_SECRET.encode() not in combined
    assert USER_AGENT_SECRET.encode() not in combined


def test_runner_reports_only_fresh_or_modified_expected_artefacts(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    stale = Path(plan.expected_artefacts[0])
    stale.write_text("operator-owned", encoding="utf-8")
    response_headers = Path(plan.expected_artefacts[1])

    result = SafeSubprocessRunner(
        _ArtefactWritingProcess((str(response_headers),), "HTTP/1.1 200 OK")
    ).run(plan)

    assert result.produced_artefacts == (str(response_headers),)
    assert result.error == "curl did not produce every expected artefact."
    assert stale.read_text(encoding="utf-8") == "operator-owned"


def test_failed_process_start_does_not_modify_existing_output(tmp_path: Path) -> None:
    plan = _curl_plan(tmp_path)
    output = Path(plan.expected_artefacts[0])
    output.write_text("existing operator artefact", encoding="utf-8")
    original = output.read_bytes()

    result = SafeSubprocessRunner(_ProcessRunner(error=FileNotFoundError())).run(plan)

    assert result.started is False
    assert output.read_bytes() == original


@pytest.mark.parametrize(
    ("rate", "expected"),
    [("2", "500000000ns"), ("2.5", "400000000ns"), ("1e1000", "1ns")],
)
def test_gobuster_delay_rounds_conservatively(rate: str, expected: str) -> None:
    assert gobuster_delay_for_rate(Decimal(rate)) == expected


def test_gobuster_unrepresentable_delay_is_omitted(tmp_path: Path) -> None:
    plan = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=30,
        configuration=_configuration(rate="1e-1000"),
        capabilities=_capabilities("gobuster"),
    )

    assert plan.compatibility_status == COMPONENT_OMITTED
    assert "representable Go duration" in plan.reason
    with pytest.raises(ValueError, match="not executable"):
        _ = plan.private_argv


def test_gobuster_plan_is_one_thread_identified_delayed_and_no_redirect(
    tmp_path: Path,
) -> None:
    plan = _gobuster_plan(tmp_path, rate="2.5")
    private = plan.private_argv

    assert private[private.index("--threads") + 1] == "1"
    assert private[private.index("--delay") + 1] == "400000000ns"
    assert private[private.index("--useragent") + 1] == USER_AGENT_SECRET
    assert f"X-Researcher-ID: {HEADER_SECRET}" in private
    assert "--follow-redirect" not in private
    assert "-r" not in private
    assert HEADER_SECRET not in repr(plan)


@pytest.mark.parametrize(
    ("help_text", "available", "reason_fragment"),
    [
        (GOBUSTER_HELP.replace("--delay", ""), True, "--delay"),
        (GOBUSTER_HELP.replace("stringArray", "string"), True, "repeatable"),
        (GOBUSTER_HELP.replace("(default false)", ""), True, "redirect"),
        (GOBUSTER_HELP.replace("--useragent", ""), True, "--useragent"),
        ("not useful", True, "required capabilities"),
        (None, False, "unavailable"),
    ],
)
def test_incompatible_gobuster_is_safely_omitted(
    tmp_path: Path,
    help_text: str | None,
    available: bool,
    reason_fragment: str,
) -> None:
    capabilities = assess_tool_capabilities(
        "gobuster", help_text, available=available
    )
    plan = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=30,
        configuration=_configuration(),
        capabilities=capabilities,
    )

    assert plan.compatibility_status == COMPONENT_OMITTED
    assert reason_fragment.casefold() in plan.reason.casefold()


def test_gobuster_reserves_first_start_and_adds_post_tool_barrier(tmp_path: Path) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = _executor(clock, transport=transport)
    process = _ProcessRunner(clock, stdout="")

    executor.request("https://example.test/before")
    run_bug_bounty_gobuster(
        _gobuster_plan(tmp_path), executor, SafeSubprocessRunner(process)
    )
    executor.request("https://example.test/after")

    assert process.starts == [Decimal("0.5")]
    assert transport.starts == [Decimal("0"), Decimal("1.0")]
    assert executor.total_request_attempts == 3


def test_gobuster_runs_exclusively_against_internal_http(tmp_path: Path) -> None:
    clock = _FakeTime()
    transport = _Transport(clock)
    executor = InternalHTTPExecutor(
        _configuration(concurrency=2),
        transport=transport,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    process = _BlockingFirstProcess()
    errors: list[Exception] = []

    def run_gobuster() -> None:
        try:
            run_bug_bounty_gobuster(
                _gobuster_plan(tmp_path),
                executor,
                SafeSubprocessRunner(process),
            )
        except Exception as exc:  # noqa: BLE001 - thread assertion collection
            errors.append(exc)

    def run_internal() -> None:
        try:
            executor.request("https://example.test/after-gobuster")
        except Exception as exc:  # noqa: BLE001 - thread assertion collection
            errors.append(exc)

    gobuster = threading.Thread(target=run_gobuster)
    internal = threading.Thread(target=run_internal)
    gobuster.start()
    assert process.first_entered.wait(timeout=1)
    internal.start()
    assert transport.starts == []
    process.release_first.set()
    gobuster.join(timeout=2)
    internal.join(timeout=2)

    assert not gobuster.is_alive()
    assert not internal.is_alive()
    assert errors == []
    assert transport.starts == [Decimal("0.5")]


@pytest.mark.parametrize(
    ("tcp_mode", "custom_ports", "confirmed", "expected_ports"),
    [
        (TCP_CONSERVATIVE, None, CONFIRMED, ",".join(map(str, BUG_BOUNTY_COMMON_WEB_PORTS))),
        (TCP_CUSTOM, "443,8080-8082", CONFIRMED, "443,8080-8082"),
        (TCP_FULL, None, CONFIRMED, "1-65535"),
    ],
)
def test_nmap_policy_modes_build_strict_tcp_only_plan(
    tmp_path: Path,
    tcp_mode: str,
    custom_ports: str | None,
    confirmed: str,
    expected_ports: str,
) -> None:
    policy = _policy(
        tcp_mode=tcp_mode,
        custom_ports=custom_ports,
        tcp_confirmed=confirmed,
    )
    plan = build_bug_bounty_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap-allports.txt",
        policy=policy,
        capabilities=_capabilities("nmap"),
    )
    argv = plan.private_argv

    assert argv[argv.index("-p") + 1] == expected_ports
    assert argv[argv.index("--max-rate") + 1] == str(MAXIMUM_NMAP_PACKET_RATE)
    assert int(argv[argv.index("--max-rate") + 1]) <= 50
    assert argv[argv.index("--max-retries") + 1] == "2"
    assert "-sT" in argv
    assert "-Pn" in argv
    assert not {
        "-sV",
        "-sC",
        "--script",
        "-A",
        "-O",
        "--traceroute",
        "-sU",
        "-T5",
        "--min-rate",
        "-p-",
    }.intersection(argv)
    assert plan.expected_artefacts == (str(tmp_path / "nmap-allports.txt"),)


def test_nmap_skip_requires_no_executable_or_process(tmp_path: Path) -> None:
    plan = build_bug_bounty_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap-allports.txt",
        policy=_policy(tcp_mode=TCP_SKIP),
        capabilities=assess_tool_capabilities("nmap", None, available=False),
    )

    assert plan.compatibility_status == COMPONENT_SUPPORTED
    assert "deliberately skipped" in plan.reason
    with pytest.raises(ValueError, match="not executable"):
        _ = plan.private_argv


def test_nmap_full_without_confirmation_is_refused_by_policy_builder(tmp_path: Path) -> None:
    policy = _policy(tcp_mode=TCP_FULL, tcp_confirmed=NOT_YET_CONFIRMED)

    with pytest.raises(ValueError, match="incomplete"):
        build_bug_bounty_nmap_plan(
            target="example.test",
            output_file=tmp_path / "nmap-allports.txt",
            policy=policy,
            capabilities=_capabilities("nmap"),
        )


def test_required_nmap_incompatibility_has_no_private_command(tmp_path: Path) -> None:
    plan = build_bug_bounty_nmap_plan(
        target="example.test",
        output_file=tmp_path / "nmap-allports.txt",
        policy=_policy(),
        capabilities=assess_tool_capabilities("nmap", "-sT -Pn", available=True),
    )

    assert plan.compatibility_status == COMPONENT_INCOMPATIBLE
    with pytest.raises(ValueError):
        _ = plan.private_argv


@pytest.mark.parametrize("target", ["-Pn", "bad_host", "2001:db8::1"])
def test_strict_nmap_rejects_option_like_malformed_or_unsupported_targets(
    tmp_path: Path,
    target: str,
) -> None:
    with pytest.raises(ValueError, match="Strict Nmap target"):
        build_bug_bounty_nmap_plan(
            target=target,
            output_file=tmp_path / "nmap-allports.txt",
            policy=_policy(),
            capabilities=_capabilities("nmap"),
        )


def test_complete_preflight_is_deterministic_and_secret_safe() -> None:
    preflight = _preflight()
    rendered = render_external_preflight(preflight)

    assert preflight.ready is True
    assert tuple(item.component for item in preflight.components) == (
        "internal_python_http",
        "curl",
        "gobuster",
        "nmap",
    )
    assert all(item.status == COMPONENT_SUPPORTED for item in preflight.components)
    assert preflight.selected_tcp_port_count == len(BUG_BOUNTY_COMMON_WEB_PORTS)
    assert "X-Researcher-ID" in rendered
    assert HEADER_SECRET not in rendered
    assert USER_AGENT_SECRET not in rendered
    assert "R0B3 controlled capture" in rendered


def test_optional_gobuster_omission_does_not_fail_preflight() -> None:
    preflight = _preflight(
        gobuster=assess_tool_capabilities("gobuster", None, available=False)
    )

    component = next(item for item in preflight.components if item.component == "gobuster")
    assert component.status == COMPONENT_OMITTED
    assert preflight.ready is True


@pytest.mark.parametrize("required_tool", ["curl", "nmap"])
def test_required_incompatibility_refuses_before_runner(required_tool: str) -> None:
    missing = assess_tool_capabilities(required_tool, None, available=False)
    kwargs = {required_tool: missing}
    preflight = _preflight(**kwargs)
    process = _ProcessRunner()

    assert preflight.ready is False
    with pytest.raises(ValueError, match="preflight refused"):
        BugBountyExternalEnforcementSession(
            policy=_policy(),
            approved_origins=("https://example.test/",),
            profile=DEEP_RECON_PROFILE,
            curl_capabilities=kwargs.get("curl", _capabilities("curl")),
            gobuster_capabilities=_capabilities("gobuster"),
            nmap_capabilities=kwargs.get("nmap", _capabilities("nmap")),
            http_executor=_executor(_FakeTime()),
        )
    assert process.calls == []


def test_capability_fixtures_are_parsed_without_executable_invocation() -> None:
    assert _capabilities("curl").supports(
        frozenset(
            {
                "--header",
                "--proto",
                "--max-redirs",
                "--user-agent",
            }
        )
    )
    assert _capabilities("gobuster").repeated_headers_supported is True
    assert _capabilities("nmap").available is True


def test_gobuster_382_bracketed_header_syntax_proves_repeatable_headers() -> None:
    capabilities = assess_tool_capabilities("gobuster", GOBUSTER_382_HELP)

    assert capabilities.repeated_headers_supported is True
    assert capabilities.redirect_following_opt_in is True
    assert capabilities.diagnostic == "compatible"


@pytest.mark.parametrize(
    "declaration",
    (
        "--headers value [ --headers value ]",
        "-H value [ -H value ]",
    ),
)
def test_gobuster_option_local_repeated_header_syntax_is_recognised(
    declaration: str,
) -> None:
    help_text = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        declaration,
    )

    assert assess_tool_capabilities(
        "gobuster", help_text
    ).repeated_headers_supported is True


def test_gobuster_single_header_or_unrelated_brackets_do_not_prove_repeatability() -> None:
    single_header = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--headers value",
    )
    unrelated_brackets = single_header + "\n--status-codes string [ --expanded ]\n"

    assert not assess_tool_capabilities(
        "gobuster", single_header
    ).repeated_headers_supported
    assert not assess_tool_capabilities(
        "gobuster", unrelated_brackets
    ).repeated_headers_supported


@pytest.mark.parametrize(
    "declaration",
    (
        "--headers value [ -h, --help ]",
        "-h value [ -h value ]",
    ),
)
def test_gobuster_lowercase_help_option_never_proves_repeatable_headers(
    declaration: str,
) -> None:
    help_text = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        declaration,
    ) + "\n-h, --help  help for dir\n"

    assert not assess_tool_capabilities(
        "gobuster", help_text
    ).repeated_headers_supported


def test_gobuster_header_local_string_array_forms_are_distinguished() -> None:
    header_long = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--headers stringArray",
    )
    header_short = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "-H stringArray",
    )
    unrelated_option = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--headers string --cookies stringArray",
    )
    unrelated_prose = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--headers value description stringArray for cookies",
    )

    assert assess_tool_capabilities(
        "gobuster", header_long
    ).repeated_headers_supported
    assert assess_tool_capabilities(
        "gobuster", header_short
    ).repeated_headers_supported
    assert not assess_tool_capabilities(
        "gobuster", unrelated_option
    ).repeated_headers_supported
    assert not assess_tool_capabilities(
        "gobuster", unrelated_prose
    ).repeated_headers_supported


def test_gobuster_missing_header_or_redirect_controls_remain_incompatible(
    tmp_path: Path,
) -> None:
    missing_headers = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--status-codes string",
    )
    missing_redirect = GOBUSTER_382_HELP.replace("(default false)", "")

    for help_text, reason in (
        (missing_headers, "--headers"),
        (missing_redirect, "redirect"),
    ):
        plan = build_bug_bounty_gobuster_plan(
            origin="https://example.test/",
            wordlist=_wordlist(tmp_path),
            output_file=tmp_path / "gobuster.txt",
            timeout_seconds=30,
            configuration=_configuration(),
            capabilities=assess_tool_capabilities("gobuster", help_text),
        )
        assert plan.compatibility_status == COMPONENT_OMITTED
        assert reason.casefold() in plan.reason.casefold()


def test_gobuster_382_session_builds_a_supported_redacted_two_header_plan(
    tmp_path: Path,
) -> None:
    second_header = "second-private-header-7284"
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="2",
        maximum_http_concurrency=1,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", HEADER_SECRET),
            IdentificationHeader("X-Programme-Handle", second_header),
        ),
        custom_user_agent=USER_AGENT_SECRET,
        updated_at="2026-07-28T10:00:00Z",
    )
    configuration = build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test/",),
    )
    session = BugBountyExternalEnforcementSession(
        policy=policy,
        approved_origins=("https://example.test/",),
        profile=DEEP_RECON_PROFILE,
        curl_capabilities=_capabilities("curl"),
        gobuster_capabilities=assess_tool_capabilities("gobuster", GOBUSTER_382_HELP),
        nmap_capabilities=_capabilities("nmap"),
        http_executor=InternalHTTPExecutor(
            configuration,
            transport=_Transport(_FakeTime()),
        ),
    )
    plan = session.build_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=30,
    )
    component = next(
        item for item in session.preflight.components if item.component == "gobuster"
    )

    assert plan.compatibility_status == COMPONENT_SUPPORTED
    assert plan.private_argv[plan.private_argv.index("--threads") + 1] == "1"
    assert plan.private_argv[plan.private_argv.index("--delay") + 1] == "500000000ns"
    assert plan.private_argv[plan.private_argv.index("--useragent") + 1] == USER_AGENT_SECRET
    assert [
        value
        for index, value in enumerate(plan.private_argv)
        if index and plan.private_argv[index - 1] == "--headers"
    ] == [
        f"X-Researcher-ID: {HEADER_SECRET}",
        f"X-Programme-Handle: {second_header}",
    ]
    assert "--follow-redirect" not in plan.private_argv
    assert HEADER_SECRET not in plan.redacted_argv
    assert second_header not in plan.redacted_argv
    assert USER_AGENT_SECRET not in plan.redacted_argv
    assert component.status == COMPONENT_SUPPORTED
    assert component.reason == GOBUSTER_STARTUP_DISCLOSURE
    assert GOBUSTER_STARTUP_DISCLOSURE in render_external_preflight(session.preflight)


def test_ambiguous_gobuster_header_help_is_safely_omitted(tmp_path: Path) -> None:
    ambiguous = GOBUSTER_382_HELP.replace(
        "--headers value, -H value [ --headers value, -H value ]",
        "--headers value [ optional values ]",
    )
    plan = build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=30,
        configuration=_configuration(),
        capabilities=assess_tool_capabilities("gobuster", ambiguous),
    )

    assert plan.compatibility_status == COMPONENT_OMITTED
    assert "repeatable" in plan.reason


def test_external_source_audit_keeps_strict_builders_central_and_shell_free() -> None:
    root = Path(__file__).resolve().parents[1] / "bugslyce"
    strict_source = (root / "recon" / "external_enforcement.py").read_text(
        encoding="utf-8"
    )
    pipeline_source = (root / "project_pipeline.py").read_text(encoding="utf-8")
    cli_source = (root / "cli.py").read_text(encoding="utf-8")

    assert "shell=True" not in strict_source
    assert '"--location"' in strict_source  # rejected by strict argv validation
    assert '"-L"' in strict_source  # rejected by strict argv validation
    assert strict_source.count('"--min-rate"') == 1  # prohibited audit set only
    assert "r0b2_bug_bounty_live_refusal_message" in pipeline_source
    assert "enforce_r0b2_bug_bounty_live_block(engagement_context)" in cli_source

    # Policy-aware external execution must enter through the bound session
    # runtime.  The generic authorised-lab subprocess runners are separately
    # blocked for bug bounty contexts until R0B3.
    for path in root.rglob("*.py"):
        if path == root / "recon" / "external_enforcement.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert "run_bug_bounty_curl(" not in source, path
        assert "run_bug_bounty_gobuster(" not in source, path
        assert "SafeSubprocessRunner(" not in source, path


@pytest.mark.parametrize(
    "engagement_context",
    ["ctf_lab", "internal_authorised", "unknown"],
)
def test_non_bug_bounty_contexts_keep_existing_live_policy(
    engagement_context: str,
) -> None:
    enforce_r0b2_bug_bounty_live_block(engagement_context)


def test_central_bug_bounty_block_names_r0b3_and_is_redacted() -> None:
    with pytest.raises(ValueError, match="R0B3") as caught:
        enforce_r0b2_bug_bounty_live_block("bug_bounty", _policy())

    assert HEADER_SECRET not in str(caught.value)
    assert USER_AGENT_SECRET not in str(caught.value)
    assert "controlled capture acceptance" in str(caught.value)


def test_evidence_backed_modular_external_workflows_use_central_block() -> None:
    root = Path(__file__).resolve().parents[1] / "bugslyce" / "recon"
    modules = {
        "http_metadata.py": "LiveHTTPMetadataRunner",
        "path_followup.py": "LivePathFollowupRunner",
        "content_run.py": "LiveContentDiscoveryRunner",
        "content_followup.py": "LiveContentFollowupRunner",
        "body_fetch.py": "LiveBodyFetchRunner",
        "nmap_services.py": "LiveNmapServiceRunner",
    }
    for filename, runner_name in modules.items():
        source = (root / filename).read_text(encoding="utf-8")
        marker = "enforce_r0b2_bug_bounty_live_block("
        block_call = source.index(marker)
        runner_use = source.index(runner_name, block_call)
        assert block_call < runner_use, filename


def test_modular_nmap_service_workflow_refuses_before_runner(tmp_path: Path) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "bugslyce_project.json").write_text(
        '{"engagement_context": "bug_bounty"}\n',
        encoding="utf-8",
    )
    runner = _ProcessRunner()

    with pytest.raises(ValueError, match="R0B3"):
        run_nmap_service_workflow(
            input_dir,
            tmp_path / "unused-scope.md",
            runner=runner,
        )

    assert runner.calls == []


def _policy(
    *,
    tcp_mode: str = TCP_CONSERVATIVE,
    custom_ports: str | None = None,
    tcp_confirmed: str = CONFIRMED,
):
    return build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second="2",
        maximum_http_concurrency=1,
        tcp_discovery_policy=tcp_mode,
        custom_tcp_ports=custom_ports,
        tcp_policy_confirmed=tcp_confirmed,
        identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", HEADER_SECRET),
        ),
        custom_user_agent=USER_AGENT_SECRET,
        updated_at="2026-07-28T10:00:00Z",
    )


def _configuration(*, rate: str = "2", concurrency: int = 1):
    policy = _policy()
    if rate != "2" or concurrency != 1:
        policy = build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            maximum_http_requests_per_second=rate,
            http_rate_source="programme_published_limit",
            programme_rate_confirmed=CONFIRMED,
            maximum_http_concurrency=concurrency,
            concurrent_automation_confirmed=(
                CONFIRMED if concurrency > 1 else "not_yet_confirmed"
            ),
            identification_requirement=IDENTIFICATION_HEADERS_AND_USER_AGENT,
            identification_headers=(
                IdentificationHeader("X-Researcher-ID", HEADER_SECRET),
            ),
            custom_user_agent=USER_AGENT_SECRET,
            updated_at="2026-07-28T10:00:00Z",
        )
    return build_http_enforcement_configuration(
        policy,
        approved_origins=("https://example.test/",),
    )


def _executor(clock: _FakeTime, *, transport=None) -> InternalHTTPExecutor:
    return InternalHTTPExecutor(
        _configuration(),
        transport=transport or _Transport(clock),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


def _session(
    clock: _FakeTime,
    *,
    policy=None,
    gobuster=None,
    executor: InternalHTTPExecutor | None = None,
) -> BugBountyExternalEnforcementSession:
    selected_policy = policy or _policy()
    return BugBountyExternalEnforcementSession(
        policy=selected_policy,
        approved_origins=("https://example.test/",),
        profile=DEEP_RECON_PROFILE,
        curl_capabilities=_capabilities("curl"),
        gobuster_capabilities=gobuster or _capabilities("gobuster"),
        nmap_capabilities=_capabilities("nmap"),
        http_executor=executor or _executor(clock),
    )


def _capabilities(tool: str):
    help_text = {"curl": CURL_HELP, "gobuster": GOBUSTER_HELP, "nmap": NMAP_HELP}[tool]
    return assess_tool_capabilities(tool, help_text)


def _curl_plan(
    tmp_path: Path,
    *,
    url: str = "https://example.test/value",
    additional_headers: tuple[tuple[str, str], ...] = (),
):
    return build_bug_bounty_curl_plan(
        url=url,
        method="GET",
        output_file=tmp_path / "body.html",
        response_headers_file=tmp_path / "response.headers",
        timeout_seconds=10,
        configuration=_configuration(),
        capabilities=_capabilities("curl"),
        purpose="test_exchange",
        additional_headers=additional_headers,
    )


def _wordlist(tmp_path: Path) -> Path:
    path = tmp_path / "wordlist.txt"
    path.write_text("admin\n", encoding="utf-8")
    return path


def _gobuster_plan(tmp_path: Path, *, rate: str = "2"):
    return build_bug_bounty_gobuster_plan(
        origin="https://example.test/",
        wordlist=_wordlist(tmp_path),
        output_file=tmp_path / "gobuster.txt",
        timeout_seconds=30,
        configuration=_configuration(rate=rate),
        capabilities=_capabilities("gobuster"),
    )


def _preflight(*, curl=None, gobuster=None, nmap=None):
    return build_bug_bounty_external_preflight(
        policy=_policy(),
        profile=DEEP_RECON_PROFILE,
        curl_capabilities=curl or _capabilities("curl"),
        gobuster_capabilities=gobuster or _capabilities("gobuster"),
        nmap_capabilities=nmap or _capabilities("nmap"),
    )
