"""Offline tests for the strict bug-bounty project runtime."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_HEADERS,
    IDENTIFICATION_NONE,
    SERVICE_VERSION_NOT_PERMITTED,
    SERVICE_VERSION_PERMITTED,
    TCP_SKIP,
    IdentificationHeader,
    build_bug_bounty_policy,
)
from bugslyce.core.models import (
    HTTPArtifact,
    ReconCommand,
    ReconHTTPMetadataExecutionResult,
)
from bugslyce.core.programme_scope import (
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.external_enforcement import (
    MAXIMUM_PROCESS_DIAGNOSTIC_CHARS,
    assess_tool_capabilities,
)
from bugslyce.recon.deep_http_fetcher import build_deep_http_fetcher
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.http_metadata import write_http_metadata_execution_result
from bugslyce.recon.modes import DEEP_RECON_PROFILE, STANDARD_RECON_PROFILE
from bugslyce.recon.project_runtime import (
    build_bug_bounty_project_runtime,
    require_project_runtime_binding,
)
import bugslyce.recon.project_runtime as project_runtime_module
from bugslyce.project_pipeline import (
    DeepPipelineOutputs,
    ServiceVersionNoWork,
    TCPDiscoveryNoWork,
    _step_runners,
)
import bugslyce.project_pipeline as pipeline_module


GOBUSTER_382_DIR_HELP = """
Usage:
  gobuster dir [flags]

Flags:
      --url string
      --wordlist string
      --threads int
      --delay duration
      --useragent string
      --headers value, -H value [ --headers value, -H value ]
            Specify HTTP headers, -H 'Header1: value' -H 'Header2: value'
      --timeout duration
      --output string
      --follow-redirect (default false)
            Follow redirects
      --no-tls-validation
"""

DIAGNOSTIC_SECRET = "external-private-header-runtime-4729"


def test_project_runtime_gobuster_probe_uses_dir_help_surface(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(argv, **_kwargs):
        calls.append(tuple(argv))
        if tuple(argv) == ("gobuster", "dir", "--help"):
            return SimpleNamespace(returncode=0, stdout=GOBUSTER_382_DIR_HELP, stderr="")
        return SimpleNamespace(returncode=0, stdout="Gobuster help", stderr="")

    monkeypatch.setattr(project_runtime_module.subprocess, "run", fake_run)

    capabilities = project_runtime_module._probe_capabilities("gobuster")

    assert calls == [("gobuster", "dir", "--help")]
    assert capabilities.available is True
    assert capabilities.diagnostic == "compatible"
    assert capabilities.repeated_headers_supported is True
    assert capabilities.redirect_following_opt_in is True


@pytest.mark.parametrize(
    "failure",
    (
        OSError("gobuster missing"),
        project_runtime_module.subprocess.TimeoutExpired(
            ("gobuster", "dir", "--help"), 10
        ),
    ),
)
def test_project_runtime_gobuster_probe_fail_closed_when_unavailable(monkeypatch, failure) -> None:
    def fake_run(_argv, **_kwargs):
        raise failure

    monkeypatch.setattr(project_runtime_module.subprocess, "run", fake_run)

    capabilities = project_runtime_module._probe_capabilities("gobuster")

    assert capabilities.available is False
    assert capabilities.diagnostic == "executable_absent"


def test_project_runtime_probe_preserves_curl_and_nmap_help_argv(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(argv, **_kwargs):
        calls.append(tuple(argv))
        return SimpleNamespace(returncode=0, stdout="help", stderr="")

    monkeypatch.setattr(project_runtime_module.subprocess, "run", fake_run)

    project_runtime_module._probe_capabilities("curl")
    project_runtime_module._probe_capabilities("nmap")

    assert calls == [("curl", "--help", "all"), ("nmap", "--help")]


def test_current_project_runtime_does_not_probe_or_require_gobuster(monkeypatch, tmp_path: Path) -> None:
    project = _project(tmp_path)
    calls: list[str] = []
    capabilities = _capabilities()

    def probe(tool: str):
        calls.append(tool)
        if tool == "gobuster":
            pytest.fail("current project runtime must not probe Gobuster")
        return capabilities[tool]

    monkeypatch.setattr(project_runtime_module, "_probe_capabilities", probe)
    runtime = build_bug_bounty_project_runtime(project, STANDARD_RECON_PROFILE)

    assert calls == ["curl", "nmap"]
    assert "gobuster" not in runtime.capabilities


def test_current_content_stage_fails_closed_without_runtime_instead_of_legacy_fallback(
    tmp_path: Path,
) -> None:
    runners = _step_runners(
        {
            "output_dir": tmp_path / "output",
            "scope_file": tmp_path / "scope.md",
            "plan_dir": tmp_path / "plan",
            "plan_path": tmp_path / "plan" / "content_discovery_plan.json",
            "export_path": tmp_path / "evidence.zip",
            "target": "app.example.test",
            "project_file": tmp_path / "bugslyce_project.json",
            "resume": False,
            "profile": STANDARD_RECON_PROFILE,
            "project_runtime": None,
        },
        None,
    )

    with pytest.raises(ValueError, match="requires a bound project runtime"):
        runners["PIPELINE-STEP-007"]()


def _capabilities():
    return {
        "curl": assess_tool_capabilities(
            "curl",
            "--disable --connect-timeout --dump-header --globoff --header --head --max-redirs --max-time --noproxy --output --proto --resolve --silent --show-error --user-agent --write-out",
        ),
        "gobuster": assess_tool_capabilities(
            "gobuster",
            "dir --url --wordlist --threads --delay --useragent --headers value -H value --timeout --output --follow-redirect (default false) --no-tls-validation",
        ),
        "nmap": assess_tool_capabilities(
            "nmap", "-sT -sV -Pn -n -p --max-rate --max-retries -oN"
        ),
    }


def _project(
    tmp_path: Path,
    *,
    excluded: bool = False,
    service_version_detection: str = SERVICE_VERSION_NOT_PERMITTED,
    tcp_discovery_policy: str | None = None,
    http_rules: tuple[tuple[str, str, str], ...] = (),
    include_target_hostname: bool = True,
    identification_requirement: str = IDENTIFICATION_NONE,
    identification_headers: tuple[IdentificationHeader, ...] = (),
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = tmp_path / "scope.md"
    scope.write_text("# Authorised scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "strict-runtime",
        "app.example.test",
        scope,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    policy_kwargs = {}
    if tcp_discovery_policy is not None:
        policy_kwargs["tcp_discovery_policy"] = tcp_discovery_policy
    save_project_engagement_policy(
        project_file,
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            identification_requirement=identification_requirement,
            identification_headers=identification_headers,
            service_version_detection=service_version_detection,
            updated_at="2026-08-08T12:00:00Z",
            **policy_kwargs,
        ),
    )
    rules = []
    if include_target_hostname:
        rules.append(
            build_programme_scope_rule(
                rule_id="include-target",
                action="include",
                kind="exact_hostname",
                value="app.example.test",
            )
        )
    rules.append(
        build_programme_scope_rule(
            rule_id="fixture-peer-network",
            action="include",
            kind="ipv4_cidr",
            value="192.0.2.0/24",
        )
    )
    if excluded:
        rules.append(
            build_programme_scope_rule(
                rule_id="exclude-target",
                action="exclude",
                kind="exact_hostname",
                value="app.example.test",
            )
        )
    for index, (action, kind, value) in enumerate(http_rules, start=1):
        rules.append(
            build_programme_scope_rule(
                rule_id=f"http-rule-{index}",
                action=action,
                kind=kind,
                value=value,
            )
        )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy(rules, updated_at="2026-08-08T12:00:00Z"),
    )
    return load_project(project_file)


def _command(
    command_id: str,
    output_file: Path,
    argv: list[str],
    *,
    tool: str = "nmap",
) -> ReconCommand:
    return ReconCommand(
        id=command_id,
        tool=tool,
        argv=argv,
        output_file=str(output_file),
        timeout_seconds=120,
        phase=command_id.lower(),
        risk_level="bounded",
        requires_confirmation=True,
        scope_sensitive=True,
        description="Synthetic strict runtime command",
        ready_for_execution=True,
        placeholders=[],
    )


class _NmapArtefactProcess:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, _timeout_seconds, _environment):
        command = tuple(argv)
        self.calls.append(command)
        output = Path(command[command.index("-oN") + 1])
        service = "http Example" if "-sV" in command else "http"
        output.write_text(
            "Nmap scan report for app.example.test (192.0.2.10)\n"
            "PORT    STATE SERVICE VERSION\n"
            f"80/tcp  open  {service}\n"
            f"443/tcp open  {service}\n"
            "Nmap done\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class _CurlArtefactProcess:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, _timeout_seconds, _environment):
        command = tuple(argv)
        self.calls.append(command)
        Path(command[command.index("--output") + 1]).write_text(
            "HTTP/1.1 200 OK\n",
            encoding="utf-8",
        )
        Path(command[command.index("--dump-header") + 1]).write_text(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="200", stderr="")


class _FailedCurlProcess:
    def __init__(self, stderr: str) -> None:
        self.stderr = stderr

    def run(self, _argv, _timeout_seconds, _environment):
        return SimpleNamespace(returncode=35, stdout="", stderr=self.stderr)


@pytest.mark.parametrize("profile", [STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE])
def test_ready_authorised_project_builds_strict_runtime(tmp_path: Path, profile: str) -> None:
    runtime = build_bug_bounty_project_runtime(
        _project(tmp_path), profile, capabilities=_capabilities()
    )

    assert runtime.target_decision.outcome == "allowed"
    assert runtime.service_version_permitted is False
    with pytest.raises(ValueError, match="origins"):
        _ = runtime.http_executor


@pytest.mark.parametrize("profile", [STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE])
def test_tcp_skip_runtime_uses_explicit_root_http_scope(
    tmp_path: Path,
    profile: str,
) -> None:
    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            tcp_discovery_policy=TCP_SKIP,
            http_rules=(("include", "http_path_prefix", "https://app.example.test/"),),
        ),
        profile,
        capabilities=_capabilities(),
    )

    assert runtime.tcp_discovery_skipped is True
    assert runtime.initial_http_origins == ("https://app.example.test/",)


def test_tcp_skip_runtime_does_not_guess_scheme_from_hostname_scope(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="explicit allowed root HTTP programme scope"):
        build_bug_bounty_project_runtime(
            _project(tmp_path, tcp_discovery_policy=TCP_SKIP),
            STANDARD_RECON_PROFILE,
            capabilities=_capabilities(),
        )


def test_tcp_skip_runtime_does_not_broaden_narrow_http_scope(
    tmp_path: Path,
) -> None:
    project = _project(
        tmp_path,
        tcp_discovery_policy=TCP_SKIP,
        http_rules=(("include", "http_path_prefix", "https://app.example.test/api/"),),
        include_target_hostname=False,
    )

    with pytest.raises(ValueError, match="not authorised|explicit allowed root HTTP"):
        build_bug_bounty_project_runtime(
            project,
            STANDARD_RECON_PROFILE,
            capabilities=_capabilities(),
        )


def test_tcp_skip_runtime_honours_root_exclusion(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="explicit allowed root HTTP programme scope"):
        build_bug_bounty_project_runtime(
            _project(
                tmp_path,
                tcp_discovery_policy=TCP_SKIP,
                http_rules=(
                    ("include", "http_path_prefix", "https://app.example.test/"),
                    ("exclude", "exact_http_url", "https://app.example.test/"),
                ),
            ),
            STANDARD_RECON_PROFILE,
            capabilities=_capabilities(),
        )


def test_tcp_skip_runtime_rejects_cross_host_http_seed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="explicit allowed root HTTP programme scope"):
        build_bug_bounty_project_runtime(
            _project(
                tmp_path,
                tcp_discovery_policy=TCP_SKIP,
                http_rules=(("include", "http_path_prefix", "https://other.example.test/"),),
            ),
            STANDARD_RECON_PROFILE,
            capabilities=_capabilities(),
        )


def test_tcp_skip_runtime_does_not_require_nmap_capability(tmp_path: Path) -> None:
    capabilities = _capabilities()
    capabilities["nmap"] = assess_tool_capabilities("nmap", None, available=False)

    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            tcp_discovery_policy=TCP_SKIP,
            service_version_detection=SERVICE_VERSION_PERMITTED,
            http_rules=(("include", "http_path_prefix", "https://app.example.test/"),),
        ),
        DEEP_RECON_PROFILE,
        capabilities=capabilities,
    )

    assert runtime.tcp_discovery_skipped is True
    assert runtime.service_version_permitted is True


@pytest.mark.parametrize("profile", [STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE])
def test_tcp_skip_pipeline_runners_noop_nmap_and_use_strict_http_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    process = _NmapArtefactProcess()
    project = _project(
        tmp_path,
        tcp_discovery_policy=TCP_SKIP,
        service_version_detection=SERVICE_VERSION_PERMITTED,
        http_rules=(("include", "http_path_prefix", "https://app.example.test/"),),
    )
    runtime = build_bug_bounty_project_runtime(
        project,
        profile,
        capabilities=_capabilities(),
        process_runner=process,
    )
    observed: dict[str, object] = {}

    def metadata(*_args, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(artifact_paths=(), report_path=str(tmp_path / "report.md"))

    monkeypatch.setattr(
        pipeline_module,
        "run_nmap_discovery_workflow",
        lambda *_args, **_kwargs: pytest.fail("Nmap discovery must not run"),
    )
    monkeypatch.setattr(
        pipeline_module,
        "run_nmap_service_workflow",
        lambda *_args, **_kwargs: pytest.fail("Nmap service detection must not run"),
    )
    monkeypatch.setattr(pipeline_module, "run_http_metadata_workflow", metadata)
    monkeypatch.setattr(
        pipeline_module,
        "write_http_metadata_execution_result",
        lambda *_args: (),
    )
    context: dict[str, object] = {
        "output_dir": Path(project.output_dir),
        "scope_file": Path(project.scope_file),
        "plan_dir": tmp_path / "plan",
        "plan_path": tmp_path / "plan" / "content_discovery_plan.json",
        "export_path": tmp_path / "pack.zip",
        "target": project.target,
        "project_file": Path(project.output_dir) / "bugslyce_project.json",
        "resume": False,
        "profile": profile,
        "deep_outputs": DeepPipelineOutputs(),
        "project_runtime": runtime,
    }
    runners = _step_runners(context, None)

    with pytest.raises(TCPDiscoveryNoWork, match="intentionally skipped"):
        runners["PIPELINE-STEP-002"]()
    with pytest.raises(ServiceVersionNoWork, match="no trusted open-port"):
        runners["PIPELINE-STEP-003"]()
    runners["PIPELINE-STEP-004"]()

    assert process.calls == []
    assert observed["project_runtime"] is runtime
    assert observed["programme_scope_seed_origins"] == runtime.initial_http_origins
    assert getattr(observed["runner"], "_bugslyce_project_runtime") is runtime
    assert runtime.http_executor is runtime._http_session.http_executor
    assert not (Path(project.output_dir) / "nmap-allports.txt").exists()
    assert not (Path(project.output_dir) / "nmap-services-all.txt").exists()


def test_explicit_programme_exclusion_blocks_runtime_before_tools(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not authorised"):
        build_bug_bounty_project_runtime(
            _project(tmp_path, excluded=True),
            STANDARD_RECON_PROFILE,
            capabilities=_capabilities(),
        )


def test_deep_uses_one_shared_programme_scoped_executor(tmp_path: Path) -> None:
    runtime = build_bug_bounty_project_runtime(
        _project(tmp_path), DEEP_RECON_PROFILE, capabilities=_capabilities()
    )
    runtime.bind_http_origins(("https://app.example.test/",))

    first = runtime.http_executor
    runtime.bind_http_origins(("https://app.example.test/",))

    assert runtime.http_executor is first
    assert runtime._http_session is not None
    assert runtime._http_session.http_executor is first
    assert build_deep_http_fetcher(executor=first).executor is first


def test_tcp_skip_deep_reuses_the_bound_programme_scoped_executor(
    tmp_path: Path,
) -> None:
    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            tcp_discovery_policy=TCP_SKIP,
            http_rules=(("include", "http_path_prefix", "https://app.example.test/"),),
        ),
        DEEP_RECON_PROFILE,
        capabilities=_capabilities(),
    )

    executor = runtime.http_executor
    runtime.bind_http_origins(runtime.initial_http_origins)

    assert runtime.http_executor is executor
    assert runtime._http_session is not None
    assert runtime._http_session.http_executor is executor
    assert build_deep_http_fetcher(executor=executor).executor is executor


def test_strict_runtime_derives_service_ports_from_its_discovery_result(
    tmp_path: Path,
) -> None:
    process = _NmapArtefactProcess()
    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            service_version_detection=SERVICE_VERSION_PERMITTED,
        ),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=process,
    )
    discovery_output = tmp_path / "project" / "nmap-allports.txt"
    service_output = tmp_path / "project" / "nmap-services-all.txt"

    discovery = runtime.nmap_discovery_runner().run(
        _command("DISCOVERY", discovery_output, ["nmap", "-p", "80,443"])
    )
    service = runtime.nmap_service_runner().run(
        _command("SERVICE", service_output, ["nmap", "-sV", "-p", "80,443"])
    )

    assert discovery.exit_code == 0
    assert service.exit_code == 0
    assert len(process.calls) == 2
    assert "-sT" in process.calls[0]
    assert "-sV" in process.calls[1]
    assert process.calls[1][process.calls[1].index("-p") + 1] == "80,443"
    assert not {
        "-sC", "--script", "-A", "-O", "--traceroute", "-sU",
        "-T4", "-T5", "--min-rate", "-p-",
    }.intersection(process.calls[1])


def test_strict_runtime_refuses_extra_service_port_before_process_start(
    tmp_path: Path,
) -> None:
    process = _NmapArtefactProcess()
    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            service_version_detection=SERVICE_VERSION_PERMITTED,
        ),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=process,
    )
    runtime.nmap_discovery_runner().run(
        _command(
            "DISCOVERY",
            tmp_path / "project" / "nmap-allports.txt",
            ["nmap", "-p", "80,443"],
        )
    )

    with pytest.raises(ValueError, match="do not match strict discovery"):
        runtime.nmap_service_runner().run(
            _command(
                "SERVICE",
                tmp_path / "project" / "nmap-services-all.txt",
                ["nmap", "-sV", "-p", "80,443,8080"],
            )
        )

    assert len(process.calls) == 1


def test_strict_runtime_restores_canonical_discovery_provenance_for_resume(
    tmp_path: Path,
) -> None:
    process = _NmapArtefactProcess()
    project = _project(
        tmp_path,
        service_version_detection=SERVICE_VERSION_PERMITTED,
    )
    output_dir = Path(project.output_dir)
    (output_dir / "nmap-allports.txt").write_text(
        "Nmap scan report for app.example.test (192.0.2.10)\n"
        "PORT    STATE SERVICE\n"
        "80/tcp  open  http\n"
        "443/tcp open  https\n"
        "Nmap done\n",
        encoding="utf-8",
    )
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "app.example.test",
                "created_by": "bugslyce-nmap-discover",
                "profile": "bug-bounty-policy-tcp",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-allports.txt"}
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    runtime = build_bug_bounty_project_runtime(
        project,
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=process,
    )

    result = runtime.nmap_service_runner().run(
        _command(
            "SERVICE",
            output_dir / "nmap-services-all.txt",
            ["nmap", "-sV", "-p", "80,443"],
        )
    )

    assert result.exit_code == 0
    assert len(process.calls) == 1
    assert "-sV" in process.calls[0]


def test_service_detection_cannot_change_the_discovered_target_peer(
    tmp_path: Path,
) -> None:
    process = _NmapArtefactProcess()
    peers = iter((("192.0.2.10",), ("192.0.2.20",)))
    runtime = build_bug_bounty_project_runtime(
        _project(
            tmp_path,
            service_version_detection=SERVICE_VERSION_PERMITTED,
        ),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: next(peers),
        process_runner=process,
    )
    runtime.nmap_discovery_runner().run(
        _command(
            "DISCOVERY",
            tmp_path / "project" / "nmap-allports.txt",
            ["nmap", "-p", "80,443"],
        )
    )

    with pytest.raises(ValueError, match="target peer"):
        runtime.nmap_service_runner().run(
            _command(
                "SERVICE",
                tmp_path / "project" / "nmap-services-all.txt",
                ["nmap", "-sV", "-p", "80,443"],
            )
        )

    assert len(process.calls) == 1


def test_nmap_only_stage_cannot_plan_http_before_origins_are_bound(tmp_path: Path) -> None:
    runtime = build_bug_bounty_project_runtime(
        _project(tmp_path),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
    )

    with pytest.raises(ValueError, match="Nmap-only"):
        runtime._nmap_session.build_curl_plan()


def test_strict_curl_adapter_uses_shared_executor_and_removes_sidecar(
    tmp_path: Path,
) -> None:
    process = _CurlArtefactProcess()
    runtime = build_bug_bounty_project_runtime(
        _project(tmp_path),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=process,
    )
    runtime.bind_http_origins(("https://app.example.test/",))
    output = tmp_path / "project" / "curl-headers.txt"

    result = runtime.curl_runner().run(
        _command(
            "HTTP_METADATA",
            output,
            ["curl", "-I", "https://app.example.test/"],
            tool="curl",
        )
    )

    assert result.exit_code == 0
    assert runtime.http_executor.total_request_attempts == 1
    assert len(process.calls) == 1
    assert "--resolve" in process.calls[0]
    assert "--noproxy" in process.calls[0]
    assert not Path(str(output) + ".strict-response-headers").exists()


def test_failed_strict_curl_diagnostic_survives_safe_runtime_handoff_and_metadata(
    tmp_path: Path,
) -> None:
    actionable = "TLS handshake failed: certificate verify failed\n"
    process = _FailedCurlProcess(
        actionable
        + f"configured identity: {DIAGNOSTIC_SECRET}\n"
        + ("bounded-tail-" * MAXIMUM_PROCESS_DIAGNOSTIC_CHARS)
    )
    project = _project(
        tmp_path,
        identification_requirement=IDENTIFICATION_HEADERS,
        identification_headers=(
            IdentificationHeader("X-Researcher-ID", DIAGNOSTIC_SECRET),
        ),
    )
    runtime = build_bug_bounty_project_runtime(
        project,
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=process,
    )
    runtime.bind_http_origins(("https://app.example.test/",))
    output = tmp_path / "project" / "curl-headers.txt"

    command_result = runtime.curl_runner().run(
        _command(
            "HTTP_METADATA",
            output,
            ["curl", "-I", "https://app.example.test/"],
            tool="curl",
        )
    )

    assert command_result.executed is True
    assert command_result.exit_code == 35
    assert command_result.error == "curl exited with code 35."
    assert command_result.stderr_path is not None
    stderr_path = Path(command_result.stderr_path)
    assert stderr_path.parent == output.parent
    diagnostic = stderr_path.read_text(encoding="utf-8")
    assert actionable.strip() in diagnostic
    assert DIAGNOSTIC_SECRET not in diagnostic
    assert "configured value redacted" in diagnostic
    assert len(diagnostic) <= MAXIMUM_PROCESS_DIAGNOSTIC_CHARS

    execution_result = ReconHTTPMetadataExecutionResult(
        mode="http-metadata",
        target="app.example.test",
        scope_file=str(tmp_path / "scope.md"),
        input_dir=str(output.parent),
        http_services=["https://app.example.test/"],
        artifact_paths=[str(stderr_path)],
        manifest_path=str(output.parent / "recon_manifest.json"),
        report_path=str(output.parent / "report.md"),
        project_state_path=str(output.parent / "project_state.json"),
        execution_count=1,
        command_results=[command_result],
        warnings=[],
    )
    execution_json, _execution_markdown = write_http_metadata_execution_result(
        execution_result,
        output.parent,
    )
    persisted = json.loads(execution_json.read_text(encoding="utf-8"))

    assert persisted["command_results"][0]["stderr_path"] == str(stderr_path)
    assert Path(persisted["command_results"][0]["stderr_path"]).read_text(
        encoding="utf-8"
    ) == diagnostic


def test_fabricated_or_cross_runtime_runner_cannot_bypass_workflow_guard(
    tmp_path: Path,
) -> None:
    first = build_bug_bounty_project_runtime(
        _project(tmp_path / "first"),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
    )
    second = build_bug_bounty_project_runtime(
        _project(tmp_path / "second"),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
    )

    with pytest.raises(ValueError, match="canonical project runtime"):
        require_project_runtime_binding(
            SimpleNamespace(require_workflow=lambda *_args: None),
            Path(first.project.output_dir),
            Path(first.project.scope_file),
            first.project.target,
            first.nmap_discovery_runner(),
            "nmap_discovery",
        )
    with pytest.raises(ValueError, match="not bound"):
        require_project_runtime_binding(
            first,
            Path(first.project.output_dir),
            Path(first.project.scope_file),
            first.project.target,
            second.nmap_discovery_runner(),
            "nmap_discovery",
        )


def test_deep_pipeline_threads_canonical_scope_and_shared_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project(tmp_path)
    runtime = build_bug_bounty_project_runtime(
        project,
        DEEP_RECON_PROFILE,
        capabilities=_capabilities(),
    )
    runtime.bind_http_origins(("https://app.example.test/",))
    state = SimpleNamespace(
        http_services=(
            SimpleNamespace(
                url="https://app.example.test/",
                status_code=200,
                title="Synthetic application",
                evidence_ids=("EVID-HTTP-0001",),
            ),
        ),
        endpoints=(),
        http_artifacts=(
            HTTPArtifact(
                url="https://app.example.test/sitemap.xml",
                artifact_type="body",
                value="retained metadata",
                source_file="sitemap.xml",
                evidence_ids=["EVID-METADATA-0001"],
                tags=["metadata"],
            ),
        ),
        discovered_paths=(),
    )
    observed: dict[str, object] = {}
    executor_view = object()

    class _ProgrammePlan:
        pass

    programme_plan = _ProgrammePlan()
    programme_plan.http_work_items = (
        SimpleNamespace(canonical_origin="https://app.example.test"),
    )
    original_plan_builder = (
        pipeline_module.build_deep_collection_request_plan_from_project_state
    )
    original_followup_builder = pipeline_module.build_deep_shallow_route_followup_plan

    def build_plan(project_state, *, programme_scope_policy=None):
        observed["plan_scope"] = programme_scope_policy
        return original_plan_builder(
            project_state,
            programme_scope_policy=programme_scope_policy,
        )

    def build_fetcher(*, executor=None):
        observed["executor"] = executor

        def fetch(request, _bounds):
            return DeepHTTPResponse(
                url=request.url,
                final_url=request.url,
                status_code=404,
                headers=(("Content-Type", "text/plain"),),
                body=b"not found",
                elapsed_seconds=0.01,
            )

        return fetch

    def build_followup(
        html_routes,
        javascript_routes,
        *,
        programme_scope_policy=None,
        materialised_origins=None,
    ):
        observed["followup_scope"] = programme_scope_policy
        observed["followup_materialised_origins"] = materialised_origins
        return original_followup_builder(
            html_routes,
            javascript_routes,
            programme_scope_policy=programme_scope_policy,
            materialised_origins=materialised_origins,
        )

    monkeypatch.setattr(pipeline_module, "build_project_state", lambda _path: state)
    monkeypatch.setattr(
        pipeline_module,
        "build_deep_collection_request_plan_from_project_state",
        build_plan,
    )
    monkeypatch.setattr(pipeline_module, "build_deep_http_fetcher", build_fetcher)
    monkeypatch.setattr(
        pipeline_module,
        "ProgrammeOrchestrationPlan",
        _ProgrammePlan,
    )
    monkeypatch.setattr(
        pipeline_module,
        "build_programme_orchestration_plan",
        lambda actual_runtime, actual_state: (
            observed.setdefault(
                "programme_plan_inputs",
                (actual_runtime, actual_state),
            ),
            programme_plan,
        )[1],
    )
    monkeypatch.setattr(
        pipeline_module,
        "build_programme_orchestration_http_executor",
        lambda actual_runtime, actual_state, actual_plan: (
            observed.setdefault(
                "executor_view_inputs",
                (actual_runtime, actual_state, actual_plan),
            ),
            executor_view,
        )[1],
    )
    monkeypatch.setattr(
        pipeline_module,
        "build_deep_shallow_route_followup_plan",
        build_followup,
    )
    context: dict[str, object] = {
        "output_dir": Path(project.output_dir),
        "scope_file": Path(project.scope_file),
        "plan_dir": tmp_path / "plan",
        "plan_path": tmp_path / "plan" / "content_discovery_plan.json",
        "export_path": tmp_path / "pack.zip",
        "target": project.target,
        "project_file": Path(project.output_dir) / "bugslyce_project.json",
        "resume": False,
        "profile": DEEP_RECON_PROFILE,
        "deep_outputs": DeepPipelineOutputs(),
        "project_runtime": runtime,
    }

    _step_runners(context, None)["PIPELINE-STEP-010D"]()

    assert observed == {
        "plan_scope": runtime.programme_scope_policy,
        "programme_plan_inputs": (runtime, state),
        "executor_view_inputs": (runtime, state, programme_plan),
        "executor": executor_view,
        "followup_scope": runtime.programme_scope_policy,
        "followup_materialised_origins": ("https://app.example.test",),
    }


def test_standard_pipeline_stages_receive_only_strict_runtime_adapters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project(tmp_path)
    runtime = build_bug_bounty_project_runtime(
        project,
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
    )
    runtime.bind_http_origins(("https://app.example.test/",))
    observed: dict[str, dict[str, object]] = {}

    def workflow(name: str, **attributes):
        def run(*_args, **kwargs):
            observed[name] = kwargs
            return SimpleNamespace(**attributes)

        return run

    output_dir = Path(project.output_dir)
    report_path = str(output_dir / "report.md")
    monkeypatch.setattr(
        pipeline_module,
        "run_nmap_discovery_workflow",
        workflow(
            "nmap",
            nmap_output_path=str(output_dir / "nmap-allports.txt"),
            report_path=report_path,
        ),
    )
    monkeypatch.setattr(
        pipeline_module,
        "write_nmap_discovery_execution_result",
        lambda *_args: (),
    )
    for name, function_name in (
        ("metadata", "run_http_metadata_workflow"),
        ("path", "run_path_followup_workflow"),
        ("content_followup", "run_content_followup_workflow"),
        ("body", "run_body_fetch_workflow"),
    ):
        monkeypatch.setattr(
            pipeline_module,
            function_name,
            workflow(name, artifact_paths=(), report_path=report_path),
        )
    for writer_name in (
        "write_http_metadata_execution_result",
        "write_path_followup_execution_result",
        "write_content_discovery_execution_result",
        "write_content_followup_execution_result",
        "write_body_fetch_execution_result",
    ):
        monkeypatch.setattr(pipeline_module, writer_name, lambda *_args: ())
    monkeypatch.setattr(
        pipeline_module,
        "build_project_state",
        lambda _path: SimpleNamespace(
            port_services=(
                SimpleNamespace(
                    host="app.example.test",
                    state="open",
                    protocol="tcp",
                    service="https",
                    port=443,
                    tags=(),
                ),
            ),
        ),
    )
    monkeypatch.setattr(pipeline_module, "ProjectState", SimpleNamespace)
    monkeypatch.setattr(
        pipeline_module,
        "build_programme_orchestration_plan",
        lambda *_args: SimpleNamespace(),
    )
    monkeypatch.setattr(
        pipeline_module,
        "build_native_content_discovery_plan",
        lambda *_args, **_kwargs: SimpleNamespace(profile="standard-bounded-core"),
    )
    monkeypatch.setattr(
        pipeline_module,
        "run_native_content_discovery",
        workflow("content"),
    )
    monkeypatch.setattr(
        pipeline_module,
        "_register_native_content_discovery_artifacts",
        lambda *_args: (),
    )
    context: dict[str, object] = {
        "output_dir": output_dir,
        "scope_file": Path(project.scope_file),
        "plan_dir": tmp_path / "plan",
        "plan_path": tmp_path / "plan" / "content_discovery_plan.json",
        "export_path": tmp_path / "pack.zip",
        "target": project.target,
        "project_file": output_dir / "bugslyce_project.json",
        "resume": False,
        "profile": STANDARD_RECON_PROFILE,
        "deep_outputs": DeepPipelineOutputs(),
        "project_runtime": runtime,
    }
    runners = _step_runners(context, None)

    with pytest.raises(ServiceVersionNoWork, match="does not permit"):
        runners["PIPELINE-STEP-003"]()

    for step_id in (
        "PIPELINE-STEP-002",
        "PIPELINE-STEP-004",
        "PIPELINE-STEP-005",
        "PIPELINE-STEP-007",
        "PIPELINE-STEP-008",
        "PIPELINE-STEP-009",
    ):
        runners[step_id]()

    assert set(observed) == {
        "nmap", "metadata", "path", "content", "content_followup", "body"
    }
    for name, values in observed.items():
        if name == "content":
            continue
        assert values["project_runtime"] is runtime
        assert values["runner"] is not None
    assert observed["content"]["progress_callback"] is None
