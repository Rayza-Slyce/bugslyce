"""WP4A RED contracts for bounded programme-native content discovery."""

from __future__ import annotations

import importlib
import json
import ssl
from dataclasses import replace
from pathlib import Path

import pytest

from bugslyce.core.engagement_policy import (
    AUTOMATION_BASIS_EXPLICIT_PERMISSION,
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_NONE,
    build_bug_bounty_policy,
)
from bugslyce.core.engagement_context import (
    BUG_BOUNTY_CONTEXT,
    CTF_LAB_CONTEXT,
    INTERNAL_AUTHORISED_CONTEXT,
    UNKNOWN_CONTEXT,
)
from bugslyce.core.models import DiscoveredPath, HTTPService, ProjectState, ReconManifest
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE,
    OUTCOME_ALLOWED,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_IPV4,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
    evaluate_raw_scope_destination,
    DESTINATION_HTTP_URL,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_PROFILES,
    ContentDiscoveryProfileDefinition,
)
from bugslyce.recon.external_enforcement import assess_tool_capabilities
from bugslyce.recon.http_enforcement import (
    HTTPRateRejected,
    HTTPRedirectRefused,
    HTTPTransportFailure,
    HTTPTransportResponse,
    InternalHTTPExecutor,
    PeerBoundHTTPTransport,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.modes import STANDARD_RECON_PROFILE
from bugslyce.recon.programme_orchestration import (
    build_programme_orchestration_plan,
)
from bugslyce.recon.project_runtime import build_bug_bounty_project_runtime


FIXED_TIME = "2026-08-29T17:00:00Z"
PROFILE = "wp4a-synthetic-root"


def _native_module():
    return importlib.import_module("bugslyce.recon.native_content_discovery")


def _capabilities():
    return {
        "curl": assess_tool_capabilities(
            "curl",
            "--disable --connect-timeout --dump-header --globoff --header --head "
            "--max-redirs --max-time --noproxy --output --proto --resolve --silent "
            "--show-error --user-agent --write-out",
        ),
        "gobuster": assess_tool_capabilities(
            "gobuster",
            "dir --url --wordlist --threads --delay --useragent --headers value "
            "-H value --timeout --output --follow-redirect (default false) "
            "--no-tls-validation",
        ),
        "nmap": assess_tool_capabilities(
            "nmap", "-sT -sV -Pn -n -p --max-rate --max-retries -oN"
        ),
    }


def _runtime(
    tmp_path: Path,
    *,
    origin: str = "https://app.example.test/",
    origins: tuple[str, ...] | None = None,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = tmp_path / "scope.md"
    scope.write_text("# Authorised synthetic scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "native-content-discovery",
        "app.example.test",
        scope,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(
        project_file,
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            automated_reconnaissance_basis=AUTOMATION_BASIS_EXPLICIT_PERMISSION,
            identification_requirement=IDENTIFICATION_NONE,
            updated_at=FIXED_TIME,
        ),
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy(
            (
                build_programme_scope_rule(
                    rule_id="include-project-target",
                    action=ACTION_INCLUDE,
                    kind=RULE_EXACT_HOSTNAME,
                    value="app.example.test",
                ),
                build_programme_scope_rule(
                    rule_id="include-qualified-wildcard",
                    action=ACTION_INCLUDE,
                    kind=RULE_WILDCARD_SUBDOMAIN,
                    value="*.example.test",
                    scheme="https",
                    port=443,
                ),
                build_programme_scope_rule(
                    rule_id="include-synthetic-resolved-peer",
                    action=ACTION_INCLUDE,
                    kind=RULE_EXACT_IPV4,
                    value="192.0.2.44",
                ),
            ),
            updated_at=FIXED_TIME,
        ),
    )
    runtime = build_bug_bounty_project_runtime(
        load_project(project_file),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _host, _port: ("192.0.2.44",),
    )
    runtime.bind_http_origins(origins or (origin,))
    return runtime


def _state(
    runtime,
    *,
    discovered_paths: tuple[DiscoveredPath, ...] = (),
) -> ProjectState:
    return ProjectState(
        project_name=runtime.project.name,
        input_dir=runtime.project.output_dir,
        processed_files=[],
        scope_summary="Synthetic retained programme evidence",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=[],
        discovered_paths=list(discovered_paths),
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at=FIXED_TIME,
        engagement_context="bug_bounty",
    )


def _runtime_less_state(
    tmp_path: Path,
    engagement_context: str,
    *,
    manifest_target: str = "app.example.test",
) -> tuple[ProjectState, Path]:
    scope = tmp_path / "scope.md"
    scope.write_text(
        "# Authorised synthetic scope\n\n## In Scope\n\n- app.example.test\n",
        encoding="utf-8",
    )
    state = ProjectState(
        project_name="runtime-less-native",
        input_dir=str(tmp_path),
        processed_files=[],
        scope_summary="Synthetic explicit scope",
        assets=[],
        http_services=[
            HTTPService(
                url="https://app.example.test/observed",
                hostname="app.example.test",
                status_code=200,
                title=None,
                technologies=[],
                content_length=2,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            ),
            HTTPService(
                url="https://unrelated.example.test/",
                hostname="unrelated.example.test",
                status_code=200,
                title=None,
                technologies=[],
                content_length=2,
                evidence_ids=["EVID-HTTP-0002"],
                tags=[],
            ),
        ],
        endpoints=[],
        port_services=[],
        http_artifacts=[],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=ReconManifest(
            schema_version="1.0",
            target=manifest_target,
            artifacts=[],
        ),
        evidence=[],
        warnings=[],
        generated_at=FIXED_TIME,
        engagement_context=engagement_context,
    )
    return state, scope


@pytest.mark.parametrize(
    "engagement_context",
    (CTF_LAB_CONTEXT, INTERNAL_AUTHORISED_CONTEXT),
)
def test_runtime_less_native_plan_uses_only_target_backed_origins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engagement_context: str,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, engagement_context)
    module = _native_module()

    plan = module.build_runtime_less_native_content_discovery_plan(
        state,
        "app.example.test",
        scope,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(10, 10),
    )

    assert tuple(request.canonical_origin for request in plan.requests) == (
        "https://app.example.test",
    )
    assert tuple(request.url for request in plan.requests) == (
        "https://app.example.test/admin",
    )


@pytest.mark.parametrize("engagement_context", (BUG_BOUNTY_CONTEXT, UNKNOWN_CONTEXT))
def test_runtime_less_native_entry_refuses_unapproved_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engagement_context: str,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, engagement_context)
    module = _native_module()

    with pytest.raises(ValueError, match="[Rr]untime-less native content discovery"):
        module.build_runtime_less_native_content_discovery_plan(
            state,
            "app.example.test",
            scope,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(10, 10),
        )


def test_runtime_less_native_entry_refuses_manifest_target_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(
        tmp_path,
        CTF_LAB_CONTEXT,
        manifest_target="other.example.test",
    )
    module = _native_module()

    with pytest.raises(ValueError, match="manifest target"):
        module.build_runtime_less_native_content_discovery_plan(
            state,
            "app.example.test",
            scope,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(10, 10),
        )


def test_runtime_less_native_entry_revalidates_target_against_scope_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, CTF_LAB_CONTEXT)
    scope.write_text(
        "# Authorised synthetic scope\n\n## In Scope\n\n- other.example.test\n",
        encoding="utf-8",
    )
    module = _native_module()

    with pytest.raises(ValueError, match="not explicitly listed"):
        module.build_runtime_less_native_content_discovery_plan(
            state,
            "app.example.test",
            scope,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(10, 10),
        )


def test_runtime_less_native_entry_refuses_origins_not_backed_by_current_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, CTF_LAB_CONTEXT)
    state = replace(state, http_services=[])
    module = _native_module()

    with pytest.raises(ValueError, match="target-backed HTTP origin"):
        module.build_runtime_less_native_content_discovery_plan(
            state,
            "app.example.test",
            scope,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(10, 10),
        )


def test_runtime_less_native_execution_refuses_plan_origin_not_backed_by_current_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, CTF_LAB_CONTEXT)
    module = _native_module()
    plan = module.build_runtime_less_native_content_discovery_plan(
        state,
        "app.example.test",
        scope,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(10, 10),
    )
    forged = replace(
        plan,
        requests=(
            replace(
                plan.requests[0],
                url="https://unrelated.example.test/admin",
                canonical_origin="https://unrelated.example.test",
            ),
        ),
        origin_allocations=(
            replace(
                plan.origin_allocations[0],
                canonical_origin="https://unrelated.example.test",
            ),
        ),
    )

    with pytest.raises(ValueError, match="request binding is not canonical"):
        module.run_runtime_less_native_content_discovery(
            state,
            "app.example.test",
            scope,
            forged,
            output_dir=tmp_path / "native-output",
        )


def test_runtime_less_native_execution_is_bounded_and_starts_no_external_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("first", "second", "third"))
    state, scope = _runtime_less_state(tmp_path, CTF_LAB_CONTEXT)
    module = _native_module()
    limits = module.NativeContentDiscoveryLimits(2, 2)
    plan = module.build_runtime_less_native_content_discovery_plan(
        state,
        "app.example.test",
        scope,
        profile=PROFILE,
        limits=limits,
    )
    transport = _ResponseTransport(lambda url: (404, url.encode("utf-8")))
    executor = InternalHTTPExecutor(None, transport=transport)

    result = module.run_runtime_less_native_content_discovery(
        state,
        "app.example.test",
        scope,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
    )

    assert result.external_commands_started == 0
    assert plan.candidate_requests_planned == 2
    assert len(transport.requests) == 5
    assert all(
        request.url.startswith("https://app.example.test/")
        for request in transport.requests
    )
    executor.close()


def test_runtime_less_native_execution_rejects_programme_configured_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    state, scope = _runtime_less_state(tmp_path, INTERNAL_AUTHORISED_CONTEXT)
    module = _native_module()
    plan = module.build_runtime_less_native_content_discovery_plan(
        state,
        "app.example.test",
        scope,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(10, 10),
    )
    strict_runtime = _runtime(tmp_path / "strict-runtime")

    with pytest.raises(ValueError, match="HTTP executor is not canonical"):
        module.run_runtime_less_native_content_discovery(
            state,
            "app.example.test",
            scope,
            plan,
            http_executor=strict_runtime.http_executor,
            output_dir=tmp_path / "native-output",
        )


def _child_state(runtime) -> ProjectState:
    return _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/start",
                status_code=301,
                content_length=0,
                redirect_location="https://api.example.test/login",
                source="raw/child-headers.txt",
                evidence_ids=["EVID-WP4A-CHILD"],
                tags=[],
            ),
        ),
    )


def _install_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entries: tuple[str, ...],
) -> None:
    wordlist = tmp_path / "wp4a-wordlist.txt"
    wordlist.write_text("\n".join(entries) + "\n", encoding="utf-8")
    monkeypatch.setitem(
        CONTENT_DISCOVERY_PROFILES,
        PROFILE,
        ContentDiscoveryProfileDefinition(
            name=PROFILE,
            description="Synthetic bounded WP4A profile.",
            wordlist=wordlist,
            threads=1,
            output_prefix="native-wp4a",
        ),
    )


class _ResponseTransport(PeerBoundHTTPTransport):
    def __init__(self, responder) -> None:
        self.responder = responder
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        response = self.responder(request.url)
        if len(response) == 2:
            status, body = response
            headers = ()
        else:
            status, headers, body = response
        return HTTPTransportResponse(status_code=status, headers=headers, body=body)


def _executor(runtime, origins: tuple[str, ...], responder):
    from bugslyce.recon.http_enforcement import build_internal_http_executor_view

    executor = build_internal_http_executor_view(
        runtime.http_executor,
        approved_origins=origins,
    )
    transport = _ResponseTransport(responder)
    executor.transport = transport
    return executor, transport


class _ConnectFailureSocket:
    def settimeout(self, _timeout: int) -> None:
        pass

    def connect(self, _address) -> None:
        raise OSError("PRIVATE-CONNECT-DETAIL")

    def close(self) -> None:
        pass


class _EnvironmentFailureTransport(PeerBoundHTTPTransport):
    def __init__(self, failure_url: str, category: str, responder=None) -> None:
        self.failure_url = failure_url
        self.category = category
        self.responder = responder or (
            lambda _url: HTTPTransportResponse(
                status_code=404,
                headers=(),
                body=b"negative",
            )
        )
        self.requests = []
        self.insecure_connection_created = False

    def __call__(self, request):
        self.requests.append(request)
        if request.url != self.failure_url:
            return self.responder(request.url)
        module = importlib.import_module("bugslyce.recon.http_enforcement")
        if self.category == "connect_error":
            module._connect_selected_ipv4(
                request.selected_ipv4,
                443,
                request.timeout_seconds,
                socket_factory=lambda _family, _kind, _protocol: _ConnectFailureSocket(),
            )
        elif self.category == "tls_error":
            def fail_context():
                raise ssl.SSLError("PRIVATE-TLS-DETAIL")

            PeerBoundHTTPTransport(ssl_context_factory=fail_context)(request)
        elif self.category == "tls_configuration_error":
            class InsecureContext:
                verify_mode = ssl.CERT_NONE
                check_hostname = False

            def unexpected_https_connection(*_args, **_kwargs):
                self.insecure_connection_created = True
                raise AssertionError("insecure TLS context reached HTTPS connection")

            PeerBoundHTTPTransport(
                ssl_context_factory=InsecureContext,
                https_connection_factory=unexpected_https_connection,
            )(request)
        else:
            raise AssertionError("unsupported synthetic environment category")
        raise AssertionError("environment failure path unexpectedly returned")


def test_native_http_context_is_sealed_to_exact_programme_work_items_without_runtime_mutation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _child_state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    before = (
        runtime.project.target,
        runtime.programme_scope_policy,
        runtime.target_decision,
        runtime.initial_http_origins,
        runtime.approved_http_origins,
        runtime.http_executor,
    )
    module = _native_module()

    executor = module.build_native_content_discovery_http_executor(
        runtime,
        state,
        orchestration,
    )

    assert isinstance(executor, InternalHTTPExecutor)
    assert tuple(origin.origin_url for origin in executor.configuration.approved_origins) == (
        "https://api.example.test",
        "https://app.example.test",
    )
    assert executor.configuration.maximum_request_starts_per_second == (
        runtime.http_executor.configuration.maximum_request_starts_per_second
    )
    assert executor.configuration.maximum_concurrent_requests == (
        runtime.http_executor.configuration.maximum_concurrent_requests
    )
    assert executor.configuration.user_agent == runtime.http_executor.configuration.user_agent
    assert executor.configuration.identification_headers == (
        runtime.http_executor.configuration.identification_headers
    )
    assert evaluate_raw_scope_destination(
        runtime.programme_scope_policy,
        DESTINATION_HTTP_URL,
        "https://ghost.example.test/",
    ).outcome == OUTCOME_ALLOWED
    with pytest.raises(ValueError, match="origin is not approved"):
        executor.request("https://ghost.example.test/hidden")
    assert (
        runtime.project.target,
        runtime.programme_scope_policy,
        runtime.target_decision,
        runtime.initial_http_origins,
        runtime.approved_http_origins,
        runtime.http_executor,
    ) == before
    executor.close()


def test_native_root_plan_has_explicit_budgets_metadata_and_deduplicates_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("health", "health", "admin"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    limits = module.NativeContentDiscoveryLimits(
        maximum_total_candidate_requests=2,
        maximum_candidate_requests_per_origin=2,
    )

    first = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=limits,
    )
    second = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=limits,
    )

    assert first == second
    assert first.limits == limits
    assert first.baseline_requests_per_origin == 3
    assert first.candidate_requests_eligible == 2
    assert first.candidate_requests_planned == 2
    assert first.candidate_requests_omitted_by_total_limit == 0
    assert tuple(request.url for request in first.requests) == (
        "https://app.example.test/health",
        "https://app.example.test/admin",
    )
    assert all(request.canonical_origin == "https://app.example.test" for request in first.requests)
    assert all(request.depth == 0 for request in first.requests)
    assert all(request.selection_reason == "profile_wordlist" for request in first.requests)
    assert all(request.evidence_ids == () for request in first.requests)


def test_native_root_plan_allocates_truncated_total_fairly_across_origins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("one", "two", "three"))
    module = _native_module()
    origins = tuple(f"https://app-{index:02d}.example.test" for index in range(3))

    plan = module._build_native_content_discovery_plan_for_origins(
        origins,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=5,
            maximum_candidate_requests_per_origin=3,
        ),
    )

    planned_counts = tuple(
        sum(request.canonical_origin == origin for request in plan.requests)
        for origin in origins
    )
    assert planned_counts == (2, 2, 1)
    assert max(planned_counts) - min(planned_counts) <= 1
    assert plan.candidate_requests_eligible == 9
    assert plan.candidate_requests_omitted_by_total_limit == 4


def test_native_root_plan_fills_twenty_origins_and_fairly_caps_later_origins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("one", "two", "three"))
    module = _native_module()
    twenty_origins = tuple(
        f"https://app-{index:02d}.example.test" for index in range(20)
    )
    full_plan = module._build_native_content_discovery_plan_for_origins(
        twenty_origins,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=60,
            maximum_candidate_requests_per_origin=3,
        ),
    )
    assert tuple(
        sum(request.canonical_origin == origin for request in full_plan.requests)
        for origin in twenty_origins
    ) == (3,) * 20

    twenty_one_origins = (
        *twenty_origins,
        "https://app-20.example.test",
    )
    capped_plan = module._build_native_content_discovery_plan_for_origins(
        twenty_one_origins,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=60,
            maximum_candidate_requests_per_origin=3,
        ),
    )
    capped_counts = tuple(
        sum(request.canonical_origin == origin for request in capped_plan.requests)
        for origin in twenty_one_origins
    )
    assert sum(capped_counts) == 60
    assert capped_counts == (3,) * 18 + (2,) * 3
    assert max(capped_counts) - min(capped_counts) <= 1


def test_native_root_contract_rejects_invalid_limits_depth_and_escaping_urls() -> None:
    module = _native_module()

    with pytest.raises(ValueError, match="budget|limit"):
        module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=-1,
            maximum_candidate_requests_per_origin=1,
        )
    with pytest.raises(ValueError, match="budget|limit"):
        module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=1,
            maximum_candidate_requests_per_origin=0,
        )
    with pytest.raises(ValueError, match="budget|limit"):
        module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=35_061,
            maximum_candidate_requests_per_origin=1,
        )
    with pytest.raises(ValueError, match="budget|limit"):
        module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=1,
            maximum_candidate_requests_per_origin=4_097,
        )
    with pytest.raises(ValueError, match="depth"):
        module.NativeContentDiscoveryRequest(
            url="https://app.example.test/admin",
            canonical_origin="https://app.example.test",
            depth=-1,
            selection_reason="profile_wordlist",
            evidence_ids=(),
        )
    with pytest.raises(ValueError, match="HTTP|URL|origin"):
        module.NativeContentDiscoveryRequest(
            url="mailto:security@example.test",
            canonical_origin="https://app.example.test",
            depth=0,
            selection_reason="profile_wordlist",
            evidence_ids=(),
        )
    with pytest.raises(ValueError, match="origin"):
        module.NativeContentDiscoveryRequest(
            url="https://ghost.example.test/admin",
            canonical_origin="https://app.example.test",
            depth=0,
            selection_reason="profile_wordlist",
            evidence_ids=(),
        )
    with pytest.raises(ValueError, match="category"):
        module.NativeContentDiscoveryCandidateFailure(
            request_url="https://app.example.test/admin",
            category="tls_configuration_error",
        )


def test_native_plan_rejects_programme_plan_from_a_different_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime_a = _runtime(tmp_path / "a")
    runtime_b = _runtime(tmp_path / "b")
    state_a = _state(runtime_a)
    plan_a = build_programme_orchestration_plan(runtime_a, state_a)
    module = _native_module()

    with pytest.raises(ValueError, match="runtime|binding|project state"):
        module.build_native_content_discovery_plan(
            runtime_b,
            _state(runtime_b),
            plan_a,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(
                maximum_total_candidate_requests=1,
                maximum_candidate_requests_per_origin=1,
            ),
        )


def test_conventional_negative_baseline_uses_native_execution_and_internal_artefact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("missing", "admin"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )

    def respond(url: str) -> tuple[int, bytes]:
        if ".bugslyce-negative-" in url:
            return 404, f"variable negative {url[-1]}".encode()
        if url.endswith("/missing"):
            return 404, b"candidate-specific missing page"
        return 200, b"administration console"

    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        respond,
    )
    progress = []
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
        progress_callback=progress.append,
    )

    assert len(transport.requests) == 5
    assert tuple(request.url for request in transport.requests[3:]) == tuple(
        request.url for request in plan.requests
    )
    assert all(request.selected_ipv4 == "192.0.2.44" for request in transport.requests)
    assert all(
        ("User-Agent", executor.configuration.user_agent) in request.headers
        for request in transport.requests
    )
    assert result.external_commands_started == 0
    assert result.origin_results[0].baseline_decision.classification == "conventional_negative"
    assert result.origin_results[0].baseline_decision.selected_policy == (
        "native_conventional_negative"
    )
    assert result.origin_results[0].suppressed_candidate_count == 1
    assert result.origin_results[0].retained_candidate_count == 1
    artifact = result.artifacts[0]
    assert artifact.artifact_type == "content_discovery_internal"
    assert artifact.canonical_origin == "https://app.example.test"
    assert artifact.profile == PROFILE
    assert artifact.selection_reason == "profile_wordlist"
    output = artifact.path.read_text(encoding="utf-8")
    assert "/admin" in output
    assert "/missing" not in output
    assert not artifact.path.name.startswith("gobuster")
    assert [event.completed for event in progress] == [0, 1, 2]
    baseline = json.loads(result.baseline_artifact_path.read_text(encoding="utf-8"))
    assert baseline["origins"][0]["baseline_equivalent_candidate_count"] == 1
    assert baseline["origins"][0]["retained_candidate_count"] == 1
    coverage = json.loads(result.coverage_artifact_path.read_text(encoding="utf-8"))
    assert result.coverage_artifact_path.name == (
        "content_discovery_native_coverage.json"
    )
    assert coverage == {
        "schema_version": "1.0",
        "created_by": "bugslyce-native-content-coverage",
        "profile": PROFILE,
        "candidate_requests_eligible": 2,
        "candidate_requests_planned": 2,
        "candidate_requests_omitted_by_total_limit": 0,
        "candidate_requests_attempted": 2,
        "candidate_responses_observed": 2,
        "failed_candidate_count": 0,
        "redirect_followup_failure_count": 0,
        "candidate_requests_unattempted": 0,
        "origins": [
            {
                "canonical_origin": "https://app.example.test",
                "selected_baseline_policy": "native_conventional_negative",
                "candidate_requests_eligible": 2,
                "candidate_requests_planned": 2,
                "candidate_requests_omitted_by_total_limit": 0,
                "candidate_requests_attempted": 2,
                "candidate_responses_observed": 2,
                "suppressed_candidate_count": 1,
                "retained_candidate_count": 1,
                "failed_candidate_count": 0,
                "redirect_followup_failure_count": 0,
                "candidate_requests_unattempted": 0,
                "failed_candidates": [],
                "redirect_followup_failures": [],
            }
        ],
    }
    executor.close()


def test_native_output_transaction_refuses_preexisting_coverage_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(1, 1),
    )
    output_dir = tmp_path / "native-output"
    output_dir.mkdir()
    coverage_path = output_dir / "content_discovery_native_coverage.json"
    coverage_path.write_text("do not replace\n", encoding="utf-8")
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (404, b"unused"),
    )

    with pytest.raises(ValueError, match="artefact path already exists"):
        module.run_native_content_discovery(
            runtime,
            state,
            orchestration,
            plan,
            http_executor=executor,
            output_dir=output_dir,
        )

    assert transport.requests == []
    assert coverage_path.read_text(encoding="utf-8") == "do not replace\n"
    assert not (output_dir / "content_discovery_baseline.json").exists()
    executor.close()


def test_native_progress_reaches_known_total_without_changing_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = tuple(f"candidate-{index:03d}" for index in range(25))
    _install_profile(monkeypatch, tmp_path, entries)
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=25,
            maximum_candidate_requests_per_origin=25,
        ),
    )

    def respond(url: str) -> tuple[int, bytes]:
        if ".bugslyce-negative-" in url:
            return 404, url.encode("utf-8")
        return 404, b"candidate response"

    progress = []
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        respond,
    )
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "with-progress",
        token_factory=iter(("one", "two", "three")).__next__,
        progress_callback=progress.append,
    )

    assert progress[0].completed == 0
    assert progress[0].total == 25
    assert progress[-1].completed == progress[-1].total == 25
    assert all(event.trusted for event in progress)
    assert all(
        earlier.completed <= later.completed
        for earlier, later in zip(progress, progress[1:])
    )
    assert len(progress) < len(plan.requests)
    assert len(progress) <= 1 + 20
    assert result.origin_results[0].suppressed_candidate_count == 25
    assert result.origin_results[0].retained_candidate_count == 0
    assert result.artifacts[0].path.read_bytes() == b""
    assert tuple(request.url for request in transport.requests[3:]) == tuple(
        request.url for request in plan.requests
    )
    executor.close()


def test_native_multi_origin_elapsed_is_candidate_time_for_named_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate",))
    runtime = _runtime(tmp_path / "runtime")
    state = _child_state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=1,
        ),
    )
    origins = tuple(dict.fromkeys(request.canonical_origin for request in plan.requests))
    assert len(origins) == 2

    now = [0.0]
    monkeypatch.setattr(
        module,
        "time",
        type("FakeTime", (), {"monotonic": staticmethod(lambda: now[0])}),
    )
    candidate_durations = {origins[0]: 11.0, origins[1]: 3.0}

    def respond(url: str) -> tuple[int, bytes]:
        origin = http_origin_from_url(url)
        assert origin is not None
        if ".bugslyce-negative-" in url:
            now[0] += 1.0
            return 404, url.encode("utf-8")
        now[0] += candidate_durations[origin.origin_url]
        return 404, b"candidate response"

    progress = []
    executor, transport = _executor(runtime, origins, respond)
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "multi-origin-progress",
        token_factory=iter(("a", "b", "c", "d", "e", "f")).__next__,
        progress_callback=progress.append,
    )

    request_origins = tuple(
        http_origin_from_url(request.url).origin_url
        for request in transport.requests
    )
    assert request_origins == (
        origins[0],
        origins[0],
        origins[0],
        origins[1],
        origins[1],
        origins[1],
        origins[0],
        origins[1],
    )
    assert tuple(request.url for request in transport.requests[-2:]) == tuple(
        request.url for request in plan.requests
    )
    for origin in origins:
        events = [event for event in progress if event.origin == origin]
        assert [event.completed for event in events] == [0, 1]
        assert [event.total for event in events] == [1, 1]
        assert events[0].elapsed_seconds == 0.0
        assert events[-1].elapsed_seconds == candidate_durations[origin]
    assert tuple(item.canonical_origin for item in result.origin_results) == origins
    executor.close()


def test_multi_origin_native_discovery_skips_refused_origin_and_collects_usable_origins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate-one", "candidate-two"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/http-root",
                status_code=301,
                content_length=0,
                redirect_location="http://app.example.test/",
                source="raw/http-root.txt",
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            ),
            DiscoveredPath(
                url="https://app.example.test/http-8080-root",
                status_code=301,
                content_length=0,
                redirect_location="http://app.example.test:8080/",
                source="raw/http-8080-root.txt",
                evidence_ids=["EVID-HTTP-0002"],
                tags=[],
            ),
        ),
    )
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(4, 2),
    )
    unstable_bodies = iter(
        (
            b"a" * 5482,
            b"b" * 5482,
            b"c" * 5482,
        )
    )

    def respond(url: str) -> tuple[int, bytes]:
        origin = http_origin_from_url(url)
        assert origin is not None
        if ".bugslyce-negative-" in url:
            if origin.origin_url == "http://app.example.test:8080":
                return 403, next(unstable_bodies)
            return 404, url.encode("utf-8")
        return 200, f"retained {origin.origin_url}".encode("utf-8")

    origins = tuple(dict.fromkeys(request.canonical_origin for request in plan.requests))
    executor, transport = _executor(runtime, origins, respond)
    progress = []

    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "multi-origin-output",
        token_factory=iter(
            ("one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
        ).__next__,
        progress_callback=progress.append,
    )

    by_origin = {item.canonical_origin: item for item in result.origin_results}
    refused = by_origin["http://app.example.test:8080"]
    assert refused.baseline_decision.classification == "unstable"
    assert refused.baseline_decision.selected_policy == "refuse"
    assert refused.suppressed_candidate_count == 0
    assert refused.retained_candidate_count == 0
    assert "varied in status, length, body hash" in (
        refused.baseline_decision.failure_or_instability_reason or ""
    ).lower()
    assert {
        item.canonical_origin
        for item in result.origin_results
        if item.baseline_decision.selected_policy != "refuse"
    } == {"http://app.example.test", "https://app.example.test"}
    assert {artifact.canonical_origin for artifact in result.artifacts} == {
        "http://app.example.test",
        "https://app.example.test",
    }
    candidate_origins = [
        http_origin_from_url(request.url).origin_url
        for request in transport.requests
        if ".bugslyce-negative-" not in request.url
    ]
    assert candidate_origins == [
        "http://app.example.test",
        "http://app.example.test",
        "https://app.example.test",
    ]
    assert [
        event.completed
        for event in progress
        if event.origin == "http://app.example.test:8080"
    ] == [0]
    baseline = json.loads(result.baseline_artifact_path.read_text(encoding="utf-8"))
    assert [item["origin"] for item in baseline["origins"]] == [
        "http://app.example.test/",
        "http://app.example.test:8080/",
        "https://app.example.test/",
    ]
    refused_payload = baseline["origins"][1]
    assert refused_payload["selected_policy"] == "refuse"
    assert {item["terminal_http_status"] for item in refused_payload["observations"]} == {
        403
    }
    assert {item["response_bytes"] for item in refused_payload["observations"]} == {
        5482
    }
    assert len(
        {item["body_sha256"] for item in refused_payload["observations"]}
    ) == 3
    assert not any("8080" in artifact.path.name for artifact in result.artifacts)
    coverage = json.loads(result.coverage_artifact_path.read_text(encoding="utf-8"))
    assert coverage["candidate_requests_eligible"] == 6
    assert coverage["candidate_requests_planned"] == 4
    assert coverage["candidate_requests_omitted_by_total_limit"] == 2
    assert coverage["candidate_requests_attempted"] == 3
    assert coverage["candidate_responses_observed"] == 3
    assert coverage["failed_candidate_count"] == 0
    assert coverage["candidate_requests_unattempted"] == 1
    assert coverage["candidate_requests_eligible"] == (
        coverage["candidate_requests_planned"]
        + coverage["candidate_requests_omitted_by_total_limit"]
    )
    assert all(
        item["candidate_requests_eligible"]
        == item["candidate_requests_planned"]
        + item["candidate_requests_omitted_by_total_limit"]
        for item in coverage["origins"]
    )
    refused_coverage = next(
        item
        for item in coverage["origins"]
        if item["canonical_origin"] == "http://app.example.test:8080"
    )
    assert refused_coverage["selected_baseline_policy"] == "refuse"
    assert refused_coverage["candidate_requests_eligible"] == 2
    assert refused_coverage["candidate_requests_planned"] == 1
    assert refused_coverage["candidate_requests_omitted_by_total_limit"] == 1
    assert refused_coverage["candidate_requests_attempted"] == 0
    assert refused_coverage["candidate_responses_observed"] == 0
    assert refused_coverage["failed_candidate_count"] == 0
    assert refused_coverage["candidate_requests_unattempted"] == 1
    assert refused_coverage["failed_candidates"] == []
    executor.close()


def test_native_progress_callback_failure_remains_hard_before_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=1,
            maximum_candidate_requests_per_origin=1,
        ),
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (404, b"unused"),
    )

    def stop_progress(_event) -> None:
        raise RuntimeError("synthetic progress callback failure")

    with pytest.raises(RuntimeError, match="progress callback failure"):
        module.run_native_content_discovery(
            runtime,
            state,
            orchestration,
            plan,
            http_executor=executor,
            output_dir=tmp_path / "callback-failure",
            token_factory=iter(("one", "two", "three")).__next__,
            progress_callback=stop_progress,
        )

    assert transport.requests == []
    executor.close()


def test_hard_native_candidate_failure_preserves_baseline_without_reporting_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(
        monkeypatch,
        tmp_path,
        tuple(f"candidate-{index}" for index in range(5)),
    )
    runtime = _runtime(tmp_path / "runtime")
    state = _child_state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=10,
            maximum_candidate_requests_per_origin=5,
        ),
    )
    planned_origins = tuple(
        dict.fromkeys(request.canonical_origin for request in plan.requests)
    )

    unstable_bodies = iter((b"a" * 64, b"b" * 64, b"c" * 64))

    def respond(url: str) -> tuple[int, bytes]:
        if url.endswith("/candidate-2"):
            raise HTTPTransportFailure("invalid_resolver_result")
        if ".bugslyce-negative-" in url:
            if "api.example.test" in url:
                return 403, next(unstable_bodies)
            return 404, url.encode("utf-8")
        return 404, b"candidate response"

    progress = []
    executor, _transport = _executor(
        runtime,
        planned_origins,
        respond,
    )
    with pytest.raises(HTTPTransportFailure, match="invalid_resolver_result"):
        module.run_native_content_discovery(
            runtime,
            state,
            orchestration,
            plan,
            http_executor=executor,
            output_dir=tmp_path / "failed-progress",
            token_factory=iter(
                ("one", "two", "three", "four", "five", "six")
            ).__next__,
            progress_callback=progress.append,
        )

    assert progress
    assert progress[-1].completed < progress[-1].total
    assert all(event.completed != event.total for event in progress)
    baseline_path = tmp_path / "failed-progress" / "content_discovery_baseline.json"
    assert baseline_path.is_file()
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert payload["created_by"] == "bugslyce-native-content-baseline"
    assert [item["origin"].removesuffix("/") for item in payload["origins"]] == list(
        planned_origins
    )
    by_origin = {
        item["origin"].removesuffix("/"): item for item in payload["origins"]
    }
    assert by_origin["https://app.example.test"]["classification"] == (
        "conventional_negative"
    )
    assert by_origin["https://app.example.test"]["selected_policy"] == (
        "native_conventional_negative"
    )
    assert by_origin["https://api.example.test"]["classification"] == "unstable"
    assert by_origin["https://api.example.test"]["selected_policy"] == "refuse"
    assert "varied in status, length, body hash" in by_origin[
        "https://api.example.test"
    ]["failure_or_instability_reason"].lower()
    assert all(item["completed_observations"] == 3 for item in payload["origins"])
    assert all(
        item["baseline_equivalent_candidate_count"] == 0
        for item in payload["origins"]
    )
    assert all(item["retained_candidate_count"] == 0 for item in payload["origins"])
    assert tuple(
        (tmp_path / "failed-progress").glob("content-discovery-internal-*.txt")
    ) == ()
    executor.close()


@pytest.mark.parametrize(
    ("failure_kind", "expected_category"),
    (
        pytest.param("timeout", "timeout", id="timeout"),
        pytest.param("oserror", "transport_error", id="transport-error"),
    ),
)
def test_native_candidate_transport_failure_does_not_prevent_later_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    expected_category: str,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("transport-failure", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    failing_url = "https://app.example.test/transport-failure"
    later_url = "https://app.example.test/later-negative"
    expected_before_failure = [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        failing_url,
    ]

    def respond(url: str):
        if url == failing_url:
            if failure_kind == "timeout":
                raise TimeoutError("synthetic candidate timeout")
            raise OSError("synthetic candidate transport error")
        return 404, b"conventional negative"

    progress = []
    output_dir = tmp_path / "native-output"
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPTransportFailure as exc:
            assert exc.category == expected_category
            assert [request.url for request in transport.requests] == (
                expected_before_failure
            )
            assert all(request.url != later_url for request in transport.requests)
            assert [event.completed for event in progress] == [0]
            baseline_path = output_dir / "content_discovery_baseline.json"
            assert baseline_path.is_file()
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            origin = baseline["origins"][0]
            assert origin["completed_observations"] == 3
            assert origin["classification"] == "conventional_negative"
            assert origin["baseline_equivalent_candidate_count"] == 0
            assert origin["retained_candidate_count"] == 0
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        assert [request.url for request in transport.requests] == [
            *expected_before_failure,
            later_url,
        ]
        assert [event.completed for event in progress] == [0, 1, 2]
        assert progress[-1].total == 2
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 0
        assert origin_result.failed_candidate_count == 1
        assert origin_result.failed_candidates == (
            module.NativeContentDiscoveryCandidateFailure(
                request_url=failing_url,
                category=expected_category,
            ),
        )
        coverage_text = result.coverage_artifact_path.read_text(encoding="utf-8")
        coverage = json.loads(coverage_text)
        assert coverage["candidate_requests_planned"] == 2
        assert coverage["candidate_requests_attempted"] == 2
        assert coverage["candidate_responses_observed"] == 1
        assert coverage["failed_candidate_count"] == 1
        assert coverage["candidate_requests_unattempted"] == 0
        assert coverage["origins"] == [
            {
                "canonical_origin": "https://app.example.test",
                "selected_baseline_policy": "native_conventional_negative",
                "candidate_requests_eligible": 2,
                "candidate_requests_planned": 2,
                "candidate_requests_omitted_by_total_limit": 0,
                "candidate_requests_attempted": 2,
                "candidate_responses_observed": 1,
                "suppressed_candidate_count": 1,
                    "retained_candidate_count": 0,
                    "failed_candidate_count": 1,
                    "redirect_followup_failure_count": 0,
                    "candidate_requests_unattempted": 0,
                "failed_candidates": [
                    {
                        "request_url": failing_url,
                        "category": expected_category,
                        }
                    ],
                    "redirect_followup_failures": [],
                }
            ]
        assert "synthetic candidate timeout" not in coverage_text
        assert "synthetic candidate transport error" not in coverage_text
        baseline = json.loads(
            result.baseline_artifact_path.read_text(encoding="utf-8")
        )
        baseline_origin = baseline["origins"][0]
        assert baseline_origin["baseline_equivalent_candidate_count"] == 1
        assert baseline_origin["retained_candidate_count"] == 0
        assert "failed_candidates" not in baseline_origin
        assert "failed_candidate_count" not in baseline_origin
        retained_output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/transport-failure" not in retained_output
        assert expected_category not in retained_output
    finally:
        executor.close()


@pytest.mark.parametrize(
    "category",
    ("dns_error", "no_usable_ipv4", "connect_error", "tls_error"),
)
def test_native_candidate_environment_failure_does_not_prevent_later_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    category: str,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("environment-failure", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    failing_url = "https://app.example.test/environment-failure"
    later_url = "https://app.example.test/later-negative"
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (404, b"conventional negative"),
    )
    if category in {"dns_error", "no_usable_ipv4"}:
        resolver_calls = 0

        def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
            nonlocal resolver_calls
            resolver_calls += 1
            if resolver_calls == 4:
                if category == "dns_error":
                    raise OSError("PRIVATE-RESOLVER-DETAIL")
                return ()
            return ("192.0.2.44",)

        runtime.http_executor._ipv4_resolver = resolver
        executor._ipv4_resolver = resolver
    else:
        transport = _EnvironmentFailureTransport(failing_url, category)
        executor.transport = transport

    progress = []
    output_dir = tmp_path / "native-output"
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPTransportFailure as exc:
            assert exc.category == category
            assert [request.url for request in transport.requests] == [
                "https://app.example.test/.bugslyce-negative-one",
                "https://app.example.test/.bugslyce-negative-two",
                "https://app.example.test/.bugslyce-negative-three",
                *(
                    [failing_url]
                    if category in {"connect_error", "tls_error"}
                    else []
                ),
            ]
            assert all(request.url != later_url for request in transport.requests)
            assert [event.completed for event in progress] == [0]
            assert (output_dir / "content_discovery_baseline.json").is_file()
            assert not (output_dir / "content_discovery_native_coverage.json").exists()
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        assert [request.url for request in transport.requests] == [
            "https://app.example.test/.bugslyce-negative-one",
            "https://app.example.test/.bugslyce-negative-two",
            "https://app.example.test/.bugslyce-negative-three",
            *(
                [failing_url]
                if category in {"connect_error", "tls_error"}
                else []
            ),
            later_url,
        ]
        assert [event.completed for event in progress] == [0, 1, 2]
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 0
        assert origin_result.failed_candidate_count == 1
        assert origin_result.failed_candidates == (
            module.NativeContentDiscoveryCandidateFailure(
                request_url=failing_url,
                category=category,
            ),
        )
        coverage_text = result.coverage_artifact_path.read_text(encoding="utf-8")
        coverage = json.loads(coverage_text)
        assert coverage["candidate_requests_planned"] == 2
        assert coverage["candidate_requests_attempted"] == 2
        assert coverage["candidate_responses_observed"] == 1
        assert coverage["failed_candidate_count"] == 1
        assert coverage["candidate_requests_unattempted"] == 0
        assert coverage["origins"][0]["failed_candidates"] == [
            {"request_url": failing_url, "category": category}
        ]
        assert "PRIVATE-" not in coverage_text
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/environment-failure" not in output
        assert category not in output
        assert "/later-negative" not in output
    finally:
        executor.close()


def test_native_candidate_insecure_tls_context_remains_hard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("insecure-tls-context", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    failing_url = "https://app.example.test/insecure-tls-context"
    later_url = "https://app.example.test/later-negative"
    executor, _base_transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (404, b"conventional negative"),
    )
    transport = _EnvironmentFailureTransport(
        failing_url,
        "tls_configuration_error",
    )
    executor.transport = transport
    progress = []
    output_dir = tmp_path / "native-output"
    try:
        with pytest.raises(HTTPTransportFailure) as exc_info:
            module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )

        assert exc_info.value.category == "tls_configuration_error"
        assert [request.url for request in transport.requests] == [
            "https://app.example.test/.bugslyce-negative-one",
            "https://app.example.test/.bugslyce-negative-two",
            "https://app.example.test/.bugslyce-negative-three",
            failing_url,
        ]
        assert later_url not in [request.url for request in transport.requests]
        assert not transport.insecure_connection_created
        assert [event.completed for event in progress] == [0]
        assert (output_dir / "content_discovery_baseline.json").is_file()
        assert not (output_dir / "content_discovery_native_coverage.json").exists()
        assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
    finally:
        executor.close()


def test_native_environment_failure_during_baseline_remains_origin_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=1,
            maximum_candidate_requests_per_origin=1,
        ),
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (404, b"must not be reached"),
    )

    def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        raise OSError("PRIVATE-BASELINE-RESOLVER-DETAIL")

    runtime.http_executor._ipv4_resolver = resolver
    executor._ipv4_resolver = resolver
    output_dir = tmp_path / "native-output"
    try:
        with pytest.raises(module.NativeContentDiscoveryBaselineRefused) as exc_info:
            module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
            )

        decision = exc_info.value.decisions[0]
        assert decision.classification == "failed"
        assert decision.selected_policy == "refuse"
        assert decision.completed_observations == 0
        assert all(
            item.failure_reason == "transport_failure:dns_error"
            for item in decision.observations
        )
        assert transport.requests == []
        payload_text = exc_info.value.baseline_artifact_path.read_text(encoding="utf-8")
        assert "PRIVATE-BASELINE-RESOLVER-DETAIL" not in payload_text
        assert not (output_dir / "content_discovery_native_coverage.json").exists()
    finally:
        executor.close()


@pytest.mark.parametrize(
    ("failure_stage", "category"),
    (
        pytest.param("resolver", "dns_error", id="redirect-resolver"),
        pytest.param("exchange", "tls_error", id="redirect-exchange"),
    ),
)
def test_redirect_followup_environment_failure_retains_source_response_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    category: str,
) -> None:
    _install_profile(
        monkeypatch,
        tmp_path,
        ("redirect-environment-failure", "later-negative"),
    )
    source_origin = "http://app.example.test"
    destination_origin = "https://app.example.test"
    runtime = _runtime(
        tmp_path / "runtime",
        origins=(f"{source_origin}/", f"{destination_origin}/"),
    )
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=4,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = f"{source_origin}/redirect-environment-failure"
    destination_url = f"{destination_origin}/permitted-followup"
    later_url = f"{source_origin}/later-negative"

    def response_for(url: str) -> HTTPTransportResponse:
        if url == candidate_url:
            return HTTPTransportResponse(
                status_code=302,
                headers=(("Location", destination_url),),
                body=b"permitted redirect response",
            )
        return HTTPTransportResponse(
            status_code=404,
            headers=(),
            body=b"conventional negative",
        )

    executor, base_transport = _executor(
        runtime,
        (source_origin, destination_origin),
        lambda url: (
            (302, (("Location", destination_url),), b"permitted redirect response")
            if url == candidate_url
            else (404, b"conventional negative")
        ),
    )
    resolver_calls = 0
    if failure_stage == "resolver":
        def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
            nonlocal resolver_calls
            resolver_calls += 1
            if resolver_calls == 8:
                raise OSError("PRIVATE-REDIRECT-RESOLVER-DETAIL")
            return ("192.0.2.44",)

        runtime.http_executor._ipv4_resolver = resolver
        executor._ipv4_resolver = resolver
        transport = base_transport
    else:
        transport = _EnvironmentFailureTransport(
            destination_url,
            category,
            response_for,
        )
        executor.transport = transport

    progress = []
    output_dir = tmp_path / "native-output"
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three", "four", "five", "six")).__next__,
                progress_callback=progress.append,
            )
        except HTTPTransportFailure as exc:
            assert exc.category == category
            transmitted = [request.url for request in transport.requests]
            assert candidate_url in transmitted
            assert (destination_url in transmitted) == (
                failure_stage == "exchange"
            )
            assert later_url not in transmitted
            assert (output_dir / "content_discovery_baseline.json").is_file()
            assert not (output_dir / "content_discovery_native_coverage.json").exists()
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        transmitted = [request.url for request in transport.requests]
        assert candidate_url in transmitted
        assert (destination_url in transmitted) == (failure_stage == "exchange")
        assert later_url in transmitted
        source_result = next(
            item for item in result.origin_results if item.canonical_origin == source_origin
        )
        assert source_result.suppressed_candidate_count == 1
        assert source_result.retained_candidate_count == 1
        assert source_result.failed_candidate_count == 0
        assert source_result.redirect_followup_failure_count == 1
        followup_failure = source_result.redirect_followup_failures[0]
        assert followup_failure.request_url == candidate_url
        assert followup_failure.source_url == candidate_url
        assert followup_failure.destination_url == destination_url
        assert followup_failure.status_code == 302
        assert followup_failure.category == category
        coverage_text = result.coverage_artifact_path.read_text(encoding="utf-8")
        coverage = json.loads(coverage_text)
        assert coverage["candidate_requests_planned"] == 4
        assert coverage["candidate_requests_attempted"] == 4
        assert coverage["candidate_responses_observed"] == 4
        assert coverage["failed_candidate_count"] == 0
        assert coverage["redirect_followup_failure_count"] == 1
        assert coverage["candidate_requests_unattempted"] == 0
        assert coverage["origins"][0]["redirect_followup_failures"] == [
            {
                "request_url": candidate_url,
                "source_url": candidate_url,
                "destination_url": destination_url,
                "status_code": 302,
                "category": category,
            }
        ]
        assert "PRIVATE-" not in coverage_text
        source_artifact = next(
            item.path
            for item in result.artifacts
            if item.canonical_origin == source_origin
        ).read_text(encoding="utf-8")
        assert "/redirect-environment-failure (Status: 302)" in source_artifact
        assert (
            f"[redirect follow-up failed: {category} --> {destination_url}]"
            in source_artifact
        )
        assert "/later-negative" not in source_artifact
    finally:
        executor.close()


def test_stable_fallback_native_execution_uses_exact_response_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("same", "same-length-different"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )

    def respond(url: str) -> tuple[int, bytes]:
        if url.endswith("/same-length-different"):
            return 200, b"stable sheLl"
        return 200, b"stable shell"

    executor, _transport = _executor(
        runtime,
        ("https://app.example.test",),
        respond,
    )
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
    )

    origin_result = result.origin_results[0]
    assert origin_result.baseline_decision.classification == "stable_fallback"
    assert origin_result.baseline_decision.selected_policy == (
        "internal_exact_body_comparator"
    )
    assert origin_result.suppressed_candidate_count == 1
    assert origin_result.retained_candidate_count == 1
    output = result.artifacts[0].path.read_text(encoding="utf-8")
    assert "/same-length-different" in output
    assert "/same (Status:" not in output
    executor.close()


def test_cross_origin_first_hop_redirect_is_compared_without_destination_transmission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("same", "different"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )

    def respond(url: str):
        if url.endswith("/different"):
            return (
                302,
                (("Location", "https://status.example.test/different"),),
                b"materially different first-hop redirect",
            )
        return (
            301,
            (("Location", "https://docs.example.test/landing"),),
            b"stable first-hop redirect",
        )

    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        respond,
    )
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
    )

    assert len(transport.requests) == 5
    assert all(
        request.url.startswith("https://app.example.test/")
        for request in transport.requests
    )
    assert all("docs.example.test" not in request.url for request in transport.requests)
    assert all("status.example.test" not in request.url for request in transport.requests)
    origin_result = result.origin_results[0]
    assert origin_result.baseline_decision.classification == "stable_redirect_fallback"
    assert origin_result.baseline_decision.completed_observations == 3
    assert origin_result.suppressed_candidate_count == 1
    assert origin_result.retained_candidate_count == 1
    output = result.artifacts[0].path.read_text(encoding="utf-8")
    assert "/different" in output
    assert "[--> https://status.example.test/different]" in output
    assert "/same" not in output
    baseline = json.loads(result.baseline_artifact_path.read_text(encoding="utf-8"))
    assert baseline["created_by"] == "bugslyce-native-content-baseline"
    observations = baseline["origins"][0]["observations"]
    assert all(item["observation_status"] == "complete" for item in observations)
    assert all(item["terminal_http_status"] == 301 for item in observations)
    assert all(item["response_bytes"] == 25 for item in observations)
    assert all(item["body_sha256"] for item in observations)
    assert all(
        item["final_url"] == item["request_url"]
        for item in observations
    )
    assert all(item["failure_reason"] is None for item in observations)
    assert all(
        item["refused_redirect"]["destination_url"]
        == "https://docs.example.test/landing"
        for item in observations
    )
    executor.close()


@pytest.mark.parametrize(
    "malformed_headers",
    (
        pytest.param((), id="missing-location"),
        pytest.param(
            (("Location", "/first"), ("Location", "/second")),
            id="duplicate-location",
        ),
    ),
)
def test_malformed_redirect_location_candidate_does_not_prevent_later_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed_headers: tuple[tuple[str, str], ...],
) -> None:
    _install_profile(monkeypatch, tmp_path, ("malformed", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = "https://app.example.test/malformed"
    later_url = "https://app.example.test/later-negative"
    expected_before_refusal = [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        candidate_url,
    ]

    def respond(url: str):
        if url == candidate_url:
            return 302, malformed_headers, b"malformed redirect response"
        return 404, b"conventional negative"

    progress = []
    output_dir = tmp_path / "native-output"
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPRedirectRefused as exc:
            assert exc.reason == "malformed_location"
            assert [request.url for request in transport.requests] == (
                expected_before_refusal
            )
            assert all(request.url != later_url for request in transport.requests)
            assert [event.completed for event in progress] == [0]
            baseline_path = output_dir / "content_discovery_baseline.json"
            assert baseline_path.is_file()
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            assert baseline["origins"][0]["completed_observations"] == 3
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        assert [request.url for request in transport.requests] == [
            *expected_before_refusal,
            later_url,
        ]
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 1
        assert [event.completed for event in progress] == [0, 1, 2]
        assert progress[-1].total == 2
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/malformed (Status: 302)" in output
        assert "[redirect refused: malformed_location]" in output
        assert "[--> None]" not in output
        assert "/later-negative" not in output
    finally:
        executor.close()


def test_stable_malformed_redirect_baseline_is_serialized_and_compared_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("same-malformed", "different-malformed"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )

    def respond(url: str):
        body = (
            b"different malformed response"
            if url.endswith("/different-malformed")
            else b"stable malformed response"
        )
        return 302, (), body

    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        respond,
    )
    try:
        result = module.run_native_content_discovery(
            runtime,
            state,
            orchestration,
            plan,
            http_executor=executor,
            output_dir=tmp_path / "native-output",
            token_factory=iter(("one", "two", "three")).__next__,
        )

        assert len(transport.requests) == 5
        origin_result = result.origin_results[0]
        assert origin_result.baseline_decision.classification == "stable_redirect_fallback"
        assert origin_result.baseline_decision.selected_policy == (
            "internal_exact_body_comparator"
        )
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 1
        baseline = json.loads(
            result.baseline_artifact_path.read_text(encoding="utf-8")
        )
        observations = baseline["origins"][0]["observations"]
        assert all(item["observation_status"] == "complete" for item in observations)
        assert all(item["terminal_http_status"] == 302 for item in observations)
        assert all(
            item["refused_redirect"]
            == {
                "status_code": 302,
                "source_url": item["request_url"],
                "destination_url": None,
                "reason": "malformed_location",
            }
            for item in observations
        )
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/same-malformed" not in output
        assert "/different-malformed (Status: 302)" in output
        assert "[redirect refused: malformed_location]" in output
        assert "[--> None]" not in output
    finally:
        executor.close()


def test_query_refused_first_hop_is_compared_and_later_native_candidate_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("query-redirect", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    query_destination = "https://app.example.test/landing?from=redirect"

    def respond(url: str):
        if url.endswith("/query-redirect"):
            return (
                302,
                (("Location", "/landing?from=redirect"),),
                b"query-bearing first-hop redirect",
            )
        return 404, b"conventional negative"

    progress = []
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
        progress_callback=progress.append,
    )

    assert len(transport.requests) == 5  # three baselines and two candidates
    assert [request.url for request in transport.requests].count(
        "https://app.example.test/later-negative"
    ) == 1
    assert all(request.url != query_destination for request in transport.requests)
    assert all("?from=redirect" not in request.url for request in transport.requests)
    origin_result = result.origin_results[0]
    assert origin_result.suppressed_candidate_count == 1
    assert origin_result.retained_candidate_count == 1
    assert [event.completed for event in progress] == [0, 1, 2]
    assert progress[-1].total == 2
    output = result.artifacts[0].path.read_text(encoding="utf-8")
    assert "/query-redirect" in output
    assert f"[--> {query_destination}]" in output
    assert "/later-negative" not in output
    executor.close()


def test_unsupported_redirect_candidate_is_retained_and_later_candidate_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("unsupported", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = "https://app.example.test/unsupported"
    refused_destination = "ftp://app.example.test/archive"
    later_url = "https://app.example.test/later-negative"
    expected_before_refusal = [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        candidate_url,
    ]

    def respond(url: str):
        if url == candidate_url:
            return (
                302,
                (("Location", refused_destination),),
                b"unsupported redirect response",
            )
        return 404, b"conventional negative"

    progress = []
    output_dir = tmp_path / "native-output"
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPRedirectRefused as exc:
            assert exc.reason == "unsupported_redirect"
            assert [request.url for request in transport.requests] == (
                expected_before_refusal
            )
            assert all(
                request.url != refused_destination for request in transport.requests
            )
            assert all(request.url != later_url for request in transport.requests)
            assert [event.completed for event in progress] == [0]
            baseline_path = output_dir / "content_discovery_baseline.json"
            assert baseline_path.is_file()
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            assert baseline["origins"][0]["completed_observations"] == 3
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        assert [request.url for request in transport.requests] == [
            *expected_before_refusal,
            later_url,
        ]
        assert all(request.url != refused_destination for request in transport.requests)
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 1
        assert origin_result.failed_candidate_count == 0
        assert [event.completed for event in progress] == [0, 1, 2]
        assert progress[-1].total == 2
        coverage = json.loads(
            result.coverage_artifact_path.read_text(encoding="utf-8")
        )
        assert coverage["candidate_requests_planned"] == 2
        assert coverage["candidate_requests_attempted"] == 2
        assert coverage["candidate_responses_observed"] == 2
        assert coverage["failed_candidate_count"] == 0
        assert coverage["candidate_requests_unattempted"] == 0
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/unsupported (Status: 302)" in output
        assert "[redirect refused: unsupported_redirect]" in output
        assert refused_destination not in output
        assert "/later-negative" not in output
    finally:
        executor.close()


def test_terminal_rate_rejection_remains_fatal_at_native_candidate_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("rate-limited", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = "https://app.example.test/rate-limited"
    later_url = "https://app.example.test/later-negative"

    def respond(url: str):
        if url == candidate_url:
            return 429, (("Retry-After", "17"),), b"rate limited"
        return 404, b"conventional negative"

    progress = []
    output_dir = tmp_path / "native-output"
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    try:
        with pytest.raises(HTTPRateRejected) as exc_info:
            module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )

        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == "17"
        assert [request.url for request in transport.requests] == [
            "https://app.example.test/.bugslyce-negative-one",
            "https://app.example.test/.bugslyce-negative-two",
            "https://app.example.test/.bugslyce-negative-three",
            candidate_url,
        ]
        assert all(request.url != later_url for request in transport.requests)
        assert [event.completed for event in progress] == [0]
        assert (output_dir / "content_discovery_baseline.json").is_file()
        assert not (output_dir / "content_discovery_native_coverage.json").exists()
        assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
        with pytest.raises(HTTPRateRejected) as terminal_exc:
            executor.request(later_url)
        assert terminal_exc.value.retry_after == "17"
        assert len(transport.requests) == 4
    finally:
        executor.close()


@pytest.mark.parametrize(
    (
        "origin",
        "candidate_name",
        "location",
        "reason",
        "expected_destination",
    ),
    (
        pytest.param(
            "https://app.example.test",
            "malformed-single-location",
            " https://app.example.test/unsafe",
            "malformed_location",
            None,
            id="malformed-single-location",
        ),
        pytest.param(
            "http://app.example.test",
            "unapproved-upgrade",
            "https://app.example.test/secure",
            "http_upgrade_not_approved",
            "https://app.example.test/secure",
            id="http-upgrade-not-approved",
        ),
    ),
)
def test_response_bearing_redirect_refusal_candidate_continues_later_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
    candidate_name: str,
    location: str,
    reason: str,
    expected_destination: str | None,
) -> None:
    _install_profile(monkeypatch, tmp_path, (candidate_name, "later-negative"))
    runtime = _runtime(tmp_path / "runtime", origin=f"{origin}/")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = f"{origin}/{candidate_name}"
    later_url = f"{origin}/later-negative"
    expected_before_refusal = [
        f"{origin}/.bugslyce-negative-one",
        f"{origin}/.bugslyce-negative-two",
        f"{origin}/.bugslyce-negative-three",
        candidate_url,
    ]

    def respond(url: str):
        if url == candidate_url:
            return 302, (("Location", location),), b"refused redirect response"
        return 404, b"conventional negative"

    progress = []
    output_dir = tmp_path / "native-output"
    executor, transport = _executor(runtime, (origin,), respond)
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=output_dir,
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPRedirectRefused as exc:
            assert exc.reason == reason
            assert [request.url for request in transport.requests] == (
                expected_before_refusal
            )
            assert all(request.url != location for request in transport.requests)
            assert all(request.url != later_url for request in transport.requests)
            assert [event.completed for event in progress] == [0]
            assert (output_dir / "content_discovery_baseline.json").is_file()
            assert tuple(output_dir.glob("content-discovery-internal-*.txt")) == ()
            raise

        assert [request.url for request in transport.requests] == [
            *expected_before_refusal,
            later_url,
        ]
        assert all(request.url != location for request in transport.requests)
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 1
        assert origin_result.failed_candidate_count == 0
        assert [event.completed for event in progress] == [0, 1, 2]
        assert progress[-1].total == 2
        coverage = json.loads(
            result.coverage_artifact_path.read_text(encoding="utf-8")
        )
        assert coverage["candidate_requests_planned"] == 2
        assert coverage["candidate_requests_attempted"] == 2
        assert coverage["candidate_responses_observed"] == 2
        assert coverage["failed_candidate_count"] == 0
        assert coverage["candidate_requests_unattempted"] == 0
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert f"/{candidate_name} (Status: 302)" in output
        if expected_destination is None:
            assert f"[redirect refused: {reason}]" in output
            assert location not in output
        else:
            assert f"[--> {expected_destination}]" in output
        assert "/later-negative" not in output
    finally:
        executor.close()


def test_redirect_loop_candidate_is_retained_and_later_native_candidate_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("loop", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    first_url = "https://app.example.test/loop"
    second_url = "https://app.example.test/loop-two"

    def respond(url: str):
        if url == first_url:
            return 302, (("Location", "/loop-two"),), b"first redirect"
        if url == second_url:
            return 302, (("Location", "/loop"),), b"loop refusal response"
        return 404, b"conventional negative"

    progress = []
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)

    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
        progress_callback=progress.append,
    )

    assert [request.url for request in transport.requests] == [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        first_url,
        second_url,
        "https://app.example.test/later-negative",
    ]
    origin_result = result.origin_results[0]
    assert origin_result.suppressed_candidate_count == 1
    assert origin_result.retained_candidate_count == 1
    assert [event.completed for event in progress] == [0, 1, 2]
    assert progress[-1].total == 2
    output = result.artifacts[0].path.read_text(encoding="utf-8")
    assert "/loop (Status: 302)" in output
    assert f"[--> {first_url}]" in output
    assert "/later-negative" not in output
    executor.close()


def test_redirect_hop_limit_candidate_is_retained_and_later_candidate_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("hop-limit", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = "https://app.example.test/hop-limit"
    hop_limit = runtime.http_executor.configuration.maximum_redirect_hops
    accepted_urls = tuple(
        f"https://app.example.test/hop-{index}"
        for index in range(1, hop_limit + 1)
    )
    refused_destination = "https://app.example.test/over-limit"
    redirect_sources = (candidate_url, *accepted_urls)
    redirect_destinations = (*accepted_urls, refused_destination)
    redirects = dict(zip(redirect_sources, redirect_destinations, strict=True))
    expected_before_refusal = [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        *redirect_sources,
    ]

    def respond(url: str):
        destination = redirects.get(url)
        if destination is not None:
            return (
                302,
                (("Location", destination),),
                f"redirect response for {url}".encode("utf-8"),
            )
        return 404, b"conventional negative"

    progress = []
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)
    try:
        try:
            result = module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=tmp_path / "native-output",
                token_factory=iter(("one", "two", "three")).__next__,
                progress_callback=progress.append,
            )
        except HTTPRedirectRefused as exc:
            assert exc.reason == "redirect_hop_limit"
            assert [request.url for request in transport.requests] == (
                expected_before_refusal
            )
            assert all(
                request.url != refused_destination for request in transport.requests
            )
            assert all(
                request.url != "https://app.example.test/later-negative"
                for request in transport.requests
            )
            raise

        assert [request.url for request in transport.requests] == [
            *expected_before_refusal,
            "https://app.example.test/later-negative",
        ]
        assert all(
            request.url != refused_destination for request in transport.requests
        )
        origin_result = result.origin_results[0]
        assert origin_result.suppressed_candidate_count == 1
        assert origin_result.retained_candidate_count == 1
        assert [event.completed for event in progress] == [0, 1, 2]
        assert progress[-1].total == 2
        output = result.artifacts[0].path.read_text(encoding="utf-8")
        assert "/hop-limit (Status: 302)" in output
        assert f"[--> {refused_destination}]" in output
        assert "/later-negative" not in output
    finally:
        executor.close()


def test_https_downgrade_candidate_is_retained_and_later_native_candidate_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("downgrade", "later-negative"))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
        ),
    )
    candidate_url = "https://app.example.test/downgrade"
    refused_destination = "http://app.example.test/landing"

    def respond(url: str):
        if url == candidate_url:
            return (
                302,
                (("Location", refused_destination),),
                b"downgrade redirect response",
            )
        return 404, b"conventional negative"

    progress = []
    executor, transport = _executor(runtime, ("https://app.example.test",), respond)

    result = module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=tmp_path / "native-output",
        token_factory=iter(("one", "two", "three")).__next__,
        progress_callback=progress.append,
    )

    assert [request.url for request in transport.requests] == [
        "https://app.example.test/.bugslyce-negative-one",
        "https://app.example.test/.bugslyce-negative-two",
        "https://app.example.test/.bugslyce-negative-three",
        candidate_url,
        "https://app.example.test/later-negative",
    ]
    assert all(request.url != refused_destination for request in transport.requests)
    origin_result = result.origin_results[0]
    assert origin_result.suppressed_candidate_count == 1
    assert origin_result.retained_candidate_count == 1
    assert [event.completed for event in progress] == [0, 1, 2]
    assert progress[-1].total == 2
    output = result.artifacts[0].path.read_text(encoding="utf-8")
    assert "/downgrade (Status: 302)" in output
    assert f"[--> {refused_destination}]" in output
    assert "/later-negative" not in output
    executor.close()


def test_true_native_baseline_refusal_persists_structured_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("candidate",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=1,
            maximum_candidate_requests_per_origin=1,
        ),
    )
    bodies = iter((b"first", b"second", b"third"))
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (500, next(bodies)),
    )

    with pytest.raises(module.NativeContentDiscoveryBaselineRefused) as exc_info:
        module.run_native_content_discovery(
            runtime,
            state,
            orchestration,
            plan,
            http_executor=executor,
            output_dir=tmp_path / "native-output",
            token_factory=iter(("one", "two", "three")).__next__,
        )

    assert len(transport.requests) == 3
    baseline_path = exc_info.value.baseline_artifact_path
    assert baseline_path == tmp_path / "native-output" / "content_discovery_baseline.json"
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert payload["created_by"] == "bugslyce-native-content-baseline"
    origin = payload["origins"][0]
    assert origin["classification"] == "unstable"
    assert origin["selected_policy"] == "refuse"
    assert origin["completed_observations"] == 3
    assert len(origin["generated_negative_request_urls"]) == 3
    assert all(item["terminal_http_status"] == 500 for item in origin["observations"])
    assert all(item["response_bytes"] for item in origin["observations"])
    assert all(item["body_sha256"] for item in origin["observations"])
    assert all(item["failure_reason"] is None for item in origin["observations"])
    assert "headers" not in baseline_path.read_text(encoding="utf-8").casefold()
    executor.close()


def test_native_plan_accepts_authorised_child_without_rebinding_strict_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime = _runtime(tmp_path / "runtime")
    state = _child_state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    approved_before = runtime.approved_http_origins
    executor_before = runtime.http_executor
    module = _native_module()

    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=1,
        ),
    )

    assert tuple(request.canonical_origin for request in plan.requests) == (
        "https://api.example.test",
        "https://app.example.test",
    )
    assert runtime.approved_http_origins == approved_before
    assert runtime.http_executor is executor_before
    with pytest.raises(ValueError, match="target"):
        runtime.require_workflow(
            Path(runtime.project.output_dir),
            Path(runtime.project.scope_file),
            "api.example.test",
        )


def test_native_entry_points_reject_same_runtime_programme_work_not_backed_by_project_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from bugslyce.core.programme_graph import (
        RELATIONSHIP_CONFIGURED_SEED,
        RELATIONSHIP_OBSERVED_REFERENCE,
        build_programme_graph,
        build_programme_http_work_items,
        build_programme_relationship_evidence,
    )

    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    legitimate = build_programme_orchestration_plan(runtime, state)

    fabricated_graph = build_programme_graph(
        runtime.programme_scope_policy,
        relationship_evidence=(
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_CONFIGURED_SEED,
                source_origin=None,
                destination_origin="https://app.example.test/",
                evidence_ids=(),
                provenance_sources=(
                    "bug_bounty_project_runtime.approved_http_origins",
                ),
            ),
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_OBSERVED_REFERENCE,
                source_origin="https://app.example.test/",
                destination_origin="https://ghost.example.test/",
                evidence_ids=("EVID-WP4A-FABRICATED",),
                provenance_sources=("raw/nonexistent-wp4a-source.html",),
            ),
        ),
    )
    forged = replace(
        legitimate,
        programme_graph=fabricated_graph,
        http_work_items=build_programme_http_work_items(fabricated_graph),
    )
    module = _native_module()

    assert "https://ghost.example.test" in {
        item.canonical_origin
        for item in forged.http_work_items
    }

    with pytest.raises(ValueError, match="state|evidence|binding|canonical"):
        module.build_native_content_discovery_http_executor(
            runtime,
            state,
            forged,
        )

    with pytest.raises(ValueError, match="state|evidence|binding|canonical"):
        module.build_native_content_discovery_plan(
            runtime,
            state,
            forged,
            profile=PROFILE,
            limits=module.NativeContentDiscoveryLimits(
                maximum_total_candidate_requests=2,
                maximum_candidate_requests_per_origin=1,
            ),
        )


def test_native_execution_rejects_tampered_profile_root_before_any_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    limits = module.NativeContentDiscoveryLimits(
        maximum_total_candidate_requests=1,
        maximum_candidate_requests_per_origin=1,
    )
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=limits,
    )

    forged_request = module.NativeContentDiscoveryRequest(
        url="https://app.example.test/invented-not-in-profile",
        canonical_origin="https://app.example.test",
        depth=0,
        selection_reason="profile_wordlist",
        evidence_ids=(),
    )
    forged_plan = replace(
        plan,
        requests=(forged_request,),
    )

    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (200, b"should never be requested"),
    )
    try:
        with pytest.raises(ValueError, match="plan|canonical|request|binding"):
            module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                forged_plan,
                http_executor=executor,
                output_dir=tmp_path / "native-output",
                token_factory=iter(("one", "two", "three")).__next__,
            )
        assert transport.requests == []
    finally:
        executor.close()
