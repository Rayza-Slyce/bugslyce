"""WP4A RED contracts for bounded programme-native content discovery."""

from __future__ import annotations

import importlib
import json
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


def _runtime(tmp_path: Path, *, origin: str = "https://app.example.test/"):
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
    runtime.bind_http_origins((origin,))
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
    assert first.candidate_requests_planned == 2
    assert tuple(request.url for request in first.requests) == (
        "https://app.example.test/health",
        "https://app.example.test/admin",
    )
    assert all(request.canonical_origin == "https://app.example.test" for request in first.requests)
    assert all(request.depth == 0 for request in first.requests)
    assert all(request.selection_reason == "profile_wordlist" for request in first.requests)
    assert all(request.evidence_ids == () for request in first.requests)


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
    _install_profile(monkeypatch, tmp_path, ("candidate",))
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
        limits=module.NativeContentDiscoveryLimits(3, 1),
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


def test_native_candidate_failure_preserves_baseline_without_reporting_completion(
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
            raise OSError("synthetic transport failure")
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
    with pytest.raises(HTTPTransportFailure, match="transport_error"):
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
