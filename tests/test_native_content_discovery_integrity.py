"""RED contracts for WP4A local preflight and evidence integrity."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from bugslyce.core.models import DiscoveredPath
from bugslyce.recon.http_enforcement import (
    HTTPRateRejected,
    HTTPTransportFailure,
    InternalHTTPExecutor,
    build_http_enforcement_configuration,
)
from bugslyce.recon.programme_orchestration import build_programme_orchestration_plan
from test_native_content_discovery import (
    PROFILE,
    _ResponseTransport,
    _child_state,
    _executor,
    _install_profile,
    _native_module,
    _runtime,
    _state,
)


def _plan_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    child: bool = False,
):
    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime = _runtime(tmp_path / "runtime")
    state = _child_state(runtime) if child else _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()
    plan = module.build_native_content_discovery_plan(
        runtime,
        state,
        orchestration,
        profile=PROFILE,
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=len(orchestration.http_work_items),
            maximum_candidate_requests_per_origin=1,
        ),
    )
    return module, runtime, state, orchestration, plan


def _native_executor(module, runtime, state, orchestration, responder):
    executor = module.build_native_content_discovery_http_executor(
        runtime,
        state,
        orchestration,
    )
    transport = _ResponseTransport(responder)
    executor.transport = transport
    return executor, transport


def _run(
    module,
    runtime,
    state,
    orchestration,
    plan,
    executor,
    output_dir: Path,
    *,
    tokens=("one", "two", "three", "four", "five", "six"),
):
    return module.run_native_content_discovery(
        runtime,
        state,
        orchestration,
        plan,
        http_executor=executor,
        output_dir=output_dir,
        token_factory=iter(tokens).__next__,
    )


def test_independent_equivalent_executor_is_rejected_before_baseline_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    origins = tuple(item.canonical_origin for item in orchestration.http_work_items)
    configuration = build_http_enforcement_configuration(
        runtime.policy,
        approved_origins=origins,
    )
    transport = _ResponseTransport(lambda _url: (200, b"independent"))
    independent = InternalHTTPExecutor(
        configuration,
        programme_scope_policy=runtime.programme_scope_policy,
        transport=transport,
        ipv4_resolver=runtime.ipv4_resolver,
    )
    try:
        with pytest.raises(ValueError, match="shared|aggregate|runtime|canonical"):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                independent,
                tmp_path / "output",
            )
    finally:
        independent.close()

    assert transport.requests == []


def test_native_executor_builder_shares_runtime_terminal_rate_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, _plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    strict_transport = _ResponseTransport(lambda _url: (429, b"slow down"))
    runtime.http_executor.transport = strict_transport
    native = module.build_native_content_discovery_http_executor(
        runtime,
        state,
        orchestration,
    )
    native_transport = _ResponseTransport(lambda _url: (200, b"must not continue"))
    native.transport = native_transport
    try:
        with pytest.raises(HTTPRateRejected):
            runtime.http_executor.request("https://app.example.test/strict")
        with pytest.raises(HTTPRateRejected):
            native.request("https://app.example.test/native")
    finally:
        native.close()

    assert len(strict_transport.requests) == 1
    assert native_transport.requests == []


def test_runtime_shared_caller_executor_remains_valid_for_native_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    origins = tuple(item.canonical_origin for item in orchestration.http_work_items)
    executor, transport = _executor(
        runtime,
        origins,
        lambda url: (
            (404, b"negative")
            if ".bugslyce-negative-" in url
            else (200, b"retained")
        ),
    )
    try:
        result = _run(
            module,
            runtime,
            state,
            orchestration,
            plan,
            executor,
            tmp_path / "output",
        )
    finally:
        executor.close()

    assert len(transport.requests) == 4
    assert result.origin_results[0].retained_candidate_count == 1


def test_output_directory_symlink_is_rejected_before_baseline_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda url: (404, b"negative") if ".bugslyce-negative-" in url else (200, b"hit"),
    )
    target = tmp_path / "actual-output"
    target.mkdir()
    requested = tmp_path / "requested-output"
    requested.symlink_to(target, target_is_directory=True)
    try:
        with pytest.raises(ValueError, match="output|symlink|unsafe"):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                executor,
                requested,
            )
    finally:
        executor.close()

    assert transport.requests == []
    assert tuple(target.iterdir()) == ()


def test_existing_non_directory_output_is_rejected_before_baseline_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda _url: (404, b"negative"),
    )
    output = tmp_path / "not-a-directory"
    output.write_text("sentinel", encoding="utf-8")
    try:
        with pytest.raises(ValueError, match="output|directory|unsafe"):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                executor,
                output,
            )
    finally:
        executor.close()

    assert transport.requests == []
    assert output.read_text(encoding="utf-8") == "sentinel"


def test_uncreatable_output_directory_is_rejected_before_baseline_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )
    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda _url: (404, b"negative"),
    )
    blocking_parent = tmp_path / "blocking-parent"
    blocking_parent.write_text("not a directory", encoding="utf-8")
    output = blocking_parent / "native-output"
    try:
        with pytest.raises((OSError, ValueError)):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                executor,
                output,
            )
    finally:
        executor.close()

    assert transport.requests == []


@pytest.mark.parametrize("unsafe_kind", ("file", "symlink", "directory"))
def test_all_origin_final_artifact_paths_are_preflighted_before_any_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
        child=True,
    )
    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda url: (404, b"negative") if ".bugslyce-negative-" in url else (200, b"hit"),
    )
    output = tmp_path / "output"
    output.mkdir()
    second_origin_path = output / module._artifact_filename("https://app.example.test")
    if unsafe_kind == "file":
        second_origin_path.write_text("existing", encoding="utf-8")
    elif unsafe_kind == "symlink":
        target = tmp_path / "outside-artifact"
        target.write_text("outside", encoding="utf-8")
        second_origin_path.symlink_to(target)
    else:
        second_origin_path.mkdir()

    try:
        with pytest.raises(ValueError, match="artefact|artifact|unsafe|exists"):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                executor,
                output,
            )
    finally:
        executor.close()

    assert transport.requests == []


def test_scheme_distinct_origins_complete_to_distinct_native_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
    runtime = _runtime(tmp_path / "runtime")
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/start",
                status_code=301,
                content_length=0,
                redirect_location="http://app.example.test:443/child",
                source="raw/scheme-redirect.txt",
                evidence_ids=["EVID-SCHEME-CHILD"],
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
        limits=module.NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=1,
        ),
    )
    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda url: (404, b"negative") if ".bugslyce-negative-" in url else (200, b"hit"),
    )
    try:
        result = _run(
            module,
            runtime,
            state,
            orchestration,
            plan,
            executor,
            tmp_path / "output",
        )
    finally:
        executor.close()

    assert tuple(item.canonical_origin for item in orchestration.http_work_items) == (
        "http://app.example.test:443",
        "https://app.example.test",
    )
    names = tuple(artifact.path.name for artifact in result.artifacts)
    assert len(names) == 2
    assert len(set(names)) == 2
    assert all(name.startswith("content-discovery-internal-") for name in names)
    assert all(not name.startswith("gobuster") for name in names)
    assert all(artifact.path.is_file() for artifact in result.artifacts)
    assert len(transport.requests) == 8


def test_later_origin_failure_leaves_no_final_artifact_and_retry_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
        child=True,
    )

    def fail_later(url: str):
        if ".bugslyce-negative-" in url:
            return 404, b"negative"
        if url == "https://api.example.test/admin":
            return 200, b"first origin"
        raise OSError("synthetic later-origin failure")

    output = tmp_path / "output"
    failing_executor, failing_transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        fail_later,
    )
    try:
        with pytest.raises(HTTPTransportFailure, match="transport_error"):
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                failing_executor,
                output,
            )
    finally:
        failing_executor.close()

    assert len(failing_transport.requests) == 8
    assert tuple(output.glob("content-discovery-internal-*.txt")) == ()

    retry_executor, retry_transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        lambda url: (404, b"negative") if ".bugslyce-negative-" in url else (200, b"hit"),
    )
    try:
        result = _run(
            module,
            runtime,
            state,
            orchestration,
            plan,
            retry_executor,
            output,
        )
    finally:
        retry_executor.close()

    assert len(retry_transport.requests) == 8
    assert len(result.artifacts) == 2
    assert all(artifact.path.is_file() for artifact in result.artifacts)


def test_native_artifact_persistence_is_exclusive_and_never_follows_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _native_module()
    existing = tmp_path / "existing.txt"
    existing.write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError, match="exists|unsafe|artefact|artifact"):
        module._write_new_artifact(existing, "replacement")
    assert existing.read_text(encoding="utf-8") == "existing"

    victim = tmp_path / "victim.txt"
    victim.write_text("victim", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    linked.symlink_to(victim)
    with pytest.raises(ValueError, match="exists|unsafe|artefact|artifact"):
        module._write_new_artifact(linked, "replacement")
    assert victim.read_text(encoding="utf-8") == "victim"

    raced = tmp_path / "raced.txt"
    entered = threading.Event()
    release = threading.Event()
    original_write_text = Path.write_text

    def pause_final_write(path: Path, content: str, *args, **kwargs):
        if path == raced:
            entered.set()
            if not release.wait(timeout=2):
                raise AssertionError("test race release was not signalled")
        return original_write_text(path, content, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", pause_final_write)

    def insert_link() -> None:
        if entered.wait(timeout=0.2):
            raced.symlink_to(victim)
            release.set()

    attacker = threading.Thread(target=insert_link)
    attacker.start()
    try:
        module._write_new_artifact(raced, "new evidence")
    finally:
        release.set()
        attacker.join(timeout=2)

    assert not attacker.is_alive()
    assert not raced.is_symlink()
    assert raced.read_text(encoding="utf-8") == "new evidence"
    assert victim.read_text(encoding="utf-8") == "victim"


def test_native_artifact_write_failure_leaves_no_final_and_retry_is_possible(
    tmp_path: Path,
) -> None:
    module = _native_module()
    artifact = tmp_path / "content-discovery-internal-test.txt"
    script = """
from pathlib import Path
import resource
import signal
import sys

from bugslyce.recon.native_content_discovery import _write_new_artifact

signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))
try:
    _write_new_artifact(Path(sys.argv[1]), "X" * 4096)
except OSError:
    raise SystemExit(23)
raise SystemExit(0)
"""
    completed = subprocess.run(
        (sys.executable, "-c", script, str(artifact)),
        cwd=Path.cwd(),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 23
    assert not artifact.exists()
    assert not artifact.is_symlink()

    module._write_new_artifact(artifact, "retry evidence\n")
    assert artifact.read_text(encoding="utf-8") == "retry evidence\n"


@pytest.mark.parametrize(
    ("response_kind", "expected_reason", "expected_transport_count"),
    (
        ("transport_failure", "transport_failure:transport_error", 3),
        ("rate_rejection", "rate_rejected", 1),
    ),
)
def test_refused_baseline_raises_with_retained_typed_failure_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response_kind: str,
    expected_reason: str,
    expected_transport_count: int,
) -> None:
    module, runtime, state, orchestration, plan = _plan_context(
        tmp_path,
        monkeypatch,
    )

    def responder(_url: str):
        if response_kind == "transport_failure":
            raise OSError("synthetic transport failure")
        return 429, b"slow down"

    executor, transport = _native_executor(
        module,
        runtime,
        state,
        orchestration,
        responder,
    )
    try:
        with pytest.raises(ValueError) as exc_info:
            _run(
                module,
                runtime,
                state,
                orchestration,
                plan,
                executor,
                tmp_path / "output",
                tokens=("one", "two", "three"),
            )
    finally:
        executor.close()

    decisions = getattr(exc_info.value, "decisions", None)
    assert isinstance(decisions, tuple)
    assert len(decisions) == 1
    reasons = tuple(
        observation.failure_reason
        for observation in decisions[0].observations
        if observation.failure_reason is not None
    )
    assert expected_reason in reasons
    assert len(transport.requests) == expected_transport_count
    assert all(".bugslyce-negative-" in request.url for request in transport.requests)


def test_native_executor_default_system_resolver_is_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bugslyce.recon.modes import STANDARD_RECON_PROFILE
    from bugslyce.recon.project_runtime import build_bug_bounty_project_runtime

    _install_profile(monkeypatch, tmp_path, ("admin",))

    seeded_runtime = _runtime(tmp_path / "seed")
    runtime = build_bug_bounty_project_runtime(
        seeded_runtime.project,
        STANDARD_RECON_PROFILE,
        capabilities=seeded_runtime.capabilities,
    )
    runtime.bind_http_origins(seeded_runtime.approved_http_origins)

    state = _state(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    module = _native_module()

    executor = module.build_native_content_discovery_http_executor(
        runtime,
        state,
        orchestration,
    )
    expected_origins = tuple(
        item.canonical_origin for item in orchestration.http_work_items
    )

    try:
        assert runtime.ipv4_resolver is None
        assert (
            executor._ipv4_resolver
            is runtime.http_executor._ipv4_resolver
        )
        module._require_compatible_executor(
            runtime,
            executor,
            expected_origins,
        )
    finally:
        executor.close()
