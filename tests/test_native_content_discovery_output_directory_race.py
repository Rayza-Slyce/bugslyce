"""RED contract for WP4A validated output-directory identity."""

from __future__ import annotations

from pathlib import Path
import tempfile

import pytest

from bugslyce.recon.programme_orchestration import build_programme_orchestration_plan
from test_native_content_discovery import (
    PROFILE,
    _executor,
    _install_profile,
    _native_module,
    _runtime,
    _state,
)


def test_output_transaction_refuses_directory_replaced_after_final_safety_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_profile(monkeypatch, tmp_path, ("admin",))
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

    requested = tmp_path / "requested-output"
    requested.mkdir()
    target = tmp_path / "replacement-target"
    target.mkdir()
    assert requested.is_dir()
    assert not requested.is_symlink()

    original_is_dir = Path.is_dir
    requested_is_dir_calls = 0

    def interleaved_is_dir(path: Path) -> bool:
        nonlocal requested_is_dir_calls
        result = original_is_dir(path)
        if path == requested:
            requested_is_dir_calls += 1
            if requested_is_dir_calls == 2:
                assert result is True
                path.rmdir()
                path.symlink_to(target, target_is_directory=True)
        return result

    original_mkstemp = tempfile.mkstemp
    preflight_directories: list[Path] = []

    def recording_mkstemp(*args, **kwargs):
        if kwargs.get("prefix") == ".bugslyce-native-preflight.":
            preflight_directories.append(Path(kwargs["dir"]))
        return original_mkstemp(*args, **kwargs)

    monkeypatch.setattr(Path, "is_dir", interleaved_is_dir)
    monkeypatch.setattr(module.tempfile, "mkstemp", recording_mkstemp)
    try:
        with pytest.raises(ValueError, match="output|directory|unsafe|identity"):
            module.run_native_content_discovery(
                runtime,
                state,
                orchestration,
                plan,
                http_executor=executor,
                output_dir=requested,
                token_factory=iter(("one", "two", "three")).__next__,
            )
    finally:
        executor.close()

    assert requested_is_dir_calls == 2
    assert requested.is_symlink()
    assert preflight_directories == []
    assert tuple(target.iterdir()) == ()
    assert transport.requests == []
