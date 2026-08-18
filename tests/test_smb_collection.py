from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce.core.models import PortService, ReconCommandResult


def _service(
    *,
    port: int,
    service: str = "microsoft-ds",
    evidence_id: str | None = None,
    source_file: str = "nmap-services-all.txt",
) -> PortService:
    return PortService(
        host="files.example.test",
        port=port,
        protocol="tcp",
        state="open",
        service=service,
        product="Samba smbd",
        version="4.x",
        source_file=source_file,
        evidence_ids=[evidence_id or f"EVID-PORT-{port}"],
        tags=[],
    )


def _state(port_services) -> SimpleNamespace:
    return SimpleNamespace(
        port_services=list(port_services),
        evidence=[],
        engagement_context="ctf",
        warnings=[],
    )


def _result(
    command,
    *,
    exit_code: int | None = 0,
    executed: bool = True,
    error: str | None = None,
) -> ReconCommandResult:
    return ReconCommandResult(
        command_id=command.id,
        tool=command.tool,
        exit_code=exit_code,
        stdout_path=None,
        stderr_path=None,
        output_file=command.output_file,
        started_at="2026-08-18T09:00:00Z",
        ended_at="2026-08-18T09:00:01Z",
        duration_seconds=1.0,
        executed=executed,
        simulated=False,
        error=error,
    )


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.md"
    path.write_text(
        "# Scope\n\n## In Scope\n\n- files.example.test\n",
        encoding="utf-8",
    )
    return path


def test_smb_collection_no_evidence_is_clean_no_work(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state(
            (
                _service(port=445, service="http"),
                _service(port=22, service="ssh"),
            )
        ),
    )

    def forbidden_factory(_target):
        raise AssertionError("No SMB runner should be created.")

    with pytest.raises(collection.SMBEnumerationNoWork) as caught:
        collection.collect_smb_share_evidence(
            tmp_path,
            _scope(tmp_path),
            runner_factory=forbidden_factory,
        )

    assert caught.value.considered == 0


def test_smb_collection_deduplicates_trigger_evidence_and_uses_arbitrary_port(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state(
            (
                _service(
                    port=31337,
                    evidence_id="EVID-PORT-0001",
                    source_file="nmap-allports.txt",
                ),
                _service(
                    port=31337,
                    evidence_id="EVID-PORT-0009",
                    source_file="nmap-services-all.txt",
                ),
            )
        ),
    )

    observed_targets = []

    def runner_factory(target):
        observed_targets.append(target)

        class Runner:
            def run(self, command):
                Path(command.output_file).write_text(
                    "Disk|nt4wrksv|Custom share\n",
                    encoding="utf-8",
                )
                return _result(command)

        return Runner()

    result = collection.collect_smb_share_evidence(
        tmp_path,
        _scope(tmp_path),
        runner_factory=runner_factory,
    )

    assert len(observed_targets) == 1
    assert observed_targets[0].port == 31337
    assert observed_targets[0].evidence_ids == (
        "EVID-PORT-0001",
        "EVID-PORT-0009",
    )

    assert result.execution_count == 1
    assert result.commands_succeeded == 1
    assert result.commands_unsuccessful == 0
    assert result.commands_timed_out == 0
    assert len(result.command_results) == 1
    assert len(result.shares) == 1
    assert result.shares[0].share_name == "nt4wrksv"
    assert result.shares[0].port == 31337


def test_smb_collection_attempts_each_distinct_evidence_backed_endpoint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state(
            (
                _service(port=1445),
                _service(port=31337, service="netbios-ssn"),
            )
        ),
    )

    attempted_ports: list[int] = []

    def runner_factory(target):
        attempted_ports.append(target.port)

        class Runner:
            def run(self, command):
                Path(command.output_file).write_text(
                    f"Disk|share-{target.port}|Synthetic\n",
                    encoding="utf-8",
                )
                return _result(command)

        return Runner()

    result = collection.collect_smb_share_evidence(
        tmp_path,
        _scope(tmp_path),
        runner_factory=runner_factory,
    )

    assert attempted_ports == [1445, 31337]
    assert result.execution_count == 2
    assert tuple(item.port for item in result.shares) == (1445, 31337)


def test_smb_collection_retains_unsuccessful_attempt_and_continues(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state(
            (
                _service(port=1445),
                _service(port=31337),
            )
        ),
    )

    def runner_factory(target):
        class Runner:
            def run(self, command):
                if target.port == 1445:
                    Path(command.output_file).write_text("", encoding="utf-8")
                    return _result(
                        command,
                        exit_code=1,
                        error="smbclient exited with code 1.",
                    )

                Path(command.output_file).write_text(
                    "Disk|data|Readable listing\n",
                    encoding="utf-8",
                )
                return _result(command)

        return Runner()

    result = collection.collect_smb_share_evidence(
        tmp_path,
        _scope(tmp_path),
        runner_factory=runner_factory,
    )

    assert result.execution_count == 2
    assert result.commands_succeeded == 1
    assert result.commands_unsuccessful == 1
    assert result.commands_timed_out == 0
    assert tuple(item.share_name for item in result.shares) == ("data",)
    assert len(result.command_results) == 2
    assert result.command_results[0].exit_code == 1
    assert result.command_results[1].exit_code == 0


def test_smb_collection_refuses_out_of_scope_endpoint_before_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state((_service(port=31337),)),
    )

    scope = tmp_path / "scope.md"
    scope.write_text(
        "# Scope\n\n## In Scope\n\n- other.example.test\n",
        encoding="utf-8",
    )

    def forbidden_factory(_target):
        raise AssertionError("Out-of-scope SMB endpoint reached runner creation.")

    with pytest.raises(ValueError, match="explicitly listed"):
        collection.collect_smb_share_evidence(
            tmp_path,
            scope,
            runner_factory=forbidden_factory,
        )


def test_smb_collection_preserves_modular_bug_bounty_live_block(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    state = _state((_service(port=31337),))
    state.engagement_context = "bug_bounty"

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: state,
    )

    def forbidden_factory(_target):
        raise AssertionError("Bug-bounty SMB endpoint reached runner creation.")

    with pytest.raises(
        ValueError,
        match="unsupported for live bug-bounty reconnaissance",
    ):
        collection.collect_smb_share_evidence(
            tmp_path,
            _scope(tmp_path),
            runner_factory=forbidden_factory,
        )


def test_smb_collection_validates_all_endpoint_scope_before_any_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    first = _service(port=1445)
    second = _service(port=2445)
    second.host = "other.example.test"

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state((first, second)),
    )

    attempted: list[tuple[str, int]] = []

    def runner_factory(target):
        class Runner:
            def run(self, command):
                attempted.append((target.host, target.port))
                Path(command.output_file).write_text(
                    "Disk|data|Synthetic\n",
                    encoding="utf-8",
                )
                return _result(command)

        return Runner()

    with pytest.raises(ValueError, match="explicitly listed"):
        collection.collect_smb_share_evidence(
            tmp_path,
            _scope(tmp_path),
            runner_factory=runner_factory,
        )

    assert attempted == []


def test_smb_collection_retries_session_setup_rejection_with_guest_on_same_port(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state((_service(port=31337),)),
    )

    attempted_users: list[str] = []
    attempted_ports: list[str] = []

    def command_result(
        command,
        *,
        exit_code: int,
        stderr_path: str | None,
        error: str | None,
    ) -> ReconCommandResult:
        return ReconCommandResult(
            command_id=command.id,
            tool=command.tool,
            exit_code=exit_code,
            stdout_path=None,
            stderr_path=stderr_path,
            output_file=command.output_file,
            started_at="2026-08-18T18:00:00Z",
            ended_at="2026-08-18T18:00:01Z",
            duration_seconds=1.0,
            executed=True,
            simulated=False,
            error=error,
        )

    def runner_factory(_target):
        class Runner:
            def run(self, command):
                attempted_users.append(
                    next(
                        value
                        for value in command.argv
                        if value.startswith("--user=")
                    )
                )
                attempted_ports.append(
                    next(
                        value
                        for value in command.argv
                        if value.startswith("--port=")
                    )
                )

                if "--user=%" in command.argv:
                    output_path = Path(command.output_file)
                    output_path.write_text("", encoding="utf-8")
                    stderr_path = output_path.with_suffix(
                        output_path.suffix + ".stderr.log"
                    )
                    stderr_path.write_text(
                        "session setup failed: NT_STATUS_ACCESS_DENIED\n",
                        encoding="utf-8",
                    )
                    return command_result(
                        command,
                        exit_code=1,
                        stderr_path=str(stderr_path),
                        error="smbclient exited with code 1.",
                    )

                assert "--user=guest%" in command.argv
                Path(command.output_file).write_text(
                    "Disk|nt4wrksv|\n",
                    encoding="utf-8",
                )
                return command_result(
                    command,
                    exit_code=0,
                    stderr_path=None,
                    error=None,
                )

        return Runner()

    result = collection.collect_smb_share_evidence(
        tmp_path,
        _scope(tmp_path),
        runner_factory=runner_factory,
    )

    assert attempted_users == [
        "--user=%",
        "--user=guest%",
    ]
    assert attempted_ports == [
        "--port=31337",
        "--port=31337",
    ]
    assert result.execution_count == 2
    assert result.commands_succeeded == 1
    assert result.commands_unsuccessful == 1
    assert tuple(item.share_name for item in result.shares) == (
        "nt4wrksv",
    )


def test_smb_collection_does_not_guest_retry_transport_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    monkeypatch.setattr(
        collection,
        "build_project_state",
        lambda _path: _state(
            (_service(port=31337, service="netbios-ssn"),)
        ),
    )

    attempted_users: list[str] = []

    def runner_factory(_target):
        class Runner:
            def run(self, command):
                attempted_users.append(
                    next(
                        value
                        for value in command.argv
                        if value.startswith("--user=")
                    )
                )
                output_path = Path(command.output_file)
                output_path.write_text("", encoding="utf-8")
                stderr_path = output_path.with_suffix(
                    output_path.suffix + ".stderr.log"
                )
                stderr_path.write_text(
                    "do_connect: Connection failed "
                    "(Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)\n",
                    encoding="utf-8",
                )
                return ReconCommandResult(
                    command_id=command.id,
                    tool=command.tool,
                    exit_code=1,
                    stdout_path=None,
                    stderr_path=str(stderr_path),
                    output_file=command.output_file,
                    started_at="2026-08-18T18:00:00Z",
                    ended_at="2026-08-18T18:00:01Z",
                    duration_seconds=1.0,
                    executed=True,
                    simulated=False,
                    error="smbclient exited with code 1.",
                )

        return Runner()

    result = collection.collect_smb_share_evidence(
        tmp_path,
        _scope(tmp_path),
        runner_factory=runner_factory,
    )

    assert attempted_users == ["--user=%"]
    assert result.execution_count == 1
    assert result.commands_succeeded == 0
    assert result.commands_unsuccessful == 1
