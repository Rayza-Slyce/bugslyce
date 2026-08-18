from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess
from types import SimpleNamespace

import bugslyce.recon.runner as runner_module
from bugslyce.recon.smb_commands import build_live_smb_share_list_command
from bugslyce.recon.smb_eligibility import SMBEnumerationTarget


def _target(*, port: int = 31337) -> SMBEnumerationTarget:
    return SMBEnumerationTarget(
        host="files.example.test",
        port=port,
        service_names=("microsoft-ds",),
        evidence_ids=("EVID-PORT-0001",),
        source_files=("nmap-services-all.txt",),
    )


def test_smb_runner_persists_stdout_and_stderr_without_shell(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "Disk|nt4wrksv|Custom share\n"
                "IPC|IPC$|IPC Service\n"
            ),
            stderr="synthetic smb diagnostic\n",
        )

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)

    target = _target(port=31337)
    command = build_live_smb_share_list_command(target, tmp_path)
    runner = runner_module.LiveSMBShareListRunner(tmp_path, target)

    result = runner.run(command)

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == command.argv

    environment = kwargs.pop("env")
    assert environment is not None
    for name in (
        "USER",
        "LOGNAME",
        "PASSWD",
        "PASSWD_FD",
        "PASSWD_FILE",
    ):
        assert name not in environment

    assert kwargs == {
        "stdin": subprocess.DEVNULL,
        "capture_output": True,
        "text": True,
        "timeout": 30,
        "check": False,
        "shell": False,
    }

    assert Path(command.output_file).read_text(encoding="utf-8") == (
        "Disk|nt4wrksv|Custom share\n"
        "IPC|IPC$|IPC Service\n"
    )
    assert result.exit_code == 0
    assert result.executed is True
    assert result.error is None
    assert result.stderr_path is not None
    assert Path(result.stderr_path).read_text(encoding="utf-8") == (
        "synthetic smb diagnostic\n"
    )


def test_smb_runner_refuses_forged_endpoint_before_process_start(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("Forged SMB command reached subprocess.")

    monkeypatch.setattr(runner_module.subprocess, "run", forbidden_run)

    target = _target(port=31337)
    command = build_live_smb_share_list_command(target, tmp_path)
    forged = replace(
        command,
        argv=[
            "--port=445" if value == "--port=31337" else value
            for value in command.argv
        ],
    )

    runner = runner_module.LiveSMBShareListRunner(tmp_path, target)
    result = runner.run(forged)

    assert result.executed is False
    assert result.exit_code is None
    assert result.error is not None
    assert (
        "approved null-identity or guest share-list argv shape"
        in result.error
    )
    assert not Path(command.output_file).exists()


def test_smb_runner_timeout_is_truthful_and_bounded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def timeout_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(runner_module.subprocess, "run", timeout_run)

    target = _target()
    command = build_live_smb_share_list_command(target, tmp_path)
    runner = runner_module.LiveSMBShareListRunner(tmp_path, target)

    result = runner.run(command)

    assert result.executed is True
    assert result.exit_code is None
    assert result.error == "SMB share listing exceeded 30 seconds."
    assert not Path(command.output_file).exists()


def test_smb_runner_retains_nonzero_process_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_run(_argv, **_kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="NT_STATUS_ACCESS_DENIED\n",
        )

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)

    target = _target(port=1445)
    command = build_live_smb_share_list_command(target, tmp_path)
    runner = runner_module.LiveSMBShareListRunner(tmp_path, target)

    result = runner.run(command)

    assert result.executed is True
    assert result.exit_code == 1
    assert result.error == "smbclient exited with code 1."
    assert Path(command.output_file).read_text(encoding="utf-8") == ""
    assert result.stderr_path is not None
    assert Path(result.stderr_path).read_text(encoding="utf-8") == (
        "NT_STATUS_ACCESS_DENIED\n"
    )


def test_smb_runner_refuses_preexisting_output_symlink_before_process_start(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("SMB subprocess started for a symlink output path.")

    monkeypatch.setattr(runner_module.subprocess, "run", forbidden_run)

    victim = tmp_path / "victim.txt"
    victim.write_text("preserve me\n", encoding="utf-8")

    output = tmp_path / "smb-shares-files.example.test-31337.txt"
    output.symlink_to(victim)

    target = _target(port=31337)
    command = build_live_smb_share_list_command(target, tmp_path)
    runner = runner_module.LiveSMBShareListRunner(tmp_path, target)

    result = runner.run(command)

    assert result.executed is False
    assert result.error is not None
    assert "symbolic link" in result.error
    assert victim.read_text(encoding="utf-8") == "preserve me\n"


def test_smb_runner_neutralises_authentication_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    inherited_credentials = {
        "USER": "unexpected-user%unexpected-password",
        "LOGNAME": "unexpected-user",
        "PASSWD": "unexpected-password",
        "PASSWD_FD": "9",
        "PASSWD_FILE": "/tmp/unexpected-smb-password",
    }

    for name, value in inherited_credentials.items():
        monkeypatch.setenv(name, value)

    monkeypatch.setenv(
        "BUGSLYCE_TEST_PRESERVE_ENV",
        "preserved",
    )

    def fake_run(_argv, **kwargs):
        environment = kwargs.get("env")

        assert environment is not None

        for name in inherited_credentials:
            assert name not in environment

        assert environment["BUGSLYCE_TEST_PRESERVE_ENV"] == "preserved"

        return SimpleNamespace(
            returncode=0,
            stdout="Disk|data|Synthetic share\n",
            stderr="",
        )

    monkeypatch.setattr(
        runner_module.subprocess,
        "run",
        fake_run,
    )

    target = _target()
    command = build_live_smb_share_list_command(
        target,
        tmp_path,
    )
    runner = runner_module.LiveSMBShareListRunner(
        tmp_path,
        target,
    )

    result = runner.run(command)

    assert result.executed is True
    assert result.exit_code == 0
    assert result.error is None
