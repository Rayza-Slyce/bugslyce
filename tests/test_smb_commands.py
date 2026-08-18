from __future__ import annotations

from dataclasses import replace
from importlib import import_module

from bugslyce.recon.smb_eligibility import SMBEnumerationTarget


def _target(
    *,
    host: str = "files.example.test",
    port: int = 31337,
) -> SMBEnumerationTarget:
    return SMBEnumerationTarget(
        host=host,
        port=port,
        service_names=("microsoft-ds",),
        evidence_ids=("EVID-PORT-0001",),
        source_files=("nmap-services-all.txt",),
    )


def test_smb_share_list_command_uses_exact_evidence_derived_port(tmp_path) -> None:
    smb_commands = import_module("bugslyce.recon.smb_commands")

    command = smb_commands.build_live_smb_share_list_command(
        _target(port=31337),
        tmp_path,
    )

    assert command.tool == "smbclient"
    assert command.argv == [
        "smbclient",
        "--configfile=/dev/null",
        "--list=files.example.test",
        "--grepable",
        "--stderr",
        "--no-pass",
        "--user=%",
        "--use-kerberos=off",
        "--name-resolve=host",
        "--port=31337",
        "--timeout=10",
    ]
    assert command.output_file == str(
        tmp_path / "smb-shares-files.example.test-31337.txt"
    )
    assert command.timeout_seconds == 30
    assert command.phase == "smb-share-list"
    assert command.ready_for_execution is True
    assert command.requires_confirmation is True
    assert command.scope_sensitive is True


def test_exact_smb_share_list_command_validates(tmp_path) -> None:
    smb_commands = import_module("bugslyce.recon.smb_commands")
    target = _target(port=1445)

    command = smb_commands.build_live_smb_share_list_command(target, tmp_path)
    validation = smb_commands.validate_live_smb_share_list_command(
        command,
        tmp_path,
        target,
    )

    assert validation.valid is True
    assert validation.errors == []


def test_smb_validator_rejects_credentials_traversal_and_commands(tmp_path) -> None:
    smb_commands = import_module("bugslyce.recon.smb_commands")
    target = _target()
    command = smb_commands.build_live_smb_share_list_command(target, tmp_path)

    forbidden_arguments = (
        "--password=secret",
        "--authentication-file=/tmp/credentials",
        "--command=ls",
        "--directory=/",
        "--machine-pass",
    )

    for forbidden in forbidden_arguments:
        forged = replace(command, argv=[*command.argv, forbidden])
        validation = smb_commands.validate_live_smb_share_list_command(
            forged,
            tmp_path,
            target,
        )

        assert validation.valid is False


def test_smb_validator_rejects_port_or_target_substitution(tmp_path) -> None:
    smb_commands = import_module("bugslyce.recon.smb_commands")
    target = _target(port=31337)
    command = smb_commands.build_live_smb_share_list_command(target, tmp_path)

    wrong_port = [
        "--port=445" if value == "--port=31337" else value
        for value in command.argv
    ]
    forged_port = replace(command, argv=wrong_port)

    wrong_target = [
        "--list=other.example.test"
        if value == "--list=files.example.test"
        else value
        for value in command.argv
    ]
    forged_target = replace(command, argv=wrong_target)

    share_path = [
        "--list=//files.example.test/private"
        if value == "--list=files.example.test"
        else value
        for value in command.argv
    ]
    forged_share = replace(command, argv=share_path)

    for forged in (forged_port, forged_target, forged_share):
        validation = smb_commands.validate_live_smb_share_list_command(
            forged,
            tmp_path,
            target,
        )

        assert validation.valid is False


def test_smb_command_ids_are_unique_per_host_and_port(tmp_path) -> None:
    smb_commands = import_module("bugslyce.recon.smb_commands")

    first = smb_commands.build_live_smb_share_list_command(
        _target(
            host="files-a.example.test",
            port=445,
        ),
        tmp_path,
    )
    second = smb_commands.build_live_smb_share_list_command(
        _target(
            host="files-b.example.test",
            port=445,
        ),
        tmp_path,
    )
    repeated = smb_commands.build_live_smb_share_list_command(
        _target(
            host="files-a.example.test",
            port=445,
        ),
        tmp_path,
    )

    assert first.id != second.id
    assert first.id == repeated.id
    assert first.id.startswith("CMD-SMB-SHARES-")
    assert second.id.startswith("CMD-SMB-SHARES-")
