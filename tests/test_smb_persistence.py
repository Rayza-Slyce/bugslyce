from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

from bugslyce.core.models import ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.reports.markdown import write_project_outputs


def _write_project(
    root: Path,
    *,
    include_smb_artefact: bool = True,
) -> None:
    (root / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- files.example.test\n",
        encoding="utf-8",
    )
    (root / "bugslyce_project.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "engagement_context": "ctf",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    (root / "nmap-allports.txt").write_text(
        "Nmap scan report for files.example.test\n"
        "PORT      STATE SERVICE\n"
        "31337/tcp open  microsoft-ds\n",
        encoding="utf-8",
    )
    (root / "nmap-services-all.txt").write_text(
        "Nmap scan report for files.example.test\n"
        "PORT      STATE SERVICE      VERSION\n"
        "31337/tcp open  microsoft-ds Samba smbd 4.19\n",
        encoding="utf-8",
    )

    artifacts: list[dict[str, object]] = [
        {
            "type": "nmap",
            "file": "nmap-allports.txt",
            "description": "Synthetic discovery evidence",
        },
        {
            "type": "nmap",
            "file": "nmap-services-all.txt",
            "description": "Synthetic service evidence",
        },
    ]

    if include_smb_artefact:
        (root / "smb-shares-files.example.test-31337.txt").write_text(
            "Disk|nt4wrksv|Custom share\n"
            "IPC|IPC$|IPC Service\n",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "type": "smb_shares",
                "file": "smb-shares-files.example.test-31337.txt",
                "host": "files.example.test",
                "port": 31337,
                "protocol": "tcp",
                "description": (
                    "Bounded anonymous SMB share listing for "
                    "evidence-backed SMB endpoint"
                ),
            }
        )

    (root / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "files.example.test",
                "scope_file": "scope.md",
                "created_by": "bugslyce-test",
                "profile": "deep-bounded",
                "artifacts": artifacts,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _command_result(command) -> ReconCommandResult:
    return ReconCommandResult(
        command_id=command.id,
        tool=command.tool,
        exit_code=0,
        stdout_path=None,
        stderr_path=None,
        output_file=command.output_file,
        started_at="2026-08-18T09:00:00Z",
        ended_at="2026-08-18T09:00:01Z",
        duration_seconds=1.0,
        executed=True,
        simulated=False,
        error=None,
    )


def test_project_state_reconstructs_smb_shares_with_direct_and_trigger_evidence(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)

    state = build_project_state(tmp_path)

    assert len(state.smb_shares) == 2

    custom = state.smb_shares[0]
    assert (
        custom.host,
        custom.port,
        custom.share_name,
        custom.share_type,
        custom.comment,
    ) == (
        "files.example.test",
        31337,
        "nt4wrksv",
        "Disk",
        "Custom share",
    )

    assert len(custom.evidence_ids) == 1
    assert custom.trigger_service_names == ["microsoft-ds"]

    port_service = state.port_services[0]
    assert custom.trigger_evidence_ids == sorted(port_service.evidence_ids)
    assert tuple(
        sorted(Path(value).name for value in custom.trigger_source_files)
    ) == (
        "nmap-allports.txt",
        "nmap-services-all.txt",
    )

    direct = next(
        item
        for item in state.evidence
        if item.id == custom.evidence_ids[0]
    )
    assert direct.evidence_type == "smb_share"
    assert direct.value == "nt4wrksv"
    assert Path(direct.source_file).name == (
        "smb-shares-files.example.test-31337.txt"
    )
    assert direct.context["host"] == "files.example.test"
    assert direct.context["port"] == 31337
    assert direct.context["share_type"] == "Disk"

    assert any(
        Path(value).name == "smb-shares-files.example.test-31337.txt"
        for value in state.processed_files
    )


def test_project_state_json_persists_typed_smb_share_evidence(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)

    state = build_project_state(tmp_path)
    write_project_outputs(state, [], tmp_path)

    payload = json.loads(
        (tmp_path / "project_state.json").read_text(encoding="utf-8")
    )
    shares = payload["project_state"]["smb_shares"]

    assert len(shares) == 2
    assert shares[0]["share_name"] == "nt4wrksv"
    assert shares[0]["port"] == 31337
    assert len(shares[0]["evidence_ids"]) == 1
    assert len(shares[0]["trigger_evidence_ids"]) == 2
    assert tuple(
        sorted(Path(value).name for value in shares[0]["trigger_source_files"])
    ) == (
        "nmap-allports.txt",
        "nmap-services-all.txt",
    )


def test_evidence_pack_includes_and_portabilises_smb_share_provenance(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)

    state = build_project_state(tmp_path)
    write_project_outputs(state, [], tmp_path)

    output_path = tmp_path.parent / f"{tmp_path.name}-evidence-pack.zip"
    export_recon_evidence_pack(
        tmp_path,
        output_path,
    )

    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        assert (
            "raw/smb-shares-files.example.test-31337.txt"
            in names
        )

        packed_state = json.loads(
            archive.read("project_state.json").decode("utf-8")
        )
        packed_manifest = json.loads(
            archive.read("recon_manifest.json").decode("utf-8")
        )

    share = packed_state["project_state"]["smb_shares"][0]

    assert share["source_file"] == (
        "raw/smb-shares-files.example.test-31337.txt"
    )
    assert tuple(sorted(share["trigger_source_files"])) == (
        "raw/nmap-allports.txt",
        "raw/nmap-services-all.txt",
    )

    direct = next(
        item
        for item in packed_state["project_state"]["evidence"]
        if item["id"] == share["evidence_ids"][0]
    )
    assert direct["source_file"] == (
        "raw/smb-shares-files.example.test-31337.txt"
    )

    smb_manifest_entries = [
        item
        for item in packed_manifest["artifacts"]
        if item["type"] == "smb_shares"
    ]
    assert smb_manifest_entries == [
        {
            "description": (
                "Bounded anonymous SMB share listing for "
                "evidence-backed SMB endpoint"
            ),
            "file": "raw/smb-shares-files.example.test-31337.txt",
            "host": "files.example.test",
            "port": 31337,
            "protocol": "tcp",
            "type": "smb_shares",
        }
    ]


def test_successful_smb_collection_registers_rebuildable_manifest_artefact(
    tmp_path: Path,
) -> None:
    from bugslyce.recon.smb_collection import collect_smb_share_evidence

    _write_project(
        tmp_path,
        include_smb_artefact=False,
    )

    observed_ports: list[int] = []

    def runner_factory(target):
        observed_ports.append(target.port)

        class Runner:
            def run(self, command):
                Path(command.output_file).write_text(
                    "Disk|nt4wrksv|Custom share\n",
                    encoding="utf-8",
                )
                return _command_result(command)

        return Runner()

    result = collect_smb_share_evidence(
        tmp_path,
        tmp_path / "scope.md",
        runner_factory=runner_factory,
    )

    assert result.commands_succeeded == 1
    assert observed_ports == [31337]

    manifest = json.loads(
        (tmp_path / "recon_manifest.json").read_text(encoding="utf-8")
    )
    entries = [
        item
        for item in manifest["artifacts"]
        if item.get("type") == "smb_shares"
    ]

    assert entries == [
        {
            "type": "smb_shares",
            "file": "smb-shares-files.example.test-31337.txt",
            "host": "files.example.test",
            "port": 31337,
            "protocol": "tcp",
            "description": (
                "Bounded anonymous SMB share listing for "
                "evidence-backed SMB endpoint"
            ),
        }
    ]

    rebuilt = build_project_state(tmp_path)

    assert len(rebuilt.smb_shares) == 1
    assert rebuilt.smb_shares[0].share_name == "nt4wrksv"
    assert rebuilt.smb_shares[0].port == 31337


def test_failed_smb_rerun_does_not_preserve_previous_success_as_current_evidence(
    tmp_path: Path,
) -> None:
    from bugslyce.recon.smb_collection import collect_smb_share_evidence

    _write_project(
        tmp_path,
        include_smb_artefact=True,
    )

    before = build_project_state(tmp_path)
    assert tuple(item.share_name for item in before.smb_shares) == (
        "nt4wrksv",
        "IPC$",
    )

    class TimeoutRunner:
        def run(self, command):
            return ReconCommandResult(
                command_id=command.id,
                tool=command.tool,
                exit_code=None,
                stdout_path=None,
                stderr_path=None,
                output_file=command.output_file,
                started_at="2026-08-18T09:00:00Z",
                ended_at="2026-08-18T09:00:30Z",
                duration_seconds=30.0,
                executed=True,
                simulated=False,
                error="SMB share listing exceeded 30 seconds.",
            )

    result = collect_smb_share_evidence(
        tmp_path,
        tmp_path / "scope.md",
        runner_factory=lambda _target: TimeoutRunner(),
    )

    assert result.commands_timed_out == 1

    manifest = json.loads(
        (tmp_path / "recon_manifest.json").read_text(encoding="utf-8")
    )
    assert not any(
        item.get("type") == "smb_shares"
        for item in manifest["artifacts"]
    )

    rebuilt = build_project_state(tmp_path)
    assert rebuilt.smb_shares == []


def test_smb_collection_refuses_scope_that_differs_from_manifest_scope(
    tmp_path: Path,
) -> None:
    import pytest

    from bugslyce.recon.smb_collection import collect_smb_share_evidence

    _write_project(
        tmp_path,
        include_smb_artefact=False,
    )

    # The project manifest declares scope.md as authoritative, but that
    # scope does not authorise the discovered SMB host.
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- other.example.test\n",
        encoding="utf-8",
    )

    # A different caller-supplied scope would authorise the SMB host.
    alternate_scope = tmp_path / "alternate-scope.md"
    alternate_scope.write_text(
        "# Scope\n\n## In Scope\n\n- files.example.test\n",
        encoding="utf-8",
    )

    def forbidden_factory(_target):
        raise AssertionError(
            "SMB runner was created using a non-authoritative scope file."
        )

    with pytest.raises(
        ValueError,
        match="authoritative project scope",
    ):
        collect_smb_share_evidence(
            tmp_path,
            alternate_scope,
            runner_factory=forbidden_factory,
        )


def test_evidence_pack_validator_rejects_missing_smb_share_source_reference(
    tmp_path: Path,
) -> None:
    from bugslyce.recon.evidence_pack_closure import validate_evidence_pack_root

    _write_project(tmp_path)

    state = build_project_state(tmp_path)
    write_project_outputs(state, [], tmp_path)

    output_path = tmp_path.parent / f"{tmp_path.name}-smb-source-closure.zip"
    export_recon_evidence_pack(
        tmp_path,
        output_path,
    )

    extracted = tmp_path.parent / f"{tmp_path.name}-smb-source-closure"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    state_path = extracted / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["smb_shares"][0]["source_file"] = (
        "raw/missing-smb-share.txt"
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any(
        error.startswith("portable_project_state_smb_share")
        for error in validation.metadata_consistency_errors
    )


def test_evidence_pack_validator_rejects_missing_smb_trigger_source_reference(
    tmp_path: Path,
) -> None:
    from bugslyce.recon.evidence_pack_closure import validate_evidence_pack_root

    _write_project(tmp_path)

    state = build_project_state(tmp_path)
    write_project_outputs(state, [], tmp_path)

    output_path = tmp_path.parent / f"{tmp_path.name}-smb-trigger-closure.zip"
    export_recon_evidence_pack(
        tmp_path,
        output_path,
    )

    extracted = tmp_path.parent / f"{tmp_path.name}-smb-trigger-closure"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    state_path = extracted / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["smb_shares"][0]["trigger_source_files"][0] = (
        "raw/missing-smb-trigger.txt"
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any(
        error.startswith("portable_project_state_smb_share")
        for error in validation.metadata_consistency_errors
    )
