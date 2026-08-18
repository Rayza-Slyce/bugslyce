from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path

from bugslyce.core.models import ReconCommandResult
from bugslyce.core.project import build_project_state
from bugslyce.recon.collection_confidence import (
    build_collection_confidence_notices_from_project,
    collection_confidence_command_notice_id,
)
from bugslyce.recon.smb_collection import SMBShareCollectionResult


def _failed_result(tmp_path: Path) -> SMBShareCollectionResult:
    command_result = ReconCommandResult(
        command_id="CMD-SMB-SHARES-files.example.test-31337",
        tool="smbclient",
        exit_code=1,
        stdout_path=None,
        stderr_path=str(
            tmp_path
            / "smb-shares-files.example.test-31337.txt.stderr.log"
        ),
        output_file=str(
            tmp_path
            / "smb-shares-files.example.test-31337.txt"
        ),
        started_at="2026-08-18T12:00:00Z",
        ended_at="2026-08-18T12:00:01Z",
        duration_seconds=1.0,
        executed=True,
        simulated=False,
        error="smbclient exited with code 1.",
    )

    return SMBShareCollectionResult(
        input_dir=str(tmp_path),
        scope_file=str(tmp_path / "scope.md"),
        execution_count=1,
        commands_succeeded=0,
        commands_unsuccessful=1,
        commands_timed_out=0,
        command_results=(command_result,),
        shares=(),
        warnings=(),
    )


def test_smb_execution_writer_persists_generic_and_phase_specific_metadata(
    tmp_path: Path,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    result = _failed_result(tmp_path)

    json_path, markdown_path = (
        collection.write_smb_share_execution_result(
            result,
            tmp_path,
        )
    )

    assert json_path == tmp_path / "recon_execution.json"
    assert markdown_path == tmp_path / "recon_execution.md"

    phase_json = tmp_path / "recon_execution_smb_shares.json"
    phase_markdown = tmp_path / "recon_execution_smb_shares.md"

    assert phase_json.is_file()
    assert phase_markdown.is_file()

    payload = json.loads(phase_json.read_text(encoding="utf-8"))

    assert payload["execution_count"] == 1
    assert payload["commands_succeeded"] == 0
    assert payload["commands_unsuccessful"] == 1
    assert payload["commands_timed_out"] == 0

    command = payload["command_results"][0]
    assert command["tool"] == "smbclient"
    assert command["executed"] is True
    assert command["exit_code"] == 1
    assert command["error"] == "smbclient exited with code 1."


def test_phase_specific_smb_failure_survives_generic_execution_metadata_replacement(
    tmp_path: Path,
) -> None:
    collection = import_module("bugslyce.recon.smb_collection")

    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- files.example.test\n",
        encoding="utf-8",
    )

    result = _failed_result(tmp_path)

    collection.write_smb_share_execution_result(
        result,
        tmp_path,
    )

    # Simulate a later pipeline stage replacing the generic latest-execution
    # metadata. The SMB-specific record must remain independently usable.
    (tmp_path / "recon_execution.json").unlink()
    (tmp_path / "recon_execution.md").unlink()

    state = build_project_state(tmp_path)
    notices = build_collection_confidence_notices_from_project(
        state,
        tmp_path,
    )

    expected_notice_id = collection_confidence_command_notice_id(
        "CMD-SMB-SHARES-files.example.test-31337"
    )
    smb_notice = next(
        item
        for item in notices
        if item.notice_id == expected_notice_id
    )

    assert smb_notice.title == (
        "Collection command failed: "
        "CMD-SMB-SHARES-files.example.test-31337"
    )
    assert smb_notice.stage_or_tool == "smbclient"
    assert smb_notice.artefact_references == (
        "recon_execution_smb_shares.json",
    )
    assert "do not infer a negative result" in (
        smb_notice.operator_implication.lower()
    )
