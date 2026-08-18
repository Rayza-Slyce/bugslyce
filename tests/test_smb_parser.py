from __future__ import annotations

from importlib import import_module
from pathlib import Path

import pytest

from bugslyce.recon.smb_eligibility import SMBEnumerationTarget


def _target(*, port: int = 31337) -> SMBEnumerationTarget:
    return SMBEnumerationTarget(
        host="files.example.test",
        port=port,
        service_names=("microsoft-ds",),
        evidence_ids=("EVID-PORT-0009", "EVID-PORT-0001"),
        source_files=("nmap-services-all.txt",),
    )


def test_smb_parser_preserves_share_values_and_trigger_provenance(
    tmp_path: Path,
) -> None:
    models = import_module("bugslyce.core.models")
    parser = import_module("bugslyce.parsers.smbclient")

    path = tmp_path / "smb-shares-files.example.test-31337.txt"
    path.write_text(
        "Disk|nt4wrksv|Custom share\n"
        "IPC|IPC$|IPC Service\n"
        "Printer|laser|Office printer\n",
        encoding="utf-8",
    )

    shares = parser.parse_smbclient_share_list(path, _target())

    assert all(isinstance(item, models.SMBShare) for item in shares)
    assert tuple(
        (
            item.host,
            item.port,
            item.share_name,
            item.share_type,
            item.comment,
            item.source_file,
            item.trigger_service_names,
            item.trigger_evidence_ids,
            item.evidence_ids,
            item.tags,
        )
        for item in shares
    ) == (
        (
            "files.example.test",
            31337,
            "nt4wrksv",
            "Disk",
            "Custom share",
            str(path),
            ["microsoft-ds"],
            ["EVID-PORT-0001", "EVID-PORT-0009"],
            [],
            [],
        ),
        (
            "files.example.test",
            31337,
            "IPC$",
            "IPC",
            "IPC Service",
            str(path),
            ["microsoft-ds"],
            ["EVID-PORT-0001", "EVID-PORT-0009"],
            [],
            [],
        ),
        (
            "files.example.test",
            31337,
            "laser",
            "Printer",
            "Office printer",
            str(path),
            ["microsoft-ds"],
            ["EVID-PORT-0001", "EVID-PORT-0009"],
            [],
            [],
        ),
    )


def test_smb_parser_ignores_non_share_records_and_preserves_comment_delimiters(
    tmp_path: Path,
) -> None:
    parser = import_module("bugslyce.parsers.smbclient")

    path = tmp_path / "shares.txt"
    path.write_text(
        "Server|FILESERVER|Synthetic server\n"
        "Workgroup|WORKGROUP|FILESERVER\n"
        "Disk|data|Comment | containing | delimiters\n",
        encoding="utf-8",
    )

    shares = parser.parse_smbclient_share_list(path, _target(port=1445))

    assert len(shares) == 1
    assert shares[0].share_name == "data"
    assert shares[0].share_type == "Disk"
    assert shares[0].comment == "Comment | containing | delimiters"
    assert shares[0].port == 1445


def test_smb_parser_warns_on_malformed_share_rows_but_keeps_valid_evidence(
    tmp_path: Path,
) -> None:
    parser = import_module("bugslyce.parsers.smbclient")

    path = tmp_path / "shares.txt"
    path.write_text(
        "Disk|missing-comment\n"
        "IPC||IPC Service\n"
        "Disk|valid|Valid share\n",
        encoding="utf-8",
    )

    with pytest.warns(RuntimeWarning, match="malformed smbclient share line"):
        shares = parser.parse_smbclient_share_list(path, _target())

    assert tuple(item.share_name for item in shares) == ("valid",)


def test_smb_parser_missing_file_is_truthful_no_evidence(
    tmp_path: Path,
) -> None:
    parser = import_module("bugslyce.parsers.smbclient")

    path = tmp_path / "missing.txt"

    with pytest.warns(RuntimeWarning, match="does not exist"):
        shares = parser.parse_smbclient_share_list(path, _target())

    assert shares == []
