"""Parser for bounded smbclient grepable share-list output."""

from __future__ import annotations

from pathlib import Path
import warnings

from bugslyce.core.models import SMBShare
from bugslyce.recon.smb_eligibility import SMBEnumerationTarget


_SHARE_RECORD_TYPES = {
    "disk": "Disk",
    "ipc": "IPC",
    "printer": "Printer",
}


def parse_smbclient_share_list(
    path: Path,
    target: SMBEnumerationTarget,
) -> list[SMBShare]:
    """Parse share rows without inferring access, writeability or vulnerability."""

    if not path.exists():
        warnings.warn(
            f"SMB share-list output file does not exist: {path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return []

    shares: list[SMBShare] = []
    trigger_service_names = sorted(
        {
            name.casefold()
            for name in target.service_names
            if name
        }
    )
    trigger_evidence_ids = sorted(set(target.evidence_ids))
    trigger_source_files = sorted(set(target.source_files))

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        parts = line.split("|", 2)
        record_type = (
            parts[0].strip().casefold()
            if parts
            else ""
        )

        if record_type not in _SHARE_RECORD_TYPES:
            continue

        if len(parts) != 3 or not parts[1].strip():
            warnings.warn(
                (
                    "Skipping malformed smbclient share line "
                    f"{line_number} in {path}"
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        shares.append(
            SMBShare(
                host=target.host,
                port=target.port,
                share_name=parts[1].strip(),
                share_type=_SHARE_RECORD_TYPES[record_type],
                comment=parts[2].strip(),
                source_file=str(path),
                trigger_service_names=list(trigger_service_names),
                trigger_evidence_ids=list(trigger_evidence_ids),
                trigger_source_files=list(trigger_source_files),
                evidence_ids=[],
                tags=[],
            )
        )

    return shares
