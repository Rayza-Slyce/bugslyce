"""Offline eligibility selection for evidence-backed SMB enumeration."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.core.models import Evidence, PortService
from bugslyce.parsers.nmap import is_smb_capable_port_service


@dataclass(frozen=True)
class SMBEnumerationTarget:
    """One retained SMB endpoint eligible for bounded enumeration."""

    host: str
    port: int
    service_names: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source_files: tuple[str, ...]


def select_smb_enumeration_targets(
    port_services: tuple[PortService, ...] | list[PortService],
    evidence: tuple[Evidence, ...] | list[Evidence] = (),
) -> tuple[SMBEnumerationTarget, ...]:
    """Select deterministic SMB endpoints entirely from retained service facts."""

    evidence_source_by_id = {
        item.id: item.source_file
        for item in evidence
        if item.id and item.source_file
    }
    grouped: dict[tuple[str, int], dict[str, set[str]]] = {}

    for record in port_services:
        if not is_smb_capable_port_service(record):
            continue

        key = (record.host, record.port)
        item = grouped.setdefault(
            key,
            {
                "service_names": set(),
                "evidence_ids": set(),
                "source_files": set(),
            },
        )
        if record.service:
            item["service_names"].add(record.service.casefold())
        item["evidence_ids"].update(record.evidence_ids)
        if record.source_file:
            item["source_files"].add(record.source_file)
        for evidence_id in record.evidence_ids:
            source_file = evidence_source_by_id.get(evidence_id)
            if source_file:
                item["source_files"].add(source_file)

    return tuple(
        SMBEnumerationTarget(
            host=host,
            port=port,
            service_names=tuple(sorted(values["service_names"])),
            evidence_ids=tuple(sorted(values["evidence_ids"])),
            source_files=tuple(sorted(values["source_files"])),
        )
        for (host, port), values in sorted(
            grouped.items(),
            key=lambda item: (item[0][0].casefold(), item[0][1], item[0][0]),
        )
    )
