"""Parser for saved nmap normal output."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import warnings

from bugslyce.core.models import NmapReportedHostPeer, PortService


SERVICE_LINE = re.compile(
    r"^\s*(?P<port>\d+)\/(?P<protocol>\S+)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<details>.*?))?\s*$"
)
FINGERPRINT_HEADER = re.compile(r"^SF-Port(?P<port>\d+)-(?P<protocol>TCP|UDP):(?P<payload>.*)$")
HTTP_PROTOCOL_EVIDENCE_TAG = "http_protocol_evidence"
NMAP_OUTPUT_DISCOVERY = "discovery"
NMAP_OUTPUT_SERVICE_VERSION = "service_version"
NMAP_OUTPUT_UNKNOWN = "unknown"
HTTP_RESPONSE_STATUS = re.compile(
    r'(?:^|%)r\([^,\r\n]+,[^,\r\n]+,"'
    r'HTTP/1\.[01][ \t]+[1-5]\d{2}(?=[ \t]|\\r|\\n|"|$)'
)


@dataclass(frozen=True)
class NmapNormalParseResult:
    """Port rows and explicit report-name to peer-host observations."""

    port_services: list[PortService]
    reported_host_peers: list[NmapReportedHostPeer]


def classify_nmap_output_role(path: Path) -> str:
    """Classify retained BugSlyce Nmap output by its service-table shape."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return NMAP_OUTPUT_UNKNOWN
    roles: set[str] = set()
    for line in lines:
        columns = line.strip().split()
        if columns[:3] != ["PORT", "STATE", "SERVICE"]:
            continue
        if len(columns) == 3:
            roles.add(NMAP_OUTPUT_DISCOVERY)
        elif columns[3] == "VERSION":
            roles.add(NMAP_OUTPUT_SERVICE_VERSION)
    if NMAP_OUTPUT_SERVICE_VERSION in roles:
        return NMAP_OUTPUT_SERVICE_VERSION
    if NMAP_OUTPUT_DISCOVERY in roles:
        return NMAP_OUTPUT_DISCOVERY
    return NMAP_OUTPUT_UNKNOWN


def parse_nmap_normal(path: Path, default_host: str | None = None) -> list[PortService]:
    """Parse service table rows from nmap normal output."""

    return parse_nmap_normal_with_host_peers(path, default_host).port_services


def parse_nmap_normal_with_host_peers(
    path: Path,
    default_host: str | None = None,
) -> NmapNormalParseResult:
    """Parse service rows and explicit Nmap report-name peer relationships."""

    if not path.exists():
        warnings.warn(f"Nmap output file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return NmapNormalParseResult([], [])

    lines = path.read_text(encoding="utf-8").splitlines()
    http_fingerprint_keys = _http_fingerprint_keys(lines, default_host)
    host = default_host or ""
    records: list[PortService] = []
    reported_host_peers: list[NmapReportedHostPeer] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for "):
            host, reported_host = _extract_report_identity(stripped)
            if reported_host is not None:
                reported_host_peers.append(
                    NmapReportedHostPeer(
                        reported_host=reported_host,
                        peer_host=host,
                        source_file=str(path),
                        report_line=line_number,
                    )
                )
            continue
        if not stripped or stripped.startswith(("PORT ", "Service detection", "Nmap done")):
            continue

        match = SERVICE_LINE.match(line)
        if not match:
            if re.match(r"^\s*\d+/", line):
                warnings.warn(
                    f"Skipping malformed nmap service line {line_number} in {path}",
                    RuntimeWarning,
                    stacklevel=2,
                )
            continue

        details = (match.group("details") or "").strip()
        product, version = _split_product_version(details)
        records.append(
            PortService(
                host=host,
                port=int(match.group("port")),
                protocol=match.group("protocol").lower(),
                state=match.group("state").lower(),
                service=match.group("service").lower(),
                product=product,
                version=version,
                source_file=str(path),
                evidence_ids=[],
                tags=(
                    [HTTP_PROTOCOL_EVIDENCE_TAG]
                    if (host, int(match.group("port")), match.group("protocol").lower())
                    in http_fingerprint_keys
                    else []
                ),
            )
        )

    return NmapNormalParseResult(records, reported_host_peers)


def is_http_capable_port_service(record: PortService) -> bool:
    """Return whether explicit service data or same-port protocol evidence identifies HTTP."""

    return http_scheme_for_port_service(record) is not None


def is_smb_capable_port_service(record: PortService) -> bool:
    """Return whether retained open-TCP service evidence identifies SMB."""

    service = (record.service or "").casefold()
    protocol = (record.protocol or "").casefold()
    state = (record.state or "").casefold()
    return (
        protocol == "tcp"
        and state == "open"
        and service in {"microsoft-ds", "netbios-ssn"}
    )


def http_scheme_for_port_service(record: PortService) -> str | None:
    """Return the evidence-backed HTTP scheme without changing the raw service label."""

    service = (record.service or "").lower()
    if service in {"http", "https", "http-proxy", "https-alt"} or "http" in service:
        return "https" if "https" in service or record.port == 443 else "http"
    if HTTP_PROTOCOL_EVIDENCE_TAG in record.tags:
        return "http"
    return None


def _http_fingerprint_keys(
    lines: list[str],
    default_host: str | None,
) -> set[tuple[str, int, str]]:
    fingerprints: dict[tuple[str, int, str], list[str]] = {}
    host = default_host or ""
    current_key: tuple[str, int, str] | None = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for "):
            host = _extract_report_host(stripped)
            current_key = None
            continue
        header = FINGERPRINT_HEADER.match(line)
        if header:
            current_key = (
                host,
                int(header.group("port")),
                header.group("protocol").lower(),
            )
            fingerprints.setdefault(current_key, []).append(header.group("payload"))
            continue
        if current_key is not None and line.startswith("SF:"):
            fingerprints[current_key].append(line.removeprefix("SF:"))
            continue
        current_key = None

    return {
        key
        for key, parts in fingerprints.items()
        if _contains_http_status_line("".join(parts))
    }


def _contains_http_status_line(payload: str) -> bool:
    normalised = payload.replace(r"\.", ".").replace(r"\x20", " ")
    return HTTP_RESPONSE_STATUS.search(normalised) is not None


def _extract_report_host(line: str) -> str:
    host, _reported_host = _extract_report_identity(line)
    return host


def _extract_report_identity(line: str) -> tuple[str, str | None]:
    value = line.removeprefix("Nmap scan report for ").strip()
    parenthesized = re.search(r"\(([^()]+)\)$", value)
    if parenthesized is None:
        return value, None
    peer_host = parenthesized.group(1).strip()
    reported_host = value[: parenthesized.start()].strip()
    if not reported_host or not peer_host or reported_host == peer_host:
        return peer_host, None
    return peer_host, reported_host


def _split_product_version(details: str) -> tuple[str | None, str | None]:
    if not details:
        return None, None
    parts = details.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else None
