"""Parser for saved nmap normal output."""

from __future__ import annotations

from pathlib import Path
import re
import warnings

from bugslyce.core.models import PortService


SERVICE_LINE = re.compile(
    r"^\s*(?P<port>\d+)\/(?P<protocol>\S+)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<details>.*?))?\s*$"
)
FINGERPRINT_HEADER = re.compile(r"^SF-Port(?P<port>\d+)-(?P<protocol>TCP|UDP):(?P<payload>.*)$")
HTTP_PROTOCOL_EVIDENCE_TAG = "http_protocol_evidence"
HTTP_RESPONSE_STATUS = re.compile(
    r'(?:^|%)r\([^,\r\n]+,[^,\r\n]+,"'
    r'HTTP/1\.[01][ \t]+[1-5]\d{2}(?=[ \t]|\\r|\\n|"|$)'
)


def parse_nmap_normal(path: Path, default_host: str | None = None) -> list[PortService]:
    """Parse service table rows from nmap normal output."""

    if not path.exists():
        warnings.warn(f"Nmap output file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    http_fingerprint_keys = _http_fingerprint_keys(lines, default_host)
    host = default_host or ""
    records: list[PortService] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for "):
            host = _extract_report_host(stripped)
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

    return records


def is_http_capable_port_service(record: PortService) -> bool:
    """Return whether explicit service data or same-port protocol evidence identifies HTTP."""

    return http_scheme_for_port_service(record) is not None


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
    value = line.removeprefix("Nmap scan report for ").strip()
    parenthesized = re.search(r"\(([^()]+)\)$", value)
    return parenthesized.group(1) if parenthesized else value


def _split_product_version(details: str) -> tuple[str | None, str | None]:
    if not details:
        return None, None
    parts = details.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else None
