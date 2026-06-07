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


def parse_nmap_normal(path: Path, default_host: str | None = None) -> list[PortService]:
    """Parse service table rows from nmap normal output."""

    if not path.exists():
        warnings.warn(f"Nmap output file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    host = default_host or ""
    records: list[PortService] = []

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
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
                tags=[],
            )
        )

    return records


def _extract_report_host(line: str) -> str:
    value = line.removeprefix("Nmap scan report for ").strip()
    parenthesized = re.search(r"\(([^()]+)\)$", value)
    return parenthesized.group(1) if parenthesized else value


def _split_product_version(details: str) -> tuple[str | None, str | None]:
    if not details:
        return None, None
    parts = details.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else None
