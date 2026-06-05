"""Parser for one-hostname-per-line subdomain files."""

from __future__ import annotations

from pathlib import Path
import warnings

from bugslyce.core.models import ParsedSubdomain


def parse_subdomains(path: Path) -> list[ParsedSubdomain]:
    """Parse a subdomain text file, preserving first-seen order after dedupe."""

    if not path.exists():
        warnings.warn(f"Subdomain file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    records: list[ParsedSubdomain] = []
    seen: set[str] = set()

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        hostname = line.strip()
        if not hostname or hostname.startswith("#"):
            continue

        hostname = hostname.lower()
        if hostname in seen:
            continue

        seen.add(hostname)
        records.append(ParsedSubdomain(hostname, str(path), line_number))

    return records
