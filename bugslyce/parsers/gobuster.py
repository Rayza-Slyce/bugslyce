"""Parser for saved gobuster directory output."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urljoin
import warnings

from bugslyce.core.models import DiscoveredPath


_ANSI_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


GOBUSTER_LINE = re.compile(
    r"^\s*(?P<path>\S+)\s+"
    r"\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?\s*$"
)


def parse_gobuster(path: Path, base_url: str | None = None) -> list[DiscoveredPath]:
    """Parse gobuster paths, status codes, sizes, and redirects."""

    if not path.exists():
        warnings.warn(f"Gobuster output file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    records: list[DiscoveredPath] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        clean_line = _ANSI_SGR_RE.sub("", line)
        stripped = clean_line.strip()
        if not stripped or stripped.startswith(("#", "================================================")):
            continue

        match = GOBUSTER_LINE.match(clean_line)
        if not match:
            if "(Status:" in clean_line:
                warnings.warn(
                    f"Skipping malformed gobuster line {line_number} in {path}",
                    RuntimeWarning,
                    stacklevel=2,
                )
            continue

        discovered = match.group("path").lstrip("/")
        url = urljoin(_ensure_trailing_slash(base_url), discovered) if base_url else discovered
        records.append(
            DiscoveredPath(
                url=url,
                status_code=int(match.group("status")),
                content_length=int(match.group("size")) if match.group("size") else None,
                redirect_location=(match.group("redirect") or "").strip() or None,
                source=str(path),
                evidence_ids=[],
                tags=[],
            )
        )

    return records


def _ensure_trailing_slash(value: str | None) -> str:
    if not value:
        return ""
    return value if value.endswith("/") else f"{value}/"
