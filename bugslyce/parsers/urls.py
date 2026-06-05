"""Parser for one-URL-per-line recon files."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlparse
import warnings

from bugslyce.core.models import ParsedURL


def parse_urls(path: Path) -> list[ParsedURL]:
    """Parse URLs, extracting standard URL components and query parameter names."""

    if not path.exists():
        warnings.warn(f"URL file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    records: list[ParsedURL] = []
    seen: set[str] = set()

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        original_url = line.strip()
        if not original_url or original_url.startswith("#"):
            continue
        if original_url in seen:
            continue

        parsed = urlparse(original_url)
        if not parsed.scheme or not parsed.netloc or not parsed.hostname:
            warnings.warn(
                f"Skipping malformed URL line {line_number} in {path}",
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        seen.add(original_url)
        records.append(
            ParsedURL(
                original_url=original_url,
                scheme=parsed.scheme.lower(),
                hostname=parsed.hostname.lower(),
                path=parsed.path or "/",
                query=parsed.query,
                query_param_names=_query_param_names(parsed.query),
                source_path=str(path),
                line_number=line_number,
            )
        )

    return records


def _query_param_names(query: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for name, _value in parse_qsl(query, keep_blank_values=True):
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names
