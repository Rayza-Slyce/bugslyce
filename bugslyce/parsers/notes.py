"""Parser for cautious Markdown recon notes."""

from __future__ import annotations

from pathlib import Path
import warnings

from bugslyce.core.models import ParsedNotes, ParserWarning


def parse_notes(path: Path) -> ParsedNotes:
    """Preserve raw notes and extract non-empty Markdown bullet items."""

    source_path = str(path)
    if not path.exists():
        warning = ParserWarning("Notes file does not exist.", source_path)
        warnings.warn(warning.message, RuntimeWarning, stacklevel=2)
        return ParsedNotes("", [], source_path, [warning])

    raw_text = path.read_text(encoding="utf-8")
    note_items: list[str] = []

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("-", "*")):
            continue

        item = stripped[1:].strip()
        if item:
            note_items.append(item)

    return ParsedNotes(raw_text, note_items, source_path)
