"""Strict, local, non-authoritative project HTTP seed-file ingestion."""

from __future__ import annotations

import os
from pathlib import Path
import stat


MAX_PROJECT_SEED_FILE_BYTES = 1024 * 1024


def load_project_seed_file(path: Path) -> tuple[str, ...]:
    """Load explicit seed strings from one bounded local UTF-8 text file."""

    if not isinstance(path, Path):
        raise ValueError("Project seed-file path must be a local path.")

    content = _read_regular_local_file(path)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Project seed file must be valid UTF-8.") from None

    seeds: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if "#" in value:
            raise ValueError(
                f"Project seed file line {line_number} uses unsupported inline comment syntax."
            )
        seeds.append(value)

    if not seeds:
        raise ValueError("Project seed file must contain one or more seed entries.")

    return tuple(seeds)


def _read_regular_local_file(path: Path) -> bytes:
    """Read one bounded regular local file without following symlinks."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Project seed file must be a regular local file.")

        if metadata.st_size > MAX_PROJECT_SEED_FILE_BYTES:
            raise ValueError("Project seed file exceeds the file-size limit.")

        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(MAX_PROJECT_SEED_FILE_BYTES + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError(
            "Project seed file must be an accessible regular local file."
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(content) > MAX_PROJECT_SEED_FILE_BYTES:
        raise ValueError("Project seed file exceeds the file-size limit.")

    return content


__all__ = [
    "MAX_PROJECT_SEED_FILE_BYTES",
    "load_project_seed_file",
]
