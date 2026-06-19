"""Offline artefact/context analysis for already-collected text."""

from __future__ import annotations

from dataclasses import dataclass
import re


POSSIBLE_HASH = "possible_hash"
POSSIBLE_MD5_SHAPE = "possible_md5_shape"
POSSIBLE_SHA1_SHAPE = "possible_sha1_shape"
POSSIBLE_SHA256_SHAPE = "possible_sha256_shape"
POSSIBLE_UNIX_CRYPT_SHAPE = "possible_unix_crypt_shape"
POSSIBLE_BCRYPT_SHAPE = "possible_bcrypt_shape"

HIGH_SIGNAL_KEYWORDS = (
    "flag",
    "password",
    "passwd",
    "secret",
    "key",
    "token",
    "robots",
    "hidden",
    "user-agent",
    "admin",
    "credential",
    "credentials",
)

MANUAL_VALIDATION_STEPS = (
    "Identify the hash type locally with a tool such as hashid or name-that-hash.",
    "Use only authorised/local wordlists if attempting offline cracking.",
    "Do not submit hashes to online databases automatically.",
)

HEX_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        POSSIBLE_SHA256_SHAPE,
        re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])"),
    ),
    (
        POSSIBLE_SHA1_SHAPE,
        re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{40})(?![0-9A-Fa-f])"),
    ),
    (
        POSSIBLE_MD5_SHAPE,
        re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32})(?![0-9A-Fa-f])"),
    ),
)
UNIX_CRYPT_PATTERN = re.compile(
    r"(?<!\S)(\$[156]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{10,86})(?!\S)"
)
BCRYPT_PATTERN = re.compile(
    r"(?<!\S)(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})(?!\S)"
)


@dataclass(frozen=True)
class ArtefactSource:
    """Source text and provenance for offline artefact analysis."""

    source_id: str
    text: str
    source_kind: str = "unknown"
    source_label: str | None = None
    url: str | None = None
    path: str | None = None
    port: int | None = None
    service: str | None = None
    field_name: str | None = None


@dataclass(frozen=True)
class HashArtefactCandidate:
    """One hash-shaped artefact candidate with bounded source context."""

    value: str
    category: str
    candidate_type: str
    source_id: str
    source_kind: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    field_name: str | None
    line_number: int
    start_offset: int
    end_offset: int
    context: str
    nearby_keywords: tuple[str, ...]
    priority: str
    explanation: str
    suggested_manual_validation: tuple[str, ...]


def find_hash_artefacts(
    source: ArtefactSource,
    *,
    max_context_chars: int = 240,
) -> tuple[HashArtefactCandidate, ...]:
    """Find hash-shaped artefacts in already-collected text.

    Detection is shape-only. Returned candidates deliberately use cautious
    wording and do not claim the hash type is confirmed.
    """

    if not source.text:
        return ()

    candidates: list[HashArtefactCandidate] = []
    seen: set[tuple[str, str]] = set()
    for candidate_type, pattern in (
        (POSSIBLE_BCRYPT_SHAPE, BCRYPT_PATTERN),
        (POSSIBLE_UNIX_CRYPT_SHAPE, UNIX_CRYPT_PATTERN),
        *HEX_PATTERNS,
    ):
        for match in pattern.finditer(source.text):
            value = match.group(1)
            identity = (candidate_type, value)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(
                _build_candidate(source, candidate_type, match, max_context_chars)
            )

    return tuple(sorted(candidates, key=lambda item: (item.start_offset, item.end_offset)))


def _build_candidate(
    source: ArtefactSource,
    candidate_type: str,
    match: re.Match[str],
    max_context_chars: int,
) -> HashArtefactCandidate:
    start = match.start(1)
    end = match.end(1)
    line_number = source.text.count("\n", 0, start) + 1
    context = _context_window(source.text, start, end, max_context_chars)
    nearby_keywords = _nearby_keywords(context)
    priority = "high" if nearby_keywords else "medium"
    explanation = (
        "Hash-shaped value appears near high-signal wording. Manual review recommended. "
        "Shape alone does not confirm the hash type."
        if nearby_keywords
        else "Possible hash candidate detected. Shape alone does not confirm the hash type."
    )
    return HashArtefactCandidate(
        value=match.group(1),
        category=POSSIBLE_HASH,
        candidate_type=candidate_type,
        source_id=source.source_id,
        source_kind=source.source_kind,
        source_label=source.source_label,
        url=source.url,
        path=source.path,
        port=source.port,
        service=source.service,
        field_name=source.field_name,
        line_number=line_number,
        start_offset=start,
        end_offset=end,
        context=context,
        nearby_keywords=nearby_keywords,
        priority=priority,
        explanation=explanation,
        suggested_manual_validation=MANUAL_VALIDATION_STEPS,
    )


def _context_window(text: str, start: int, end: int, max_context_chars: int) -> str:
    line_start = text.rfind("\n", 0, start)
    previous_line_start = text.rfind("\n", 0, max(line_start, 0))
    context_start = 0 if previous_line_start == -1 else previous_line_start + 1

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    next_line_end = text.find("\n", line_end + 1)
    context_end = len(text) if next_line_end == -1 else next_line_end

    context = text[context_start:context_end].strip()
    if len(context) <= max_context_chars:
        return context

    relative_start = max(0, start - context_start)
    relative_end = max(relative_start, end - context_start)
    keep_before = max(0, (max_context_chars - (relative_end - relative_start)) // 2)
    window_start = max(0, relative_start - keep_before)
    window_end = min(len(context), window_start + max_context_chars)
    if window_end - window_start < max_context_chars:
        window_start = max(0, window_end - max_context_chars)
    prefix = "..." if window_start > 0 else ""
    suffix = "..." if window_end < len(context) else ""
    available = max_context_chars - len(prefix) - len(suffix)
    bounded = context[window_start : window_start + max(0, available)].strip()
    bounded = f"{prefix}{bounded}{suffix}"
    return bounded


def _nearby_keywords(context: str) -> tuple[str, ...]:
    lowered = context.lower()
    return tuple(keyword for keyword in HIGH_SIGNAL_KEYWORDS if keyword in lowered)
