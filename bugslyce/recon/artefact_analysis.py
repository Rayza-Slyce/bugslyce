"""Offline artefact/context analysis for already-collected text."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import codecs
import re
from urllib.parse import unquote


POSSIBLE_HASH = "possible_hash"
POSSIBLE_MD5_SHAPE = "possible_md5_shape"
POSSIBLE_SHA1_SHAPE = "possible_sha1_shape"
POSSIBLE_SHA256_SHAPE = "possible_sha256_shape"
POSSIBLE_UNIX_CRYPT_SHAPE = "possible_unix_crypt_shape"
POSSIBLE_BCRYPT_SHAPE = "possible_bcrypt_shape"
POSSIBLE_TRANSFORM = "possible_transform"
POSSIBLE_BASE64 = "possible_base64"
POSSIBLE_BASE32 = "possible_base32"
POSSIBLE_HEX_ENCODING = "possible_hex_encoding"
POSSIBLE_URL_ENCODING = "possible_url_encoding"
POSSIBLE_BINARY_ASCII = "possible_binary_ascii"
POSSIBLE_REVERSED_TEXT = "possible_reversed_text"
POSSIBLE_ROT_OR_CAESAR = "possible_rot_or_caesar"

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
    "clue",
    "decode",
    "encoded",
    "cipher",
    "rot",
    "shift",
    "reverse",
    "backwards",
    "mirror",
)

MANUAL_VALIDATION_STEPS = (
    "Identify the hash type locally with a tool such as hashid or name-that-hash.",
    "Use only authorised/local wordlists if attempting offline cracking.",
    "Do not submit hashes to online databases automatically.",
)
TRANSFORM_MANUAL_VALIDATION_STEPS = (
    "Validate the transformation locally before treating it as evidence.",
    "Preserve both the original value and decoded preview.",
    "Do not submit artefacts to online decoders automatically.",
    "Use only authorised/local tooling and wordlists.",
    "Treat decoded previews as advisory until manually confirmed.",
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
BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])")
BASE32_PATTERN = re.compile(r"(?<![A-Z2-7=])([A-Z2-7]{16,}={0,6})(?![A-Z2-7=])")
HEX_ENCODING_PATTERN = re.compile(r"(?<![#0-9A-Fa-f])([0-9A-Fa-f]{8,128})(?![0-9A-Fa-f])")
URL_ENCODING_PATTERN = re.compile(
    r"((?:[A-Za-z0-9._~/-]*%[0-9A-Fa-f]{2}){2,}[A-Za-z0-9._~/-]*)"
)
BINARY_ASCII_PATTERN = re.compile(r"(?<![01])((?:[01]{8}\s+){2,}[01]{8})(?![01])")
QUOTED_TOKEN_PATTERN = re.compile(r"[\"'`]([A-Za-z0-9_./-]{6,80})[\"'`]")
TEXT_TOKEN_PATTERN = re.compile(r"\b([A-Za-z]{6,80})\b")
MAX_TRANSFORM_VALUE_CHARS = 256
MAX_DECODED_PREVIEW_CHARS = 120


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
    evidence_ids: tuple[str, ...] = ()


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
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransformArtefactCandidate:
    """One encoded-looking or transform-looking artefact candidate."""

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
    decoded_preview: str | None
    priority: str
    explanation: str
    suggested_manual_validation: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()


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


def find_transform_artefacts(
    source: ArtefactSource,
    *,
    max_context_chars: int = 240,
    max_preview_chars: int = MAX_DECODED_PREVIEW_CHARS,
) -> tuple[TransformArtefactCandidate, ...]:
    """Find possible encoding/transform candidates in already-collected text."""

    if not source.text:
        return ()

    candidates: list[TransformArtefactCandidate] = []
    seen: set[tuple[str, str]] = set()

    detectors = (
        (POSSIBLE_URL_ENCODING, URL_ENCODING_PATTERN, _decode_url_value),
        (POSSIBLE_BINARY_ASCII, BINARY_ASCII_PATTERN, _decode_binary_ascii),
        (POSSIBLE_BASE64, BASE64_PATTERN, _decode_base64_value),
        (POSSIBLE_BASE32, BASE32_PATTERN, _decode_base32_value),
        (POSSIBLE_HEX_ENCODING, HEX_ENCODING_PATTERN, _decode_hex_value),
    )
    for candidate_type, pattern, decoder in detectors:
        for match in pattern.finditer(source.text):
            value = match.group(1)
            if len(value) > MAX_TRANSFORM_VALUE_CHARS:
                continue
            decoded = decoder(value, max_preview_chars)
            if decoded is None:
                continue
            identity = (candidate_type, value)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(
                _build_transform_candidate(
                    source,
                    candidate_type,
                    match,
                    decoded,
                    max_context_chars,
                )
            )

    if _context_hints_transform(source.text, ("reverse", "backwards", "mirror")):
        for match in QUOTED_TOKEN_PATTERN.finditer(source.text):
            value = match.group(1)
            decoded = _bounded_preview(value[::-1], max_preview_chars)
            identity = (POSSIBLE_REVERSED_TEXT, value)
            if identity not in seen and _looks_readable(decoded):
                seen.add(identity)
                candidates.append(
                    _build_transform_candidate(
                        source,
                        POSSIBLE_REVERSED_TEXT,
                        match,
                        decoded,
                        max_context_chars,
                    )
                )

    if _context_hints_transform(source.text, ("rot", "rotate", "caesar", "shift", "cipher")):
        for match in TEXT_TOKEN_PATTERN.finditer(source.text):
            value = match.group(1)
            if value.lower() in HIGH_SIGNAL_KEYWORDS:
                continue
            decoded = _bounded_preview(codecs.decode(value, "rot_13"), max_preview_chars)
            identity = (POSSIBLE_ROT_OR_CAESAR, value)
            if identity not in seen and decoded.lower() != value.lower():
                seen.add(identity)
                candidates.append(
                    _build_transform_candidate(
                        source,
                        POSSIBLE_ROT_OR_CAESAR,
                        match,
                        decoded,
                        max_context_chars,
                    )
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
        evidence_ids=source.evidence_ids,
    )


def _build_transform_candidate(
    source: ArtefactSource,
    candidate_type: str,
    match: re.Match[str],
    decoded_preview: str | None,
    max_context_chars: int,
) -> TransformArtefactCandidate:
    start = match.start(1)
    end = match.end(1)
    line_number = source.text.count("\n", 0, start) + 1
    context = _context_window(source.text, start, end, max_context_chars)
    nearby_keywords = _nearby_keywords(context)
    priority = "high" if nearby_keywords else "medium"
    explanation = _transform_explanation(candidate_type, decoded_preview, nearby_keywords)
    return TransformArtefactCandidate(
        value=match.group(1),
        category=POSSIBLE_TRANSFORM,
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
        decoded_preview=decoded_preview,
        priority=priority,
        explanation=explanation,
        suggested_manual_validation=TRANSFORM_MANUAL_VALIDATION_STEPS,
        evidence_ids=source.evidence_ids,
    )


def _transform_explanation(
    candidate_type: str,
    decoded_preview: str | None,
    nearby_keywords: tuple[str, ...],
) -> str:
    if candidate_type == POSSIBLE_BASE64:
        prefix = "Possible Base64 candidate detected."
    elif candidate_type == POSSIBLE_BASE32:
        prefix = "Possible Base32 candidate detected."
    elif candidate_type == POSSIBLE_HEX_ENCODING:
        prefix = "Possible hex-encoded candidate detected."
    elif candidate_type == POSSIBLE_URL_ENCODING:
        prefix = "Possible URL-encoded candidate detected."
    elif candidate_type == POSSIBLE_BINARY_ASCII:
        prefix = "Possible binary ASCII candidate detected."
    elif candidate_type == POSSIBLE_REVERSED_TEXT:
        prefix = "Shape and context suggest a possible reversed-text candidate."
    else:
        prefix = "Shape and context suggest a possible ROT/Caesar transform candidate."

    context = (
        " Encoded-looking value appears near high-signal wording. Manual review recommended."
        if nearby_keywords
        else " Encoded-looking value detected. Manual review recommended."
    )
    preview = (
        " Decoded preview appears path-like; validate manually."
        if decoded_preview and _looks_path_like(decoded_preview)
        else " Derived preview is advisory and may be incorrect."
    )
    return prefix + context + preview


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


def _decode_base64_value(value: str, max_preview_chars: int) -> str | None:
    if len(value) % 4 != 0 or len(value.rstrip("=")) < 8:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _decode_printable_bytes(decoded, max_preview_chars)


def _decode_base32_value(value: str, max_preview_chars: int) -> str | None:
    if len(value) % 8 != 0 or not any(character in "234567" for character in value):
        return None
    try:
        decoded = base64.b32decode(value, casefold=True)
    except (binascii.Error, ValueError):
        return None
    return _decode_printable_bytes(decoded, max_preview_chars)


def _decode_hex_value(value: str, max_preview_chars: int) -> str | None:
    if len(value) % 2 != 0 or len(value) < 8 or len(value) in {32, 40, 64}:
        return None
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return None
    return _decode_printable_bytes(decoded, max_preview_chars)


def _decode_url_value(value: str, max_preview_chars: int) -> str | None:
    decoded = unquote(value)
    if decoded == value or not _looks_readable(decoded):
        return None
    return _bounded_preview(decoded, max_preview_chars)


def _decode_binary_ascii(value: str, max_preview_chars: int) -> str | None:
    groups = value.split()
    try:
        decoded = "".join(chr(int(group, 2)) for group in groups)
    except ValueError:
        return None
    if not _looks_readable(decoded):
        return None
    return _bounded_preview(decoded, max_preview_chars)


def _decode_printable_bytes(value: bytes, max_preview_chars: int) -> str | None:
    if not value:
        return None
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _looks_readable(decoded):
        return None
    return _bounded_preview(decoded, max_preview_chars)


def _bounded_preview(value: str, max_preview_chars: int) -> str:
    if len(value) <= max_preview_chars:
        return value
    if max_preview_chars <= 3:
        return value[:max_preview_chars]
    return value[: max_preview_chars - 3] + "..."


def _looks_readable(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 2:
        return False
    printable = sum(character.isprintable() and character not in "\x0b\x0c" for character in stripped)
    return printable / len(stripped) >= 0.9


def _looks_path_like(value: str) -> bool:
    return value.startswith("/") or "/" in value


def _context_hints_transform(text: str, hints: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in hints)
