"""Shared operator wording for retained sensitive target evidence."""

from __future__ import annotations

from collections.abc import Iterable


REPORT_SENSITIVE_EVIDENCE_NOTICE = (
    "Evidence directories and exported ZIP packs may retain complete response "
    "headers, cookie values, session identifiers, or tokens. Human-facing "
    "cookie summaries omit values, but raw and machine-readable evidence may retain them.",
    "Restrict access and delete or sanitise sensitive retained evidence after "
    "the authorised engagement when it is no longer required.",
)
PACK_SENSITIVE_EVIDENCE_NOTICE = (
    "This archive may contain sensitive recon evidence, including target IP "
    "addresses, URLs, response headers, saved HTML, service banners, and discovered "
    "paths. Raw response evidence may include complete Set-Cookie headers and cookie "
    "values, session identifiers, tokens, or other target-derived values.",
    "Restrict access to this archive. Do not share it publicly unless sharing is "
    "authorised and the contents have been reviewed. Delete it, or sanitise retained "
    "sensitive evidence, after the authorised engagement when it is no longer required.",
)
EXPORT_RESULT_SENSITIVE_WARNINGS = (
    "This export may contain sensitive recon evidence, including retained response "
    "headers, cookie values, session identifiers, or tokens.",
    "Restrict access and delete or sanitise retained sensitive evidence after the "
    "authorised engagement when it is no longer required.",
)
DEEP_SENSITIVE_EVIDENCE_NOTICE = (
    "Sensitive evidence notice: raw HTTP artefacts may retain complete cookie "
    "values; human summaries display cookie names and relevant attributes without "
    "values. Restrict retained evidence appropriately for the authorised engagement."
)


def is_generic_sensitive_retention_note(note: str) -> bool:
    """Identify generic cookie retention/redaction prose, not cookie observations."""

    lowered = note.casefold()
    return "cookie" in lowered and any(
        marker in lowered
        for marker in ("retain", "redact", "omit", "omits", "redacted")
    )


def without_generic_sensitive_retention_notes(
    notes: Iterable[str],
) -> tuple[str, ...]:
    """Remove repeated generic policy prose while preserving evidential notes."""

    return tuple(
        note for note in notes if not is_generic_sensitive_retention_note(note)
    )
