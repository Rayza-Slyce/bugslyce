"""Immutable shared operator-brief semantics and deterministic persistence."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from bugslyce.reports.operator_summary import OperatorSummary


OPERATOR_BRIEF_FILENAME = "operator_brief.json"
_OPERATOR_BRIEF_SCHEMA_VERSION = 1
_OPERATOR_BRIEF_GENERATED_BY = "bugslyce.operator_brief"

PRIMARY_THREAD = "primary_thread"
SUPPORTING_CONTEXT = "supporting_context"
DEPRIORITISED_CONTEXT = "deprioritised_context"
EVIDENCE_ONLY = "evidence_only"

_VALID_DISPOSITIONS = frozenset(
    {
        PRIMARY_THREAD,
        SUPPORTING_CONTEXT,
        DEPRIORITISED_CONTEXT,
        EVIDENCE_ONLY,
    }
)


@dataclass(frozen=True)
class OperatorBriefThread:
    """One immutable operator-facing investigation subject."""

    thread_id: str
    title: str
    rank: int
    score: int
    signal: str
    source_lead_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    why_review: str
    next_review_step: str
    observed_facts: tuple[str, ...] = ()
    related_context: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    coverage_limitations: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    source_artefacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.thread_id.strip():
            raise ValueError("Operator Brief threads require a thread ID.")
        if not self.title.strip():
            raise ValueError("Operator Brief threads require a title.")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank < 1:
            raise ValueError("Operator Brief thread rank must be a positive integer.")
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise ValueError("Operator Brief thread score must be an integer.")
        if not self.signal.strip():
            raise ValueError("Operator Brief threads require a signal.")
        if any(not value.strip() for value in self.source_lead_ids):
            raise ValueError("Operator Brief source lead IDs cannot be blank.")


@dataclass(frozen=True)
class OperatorBriefDisposition:
    """Auditable disposition of one existing operator-facing interpretation."""

    source_kind: str
    source_id: str
    disposition: str
    thread_id: str = ""

    def __post_init__(self) -> None:
        if not self.source_kind.strip():
            raise ValueError("Operator Brief dispositions require a source kind.")
        if not self.source_id.strip():
            raise ValueError("Operator Brief dispositions require a source ID.")
        if self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("Operator Brief disposition is invalid.")
        if self.disposition in {PRIMARY_THREAD, SUPPORTING_CONTEXT} and not (
            self.thread_id.strip()
        ):
            raise ValueError(
                "Primary-thread and supporting-context dispositions require a thread ID."
            )


@dataclass(frozen=True)
class OperatorBriefView:
    """Shared semantic Operator Brief consumed by report presentation paths."""

    threads: tuple[OperatorBriefThread, ...]
    dispositions: tuple[OperatorBriefDisposition, ...]

    def __post_init__(self) -> None:
        thread_ids = {thread.thread_id for thread in self.threads}
        if len(thread_ids) != len(self.threads):
            raise ValueError("Operator Brief contains duplicate thread IDs.")

        disposition_sources = {
            (item.source_kind, item.source_id)
            for item in self.dispositions
        }
        if len(disposition_sources) != len(self.dispositions):
            raise ValueError("Operator Brief contains duplicate disposition sources.")

        if any(
            item.thread_id and item.thread_id not in thread_ids
            for item in self.dispositions
        ):
            raise ValueError("Operator Brief disposition references an unknown thread ID.")


def build_operator_brief_view(
    operator_summary: OperatorSummary,
) -> OperatorBriefView:
    """Project current canonical leads one-for-one without changing semantics."""

    threads: list[OperatorBriefThread] = []
    dispositions: list[OperatorBriefDisposition] = []

    for lead in operator_summary.ranked_leads:
        if not lead.lead_id.strip():
            raise ValueError(
                "Canonical operator-summary leads require an ID before "
                "Operator Brief projection."
            )

        thread_id = _thread_id_for_source_lead(lead.lead_id)
        thread = OperatorBriefThread(
            thread_id=thread_id,
            title=lead.title,
            rank=lead.rank,
            score=lead.score,
            signal=lead.signal,
            source_lead_ids=(lead.lead_id,),
            endpoints=tuple(lead.endpoints),
            evidence_ids=tuple(lead.evidence_ids),
            why_review=lead.why,
            next_review_step=lead.next_action,
        )
        threads.append(thread)
        dispositions.append(
            OperatorBriefDisposition(
                source_kind="operator_summary_lead",
                source_id=lead.lead_id,
                disposition=PRIMARY_THREAD,
                thread_id=thread_id,
            )
        )

    return OperatorBriefView(
        threads=tuple(threads),
        dispositions=tuple(dispositions),
    )


def write_operator_brief_artifact(
    root: Path,
    brief: OperatorBriefView,
) -> Path:
    """Persist one exact Operator Brief deterministically."""

    if not isinstance(brief, OperatorBriefView):
        raise TypeError("Operator Brief persistence requires an OperatorBriefView.")

    payload = {
        "schema_version": _OPERATOR_BRIEF_SCHEMA_VERSION,
        "generated_by": _OPERATOR_BRIEF_GENERATED_BY,
        "threads": [_thread_to_dict(thread) for thread in brief.threads],
        "dispositions": [
            _disposition_to_dict(disposition)
            for disposition in brief.dispositions
        ],
    }

    root.mkdir(parents=True, exist_ok=True)
    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if path.exists() and not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_operator_brief_artifact(
    root: Path,
) -> OperatorBriefView | None:
    """Load a persisted Operator Brief, or None for legacy absence."""

    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"could not parse {OPERATOR_BRIEF_FILENAME}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} must contain a JSON object"
        )

    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != _OPERATOR_BRIEF_SCHEMA_VERSION
    ):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} has an unsupported schema_version"
        )

    if payload.get("generated_by") != _OPERATOR_BRIEF_GENERATED_BY:
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} has an invalid generated_by value"
        )

    raw_threads = payload.get("threads")
    if not isinstance(raw_threads, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'threads' must be a list"
        )

    raw_dispositions = payload.get("dispositions")
    if not isinstance(raw_dispositions, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'dispositions' must be a list"
        )

    threads = tuple(
        _thread_from_dict(value, index)
        for index, value in enumerate(raw_threads)
    )
    dispositions = tuple(
        _disposition_from_dict(value, index)
        for index, value in enumerate(raw_dispositions)
    )

    return OperatorBriefView(
        threads=threads,
        dispositions=dispositions,
    )


def _thread_id_for_source_lead(lead_id: str) -> str:
    identity = {
        "source_kind": "operator_summary_lead",
        "source_ids": [lead_id],
    }
    digest = sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()[:16].upper()
    return f"THREAD-{digest}"


def _thread_to_dict(
    thread: OperatorBriefThread,
) -> dict[str, object]:
    return {
        "thread_id": thread.thread_id,
        "title": thread.title,
        "rank": thread.rank,
        "score": thread.score,
        "signal": thread.signal,
        "source_lead_ids": list(thread.source_lead_ids),
        "endpoints": list(thread.endpoints),
        "evidence_ids": list(thread.evidence_ids),
        "why_review": thread.why_review,
        "next_review_step": thread.next_review_step,
        "observed_facts": list(thread.observed_facts),
        "related_context": list(thread.related_context),
        "conflicts": list(thread.conflicts),
        "coverage_limitations": list(thread.coverage_limitations),
        "unknowns": list(thread.unknowns),
        "source_artefacts": list(thread.source_artefacts),
    }


def _disposition_to_dict(
    disposition: OperatorBriefDisposition,
) -> dict[str, object]:
    return {
        "source_kind": disposition.source_kind,
        "source_id": disposition.source_id,
        "disposition": disposition.disposition,
        "thread_id": disposition.thread_id,
    }


def _thread_from_dict(
    value: object,
    index: int,
) -> OperatorBriefThread:
    label = f"{OPERATOR_BRIEF_FILENAME} threads[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")

    try:
        return OperatorBriefThread(
            thread_id=_text_field(value, "thread_id", label),
            title=_text_field(value, "title", label),
            rank=_int_field(value, "rank", label),
            score=_int_field(value, "score", label),
            signal=_text_field(value, "signal", label),
            source_lead_ids=_text_tuple_field(
                value,
                "source_lead_ids",
                label,
            ),
            endpoints=_text_tuple_field(value, "endpoints", label),
            evidence_ids=_text_tuple_field(
                value,
                "evidence_ids",
                label,
            ),
            why_review=_text_field(value, "why_review", label),
            next_review_step=_text_field(
                value,
                "next_review_step",
                label,
            ),
            observed_facts=_text_tuple_field(
                value,
                "observed_facts",
                label,
            ),
            related_context=_text_tuple_field(
                value,
                "related_context",
                label,
            ),
            conflicts=_text_tuple_field(value, "conflicts", label),
            coverage_limitations=_text_tuple_field(
                value,
                "coverage_limitations",
                label,
            ),
            unknowns=_text_tuple_field(value, "unknowns", label),
            source_artefacts=_text_tuple_field(
                value,
                "source_artefacts",
                label,
            ),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _disposition_from_dict(
    value: object,
    index: int,
) -> OperatorBriefDisposition:
    label = f"{OPERATOR_BRIEF_FILENAME} dispositions[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")

    try:
        return OperatorBriefDisposition(
            source_kind=_text_field(value, "source_kind", label),
            source_id=_text_field(value, "source_id", label),
            disposition=_text_field(value, "disposition", label),
            thread_id=_text_field(value, "thread_id", label),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _text_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> str:
    field = value.get(key)
    if not isinstance(field, str):
        raise ValueError(f"{label}.{key} must be text")
    return field


def _int_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> int:
    field = value.get(key)
    if isinstance(field, bool) or not isinstance(field, int):
        raise ValueError(f"{label}.{key} must be an integer")
    return field


def _text_tuple_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> tuple[str, ...]:
    field = value.get(key)
    if not isinstance(field, list):
        raise ValueError(f"{label}.{key} must be a list")
    if any(not isinstance(item, str) for item in field):
        raise ValueError(f"{label}.{key} must contain text values")
    return tuple(field)


def retire_operator_brief_artifact(root: Path) -> None:
    """Remove a stale Operator Brief while refusing unsafe path types."""

    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if not path.exists():
        return
    if not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    path.unlink()
