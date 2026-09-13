"""Canonical, versioned persistence for investigation-thread snapshots."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import tempfile

from bugslyce.recon.investigation_threads import InvestigationThread


INVESTIGATION_THREADS_FILENAME = "investigation_threads.json"
_SCHEMA_VERSION = 1
_GENERATED_BY = "bugslyce.investigation_threads"
_MAX_FILE_BYTES = 16 * 1024 * 1024
_THREAD_ID = re.compile(r"THREAD-[0-9a-f]{64}\Z")
_THREAD_KEYS = {
    "thread_id", "title", "priority", "category", "summary", "why_it_matters",
    "related_endpoints", "related_evidence_ids", "related_candidate_ids",
    "related_lead_ids", "suggested_manual_review_order", "kill_switch_guidance",
    "related_native_observation_ids", "related_application_relation_ids",
    "limitation_codes",
}


def _object_without_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("investigation thread JSON has a duplicate object member")
        result[key] = value
    return result


def _mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has missing or unexpected fields")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    return value


def _texts(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return tuple(_text(item, f"{label} item") for item in value)


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _thread_to_dict(thread: InvestigationThread) -> dict[str, object]:
    if not isinstance(thread, InvestigationThread):
        raise TypeError("investigation thread snapshot requires InvestigationThread values")
    if not _THREAD_ID.fullmatch(thread.thread_id):
        raise ValueError("thread_id must be a semantic THREAD-<64 lowercase hex> value")
    return {
        "thread_id": thread.thread_id,
        "title": thread.title,
        "priority": thread.priority,
        "category": thread.category,
        "summary": thread.summary,
        "why_it_matters": thread.why_it_matters,
        "related_endpoints": list(thread.related_endpoints),
        "related_evidence_ids": list(thread.related_evidence_ids),
        "related_candidate_ids": list(thread.related_candidate_ids),
        "related_lead_ids": list(thread.related_lead_ids),
        "suggested_manual_review_order": list(thread.suggested_manual_review_order),
        "kill_switch_guidance": thread.kill_switch_guidance,
        "related_native_observation_ids": list(thread.related_native_observation_ids),
        "related_application_relation_ids": list(thread.related_application_relation_ids),
        "limitation_codes": list(thread.limitation_codes),
    }


def _thread_from_dict(value: object, label: str) -> InvestigationThread:
    item = _mapping(value, _THREAD_KEYS, label)
    thread_id = _text(item["thread_id"], f"{label}.thread_id")
    if not _THREAD_ID.fullmatch(thread_id):
        raise ValueError("thread_id must be a semantic THREAD-<64 lowercase hex> value")
    return InvestigationThread(
        thread_id=thread_id,
        title=_text(item["title"], f"{label}.title"),
        priority=_text(item["priority"], f"{label}.priority"),
        category=_text(item["category"], f"{label}.category"),
        summary=_text(item["summary"], f"{label}.summary"),
        why_it_matters=_text(item["why_it_matters"], f"{label}.why_it_matters"),
        related_endpoints=_texts(item["related_endpoints"], f"{label}.related_endpoints"),
        related_evidence_ids=_texts(item["related_evidence_ids"], f"{label}.related_evidence_ids"),
        related_candidate_ids=_texts(item["related_candidate_ids"], f"{label}.related_candidate_ids"),
        related_lead_ids=_texts(item["related_lead_ids"], f"{label}.related_lead_ids"),
        suggested_manual_review_order=_texts(item["suggested_manual_review_order"], f"{label}.suggested_manual_review_order"),
        kill_switch_guidance=_optional_text(item["kill_switch_guidance"], f"{label}.kill_switch_guidance"),
        related_native_observation_ids=_texts(item["related_native_observation_ids"], f"{label}.related_native_observation_ids"),
        related_application_relation_ids=_texts(item["related_application_relation_ids"], f"{label}.related_application_relation_ids"),
        limitation_codes=_texts(item["limitation_codes"], f"{label}.limitation_codes"),
    )


def investigation_threads_to_dict(threads: tuple[InvestigationThread, ...]) -> dict[str, object]:
    if not isinstance(threads, tuple):
        raise TypeError("investigation thread snapshot must be an ordered tuple")
    payload = [_thread_to_dict(thread) for thread in threads]
    ids = [thread["thread_id"] for thread in payload]
    if len(ids) != len(set(ids)):
        raise ValueError("investigation thread snapshot has duplicate thread IDs")
    return {"schema_version": _SCHEMA_VERSION, "generated_by": _GENERATED_BY, "threads": payload}


def investigation_threads_from_dict(value: object) -> tuple[InvestigationThread, ...]:
    item = _mapping(value, {"schema_version", "generated_by", "threads"}, "investigation thread snapshot")
    if isinstance(item["schema_version"], bool) or item["schema_version"] != _SCHEMA_VERSION:
        raise ValueError("investigation thread snapshot has an unsupported schema version")
    if _text(item["generated_by"], "generated_by") != _GENERATED_BY:
        raise ValueError("investigation thread snapshot has an unsupported generator")
    if not isinstance(item["threads"], list):
        raise ValueError("threads must be a list")
    threads = tuple(_thread_from_dict(raw, f"threads[{index}]") for index, raw in enumerate(item["threads"]))
    if len({thread.thread_id for thread in threads}) != len(threads):
        raise ValueError("investigation thread snapshot has duplicate thread IDs")
    return threads


def _path(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("investigation thread root must be a Path")
    return root / INVESTIGATION_THREADS_FILENAME


def _validate_file(path: Path, *, allow_absent: bool) -> bool:
    if path.is_symlink():
        raise ValueError("investigation thread artefact must be a regular file")
    if not path.exists():
        return not allow_absent
    if not path.is_file():
        raise ValueError("investigation thread artefact must be a regular file")
    return True


def write_investigation_threads_artifact(root: Path, threads: tuple[InvestigationThread, ...]) -> Path:
    payload = investigation_threads_to_dict(threads)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    root.mkdir(parents=True, exist_ok=True)
    path = _path(root)
    _validate_file(path, allow_absent=False)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{INVESTIGATION_THREADS_FILENAME}.", dir=root, delete=False) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_file(path, allow_absent=False)
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise ValueError(f"could not write {INVESTIGATION_THREADS_FILENAME}: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def load_investigation_threads_artifact(root: Path) -> tuple[InvestigationThread, ...] | None:
    path = _path(root)
    if not _validate_file(path, allow_absent=True):
        return None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
            raise ValueError("investigation thread artefact is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(_MAX_FILE_BYTES + 1)
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError("investigation thread artefact exceeds the size limit")
        return investigation_threads_from_dict(json.loads(content.decode("utf-8"), object_pairs_hook=_object_without_duplicate_members))
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse {INVESTIGATION_THREADS_FILENAME} JSON: {exc}") from exc
    except ValueError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError) as exc:
        raise ValueError(f"{INVESTIGATION_THREADS_FILENAME} is malformed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
