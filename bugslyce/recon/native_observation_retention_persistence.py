"""Strict persistence for the canonical native body-retention plan."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from bugslyce.recon.native_observation_retention import (
    NativeBodyRetentionDecision,
    NativeBodyRetentionFamily,
    NativeObservationRetentionPlan,
)


NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME = (
    "native_observation_retention_plan.json"
)
SCHEMA_VERSION = 1
GENERATED_BY = "bugslyce.native_observation_retention_plan"
_MAX_FILE_BYTES = 32 * 1024 * 1024


def _mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has missing or unexpected fields")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be text or null")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _decision_to_dict(value: NativeBodyRetentionDecision) -> dict[str, object]:
    return {
        "action": value.action,
        "body_sha256": value.body_sha256,
        "candidate_index": value.candidate_index,
        "captured_bytes": value.captured_bytes,
        "exchange_index": value.exchange_index,
        "family_id": value.family_id,
        "reason_code": value.reason_code,
        "request_url": value.request_url,
        "source_id": value.source_id,
        "status_code": value.status_code,
    }


def _decision_from_dict(value: object, label: str) -> NativeBodyRetentionDecision:
    item = _mapping(
        value,
        {
            "action",
            "body_sha256",
            "candidate_index",
            "captured_bytes",
            "exchange_index",
            "family_id",
            "reason_code",
            "request_url",
            "source_id",
            "status_code",
        },
        label,
    )
    return NativeBodyRetentionDecision(
        source_id=_text(item["source_id"], f"{label}.source_id"),
        candidate_index=_integer(
            item["candidate_index"], f"{label}.candidate_index"
        ),
        exchange_index=_integer(item["exchange_index"], f"{label}.exchange_index"),
        request_url=_text(item["request_url"], f"{label}.request_url"),
        status_code=_integer(item["status_code"], f"{label}.status_code"),
        captured_bytes=_integer(item["captured_bytes"], f"{label}.captured_bytes"),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        action=_text(item["action"], f"{label}.action"),
        reason_code=_text(item["reason_code"], f"{label}.reason_code"),
        family_id=_optional_text(item["family_id"], f"{label}.family_id"),
    )


def _family_to_dict(value: NativeBodyRetentionFamily) -> dict[str, object]:
    return {
        "canonical_origin": value.canonical_origin,
        "family_id": value.family_id,
        "grouping_rule": value.grouping_rule,
        "grouping_signature_sha256": value.grouping_signature_sha256,
        "member_body_sha256": list(value.member_body_sha256),
        "member_source_ids": list(value.member_source_ids),
        "representative_body_sha256": value.representative_body_sha256,
        "representative_source_id": value.representative_source_id,
    }


def _family_from_dict(value: object, label: str) -> NativeBodyRetentionFamily:
    item = _mapping(
        value,
        {
            "canonical_origin",
            "family_id",
            "grouping_rule",
            "grouping_signature_sha256",
            "member_body_sha256",
            "member_source_ids",
            "representative_body_sha256",
            "representative_source_id",
        },
        label,
    )
    return NativeBodyRetentionFamily(
        family_id=_text(item["family_id"], f"{label}.family_id"),
        grouping_rule=_text(item["grouping_rule"], f"{label}.grouping_rule"),
        canonical_origin=_text(item["canonical_origin"], f"{label}.canonical_origin"),
        grouping_signature_sha256=_text(
            item["grouping_signature_sha256"],
            f"{label}.grouping_signature_sha256",
        ),
        representative_source_id=_text(
            item["representative_source_id"], f"{label}.representative_source_id"
        ),
        representative_body_sha256=_text(
            item["representative_body_sha256"],
            f"{label}.representative_body_sha256",
        ),
        member_source_ids=tuple(
            _text(member, f"{label}.member_source_ids[{index}]")
            for index, member in enumerate(
                _array(item["member_source_ids"], f"{label}.member_source_ids")
            )
        ),
        member_body_sha256=tuple(
            _text(member, f"{label}.member_body_sha256[{index}]")
            for index, member in enumerate(
                _array(item["member_body_sha256"], f"{label}.member_body_sha256")
            )
        ),
    )


def native_observation_retention_plan_to_dict(
    plan: NativeObservationRetentionPlan,
) -> dict[str, object]:
    if not isinstance(plan, NativeObservationRetentionPlan):
        raise TypeError("native retention persistence requires a typed plan")
    return {
        "decisions": [_decision_to_dict(item) for item in plan.decisions],
        "families": [_family_to_dict(item) for item in plan.families],
        "generated_by": GENERATED_BY,
        "grouping_rule": plan.grouping_rule,
        "schema_version": SCHEMA_VERSION,
    }


def native_observation_retention_plan_from_dict(
    payload: object,
) -> NativeObservationRetentionPlan:
    top = _mapping(
        payload,
        {"decisions", "families", "generated_by", "grouping_rule", "schema_version"},
        NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME,
    )
    if _integer(top["schema_version"], "schema_version") != SCHEMA_VERSION:
        raise ValueError("native retention plan has an unsupported schema version")
    if _text(top["generated_by"], "generated_by") != GENERATED_BY:
        raise ValueError("native retention plan has an invalid generated_by value")
    plan = NativeObservationRetentionPlan(
        grouping_rule=_text(top["grouping_rule"], "grouping_rule"),
        decisions=tuple(
            _decision_from_dict(item, f"decisions[{index}]")
            for index, item in enumerate(_array(top["decisions"], "decisions"))
        ),
        families=tuple(
            _family_from_dict(item, f"families[{index}]")
            for index, item in enumerate(_array(top["families"], "families"))
        ),
    )
    if native_observation_retention_plan_to_dict(plan) != top:
        raise ValueError("native retention plan payload is not canonical")
    return plan


def _object_without_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("native retention plan JSON has a duplicate member")
        result[key] = value
    return result


def _path(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("native retention plan root must be a Path")
    return root / NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME


def _validate_file(path: Path, *, allow_absent: bool) -> bool:
    if path.is_symlink():
        raise ValueError("native retention plan must be a regular file")
    if not path.exists():
        return not allow_absent
    if not path.is_file():
        raise ValueError("native retention plan must be a regular file")
    return True


def write_native_observation_retention_plan_artifact(
    root: Path,
    plan: NativeObservationRetentionPlan,
) -> Path:
    payload = native_observation_retention_plan_to_dict(plan)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    root.mkdir(parents=True, exist_ok=True)
    path = _path(root)
    _validate_file(path, allow_absent=False)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME}.",
            dir=root,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_file(path, allow_absent=False)
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise ValueError(f"could not write native retention plan: {exc}") from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def load_native_observation_retention_plan_artifact(
    root: Path,
) -> NativeObservationRetentionPlan | None:
    path = _path(root)
    if not _validate_file(path, allow_absent=True):
        return None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
            raise ValueError("native retention plan is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(_MAX_FILE_BYTES + 1)
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError("native retention plan exceeds the size limit")
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_members,
        )
        return native_observation_retention_plan_from_dict(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse native retention plan JSON: {exc}") from exc
    except ValueError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError) as exc:
        raise ValueError("native retention plan is malformed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
