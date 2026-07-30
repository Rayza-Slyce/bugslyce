"""Secure private persistence for canonical programme-scope policies."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from bugslyce.core.programme_scope import (
    ProgrammeScopePolicy,
    ProgrammeScopeRule,
    build_programme_scope_policy,
    build_programme_scope_rule,
)


PROGRAMME_SCOPE_FILENAME = "programme_scope.json"
MAX_PROGRAMME_SCOPE_FILE_BYTES = 1024 * 1024

_POLICY_FIELDS = frozenset(
    {"schema_version", "engagement_context", "updated_at", "rules"}
)
_RULE_FIELDS = frozenset(
    {
        "rule_id",
        "action",
        "kind",
        "canonical_value",
        "private_note",
        "private_source_wording",
    }
)


class _DuplicateJSONKeyError(ValueError):
    pass


def save_programme_scope_policy(path: Path, policy: ProgrammeScopePolicy) -> None:
    """Atomically save one canonical private policy with exact mode 0600."""

    destination = _programme_scope_path(path)
    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("Programme scope policy must use the canonical policy model.")
    validated_policy = _policy_from_payload(policy.to_dict())
    content = (
        json.dumps(
            validated_policy.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if len(content) > MAX_PROGRAMME_SCOPE_FILE_BYTES:
        raise ValueError("Programme scope policy exceeds the technical size limit.")

    _refuse_unsafe_destination(destination)
    fd, temporary_name = tempfile.mkstemp(
        prefix=".programme_scope.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _refuse_unsafe_destination(destination)
        os.replace(temporary, destination)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise


def load_programme_scope_policy(path: Path) -> ProgrammeScopePolicy:
    """Load one private policy from the same no-follow descriptor that is checked."""

    policy_path = _programme_scope_path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = -1
    try:
        fd = os.open(policy_path, flags)
    except FileNotFoundError:
        raise ValueError("Programme scope policy file is missing.") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                "Programme scope policy path must be a regular file, not a link."
            ) from None
        raise ValueError(
            "Programme scope policy file could not be opened safely."
        ) from None

    try:
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise ValueError(
                "Programme scope policy path must be a regular file, not a link."
            )
        if descriptor_stat.st_uid != os.geteuid():
            raise ValueError(
                "Programme scope policy file must be owned by the current user."
            )
        if stat.S_IMODE(descriptor_stat.st_mode) != 0o600:
            raise ValueError(
                "Programme scope policy permissions are unsafe; set exact mode 0600."
            )
        if descriptor_stat.st_size > MAX_PROGRAMME_SCOPE_FILE_BYTES:
            raise ValueError(
                "Programme scope policy file exceeds the technical size limit."
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            content = handle.read(MAX_PROGRAMME_SCOPE_FILE_BYTES + 1)
        if len(content) > MAX_PROGRAMME_SCOPE_FILE_BYTES:
            raise ValueError(
                "Programme scope policy file exceeds the technical size limit."
            )
    except ValueError:
        raise
    except OSError:
        raise ValueError(
            "Programme scope policy file could not be read safely."
        ) from None
    finally:
        if fd >= 0:
            os.close(fd)

    try:
        text = content.decode("utf-8", errors="strict")
        payload = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except _DuplicateJSONKeyError:
        raise ValueError(
            "Programme scope policy JSON contains duplicate object keys."
        ) from None
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Programme scope policy JSON is malformed or unreadable.") from None
    return _policy_from_payload(payload)


def _programme_scope_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise ValueError("Programme scope policy path must be a filesystem path.")
    expanded = path.expanduser()
    if expanded.name != PROGRAMME_SCOPE_FILENAME:
        raise ValueError(
            f"Programme scope policy path must end with {PROGRAMME_SCOPE_FILENAME}."
        )
    try:
        parent = expanded.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("Programme scope policy directory does not exist.") from None
    if not parent.is_dir():
        raise ValueError("Programme scope policy directory does not exist.")
    return parent / PROGRAMME_SCOPE_FILENAME


def _refuse_unsafe_destination(path: Path) -> None:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(
            "Programme scope policy path must be a regular file, not a link."
        )
    if path_stat.st_uid != os.geteuid():
        raise ValueError(
            "Programme scope policy file must be owned by the current user."
        )


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError
        result[key] = value
    return result


def _policy_from_payload(payload: object) -> ProgrammeScopePolicy:
    if not isinstance(payload, dict):
        raise ValueError("Programme scope policy must contain one JSON object.")
    if set(payload) != _POLICY_FIELDS:
        raise ValueError("Programme scope policy top-level schema is invalid.")
    rules_payload = payload.get("rules")
    if not isinstance(rules_payload, list):
        raise ValueError("Programme scope policy rules must be a JSON list.")

    rules: list[ProgrammeScopeRule] = []
    for rule_payload in rules_payload:
        if not isinstance(rule_payload, dict) or set(rule_payload) != _RULE_FIELDS:
            raise ValueError("Programme scope policy rule schema is invalid.")
        rule = build_programme_scope_rule(
            rule_id=rule_payload["rule_id"],
            action=rule_payload["action"],
            kind=rule_payload["kind"],
            value=rule_payload["canonical_value"],
            private_note=rule_payload["private_note"],
            private_source_wording=rule_payload["private_source_wording"],
        )
        if rule.canonical_value != rule_payload["canonical_value"]:
            raise ValueError(
                "Programme scope policy rule value is not in canonical form."
            )
        rules.append(rule)

    policy = build_programme_scope_policy(
        rules,
        schema_version=payload["schema_version"],
        engagement_context=payload["engagement_context"],
        updated_at=payload["updated_at"],
    )
    if tuple(rules) != policy.rules or policy.to_dict() != payload:
        raise ValueError("Programme scope policy content is not canonical.")
    return policy
