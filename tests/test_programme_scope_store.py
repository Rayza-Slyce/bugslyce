"""Tests for secure private programme-scope persistence and project references."""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    RULE_EXACT_IPV4,
    RULE_HTTP_PATH_PREFIX,
    RULE_IPV4_CIDR,
    RULE_WILDCARD_SUBDOMAIN,
    ProgrammeScopePolicy,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.core.programme_scope_store import (
    MAX_PROGRAMME_SCOPE_FILE_BYTES,
    PROGRAMME_SCOPE_FILENAME,
    load_programme_scope_policy,
    save_programme_scope_policy,
)
import bugslyce.core.programme_scope_store as scope_store
import bugslyce.project_session as project_session
from bugslyce.project_session import (
    LEGACY_PROJECT_SCHEMA_VERSION,
    PROJECT_SCHEMA_VERSION,
    initialize_project,
    load_project,
    load_project_programme_scope_policy,
    save_project_programme_scope_policy,
)


FIXED_TIMESTAMP = "2026-07-30T09:15:00Z"
PRIVATE_NOTE = "private-note-sentinel-4815"
PRIVATE_SOURCE = "Private programme wording résumé sentinel-4815"


def _rule(
    rule_id: str,
    kind: str,
    value: str,
    *,
    action: str = ACTION_INCLUDE,
    private: bool = False,
):
    return build_programme_scope_rule(
        rule_id=rule_id,
        action=action,
        kind=kind,
        value=value,
        private_note=PRIVATE_NOTE if private else None,
        private_source_wording=PRIVATE_SOURCE if private else None,
    )


def _minimal_policy() -> ProgrammeScopePolicy:
    return build_programme_scope_policy([], updated_at=FIXED_TIMESTAMP)


def _complete_policy() -> ProgrammeScopePolicy:
    return build_programme_scope_policy(
        [
            _rule("z-host", RULE_EXACT_HOSTNAME, "example.test", private=True),
            _rule("a-wild", RULE_WILDCARD_SUBDOMAIN, "*.example.test"),
            _rule(
                "exclude-url",
                RULE_EXACT_HTTP_URL,
                "https://example.test/private?source=brief",
                action=ACTION_EXCLUDE,
            ),
            _rule(
                "path",
                RULE_HTTP_PATH_PREFIX,
                "https://example.test/api",
            ),
            _rule("ip", RULE_EXACT_IPV4, "192.0.2.8"),
            _rule(
                "network",
                RULE_IPV4_CIDR,
                "198.51.100.0/24",
                action=ACTION_EXCLUDE,
            ),
        ],
        updated_at=FIXED_TIMESTAMP,
    )


def _policy_path(tmp_path: Path) -> Path:
    return tmp_path / PROGRAMME_SCOPE_FILENAME


def _write_bytes(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def _write_payload(path: Path, payload: object) -> None:
    _write_bytes(
        path,
        (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )


def _saved_payload(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    path = _policy_path(tmp_path)
    save_programme_scope_policy(path, _complete_policy())
    return path, json.loads(path.read_text(encoding="utf-8"))


def _project(tmp_path: Path, *, context: str = "bug_bounty") -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n", encoding="utf-8")
    _project_model, project_file = initialize_project(
        "scope-store",
        "example.test",
        scope,
        tmp_path / "project",
        engagement_context=context,
    )
    return project_file


def test_minimal_and_complete_policies_round_trip_as_immutable_models(
    tmp_path: Path,
) -> None:
    for directory, policy in (
        (tmp_path / "minimal", _minimal_policy()),
        (tmp_path / "complete", _complete_policy()),
    ):
        directory.mkdir()
        path = directory / PROGRAMME_SCOPE_FILENAME
        save_programme_scope_policy(path, policy)
        loaded = load_programme_scope_policy(path)

        assert loaded == policy
        assert isinstance(loaded, ProgrammeScopePolicy)
        assert loaded.rules == policy.rules


def test_qualified_hostname_scope_round_trips_with_explicit_qualifiers(
    tmp_path: Path,
) -> None:
    rule = build_programme_scope_rule(
        rule_id="qualified-wildcard",
        action=ACTION_INCLUDE,
        kind=RULE_WILDCARD_SUBDOMAIN,
        value="*.example.test",
        scheme="https",
        port=443,
    )
    policy = build_programme_scope_policy((rule,), updated_at=FIXED_TIMESTAMP)
    path = _policy_path(tmp_path)

    save_programme_scope_policy(path, policy)
    payload = json.loads(path.read_text(encoding="utf-8"))
    loaded = load_programme_scope_policy(path)

    assert loaded == policy
    assert loaded.rules[0].scheme == "https"
    assert loaded.rules[0].port == 443
    assert payload["rules"][0]["scheme"] == "https"
    assert payload["rules"][0]["port"] == 443


def test_schema_1_0_programme_scope_loads_without_qualifier_inference(
    tmp_path: Path,
) -> None:
    path = _policy_path(tmp_path)
    payload = {
        "schema_version": "1.0",
        "engagement_context": "bug_bounty",
        "updated_at": FIXED_TIMESTAMP,
        "rules": [
            {
                "rule_id": "legacy-wildcard",
                "action": "include",
                "kind": "wildcard_subdomain",
                "canonical_value": "*.example.test",
                "private_note": None,
                "private_source_wording": None,
            }
        ],
    }
    _write_payload(path, payload)
    before = path.read_bytes()

    loaded = load_programme_scope_policy(path)

    assert loaded.rules[0].canonical_value == "*.example.test"
    assert loaded.rules[0].scheme is None
    assert loaded.rules[0].port is None
    assert path.read_bytes() == before


def test_serialisation_is_canonical_utf8_ordered_and_byte_deterministic(
    tmp_path: Path,
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first = first_dir / PROGRAMME_SCOPE_FILENAME
    second = second_dir / PROGRAMME_SCOPE_FILENAME
    policy = _complete_policy()

    save_programme_scope_policy(first, policy)
    save_programme_scope_policy(second, policy)
    content = first.read_bytes()
    payload = json.loads(content.decode("utf-8"))

    assert content == second.read_bytes()
    assert content.endswith(b"\n") and not content.endswith(b"\n\n")
    assert "résumé".encode() in content
    assert [rule["rule_id"] for rule in payload["rules"]] == [
        rule.rule_id for rule in policy.rules
    ]
    assert load_programme_scope_policy(first) == load_programme_scope_policy(second)


def test_private_fields_use_one_exact_nullable_rule_schema(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    save_programme_scope_policy(path, _complete_policy())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert set(payload) == {
        "engagement_context",
        "rules",
        "schema_version",
        "updated_at",
    }
    assert all(
        set(rule)
        == {
            "action",
            "canonical_value",
            "kind",
            "private_note",
            "private_source_wording",
            "scheme",
            "port",
            "rule_id",
        }
        for rule in payload["rules"]
    )
    assert any(rule["private_note"] is None for rule in payload["rules"])
    assert any(rule["private_note"] == PRIVATE_NOTE for rule in payload["rules"])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(schema_version="2.0"),
        lambda payload: payload.update(engagement_context="ctf_lab"),
        lambda payload: payload.pop("updated_at"),
        lambda payload: payload.update(unexpected="field"),
        lambda payload: payload["rules"][0].pop("rule_id"),
        lambda payload: payload["rules"][0].update(unexpected="field"),
        lambda payload: payload["rules"].append(deepcopy(payload["rules"][0])),
        lambda payload: payload["rules"][0].update(action="allow"),
        lambda payload: payload["rules"][0].update(kind="generic"),
        lambda payload: payload["rules"][0].update(canonical_value="Example.TEST"),
        lambda payload: payload["rules"][0].update(
            kind=RULE_EXACT_HTTP_URL,
            canonical_value="HTTPS://example.test/",
        ),
        lambda payload: payload["rules"][0].update(
            kind=RULE_IPV4_CIDR,
            canonical_value="192.0.2.1/24",
        ),
        lambda payload: payload.update(updated_at="2026-07-30"),
        lambda payload: payload["rules"][0].update(private_note="unsafe\ntext"),
    ],
)
def test_loader_rejects_noncanonical_or_invalid_policy_content(
    tmp_path: Path,
    mutation,
) -> None:
    path, payload = _saved_payload(tmp_path)
    mutation(payload)
    _write_payload(path, payload)

    with pytest.raises(ValueError):
        load_programme_scope_policy(path)


def test_loader_rejects_nonobject_and_nonlist_rules(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    _write_payload(path, [])
    with pytest.raises(ValueError, match="one JSON object"):
        load_programme_scope_policy(path)

    payload = _minimal_policy().to_dict()
    payload["rules"] = {}
    _write_payload(path, payload)
    with pytest.raises(ValueError, match="JSON list"):
        load_programme_scope_policy(path)


def test_loader_rejects_noncanonical_stored_rule_order(tmp_path: Path) -> None:
    path, payload = _saved_payload(tmp_path)
    payload["rules"].reverse()
    _write_payload(path, payload)

    with pytest.raises(ValueError, match="not canonical"):
        load_programme_scope_policy(path)


def test_loader_rejects_trailing_data_and_invalid_utf8(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    _write_bytes(path, b"{} trailing")
    with pytest.raises(ValueError, match="malformed or unreadable"):
        load_programme_scope_policy(path)

    _write_bytes(path, b"{\"schema_version\": \"1.0\", \"bad\": \xff}")
    with pytest.raises(ValueError, match="malformed or unreadable"):
        load_programme_scope_policy(path)


def test_loader_rejects_duplicate_keys_at_top_and_rule_levels(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    top_level = (
        '{"schema_version":"1.0","schema_version":"1.0",'
        '"engagement_context":"bug_bounty","updated_at":"'
        + FIXED_TIMESTAMP
        + '","rules":[]}\n'
    )
    _write_bytes(path, top_level.encode())
    with pytest.raises(ValueError, match="duplicate object keys"):
        load_programme_scope_policy(path)

    rule_level = (
        '{"schema_version":"1.0","engagement_context":"bug_bounty",'
        '"updated_at":"'
        + FIXED_TIMESTAMP
        + '","rules":[{"rule_id":"host","rule_id":"other",'
        '"action":"include","kind":"exact_hostname",'
        '"canonical_value":"example.test","private_note":null,'
        '"private_source_wording":null}]}\n'
    )
    _write_bytes(path, rule_level.encode())
    with pytest.raises(ValueError, match="duplicate object keys"):
        load_programme_scope_policy(path)


def test_loader_classifies_missing_file_without_creating_it(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)

    with pytest.raises(ValueError, match="file is missing"):
        load_programme_scope_policy(path)
    assert not path.exists()


def test_saved_mode_is_exactly_private_and_replacement_repairs_permissions(
    tmp_path: Path,
) -> None:
    path = _policy_path(tmp_path)
    path.write_text("old", encoding="utf-8")
    os.chmod(path, 0o666)

    save_programme_scope_policy(path, _minimal_policy())

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_programme_scope_policy(path) == _minimal_policy()


def test_umask_cannot_weaken_saved_permissions(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    previous = os.umask(0)
    try:
        save_programme_scope_policy(path, _minimal_policy())
    finally:
        os.umask(previous)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_and_load_refuse_symlinks_without_touching_the_target(
    tmp_path: Path,
) -> None:
    path = _policy_path(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    path.symlink_to(outside)

    with pytest.raises(ValueError, match="regular file, not a link"):
        save_programme_scope_policy(path, _minimal_policy())
    with pytest.raises(ValueError, match="regular file, not a link"):
        load_programme_scope_policy(path)
    assert outside.read_text(encoding="utf-8") == "outside"


def test_load_refuses_directory_and_fifo_without_blocking(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        load_programme_scope_policy(path)
    path.rmdir()

    os.mkfifo(path, mode=0o600)
    with pytest.raises(ValueError, match="regular file"):
        load_programme_scope_policy(path)


def test_load_refuses_unsafe_permissions_without_modifying_them(tmp_path: Path) -> None:
    path = _policy_path(tmp_path)
    save_programme_scope_policy(path, _minimal_policy())
    os.chmod(path, 0o640)

    with pytest.raises(ValueError, match="exact mode 0600"):
        load_programme_scope_policy(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_load_refuses_unexpected_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _policy_path(tmp_path)
    save_programme_scope_policy(path, _minimal_policy())
    monkeypatch.setattr(scope_store.os, "geteuid", lambda: path.stat().st_uid + 1)

    with pytest.raises(ValueError, match="owned by the current user"):
        load_programme_scope_policy(path)


def test_oversized_file_is_rejected_before_json_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _policy_path(tmp_path)
    _write_bytes(path, b"{" + b" " * MAX_PROGRAMME_SCOPE_FILE_BYTES + b"}")
    called = False

    def forbidden_loads(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("JSON parser must not run")

    monkeypatch.setattr(scope_store.json, "loads", forbidden_loads)
    with pytest.raises(ValueError, match="technical size limit"):
        load_programme_scope_policy(path)
    assert called is False


def test_oversized_canonical_policy_is_refused_before_temporary_creation(
    tmp_path: Path,
) -> None:
    private_text = "x" * 4096
    rules = [
        build_programme_scope_rule(
            rule_id=f"rule-{index:04d}",
            action=ACTION_INCLUDE,
            kind=RULE_EXACT_HOSTNAME,
            value=f"host-{index}.example.test",
            private_note=private_text,
            private_source_wording=private_text,
        )
        for index in range(140)
    ]
    policy = build_programme_scope_policy(rules, updated_at=FIXED_TIMESTAMP)
    path = _policy_path(tmp_path)

    with pytest.raises(ValueError, match="technical size limit"):
        save_programme_scope_policy(path, policy)

    assert not path.exists()
    assert list(tmp_path.glob(".programme_scope.*.tmp")) == []


def test_atomic_replace_failure_preserves_existing_file_and_cleans_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _policy_path(tmp_path)
    save_programme_scope_policy(path, _minimal_policy())
    previous = path.read_bytes()

    def fail_replace(_source, _destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(scope_store.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        save_programme_scope_policy(path, _complete_policy())

    assert path.read_bytes() == previous
    assert list(tmp_path.glob(".programme_scope.*.tmp")) == []


def test_precommit_failure_leaves_no_partial_file_or_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _policy_path(tmp_path)

    def fail_fsync(_fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(scope_store.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated fsync failure"):
        save_programme_scope_policy(path, _minimal_policy())

    assert not path.exists()
    assert list(tmp_path.glob(".programme_scope.*.tmp")) == []


def test_storage_errors_do_not_echo_private_policy_values(tmp_path: Path) -> None:
    path, payload = _saved_payload(tmp_path)
    payload["rules"][0]["private_note"] = f"{PRIVATE_NOTE}\nunsafe"
    _write_payload(path, payload)

    with pytest.raises(ValueError) as caught:
        load_programme_scope_policy(path)
    assert PRIVATE_NOTE not in str(caught.value)
    assert PRIVATE_SOURCE not in str(caught.value)


def test_project_schema_1_0_loads_without_rewrite_or_scope_inference(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    project_file.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    before = project_file.read_bytes()
    (project_file.parent / "scope.md").write_text("legacy scope\n", encoding="utf-8")

    project = load_project(project_file)

    assert project.schema_version == "1.0"
    assert project.programme_scope_file is None
    assert project_file.read_bytes() == before
    assert not (project_file.parent / PROGRAMME_SCOPE_FILENAME).exists()


def test_project_schema_1_0_preserves_historical_unknown_field_tolerance(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    payload["legacy_extension"] = {"retained_only_on_disk": True}
    project_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    before = project_file.read_bytes()

    project = load_project(project_file)

    assert project.schema_version == LEGACY_PROJECT_SCHEMA_VERSION
    assert not hasattr(project, "legacy_extension")
    assert project.programme_scope_file is None
    assert project_file.read_bytes() == before
    assert not (project_file.parent / PROGRAMME_SCOPE_FILENAME).exists()


def test_explicit_scope_save_upgrades_legacy_bug_bounty_project(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    project_file.write_text(json.dumps(payload), encoding="utf-8")

    updated, policy_path = save_project_programme_scope_policy(
        project_file,
        _complete_policy(),
    )

    stored = json.loads(project_file.read_text(encoding="utf-8"))
    assert updated.schema_version == PROJECT_SCHEMA_VERSION
    assert updated.programme_scope_file == PROGRAMME_SCOPE_FILENAME
    assert stored["schema_version"] == PROJECT_SCHEMA_VERSION
    assert stored["programme_scope_file"] == PROGRAMME_SCOPE_FILENAME
    assert policy_path == project_file.parent / PROGRAMME_SCOPE_FILENAME


def test_scope_save_refuses_legacy_project_extensions_before_creating_policy(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    extension_value = "legacy-extension-private-sentinel-7319"
    payload["legacy_extension"] = extension_value
    project_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    before = project_file.read_bytes()

    with pytest.raises(ValueError) as caught:
        save_project_programme_scope_policy(project_file, _complete_policy())

    assert "cannot be upgraded automatically" in str(caught.value)
    assert extension_value not in str(caught.value)
    assert project_file.read_bytes() == before
    assert not (project_file.parent / PROGRAMME_SCOPE_FILENAME).exists()
    assert list(project_file.parent.glob(".programme_scope.*.tmp")) == []


def test_scope_upgrade_refusal_preserves_unreferenced_private_policy(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    payload["legacy_extension"] = {"private": "legacy-value-sentinel-2846"}
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    project_before = project_file.read_bytes()
    policy_path = project_file.parent / PROGRAMME_SCOPE_FILENAME
    save_programme_scope_policy(policy_path, _minimal_policy())
    policy_before = policy_path.read_bytes()
    mode_before = stat.S_IMODE(policy_path.stat().st_mode)
    owner_before = policy_path.stat().st_uid

    with pytest.raises(ValueError, match="cannot be upgraded automatically"):
        save_project_programme_scope_policy(project_file, _complete_policy())

    assert project_file.read_bytes() == project_before
    assert policy_path.read_bytes() == policy_before
    assert stat.S_IMODE(policy_path.stat().st_mode) == mode_before == 0o600
    assert policy_path.stat().st_uid == owner_before == os.geteuid()
    assert list(project_file.parent.glob(".programme_scope.*.tmp")) == []


def test_project_schema_1_1_loads_with_or_without_fixed_private_reference(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    project = load_project(project_file)
    assert project.schema_version == PROJECT_SCHEMA_VERSION == "1.1"
    assert project.programme_scope_file is None

    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["programme_scope_file"] = PROGRAMME_SCOPE_FILENAME
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    referenced = load_project(project_file)

    assert referenced.programme_scope_file == PROGRAMME_SCOPE_FILENAME
    assert not (project_file.parent / PROGRAMME_SCOPE_FILENAME).exists()
    with pytest.raises(ValueError, match="file is missing"):
        load_project_programme_scope_policy(referenced)

    payload["programme_scope_file"] = None
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    assert load_project(project_file).programme_scope_file is None


@pytest.mark.parametrize(
    "reference",
    ["", " ", "other.json", "../programme_scope.json", "/tmp/programme_scope.json", "bad\npath"],
)
def test_project_rejects_empty_or_unsafe_programme_scope_reference(
    tmp_path: Path,
    reference: str,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["programme_scope_file"] = reference
    project_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="dedicated project-local reference"):
        load_project(project_file)


def test_project_rejects_programme_scope_on_schema_1_0_and_unknown_fields(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = "1.0"
    payload["programme_scope_file"] = PROGRAMME_SCOPE_FILENAME
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_project(project_file)

    payload["schema_version"] = "1.1"
    payload.pop("programme_scope_file")
    payload["unexpected"] = "field"
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_project(project_file)


def test_project_rejects_unknown_schema(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = "2.0"
    project_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported project schema"):
        load_project(project_file)


@pytest.mark.parametrize("context", ["ctf_lab", "internal_authorised"])
def test_non_bug_bounty_projects_need_no_programme_scope(
    tmp_path: Path,
    context: str,
) -> None:
    project = load_project(_project(tmp_path, context=context))
    assert project.programme_scope_file is None


@pytest.mark.parametrize("context", ["ctf_lab", "internal_authorised"])
def test_legacy_non_bug_bounty_projects_need_no_programme_scope(
    tmp_path: Path,
    context: str,
) -> None:
    project_file = _project(tmp_path, context=context)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["schema_version"] = LEGACY_PROJECT_SCHEMA_VERSION
    project_file.write_text(json.dumps(payload), encoding="utf-8")

    project = load_project(project_file)

    assert project.schema_version == LEGACY_PROJECT_SCHEMA_VERSION
    assert project.engagement_context == context
    assert project.programme_scope_file is None


def test_bug_bounty_project_without_scope_reference_remains_loadable(
    tmp_path: Path,
) -> None:
    project = load_project(_project(tmp_path))
    assert project.engagement_context == "bug_bounty"
    assert project.programme_scope_file is None


def test_project_scope_save_adds_only_reference_and_explicit_load_validates_policy(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)

    updated, policy_path = save_project_programme_scope_policy(
        project_file,
        _complete_policy(),
    )
    metadata = project_file.read_text(encoding="utf-8")

    assert updated.schema_version == "1.1"
    assert updated.programme_scope_file == PROGRAMME_SCOPE_FILENAME
    assert policy_path == project_file.parent / PROGRAMME_SCOPE_FILENAME
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o600
    assert PRIVATE_NOTE not in metadata
    assert PRIVATE_SOURCE not in metadata
    assert load_project_programme_scope_policy(load_project(project_file)) == _complete_policy()


def test_project_metadata_failure_removes_first_unreferenced_scope_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_file = _project(tmp_path)
    before = project_file.read_bytes()

    def fail_metadata(_path, _project):
        raise OSError("simulated metadata failure")

    monkeypatch.setattr(project_session, "_write_project_metadata", fail_metadata)
    with pytest.raises(OSError, match="simulated metadata failure"):
        save_project_programme_scope_policy(project_file, _complete_policy())

    assert project_file.read_bytes() == before
    assert not (project_file.parent / PROGRAMME_SCOPE_FILENAME).exists()


def test_explicit_project_load_refuses_symlinked_scope_policy(tmp_path: Path) -> None:
    project_file = _project(tmp_path)
    payload = json.loads(project_file.read_text(encoding="utf-8"))
    payload["programme_scope_file"] = PROGRAMME_SCOPE_FILENAME
    project_file.write_text(json.dumps(payload), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text("private", encoding="utf-8")
    (project_file.parent / PROGRAMME_SCOPE_FILENAME).symlink_to(outside)

    with pytest.raises(ValueError, match="regular file, not a link"):
        load_project_programme_scope_policy(load_project(project_file))
