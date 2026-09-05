"""Grouped HackerOne programme-scope import and save contracts."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    RULE_EXACT_HOSTNAME,
    RULE_EXACT_HTTP_URL,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.programme_scope_hackerone_csv import (
    ASSET_GOOGLE_PLAY_APP_ID,
    ASSET_OTHER,
    ASSET_SOURCE_CODE,
    ASSET_URL,
    ASSET_WILDCARD,
    HACKERONE_CSV_HEADERS,
    build_hackerone_programme_scope_proposal,
)
from bugslyce.programme_scope_hackerone_import import (
    HACKERONE_IMPORT_MODE_MERGE,
    HACKERONE_IMPORT_MODE_NEW,
    HACKERONE_IMPORT_MODE_REPLACE,
    HackerOneImportCancelled,
    build_hackerone_import_completeness,
    import_hackerone_programme_scope,
    parse_hackerone_group_selection,
    prepare_hackerone_import_proposal,
    render_hackerone_import_completeness,
    render_hackerone_import_groups,
    render_hackerone_import_summary,
    review_hackerone_instruction_dossier,
    sanitise_hackerone_instruction_text,
    view_hackerone_instruction_dossier,
)
from bugslyce.programme_scope_hackerone_resolution import (
    ROW_STATE_AUTOMATIC_RULE,
    ROW_STATE_TYPED_NON_AUTHORITY,
    acknowledge_hackerone_scope_instruction,
    build_hackerone_scope_resolution_session,
    finalize_hackerone_scope_resolution,
    resolve_hackerone_scope_include_as_non_authority,
    resolve_hackerone_scope_row_with_rule,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    load_project_programme_scope_policy,
    save_project_programme_scope_policy,
)
import bugslyce.programme_scope_hackerone_import as import_module
import bugslyce.programme_scope_setup as scope_setup_module


FIXED_TIME = "2026-09-04T12:00:00Z"


def _row(**overrides: str) -> dict[str, str]:
    row = {
        "identifier": "https://example.test/service",
        "asset_type": ASSET_URL,
        "instruction": "",
        "eligible_for_bounty": "true",
        "eligible_for_submission": "true",
        "availability_requirement": "high",
        "confidentiality_requirement": "high",
        "integrity_requirement": "high",
        "max_severity": "critical",
        "system_tags": "",
        "created_at": "2026-09-01 12:00:00 UTC",
        "updated_at": "2026-09-02 12:00:00 UTC",
    }
    row.update(overrides)
    return row


def _write_csv(tmp_path: Path, *rows: dict[str, str], name: str = "scope.csv") -> Path:
    path = tmp_path / name
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(HACKERONE_CSV_HEADERS)
        for row in rows:
            writer.writerow(tuple(row[header] for header in HACKERONE_CSV_HEADERS))
    return path


def _session(tmp_path: Path, *rows: dict[str, str]):
    return build_hackerone_scope_resolution_session(
        build_hackerone_programme_scope_proposal(_write_csv(tmp_path, *rows))
    )


def _project(tmp_path: Path) -> Path:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "h1-import",
        "example.test",
        scope,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    return project_file


def _inputs(*answers: str):
    values = iter(answers)
    return lambda _prompt: next(values)


def _resolve_all_explicit(session):
    changed = session
    for row, resolution in zip(
        session.source_result.document.rows,
        session.resolutions,
        strict=True,
    ):
        if resolution.instruction_sha256 is not None:
            changed = acknowledge_hackerone_scope_instruction(
                changed,
                row.row_id,
                source_sha256=session.source_sha256,
                instruction_sha256=resolution.instruction_sha256,
            )
        if resolution.state in {ROW_STATE_AUTOMATIC_RULE, ROW_STATE_TYPED_NON_AUTHORITY}:
            continue
        if resolution.proposed_action == ACTION_INCLUDE and row.asset_type == ASSET_OTHER:
            changed = resolve_hackerone_scope_include_as_non_authority(changed, row.row_id)
        else:
            changed = resolve_hackerone_scope_row_with_rule(
                changed,
                row.row_id,
                kind=RULE_EXACT_HOSTNAME,
                value=row.identifier,
            )
    return changed


def test_summary_groups_and_completeness_are_deterministic_and_private(
    tmp_path: Path,
) -> None:
    secret = "private instruction sentinel"
    session = _session(
        tmp_path,
        _row(identifier="https://auto.example.test/", eligible_for_submission="true"),
        _row(
            identifier="*.example.test",
            asset_type=ASSET_WILDCARD,
            eligible_for_submission="false",
        ),
        _row(identifier="one.example.test", eligible_for_submission="true"),
        _row(identifier="two.example.test", eligible_for_submission="false"),
        _row(identifier="com.example.app", asset_type=ASSET_GOOGLE_PLAY_APP_ID),
        _row(identifier="https://review.example.test/", instruction=secret),
    )

    summary = render_hackerone_import_summary(session)
    groups = render_hackerone_import_groups(session)
    completeness = build_hackerone_import_completeness(session)
    rendered_completeness = render_hackerone_import_completeness(completeness)

    assert session.source_result.document.source_filename in summary
    assert session.source_sha256 in summary
    assert "Source rows: 6" in summary
    assert "Automatic rules: 1 include; 1 exclude" in summary
    assert "Unresolved: 2 include; 1 exclude" in summary
    assert "Typed non-authority: 1 include; 0 exclude" in summary
    assert "Instruction-required rows: 1" in summary
    assert f"Resolution groups: {len(session.groups)}" in summary
    assert secret not in summary + groups + rendered_completeness
    assert tuple(line for line in groups.splitlines() if line.startswith("Group ")) == tuple(
        sorted(line for line in groups.splitlines() if line.startswith("Group "))
    )
    assert completeness.unresolved_include_rows == (3, 6)
    assert completeness.unresolved_exclude_rows == (4,)
    assert completeness.unacknowledged_instruction_rows == (6,)
    assert completeness.automatic_rules == 2
    assert "Save available: no" in rendered_completeness


def test_group_selection_supports_all_lists_ranges_and_is_fail_closed(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        *(_row(identifier=f"host-{number}.example.test") for number in range(1, 6)),
    )
    group = session.groups[0]

    assert parse_hackerone_group_selection("all", session=session, group=group) == group.row_ids
    selected = parse_hackerone_group_selection(
        "1,3-4", session=session, group=group
    )
    assert selected == (group.row_ids[0], group.row_ids[2], group.row_ids[3])
    assert parse_hackerone_group_selection("back", session=session, group=group) is None
    for invalid in ("", "1,1", "1-3,3", "4-2", "0", "9", "one", "1,,2"):
        with pytest.raises(ValueError):
            parse_hackerone_group_selection(invalid, session=session, group=group)
    assert all(item.state == "unresolved" for item in session.resolutions)


def test_instruction_dossier_groups_exact_bodies_sanitises_controls_and_acks_each_row(
    tmp_path: Path,
) -> None:
    instruction = "Review <b>literally</b>.\n\x1b[31mDo not colour this."
    session = _session(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction=instruction),
        _row(identifier="https://two.example.test/", instruction=instruction),
    )
    output: list[str] = []

    changed = review_hackerone_instruction_dossier(
        session,
        input_func=_inputs("ACKNOWLEDGE ALL"),
        print_func=output.append,
        error_func=pytest.fail,
    )

    rendered = "\n".join(output)
    assert rendered.count("BEGIN HACKERONE INSTRUCTION") == 1
    assert rendered.count("END HACKERONE INSTRUCTION") == 1
    assert "Rows: 1, 2" in rendered
    assert "\x1b" not in rendered
    assert "\\x1b[31m" in rendered
    assert "<b>literally</b>" in rendered
    assert all(item.instruction_acknowledged for item in changed.resolutions)
    assert sanitise_hackerone_instruction_text("ok\x07\x1b") == "ok\\x07\\x1b"


def test_instruction_dossier_is_continuous_and_uses_one_final_acknowledgement(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction="First instruction."),
        _row(identifier="https://two.example.test/", instruction="Second instruction."),
        _row(identifier="https://three.example.test/", instruction="Third instruction."),
    )
    output: list[str] = []
    prompts: list[str] = []

    def acknowledge_all(prompt: str) -> str:
        prompts.append(prompt)
        if "ACKNOWLEDGE ALL" in prompt:
            return "ACKNOWLEDGE ALL"
        if "Press Enter" in prompt:
            return ""
        raise AssertionError(f"unexpected per-instruction prompt: {prompt}")

    changed = review_hackerone_instruction_dossier(
        session,
        input_func=acknowledge_all,
        print_func=output.append,
        error_func=pytest.fail,
    )

    rendered = "\n".join(output)
    assert "Programme instructions" in rendered
    assert "3 distinct instructions affect 3 scope rows." in rendered
    assert "Instruction 1 of 3" in rendered
    assert "Instruction 2 of 3" in rendered
    assert "Instruction 3 of 3" in rendered
    assert len([prompt for prompt in prompts if "ACKNOWLEDGE ALL" in prompt]) == 1
    assert all(item.instruction_acknowledged for item in changed.resolutions)


def test_instruction_dossier_cancellation_does_not_partially_acknowledge(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction="First instruction."),
        _row(identifier="https://two.example.test/", instruction="Second instruction."),
    )
    acknowledgements: list[str] = []
    real_acknowledge = import_module.acknowledge_hackerone_scope_instruction

    def record_acknowledgement(*args, **kwargs):
        acknowledgements.append(kwargs["instruction_sha256"])
        return real_acknowledge(*args, **kwargs)

    monkeypatch.setattr(
        import_module,
        "acknowledge_hackerone_scope_instruction",
        record_acknowledgement,
    )
    with pytest.raises(HackerOneImportCancelled):
        review_hackerone_instruction_dossier(
            session,
            input_func=_inputs("ACKNOWLEDGE", "CANCEL"),
            print_func=lambda _line: None,
            error_func=lambda _line: None,
        )

    assert acknowledgements == []
    assert all(not item.instruction_acknowledged for item in session.resolutions)


def test_instruction_dossier_eof_does_not_partially_acknowledge(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction="First instruction."),
        _row(identifier="https://two.example.test/", instruction="Second instruction."),
    )
    acknowledgements: list[str] = []
    real_acknowledge = import_module.acknowledge_hackerone_scope_instruction

    def record_acknowledgement(*args, **kwargs):
        acknowledgements.append(kwargs["instruction_sha256"])
        return real_acknowledge(*args, **kwargs)

    monkeypatch.setattr(
        import_module,
        "acknowledge_hackerone_scope_instruction",
        record_acknowledgement,
    )
    with pytest.raises(EOFError):
        review_hackerone_instruction_dossier(
            session,
            input_func=lambda _prompt: (_ for _ in ()).throw(EOFError()),
            print_func=lambda _line: None,
            error_func=lambda _line: None,
        )

    assert acknowledgements == []
    assert all(not item.instruction_acknowledged for item in session.resolutions)


def test_read_only_instruction_dossier_reopens_acknowledged_rows_without_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction="Review this."),
    )
    acknowledged = acknowledge_hackerone_scope_instruction(
        session,
        session.resolutions[0].row_id,
        source_sha256=session.source_sha256,
        instruction_sha256=session.resolutions[0].instruction_sha256,
    )
    calls: list[object] = []
    monkeypatch.setattr(
        import_module,
        "acknowledge_hackerone_scope_instruction",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    output: list[str] = []

    viewed = view_hackerone_instruction_dossier(
        acknowledged,
        input_func=lambda _prompt: "",
        print_func=output.append,
        error_func=pytest.fail,
    )

    assert viewed is acknowledged
    assert calls == []
    assert "Instruction 1 of 1" in "\n".join(output)
    assert viewed.resolutions == acknowledged.resolutions


def test_read_only_instruction_dossier_can_be_limited_to_one_semantic_group(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="one.example.test", instruction="Hostname instruction."),
        _row(identifier="label", asset_type=ASSET_OTHER, instruction="Other instruction."),
    )
    output: list[str] = []

    viewed = view_hackerone_instruction_dossier(
        session,
        row_ids=session.groups[0].row_ids,
        input_func=lambda _prompt: "",
        print_func=output.append,
        error_func=pytest.fail,
    )

    rendered = "\n".join(output)
    assert "Hostname instruction." in rendered
    assert "Other instruction." not in rendered
    assert viewed is session


def test_group_instruction_action_reopens_only_its_instruction_without_mutation(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="one.example.test", instruction="Hostname instruction."),
        _row(identifier="label", asset_type=ASSET_OTHER, instruction="Other instruction."),
    )
    output: list[str] = []

    changed = import_module._review_group(
        session,
        session.groups[0],
        input_func=_inputs("VIEW-INSTRUCTION", "DEFER"),
        print_func=output.append,
        error_func=pytest.fail,
    )

    rendered = "\n".join(output)
    assert "Hostname instruction." in rendered
    assert "Other instruction." not in rendered
    assert changed is session


def test_final_change_regenerates_proposal_from_amended_resolution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, _row(identifier="host.example.test"))
    captured: list[ProgrammeScopeProposal] = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE",
            "1", "HOSTNAME", "all", "REVIEW",
            "CHANGE",
            "1", "RESET", "all",
            "1", "URL", "all", "https://host.example.test/only",
            "REVIEW",
            "SAVE",
        ),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert len(captured) == 1
    assert captured[0].rules[0].kind == RULE_EXACT_HTTP_URL
    assert captured[0].rules[0].canonical_value == "https://host.example.test/only"


def test_final_import_cancel_does_not_enter_p1_save_seam(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, _row(identifier="https://example.test/service"))
    calls: list[object] = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "REVIEW", "CANCEL"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert calls == []
    assert not (project_file.parent / "programme_scope.json").exists()


def test_final_instructions_reopens_read_only_dossier_then_save(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        _row(identifier="https://example.test/service", instruction="Review this condition."),
    )
    captured: list[ProgrammeScopeProposal] = []
    output: list[str] = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE", "ACKNOWLEDGE ALL",
            "1", "ACCEPT-CANONICAL", "all", "ACCEPT CANONICAL RULES", "REVIEW",
            "INSTRUCTIONS", "SAVE",
        ),
        print_func=output.append,
        error_func=pytest.fail,
    ) == 0
    assert "Programme instructions (read-only)" in "\n".join(output)
    assert len(captured) == 1


def test_replace_change_save_uses_amended_candidate_and_requires_fresh_acknowledgement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    existing = build_programme_scope_rule(
        rule_id="existing-rule",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="existing.example.test",
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy((existing,), updated_at=FIXED_TIME),
    )
    csv_path = _write_csv(tmp_path, _row(identifier="new.example.test"))
    captured: list[ProgrammeScopeProposal] = []
    prompts: list[str] = []
    answers = iter(
        (
            "CONTINUE", "REPLACE",
            "1", "HOSTNAME", "all", "REVIEW",
            "CHANGE",
            "1", "RESET", "all",
            "1", "URL", "all", "https://new.example.test/only", "REVIEW",
            "SAVE", "REPLACE EXISTING POLICY",
        )
    )
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=lambda prompt: prompts.append(prompt) or next(answers),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert len(captured) == 1
    assert captured[0].rules[0].canonical_value == "https://new.example.test/only"
    assert any("REPLACE EXISTING POLICY" in prompt for prompt in prompts)


def test_shopify_shaped_dossier_uses_one_acknowledgement_for_all_rows(
    tmp_path: Path,
) -> None:
    instructions = tuple(f"Instruction body {index}." for index in range(1, 22))
    session = _session(
        tmp_path,
        *(
            _row(
                identifier=f"https://{index}.example.test/",
                instruction=instructions[(index - 1) % len(instructions)],
            )
            for index in range(1, 30)
        ),
    )
    output: list[str] = []
    prompts: list[str] = []

    def complete_dossier(prompt: str) -> str:
        prompts.append(prompt)
        if "ACKNOWLEDGE ALL" in prompt:
            return "ACKNOWLEDGE ALL"
        if "Press Enter" in prompt:
            return ""
        raise AssertionError(prompt)

    changed = review_hackerone_instruction_dossier(
        session,
        input_func=complete_dossier,
        print_func=output.append,
        error_func=pytest.fail,
    )

    rendered = "\n".join(output)
    assert rendered.count("BEGIN HACKERONE INSTRUCTION") == 21
    assert len([prompt for prompt in prompts if "ACKNOWLEDGE ALL" in prompt]) == 1
    assert all(item.instruction_acknowledged for item in changed.resolutions)
    assert all(item.state == "unresolved" for item in changed.resolutions)
    assert all(
        item.instruction_acknowledgement is not None
        and item.instruction_acknowledgement.source_sha256 == changed.source_sha256
        and item.instruction_acknowledgement.row_id == item.row_id
        and item.instruction_acknowledgement.instruction_sha256 == item.instruction_sha256
        for item in changed.resolutions
    )


def test_instruction_must_be_fully_displayed_before_acknowledgement(
    tmp_path: Path,
) -> None:
    instruction = "\n".join(f"line {index}" for index in range(1, 26))
    session = _session(tmp_path, _row(instruction=instruction))
    errors: list[str] = []

    with pytest.raises(HackerOneImportCancelled):
        review_hackerone_instruction_dossier(
            session,
            input_func=_inputs("ACKNOWLEDGE ALL", "CANCEL"),
            print_func=lambda _line: None,
            error_func=errors.append,
        )

    assert errors == ["Error: press Enter to display the complete dossier."]
    assert session.resolutions[0].instruction_acknowledged is False


def test_prepare_merge_deduplicates_same_action_and_preserves_exclusion_precedence(
    tmp_path: Path,
) -> None:
    session = _session(
        tmp_path,
        _row(identifier="same.example.test"),
        _row(identifier="blocked.example.test", eligible_for_submission="false"),
    )
    resolved = _resolve_all_explicit(session)
    imported = finalize_hackerone_scope_resolution(resolved)
    existing_same = build_programme_scope_rule(
        rule_id="existing-include",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="same.example.test",
        private_note="never render this private note",
    )
    overlapping_include = build_programme_scope_rule(
        rule_id="existing-broad",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="blocked.example.test",
    )
    existing = build_programme_scope_policy(
        (existing_same, overlapping_include), updated_at=FIXED_TIME
    )

    merged = prepare_hackerone_import_proposal(
        imported, existing_policy=existing, mode=HACKERONE_IMPORT_MODE_MERGE
    )

    assert sum(
        rule.action == ACTION_INCLUDE
        and rule.kind == RULE_EXACT_HOSTNAME
        and rule.canonical_value == "same.example.test"
        for rule in merged.rules
    ) == 1
    assert existing_same in merged.rules
    assert overlapping_include in merged.rules
    assert any(
        rule.action == ACTION_EXCLUDE
        and rule.canonical_value == "blocked.example.test"
        for rule in merged.rules
    )
    assert "never render this private note" not in render_hackerone_import_summary(session)


def test_prepare_merge_rejects_id_collision_but_replace_and_new_are_exact(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path, _row(identifier="host.example.test"))
    imported = finalize_hackerone_scope_resolution(_resolve_all_explicit(session))
    imported_rule = imported.rules[0]
    collision = build_programme_scope_rule(
        rule_id=imported_rule.rule_id.upper(),
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="different.example.test",
    )
    existing = build_programme_scope_policy((collision,), updated_at=FIXED_TIME)

    with pytest.raises(ValueError, match="rule ID collision"):
        prepare_hackerone_import_proposal(
            imported, existing_policy=existing, mode=HACKERONE_IMPORT_MODE_MERGE
        )
    assert prepare_hackerone_import_proposal(
        imported, existing_policy=existing, mode=HACKERONE_IMPORT_MODE_REPLACE
    ).rules == imported.rules
    assert prepare_hackerone_import_proposal(
        imported, existing_policy=None, mode=HACKERONE_IMPORT_MODE_NEW
    ).rules == imported.rules
    with pytest.raises(ValueError, match="explicit MERGE, REPLACE or CANCEL"):
        prepare_hackerone_import_proposal(
            imported, existing_policy=existing, mode=HACKERONE_IMPORT_MODE_NEW
        )


def test_malformed_csv_and_summary_cancellation_never_reach_save(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    malformed = tmp_path / "bad.csv"
    malformed.write_text("wrong,header\n", encoding="utf-8")
    calls = 0

    def forbidden(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        pytest.fail("invalid or cancelled import must not reach P1 save")

    monkeypatch.setattr(import_module, "review_and_save_programme_scope_proposal", forbidden)
    errors: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        malformed,
        input_func=pytest.fail,
        print_func=lambda _line: None,
        error_func=errors.append,
    ) == 2
    valid = _write_csv(tmp_path, _row())
    output: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        valid,
        input_func=_inputs("CANCEL"),
        print_func=output.append,
        error_func=errors.append,
    ) == 0
    assert calls == 0
    assert "stored values are unchanged" in "\n".join(output)
    assert not (project_file.parent / "programme_scope.json").exists()


def test_simple_automatic_import_reaches_p1_and_saves_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, _row(identifier="https://example.test/service"))
    real_save = scope_setup_module.save_project_programme_scope_policy
    calls = 0

    def counted_save(path, policy):
        nonlocal calls
        calls += 1
        return real_save(path, policy)

    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        counted_save,
    )
    output: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "REVIEW", "SAVE", "YES"),
        print_func=output.append,
        error_func=pytest.fail,
        now_func=lambda: FIXED_TIME,
    ) == 0

    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert len(policy.rules) == 1
    assert policy.rules[0].kind == RULE_EXACT_HTTP_URL
    assert calls == 1
    rendered = "\n".join(output)
    assert "This proposal is not authority until explicitly confirmed and saved." in rendered
    assert "No reconnaissance was executed." in rendered


def test_grouped_bare_hostname_actions_are_explicit_and_empty_needs_exact_confirmation(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        _row(identifier="one.example.test"),
        _row(identifier="two.example.test"),
    )
    output: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE", "1", "NON-AUTHORITY", "all", "REVIEW", "SAVE", "SAVE EMPTY POLICY"
        ),
        print_func=output.append,
        error_func=pytest.fail,
        now_func=lambda: FIXED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None and policy.rules == ()
    rendered = "\n".join(output)
    assert "broader than accepting one exact URL" in rendered
    assert "exact_hostname" not in "\n".join(
        line for line in output if line.startswith("Rule resolved:")
    )


@pytest.mark.parametrize(
    ("row", "answers", "expected_kind", "expected_value"),
    (
        (
            _row(identifier="host.example.test"),
            ("CONTINUE", "1", "HOSTNAME", "all", "REVIEW", "SAVE"),
            RULE_EXACT_HOSTNAME,
            "host.example.test",
        ),
        (
            _row(identifier="host.example.test"),
            (
                "CONTINUE", "1", "URL", "all",
                "https://host.example.test/only", "REVIEW", "SAVE",
            ),
            RULE_EXACT_HTTP_URL,
            "https://host.example.test/only",
        ),
        (
            _row(identifier="example.test/service"),
            (
                "CONTINUE", "1", "URL", "all",
                "https://example.test/service", "REVIEW", "SAVE",
            ),
            RULE_EXACT_HTTP_URL,
            "https://example.test/service",
        ),
        (
            _row(identifier="*.example.test", asset_type=ASSET_URL),
            ("CONTINUE", "1", "WILDCARD", "all", "REVIEW", "SAVE"),
            "wildcard_subdomain",
            "*.example.test",
        ),
        (
            _row(identifier="HTTPS://Example.TEST:443/service"),
            (
                "CONTINUE", "1", "ACCEPT-CANONICAL", "all",
                "ACCEPT CANONICAL RULES", "REVIEW", "SAVE",
            ),
            RULE_EXACT_HTTP_URL,
            "https://example.test/service",
        ),
        (
            _row(identifier="label-only", asset_type=ASSET_OTHER),
            (
                "CONTINUE", "1", "CANONICAL", "all", RULE_EXACT_HOSTNAME,
                "explicit.example.test", "", "", "REVIEW", "SAVE",
            ),
            RULE_EXACT_HOSTNAME,
            "explicit.example.test",
        ),
    ),
)
def test_group_actions_require_explicit_safe_operator_decisions(
    tmp_path: Path,
    monkeypatch,
    row: dict[str, str],
    answers: tuple[str, ...],
    expected_kind: str,
    expected_value: str,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, row)
    captured = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(*answers),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert len(captured) == 1
    assert captured[0].rules[0].kind == expected_kind
    assert captured[0].rules[0].canonical_value == expected_value


def test_web_exclusion_cannot_be_dismissed_and_other_can_be_deliberately_non_web(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    excluded = _write_csv(
        tmp_path,
        _row(identifier="admin.example.test", eligible_for_submission="false"),
    )
    errors: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        excluded,
        input_func=_inputs("CONTINUE", "1", "NON-AUTHORITY", "CANCEL"),
        print_func=lambda _line: None,
        error_func=errors.append,
    ) == 0
    assert errors == ["Error: that action is not available for this resolution group."]
    assert not (project_file.parent / "programme_scope.json").exists()

    outside = _write_csv(
        tmp_path,
        _row(
            identifier="operator-classified-item",
            asset_type=ASSET_OTHER,
            eligible_for_submission="false",
        ),
        name="other.csv",
    )
    captured = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )
    assert import_hackerone_programme_scope(
        project_file,
        outside,
        input_func=_inputs("CONTINUE", "1", "NON-WEB", "all", "REVIEW", "SAVE"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert captured[0].rules == ()
    assert "explicit_non_web_classification" in captured[0].non_authority_context[0].value


def test_group_member_inspection_and_wildcard_warning_do_not_mutate_or_save(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        _row(identifier="*.example.test", asset_type=ASSET_URL),
    )
    output: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "1", "INSPECT", "BACK", "CANCEL"),
        print_func=output.append,
        error_func=pytest.fail,
    ) == 0
    rendered = "\n".join(output)
    assert "Group members" in rendered
    assert "row 1 | unresolved | *.example.test" in rendered
    assert "covers descendants and does not include the apex" in rendered
    assert not (project_file.parent / "programme_scope.json").exists()


def test_other_rows_require_individual_resolution_even_with_group_selection(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        _row(identifier="first-label", asset_type=ASSET_OTHER),
        _row(identifier="second-label", asset_type=ASSET_OTHER),
    )
    errors: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "1", "NON-WEB", "all", "CANCEL"),
        print_func=lambda _line: None,
        error_func=errors.append,
    ) == 0
    assert errors == ["Error: OTHER/unsupported source rows must be reviewed individually."]
    assert not (project_file.parent / "programme_scope.json").exists()


def test_identical_instruction_is_displayed_once_but_rule_acceptance_is_per_row(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    instruction = "Review this programme condition."
    csv_path = _write_csv(
        tmp_path,
        _row(identifier="https://one.example.test/", instruction=instruction),
        _row(identifier="https://two.example.test/", instruction=instruction),
    )
    output: list[str] = []
    captured = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE", "ACKNOWLEDGE ALL", "1", "ACCEPT-CANONICAL", "all",
            "ACCEPT CANONICAL RULES", "REVIEW", "SAVE",
        ),
        print_func=output.append,
        error_func=pytest.fail,
    ) == 0
    rendered = "\n".join(output)
    assert rendered.count("BEGIN HACKERONE INSTRUCTION") == 1
    assert len(captured[0].rules) == 2


def test_typed_non_web_rows_require_no_per_row_resolution_prompt(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        *(
            _row(identifier=f"repo-{index}", asset_type=ASSET_SOURCE_CODE)
            for index in range(1, 8)
        ),
    )
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "REVIEW", "SAVE", "SAVE EMPTY POLICY"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        now_func=lambda: FIXED_TIME,
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None and policy.rules == ()


def test_reset_automatic_exclusion_blocks_review_until_canonical_closure_is_restored(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(
        tmp_path,
        _row(
            identifier="*.blocked.example.test",
            asset_type=ASSET_WILDCARD,
            eligible_for_submission="false",
        ),
    )
    output: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE",
            "1", "RESET", "all",
            "REVIEW",
            "1", "WILDCARD", "all",
            "REVIEW", "SAVE", "YES",
        ),
        print_func=output.append,
        error_func=pytest.fail,
        now_func=lambda: FIXED_TIME,
    ) == 0
    rendered = "\n".join(output)
    assert "Unresolved exclusion rows: 1" in rendered
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None and policy.rules[0].action == ACTION_EXCLUDE


def test_existing_policy_requires_merge_replace_or_cancel_and_replace_ack(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    existing_rule = build_programme_scope_rule(
        rule_id="existing",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="old.example.test",
        private_note="private replacement sentinel",
    )
    existing = build_programme_scope_policy((existing_rule,), updated_at=FIXED_TIME)
    save_project_programme_scope_policy(project_file, existing)
    policy_path = project_file.parent / "programme_scope.json"
    before = policy_path.read_bytes()
    csv_path = _write_csv(tmp_path, _row(identifier="https://new.example.test/"))
    output: list[str] = []
    errors: list[str] = []
    answers = iter(("CONTINUE", "REPLACE", "REVIEW", "SAVE", "wrong"))

    def inputs(prompt: str) -> str:
        output.append(prompt)
        return next(answers)

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=inputs,
        print_func=output.append,
        error_func=errors.append,
        now_func=lambda: pytest.fail("replacement refusal must not save"),
    ) == 0
    assert policy_path.read_bytes() == before
    rendered = "\n".join(output)
    assert "existing | include | exact_hostname | old.example.test" in rendered
    assert "private replacement sentinel" not in rendered
    assert "REPLACE EXISTING POLICY" in rendered


def test_merge_preserves_existing_and_final_yes_refusal_writes_nothing(
    tmp_path: Path,
) -> None:
    project_file = _project(tmp_path)
    existing_rule = build_programme_scope_rule(
        rule_id="existing",
        action=ACTION_EXCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="blocked.example.test",
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy((existing_rule,), updated_at=FIXED_TIME),
    )
    policy_path = project_file.parent / "programme_scope.json"
    before = policy_path.read_bytes()
    csv_path = _write_csv(tmp_path, _row(identifier="https://new.example.test/"))

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", "MERGE", "REVIEW", "SAVE", "NO"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        now_func=lambda: pytest.fail("final refusal must not save"),
    ) == 0
    assert policy_path.read_bytes() == before


@pytest.mark.parametrize(
    ("mode", "extra_answers", "expected_values"),
    (
        (
            "MERGE",
            (),
            {"old.example.test", "https://new.example.test/"},
        ),
        (
            "REPLACE",
            ("REPLACE EXISTING POLICY",),
            {"https://new.example.test/"},
        ),
    ),
)
def test_existing_policy_merge_and_replace_success_paths(
    tmp_path: Path,
    mode: str,
    extra_answers: tuple[str, ...],
    expected_values: set[str],
) -> None:
    project_file = _project(tmp_path)
    old = build_programme_scope_rule(
        rule_id="old",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="old.example.test",
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy((old,), updated_at=FIXED_TIME),
    )
    csv_path = _write_csv(tmp_path, _row(identifier="https://new.example.test/"))

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CONTINUE", mode, "REVIEW", "SAVE", *extra_answers, "YES"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
        now_func=lambda: "2026-09-04T13:00:00Z",
    ) == 0
    policy = load_project_programme_scope_policy(load_project(project_file))
    assert policy is not None
    assert {rule.canonical_value for rule in policy.rules} == expected_values


@pytest.mark.parametrize(
    "answers",
    (
        (),
        ("CONTINUE",),
        ("CONTINUE", "1"),
    ),
)
def test_eof_at_summary_group_or_group_action_never_persists(
    tmp_path: Path,
    answers: tuple[str, ...],
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, _row(identifier="host.example.test"))
    values = iter(answers)

    def inputs(_prompt: str) -> str:
        try:
            return next(values)
        except StopIteration:
            raise EOFError from None

    errors: list[str] = []
    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=inputs,
        print_func=lambda _line: None,
        error_func=errors.append,
    ) == 2
    assert errors == ["Error: HackerOne programme-scope input ended unexpectedly."]
    assert not (project_file.parent / "programme_scope.json").exists()


def test_save_failure_uses_p1_atomic_path_and_preserves_existing_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    old = build_programme_scope_rule(
        rule_id="old",
        action=ACTION_INCLUDE,
        kind=RULE_EXACT_HOSTNAME,
        value="old.example.test",
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy((old,), updated_at=FIXED_TIME),
    )
    policy_path = project_file.parent / "programme_scope.json"
    before = policy_path.read_bytes()
    csv_path = _write_csv(tmp_path, _row(identifier="https://new.example.test/"))
    monkeypatch.setattr(
        scope_setup_module,
        "save_project_programme_scope_policy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("synthetic")),
    )
    errors: list[str] = []

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(
            "CONTINUE", "REPLACE", "REVIEW", "SAVE", "REPLACE EXISTING POLICY", "YES"
        ),
        print_func=lambda _line: None,
        error_func=errors.append,
        now_func=lambda: "2026-09-04T13:00:00Z",
    ) == 2
    assert errors == ["Error: programme scope could not be saved safely."]
    assert policy_path.read_bytes() == before


def test_source_csv_is_unchanged_and_no_subprocess_or_network_is_used(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    csv_path = _write_csv(tmp_path, _row())
    before = csv_path.read_bytes()
    monkeypatch.setattr(
        "socket.create_connection",
        lambda *_args, **_kwargs: pytest.fail("import must not use network"),
    )
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("import must not use subprocesses"),
    )

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs("CANCEL"),
        print_func=lambda _line: None,
        error_func=pytest.fail,
    ) == 0
    assert csv_path.read_bytes() == before


def test_shopify_shaped_grouped_import_reaches_complete_p1_proposal_without_save(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_file = _project(tmp_path)
    instruction = "One shared synthetic programme condition for explicit review."
    rows = []
    rows.extend(
        _row(
            identifier=f"excluded-{index}.example.test",
            instruction=instruction,
            eligible_for_submission="false",
        )
        for index in range(1, 7)
    )
    rows.extend(
        _row(identifier=f"included-{index}.example.test", instruction=instruction)
        for index in range(1, 10)
    )
    rows.extend(
        _row(
            identifier=f"other-excluded-{index}",
            asset_type=ASSET_OTHER,
            instruction=instruction,
            eligible_for_submission="false",
        )
        for index in range(1, 3)
    )
    rows.append(_row(identifier="other-include-plain", asset_type=ASSET_OTHER))
    rows.extend(
        _row(
            identifier=f"other-included-{index}",
            asset_type=ASSET_OTHER,
            instruction=instruction,
        )
        for index in range(1, 5)
    )
    rows.append(
        _row(
            identifier="*.excluded.example.test",
            asset_type=ASSET_WILDCARD,
            instruction=instruction,
            eligible_for_submission="false",
        )
    )
    rows.extend(
        _row(
            identifier=f"*.included-{index}.example.test",
            asset_type=ASSET_WILDCARD,
            instruction=instruction,
        )
        for index in range(1, 7)
    )
    rows.append(
        _row(
            identifier="synthetic-repository",
            asset_type=ASSET_SOURCE_CODE,
            instruction=instruction,
        )
    )
    assert len(rows) == 30
    csv_path = _write_csv(tmp_path, *rows)
    captured = []
    monkeypatch.setattr(
        import_module,
        "review_and_save_programme_scope_proposal",
        lambda _path, proposal, **_kwargs: captured.append(proposal) or 0,
    )
    answers = (
        "CONTINUE", "", "ACKNOWLEDGE ALL",
        "1", "HOSTNAME", "all",
        "2", "HOSTNAME", "all",
        "3", "NON-WEB", "16",
        "3", "NON-WEB", "17",
        "4", "NON-WEB", "all",
        "5", "NON-WEB", "19",
        "5", "NON-WEB", "20",
        "5", "NON-WEB", "21",
        "5", "NON-WEB", "22",
        "6", "ACCEPT-CANONICAL", "all", "ACCEPT CANONICAL RULES",
        "7", "ACCEPT-CANONICAL", "all", "ACCEPT CANONICAL RULES",
        "REVIEW", "SAVE",
    )
    output: list[str] = []

    assert import_hackerone_programme_scope(
        project_file,
        csv_path,
        input_func=_inputs(*answers),
        print_func=output.append,
        error_func=pytest.fail,
    ) == 0
    assert len(captured) == 1
    assert captured[0].unresolved_items == ()
    assert len(captured[0].rules) == 22
    assert sum(rule.action == ACTION_EXCLUDE for rule in captured[0].rules) == 7
    assert len(captured[0].non_authority_context) == 30
    assert "Resolution groups: 8" in "\n".join(output)
    assert not (project_file.parent / "programme_scope.json").exists()
