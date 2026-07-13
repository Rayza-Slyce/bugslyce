"""Tests for local-only BugSlyce evidence pack export."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import zipfile

import pytest

from bugslyce.cli import main
from bugslyce.recon.export import export_recon_evidence_pack


FIXED_TIME = datetime(2026, 6, 14, 13, 45, 12, tzinfo=timezone.utc)


def test_export_refuses_missing_input_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        export_recon_evidence_pack(tmp_path / "missing", tmp_path / "pack.zip")


def test_export_refuses_missing_manifest(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="Recon manifest does not exist"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_refuses_non_zip_output(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="must end with .zip"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.tar")


def test_export_refuses_overwrite_without_force_and_allows_force(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"existing")

    with pytest.raises(ValueError, match="Re-run with --force"):
        export_recon_evidence_pack(input_dir, output_path)

    result = export_recon_evidence_pack(input_dir, output_path, force=True)

    assert result.output_path == str(output_path.resolve())
    assert zipfile.is_zipfile(output_path)


def test_export_preserves_existing_positional_force_and_clock(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"existing")

    result = export_recon_evidence_pack(input_dir, output_path, True, lambda: FIXED_TIME)

    assert result.exported_at == "2026-06-14T13:45:12Z"
    assert zipfile.is_zipfile(output_path)


def test_export_rejects_positional_deep_evidence_paths(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_file = input_dir / "deep.md"
    deep_file.write_text("# deep\n", encoding="utf-8")

    with pytest.raises(TypeError):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            False,
            lambda: FIXED_TIME,
            (deep_file,),
        )


def test_export_contains_pack_metadata_scope_and_manifest_artifacts(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
    )

    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        readme = archive.read("BUGSLYCE_EXPORT_README.md").decode("utf-8")

    assert {
        "BUGSLYCE_EXPORT_README.md",
        "bugslyce_export_manifest.json",
        "report.md",
        "project_state.json",
        "recon_manifest.json",
        "recon_status.md",
        "recon_status.json",
        "scope.md",
        "metadata/recon_execution.md",
        "metadata/recon_execution.json",
        "metadata/recon_execution_content_run.md",
        "metadata/recon_execution_content_run.json",
        "metadata/content_discovery_execution.md",
        "metadata/content_discovery_execution.json",
        "raw/nmap-allports.txt",
        "raw/nested/homepage-target-80.html",
    }.issubset(names)
    assert result.files_included == export_manifest["files_included"]
    assert export_manifest["target"] == "10.10.10.10"
    assert export_manifest["raw_profile"] == "lab-tcp-full-plus-services"
    assert export_manifest["exported_at"] == "2026-06-14T13:45:12Z"
    assert export_manifest["file_count"] == len(names)
    assert export_manifest["warning"] == "sensitive recon evidence"
    assert export_manifest["no_live_commands_executed"] is True
    assert "may contain sensitive recon evidence" in readme
    assert "Exported at: `2026-06-14T13:45:12Z`" in readme
    assert "No live commands were executed during export." in readme


def test_export_accepts_absolute_manifest_path_inside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(input_dir / "nmap-allports.txt")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        assert "raw/nmap-allports.txt" in archive.namelist()


def test_export_rejects_path_traversal_reference(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = "../outside.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_rejects_absolute_path_outside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(outside)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_records_missing_manifest_artifacts_without_failing(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {"type": "robots", "file": "missing-robots.txt", "url": "http://10.10.10.10/robots.txt"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        assert "raw/missing-robots.txt" not in archive.namelist()
    assert result.missing_files == ["missing-robots.txt"]
    assert export_manifest["missing_files"] == ["missing-robots.txt"]


def test_export_excludes_unrelated_and_cache_files(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / ".git").mkdir()
    (input_dir / ".git" / "config").write_text("private", encoding="utf-8")
    (input_dir / ".venv").mkdir()
    (input_dir / ".venv" / "secret").write_text("private", encoding="utf-8")
    (input_dir / "__pycache__").mkdir()
    (input_dir / "__pycache__" / "cache.pyc").write_bytes(b"cache")
    (input_dir / ".pytest_cache").mkdir()
    (input_dir / ".pytest_cache" / "state").write_text("cache", encoding="utf-8")
    (input_dir / "unrelated.txt").write_text("not evidence", encoding="utf-8")
    output_path = input_dir / "evidence-pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert not any(".git" in name for name in names)
    assert not any(".venv" in name for name in names)
    assert not any("__pycache__" in name for name in names)
    assert not any(".pytest_cache" in name for name in names)
    assert "unrelated.txt" not in names
    assert "evidence-pack.zip" not in names


def test_export_is_deterministic_for_unchanged_input(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    export_recon_evidence_pack(input_dir, first, clock=lambda: FIXED_TIME)
    export_recon_evidence_pack(input_dir, second, clock=lambda: FIXED_TIME)

    assert first.read_bytes() == second.read_bytes()


def test_export_deep_evidence_omitted_none_and_empty_are_unchanged(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    baseline = tmp_path / "baseline.zip"
    explicit_none = tmp_path / "none.zip"
    explicit_empty = tmp_path / "empty.zip"

    export_recon_evidence_pack(input_dir, baseline, clock=lambda: FIXED_TIME)
    export_recon_evidence_pack(
        input_dir,
        explicit_none,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=None,
    )
    export_recon_evidence_pack(
        input_dir,
        explicit_empty,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(),
    )

    assert explicit_none.read_bytes() == baseline.read_bytes()
    assert explicit_empty.read_bytes() == baseline.read_bytes()


def test_export_accepts_tuple_and_list_of_path_deep_evidence(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    first_file = input_dir / "deep-one.md"
    second_file = input_dir / "deep-two.md"
    first_file.write_text("one\n", encoding="utf-8")
    second_file.write_text("two\n", encoding="utf-8")
    supplied_list = [second_file]

    export_recon_evidence_pack(
        input_dir,
        tmp_path / "tuple.zip",
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(first_file,),
    )
    export_recon_evidence_pack(
        input_dir,
        tmp_path / "list.zip",
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=supplied_list,
    )

    assert supplied_list == [second_file]


@pytest.mark.parametrize(
    "invalid_value",
    [
        "deep.md",
        b"deep.md",
        Path("deep.md"),
        ("deep.md",),
        (1,),
    ],
)
def test_export_rejects_invalid_deep_evidence_path_types(
    tmp_path: Path,
    invalid_value,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    with pytest.raises(
        TypeError,
        match="deep_evidence_paths must be a sequence of pathlib.Path values",
    ):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=invalid_value,
        )

    assert not output_path.exists()


def test_export_rejects_object_deep_evidence_without_string_coercion(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    class StringTrap:
        def __str__(self) -> str:
            raise AssertionError("__str__ must not be called for invalid Deep evidence paths")

    with pytest.raises(
        TypeError,
        match="deep_evidence_paths must be a sequence of pathlib.Path values",
    ):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(StringTrap(),),
        )

    assert not output_path.exists()


def test_export_resolves_relative_deep_evidence_against_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_dir = input_dir / "deep"
    deep_dir.mkdir()
    (deep_dir / "relative.md").write_text("relative\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(Path("deep/relative.md"),),
    )

    with zipfile.ZipFile(output_path) as archive:
        assert archive.read("raw/deep/relative.md") == b"relative\n"


def test_export_rejects_deep_evidence_path_traversal(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(Path("../outside.md"),),
        )


def test_export_includes_explicit_deep_evidence_files_deterministically(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_dir = input_dir / "deep"
    deep_dir.mkdir()
    alpha = deep_dir / "deep-alpha.md"
    beta = deep_dir / "deep-beta.json"
    alpha.write_bytes(b"# alpha\n")
    beta.write_bytes(b'{"beta": true}\n')
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    result = export_recon_evidence_pack(
        input_dir,
        first,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(beta, alpha, alpha),
    )
    export_recon_evidence_pack(
        input_dir,
        second,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(alpha, beta),
    )

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("bugslyce_export_manifest.json").decode("utf-8"))
        assert archive.read("raw/deep/deep-alpha.md") == b"# alpha\n"
        assert archive.read("raw/deep/deep-beta.json") == b'{"beta": true}\n'
    assert names.count("raw/deep/deep-alpha.md") == 1
    assert names.count("raw/deep/deep-beta.json") == 1
    assert "raw/nmap-allports.txt" in names
    assert all(not name.startswith("/") for name in names)
    assert all(".." not in Path(name).parts for name in names)
    assert manifest["files_included"] == sorted(manifest["files_included"])
    assert result.files_included == manifest["files_included"]


def test_export_skips_deep_evidence_already_included_as_top_level_file(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(input_dir / "report.md",),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert "report.md" in names
    assert "raw/report.md" not in names
    assert "report.md" in result.files_included
    assert "raw/report.md" not in result.files_included
    assert result.missing_files == []


def test_export_skips_deep_evidence_already_included_as_manifest_artifact(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(input_dir / "nmap-allports.txt",),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert names.count("raw/nmap-allports.txt") == 1


def test_export_skips_symlink_alias_to_existing_in_root_source(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    alias = input_dir / "nmap-alias.txt"
    alias.symlink_to(input_dir / "nmap-allports.txt")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(alias,),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert names.count("raw/nmap-allports.txt") == 1
    assert "raw/nmap-alias.txt" not in names


def test_export_includes_different_deep_files_with_same_basename_deterministically(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    first_dir = input_dir / "first"
    second_dir = input_dir / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first_file = first_dir / "shared.md"
    second_file = second_dir / "shared.md"
    first_file.write_bytes(b"first\n")
    second_file.write_bytes(b"second\n")
    first_zip = tmp_path / "first.zip"
    second_zip = tmp_path / "second.zip"

    export_recon_evidence_pack(
        input_dir,
        first_zip,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(second_file, first_file),
    )
    export_recon_evidence_pack(
        input_dir,
        second_zip,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(first_file, second_file),
    )

    assert first_zip.read_bytes() == second_zip.read_bytes()
    with zipfile.ZipFile(first_zip) as archive:
        assert archive.read("raw/first/shared.md") == b"first\n"
        assert archive.read("raw/second/shared.md") == b"second\n"


def test_export_rejects_deep_evidence_self_inclusion_before_writing(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = input_dir / "pack.zip"

    with pytest.raises(ValueError, match="cannot be the export output path"):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(output_path,),
        )

    assert not output_path.exists()


def test_export_rejects_existing_output_self_inclusion_without_truncating(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = input_dir / "pack.zip"
    output_path.write_bytes(b"keep this zip placeholder")

    with pytest.raises(ValueError, match="cannot be the export output path"):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            force=True,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(output_path,),
        )

    assert output_path.read_bytes() == b"keep this zip placeholder"


def test_export_deep_evidence_uses_existing_missing_directory_and_outside_policy(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    missing = input_dir / "deep-missing.md"
    directory = input_dir / "deep-dir"
    directory.mkdir()
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(missing, directory),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert "raw/deep-missing.md" not in names
    assert "raw/deep-dir" not in names
    assert result.missing_files == [str(directory), str(missing)]

    outside = tmp_path / "outside-deep.md"
    outside.write_text("outside\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "outside.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(outside,),
        )


def test_export_deep_evidence_symlink_policy_matches_existing_root_policy(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside-secret.md"
    outside.write_text("secret\n", encoding="utf-8")
    link = input_dir / "deep-link.md"
    link.symlink_to(outside)

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(link,),
        )


def test_export_does_not_discover_deep_files_without_explicit_paths(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "deep-unlisted.md").write_text("# deep\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)

    with zipfile.ZipFile(output_path) as archive:
        assert "raw/deep-unlisted.md" not in archive.namelist()


def test_export_zip_entry_timestamps_remain_fixed(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)

    with zipfile.ZipFile(output_path) as archive:
        assert {info.date_time for info in archive.infolist()} == {
            (1980, 1, 1, 0, 0, 0)
        }


def test_cli_export_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "export", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon export" in captured.out
    assert "--input-dir" in captured.out
    assert "--output" in captured.out
    assert "--force" in captured.out


def test_cli_export_succeeds_without_live_activity(tmp_path: Path, capsys) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    exit_code = main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "by Rayza Slyce" not in captured.out
    assert output_path.is_file()
    assert "BugSlyce evidence pack export complete" in captured.out
    assert "No live commands were executed." in captured.out
    assert "No network requests were made." in captured.out


def test_export_module_has_no_command_or_network_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "export.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def test_export_module_does_not_import_deep_implementation_modules() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "export.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "deep_collection_review_bundle",
        "deep_http_fingerprint_summary",
        "deep_redirect_auth_flow_review",
        "deep_response_similarity_review",
        "deep_html_route_extraction",
        "deep_javascript_route_extraction",
        "deep_shallow_route_followup",
        "deep_form_inventory",
        "deep_parameter_inventory",
    ):
        assert forbidden not in source


def _export_input(tmp_path: Path) -> Path:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    (input_dir / "nested").mkdir()
    files = {
        "report.md": "# BugSlyce Recon Pack\n",
        "project_state.json": '{"project_state": {}, "candidates": []}\n',
        "recon_status.md": "# BugSlyce Recon Status\n",
        "recon_status.json": '{"target": "10.10.10.10"}\n',
        "recon_execution.md": "# Latest execution\n",
        "recon_execution.json": '{"mode": "content-run"}\n',
        "recon_execution_content_run.md": "# Content discovery\n",
        "recon_execution_content_run.json": '{"mode": "content-run"}\n',
        "content_discovery_execution.md": "# Content discovery\n",
        "content_discovery_execution.json": '{"mode": "content-run"}\n',
        "scope.md": "## In Scope\n\n- 10.10.10.10\n",
        "nmap-allports.txt": "80/tcp open http\n",
        "nested/homepage-target-80.html": "<title>Home</title>\n",
    }
    for name, content in files.items():
        (input_dir / name).write_text(content, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "scope_file": "scope.md",
        "profile": "lab-tcp-full-plus-services",
        "artifacts": [
            {"type": "nmap", "file": "nmap-allports.txt"},
            {
                "type": "html",
                "file": "nested/homepage-target-80.html",
                "url": "http://10.10.10.10/",
            },
        ],
    }
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return input_dir
