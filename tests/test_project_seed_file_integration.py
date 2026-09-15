import json
from pathlib import Path

from bugslyce.cli import main
from bugslyce.project_session import (
    PROJECT_FILENAME,
    load_project,
    scaffold_project,
)


def _scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.md"
    path.write_text("# Scope\n", encoding="utf-8")
    return path


def test_scaffold_project_persists_configured_http_seed_identity(
    tmp_path: Path,
) -> None:
    result = scaffold_project(
        name="multi-seed",
        target="app.example.test",
        projects_dir=tmp_path / "projects",
        configured_http_seeds=(
            "https://www.example.test/",
            "https://api.example.test/",
        ),
    )

    loaded = load_project(Path(result.project_file))

    assert loaded.schema_version == "1.2"
    assert loaded.configured_http_seeds == (
        "https://api.example.test/",
        "https://www.example.test/",
    )


def test_cli_project_init_loads_seed_file_into_persistent_identity(
    tmp_path: Path,
) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "output"
    seeds = tmp_path / "seeds.txt"
    seeds.write_text(
        "# supplied roots\n"
        "https://www.example.test/\n"
        "https://api.example.test/\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "project",
            "init",
            "--name",
            "seeded-cli",
            "--target",
            "www.example.test",
            "--scope",
            str(scope),
            "--output-dir",
            str(output_dir),
            "--seeds-file",
            str(seeds),
        ]
    )

    assert exit_code == 0

    project_file = output_dir / PROJECT_FILENAME
    payload = json.loads(project_file.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.2"
    assert payload["configured_http_seeds"] == [
        "https://api.example.test/",
        "https://www.example.test/",
    ]


def test_cli_project_scaffold_loads_seed_file_into_persistent_identity(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    seeds = tmp_path / "seeds.txt"
    seeds.write_text(
        "https://app.example.test/\n"
        "https://api.example.test/\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "project",
            "scaffold",
            "--name",
            "seeded-scaffold",
            "--target",
            "app.example.test",
            "--projects-dir",
            str(projects_dir),
            "--seeds-file",
            str(seeds),
        ]
    )

    assert exit_code == 0

    loaded = load_project(
        projects_dir / "seeded-scaffold" / PROJECT_FILENAME
    )
    assert loaded.configured_http_seeds == (
        "https://api.example.test/",
        "https://app.example.test/",
    )


def test_cli_seed_file_invalid_seed_is_rejected_by_project_identity_owner(
    tmp_path: Path,
    capsys,
) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "output"
    seeds = tmp_path / "seeds.txt"
    seeds.write_text(
        "api.example.test\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "project",
            "init",
            "--name",
            "invalid-seed",
            "--target",
            "api.example.test",
            "--scope",
            str(scope),
            "--output-dir",
            str(output_dir),
            "--seeds-file",
            str(seeds),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "configured HTTP seed" in captured.err
    assert "No network requests were made." in captured.err
    assert not (output_dir / PROJECT_FILENAME).exists()


def test_cli_project_init_without_seed_file_preserves_schema_1_1(
    tmp_path: Path,
) -> None:
    scope = _scope_file(tmp_path)
    output_dir = tmp_path / "output"

    exit_code = main(
        [
            "project",
            "init",
            "--name",
            "legacy-cli",
            "--target",
            "www.example.test",
            "--scope",
            str(scope),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0

    payload = json.loads(
        (output_dir / PROJECT_FILENAME).read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "1.1"
    assert "configured_http_seeds" not in payload
