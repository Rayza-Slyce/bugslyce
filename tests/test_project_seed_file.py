from pathlib import Path

import pytest


def _loader():
    from bugslyce.project_seed_file import load_project_seed_file

    return load_project_seed_file


def test_seed_file_loads_explicit_lines_and_ignores_blank_lines_and_comments(
    tmp_path: Path,
) -> None:
    path = tmp_path / "seeds.txt"
    path.write_text(
        "\n"
        "# Primary application\n"
        "  https://www.example.test/  \n"
        "\n"
        "# API\n"
        "https://api.example.test/\n",
        encoding="utf-8",
    )

    assert _loader()(path) == (
        "https://www.example.test/",
        "https://api.example.test/",
    )


def test_seed_file_rejects_empty_effective_input(tmp_path: Path) -> None:
    path = tmp_path / "seeds.txt"
    path.write_text(
        "\n# no configured seeds\n   \n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="one or more"):
        _loader()(path)


def test_seed_file_rejects_inline_comment_syntax(tmp_path: Path) -> None:
    path = tmp_path / "seeds.txt"
    path.write_text(
        "https://www.example.test/ # primary\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="line|comment|#"):
        _loader()(path)


def test_seed_file_does_not_guess_or_validate_url_semantics(tmp_path: Path) -> None:
    path = tmp_path / "seeds.txt"
    path.write_text(
        "api.example.test\n"
        "https://www.example.test/path\n",
        encoding="utf-8",
    )

    assert _loader()(path) == (
        "api.example.test",
        "https://www.example.test/path",
    )


def test_seed_file_rejects_non_regular_or_symlink_input(tmp_path: Path) -> None:
    load = _loader()

    with pytest.raises(ValueError, match="regular|file"):
        load(tmp_path)

    target = tmp_path / "real-seeds.txt"
    target.write_text("https://example.test/\n", encoding="utf-8")

    link = tmp_path / "linked-seeds.txt"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="regular|symlink|file"):
        load(link)


def test_seed_file_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "seeds.txt"
    path.write_bytes(b"https://example.test/\n\xff")

    with pytest.raises(ValueError, match="UTF-8"):
        _loader()(path)


def test_seed_file_rejects_oversized_input(tmp_path: Path) -> None:
    from bugslyce.project_seed_file import MAX_PROJECT_SEED_FILE_BYTES

    path = tmp_path / "seeds.txt"
    path.write_bytes(b"x" * (MAX_PROJECT_SEED_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="file-size limit"):
        _loader()(path)
