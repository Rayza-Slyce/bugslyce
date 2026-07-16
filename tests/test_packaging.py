"""Tests for editable-install metadata and bundled package data."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
import tomllib

import pytest

from bugslyce import __version__
from bugslyce.cli import main


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_defines_bugslyce_console_script() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["project"]["name"] == "bugslyce"
    assert pyproject["project"]["requires-python"] == ">=3.11"
    assert pyproject["project"]["scripts"]["bugslyce"] == "bugslyce.cli:main"
    assert callable(main)


def test_pyproject_includes_bundled_wordlist_package_data() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    package_data = pyproject["tool"]["setuptools"]["package-data"]["bugslyce"]
    assert "wordlists/*.txt" in package_data


def test_bundled_tiny_wordlist_is_accessible_through_package_resources() -> None:
    wordlist = (
        importlib.resources.files("bugslyce")
        .joinpath("wordlists")
        .joinpath("lab-root-tiny.txt")
    )

    assert wordlist.is_file()
    entries = wordlist.read_text(encoding="utf-8").splitlines()
    assert "robots.txt" in entries
    assert "admin" in entries


def test_cli_version_and_wizard_remain_available(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    version_output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert f"bugslyce {__version__}" in version_output.out

    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    help_output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "wizard" in help_output.out
