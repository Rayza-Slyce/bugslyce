"""Tests for lightweight terminal branding."""

from __future__ import annotations

from pathlib import Path

from bugslyce.branding import get_banner, get_short_brand_line


def test_banner_contains_required_branding() -> None:
    banner = get_banner()

    assert "|  ____              ____  _                     |" in banner
    assert r"| |____/ \__,_|\__, |____/|_|\__, |\___\___|     |" in banner
    assert "by Rayza Slyce" in banner
    assert "|                   BugSlyce                     |" not in banner
    assert "local-first recon triage" not in banner
    assert banner.startswith("+------------------------------------------------+")
    assert banner.endswith("+------------------------------------------------+")


def test_banner_remains_compact() -> None:
    banner = get_banner()

    assert len(banner) < 700
    assert len(banner.splitlines()) <= 12
    assert {len(line) for line in banner.splitlines()} == {50}


def test_short_brand_line_is_plain_and_single_line() -> None:
    line = get_short_brand_line()

    assert line == "BugSlyce by Rayza Slyce | local-first recon triage"
    assert "\n" not in line


def test_branding_adds_no_external_dependency() -> None:
    pyproject = (
        Path(__file__).resolve().parents[1] / "pyproject.toml"
    ).read_text(encoding="utf-8")

    for dependency in ("rich", "pyfiglet", "prompt_toolkit", "curses"):
        assert dependency not in pyproject
