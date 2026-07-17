"""Lightweight documentation consistency checks."""

from __future__ import annotations

import re
from pathlib import Path
import tomllib

from bugslyce.doctor import REQUIRED_EXTERNAL_TOOLS
from bugslyce.recon.content_plan import (
    DEEP_BOUNDED_CORE_PROFILE,
    DEEP_BOUNDED_CORE_WORDLIST,
    STANDARD_BOUNDED_CORE_PROFILE,
    TINY_WORDLIST,
    STANDARD_BOUNDED_CORE_WORDLIST,
)
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
)


ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = (
    ROOT / "README.md",
    ROOT / "docs" / "INSTALLATION.md",
    ROOT / "docs" / "OPERATOR_GUIDE.md",
    ROOT / "docs" / "TROUBLESHOOTING.md",
    ROOT / "docs" / "RECON_MODES.md",
)


def test_required_documentation_files_exist() -> None:
    for path in DOC_FILES:
        assert path.is_file(), path


def test_readme_links_to_detailed_documentation() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for link in (
        "docs/INSTALLATION.md",
        "docs/OPERATOR_GUIDE.md",
        "docs/TROUBLESHOOTING.md",
        "docs/RECON_MODES.md",
        "docs/RELEASE_NOTES.md",
        "docs/RELEASE_ACCEPTANCE.md",
        "LICENSE",
    ):
        assert f"]({link})" in readme
        assert (ROOT / link).exists()


def test_markdown_relative_links_resolve() -> None:
    for path in DOC_FILES + (
        ROOT / "docs" / "RELEASE_NOTES.md",
        ROOT / "docs" / "RELEASE_CHECKLIST.md",
    ):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
            target = match.group(1)
            if "://" in target or target.startswith("#"):
                continue
            target_path = (path.parent / target).resolve()
            assert target_path.exists(), f"{path}: {target}"


def test_documented_python_minimum_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    minimum = pyproject["project"]["requires-python"].removeprefix(">=")
    combined = _combined_public_docs()

    assert minimum == "3.11"
    assert f"Python `{minimum}` or newer" in combined
    assert f"Minimum supported Python: {minimum}" in combined


def test_modes_profiles_tools_and_resources_are_documented() -> None:
    combined = _combined_public_docs()

    for expected in (
        "Manual Setup Only",
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
        QUICK_RECON_PROFILE,
        STANDARD_RECON_PROFILE,
        DEEP_RECON_PROFILE,
        "lab-root-tiny",
        STANDARD_BOUNDED_CORE_PROFILE,
        DEEP_BOUNDED_CORE_PROFILE,
        TINY_WORDLIST.name,
        STANDARD_BOUNDED_CORE_WORDLIST.name,
        DEEP_BOUNDED_CORE_WORDLIST.name,
    ):
        assert expected in combined

    for tool, _purpose, _workflows in REQUIRED_EXTERNAL_TOOLS:
        assert f"`{tool}`" in combined


def test_resume_and_evidence_handling_are_documented() -> None:
    operator = (ROOT / "docs" / "OPERATOR_GUIDE.md").read_text(encoding="utf-8")
    troubleshooting = (ROOT / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")
    combined = operator + "\n" + troubleshooting

    assert "bugslyce_project.json" in combined
    assert "not just the project directory" in combined
    assert "Partial Deep state fails closed" in combined
    assert "completed Deep resume is a verified no-op" in combined
    assert "evidence ZIP" in combined
    assert "not encrypted and is not redacted" in combined


def test_authorisation_boundary_is_documented() -> None:
    combined = _combined_public_docs().lower()

    assert "explicitly authorised" in combined
    assert "scope.md" in combined
    assert "not authorisation" in combined
    assert "does not claim confirmed vulnerabilities" in combined


def test_host_validation_wording_is_precise() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
    combined = readme + "\n" + installation
    compact = " ".join(combined.split())

    assert "validated on Kali Linux and Linux Mint" in readme
    assert "Kali Linux | Directly validated" in installation
    assert "Linux Mint | Directly validated" in installation
    assert "Ubuntu and other Debian-derived Linux systems" in installation
    assert "not currently part of the directly validated host set" in compact
    assert "Ubuntu" in combined
    assert "validated on Debian-derived systems such as Kali, Ubuntu and Linux Mint" not in combined
    assert "Native Windows and macOS operation is not currently claimed" in compact


def test_public_docs_do_not_contain_internal_or_stale_terms() -> None:
    combined = _combined_public_docs()

    for forbidden in (
        "93" + "D",
        "94" + "A",
        "94" + "B",
        "W" + "gel",
        "10.81.148" + ".200",
        "Co" + "dex",
        "Ja" + "mie",
        "Operation " + "Blackout",
        "Deep Recon remains unavailable",
        "planned future modes",
    ):
        assert forbidden not in combined


def test_command_examples_use_recognised_commands() -> None:
    recognised_top = {
        "run",
        "wizard",
        "doctor",
        "config",
        "project",
        "recon",
        "--help",
    }
    recognised_project = {
        "init",
        "scaffold",
        "list",
        "runbook",
        "run",
        "show",
        "status",
        "next",
    }
    recognised_recon = {
        "--help",
        "export",
        "status",
    }

    for command in _documented_bugslyce_commands():
        parts = command.split()
        assert parts[0] == "bugslyce"
        if len(parts) == 1:
            continue
        assert parts[1] in recognised_top, command
        if parts[1] == "project" and len(parts) > 2:
            assert parts[2] in recognised_project, command
        if parts[1] == "recon" and len(parts) > 2:
            assert parts[2] in recognised_recon, command


def _combined_public_docs() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in DOC_FILES)


def _documented_bugslyce_commands() -> tuple[str, ...]:
    commands: list[str] = []
    for path in DOC_FILES:
        in_fence = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("```"):
                in_fence = not in_fence
                continue
            stripped = line.strip()
            if in_fence and (stripped == "bugslyce" or stripped.startswith("bugslyce ")):
                commands.append(stripped.rstrip("\\"))
    return tuple(commands)
