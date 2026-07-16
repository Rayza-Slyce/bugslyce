"""Release-candidate metadata and acceptance-document checks."""

from __future__ import annotations

import importlib.resources
import re
from pathlib import Path
import tomllib

import pytest

import bugslyce
from bugslyce.cli import main
from bugslyce.recon.content_plan import (
    STANDARD_BOUNDED_CORE_PROFILE,
    STANDARD_BOUNDED_CORE_WORDLIST,
    TINY_WORDLIST,
)
from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
)


ROOT = Path(__file__).resolve().parents[1]
RC_VERSION = "1.0.0rc1"


def test_package_metadata_version_is_release_candidate() -> None:
    pyproject = _pyproject()

    assert pyproject["project"]["version"] == RC_VERSION


def test_runtime_version_is_release_candidate() -> None:
    assert bugslyce.__version__ == RC_VERSION


def test_package_metadata_and_runtime_version_agree() -> None:
    assert _pyproject()["project"]["version"] == bugslyce.__version__


def test_cli_version_prints_release_candidate(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert captured.out.strip() == f"bugslyce {RC_VERSION}"


def test_readme_states_release_candidate_version_not_final_release() -> None:
    readme = _read("README.md")
    compact = " ".join(readme.split())

    assert f"Current package version: `{RC_VERSION}`" in readme
    assert "first BugSlyce v1 release candidate" in compact
    assert "not the final `1.0.0` release" in compact


def test_release_notes_have_current_release_candidate_section() -> None:
    notes = _read("docs/RELEASE_NOTES.md")

    assert f"## {RC_VERSION}" in notes
    assert "Manual Setup Only" in notes
    assert "same-origin" in notes
    assert "Known Limitations" in notes


def test_release_checklist_references_all_executable_profiles() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")

    for profile in (QUICK_RECON_PROFILE, STANDARD_RECON_PROFILE, DEEP_RECON_PROFILE):
        assert profile in checklist


def test_release_acceptance_guide_exists_and_covers_all_modes() -> None:
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")

    for expected in (
        "Manual Setup Only",
        "Quick",
        "Standard",
        "Deep",
        QUICK_RECON_PROFILE,
        STANDARD_RECON_PROFILE,
        DEEP_RECON_PROFILE,
    ):
        assert expected in acceptance


def test_release_acceptance_documents_deep_hash_stability_and_partial_refusal() -> None:
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")
    compact = " ".join(acceptance.split())

    assert "sha256sum" in acceptance
    assert "identical canonical artefact hashes" in compact
    assert "Partial Deep state must fail closed" in acceptance


def test_release_acceptance_has_no_real_target_ip_or_internal_phase_terms() -> None:
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")

    assert "AUTHORISED_TARGET" in acceptance
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", acceptance)
    for forbidden in ("93" + "D", "94" + "A", "94" + "B", "95" + "A", "95" + "B"):
        assert forbidden not in acceptance


def test_directly_validated_hosts_and_ubuntu_boundary_are_documented() -> None:
    combined = _read("README.md") + "\n" + _read("docs/INSTALLATION.md")
    compact = " ".join(combined.split())

    assert "validated on Kali Linux and Linux Mint" in combined
    assert "Ubuntu and other Debian-derived Linux systems" in combined
    assert "not currently part of the directly validated host set" in compact
    assert "validated on Kali Linux, Ubuntu and Linux Mint" not in combined


def test_relative_markdown_links_resolve_in_release_documents() -> None:
    for path in (
        ROOT / "README.md",
        ROOT / "docs" / "RELEASE_NOTES.md",
        ROOT / "docs" / "RELEASE_CHECKLIST.md",
        ROOT / "docs" / "RELEASE_ACCEPTANCE.md",
    ):
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            assert (path.parent / target).resolve().exists(), f"{path}: {target}"


def test_required_bundled_wordlists_are_tracked_and_package_data_includes_them() -> None:
    pyproject = _pyproject()
    package_data = pyproject["tool"]["setuptools"]["package-data"]["bugslyce"]
    resource_dir = importlib.resources.files("bugslyce").joinpath("wordlists")

    assert "wordlists/*.txt" in package_data
    for wordlist in (TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST):
        assert wordlist.is_file()
        assert wordlist.read_text(encoding="utf-8").strip()
        installed = resource_dir.joinpath(wordlist.name)
        assert installed.is_file()
        assert installed.read_text(encoding="utf-8").strip()
    assert STANDARD_BOUNDED_CORE_PROFILE in _read("docs/INSTALLATION.md")


def test_release_documents_do_not_claim_pypi_publication() -> None:
    combined = "\n".join(
        _read(path)
        for path in (
            "README.md",
            "docs/INSTALLATION.md",
            "docs/RELEASE_NOTES.md",
            "docs/RELEASE_CHECKLIST.md",
            "docs/RELEASE_ACCEPTANCE.md",
        )
    )

    assert "pip install bugslyce" not in combined
    assert "published to PyPI" not in combined


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")
