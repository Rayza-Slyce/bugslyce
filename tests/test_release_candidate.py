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
    DEEP_BOUNDED_CORE_PROFILE,
    DEEP_BOUNDED_CORE_WORDLIST,
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
FINAL_VERSION = "1.0.0"
RC2_VERSION = "1.0.0rc2"
PREVIOUS_RC_VERSION = "1.0.0rc1"
RC2_WHEEL_FILENAME = "bugslyce-1.0.0rc2-py3-none-any.whl"
RC2_WHEEL_SHA256 = "24ecc358ed6b4e3db9213e7142637fade953b30744fb11fa613c050f1ae6a441"
RC2_WORDLIST_FILES = (
    "lab-root-tiny.txt",
    "standard-auth-core.txt",
    "standard-bounded-core.txt",
    "deep-bounded-core.txt",
)


def test_current_checkout_uses_final_v1_version() -> None:
    readme = _read("README.md")
    notes = _read("docs/RELEASE_NOTES.md")

    assert _pyproject()["project"]["version"] == FINAL_VERSION
    assert bugslyce.__version__ == FINAL_VERSION
    assert f"Current package version: `{FINAL_VERSION}`" in readme
    assert f"## {FINAL_VERSION}" in notes


def test_package_metadata_version_is_final_v1() -> None:
    pyproject = _pyproject()

    assert pyproject["project"]["version"] == FINAL_VERSION


def test_runtime_version_is_final_v1() -> None:
    assert bugslyce.__version__ == FINAL_VERSION


def test_package_metadata_and_runtime_version_agree() -> None:
    assert _pyproject()["project"]["version"] == bugslyce.__version__


def test_cli_version_prints_final_v1(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert captured.out.strip() == f"bugslyce {FINAL_VERSION}"


def test_readme_states_final_version_prepared_but_not_published() -> None:
    readme = _read("README.md")
    compact = " ".join(readme.split())

    assert f"Current package version: `{FINAL_VERSION}`" in readme
    assert "prepared for final release" in compact
    assert "has not yet been tagged or published" in compact


def test_release_notes_have_current_final_v1_section() -> None:
    notes = _read("docs/RELEASE_NOTES.md")

    assert f"## {FINAL_VERSION}" in notes
    assert "Manual Setup Only" in notes
    assert "same-origin" in notes
    assert "Known Limitations" in notes


def test_release_documents_record_completed_acceptance_state() -> None:
    notes = _read("docs/RELEASE_NOTES.md")
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")
    combined = "\n".join((notes, checklist, acceptance))

    assert "Historical rc2 release-candidate acceptance" in checklist
    assert "2026-07-16" in acceptance
    assert "e4c8fba" in combined
    for workflow in ("Manual Setup Only", "Quick", "Standard", "Deep"):
        assert workflow in acceptance
        assert f"{workflow} | passed" in acceptance
    assert "Completed Deep no-op resume | passed" in acceptance
    assert "Canonical Deep hash stability | passed" in acceptance
    assert "Evidence-pack review | passed" in acceptance
    assert "authorised private lab/CTF target, identifier withheld" in acceptance
    assert "The `v1.0.0rc1` tag was subsequently created." in combined
    assert "No package was published" in combined
    assert "not final `1.0.0`" in combined


def test_release_checklist_records_exact_rc2_pipx_acceptance() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")

    assert "pending exact-wheel pipx acceptance" not in checklist
    assert RC2_WHEEL_FILENAME in checklist
    assert RC2_WHEEL_SHA256 in checklist
    assert "Mint temporary pipx acceptance: completed" in checklist
    assert "Kali temporary pipx acceptance: completed" in checklist
    assert "pipx 1.4.3" in checklist
    assert "pipx 1.8.0" in checklist
    assert "Python 3.13.11" in checklist
    assert "Doctor exit `2` was caused by missing `gobuster`" in checklist
    for wordlist in RC2_WORDLIST_FILES:
        assert wordlist in checklist


def test_final_release_documents_preserve_historical_rc2_evidence() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    notes = _read("docs/RELEASE_NOTES.md")

    assert "Historical rc2 release-candidate acceptance" in checklist
    assert "113494f3c727c4543ca87e9be37b64c8c1858dbe" in checklist
    assert RC2_VERSION in notes
    assert RC2_WHEEL_FILENAME in checklist
    assert RC2_WHEEL_SHA256 in checklist
    assert "Mint temporary pipx acceptance: completed" in checklist
    assert "Kali temporary pipx acceptance: completed" in checklist


def test_final_release_checklist_keeps_publication_pending() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")

    assert "Current 1.0.0 finalisation checks" in checklist
    for completed in (
        "- [x] Final version alignment in the working tree.",
        "- [x] Final checkout wheel and source-distribution build.",
        "- [x] Source-distribution wheel rebuild.",
        "- [x] Local temporary-venv installation and semantic wheel comparison.",
        "- [x] All four runtime resources verified from the final wheel.",
    ):
        assert completed in checklist
    for pending in (
        "Review and commit the finalisation change.",
        "Push the committed finalisation state.",
        "Pull and verify the committed finalisation state on Kali.",
        "Final clean build from the committed release state.",
        "Exact final-wheel temporary pipx acceptance on Mint.",
        "Exact same final-wheel temporary pipx acceptance on Kali.",
        "Final `v1.0.0` tag.",
        "GitHub release.",
        "PyPI publication.",
    ):
        assert pending in checklist
    assert "final v1 publication remains pending" in checklist


def test_final_package_filename_contract() -> None:
    distribution_name = _pyproject()["project"]["name"]

    assert distribution_name == "bugslyce"
    assert f"{distribution_name}-{FINAL_VERSION}-py3-none-any.whl" == (
        "bugslyce-1.0.0-py3-none-any.whl"
    )
    assert f"{distribution_name}-{FINAL_VERSION}.tar.gz" == "bugslyce-1.0.0.tar.gz"


def test_release_documents_distinguish_current_final_state_and_history() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")

    assert "Historical rc1 acceptance" in checklist
    assert "Historical rc2 release-candidate acceptance" in checklist
    assert "Current 1.0.0 finalisation checks" in checklist
    assert "Still pending for final publication" in checklist
    for pending in (
        "Review and commit the finalisation change.",
        "Push the committed finalisation state.",
        "Pull and verify the committed finalisation state on Kali.",
        "Final clean build from the committed release state.",
        "Exact final-wheel temporary pipx acceptance on Mint.",
        "Exact same final-wheel temporary pipx acceptance on Kali.",
        "Final `v1.0.0` tag.",
        "GitHub release.",
        "PyPI publication.",
    ):
        assert pending in checklist
    assert "completed public record below documents the earlier `1.0.0rc1` acceptance" in acceptance


def test_release_acceptance_documents_exact_wheel_pipx_contract() -> None:
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")

    assert "all four files must exist and be non-empty" in acceptance.lower()
    assert "exact-wheel SHA-256 equality between Mint and Kali" in acceptance
    assert "outside the source checkout" in acceptance
    assert "installed distribution version" in acceptance
    assert "missing external tooling" in acceptance
    assert "pipx bootstrap network" in acceptance
    assert "BugSlyce target contact" in acceptance
    assert "installed with `--no-deps`" in acceptance
    for wordlist in RC2_WORDLIST_FILES:
        assert wordlist in acceptance


def test_release_documents_preserve_rc1_wordlist_history() -> None:
    notes = _read("docs/RELEASE_NOTES.md")
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")
    rc1_notes = notes.split("## 1.0.0rc1", 1)[1]

    assert "Since `1.0.0rc1`, Deep" in notes
    assert "tagged `1.0.0rc1` release candidate used" in notes
    assert "`standard-bounded-core` for both" in notes
    assert "Standard and Deep" in notes
    assert "`deep-bounded-core` gates" not in rc1_notes
    assert "standard-bounded-core` gates Standard and Deep Recon" in rc1_notes
    assert "deep-bounded-core.txt" in checklist
    assert "deep-bounded-core.txt" in acceptance


def test_completed_public_acceptance_record_preserves_privacy() -> None:
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")
    public_record = acceptance.split("## Part 1:", 1)[0]

    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", public_record)
    for forbidden in (
        "/" + "home/",
        "W" + "gel",
        "Co" + "dex",
        "Ja" + "mie",
        "95" + "B",
        "95" + "C",
    ):
        assert forbidden not in public_record
    assert "e4c8fba" in public_record
    assert "deep_source_route_collection.md" not in public_record


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
    for wordlist in (TINY_WORDLIST, STANDARD_BOUNDED_CORE_WORDLIST, DEEP_BOUNDED_CORE_WORDLIST):
        assert wordlist.is_file()
        assert wordlist.read_text(encoding="utf-8").strip()
        installed = resource_dir.joinpath(wordlist.name)
        assert installed.is_file()
        assert installed.read_text(encoding="utf-8").strip()
    assert STANDARD_BOUNDED_CORE_PROFILE in _read("docs/INSTALLATION.md")
    assert DEEP_BOUNDED_CORE_PROFILE in _read("docs/INSTALLATION.md")


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
    assert "published to " + "PyPI" not in combined
    assert "GitHub release " + "created" not in combined


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")
