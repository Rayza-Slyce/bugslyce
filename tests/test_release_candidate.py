"""Release-candidate metadata and acceptance-document checks."""

from __future__ import annotations

import importlib.resources
from hashlib import sha256
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
FINAL_VERSION = "1.3.0"
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
V1_WHEEL_FILENAME = "bugslyce-1.0.0-py3-none-any.whl"
FINAL_WHEEL_SHA256 = "e29346eda47bd37d166612bee775e231a48b79749696a1a66aaeb7e499860f63"
FINAL_BUILD_EVIDENCE_SHA256 = "7ef3d9ffd6385b70adf33a31935e3248f8ba70a3cbd917a62c5787256f7668c2"
FINAL_MINT_ACCEPTANCE_SHA256 = "40f487df5eb676b49e8509485be99e289067a0ae0bbb222d72bd60b822f68820"
FINAL_KALI_ACCEPTANCE_SHA256 = "23e68a4ca031dd7585118d6f93232a4658149f65c65d985a16106c69222013af"
V11_RELEASE_COMMIT = "a7f37b3235c27fad0d4f2f9ed2ccf29f4f86380c"
V11_WHEEL_FILENAME = "bugslyce-1.1.0-py3-none-any.whl"
V11_WHEEL_SHA256 = "8765dcfeeb9fa9f43de154f54d13049c46d7fa7c241cb8e9b759da620a1c6a87"
V11_SDIST_FILENAME = "bugslyce-1.1.0.tar.gz"
V11_SDIST_SHA256 = "bec36c61f618f5ed2a85e1b38b01bc515965495efc5d91354eb3bbe04849c477"
V13_RELEASE_SOURCE_COMMIT = "0030865d5d2346d7da6092d6b2338eb5ea6f8f01"
V13_SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH=1787825359"
V13_WHEEL_FILENAME = "bugslyce-1.3.0-py3-none-any.whl"
V13_WHEEL_SHA256 = "36e5f4e37a6530fa94090f9b19f490ed0f0b255f09b7e47b37f40a6fd0b129d1"
V13_PREFINAL_SDIST_SHA256 = "2cce445c931b932335c6d9e766a16f351387208b5d43f65e5af4a2c886210a0f"


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


def test_readme_states_current_release_preparation_and_install_path() -> None:
    readme = _read("README.md")
    compact = " ".join(readme.split())

    assert f"Current package version: `{FINAL_VERSION}`" in readme
    assert "BugSlyce v1.1.0 is prepared for review and release" not in compact
    assert "PyPI may continue to provide v1.0.0 until v1.1.0 is published" not in compact
    assert "BugSlyce v1.1.0 has already been published" not in compact
    assert "pipx install bugslyce" in readme
    assert "pipx upgrade bugslyce" in readme
    assert "bugslyce-interactive-menu.png" in readme
    assert "bugslyce-html-evidence-report.png" in readme


def test_release_notes_have_current_final_v1_section() -> None:
    notes = _read("docs/RELEASE_NOTES.md")
    compact = " ".join(notes.split())

    assert f"## {FINAL_VERSION}" in notes
    assert "authorised Blog and Skynet lab acceptance" in compact
    assert "secondary searchable technical evidence" in compact
    assert "standard SMB 139/445 TCP transport pair" in compact
    assert (
        "BugSlyce `1.1.0` adds a self-contained offline HTML evidence report "
        "and improves presentation of existing deterministic evidence and review models."
    ) in compact
    assert "prepared for review and release" not in compact
    assert "not been tagged or published" not in compact
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


def test_release_checklist_preserves_v1_acceptance_and_records_v11_publication() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    compact_checklist = " ".join(checklist.split())
    compact_notes = " ".join(_read("docs/RELEASE_NOTES.md").split())

    assert "Historical 1.0.0 final technical acceptance" in checklist
    for completed in (
        "Accepted source commit: `32bfd20f78cda81e22241bb73836038defac0504`.",
        "Full suite: `1,983 passed`",
        "Technical GO: GO to tag and publish.",
    ):
        assert completed in checklist
    assert "### 1.1.0 release record" in checklist
    for released in (
        f"Accepted release commit: `{V11_RELEASE_COMMIT}`.",
        "Annotated tag: `v1.1.0`, created and pushed to GitHub.",
        "GitHub release published:",
        "https://github.com/Rayza-Slyce/bugslyce/releases/tag/v1.1.0",
        V11_WHEEL_FILENAME,
        V11_WHEEL_SHA256,
        V11_SDIST_FILENAME,
        V11_SDIST_SHA256,
        "Kali pipx upgraded BugSlyce from `1.0.0` to `1.1.0` successfully.",
        "permanently attached to release commit",
        "not part of the tagged release artefacts",
    ):
        assert released in compact_checklist
    assert "tagging and publication remain pending" not in compact_checklist
    for value in (
        "32bfd20f78cda81e22241bb73836038defac0504",
        V1_WHEEL_FILENAME,
        FINAL_WHEEL_SHA256,
        FINAL_BUILD_EVIDENCE_SHA256,
        FINAL_MINT_ACCEPTANCE_SHA256,
        FINAL_KALI_ACCEPTANCE_SHA256,
        "pipx 1.4.3",
        "Python 3.12.3",
        "pipx 1.8.0",
        "Python 3.13.11",
        "1,983 passed",
        "Technical GO: GO to tag and publish.",
        "SOURCE_DATE_EPOCH=1784728149",
    ):
        assert value in checklist
    assert "Mint final-wheel temporary pipx acceptance: completed" in checklist
    assert "Kali same-wheel temporary pipx acceptance: completed" in checklist
    assert "Doctor exit `2`" in checklist
    assert "occurred because Gobuster was absent" in checklist
    assert "doctor exit `0`" in checklist
    assert "exact same wheel was accepted through isolated temporary pipx acceptance on Mint and Kali" in compact_notes
    assert "approved to tag and publish" in compact_notes
    assert "PyPI publication: completed." in checklist
    assert "Focused documentation/release tests: `42 passed`" in compact_checklist
    assert "affected release, packaging, CLI, HTML and report tests: `311 passed`" in compact_checklist
    assert "full suite: `2,015 passed`" in compact_checklist


def test_final_package_filename_contract() -> None:
    distribution_name = _pyproject()["project"]["name"]

    assert distribution_name == "bugslyce"
    assert f"{distribution_name}-{FINAL_VERSION}-py3-none-any.whl" == (
        "bugslyce-1.3.0-py3-none-any.whl"
    )
    assert f"{distribution_name}-{FINAL_VERSION}.tar.gz" == "bugslyce-1.3.0.tar.gz"


def test_release_documents_distinguish_current_final_state_and_history() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    acceptance = _read("docs/RELEASE_ACCEPTANCE.md")

    assert "Historical rc1 acceptance" in checklist
    assert "Historical rc2 release-candidate acceptance" in checklist
    assert "Historical 1.0.0 final technical acceptance" in checklist
    assert "Historical `1.2.1` release acceptance" in checklist
    assert "Still required for `1.3.0`" in checklist
    assert "annotated tag `v1.3.0`" in checklist
    assert "1.1.0 release record" in checklist
    assert "1.1.0 actions still pending" not in checklist
    assert "tagging and publication remain pending" not in " ".join(checklist.split())
    assert "completed public record below documents the earlier `1.0.0rc1` acceptance" in acceptance


def test_v13_release_record_freezes_accepted_technical_evidence_and_pending_publication() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md").split(
        "## Historical `1.2.1` release acceptance", 1
    )[0]
    notes = _read("docs/RELEASE_NOTES.md").split("## 1.2.1", 1)[0]
    compact_checklist = " ".join(checklist.split())
    compact_notes = " ".join(notes.split())

    for accepted in (
        V13_RELEASE_SOURCE_COMMIT,
        V13_SOURCE_DATE_EPOCH,
        V13_WHEEL_FILENAME,
        V13_WHEEL_SHA256,
        V13_PREFINAL_SDIST_SHA256,
        "Full Mint regression suite passed: `4,270 passed`",
        "Both hosts verified the exact wheel SHA-256 shown above byte-for-byte",
        "Technical decision: **GO to tag and publish.**",
    ):
        assert accepted in checklist
    assert "not the final publication source distribution" in compact_checklist
    for pending in (
        "Confirm a fixed-epoch rebuild of that checkout reproduces the exact accepted wheel SHA-256",
        "Build the fresh final source distribution from the final release-record commit",
        "Create and push annotated tag `v1.3.0`",
        "Publish the GitHub `v1.3.0` release",
        "Publish to PyPI and verify the public `1.3.0` package",
    ):
        assert f"- [ ] {pending}" in compact_checklist
    assert "Technical acceptance is complete" in compact_notes
    assert "exact same `1.3.0` wheel was accepted on Mint and Kali" in compact_notes
    assert "`v1.3.0` tag, GitHub release and PyPI publication are still pending" in compact_notes


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


def test_release_checklist_records_the_approved_lab_screenshot_exception() -> None:
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    compact = " ".join(checklist.split())
    screenshot = ROOT / "docs" / "images" / "bugslyce-html-evidence-report.png"

    assert "No generated target evidence is tracked." not in checklist
    for expected in (
        "No raw or private evidence pack is tracked.",
        "No generated HTML evidence report is tracked.",
        "No unapproved target artefact is tracked.",
        "No private credentials, secrets or private engagement material is tracked.",
        "docs/images/bugslyce-html-evidence-report.png",
        "approved authorised-lab screenshot",
        "6ca7366d4faaedba817248727107693e12b3917555664bf86594022f1673957c",
    ):
        assert expected in compact
    assert sha256(screenshot.read_bytes()).hexdigest() in compact
    release_files = "\n".join(
        _read(path)
        for path in (
            "docs/RELEASE_NOTES.md",
            "docs/RELEASE_CHECKLIST.md",
            "docs/RELEASE_ACCEPTANCE.md",
        )
    )
    assert "bugslyce-v11-recruitx-baseline" not in release_files
    assert "recruitx-1.1.0.html" not in release_files


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
