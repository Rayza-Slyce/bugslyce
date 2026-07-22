"""Public documentation readiness checks."""

from __future__ import annotations

from pathlib import Path

def test_readme_documents_mvp_workflow_outputs_and_safety() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    lowered = readme.lower()

    for command in (
        "bugslyce",
        "bugslyce doctor",
        "bugslyce --help",
    ):
        assert command in readme

    assert "[![Tests]" in readme
    assert "actions/workflows/tests.yml" in readme
    assert "## What BugSlyce Provides" in readme
    assert "## Operator Modes" in readme
    assert "lab-safe-tiny" in readme
    assert "standard-bounded" in readme
    assert "deep-bounded" in readme

    assert "python3 -m venv .venv" in readme
    assert "python -m pip install ." in readme
    assert "## Licence" in readme
    assert "## License" not in readme

    for term in (
        "quick recon",
        "standard recon",
        "deep recon",
        "manual setup only",
        "evidence pack",
        "mit licence",
        "authorised",
        "does not claim confirmed vulnerabilities",
        "partial deep network state fails closed",
    ):
        assert term in lowered

    assert "Deep Recon remains unavailable" not in readme
    assert "v1.0.0 has already been released" not in readme
    assert 'alias bugslyce="$HOME/projects/bugslyce/.venv/bin/bugslyce"' not in readme


def test_readme_has_release_checkpoint_and_honest_limitations() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    compact = " ".join(readme.split())

    assert "Current package version: `1.0.0`" in readme
    assert "prepared for final release" in compact
    assert "has not yet been tagged or published" in compact
    assert "validated on Kali Linux and Linux Mint" in readme
    assert "not currently part of the directly validated host set" in compact
    assert "validated on Debian-derived systems such as Kali, Ubuntu and Linux Mint" not in readme
    assert "Standard Recon | `standard-bounded`" in readme
    assert "Deep Recon | `deep-bounded`" in readme
    assert "interactive resume preview is read-only" in readme.lower()
    assert "not proof that a vulnerability exists" in compact


def test_demo_walkthrough_documents_authorised_mvp_flow() -> None:
    root = Path(__file__).resolve().parents[1]
    walkthrough_path = root / "docs" / "DEMO_WALKTHROUGH.md"
    assert walkthrough_path.is_file()

    walkthrough = walkthrough_path.read_text(encoding="utf-8")
    lowered = walkthrough.lower()
    for expected in (
        "bugslyce",
        "bugslyce doctor",
        "bugslyce project scaffold",
        "bugslyce project run",
        "lab-safe-tiny",
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
        "Manual Setup Only",
        "--resume",
        "report.md",
    ):
        assert expected in walkthrough

    assert "brute force" in lowered
    assert "exploitation" in lowered
    assert "authorised lab-style target" in lowered
    assert "example target `target.example.test` is a documentation placeholder" in lowered

    assert "10.10.10.10" not in walkthrough


def test_release_checklist_documents_current_release_gate() -> None:
    root = Path(__file__).resolve().parents[1]
    checklist_path = root / "docs" / "RELEASE_CHECKLIST.md"
    assert checklist_path.is_file()

    checklist = checklist_path.read_text(encoding="utf-8")
    compact = " ".join(checklist.split())
    compact_lower = compact.lower()
    lowered = checklist.lower()
    for expected in (
        "1.0.0",
        "lab-safe-tiny",
        "standard-bounded",
        "deep-bounded",
        "Deep Recon",
        "bugslyce doctor",
        "Documentation tests pass",
        "Full suite passes",
    ):
        assert expected in compact

    assert "brute force" in lowered
    assert "exploitation" in lowered
    assert "does not create a git tag" in compact_lower
    assert "Historical rc2 release-candidate acceptance" in checklist

    assert "Deep Recon remains unavailable" not in checklist
    assert "git tag v0.3.0" not in checklist


def test_release_notes_document_current_scope() -> None:
    root = Path(__file__).resolve().parents[1]
    notes_path = root / "docs" / "RELEASE_NOTES.md"
    assert notes_path.is_file()

    notes = notes_path.read_text(encoding="utf-8")
    compact = " ".join(notes.split())
    for expected in (
        "1.0.0",
        "Manual Setup Only",
        "Quick Recon using `lab-safe-tiny`",
        "Standard Recon using `standard-bounded`",
        "Deep Recon using `deep-bounded`",
        "technical acceptance is complete",
        "has not yet created the final tag, GitHub release or PyPI publication",
    ):
        assert expected in compact

    assert "Deep Recon remains unavailable" not in notes


def test_public_repo_security_and_ci_docs_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    security_path = root / "SECURITY.md"
    workflow_path = root / ".github" / "workflows" / "tests.yml"

    assert security_path.is_file()
    assert workflow_path.is_file()

    security = security_path.read_text(encoding="utf-8")
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "# Security Policy" in security
    assert "Reporting a Vulnerability" in security
    assert "authorised testing" in security
    assert "private bug bounty programme data" in security

    assert "name: Tests" in workflow
    assert "python-version: \"3.12\"" in workflow
    assert 'python -m pip install -e ".[dev]"' in workflow
    assert "pytest" in workflow
