"""README MVP release-readiness checks."""

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
        "bugslyce project scaffold",
        "bugslyce project run",
        "bugslyce project next",
        "bugslyce recon export",
    ):
        assert command in readme

    assert "[![Tests]" in readme
    assert "actions/workflows/tests.yml" in readme
    assert "## Why BugSlyce?" in readme
    assert "## What It Looks Like" in readme
    assert "lab-safe-tiny" in readme

    assert "pipx install git+https://github.com/Rayza-Slyce/bugslyce.git" in readme
    assert "python3 -m venv .venv" in readme
    assert "python -m pip install -e" in readme
    assert ".[dev]" in readme

    for term in (
        "quick recon",
        "manual setup only",
        "operator summary",
        "evidence pack",
        "security policy",
        "mit licence",
        "authorised",
        "no exploitation",
        "no brute force",
        "no arbitrary",
        "no llm",
    ):
        assert term in lowered

    assert "BugSlyce is not published to PyPI" not in readme


def test_readme_has_release_checkpoint_and_honest_limitations() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )

    assert "## Current MVP Limitations" in readme
    assert "## MVP Release Checkpoint" in readme
    assert "Current version: `0.1.0`" in readme
    assert "Release tag: `v0.1.0`" in readme
    assert "There is no vulnerability confirmation" in readme
    assert "does not replace human programme-scope review" in readme


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
    assert "example target `10.10.10.10` is a placeholder" in lowered

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "docs/DEMO_WALKTHROUGH.md" in readme


def test_release_checklist_documents_v010_release_gate() -> None:
    root = Path(__file__).resolve().parents[1]
    checklist_path = root / "docs" / "RELEASE_CHECKLIST.md"
    assert checklist_path.is_file()

    checklist = checklist_path.read_text(encoding="utf-8")
    lowered = checklist.lower()
    for expected in (
        "v0.1.0",
        ".venv/bin/pytest",
        "bugslyce doctor",
        "lab-safe-tiny",
        "--resume",
        "git tag v0.1.0",
    ):
        assert expected in checklist

    assert "brute force" in lowered
    assert "exploitation" in lowered
    assert "private evidence" in lowered
    assert "no zip evidence packs are staged" in lowered

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "docs/RELEASE_CHECKLIST.md" in readme


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
