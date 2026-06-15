"""README MVP release-readiness checks."""

from __future__ import annotations

from pathlib import Path


def test_readme_documents_mvp_workflow_outputs_and_safety() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    lowered = readme.lower()

    for command in (
        "bugslyce doctor",
        "bugslyce project scaffold",
        "bugslyce project run",
        "bugslyce project next",
        "bugslyce recon export",
    ):
        assert command in readme

    assert "lab-safe-tiny" in readme
    assert "--resume" in readme
    assert "report.md" in readme
    assert "evidence-pack.zip" in readme
    assert "manual validation" in lowered

    for boundary in (
        "No NSE scripts",
        "No UDP scans",
        "No brute force",
        "No exploitation",
        "No recursive discovery",
        "No form submission",
        "No authentication testing",
        "No LLM calls",
    ):
        assert boundary in readme


def test_readme_has_release_checkpoint_and_honest_limitations() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )

    assert "## Current MVP Limitations" in readme
    assert "## MVP Release Checkpoint" in readme
    assert "Current version: `0.1.0`" in readme
    assert "Release tag: not yet created" in readme
    assert "There is no vulnerability confirmation" in readme
    assert "does not replace human programme-scope review" in readme


def test_demo_walkthrough_documents_authorised_mvp_flow() -> None:
    root = Path(__file__).resolve().parents[1]
    walkthrough_path = root / "docs" / "DEMO_WALKTHROUGH.md"
    assert walkthrough_path.is_file()

    walkthrough = walkthrough_path.read_text(encoding="utf-8")
    lowered = walkthrough.lower()
    for expected in (
        "bugslyce doctor",
        "bugslyce project scaffold",
        "bugslyce project run",
        "lab-safe-tiny",
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
