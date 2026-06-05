"""README release-readiness checks."""

from __future__ import annotations

from pathlib import Path


def test_readme_contains_mvp_workflow_and_candidate_language() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

    assert "does not gather recon itself yet" in readme
    assert "candidates are manual review leads" in readme.lower()
    assert "Priority means manual attention priority" in readme
    assert "Automated recon is planned later" in readme
