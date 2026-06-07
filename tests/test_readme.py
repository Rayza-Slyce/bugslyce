"""README release-readiness checks."""

from __future__ import annotations

from pathlib import Path


def test_readme_contains_mvp_workflow_and_candidate_language() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

    assert "does not gather recon itself yet" in readme
    assert "candidates are manual review leads" in readme.lower()
    assert "Priority means manual attention priority" in readme
    assert "Automated recon is planned later" in readme
    assert "## Recon Plan Mode" in readme
    assert "It does not execute nmap, curl, gobuster, ffuf" in readme
    assert "`lab-full`" in readme
    assert "`bug-bounty-standard`" in readme
    assert "`passive-only`" in readme
    assert "`recon_manifest.json` remains the bridge" in readme
    assert "### Recon Execution Dry Run" in readme
    assert "bugslyce recon execute" in readme
    assert "It does not run commands." in readme
    assert "Live recon execution is not implemented yet" in readme
    assert "### Recon Safety Preflight" in readme
    assert "bugslyce recon preflight" in readme
    assert "Expected local tool availability using PATH lookup only" in readme
    assert "Preflight does not run commands or contact targets" in readme
    assert "required safety layer" in readme
    assert "### Passive-only Execution" in readme
    assert "--passive-only" in readme
    assert "--input-dir" in readme
    assert "`recon_execution.json`" in readme
    assert "does not run network commands or execute command-preview strings" in readme
