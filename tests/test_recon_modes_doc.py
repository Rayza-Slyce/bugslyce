"""Recon mode documentation contract checks."""

from __future__ import annotations

from pathlib import Path


def test_recon_modes_design_contract_exists_and_covers_required_terms() -> None:
    path = Path(__file__).resolve().parents[1] / "docs" / "RECON_MODES.md"
    assert path.is_file()

    content = path.read_text(encoding="utf-8")
    lowered = content.lower()

    for expected in (
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
        "`lab-safe-tiny`",
        "`standard-bounded`",
        "`deep-correlation`",
        "authorisation",
        "strict scope",
        "Global Forbidden Behaviours",
        "Vulnerability Intelligence Later",
        "Optional LLM Review Later",
        "unsupported vulnerability claims",
        "CTF/lab",
        "Local Evidence Mode",
        "hash-looking artefact",
        "encoding",
        "robots.txt",
        "Hidden HTML",
        "evidence chain",
        "Bounded nested discovery",
        "Cron Misconfiguration",
        "Standard Recon v1",
        "Manual Review Leads",
        "already-collected evidence",
        "ArtefactSource",
        "offline interpretation collector",
        "does not increase scan volume",
        "does not mean bigger wordlists",
        "does not mean recursive crawling",
        "not proof of vulnerability",
        "planned and still unavailable",
    ):
        assert expected.lower() in lowered

    for forbidden_boundary in (
        "Do not add `shell=True`",
        "Do not add `subprocess.Popen`",
        "Do not add `os.system`",
        "Do not add `pexpect`",
        "Do not add arbitrary command execution",
    ):
        assert forbidden_boundary in content
