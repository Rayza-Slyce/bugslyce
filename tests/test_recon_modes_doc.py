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
        "`deep-bounded`",
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
        "Standard Recon v1 is now available",
        "does not fetch extra pages",
        "Deep Recon remains unavailable",
        "Deep Recon v1 design contract",
        "aggressive evidence discovery inside strict authorisation, scope, method, and rate limits",
        "genuine step up from Standard",
        "expanded bounded collection",
        "bounded second-pass content discovery",
        "shallow same-origin crawl",
        "same-origin JavaScript/source file collection as text only",
        "static route extraction",
        "static parameter inventory",
        "HTML form inventory without submitting forms",
        "source map detection",
        "deeper correlation",
        "must not increase attack behaviour",
        "Brute forcing live services",
        "Password spraying",
        "Credential stuffing",
        "Authentication testing",
        "Form submission",
        "Browser automation that interacts with applications",
        "JavaScript execution",
        "`sqlmap`",
        "`hydra`",
        "`masscan`",
        "Deep Recon must remain unavailable until all of these gates exist",
        "Tests proving Quick remains unchanged",
        "Tests proving Standard remains unchanged",
        "Tests proving Deep has explicit bounds",
        "Tests proving Deep unavailable state is intentional until enabled",
        "Code-level planned profile contract and explicit bounds model",
        "code-level planned-pipeline skeleton",
        "static contract data only",
        "does not make `deep-bounded` executable",
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
