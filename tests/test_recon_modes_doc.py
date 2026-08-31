"""Recon mode documentation contract checks."""

from __future__ import annotations

from pathlib import Path

from bugslyce.recon.modes import (
    DEEP_RECON_PROFILE,
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
)


def test_recon_modes_doc_matches_current_public_modes() -> None:
    path = Path(__file__).resolve().parents[1] / "docs" / "RECON_MODES.md"
    content = path.read_text(encoding="utf-8")
    lowered = content.lower()

    for expected in (
        "Manual Setup Only",
        "Reconnaissance",
        f"`{QUICK_RECON_PROFILE}`",
        f"`{STANDARD_RECON_PROFILE}`",
        f"`{DEEP_RECON_PROFILE}`",
        "bundled `deep-bounded-core`",
        "`nmap`",
        "`curl`",
        "`gobuster`",
        "exact materialised-origin authority",
        "one bounded depth-one evidence-feedback pass",
        "no authentication testing or form submission",
        "no browser automation or JavaScript execution",
        "query names and query-bearing references may still be retained",
        "not proof of vulnerability",
        "cannot start or resume a new normal project execution",
    ):
        assert expected.lower() in lowered

    for stale in (
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
        "deep recon remains unavailable",
        "planned but not implemented",
        "non-executable",
        "phase 93",
    ):
        assert stale not in lowered
