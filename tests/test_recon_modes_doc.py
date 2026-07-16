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
        "Quick Recon",
        "Standard Recon",
        "Deep Recon",
        f"`{QUICK_RECON_PROFILE}`",
        f"`{STANDARD_RECON_PROFILE}`",
        f"`{DEEP_RECON_PROFILE}`",
        "bundled `lab-root-tiny`",
        "bundled `standard-bounded-core`",
        "`nmap`",
        "`curl`",
        "`gobuster`",
        "same-origin",
        "no form submission",
        "no JavaScript execution",
        "no parameter replay, guessing or mutation",
        "not proof of vulnerability",
        "Interrupted Deep network stages fail closed",
        "completed Deep resume is a no-op",
    ):
        assert expected.lower() in lowered

    for stale in (
        "deep recon remains unavailable",
        "planned but not implemented",
        "non-executable",
        "phase 93",
    ):
        assert stale not in lowered
