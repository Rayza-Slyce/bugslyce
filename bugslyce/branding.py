"""Small, dependency-free terminal branding helpers."""

from __future__ import annotations


def get_banner() -> str:
    """Return the boxed BugSlyce guided-mode wordmark."""

    return "\n".join(
        [
            "+------------------------------------------------+",
            r"|  ____              ____  _                     |",
            r"| | __ ) _   _  __ _/ ___|| |_   _  ___ ___      |",
            r"| |  _ \| | | |/ _` \___ \| | | | |/ __/ _ \     |",
            r"| | |_) | |_| | (_| |___) | | |_| | (_|  __/     |",
            r"| |____/ \__,_|\__, |____/|_|\__, |\___\___|     |",
            r"|               |___/         |___/              |",
            r"|                                                |",
            r"|                by Rayza Slyce                  |",
            "+------------------------------------------------+",
        ]
    )


def get_short_brand_line() -> str:
    """Return a single-line BugSlyce brand label."""

    return "BugSlyce by Rayza Slyce | local-first recon triage"
