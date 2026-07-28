"""Authoritative BugSlyce built-in HTTP User-Agent identity."""

from bugslyce import __version__


R0B_NON_CENTRAL_USER_AGENT_CALL_SITES = (
    "bugslyce.recon.deep_http_fetcher.USER_AGENT",
)


def built_in_user_agent() -> str:
    """Return the versioned built-in identity for future HTTP integrations."""

    return f"BugSlyce/{__version__} authorised-recon"
