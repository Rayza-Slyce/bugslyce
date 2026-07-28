"""Authoritative BugSlyce built-in HTTP User-Agent identity."""

from bugslyce import __version__


R0B2_POLICY_AWARE_EXTERNAL_BOUNDARIES = (
    "bugslyce.recon.external_enforcement.build_bug_bounty_curl_plan",
    "bugslyce.recon.external_enforcement.build_bug_bounty_gobuster_plan",
    "bugslyce.recon.external_enforcement.build_bug_bounty_nmap_plan",
)

# Existing context-neutral live runners remain authorised-lab interfaces. They
# are not reachable from a bug bounty project pipeline while the R0B3 block is
# active and must not be mistaken for policy-aware command boundaries.
R0B3_BLOCKED_LEGACY_LIVE_RUNNERS = (
    "bugslyce.recon.runner.LiveCurlHeaderRunner",
    "bugslyce.recon.runner.LiveHTTPMetadataRunner",
    "bugslyce.recon.runner.LivePathFollowupRunner",
    "bugslyce.recon.runner.LiveContentFollowupRunner",
    "bugslyce.recon.runner.LiveBodyFetchRunner",
    "bugslyce.recon.runner.LiveContentDiscoveryRunner",
    "bugslyce.recon.runner.LiveNmapDiscoveryRunner",
    "bugslyce.recon.runner.LiveNmapServiceRunner",
)

# Retained as a compatibility audit surface: no Python HTTP path remains outside
# the central executor after R0B1.
R0B_NON_CENTRAL_USER_AGENT_CALL_SITES: tuple[str, ...] = ()


def built_in_user_agent() -> str:
    """Return the versioned built-in identity for future HTTP integrations."""

    return f"BugSlyce/{__version__} authorised-recon"
