"""Kill-switch helpers for deterministic triage leads."""

from __future__ import annotations

from bugslyce.core.models import Asset, Endpoint


STATIC_LOW_SIGNAL_GUIDANCE = (
    "Do not spend time here unless new evidence links this static asset to sensitive functionality."
)
UNKNOWN_SCOPE_GUIDANCE = "Review programme scope before testing this host further."
OUT_OF_SCOPE_GUIDANCE = "Review programme scope before testing this host further."
LOW_SIGNAL_GUIDANCE = "Treat this as low signal unless manual recon adds stronger context."
VALIDATION_GUIDANCE = "Do not treat this as a finding without manual validation."


def asset_kill_switch_guidance(asset: Asset | None) -> str | None:
    """Return practical guidance for assets that need scope or signal caution."""

    if asset is None:
        return UNKNOWN_SCOPE_GUIDANCE
    if asset.in_scope is False:
        return OUT_OF_SCOPE_GUIDANCE
    if asset.in_scope is None:
        return UNKNOWN_SCOPE_GUIDANCE
    if "static_or_cdn" in asset.tags and len(asset.tags) == 1:
        return STATIC_LOW_SIGNAL_GUIDANCE
    return None


def endpoint_kill_switch_guidance(endpoint: Endpoint, asset: Asset | None) -> str | None:
    """Return practical guidance for endpoints that need scope or signal caution."""

    scope_guidance = asset_kill_switch_guidance(asset)
    if scope_guidance:
        return scope_guidance
    if "static_asset" in endpoint.tags and len(endpoint.tags) == 1:
        return STATIC_LOW_SIGNAL_GUIDANCE
    if not endpoint.tags:
        return LOW_SIGNAL_GUIDANCE
    return VALIDATION_GUIDANCE


def should_force_kill_switch(asset: Asset | None, endpoint: Endpoint | None = None) -> bool:
    """Return true when scope state or low-signal static context should stop promotion."""

    if asset is None or asset.in_scope is not True:
        return True
    if endpoint and "static_asset" in endpoint.tags and len(endpoint.tags) == 1:
        return True
    return False
