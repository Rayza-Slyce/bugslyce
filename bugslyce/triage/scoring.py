"""Explainable deterministic priority helpers for manual review leads."""

from __future__ import annotations

from bugslyce.core.models import Asset, Endpoint, HTTPService
from bugslyce.triage.killswitch import should_force_kill_switch


def priority_for_endpoint(endpoint: Endpoint, asset: Asset | None, candidate_type: str) -> str:
    """Map endpoint tags to a cautious manual-review priority."""

    if should_force_kill_switch(asset, endpoint):
        return "kill_switch"

    score = 0
    if candidate_type in {"auth_surface", "admin_surface", "api_surface"}:
        score += 2
    if candidate_type in {"object_reference_review", "file_or_content_surface"}:
        score += 2
    if candidate_type == "redirect_parameter_review":
        score += 1
    if "static_asset" in endpoint.tags:
        score -= 3

    return priority_from_score(score)


def priority_for_asset(asset: Asset, candidate_type: str) -> str:
    """Map asset tags and scope state to a cautious manual-review priority."""

    if should_force_kill_switch(asset):
        return "kill_switch"

    score = 0
    if candidate_type == "environment_surface":
        score += 2
    if "admin" in asset.tags or "api" in asset.tags:
        score += 1
    if "static_or_cdn" in asset.tags and len(asset.tags) == 1:
        score -= 3

    return priority_from_score(score)


def priority_for_service(service: HTTPService, asset: Asset | None) -> str:
    """Map service metadata context to a cautious manual-review priority."""

    if should_force_kill_switch(asset):
        return "kill_switch"

    score = 1 if service.technologies else 0
    if asset and any(tag in asset.tags for tag in ("admin", "api", "environment")):
        score += 1

    return priority_from_score(score)


def priority_for_note(asset: Asset | None = None) -> str:
    """Map note evidence to a low manual-review priority unless scope says stop."""

    if asset is not None and should_force_kill_switch(asset):
        return "kill_switch"
    return "low"


def priority_from_score(score: int) -> str:
    """Convert an internal score into the limited priority vocabulary."""

    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"
