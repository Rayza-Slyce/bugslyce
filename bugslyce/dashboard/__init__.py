"""Read-only projections of existing canonical project state; no UI or execution."""

from bugslyce.dashboard.read_model import (
    DashboardAuthoritySummary,
    DashboardProjectIdentity,
    DashboardReadModel,
    build_dashboard_read_model,
)

__all__ = [
    "DashboardAuthoritySummary",
    "DashboardProjectIdentity",
    "DashboardReadModel",
    "build_dashboard_read_model",
]
