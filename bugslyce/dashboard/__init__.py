"""Read-only projections and local browser views of canonical project state."""

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
