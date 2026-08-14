"""Shared presentation indexes over immutable investigation-context state."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from bugslyce.reports.investigation_context import (
    InvestigationContextAssembly,
    InvestigationContextBacklink,
    InvestigationContextView,
    ReportNavigationReference,
    ReportReferenceTarget,
    build_report_navigation_references,
)


@dataclass(frozen=True)
class InvestigationContextPresentationIndex:
    """Bounded renderer lookups without deriving new semantic relationships."""

    primary_by_anchor_id: Mapping[str, InvestigationContextView]
    reference_by_target: Mapping[tuple[str, str], ReportNavigationReference]
    evidence_backlink_by_id: Mapping[str, InvestigationContextBacklink]
    route_backlink_by_url: Mapping[str, InvestigationContextBacklink]
    route_reference_by_url: Mapping[str, ReportNavigationReference]


def build_investigation_context_presentation_index(
    assembly: InvestigationContextAssembly,
) -> InvestigationContextPresentationIndex:
    """Index one frozen C1 assembly once for a report rendering pass."""

    references = {
        (reference.target_kind, reference.target_id): reference
        for context in assembly.primary_contexts
        for reference in context.navigation_references
    }
    route_references = build_report_navigation_references(
        ReportReferenceTarget("route", backlink.target_identity, (backlink.target_identity,))
        for backlink in assembly.route_backlinks
    )
    references.update({
        (reference.target_kind, reference.target_id): reference
        for reference in route_references
    })
    return InvestigationContextPresentationIndex(
        primary_by_anchor_id=MappingProxyType({
            context.anchor_id: context for context in assembly.primary_contexts
        }),
        reference_by_target=MappingProxyType(references),
        evidence_backlink_by_id=MappingProxyType({
            backlink.target_identity: backlink
            for backlink in assembly.evidence_backlinks
        }),
        route_backlink_by_url=MappingProxyType({
            backlink.target_identity: backlink for backlink in assembly.route_backlinks
        }),
        route_reference_by_url=MappingProxyType({
            reference.target_id: reference for reference in route_references
        }),
    )
