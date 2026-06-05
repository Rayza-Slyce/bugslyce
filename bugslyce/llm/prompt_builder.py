"""Minimized triage context builder for future optional LLM mode."""

from __future__ import annotations

import json
from typing import Any

from bugslyce.core.models import Candidate, ProjectState


def build_minimised_triage_context(
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    max_candidates: int = 10,
    max_endpoints_per_candidate: int = 3,
    max_evidence: int = 10,
) -> dict[str, Any]:
    """Build compact structured context without raw recon file contents."""

    return {
        "project_name": project_state.project_name,
        "scope_summary": project_state.scope_summary,
        "asset_count": len(project_state.assets),
        "endpoint_count": len(project_state.endpoints),
        "candidate_count": len(candidates),
        "top_candidates": [
            {
                "id": candidate.id,
                "candidate_type": candidate.candidate_type,
                "priority": candidate.priority,
                "title": candidate.title,
                "evidence_ids": candidate.evidence_ids,
                "affected_assets": candidate.affected_assets,
                "affected_endpoints": candidate.affected_endpoints[:max_endpoints_per_candidate],
            }
            for candidate in candidates[:max_candidates]
        ],
        "evidence_summary": [
            {
                "id": evidence.id,
                "evidence_type": evidence.evidence_type,
                "source_file": evidence.source_file,
            }
            for evidence in project_state.evidence[:max_evidence]
        ],
        "project_warnings": project_state.warnings,
        "language_rules": {
            "prefer": [
                "candidate",
                "hypothesis",
                "manual review",
                "manual validation",
                "evidence suggests",
                "requires confirmation",
            ],
            "avoid": [
                "unsupported confirmation claims",
                "active attack instructions",
                "destructive testing language",
                "provider claims without manual evidence",
            ],
        },
        "privacy_note": "Raw recon files are not included by default.",
    }


def estimate_context_size(context: dict) -> int:
    """Estimate context size using deterministic JSON serialization length."""

    return len(json.dumps(context, sort_keys=True))
