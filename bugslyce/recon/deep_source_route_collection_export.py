"""Explicit export helpers for Deep source/route collection results."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectionResult,
    SAFETY_NOTES,
    render_deep_source_route_collection_result_markdown,
)


DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN = "deep_source_route_collection.md"
DEEP_SOURCE_ROUTE_COLLECTION_JSON = "deep_source_route_collection.json"


def deep_source_route_collection_result_to_dict(
    result: DeepSourceRouteCollectionResult,
) -> dict:
    """Convert a Deep source/route collection result to a stable JSON payload."""

    return {
        "schema_version": 1,
        "generated_by": "bugslyce.deep_source_route_collection",
        "collected": [
            {
                "url": item.url,
                "method": item.method,
                "status_code": item.status_code,
                "final_url": item.final_url,
                "headers": [list(header) for header in item.headers],
                "body_preview": item.body_preview,
                "body_sha256": item.body_sha256,
                "body_bytes": item.body_bytes,
                "elapsed_seconds": item.elapsed_seconds,
                "source": item.source,
                "reason": item.reason,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in result.collected
        ],
        "skipped": [
            {
                "url": item.url,
                "method": item.method,
                "reason": item.reason,
                "source": item.source,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in result.skipped
        ],
        "total_considered": result.total_considered,
        "total_collected": result.total_collected,
        "total_skipped": result.total_skipped,
        "safety_notes": list(SAFETY_NOTES),
    }


def write_deep_source_route_collection_artifacts(
    result: DeepSourceRouteCollectionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write Markdown and JSON Deep source/route collection artefacts."""

    if not output_dir.exists():
        raise FileNotFoundError(f"output directory does not exist: {output_dir}")
    if not output_dir.is_dir():
        raise NotADirectoryError(f"output path is not a directory: {output_dir}")

    markdown_path = output_dir / DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN
    json_path = output_dir / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    markdown_path.write_text(
        render_deep_source_route_collection_result_markdown(result) + "\n",
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(
            deep_source_route_collection_result_to_dict(result),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return markdown_path, json_path
