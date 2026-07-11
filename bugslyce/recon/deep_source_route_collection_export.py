"""Explicit export helpers for Deep source/route collection results."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
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


def deep_source_route_collection_result_from_dict(
    payload: dict,
) -> DeepSourceRouteCollectionResult:
    """Rebuild a Deep source/route collection result from a JSON payload."""

    if not isinstance(payload, dict):
        raise ValueError("deep source/route collection payload must be an object.")
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ValueError("schema_version must be integer 1.")
    if schema_version != 1:
        raise ValueError("unsupported deep source/route collection schema_version.")
    generated_by = payload.get("generated_by")
    if generated_by != "bugslyce.deep_source_route_collection":
        raise ValueError(
            "generated_by must be bugslyce.deep_source_route_collection."
        )

    collected_payload = _require_list(payload, "collected")
    skipped_payload = _require_list(payload, "skipped")
    collected = tuple(_collected_item_from_dict(item) for item in collected_payload)
    skipped = tuple(_skipped_item_from_dict(item) for item in skipped_payload)
    return DeepSourceRouteCollectionResult(
        collected=collected,
        skipped=skipped,
        total_considered=_require_int(payload, "total_considered"),
        total_collected=_require_int(payload, "total_collected"),
        total_skipped=_require_int(payload, "total_skipped"),
    )


def load_deep_source_route_collection_result(
    path: Path,
) -> DeepSourceRouteCollectionResult:
    """Load a Deep source/route collection result from an existing JSON artefact."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"could not parse deep source/route collection JSON: {exc}"
        ) from exc
    return deep_source_route_collection_result_from_dict(payload)


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


def _collected_item_from_dict(payload: object) -> DeepSourceRouteCollectedItem:
    if not isinstance(payload, dict):
        raise ValueError("collected item must be an object.")
    if "body" in payload:
        raise ValueError("collected item must not include a full body field.")
    return DeepSourceRouteCollectedItem(
        url=_require_str(payload, "url"),
        method=_require_str(payload, "method"),
        status_code=_require_int(payload, "status_code"),
        final_url=_require_str(payload, "final_url"),
        headers=_headers_from_payload(_require_list(payload, "headers")),
        body_preview=_require_str(payload, "body_preview"),
        body_sha256=_require_str(payload, "body_sha256"),
        body_bytes=_require_int(payload, "body_bytes"),
        elapsed_seconds=_require_number(payload, "elapsed_seconds"),
        source=_require_str(payload, "source"),
        reason=_require_str(payload, "reason"),
        evidence_ids=_str_tuple(_require_list(payload, "evidence_ids"), "evidence_ids"),
    )


def _skipped_item_from_dict(payload: object) -> DeepSourceRouteSkippedItem:
    if not isinstance(payload, dict):
        raise ValueError("skipped item must be an object.")
    return DeepSourceRouteSkippedItem(
        url=_require_str(payload, "url"),
        method=_require_str(payload, "method"),
        reason=_require_str(payload, "reason"),
        source=_require_str(payload, "source"),
        evidence_ids=_str_tuple(_require_list(payload, "evidence_ids"), "evidence_ids"),
    )


def _headers_from_payload(values: list) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    for value in values:
        if (
            not isinstance(value, list)
            or len(value) != 2
            or not isinstance(value[0], str)
            or not isinstance(value[1], str)
        ):
            raise ValueError("headers must be a list of two-string lists.")
        headers.append((value[0], value[1]))
    return tuple(headers)


def _str_tuple(values: list, field: str) -> tuple[str, ...]:
    if not all(isinstance(value, str) for value in values):
        raise ValueError(f"{field} must contain only strings.")
    return tuple(values)


def _require_list(payload: dict, field: str) -> list:
    value = payload.get(field)
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list.")
    return value


def _require_str(payload: dict, field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string.")
    return value


def _require_int(payload: dict, field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    return value


def _require_number(payload: dict, field: str) -> float:
    value = payload.get(field)
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError(f"{field} must be a number.")
    return float(value)
