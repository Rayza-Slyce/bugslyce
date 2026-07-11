"""Explicit export helpers for Deep metadata collection results."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
    DeepMetadataSkippedItem,
    SAFETY_NOTES,
    render_deep_metadata_collection_result_markdown,
)


DEEP_METADATA_COLLECTION_MARKDOWN = "deep_metadata_collection.md"
DEEP_METADATA_COLLECTION_JSON = "deep_metadata_collection.json"


def deep_metadata_collection_result_to_dict(
    result: DeepMetadataCollectionResult,
) -> dict:
    """Convert a Deep metadata collection result to a stable JSON payload."""

    return {
        "schema_version": 1,
        "generated_by": "bugslyce.deep_metadata_collection",
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


def deep_metadata_collection_result_from_dict(
    payload: dict,
) -> DeepMetadataCollectionResult:
    """Rebuild a Deep metadata collection result from a JSON payload."""

    if not isinstance(payload, dict):
        raise ValueError("deep metadata collection payload must be an object.")
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ValueError("schema_version must be integer 1.")
    if schema_version != 1:
        raise ValueError("unsupported deep metadata collection schema_version.")
    generated_by = payload.get("generated_by")
    if generated_by != "bugslyce.deep_metadata_collection":
        raise ValueError("generated_by must be bugslyce.deep_metadata_collection.")

    collected_payload = _require_list(payload, "collected")
    skipped_payload = _require_list(payload, "skipped")
    collected = tuple(_collected_item_from_dict(item) for item in collected_payload)
    skipped = tuple(_skipped_item_from_dict(item) for item in skipped_payload)
    return DeepMetadataCollectionResult(
        collected=collected,
        skipped=skipped,
        total_considered=_require_int(payload, "total_considered"),
        total_collected=_require_int(payload, "total_collected"),
        total_skipped=_require_int(payload, "total_skipped"),
    )


def load_deep_metadata_collection_result(
    path: Path,
) -> DeepMetadataCollectionResult:
    """Load a Deep metadata collection result from an existing JSON artefact."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse deep metadata collection JSON: {exc}") from exc
    return deep_metadata_collection_result_from_dict(payload)


def write_deep_metadata_collection_artifacts(
    result: DeepMetadataCollectionResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write Markdown and JSON Deep metadata collection artefacts."""

    if not output_dir.exists():
        raise FileNotFoundError(f"output directory does not exist: {output_dir}")
    if not output_dir.is_dir():
        raise NotADirectoryError(f"output path is not a directory: {output_dir}")

    markdown_path = output_dir / DEEP_METADATA_COLLECTION_MARKDOWN
    json_path = output_dir / DEEP_METADATA_COLLECTION_JSON
    markdown_path.write_text(
        render_deep_metadata_collection_result_markdown(result) + "\n",
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(
            deep_metadata_collection_result_to_dict(result),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return markdown_path, json_path


def _collected_item_from_dict(payload: object) -> DeepMetadataCollectedItem:
    if not isinstance(payload, dict):
        raise ValueError("collected item must be an object.")
    if "body" in payload:
        raise ValueError("collected item must not include a full body field.")
    return DeepMetadataCollectedItem(
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


def _skipped_item_from_dict(payload: object) -> DeepMetadataSkippedItem:
    if not isinstance(payload, dict):
        raise ValueError("skipped item must be an object.")
    return DeepMetadataSkippedItem(
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
