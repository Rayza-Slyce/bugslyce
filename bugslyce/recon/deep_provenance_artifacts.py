"""Retained bounded Deep observations and response ownership.

These are collection summaries, not full bodies or an authenticity signature.
Loaders never manufacture evidence for historical observations.
"""
from dataclasses import fields, is_dataclass
import json
import math
from pathlib import Path
from types import UnionType
from typing import get_args, get_origin, get_type_hints

from bugslyce.recon.deep_collection_provenance import (
    is_response_id, item_response_identity, validate_response_id,
)
from bugslyce.recon.deep_html_route_extraction import (
    DeepHtmlRouteExtractionResult, redacted_source_url as html_source_url,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteExtractionResult, redacted_source_url as javascript_source_url,
)
from bugslyce.recon.deep_shallow_route_followup import DeepShallowRouteFollowupResult

SHALLOW_JSON = "deep_shallow_route_followup_collection.json"
EXTRACTION_JSON = "deep_route_extraction.json"


def _encode(value):
    if is_dataclass(value):
        return {field.name: _encode(getattr(value, field.name))
                for field in fields(value) if field.name != "body"}
    if isinstance(value, tuple):
        return [_encode(item) for item in value]
    return value


def _decode(kind, value):
    """Exact typed decoding of the two fixed observation schemas."""
    if is_dataclass(kind):
        expected = {field.name for field in fields(kind) if field.name != "body"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("invalid Deep observation field set")
        hints = get_type_hints(kind)
        return kind(**{key: _decode(hints[key], item) for key, item in value.items()})
    if get_origin(kind) is tuple:
        if not isinstance(value, list):
            raise ValueError("Deep observation requires an array")
        args = get_args(kind)
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        if len(value) != len(args):
            raise ValueError("invalid Deep observation tuple")
        return tuple(_decode(arg, item) for arg, item in zip(args, value))
    if get_origin(kind) is UnionType:
        for option in get_args(kind):
            try:
                return _decode(option, value)
            except ValueError:
                pass
        raise ValueError("invalid Deep observation optional field")
    if kind is float:
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid Deep observation numeric field")
        return float(value)
    if type(value) is not kind:
        raise ValueError("invalid Deep observation field type")
    if kind is int and value < 0:
        raise ValueError("negative Deep observation count")
    return value


def _envelope(producer, **values):
    return {"schema_version": 1, "generated_by": producer, **values}


def _validate_envelope(payload, producer, keys):
    if (not isinstance(payload, dict) or set(payload) != {"schema_version", "generated_by", *keys}
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["generated_by"] != producer):
        raise ValueError("unsupported Deep provenance artifact schema or producer")


def shallow_collection_to_dict(result):
    return _envelope("bugslyce.deep_shallow_route_followup_collection", result=_encode(result))


def shallow_collection_from_dict(payload):
    _validate_envelope(payload, "bugslyce.deep_shallow_route_followup_collection", {"result"})
    result = _decode(DeepShallowRouteFollowupResult, payload["result"])
    counts = result.summary_counts
    if counts.responses_collected != len(result.collected) or counts.requests_skipped_or_failed != len(result.skipped):
        raise ValueError("inconsistent shallow collection counts")
    for item in result.collected:
        item_response_identity("shallow-followup", item)
    return result


def extraction_to_dict(html, javascript):
    return _envelope("bugslyce.deep_route_extraction", html=_encode(html), javascript=_encode(javascript))


def extraction_from_dict(payload):
    _validate_envelope(payload, "bugslyce.deep_route_extraction", {"html", "javascript"})
    return (_decode(DeepHtmlRouteExtractionResult, payload["html"]),
            _decode(DeepJavaScriptRouteExtractionResult, payload["javascript"]))


def write_deep_provenance_artifacts(output_dir, shallow, html, javascript):
    paths = []
    for filename, payload in ((SHALLOW_JSON, shallow_collection_to_dict(shallow)),
                              (EXTRACTION_JSON, extraction_to_dict(html, javascript))):
        path = Path(output_dir) / filename
        if path.is_symlink():
            raise ValueError("refusing a symlink Deep provenance output")
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return tuple(paths)


def owned_responses(owner, collection):
    """Only the recomputed direct ID declares ownership, never antecedents."""
    result = {}
    for item in collection.collected:
        if not any(is_response_id(value) for value in item.evidence_ids):
            continue  # legacy records acquire nothing on load
        for value in item.evidence_ids:
            if is_response_id(value):
                validate_response_id(value)
        identifier = item_response_identity(owner, item)
        if identifier in item.evidence_ids:
            if item.evidence_ids.count(identifier) != 1:
                raise ValueError("duplicate direct Deep response declaration")
            previous = result.get(identifier)
            if previous is not None and _encode(previous) != _encode(item):
                raise ValueError("conflicting Deep response observations")
            result[identifier] = item
    return result


def validate_extraction_bindings(html, javascript, source_responses):
    """Validate direct extraction-response bindings, independently of the model.

    The retained observation records the bounded parser's output. Its direct
    source IDs identify exact responses, not just URLs or sequence positions.
    """
    observations = [(record, html_source_url) for record in html.routes]
    observations.extend((record, javascript_source_url) for record in javascript.candidates)
    for record, source_url in observations:
        if not any(is_response_id(value) for value in record.evidence_ids):
            continue
        if not record.source_response_ids:
            raise ValueError("missing extraction response binding")
        expected = set()
        expected_urls = set()
        for identifier in record.source_response_ids:
            validate_response_id(identifier)
            item = source_responses.get(identifier)
            if item is None:
                raise ValueError("extraction response binding has no retained owner")
            expected.update(item.evidence_ids)
            expected_urls.add(source_url(item.url))
        if expected != set(record.evidence_ids):
            raise ValueError("extraction evidence does not match bound responses")
        if expected_urls != set(record.source_request_urls):
            raise ValueError("extraction source URLs do not match bound responses")
