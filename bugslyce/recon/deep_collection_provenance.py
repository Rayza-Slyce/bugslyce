"""Content-addressed identity for accepted Deep responses, not scope authority.

The digest commits to a retained response summary, not to the authenticity of
an unsigned evidence pack. Full bodies are deliberately not required on load.
"""

from hashlib import sha256
import json
import re

from bugslyce.core.programme_scope import canonicalise_http_url_destination

RESPONSE_PREFIX = "DEEP-RESP-SHA256-"
COLLECTION_OWNERS = frozenset({"metadata", "source-route", "shallow-followup"})


def response_identity(*, owner, method, request_url, final_url, status_code, body_sha256):
    """Return one identity from validated immutable response facts."""
    if owner not in COLLECTION_OWNERS:
        raise ValueError("unsupported Deep response owner")
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
        raise ValueError("invalid Deep response method")
    if type(status_code) is not int or not 100 <= status_code <= 599:
        raise ValueError("invalid Deep response status")
    if not isinstance(body_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", body_sha256):
        raise ValueError("invalid Deep response body digest")
    payload = {
        "version": 1,
        "owner": owner,
        "method": method.upper(),
        "request_url": canonicalise_http_url_destination(request_url).canonical_value,
        "final_url": canonicalise_http_url_destination(final_url).canonical_value,
        "status_code": status_code,
        "body_sha256": body_sha256,
    }
    return RESPONSE_PREFIX + sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def item_response_identity(owner, item):
    return response_identity(
        owner=owner, method=item.method,
        request_url=item.requested_url if owner == "shallow-followup" else item.url,
        final_url=item.final_url, status_code=item.status_code, body_sha256=item.body_sha256,
    )


def merge_response_evidence(antecedents, **facts):
    return tuple(dict.fromkeys((*antecedents, response_identity(**facts))))


def is_response_id(value):
    return isinstance(value, str) and value.startswith("DEEP-RESP-")


def validate_response_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"DEEP-RESP-SHA256-[0-9a-f]{64}", value):
        raise ValueError("malformed Deep response evidence ID")


def source_response_reference(item, legacy_reference):
    if not any(is_response_id(value) for value in item.evidence_ids):
        return legacy_reference
    identifier = item_response_identity("source-route", item)
    return identifier if identifier in item.evidence_ids else legacy_reference


def extraction_source_id(kind, source_id, url, source_urls, evidence_ids, response_ids, semantics=()):
    """Bind fresh extraction source references to their retained observation.

    Historical extraction references remain unchanged. The new reference commits
    to the observation's route, semantics and exact supporting response set.
    """
    if not any(is_response_id(value) for value in evidence_ids):
        return source_id
    responses = sorted(set(response_ids))
    if not responses:
        raise ValueError("fresh extraction requires direct response bindings")
    for value in responses:
        validate_response_id(value)
    payload = {"version": 1, "kind": kind, "route": url,
               "sources": sorted(set(source_urls)), "responses": responses,
               "evidence": sorted(set(evidence_ids)),
               "semantics": sorted(set(semantics))}
    return "DEEP-EXTRACT-SHA256-" + sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
