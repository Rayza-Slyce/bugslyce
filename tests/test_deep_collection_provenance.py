"""Collection identity is deterministic evidence, never execution authority."""
from hashlib import sha256
import re

import pytest

from bugslyce.recon.deep_collection_provenance import response_identity, merge_response_evidence


def facts():
    return dict(owner="metadata", method="GET", request_url="https://example.test/sitemap.xml",
                final_url="https://example.test/sitemap.xml", status_code=200,
                body_sha256=sha256(b"response").hexdigest())


def test_identity_is_deterministic_and_not_core_evidence():
    identifier = response_identity(**facts())
    assert identifier == response_identity(**facts())
    assert re.fullmatch(r"DEEP-RESP-SHA256-[0-9a-f]{64}", identifier)
    assert not identifier.startswith("EVID-")
    assert identifier == response_identity(**(facts() | {"method": "get"}))


@pytest.mark.parametrize("change", [
    {"owner": "source-route"}, {"owner": "shallow-followup"},
    {"body_sha256": sha256(b"other").hexdigest()},
    {"request_url": "https://example.test/other"},
    {"final_url": "https://example.test/other"}, {"status_code": 404}, {"method": "HEAD"},
])
def test_identity_commits_to_each_immutable_dimension(change):
    assert response_identity(**facts()) != response_identity(**(facts() | change))


def test_antecedents_are_retained_in_order_and_deduplicated():
    identifier = response_identity(**facts())
    assert merge_response_evidence(("EVID-B", "EVID-A", "EVID-B", identifier), **facts()) == (
        "EVID-B", "EVID-A", identifier,
    )


@pytest.mark.parametrize("change", [
    {"owner": "other"}, {"method": "POST"}, {"status_code": True},
    {"status_code": 0}, {"body_sha256": "bad"}, {"request_url": "not-a-url"},
])
def test_invalid_identity_facts_fail_closed(change):
    with pytest.raises(ValueError):
        response_identity(**(facts() | change))
