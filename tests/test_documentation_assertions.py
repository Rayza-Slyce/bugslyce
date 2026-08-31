"""WP5A2 target-independent offline documentation assertion RED contract."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from hashlib import sha256
import importlib
import inspect

import pytest

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin


def _api():
    return importlib.import_module("bugslyce.recon.documentation_assertions")


def _item(
    body: bytes,
    *,
    url: str = "https://docs.example.test/guide",
    final_url: str | None = None,
    status_code: int = 200,
    content_type: str | None = "text/html; charset=utf-8",
    evidence_ids: tuple[str, ...] = ("EVID-DOC-0001",),
    body_sha256: str | None = None,
    body_bytes: int | None = None,
) -> DeepSourceRouteCollectedItem:
    headers = () if content_type is None else (("content-type", content_type),)
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=final_url or url,
        headers=headers,
        body_preview=body.decode("utf-8", errors="replace")[:120],
        body_sha256=body_sha256 or sha256(body).hexdigest(),
        body_bytes=len(body) if body_bytes is None else body_bytes,
        elapsed_seconds=0.125,
        source="recursive_evidence_feedback",
        reason="bounded_second_pass",
        evidence_ids=evidence_ids,
        body=body,
    )


def _collection(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _assertions_of_kind(result, kind):
    return tuple(item for item in result.assertions if item.kind is kind)


def test_explicit_service_base_label_extracts_service_base_url() -> None:
    api = _api()
    body = b"""
        <html><main>
          <h2>API base URL</h2>
          <pre>https://api.example.test/v1</pre>
        </main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertions = _assertions_of_kind(
        result, api.DocumentationAssertionKind.SERVICE_BASE_URL
    )
    assert len(assertions) == 1
    value = assertions[0].value
    assert isinstance(value, api.DocumentedServiceBaseURL)
    assert value.canonical_url == "https://api.example.test/v1"
    assert value.origin == HttpOrigin("https", "api.example.test", 443)
    support = assertions[0].supports[0]
    assert support.source_reference.evidence_ids == ("EVID-DOC-0001",)
    assert support.source_reference.body_bytes == len(body)
    assert (
        support.structural_context
        is api.DocumentationStructuralContext.LABELLED_CODE_BLOCK
    )


def test_arbitrary_visible_url_and_navigation_href_do_not_emit_service_base() -> None:
    api = _api()
    body = b"""
        <html><body>
          <nav><a href="https://api.example.test/v1">API</a></nav>
          <p>You can also read https://api.example.test/v1 in this sentence.</p>
        </body></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert result.assertions == ()


def test_explicit_operation_structure_extracts_method_and_templated_route() -> None:
    api = _api()
    body = b"""
        <html><main>
          <h2>HTTP operation</h2>
          <pre>POST /v1/accounts/{accountId}/token?format=compact</pre>
        </main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.HTTP_OPERATION
    )[0]
    assert assertion.value == api.DocumentedHttpOperation(
        method="POST",
        route="/v1/accounts/{accountId}/token?format=compact",
    )


def test_unrelated_prose_http_method_word_does_not_emit_operation() -> None:
    api = _api()
    body = b"""
        <html><main><p>After reading this post, visit the account page.</p></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.HTTP_OPERATION
    ) == ()


def test_explicit_required_header_structure_extracts_generic_header() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Header name</th><th>Required</th></tr>
          <tr><td>X-Client-Token</td><td>Yes</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.REQUIRED_HEADER
    )[0]
    assert assertion.value == api.DocumentedRequiredHeader(
        header_name="x-client-token"
    )
    assert (
        assertion.supports[0].structural_context
        is api.DocumentationStructuralContext.TABLE_ROW
    )
    assert assertion.supports[0].matched_excerpt == "X-Client-Token"


def test_optional_and_lexical_header_text_do_not_emit_required_header() -> None:
    api = _api()
    body = b"""
        <html><main>
          <table>
            <tr><th>Header name</th><th>Required</th></tr>
            <tr><td>X-Trace-ID</td><td>No</td></tr>
          </table>
          <p>X-Lexical-Token is mentioned here.</p>
        </main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.REQUIRED_HEADER
    ) == ()


def test_explicit_authentication_context_extracts_recognised_scheme() -> None:
    api = _api()
    body = b"""
        <html><main><dl>
          <dt>Required authentication scheme</dt><dd>Bearer</dd>
        </dl></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.AUTHENTICATION_SCHEME
    )[0]
    assert assertion.value == api.DocumentedAuthentication(
        scheme=api.DocumentationAuthenticationScheme.BEARER
    )
    assert (
        assertion.supports[0].structural_context
        is api.DocumentationStructuralContext.DEFINITION_PAIR
    )


def test_generic_authentication_word_mention_does_not_emit_scheme() -> None:
    api = _api()
    body = b"""
        <html><main><p>A bearer is a person who presents an item.</p></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.AUTHENTICATION_SCHEME
    ) == ()


def test_explicit_oauth_scope_structure_extracts_neutral_scope_token() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Required OAuth scope</th></tr>
          <tr><td>account:write</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.OAUTH_SCOPE
    )[0]
    assert assertion.value == api.DocumentedOAuthScope(scope="account:write")


def test_multicolumn_service_table_extracts_service_base_url() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Service</th><th>Base URL</th></tr>
          <tr><td>Trading API</td><td>https://api.example.test/v1</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.SERVICE_BASE_URL
    )[0]
    assert assertion.value == api.DocumentedServiceBaseURL(
        canonical_url="https://api.example.test/v1",
        origin=HttpOrigin("https", "api.example.test", 443),
    )
    support = assertion.supports[0]
    assert (
        support.structural_context
        is api.DocumentationStructuralContext.TABLE_ROW
    )
    assert support.matched_excerpt == "https://api.example.test/v1"


def test_multicolumn_authentication_table_extracts_bearer_scheme() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Authentication</th><th>Scheme</th></tr>
          <tr><td>Required</td><td>Bearer</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.AUTHENTICATION_SCHEME
    )[0]
    assert assertion.value == api.DocumentedAuthentication(
        scheme=api.DocumentationAuthenticationScheme.BEARER
    )
    support = assertion.supports[0]
    assert (
        support.structural_context
        is api.DocumentationStructuralContext.TABLE_ROW
    )
    assert support.matched_excerpt == "Bearer"
    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.REQUIRED_HEADER
    ) == ()
    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.OAUTH_SCOPE
    ) == ()


def test_multicolumn_oauth_table_extracts_scope() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Security</th><th>OAuth scope</th></tr>
          <tr><td>Required</td><td>account:write</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.OAUTH_SCOPE
    )[0]
    assert assertion.value == api.DocumentedOAuthScope(scope="account:write")
    support = assertion.supports[0]
    assert (
        support.structural_context
        is api.DocumentationStructuralContext.TABLE_ROW
    )
    assert support.matched_excerpt == "account:write"


def test_multicolumn_realtime_table_extracts_non_executable_endpoint() -> None:
    api = _api()
    body = b"""
        <html><main><table>
          <tr><th>Protocol</th><th>WebSocket endpoint</th></tr>
          <tr><td>WebSocket</td><td>wss://stream.example.test/v1/public</td></tr>
        </table></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.REALTIME_ENDPOINT
    )[0]
    value = assertion.value
    assert isinstance(value, api.DocumentedRealtimeEndpoint)
    assert not isinstance(value, HttpOrigin)
    assert value.canonical_url == "wss://stream.example.test/v1/public"
    assert value.scheme == "wss"
    assert value.hostname == "stream.example.test"
    assert value.effective_port == 443
    assert value.path == "/v1/public"
    assert value.query == ""
    support = assertion.supports[0]
    assert (
        support.structural_context
        is api.DocumentationStructuralContext.TABLE_ROW
    )
    assert support.matched_excerpt == "wss://stream.example.test/v1/public"


def test_ordinary_scope_token_occurrence_does_not_emit_oauth_scope() -> None:
    api = _api()
    body = b"""
        <html><main><p>The account:write string appears in ordinary prose.</p></main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.OAUTH_SCOPE
    ) == ()


def test_labelled_wss_endpoint_emits_non_executable_realtime_value() -> None:
    api = _api()
    body = b"""
        <html><main>
          <h2>Public WebSocket endpoint</h2>
          <pre>wss://STREAM.example.test/v1/public?format=json</pre>
        </main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assertion = _assertions_of_kind(
        result, api.DocumentationAssertionKind.REALTIME_ENDPOINT
    )[0]
    value = assertion.value
    assert isinstance(value, api.DocumentedRealtimeEndpoint)
    assert not isinstance(value, HttpOrigin)
    assert value.canonical_url == (
        "wss://stream.example.test/v1/public?format=json"
    )
    assert (value.scheme, value.hostname, value.effective_port) == (
        "wss",
        "stream.example.test",
        443,
    )
    assert value.path == "/v1/public"
    assert value.query == "format=json"


def test_navigation_and_framework_wss_strings_do_not_emit_realtime_endpoint() -> None:
    api = _api()
    body = b"""
        <html><body>
          <nav><a href="wss://stream.example.test/v1/public">Realtime</a></nav>
          <script type="application/json">
            {"endpoint":"wss://stream.example.test/v1/public"}
          </script>
        </body></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.REALTIME_ENDPOINT
    ) == ()


@pytest.mark.parametrize(
    "invalid_url",
    (
        "wss://user@stream.example.test/v1/public",
        "wss://stream.example.test/v1/public#fragment",
    ),
)
def test_invalid_labelled_realtime_endpoint_does_not_emit(invalid_url: str) -> None:
    api = _api()
    body = (
        "<html><main><h2>WebSocket endpoint</h2><pre>"
        f"{invalid_url}</pre></main></html>"
    ).encode()

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert result.skipped_sources == ()
    assert _assertions_of_kind(
        result, api.DocumentationAssertionKind.REALTIME_ENDPOINT
    ) == ()


def test_code_examples_document_operations_and_endpoints_but_not_requirements() -> None:
    api = _api()
    body = b"""
        <html><main>
          <h2>Request example</h2>
          <pre>POST /v1/accounts/{accountId}/token
Authorization: Bearer example
X-Client-Token: example
scope=account:write</pre>
          <h2>Realtime endpoint example</h2>
          <pre>wss://stream.example.test/v1/public</pre>
        </main></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    kinds = {item.kind for item in result.assertions}
    assert api.DocumentationAssertionKind.HTTP_OPERATION in kinds
    assert api.DocumentationAssertionKind.REALTIME_ENDPOINT in kinds
    assert api.DocumentationAssertionKind.REQUIRED_HEADER not in kinds
    assert api.DocumentationAssertionKind.AUTHENTICATION_SCHEME not in kinds
    assert api.DocumentationAssertionKind.OAUTH_SCOPE not in kinds


def test_excluded_and_hidden_strong_structures_emit_no_assertions() -> None:
    api = _api()
    body = b"""
        <html><body>
          <script><h2>API base URL</h2><pre>https://api.example.test</pre></script>
          <style><h2>WebSocket endpoint</h2><pre>wss://stream.example.test</pre></style>
          <template><h2>HTTP operation</h2><pre>GET /v1/private</pre></template>
          <noscript><h2>API base URL</h2><pre>https://api.example.test</pre></noscript>
          <nav><h2>API base URL</h2><pre>https://api.example.test</pre></nav>
          <header><h2>HTTP operation</h2><pre>POST /v1/private</pre></header>
          <footer><h2>WebSocket endpoint</h2><pre>wss://stream.example.test</pre></footer>
          <aside><h2>API base URL</h2><pre>https://api.example.test</pre></aside>
          <section hidden><h2>API base URL</h2><pre>https://api.example.test</pre></section>
          <section aria-hidden="true"><h2>HTTP operation</h2><pre>GET /v1/private</pre></section>
          <section style="display: none"><h2>API base URL</h2><pre>https://api.example.test</pre></section>
          <section style="visibility:hidden"><h2>WebSocket endpoint</h2><pre>wss://stream.example.test</pre></section>
        </body></html>
    """

    result = api.build_documentation_assertions(_collection(_item(body)))

    assert result.assertions == ()


def test_duplicate_semantic_assertion_coalesces_and_retains_distinct_supports() -> None:
    api = _api()
    first_body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )
    second_body = (
        b"<html><main><dl><dt>Service base URL</dt>"
        b"<dd>https://api.example.test/</dd></dl></main></html>"
    )
    first = _item(first_body, evidence_ids=("EVID-FIRST",))
    second = _item(
        second_body,
        url="https://docs.example.test/reference",
        evidence_ids=("EVID-SECOND",),
    )

    result = api.build_documentation_assertions(_collection(first, second))

    assert len(result.assertions) == 1
    assert len(result.assertions[0].supports) == 2
    assert {
        support.source_reference.evidence_ids
        for support in result.assertions[0].supports
    } == {("EVID-FIRST",), ("EVID-SECOND",)}


def test_corroborating_support_does_not_change_assertion_identity() -> None:
    api = _api()
    first_body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )
    second_body = (
        b"<html><main><dl><dt>Service base URL</dt>"
        b"<dd>https://api.example.test/</dd></dl></main></html>"
    )
    first = _item(first_body, evidence_ids=("EVID-FIRST",))
    second = _item(
        second_body,
        url="https://docs.example.test/reference",
        evidence_ids=("EVID-SECOND",),
    )

    initial = api.build_documentation_assertions(_collection(first))
    corroborated = api.build_documentation_assertions(_collection(first, second))

    assert initial.assertions[0].assertion_id == (
        corroborated.assertions[0].assertion_id
    )
    assert len(initial.assertions[0].supports) == 1
    assert len(corroborated.assertions[0].supports) == 2


def test_reversed_source_order_produces_equal_deterministic_result() -> None:
    api = _api()
    first = _item(
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>",
        evidence_ids=("EVID-B", "EVID-A"),
    )
    second = _item(
        b"<html><main><h2>HTTP operation</h2>"
        b"<pre>GET /v1/status</pre></main></html>",
        url="https://docs.example.test/status",
        evidence_ids=("EVID-C",),
    )

    forward = api.build_documentation_assertions(_collection(first, second))
    reversed_result = api.build_documentation_assertions(
        _collection(second, first)
    )

    assert forward == reversed_result
    assert tuple(item.assertion_id for item in forward.assertions) == tuple(
        sorted(item.assertion_id for item in forward.assertions)
    )
    assert all(
        assertion.supports
        == tuple(
            sorted(
                assertion.supports,
                key=lambda support: (
                    support.source_reference.source_id,
                    support.start_offset,
                    support.end_offset,
                    support.structural_context.value,
                    support.structural_locator,
                ),
            )
        )
        for assertion in forward.assertions
    )


def test_body_hash_mismatch_fails_closed_with_typed_skip() -> None:
    api = _api()
    body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )

    result = api.build_documentation_assertions(
        _collection(_item(body, body_sha256="0" * 64))
    )

    assert result.assertions == ()
    assert (
        result.skipped_sources[0].reason
        is api.DocumentationSourceSkipReason.BODY_HASH_MISMATCH
    )


def test_body_length_mismatch_fails_closed_with_typed_skip() -> None:
    api = _api()
    body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )

    result = api.build_documentation_assertions(
        _collection(_item(body, body_bytes=len(body) + 1))
    )

    assert result.assertions == ()
    assert (
        result.skipped_sources[0].reason
        is api.DocumentationSourceSkipReason.BODY_LENGTH_MISMATCH
    )


@pytest.mark.parametrize(
    ("item", "expected_reason"),
    (
        (_item(b""), "missing_body"),
        (
            _item(
                b"<html><main><h2>API base URL</h2>"
                b"<code>https://api.example.test</code></main></html>",
                evidence_ids=(),
            ),
            "missing_evidence",
        ),
    ),
)
def test_missing_body_or_evidence_fails_closed(item, expected_reason) -> None:
    api = _api()

    result = api.build_documentation_assertions(_collection(item))

    assert result.assertions == ()
    assert result.skipped_sources[0].reason.value == expected_reason


@pytest.mark.parametrize(
    ("item", "expected_reason"),
    (
        (
            _item(
                b"<html><main><h2>API base URL</h2>"
                b"<code>https://api.example.test</code></main></html>",
                status_code=404,
            ),
            "non_success_status",
        ),
        (
            _item(
                b"<html><main><h2>API base URL</h2>"
                b"<code>https://api.example.test</code></main></html>",
                content_type=None,
            ),
            "unsupported_media_type",
        ),
        (
            _item(
                b"<html><main><h2>API base URL</h2>"
                b"<code>https://api.example.test</code></main></html>",
                content_type="application/octet-stream",
            ),
            "unsupported_media_type",
        ),
        (
            _item(
                b"<html><main><h2>API base URL</h2>"
                b"<code>https://api.example.test</code></main></html>",
                content_type="text/plain",
            ),
            "unsupported_media_type",
        ),
        (
            _item(
                b'{"api_base":"https://api.example.test"}',
                content_type="application/json",
            ),
            "unsupported_media_type",
        ),
    ),
)
def test_unsupported_media_or_non_success_status_emits_no_assertion(
    item, expected_reason
) -> None:
    api = _api()

    result = api.build_documentation_assertions(_collection(item))

    assert result.assertions == ()
    assert result.skipped_sources[0].reason.value == expected_reason


def test_support_locator_resolves_to_bounded_raw_decoded_source() -> None:
    api = _api()
    body = b"""
        <html><main>
          <h2>API base URL</h2><pre>https://api.example.test/v1</pre>
        </main></html>
    """
    item = _item(body)

    result = api.build_documentation_assertions(_collection(item))

    support = result.assertions[0].supports[0]
    decoded = body.decode("utf-8", errors="replace")
    assert decoded[support.start_offset : support.end_offset] == (
        support.matched_excerpt
    )
    assert support.matched_excerpt == "https://api.example.test/v1"
    assert 0 < len(support.matched_excerpt) <= 200
    assert 0 < len(support.structural_locator) <= 200
    assert support.line_number == decoded.count("\n", 0, support.start_offset) + 1
    assert support.source_reference.body_sha256 == item.body_sha256
    assert support.source_reference.body_bytes == len(body)


def test_assertion_kind_and_typed_value_mismatch_fails_closed() -> None:
    api = _api()
    body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )
    result = api.build_documentation_assertions(_collection(_item(body)))
    assertion = result.assertions[0]

    with pytest.raises(ValueError, match="kind|value"):
        replace(
            assertion,
            kind=api.DocumentationAssertionKind.HTTP_OPERATION,
        )


def test_public_models_are_immutable() -> None:
    api = _api()
    body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )
    result = api.build_documentation_assertions(_collection(_item(body)))

    with pytest.raises(FrozenInstanceError):
        result.assertions = ()
    with pytest.raises(FrozenInstanceError):
        result.assertions[0].supports = ()
    with pytest.raises(FrozenInstanceError):
        result.assertions[0].supports[0].matched_excerpt = "changed"
    with pytest.raises(FrozenInstanceError):
        result.assertions[0].value.canonical_url = (
            "https://changed.example.test/"
        )


def test_builder_does_not_mutate_source_collection() -> None:
    api = _api()
    body = (
        b"<html><main><h2>API base URL</h2>"
        b"<code>https://api.example.test</code></main></html>"
    )
    source = _item(body)
    collection = _collection(source)
    before = replace(collection, collected=tuple(collection.collected))

    api.build_documentation_assertions(collection)

    assert collection == before
    assert collection.collected[0] is source


def test_public_vocabularies_value_schemas_and_builder_boundary_are_closed() -> None:
    api = _api()

    assert {item.value for item in api.DocumentationAssertionKind} == {
        "service_base_url",
        "http_operation",
        "required_header",
        "authentication_scheme",
        "oauth_scope",
        "realtime_endpoint",
    }
    assert {item.value for item in api.DocumentationAuthenticationScheme} == {
        "bearer"
    }
    assert {item.value for item in api.DocumentationSourceOwnerKind} == {
        "deep_source_route_collected_item"
    }
    assert {item.value for item in api.DocumentationStructuralContext} == {
        "labelled_code_block",
        "definition_pair",
        "table_row",
    }
    assert {item.value for item in api.DocumentationSourceSkipReason} == {
        "missing_body",
        "body_hash_mismatch",
        "body_length_mismatch",
        "missing_evidence",
        "non_success_status",
        "unsupported_media_type",
    }
    assert tuple(
        inspect.signature(api.build_documentation_assertions).parameters
    ) == ("source_collection",)
    assert tuple(
        field.name for field in fields(api.DocumentationAssertionSourceReference)
    ) == (
        "owner_kind",
        "source_id",
        "request_url",
        "final_url",
        "method",
        "status_code",
        "body_sha256",
        "body_bytes",
        "evidence_ids",
        "media_type",
    )
    assert tuple(field.name for field in fields(api.DocumentedServiceBaseURL)) == (
        "canonical_url",
        "origin",
    )
    assert tuple(field.name for field in fields(api.DocumentedHttpOperation)) == (
        "method",
        "route",
    )
    assert tuple(field.name for field in fields(api.DocumentedRequiredHeader)) == (
        "header_name",
    )
    assert tuple(field.name for field in fields(api.DocumentedAuthentication)) == (
        "scheme",
    )
    assert tuple(field.name for field in fields(api.DocumentedOAuthScope)) == (
        "scope",
    )
    assert tuple(
        field.name for field in fields(api.DocumentedRealtimeEndpoint)
    ) == (
        "canonical_url",
        "scheme",
        "hostname",
        "effective_port",
        "path",
        "query",
    )
