"""Deep collection adapter for the central internal HTTP executor."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
)
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.http_enforcement import (
    HTTPEnforcementConfiguration,
    HTTPTransport,
    InternalHTTPExecutor,
)


@dataclass(frozen=True)
class DeepHTTPFetcher:
    """Callable Deep adapter sharing one central executor across stages."""

    executor: InternalHTTPExecutor

    def __call__(
        self,
        request: DeepCollectionRequest,
        bounds: DeepCollectionBounds,
    ) -> DeepHTTPResponse:
        method = request.method.upper().strip()
        if method not in {"GET", "HEAD"}:
            raise ValueError("method_not_allowed")
        if "?" in request.url and not bounds.allow_query_strings:
            raise ValueError("query_string_not_allowed")

        response = self.executor.request(
            request.url,
            method=method,
            timeout_seconds=bounds.timeout_seconds,
            maximum_response_bytes=bounds.max_response_bytes,
            allow_query_strings=bounds.allow_query_strings,
        )
        return DeepHTTPResponse(
            url=request.url,
            final_url=response.final_url,
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
            elapsed_seconds=response.elapsed_seconds,
            redirects=response.redirects,
        )


def build_deep_http_fetcher(
    configuration: HTTPEnforcementConfiguration | None = None,
    *,
    executor: InternalHTTPExecutor | None = None,
    transport: HTTPTransport | None = None,
) -> DeepHTTPFetcher:
    """Build one shareable Deep fetcher for an invocation or pipeline run."""
    if executor is not None:
        if configuration is not None or transport is not None:
            raise ValueError("Injected Deep HTTP executor cannot be combined with new configuration.")
        return DeepHTTPFetcher(executor)
    return DeepHTTPFetcher(InternalHTTPExecutor(configuration, transport=transport))


def urllib_deep_http_fetcher(
    request: DeepCollectionRequest,
    bounds: DeepCollectionBounds,
) -> DeepHTTPResponse:
    """Compatibility wrapper that still executes through the central boundary."""

    return build_deep_http_fetcher()(request, bounds)
