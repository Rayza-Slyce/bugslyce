"""Bounded standard-library HTTP fetcher for future Deep metadata collection.

This module provides a transport primitive only. It does not expose CLI
commands, write files, create directories, crawl, submit forms, authenticate,
execute browser JavaScript, call external tools, or enable Deep Recon.
"""

from __future__ import annotations

from time import perf_counter
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
)
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse


USER_AGENT = "BugSlyce/0.3 authorised-recon"


def urllib_deep_http_fetcher(
    request: DeepCollectionRequest,
    bounds: DeepCollectionBounds,
) -> DeepHTTPResponse:
    """Fetch one bounded HTTP response using the Python standard library."""

    method = request.method.upper().strip()
    if method not in {"GET", "HEAD"}:
        raise ValueError("method_not_allowed")

    parsed = urlparse(request.url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("unsupported_scheme")
    if not parsed.hostname:
        raise ValueError("missing_hostname")
    if parsed.username or parsed.password:
        raise ValueError("url_userinfo_not_allowed")
    if parsed.fragment:
        raise ValueError("url_fragment_not_allowed")
    if parsed.query and not bounds.allow_query_strings:
        raise ValueError("query_string_not_allowed")

    urllib_request = Request(
        request.url,
        headers={"User-Agent": USER_AGENT},
        method=method,
    )
    opener = build_opener(_NoRedirectHandler)
    started = perf_counter()
    try:
        response = opener.open(urllib_request, timeout=bounds.timeout_seconds)
    except HTTPError as error:
        response = error
    elapsed = perf_counter() - started

    body = response.read(bounds.max_response_bytes + 1)
    return DeepHTTPResponse(
        url=request.url,
        final_url=_response_url(response, request.url),
        status_code=_response_status(response),
        headers=tuple((str(name), str(value)) for name, value in response.headers.items()),
        body=body,
        elapsed_seconds=elapsed,
    )


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from automatically following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _response_status(response) -> int:
    status = getattr(response, "status", None)
    if status is not None:
        return int(status)
    code = getattr(response, "code", None)
    if code is not None:
        return int(code)
    return int(response.getcode())


def _response_url(response, fallback: str) -> str:
    geturl = getattr(response, "geturl", None)
    if geturl is None:
        return fallback
    return str(geturl() or fallback)
