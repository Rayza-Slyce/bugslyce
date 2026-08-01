"""Tests for bounded content-discovery negative baselines."""

from __future__ import annotations

from decimal import Decimal

import pytest

from bugslyce.recon.content_run import (
    BASELINE_CLASSIFICATION_CONVENTIONAL,
    BASELINE_CLASSIFICATION_FAILED,
    BASELINE_CLASSIFICATION_STABLE_FALLBACK,
    BASELINE_CLASSIFICATION_STABLE_REDIRECT,
    BASELINE_CLASSIFICATION_UNSTABLE,
    BASELINE_POLICY_GOBUSTER,
    BASELINE_POLICY_INTERNAL_COMPARATOR,
    BASELINE_POLICY_REFUSE,
    ContentBaselineObservation,
    calculate_content_comparator_runtime_budget,
    classify_content_discovery_baseline,
    collect_content_discovery_baseline,
    response_comparison_signature,
)
from bugslyce.recon.http_enforcement import HTTPRedirectHop, InternalHTTPResponse
from bugslyce.recon.http_enforcement import InternalHTTPExecutionError


ORIGIN = "http://app.example.test:3000/"


def test_unpaced_comparator_budgets_scale_with_candidate_count() -> None:
    quick = calculate_content_comparator_runtime_budget(25, None)
    standard = calculate_content_comparator_runtime_budget(220, None)
    deep = calculate_content_comparator_runtime_budget(1753, None)

    assert quick == 85
    assert standard == 280
    assert deep == 1813
    assert quick < standard < deep
    assert deep > 120


def test_paced_deep_comparator_budget_covers_start_spacing_and_overhead() -> None:
    at_two = calculate_content_comparator_runtime_budget(1753, Decimal("2"))
    at_one = calculate_content_comparator_runtime_budget(1753, Decimal("1"))
    at_half = calculate_content_comparator_runtime_budget(1753, Decimal("0.5"))

    assert at_two == 2690
    assert at_two > Decimal("876.5")
    assert at_one == 3566
    assert at_one > 1753
    assert at_half == 5319
    assert at_two < at_one < at_half


def test_comparator_budget_is_deterministic_and_capped_at_two_hours() -> None:
    assert calculate_content_comparator_runtime_budget(1753, Decimal("2")) == 2690
    assert calculate_content_comparator_runtime_budget(1753, Decimal("2")) == 2690
    assert calculate_content_comparator_runtime_budget(4096, Decimal("0.1")) == 7200


def test_variable_body_conventional_404_selects_gobuster() -> None:
    observations = tuple(
        _observation(
            f"{ORIGIN}.bugslyce-negative-{index}",
            status=404,
            body=f"missing-{index}".encode(),
        )
        for index in range(3)
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_CONVENTIONAL
    assert decision.selected_policy == BASELINE_POLICY_GOBUSTER


def test_identical_conventional_410_selects_gobuster() -> None:
    observations = tuple(
        _observation(f"{ORIGIN}.bugslyce-negative-{index}", status=410, body=b"gone")
        for index in range(3)
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_CONVENTIONAL
    assert decision.selected_policy == BASELINE_POLICY_GOBUSTER


def test_mixed_404_and_410_is_unstable() -> None:
    observations = tuple(
        _observation(
            f"{ORIGIN}.bugslyce-negative-{index}",
            status=status,
            body=b"missing",
        )
        for index, status in enumerate((404, 410, 404))
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_UNSTABLE
    assert decision.selected_policy == BASELINE_POLICY_REFUSE


@pytest.mark.parametrize("status", [200, 403])
def test_identical_non_error_or_soft_error_selects_internal_comparator(status: int) -> None:
    observations = tuple(
        _observation(
            f"{ORIGIN}.bugslyce-negative-{index}",
            status=status,
            body=b"stable application shell",
        )
        for index in range(3)
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_STABLE_FALLBACK
    assert decision.selected_policy == BASELINE_POLICY_INTERNAL_COMPARATOR
    assert decision.comparison_signature is not None


def test_stable_redirect_fallback_includes_hop_signature() -> None:
    observations = tuple(
        _observation(
            f"{ORIGIN}.bugslyce-negative-{index}",
            status=200,
            body=b"login",
            final_url=f"{ORIGIN}login",
            redirects=((302, f"{ORIGIN}login"),),
        )
        for index in range(3)
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_STABLE_REDIRECT
    assert decision.selected_policy == BASELINE_POLICY_INTERNAL_COMPARATOR


@pytest.mark.parametrize("vary", ["status", "length", "hash", "final_url", "redirect"])
def test_required_signature_variation_is_unstable(vary: str) -> None:
    observations = [
        _observation(
            f"{ORIGIN}.bugslyce-negative-{index}",
            status=200,
            body=b"stable shell",
        )
        for index in range(3)
    ]
    request_url = observations[1].request_url
    if vary == "status":
        observations[1] = _observation(request_url, status=201, body=b"stable shell")
    elif vary == "length":
        observations[1] = _observation(request_url, status=200, body=b"longer shell")
    elif vary == "hash":
        observations[1] = _observation(request_url, status=200, body=b"stable sheLl")
    elif vary == "final_url":
        observations[1] = _observation(
            request_url,
            status=200,
            body=b"stable shell",
            final_url=f"{ORIGIN}other",
        )
    else:
        observations[1] = _observation(
            request_url,
            status=200,
            body=b"stable shell",
            final_url=f"{ORIGIN}login",
            redirects=((302, f"{ORIGIN}login"),),
        )

    decision = classify_content_discovery_baseline(ORIGIN, tuple(observations))

    assert decision.classification == BASELINE_CLASSIFICATION_UNSTABLE
    assert decision.selected_policy == BASELINE_POLICY_REFUSE


def test_failed_observation_selects_controlled_refusal() -> None:
    observations = (
        _observation(f"{ORIGIN}.bugslyce-negative-0", status=200, body=b"shell"),
        ContentBaselineObservation.failed(
            f"{ORIGIN}.bugslyce-negative-1",
            "transport_error",
        ),
        _observation(f"{ORIGIN}.bugslyce-negative-2", status=200, body=b"shell"),
    )

    decision = classify_content_discovery_baseline(ORIGIN, observations)

    assert decision.classification == BASELINE_CLASSIFICATION_FAILED
    assert decision.selected_policy == BASELINE_POLICY_REFUSE
    assert decision.completed_observations == 2


def test_collection_uses_three_distinct_same_origin_urls_without_retry() -> None:
    executor = _SequenceExecutor(
        [_response("unused", status=404, body=b"not found") for _ in range(3)]
    )
    tokens = iter(("fixed-one", "fixed-two", "fixed-three"))

    decision = collect_content_discovery_baseline(
        ORIGIN,
        executor,
        token_factory=lambda: next(tokens),
    )

    assert decision.classification == BASELINE_CLASSIFICATION_CONVENTIONAL
    assert executor.urls == [
        f"{ORIGIN}.bugslyce-negative-fixed-one",
        f"{ORIGIN}.bugslyce-negative-fixed-two",
        f"{ORIGIN}.bugslyce-negative-fixed-three",
    ]
    assert all("?" not in url for url in executor.urls)


def test_failed_collection_still_makes_only_three_required_observations() -> None:
    executor = _FailingExecutor()
    tokens = iter(("fixed-one", "fixed-two", "fixed-three"))

    decision = collect_content_discovery_baseline(
        ORIGIN,
        executor,
        token_factory=lambda: next(tokens),
    )

    assert decision.classification == BASELINE_CLASSIFICATION_FAILED
    assert decision.completed_observations == 2
    assert len(executor.urls) == 3


def test_redirect_comparison_requires_the_complete_redirect_signature() -> None:
    baseline = _response(
        f"{ORIGIN}missing",
        body=b"login",
        final_url=f"{ORIGIN}login",
        redirects=((302, f"{ORIGIN}login"),),
    )
    same = _response(
        f"{ORIGIN}candidate",
        body=b"login",
        final_url=f"{ORIGIN}login",
        redirects=((302, f"{ORIGIN}login"),),
    )
    different = _response(
        f"{ORIGIN}other",
        body=b"login",
        final_url=f"{ORIGIN}login",
        redirects=((301, f"{ORIGIN}login"),),
    )

    assert response_comparison_signature(baseline) == response_comparison_signature(same)
    assert response_comparison_signature(baseline) != response_comparison_signature(different)


def test_comparison_signature_retains_same_length_different_hash() -> None:
    baseline = _response("http://app.example.test:3000/missing", body=b"hash-A")
    candidate = _response("http://app.example.test:3000/real", body=b"hash-B")

    assert len(baseline.body) == len(candidate.body)
    assert response_comparison_signature(baseline) != response_comparison_signature(candidate)


def _observation(
    request_url: str,
    *,
    status: int,
    body: bytes,
    final_url: str | None = None,
    redirects: tuple[tuple[int, str], ...] = (),
) -> ContentBaselineObservation:
    response = _response(
        request_url,
        status=status,
        body=body,
        final_url=final_url,
        redirects=redirects,
    )
    return ContentBaselineObservation.complete(request_url, response)


def _response(
    request_url: str,
    *,
    status: int = 200,
    body: bytes = b"stable",
    final_url: str | None = None,
    redirects: tuple[tuple[int, str], ...] = (),
) -> InternalHTTPResponse:
    redirect_hops = tuple(
        HTTPRedirectHop(
            status_code=hop_status,
            source_url=request_url,
            destination_url=destination,
        )
        for hop_status, destination in redirects
    )
    return InternalHTTPResponse(
        requested_url=request_url,
        final_url=final_url or request_url,
        status_code=status,
        headers=(),
        body=body,
        elapsed_seconds=0.01,
        redirects=redirect_hops,
    )


class _SequenceExecutor:
    def __init__(self, responses: list[InternalHTTPResponse]) -> None:
        self.responses = list(responses)
        self.urls: list[str] = []

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        response = self.responses.pop(0)
        return InternalHTTPResponse(
            requested_url=url,
            final_url=(url if response.final_url == "unused" else response.final_url),
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
            elapsed_seconds=response.elapsed_seconds,
            redirects=response.redirects,
        )


class _FailingExecutor:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(self, url: str, **_kwargs) -> InternalHTTPResponse:
        self.urls.append(url)
        if len(self.urls) == 2:
            raise InternalHTTPExecutionError("scope refused before transport")
        return _response(url, status=404, body=b"missing")
