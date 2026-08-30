"""WP4B RED contracts for bounded recursive evidence feedback."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import importlib
from pathlib import Path

import pytest

from bugslyce.core.models import Evidence
from bugslyce.recon.deep_html_route_extraction import (
    build_deep_html_route_extraction,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_enforcement import (
    HTTPRateRejected,
    HTTPTransportFailure,
    internal_http_executors_share_enforcement_state,
)
from bugslyce.recon.native_content_discovery import (
    NativeContentDiscoveryLimits,
    NativeContentDiscoveryPlan,
    NativeContentDiscoveryRequest,
)
from bugslyce.recon.programme_orchestration import (
    build_programme_orchestration_plan,
)

from test_native_content_discovery import (
    PROFILE,
    _child_state,
    _executor,
    _runtime,
    _state,
)


def _recursive_module():
    return importlib.import_module("bugslyce.recon.recursive_evidence_feedback")


def _state_with_evidence(
    runtime,
    *evidence_ids: str,
    child: bool = False,
):
    state = _child_state(runtime) if child else _state(runtime)
    return replace(
        state,
        evidence=[
            Evidence(
                id=evidence_id,
                source_file=f"raw/{evidence_id.lower()}.txt",
                evidence_type="recursive_feedback_source",
                value="Retained synthetic source evidence",
                context={"stage": "offline_extraction"},
            )
            for evidence_id in evidence_ids
        ],
    )


def _empty_source_collection() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )


def _source_item(
    *,
    url: str,
    body: bytes,
    content_type: str,
    evidence_ids: tuple[str, ...],
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", content_type),),
        body_preview=body[:500].decode("utf-8", errors="replace"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="policy_allowed",
        evidence_ids=evidence_ids,
        body=body,
    )


def _source_collection(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _empty_html_extraction():
    return build_deep_html_route_extraction(_empty_source_collection())


def _empty_javascript_extraction():
    return build_deep_javascript_route_extraction(_empty_source_collection())


def _sitemap_item(
    *,
    origin: str = "https://app.example.test",
    routes: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> DeepMetadataCollectedItem:
    url = f"{origin}/sitemap.xml"
    return DeepMetadataCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", "application/xml"),),
        body_preview="<urlset>...</urlset>",
        body_sha256=f"hash-{origin}",
        body_bytes=64,
        elapsed_seconds=0.01,
        source="metadata_coverage",
        reason="policy_allowed",
        evidence_ids=evidence_ids,
        sitemap_route_references=routes,
    )


def _metadata_collection(
    *items: DeepMetadataCollectedItem,
) -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _empty_metadata_collection() -> DeepMetadataCollectionResult:
    return _metadata_collection()


def _root_plan(*urls: str) -> NativeContentDiscoveryPlan:
    requests = tuple(
        NativeContentDiscoveryRequest(
            url=url,
            canonical_origin=(
                f"{url.split('://', 1)[0]}://{url.split('://', 1)[1].split('/', 1)[0]}"
            ),
            depth=0,
            selection_reason="profile_wordlist",
            evidence_ids=(),
        )
        for url in urls
    )
    return NativeContentDiscoveryPlan(
        profile=PROFILE,
        limits=NativeContentDiscoveryLimits(
            maximum_total_candidate_requests=max(1, len(requests)),
            maximum_candidate_requests_per_origin=max(1, len(requests)),
        ),
        baseline_requests_per_origin=3,
        candidate_requests_planned=len(requests),
        requests=requests,
    )


def _limits(module, *, total: int = 8, per_origin: int = 4):
    return module.RecursiveEvidenceFeedbackLimits(
        maximum_total_candidate_requests=total,
        maximum_candidate_requests_per_origin=per_origin,
        maximum_depth=1,
    )


def _build_plan(
    module,
    runtime,
    state,
    orchestration,
    *,
    root_plan: NativeContentDiscoveryPlan | None = None,
    metadata: DeepMetadataCollectionResult | None = None,
    html=None,
    javascript=None,
    source_depth: int = 0,
    limits=None,
):
    return module.build_recursive_evidence_feedback_plan(
        runtime,
        state,
        orchestration,
        root_plan=root_plan or _root_plan(),
        metadata_collection=metadata or _empty_metadata_collection(),
        html_extraction=html or _empty_html_extraction(),
        javascript_extraction=javascript or _empty_javascript_extraction(),
        source_depth=source_depth,
        limits=limits or _limits(module),
    )


def test_later_sitemap_evidence_selects_one_depth_one_documentation_route_with_provenance(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-SITEMAP-DOCS")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs/websocket-api",),
            evidence_ids=("EVID-SITEMAP-DOCS",),
        )
    )
    module = _recursive_module()

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=metadata,
        limits=_limits(module, total=1, per_origin=1),
    )

    assert plan.maximum_depth == 1
    assert plan.source_depth == 0
    assert plan.baseline_requests_per_origin == 0
    assert plan.recursive_requests_planned == 1
    assert plan.budget_consumed == 1
    assert plan.budget_remaining == 0
    assert plan.requests == (
        NativeContentDiscoveryRequest(
            url="https://app.example.test/docs/websocket-api",
            canonical_origin="https://app.example.test",
            depth=1,
            selection_reason="sitemap_declared",
            evidence_ids=("EVID-SITEMAP-DOCS",),
        ),
    )
    assert plan.decisions[0].outcome == "selected"
    assert plan.decisions[0].reason == "selected_for_bounded_second_pass"


def test_semantic_html_and_javascript_evidence_select_but_lexical_noise_does_not(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-HTML-GUIDE", "EVID-JS-LIVE")
    orchestration = build_programme_orchestration_plan(runtime, state)
    html_source = _source_collection(
        _source_item(
            url="https://app.example.test/start",
            content_type="text/html",
            body=b'<html><a href="/guide">Guide</a></html>',
            evidence_ids=("EVID-HTML-GUIDE",),
        )
    )
    javascript_source = _source_collection(
        _source_item(
            url="https://app.example.test/app.js",
            content_type="application/javascript",
            body=(
                b'fetch("/api/live"); '
                b'const endpoint = "/api/live"; '
                b'const baseUrl = "/service/status"; '
                b'const descriptiveText = "/api/lexical-noise"; '
                b'self.__next_f.push([1, "/api/framework-state"]);'
            ),
            evidence_ids=("EVID-JS-LIVE",),
        )
    )
    html = build_deep_html_route_extraction(html_source)
    javascript = build_deep_javascript_route_extraction(javascript_source)
    javascript_by_url = {
        candidate.safe_resolved_url: candidate for candidate in javascript.candidates
    }
    assert set(javascript_by_url) == {
        "https://app.example.test/api/live",
        "https://app.example.test/service/status",
    }
    assert javascript_by_url["https://app.example.test/api/live"].semantic_contexts == (
        "request_call",
        "route_configuration",
    )
    assert javascript_by_url[
        "https://app.example.test/service/status"
    ].semantic_contexts == ("route_configuration",)
    module = _recursive_module()

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        html=html,
        javascript=javascript,
    )

    by_url = {request.url: request for request in plan.requests}
    assert set(by_url) == {
        "https://app.example.test/api/live",
        "https://app.example.test/service/status",
        "https://app.example.test/guide",
    }
    assert by_url["https://app.example.test/api/live"].selection_reason == (
        "javascript_request_call"
    )
    assert by_url["https://app.example.test/api/live"].evidence_ids == (
        "EVID-JS-LIVE",
    )
    assert by_url["https://app.example.test/service/status"].selection_reason == (
        "javascript_route_configuration"
    )
    assert by_url["https://app.example.test/service/status"].evidence_ids == (
        "EVID-JS-LIVE",
    )
    assert by_url["https://app.example.test/guide"].selection_reason == (
        "html_route_reference"
    )
    assert "lexical-noise" not in repr(plan)
    assert "framework-state" not in repr(plan)


def test_duplicate_sources_combine_provenance_and_depth_zero_url_is_not_recollected(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-HTML", "EVID-SITEMAP")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=(
                "https://app.example.test/admin",
                "https://app.example.test/docs",
            ),
            evidence_ids=("EVID-SITEMAP",),
        )
    )
    html = build_deep_html_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/start",
                content_type="text/html",
                body=b'<a href="/docs">Docs</a><a href="/admin">Admin</a>',
                evidence_ids=("EVID-HTML",),
            )
        )
    )
    module = _recursive_module()

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        root_plan=_root_plan("https://app.example.test/admin"),
        metadata=metadata,
        html=html,
    )

    assert tuple(request.url for request in plan.requests) == (
        "https://app.example.test/docs",
    )
    assert plan.requests[0].selection_reason == "sitemap_declared"
    assert plan.requests[0].evidence_ids == ("EVID-HTML", "EVID-SITEMAP")
    by_url = {decision.url: decision for decision in plan.decisions}
    assert by_url["https://app.example.test/admin"].outcome == "suppressed"
    assert by_url["https://app.example.test/admin"].reason == "already_collected"
    assert by_url["https://app.example.test/docs"].selection_reasons == (
        "sitemap_declared",
        "html_route_reference",
    )


def test_recursive_budgets_are_global_per_origin_and_order_independent(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(
        runtime,
        "EVID-WP4A-CHILD",
        "EVID-APP-SITEMAP",
        "EVID-API-SITEMAP",
        child=True,
    )
    orchestration = build_programme_orchestration_plan(runtime, state)
    app = _sitemap_item(
        origin="https://app.example.test",
        routes=(
            "https://app.example.test/b",
            "https://app.example.test/a",
        ),
        evidence_ids=("EVID-APP-SITEMAP",),
    )
    api = _sitemap_item(
        origin="https://api.example.test",
        routes=(
            "https://api.example.test/b",
            "https://api.example.test/a",
        ),
        evidence_ids=("EVID-API-SITEMAP",),
    )
    module = _recursive_module()
    limits = _limits(module, total=2, per_origin=1)

    normal = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=_metadata_collection(app, api),
        limits=limits,
    )
    reversed_inputs = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=_metadata_collection(api, app),
        limits=limits,
    )

    assert reversed_inputs == normal
    assert tuple(request.url for request in normal.requests) == (
        "https://api.example.test/a",
        "https://app.example.test/a",
    )
    assert normal.budget_consumed == 2
    assert normal.budget_remaining == 0
    assert {decision.reason for decision in normal.decisions if decision.outcome != "selected"} == {
        "per_origin_limit_exceeded",
    }
    total_limited = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=_metadata_collection(app, api),
        limits=_limits(module, total=1, per_origin=2),
    )
    assert total_limited.budget_consumed == 1
    assert "total_request_limit_exceeded" in {
        decision.reason
        for decision in total_limited.decisions
        if decision.outcome != "selected"
    }


def test_maximum_depth_one_stops_depth_one_evidence_before_depth_two(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-DEPTH-ONE")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/deeper",),
            evidence_ids=("EVID-DEPTH-ONE",),
        )
    )
    module = _recursive_module()
    with pytest.raises(ValueError, match="depth"):
        module.RecursiveEvidenceFeedbackLimits(
            maximum_total_candidate_requests=2,
            maximum_candidate_requests_per_origin=2,
            maximum_depth=2,
        )

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=metadata,
        source_depth=1,
    )

    assert plan.requests == ()
    assert plan.budget_consumed == 0
    assert plan.decisions[0].outcome == "suppressed"
    assert plan.decisions[0].reason == "depth_exhausted"
    assert plan.decisions[0].depth == 2


def test_evidence_cannot_authorise_unknown_or_unmaterialised_origins(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-CROSS-ORIGIN")
    orchestration = build_programme_orchestration_plan(runtime, state)
    html = build_deep_html_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/start",
                content_type="text/html",
                body=(
                    b'<a href="https://ghost.example.test/docs">Ghost</a>'
                    b'<a href="https://service.other.test/docs">Other</a>'
                ),
                evidence_ids=("EVID-CROSS-ORIGIN",),
            )
        )
    )
    module = _recursive_module()

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        html=html,
    )

    assert plan.requests == ()
    by_url = {decision.url: decision for decision in plan.decisions}
    assert by_url["https://ghost.example.test/docs"].reason == (
        "unmaterialised_origin"
    )
    assert by_url["https://service.other.test/docs"].reason == (
        "programme_scope_unknown"
    )
    assert tuple(item.canonical_origin for item in orchestration.http_work_items) == (
        "https://app.example.test",
    )


def test_recursive_collection_uses_shared_native_http_state_and_no_external_commands(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-COLLECT-DOCS")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs",),
            evidence_ids=("EVID-COLLECT-DOCS",),
        )
    )
    module = _recursive_module()
    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=metadata,
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (200, b"bounded documentation response"),
    )
    elapsed_ticks = iter((100.0, 100.125))
    executor._monotonic = lambda: next(elapsed_ticks)
    try:
        result = module.run_recursive_evidence_feedback(
            runtime,
            state,
            orchestration,
            plan,
            root_plan=_root_plan(),
            metadata_collection=metadata,
            html_extraction=_empty_html_extraction(),
            javascript_extraction=_empty_javascript_extraction(),
            http_executor=executor,
        )
    finally:
        executor.close()

    assert internal_http_executors_share_enforcement_state(
        runtime.http_executor,
        executor,
    )
    assert tuple(request.url for request in transport.requests) == (
        "https://app.example.test/docs",
    )
    assert result.external_commands_started == 0
    assert result.requests_attempted == 1
    assert result.budget_consumed == 1
    assert len(result.collected) == 1
    assert result.collected[0].request == plan.requests[0]
    assert result.collected[0].status_code == 200
    assert result.collected[0].elapsed_seconds == 0.125
    assert result.collected[0].evidence_ids == ("EVID-COLLECT-DOCS",)


def test_recursive_execution_refuses_same_origin_request_not_backed_by_bound_evidence(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-TAMPER-BOUNDARY")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs",),
            evidence_ids=("EVID-TAMPER-BOUNDARY",),
        )
    )
    module = _recursive_module()
    canonical_plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=metadata,
    )
    tampered_plan = replace(
        canonical_plan,
        requests=(
            replace(
                canonical_plan.requests[0],
                url="https://app.example.test/not-in-retained-evidence",
            ),
        ),
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (200, b"must not be requested"),
    )
    try:
        with pytest.raises(ValueError, match="canonical|binding|evidence"):
            module.run_recursive_evidence_feedback(
                runtime,
                state,
                orchestration,
                tampered_plan,
                root_plan=_root_plan(),
                metadata_collection=metadata,
                html_extraction=_empty_html_extraction(),
                javascript_extraction=_empty_javascript_extraction(),
                http_executor=executor,
            )
    finally:
        executor.close()

    assert tampered_plan.requests[0].canonical_origin == "https://app.example.test"
    assert transport.requests == []


@pytest.mark.parametrize(
    ("responder", "expected_exception"),
    (
        (lambda _url: (429, b"rate limited"), HTTPRateRejected),
        (lambda _url: (_ for _ in ()).throw(OSError("synthetic failure")), HTTPTransportFailure),
    ),
)
def test_recursive_rate_rejection_and_transport_failure_remain_truthful(
    tmp_path: Path,
    responder,
    expected_exception,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-FAILURE")
    orchestration = build_programme_orchestration_plan(runtime, state)
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs",),
            evidence_ids=("EVID-FAILURE",),
        )
    )
    module = _recursive_module()
    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        metadata=metadata,
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        responder,
    )
    try:
        with pytest.raises(expected_exception):
            module.run_recursive_evidence_feedback(
                runtime,
                state,
                orchestration,
                plan,
                root_plan=_root_plan(),
                metadata_collection=metadata,
                html_extraction=_empty_html_extraction(),
                javascript_extraction=_empty_javascript_extraction(),
                http_executor=executor,
            )
    finally:
        executor.close()

    assert len(transport.requests) == 1


def test_recursive_stop_reasons_and_budget_accounting_are_machine_readable(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state_with_evidence(runtime, "EVID-JS-QUERY")
    orchestration = build_programme_orchestration_plan(runtime, state)
    javascript = build_deep_javascript_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/app.js",
                content_type="application/javascript",
                body=b'fetch("/api/items?tenant=blue");',
                evidence_ids=("EVID-JS-QUERY",),
            ),
            _source_item(
                url="https://app.example.test/no-evidence.js",
                content_type="application/javascript",
                body=b'fetch("/api/without-evidence");',
                evidence_ids=(),
            ),
            _source_item(
                url="https://app.example.test/unretained.js",
                content_type="application/javascript",
                body=b'fetch("/api/unretained-evidence");',
                evidence_ids=("EVID-NOT-IN-STATE",),
            ),
        )
    )
    module = _recursive_module()

    plan = _build_plan(
        module,
        runtime,
        state,
        orchestration,
        javascript=javascript,
    )

    assert plan.requests == ()
    assert plan.recursive_requests_planned == 0
    assert plan.budget_consumed == 0
    assert plan.budget_remaining == plan.limits.maximum_total_candidate_requests
    by_url = {decision.url: decision for decision in plan.decisions}
    assert by_url["https://app.example.test/api/items?tenant"].reason == (
        "query_string_not_allowed"
    )
    assert by_url["https://app.example.test/api/without-evidence"].reason == (
        "missing_evidence_provenance"
    )
    assert by_url["https://app.example.test/api/unretained-evidence"].reason == (
        "evidence_not_retained"
    )
    assert all(decision.outcome == "suppressed" for decision in plan.decisions)
