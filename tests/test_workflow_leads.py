"""Focused edge-case tests for shared concise workflow decisions."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qsl, urlparse

import pytest

from bugslyce.core.models import DiscoveredPath, Endpoint, ProjectState
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


@pytest.mark.parametrize(
    "urls",
    (
        (
            "https://portal.example.test/assets/password-meter.js",
            "https://portal.example.test/docs/account.css",
        ),
        (
            "https://portal.example.test/static/profile.js",
            "https://portal.example.test/styles/account.css",
        ),
    ),
)
def test_static_or_documentation_routes_do_not_create_account_workflows(
    urls: tuple[str, str],
) -> None:
    state = _state(
        endpoints=[
            _endpoint(url, f"EVID-STATIC-{index}")
            for index, url in enumerate(urls, start=1)
        ]
    )

    assert not _leads_for(state, "account_workflow")


def test_password_form_on_neutral_application_route_still_qualifies() -> None:
    url = "https://portal.example.test/workflow/start.html"
    orchestration = _orchestration(
        forms=(
            SimpleNamespace(
                safe_document_urls=(url,),
                safe_resolved_action_url="https://portal.example.test/workflow/continue",
                methods=("post",),
                control_summary=SimpleNamespace(password_controls=1),
                evidence_ids=("EVID-NEUTRAL-FORM",),
            ),
        )
    )

    leads = _leads_for(_state(), "account_workflow", orchestration)

    assert len(leads) == 1
    assert "directly observed form" in leads[0].why_it_matters
    assert leads[0].evidence_ids == ("EVID-NEUTRAL-FORM",)


def test_dynamic_account_routes_remain_supported() -> None:
    urls = (
        "https://portal.example.test/account.php",
        "https://portal.example.test/profile.php",
        "https://portal.example.test/recover-access",
    )

    leads = _leads_for(
        _state(
            endpoints=[
                _endpoint(url, f"EVID-DYNAMIC-{index}")
                for index, url in enumerate(urls, start=1)
            ]
        ),
        "account_workflow",
    )

    assert len(leads) == 1
    assert all(url in leads[0].covered_urls for url in urls)


@pytest.mark.parametrize(
    "static_source",
    (
        "https://portal.example.test/assets/session.js",
        "https://portal.example.test/static/login.js",
    ),
)
def test_static_deep_redirect_source_does_not_complete_account_threshold(
    static_source: str,
) -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://portal.example.test/account.php",
                "EVID-DYNAMIC-ACCOUNT",
            )
        ]
    )
    orchestration = _orchestration(
        redirects=(
            _redirect_observation(
                static_source,
                "https://portal.example.test/maintenance",
                source_auth=True,
                target_auth=False,
                evidence_id="EVID-STATIC-REDIRECT",
            ),
        )
    )

    assert not _leads_for(state, "account_workflow", orchestration)


def test_two_static_deep_redirects_do_not_combine_into_account_workflow() -> None:
    orchestration = _orchestration(
        redirects=(
            _redirect_observation(
                "https://portal.example.test/assets/session.js",
                "https://portal.example.test/maintenance",
                source_auth=True,
                target_auth=False,
                evidence_id="EVID-STATIC-A",
            ),
            _redirect_observation(
                "https://portal.example.test/static/login.js",
                "https://portal.example.test/unavailable",
                source_auth=True,
                target_auth=False,
                evidence_id="EVID-STATIC-B",
            ),
        )
    )

    assert not _leads_for(_state(), "account_workflow", orchestration)


def test_static_deep_redirect_target_does_not_complete_account_threshold() -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://portal.example.test/account.php",
                "EVID-DYNAMIC-ACCOUNT",
            )
        ]
    )
    orchestration = _orchestration(
        redirects=(
            _redirect_observation(
                "https://portal.example.test/private",
                "https://portal.example.test/static/login.js",
                source_auth=False,
                target_auth=True,
                evidence_id="EVID-STATIC-TARGET",
            ),
        )
    )

    assert not _leads_for(state, "account_workflow", orchestration)


@pytest.mark.parametrize(
    ("source", "target", "source_auth", "target_auth", "expected_label"),
    (
        (
            "https://portal.example.test/private",
            "https://portal.example.test/signin",
            False,
            True,
            "authentication redirects",
        ),
        (
            "https://portal.example.test/member/home",
            "https://portal.example.test/login",
            False,
            True,
            "authentication redirects",
        ),
        (
            "https://portal.example.test/account",
            "https://portal.example.test/maintenance",
            True,
            False,
            "account-route redirects",
        ),
    ),
)
def test_deep_redirect_urls_are_reclassified_by_shared_route_semantics(
    source: str,
    target: str,
    source_auth: bool,
    target_auth: bool,
    expected_label: str,
) -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://portal.example.test/account.php",
                "EVID-CORRELATED-ACCOUNT",
            )
        ]
    )
    redirect = _redirect_observation(
        source,
        target,
        source_auth=source_auth,
        target_auth=target_auth,
        evidence_id="EVID-DEEP-REDIRECT",
    )

    first = _leads_for(
        state,
        "account_workflow",
        _orchestration(redirects=(redirect,)),
    )
    second = _leads_for(
        state,
        "account_workflow",
        _orchestration(redirects=(redirect,)),
    )

    assert first == second
    assert len(first) == 1
    assert expected_label in first[0].summary
    assert source in first[0].summary
    assert target in first[0].summary
    assert "EVID-DEEP-REDIRECT" in first[0].evidence_ids


def test_dynamic_session_and_account_php_deep_sources_remain_supported() -> None:
    orchestration = _orchestration(
        redirects=(
            _redirect_observation(
                "https://portal.example.test/session",
                "https://portal.example.test/maintenance",
                source_auth=True,
                target_auth=False,
                evidence_id="EVID-SESSION",
            ),
            _redirect_observation(
                "https://portal.example.test/account.php",
                "https://portal.example.test/unavailable",
                source_auth=True,
                target_auth=False,
                evidence_id="EVID-ACCOUNT-PHP",
            ),
        )
    )

    leads = _leads_for(_state(), "account_workflow", orchestration)

    assert len(leads) == 1
    assert "account-route redirects" in leads[0].summary
    assert leads[0].evidence_ids == ("EVID-ACCOUNT-PHP", "EVID-SESSION")


@pytest.mark.parametrize(
    ("source", "target", "expected_label", "unexpected_label"),
    (
        (
            "https://portal.example.test/account",
            "/maintenance",
            "account-route redirects",
            "authentication redirects",
        ),
        (
            "https://portal.example.test/member/home",
            "/signin",
            "authentication redirects",
            "account-route redirects",
        ),
        (
            "https://portal.example.test/private",
            "/login",
            "authentication redirects",
            "account-route redirects",
        ),
        (
            "https://portal.example.test/login",
            "/dashboard",
            "account-route redirects",
            "authentication redirects",
        ),
    ),
)
def test_account_redirect_classification_uses_observed_target_semantics(
    source: str,
    target: str,
    expected_label: str,
    unexpected_label: str,
) -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://portal.example.test/profile",
                "EVID-CORRELATED-ACCOUNT-ROUTE",
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=source,
                status_code=302,
                content_length=0,
                redirect_location=target,
                source="bounded-followup",
                evidence_ids=["EVID-REDIRECT"],
                tags=[],
            )
        ]
    )

    leads = _leads_for(state, "account_workflow")

    assert len(leads) == 1
    assert expected_label in leads[0].summary
    assert unexpected_label not in leads[0].summary
    assert source in leads[0].summary
    assert target.lstrip("/") in leads[0].summary


@pytest.mark.parametrize("status_code", (401, 403))
def test_account_access_responses_remain_access_boundaries(status_code: int) -> None:
    base = "https://portal.example.test"
    state = _state(
        endpoints=[_endpoint(f"{base}/profile", "EVID-PROFILE")],
        discovered_paths=[
            DiscoveredPath(
                url=f"{base}/account",
                status_code=status_code,
                content_length=0,
                redirect_location=None,
                source="bounded-followup",
                evidence_ids=["EVID-BOUNDARY"],
                tags=[],
            )
        ],
    )

    lead = _leads_for(state, "account_workflow")[0]

    assert "access boundaries" in lead.summary
    assert "authentication redirects" not in lead.summary


def test_object_references_on_different_origins_do_not_combine() -> None:
    state = _state(
        endpoints=[
            _endpoint("https://a.example.test/view?id=1", "EVID-A-1"),
            _endpoint("https://b.example.test/view?id=2", "EVID-B-1"),
        ]
    )

    assert not _leads_for(state, "object_reference_surface")


def test_object_references_combine_only_within_each_origin() -> None:
    state = _state(
        endpoints=[
            _endpoint("https://a.example.test/view?id=1", "EVID-A-1"),
            _endpoint("https://a.example.test/history?id=2", "EVID-A-2"),
            _endpoint("https://b.example.test/view?id=3", "EVID-B-1"),
            _endpoint("https://b.example.test/history?id=4", "EVID-B-2"),
        ]
    )

    first = _leads_for(state, "object_reference_surface")
    second = _leads_for(state, "object_reference_surface")

    assert first == second
    assert len(first) == 2
    assert all(
        len({urlparse(url).hostname for url in lead.covered_urls}) == 1
        for lead in first
    )
    assert first[0].covered_urls == (
        "https://a.example.test/history",
        "https://a.example.test/view",
    )
    assert first[1].covered_urls == (
        "https://b.example.test/history",
        "https://b.example.test/view",
    )


def test_account_workflows_are_split_by_origin() -> None:
    state = _state(
        endpoints=[
            _endpoint("https://a.example.test/signin", "EVID-A-SIGNIN"),
            _endpoint("https://a.example.test/profile", "EVID-A-PROFILE"),
            _endpoint("https://b.example.test/login", "EVID-B-LOGIN"),
            _endpoint("https://b.example.test/account", "EVID-B-ACCOUNT"),
        ]
    )

    leads = _leads_for(state, "account_workflow")
    repeated = _leads_for(state, "account_workflow")

    assert leads == repeated
    assert len(leads) == 2
    assert all(
        len({urlparse(url).netloc for url in lead.covered_urls}) == 1
        for lead in leads
    )


def test_schemes_and_ports_are_distinct_workflow_origins() -> None:
    state = _state(
        endpoints=[
            _endpoint("http://portal.example.test/signin", "EVID-HTTP"),
            _endpoint("https://portal.example.test/profile", "EVID-HTTPS"),
            _endpoint("http://portal.example.test:8080/account", "EVID-ALT"),
        ]
    )

    assert not _leads_for(state, "account_workflow")


def test_explicit_and_implicit_default_ports_share_one_origin() -> None:
    state = _state(
        endpoints=[
            _endpoint("http://portal.example.test/signin", "EVID-IMPLICIT"),
            _endpoint("http://portal.example.test:80/profile", "EVID-EXPLICIT"),
        ]
    )

    leads = _leads_for(state, "account_workflow")

    assert len(leads) == 1
    assert leads[0].signal.endswith("origin=http://portal.example.test")


def test_query_inventory_is_split_by_origin_and_uses_neutral_action_wording() -> None:
    parameter = SimpleNamespace(
        name="record_id",
        contexts=("html_route_query",),
        safe_form_action_urls=(),
        safe_route_urls=(
            "https://a.example.test/view?record_id=1",
            "https://a.example.test/history?record_id=2",
            "https://b.example.test/view?record_id=3",
        ),
        safe_source_urls=(),
        occurrence_count=3,
        evidence_ids=("EVID-PARAM",),
    )

    leads = _leads_for(
        _state(),
        "object_reference_surface",
        _orchestration(parameters=(parameter,)),
    )

    assert len(leads) == 1
    assert all("a.example.test" in url for url in leads[0].covered_urls)
    assert "retained responses and directly observed URLs" in (
        leads[0].suggested_manual_action
    )
    assert "account contexts" not in leads[0].suggested_manual_action
    assert "active parameter testing is outside BugSlyce v1" in (
        leads[0].suggested_manual_action
    )


def _leads_for(
    state: ProjectState,
    category: str,
    orchestration: object | None = None,
):
    return tuple(
        lead
        for lead in build_grouped_workflow_leads(state, orchestration)
        if lead.category == category
    )


def _state(
    *,
    endpoints: list[Endpoint] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="workflow-edge-test",
        input_dir="/tmp/workflow-edge-test",
        processed_files=[],
        scope_summary="Synthetic authorised scope.",
        assets=[],
        http_services=[],
        endpoints=endpoints or [],
        port_services=[],
        http_artifacts=[],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-19T00:00:00Z",
    )


def _endpoint(url: str, evidence_id: str) -> Endpoint:
    parsed = urlparse(url)
    return Endpoint(
        url=url,
        hostname=parsed.hostname or "",
        path=parsed.path,
        query_params=[name for name, _value in parse_qsl(parsed.query)],
        evidence_ids=[evidence_id],
        tags=[],
    )


def _orchestration(
    *,
    forms: tuple[SimpleNamespace, ...] = (),
    parameters: tuple[SimpleNamespace, ...] = (),
    redirects: tuple[SimpleNamespace, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        form_inventory=SimpleNamespace(forms=forms),
        parameter_inventory=SimpleNamespace(parameters=parameters),
        html_route_extraction=SimpleNamespace(routes=()),
        javascript_route_extraction=SimpleNamespace(candidates=()),
        redirect_auth_flow_review=SimpleNamespace(observations=redirects),
    )


def _redirect_observation(
    source_url: str,
    target_url: str,
    *,
    source_auth: bool,
    target_auth: bool,
    evidence_id: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        safe_source_url=source_url,
        safe_resolved_target_url=target_url,
        source_path_auth_related=source_auth,
        target_path_auth_related=target_auth,
        evidence_ids=(evidence_id,),
    )
