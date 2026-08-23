"""Focused edge-case tests for shared concise workflow decisions."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlparse

import pytest

from bugslyce.core.models import DiscoveredPath, Endpoint, ProjectState
from bugslyce.triage import workflow_leads as workflow_leads_module
from bugslyce.triage.workflow_leads import WorkflowLead, build_grouped_workflow_leads


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


def test_account_workflow_retains_typed_form_observations_without_values() -> None:
    secret_value = "R3B-SECRET-FIELD-VALUE-DO-NOT-RETAIN"
    document_url = f"https://portal.example.test/login?password={secret_value}"
    action_url = "https://portal.example.test/session"
    orchestration = _orchestration(
        forms=(
            SimpleNamespace(
                safe_document_urls=(document_url,),
                safe_resolved_action_url=action_url,
                methods=("post", "GET", "post"),
                control_summary=SimpleNamespace(password_controls=1),
                evidence_ids=("EVID-FORM-B", "EVID-FORM-A", "EVID-FORM-A"),
            ),
        ),
        parameters=(
            _form_parameter("username", document_url, action_url),
            _form_parameter("password", document_url, action_url, value=secret_value),
        ),
    )

    lead = _leads_for(_state(), "account_workflow", orchestration)[0]

    assert secret_value not in lead.covered_urls
    assert secret_value not in lead.summary
    (
        account_retention_type,
        _object_retention_type,
        observation_type,
        observation_kind,
    ) = _workflow_retention_api()
    assert isinstance(lead.retention, account_retention_type)
    assert lead.retention.origin == "https://portal.example.test"
    assert all(isinstance(item, observation_type) for item in lead.retention.observations)
    form = next(
        item
        for item in lead.retention.observations
        if item.kind is observation_kind.OBSERVED_FORM
    )
    assert form.url == "https://portal.example.test/login"
    assert form.methods == ("GET", "POST")
    assert form.field_names == ("password", "username")
    assert form.evidence_ids == ("EVID-FORM-A", "EVID-FORM-B")
    assert form.redirect_target_url is None
    assert secret_value not in form.url
    assert secret_value not in form.field_names
    assert all(
        secret_value
        not in (
            item.url,
            item.redirect_target_url or "",
            *item.methods,
            *item.field_names,
            *item.evidence_ids,
        )
        for item in lead.retention.observations
    )


def test_account_workflow_retains_authoritative_redirect_target_and_evidence() -> None:
    source = "https://portal.example.test/private?return=discarded"
    target = "https://portal.example.test/signin?next=discarded"
    state = _state(
        endpoints=[_endpoint("https://portal.example.test/profile", "EVID-PROFILE")]
    )
    orchestration = _orchestration(
        redirects=(
            _redirect_observation(
                source,
                target,
                source_auth=False,
                target_auth=True,
                evidence_id="EVID-REDIRECT",
            ),
        )
    )

    lead = _leads_for(state, "account_workflow", orchestration)[0]

    assert len(_leads_for(state, "account_workflow", orchestration)) == 1
    (
        account_retention_type,
        _object_retention_type,
        _observation_type,
        observation_kind,
    ) = _workflow_retention_api()
    assert isinstance(lead.retention, account_retention_type)
    redirect = next(
        item
        for item in lead.retention.observations
        if item.kind is observation_kind.AUTHENTICATION_REDIRECT
    )
    route = next(
        item
        for item in lead.retention.observations
        if item.kind is observation_kind.OBSERVED_ROUTE
    )
    assert redirect.url == "https://portal.example.test/private"
    assert redirect.redirect_target_url == "https://portal.example.test/signin"
    assert redirect.evidence_ids == ("EVID-REDIRECT",)
    assert route.redirect_target_url is None
    assert route.evidence_ids == ("EVID-PROFILE",)


def test_account_workflow_retention_is_deterministic_and_preserves_grouping() -> None:
    endpoints = [
        _endpoint("https://portal.example.test/profile", "EVID-PROFILE"),
        _endpoint(
            "https://portal.example.test/login?flow=first",
            "EVID-LOGIN-B",
        ),
        _endpoint("https://portal.example.test/account", "EVID-ACCOUNT"),
        _endpoint(
            "https://portal.example.test/login?flow=second",
            "EVID-LOGIN-A",
        ),
    ]

    forward = _leads_for(_state(endpoints=endpoints), "account_workflow")
    reverse = _leads_for(_state(endpoints=list(reversed(endpoints))), "account_workflow")

    assert len(forward) == 1
    (
        _account_retention_type,
        _object_retention_type,
        _observation_type,
        observation_kind,
    ) = _workflow_retention_api()
    assert forward == reverse
    assert len(forward[0].retention.observations) == 3
    assert tuple(item.url for item in forward[0].retention.observations) == tuple(
        sorted(item.url for item in forward[0].retention.observations)
    )
    assert forward[0].covered_urls == (
        "https://portal.example.test/account",
        "https://portal.example.test/login",
        "https://portal.example.test/profile",
    )
    login = next(
        item
        for item in forward[0].retention.observations
        if item.kind is observation_kind.OBSERVED_ROUTE
        and item.url == "https://portal.example.test/login"
    )
    assert login.evidence_ids == ("EVID-LOGIN-A", "EVID-LOGIN-B")


def test_object_reference_retains_canonical_parameter_names_without_values() -> None:
    secret_value = "R3B-OBJECT-ID-VALUE-DO-NOT-RETAIN"
    endpoints = [
        _endpoint(
            f"https://portal.example.test/view?record_id={secret_value}",
            "EVID-VIEW",
        ),
        _endpoint(
            "https://portal.example.test/history?record_id=123456",
            "EVID-HISTORY",
        ),
    ]

    lead = _leads_for(_state(endpoints=endpoints), "object_reference_surface")[0]

    assert secret_value not in lead.covered_urls
    assert secret_value not in lead.summary
    (
        _account_retention_type,
        object_retention_type,
        _observation_type,
        _observation_kind,
    ) = _workflow_retention_api()
    assert isinstance(lead.retention, object_retention_type)
    assert lead.retention.origin == "https://portal.example.test"
    assert lead.retention.parameter_names == ("record_id",)
    assert lead.covered_urls == (
        "https://portal.example.test/history",
        "https://portal.example.test/view",
    )
    assert secret_value not in lead.retention.parameter_names
    assert all(secret_value not in url for url in lead.covered_urls)


def test_object_reference_retention_is_deterministic_and_split_by_origin() -> None:
    endpoints = [
        _endpoint("https://a.example.test/view?record_id=1", "EVID-A-1"),
        _endpoint("https://a.example.test/history?record_id=2", "EVID-A-2"),
        _endpoint("https://a.example.test/audit?user_id=3", "EVID-A-3"),
        _endpoint("https://a.example.test/users?user_id=4", "EVID-A-4"),
        _endpoint("https://b.example.test/view?record_id=5", "EVID-B-1"),
        _endpoint("https://b.example.test/history?record_id=6", "EVID-B-2"),
    ]

    forward = _leads_for(_state(endpoints=endpoints), "object_reference_surface")
    reverse = _leads_for(
        _state(endpoints=list(reversed(endpoints))),
        "object_reference_surface",
    )

    assert len(forward) == 2
    _workflow_retention_api()
    assert forward == reverse
    assert tuple(item.retention.origin for item in forward) == (
        "https://a.example.test",
        "https://b.example.test",
    )
    assert forward[0].retention.parameter_names == ("record_id", "user_id")
    assert forward[1].retention.parameter_names == ("record_id",)
    assert forward[0].evidence_ids == (
        "EVID-A-1",
        "EVID-A-2",
        "EVID-A-3",
        "EVID-A-4",
    )
    assert forward[1].evidence_ids == ("EVID-B-1", "EVID-B-2")
    assert all(item.category == "object_reference_surface" for item in forward)

    sparse = _leads_for(
        _state(
            endpoints=[
                _endpoint("https://a.example.test/view?record_id=1", "EVID-ONE"),
                _endpoint("https://a.example.test/history?record_id=2", "EVID-TWO"),
            ]
        ),
        "object_reference_surface",
    )[0]
    dense = _leads_for(
        _state(
            endpoints=[
                _endpoint(
                    "https://a.example.test/view?record_id=1&user_id=3",
                    "EVID-ONE",
                ),
                _endpoint(
                    "https://a.example.test/history?record_id=2&user_id=4",
                    "EVID-TWO",
                ),
            ]
        ),
        "object_reference_surface",
    )[0]
    assert (
        sparse.category,
        sparse.retention.origin,
        sparse.covered_urls,
    ) == (
        dense.category,
        dense.retention.origin,
        dense.covered_urls,
    )
    assert sparse.retention.parameter_names == ("record_id",)
    assert dense.retention.parameter_names == ("record_id", "user_id")


def test_object_reference_public_evidence_is_permutation_invariant() -> None:
    endpoints = [
        _endpoint("https://portal.example.test/view?record_id=1", "EVID-OBJ-B"),
        _endpoint("https://portal.example.test/history?record_id=2", "EVID-OBJ-A"),
        _endpoint("https://portal.example.test/audit?record_id=3", "EVID-OBJ-C"),
    ]

    forward = _leads_for(_state(endpoints=endpoints), "object_reference_surface")
    reverse = _leads_for(
        _state(endpoints=list(reversed(endpoints))),
        "object_reference_surface",
    )

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0].evidence_ids == (
        "EVID-OBJ-A",
        "EVID-OBJ-B",
        "EVID-OBJ-C",
    )


def test_object_reference_public_evidence_is_sorted_before_cap() -> None:
    endpoints = [
        _endpoint(
            f"https://portal.example.test/item-{index}?record_id={index}",
            f"EVID-CAP-{index:02d}",
        )
        for index in reversed(range(15))
    ]
    expected = tuple(f"EVID-CAP-{index:02d}" for index in range(12))

    forward = _leads_for(_state(endpoints=endpoints), "object_reference_surface")
    reverse = _leads_for(
        _state(endpoints=list(reversed(endpoints))),
        "object_reference_surface",
    )

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0].evidence_ids == expected
    assert reverse[0].evidence_ids == expected


def test_account_public_and_retained_evidence_are_permutation_invariant() -> None:
    endpoints = [
        _endpoint(
            "https://portal.example.test/login?flow=first",
            "EVID-LOGIN-B",
        ),
        _endpoint("https://portal.example.test/profile", "EVID-PROFILE"),
        _endpoint(
            "https://portal.example.test/login?flow=second",
            "EVID-LOGIN-A",
        ),
    ]

    forward = _leads_for(_state(endpoints=endpoints), "account_workflow")
    reverse = _leads_for(
        _state(endpoints=list(reversed(endpoints))),
        "account_workflow",
    )

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0].evidence_ids == (
        "EVID-LOGIN-A",
        "EVID-LOGIN-B",
        "EVID-PROFILE",
    )
    (
        _account_retention_type,
        _object_retention_type,
        _observation_type,
        observation_kind,
    ) = _workflow_retention_api()
    login = next(
        item
        for item in forward[0].retention.observations
        if item.kind is observation_kind.OBSERVED_ROUTE
        and item.url == "https://portal.example.test/login"
    )
    assert login.evidence_ids == ("EVID-LOGIN-A", "EVID-LOGIN-B")


def test_workflow_retention_payloads_are_immutable_and_category_checked() -> None:
    (
        account_retention_type,
        object_retention_type,
        observation_type,
        observation_kind,
    ) = _workflow_retention_api()
    observation = observation_type(
        kind=observation_kind.OBSERVED_ROUTE,
        url="https://portal.example.test/profile",
        evidence_ids=("EVID-PROFILE",),
    )
    account_retention = account_retention_type(
        origin="https://portal.example.test",
        observations=(observation,),
    )
    object_retention = object_retention_type(
        origin="https://portal.example.test",
        parameter_names=("record_id",),
    )

    with pytest.raises(FrozenInstanceError):
        observation.url = "https://portal.example.test/changed"
    with pytest.raises(ValueError):
        _workflow_lead("account_workflow", retention=object_retention)
    with pytest.raises(ValueError):
        _workflow_lead("object_reference_surface", retention=account_retention)

    legacy = _workflow_lead("account_workflow")
    assert legacy.retention is None
    assert legacy.category == "account_workflow"
    assert legacy.covered_urls == ("https://portal.example.test/profile",)


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


def _workflow_retention_api():
    return (
        getattr(workflow_leads_module, "WorkflowAccountRetention"),
        getattr(workflow_leads_module, "WorkflowObjectReferenceRetention"),
        getattr(workflow_leads_module, "WorkflowAccountObservation"),
        getattr(workflow_leads_module, "WorkflowAccountObservationKind"),
    )


def _workflow_lead(category: str, *, retention=None) -> WorkflowLead:
    return WorkflowLead(
        title="Workflow retention compatibility fixture",
        priority="medium",
        category=category,
        summary="Existing grouped workflow.",
        why_it_matters="Review retained evidence.",
        suggested_manual_action="Review retained evidence.",
        representative_urls=("https://portal.example.test/profile",),
        covered_urls=("https://portal.example.test/profile",),
        evidence_ids=("EVID-PROFILE",),
        signal="direct evidence",
        retention=retention,
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


def _form_parameter(
    name: str,
    document_url: str,
    action_url: str,
    *,
    value: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        value=value,
        contexts=("form_control",),
        safe_form_action_urls=(action_url,),
        safe_route_urls=(),
        safe_source_urls=(document_url,),
        evidence_ids=(f"EVID-FIELD-{name.upper()}",),
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
