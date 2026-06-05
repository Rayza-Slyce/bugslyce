"""Tests for deterministic project state assembly."""

from __future__ import annotations

from pathlib import Path

from bugslyce.core.project import build_project_state


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_build_project_state_basic_saas() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")

    assert state.project_name == "basic_saas"
    assert len(state.processed_files) == 5
    assert "5 in-scope entries" in state.scope_summary
    assert state.evidence
    assert state.assets
    assert state.http_services
    assert state.endpoints
    assert state.generated_at


def test_assets_include_expected_fake_hosts() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    assets = {asset.hostname: asset for asset in state.assets}

    assert "app.example-bounty.test" in assets
    assert "api.example-bounty.test" in assets
    assert "staging.example-bounty.test" in assets
    assert "admin.example-bounty.test" in assets
    assert "cdn.example-bounty.test" in assets
    assert assets["app.example-bounty.test"].in_scope is True
    assert assets["assets.cdn.example-bounty.test"].in_scope is True


def test_duplicate_subdomains_and_urls_do_not_duplicate_assets_or_endpoints() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    asset_hosts = [asset.hostname for asset in state.assets]
    endpoint_urls = [endpoint.url for endpoint in state.endpoints]

    assert asset_hosts.count("app.example-bounty.test") == 1
    assert endpoint_urls.count("https://app.example-bounty.test/dashboard?org_id=acme-demo") == 1


def test_evidence_ids_are_generated_and_linked() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    evidence_ids = {item.id for item in state.evidence}

    assert "EVID-SCOPE-0001" in evidence_ids
    assert "EVID-HOST-0001" in evidence_ids
    assert "EVID-HTTP-0001" in evidence_ids
    assert "EVID-URL-0001" in evidence_ids
    assert "EVID-NOTE-0001" in evidence_ids
    assert all(evidence_id in evidence_ids for asset in state.assets for evidence_id in asset.evidence_ids)
    assert all(evidence_id in evidence_ids for endpoint in state.endpoints for evidence_id in endpoint.evidence_ids)


def test_every_asset_and_endpoint_has_evidence() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")

    assert all(asset.evidence_ids for asset in state.assets)
    assert all(endpoint.evidence_ids for endpoint in state.endpoints)


def test_httpx_records_become_http_services() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    services = {service.url: service for service in state.http_services}

    service = services["https://api.example-bounty.test/"]
    assert service.hostname == "api.example-bounty.test"
    assert service.status_code == 200
    assert service.title == "API Gateway"
    assert service.technologies == ["nginx"]
    assert service.content_length == 821
    assert service.evidence_ids == ["EVID-HTTP-0002"]


def test_endpoint_query_params_are_preserved() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    endpoints = {endpoint.url: endpoint for endpoint in state.endpoints}

    assert endpoints["https://app.example-bounty.test/account/settings?user_id=1001"].query_params == ["user_id"]
    assert endpoints["https://app.example-bounty.test/auth/callback?next=/dashboard"].query_params == ["next"]


def test_deterministic_tags_are_applied() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    assets = {asset.hostname: asset for asset in state.assets}
    endpoints = {endpoint.url: endpoint for endpoint in state.endpoints}

    assert "api" in assets["api.example-bounty.test"].tags
    assert "admin" in assets["admin.example-bounty.test"].tags
    assert "environment" in assets["staging.example-bounty.test"].tags
    assert "static_or_cdn" in assets["cdn.example-bounty.test"].tags

    account_endpoint = endpoints["https://app.example-bounty.test/account/settings?user_id=1001"]
    export_endpoint = endpoints["https://app.example-bounty.test/export?account_id=1001&format=csv"]
    callback_endpoint = endpoints["https://app.example-bounty.test/auth/callback?next=/dashboard"]
    api_endpoint = endpoints["https://api.example-bounty.test/v1/users?tenant_id=demo-tenant"]
    api_account_endpoint = endpoints[
        "https://api.example-bounty.test/v1/accounts/1001/orders?order_id=5001"
    ]
    static_endpoint = endpoints["https://cdn.example-bounty.test/static/app.js"]

    assert "auth_surface" in account_endpoint.tags
    assert "object_reference" in account_endpoint.tags
    assert "file_or_content_surface" in export_endpoint.tags
    assert "redirect_parameter" in callback_endpoint.tags
    assert "api_surface" in api_endpoint.tags
    assert "api_surface" in api_account_endpoint.tags
    assert "object_reference" in api_account_endpoint.tags
    assert "auth_surface" not in api_account_endpoint.tags
    assert "static_asset" in static_endpoint.tags


def test_missing_optional_files_do_not_crash_project_assembly(tmp_path: Path) -> None:
    (tmp_path / "subdomains.txt").write_text(
        "app.example-bounty.test\napp.example-bounty.test\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert state.project_name == tmp_path.name
    assert [asset.hostname for asset in state.assets] == ["app.example-bounty.test"]
    assert state.http_services == []
    assert state.endpoints == []
    assert state.warnings
    assert any("Optional input file missing" in warning for warning in state.warnings)
