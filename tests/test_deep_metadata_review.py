"""Tests for offline Deep metadata review leads."""

from __future__ import annotations
from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_metadata_review import (
    DeepMetadataReviewSummary,
    build_deep_metadata_review_from_project_state,
    render_deep_metadata_review_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_project_state_produces_no_leads_and_safe_rendering() -> None:
    summary = build_deep_metadata_review_from_project_state(_project_state())
    rendered = render_deep_metadata_review_markdown(summary)

    assert isinstance(summary, DeepMetadataReviewSummary)
    assert summary.leads == ()
    assert rendered.startswith("## Deep Metadata Review\n")
    assert "No Deep metadata review leads were generated from the collected evidence." in rendered
    assert "not confirmed findings" in rendered


def test_robots_value_artifact_creates_review_lead_with_preview_and_evidence() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots_value",
                    value="Wubbalubbadubdub",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0002"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    assert len(summary.leads) == 1
    lead = summary.leads[0]
    assert lead.lead_id == "LEAD-DEEP-META-0001"
    assert lead.category == "robots_value"
    assert lead.priority == "high"
    assert lead.url == "http://example.test/robots.txt"
    assert lead.evidence_ids == ("EVID-ART-0002",)
    assert lead.value_preview == "Wubbalubbadubdub"


def test_raw_robots_file_path_artifact_alone_does_not_create_high_value_lead() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots",
                    value="/tmp/robots-example-80.txt",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0001"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    assert summary.leads == ()


def test_generic_user_agent_value_is_ignored() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="user_agent",
                    value="*",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0001"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    assert summary.leads == ()


def test_disallow_rule_creates_route_hint_without_credential_wording() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="disallow_rule",
                    value="/admin/",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0003"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )
    rendered = render_deep_metadata_review_markdown(summary)

    assert [lead.category for lead in summary.leads] == ["robots_route_hint"]
    assert summary.leads[0].value_preview == "/admin/"
    assert "credentials found" not in rendered.lower()
    assert "password found" not in rendered.lower()


def test_sitemap_rule_creates_sitemap_reference_lead() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="sitemap_rule",
                    value="http://example.test/sitemap.xml",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0004"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    assert [lead.category for lead in summary.leads] == ["sitemap_reference"]
    assert summary.leads[0].title == "Sitemap reference observed"


def test_discovered_metadata_paths_create_expected_categories() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            discovered_paths=[
                _path("https://example.test/security.txt", "EVID-PATH-0001"),
                _path("https://example.test/.well-known/security.txt", "EVID-PATH-0002"),
                _path("https://example.test/humans.txt", "EVID-PATH-0003"),
                _path("https://example.test/crossdomain.xml", "EVID-PATH-0004"),
                _path("https://example.test/clientaccesspolicy.xml", "EVID-PATH-0005"),
                _path("https://example.test/favicon.ico", "EVID-PATH-0006"),
            ]
        )
    )

    assert [lead.category for lead in summary.leads] == [
        "security_contact",
        "security_contact",
        "humans_metadata",
        "policy_file",
        "policy_file",
        "favicon_reference",
    ]
    assert summary.leads[-1].priority == "info"


def test_endpoint_sitemap_path_creates_sitemap_reference_lead() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="https://example.test/sitemap.xml",
                    hostname="example.test",
                    path="/sitemap.xml",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    assert [lead.category for lead in summary.leads] == ["sitemap_reference"]
    assert summary.leads[0].source == "project-state:endpoint"


def test_same_metadata_url_from_endpoint_and_discovered_path_merges_evidence_ids() -> None:
    state = _project_state(
        endpoints=[
            Endpoint(
                url="https://example.test/security.txt",
                hostname="example.test",
                path="/security.txt",
                query_params=[],
                evidence_ids=["EVID-URL-0001"],
                tags=[],
            )
        ],
        discovered_paths=[
            _path("https://example.test/security.txt", "EVID-PATH-0001")
        ],
    )

    first = build_deep_metadata_review_from_project_state(state)
    second = build_deep_metadata_review_from_project_state(state)

    assert first == second
    assert [(lead.lead_id, lead.category) for lead in first.leads] == [
        ("LEAD-DEEP-META-0001", "security_contact")
    ]
    lead = first.leads[0]
    assert lead.source == "project-state:endpoint"
    assert lead.evidence_ids == ("EVID-URL-0001", "EVID-PATH-0001")


def test_renderer_is_card_like_and_uses_safe_manual_review_wording() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots_value",
                    value="remember-this",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0002"],
                    tags=[],
                )
            ]
        )
    )

    rendered = render_deep_metadata_review_markdown(summary)

    assert "### LEAD-DEEP-META-0001: robots.txt clue-like value observed" in rendered
    assert "- Priority: high" in rendered
    assert "- Category: robots_value" in rendered
    assert "- Evidence: `EVID-ART-0002`" in rendered
    assert "- Value preview: `remember-this`" in rendered
    assert "Treat metadata values as context, not credentials." in rendered
    assert "Do not submit forms, attempt authentication, brute force, or use credentials" in rendered


def test_renderer_avoids_confirmed_finding_and_exploit_wording() -> None:
    summary = build_deep_metadata_review_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots_value",
                    value="exploit flag vulnerable vulnerability",
                    source_file="robots-example-80.txt",
                    evidence_ids=["EVID-ART-0002"],
                    tags=[],
                )
            ]
        )
    )
    rendered = render_deep_metadata_review_markdown(summary).lower()

    for forbidden in (
        "vulnerability found",
        "credentials found",
        "password found",
        "login bypass",
        "exploit",
        "valid credential",
    ):
        assert forbidden not in rendered
    assert "[redacted]" in rendered


def test_duplicate_evidence_produces_one_logical_lead_and_ordering_is_stable() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="remember-this",
                source_file="robots-example-80.txt",
                evidence_ids=["EVID-ART-0002"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="remember-this",
                source_file="robots-example-80.txt",
                evidence_ids=["EVID-ART-0002"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin/",
                source_file="robots-example-80.txt",
                evidence_ids=["EVID-ART-0003"],
                tags=[],
            ),
        ]
    )

    first = build_deep_metadata_review_from_project_state(state)
    second = build_deep_metadata_review_from_project_state(state)

    assert first == second
    assert [(lead.lead_id, lead.category) for lead in first.leads] == [
        ("LEAD-DEEP-META-0001", "robots_value"),
        ("LEAD-DEEP-META-0002", "robots_route_hint"),
    ]


def test_no_cli_or_mode_enablement_changes() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="unit",
        input_dir="",
        processed_files=[],
        scope_summary="No scope",
        assets=[],
        http_services=http_services or [],
        endpoints=endpoints or [],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-01T00:00:00Z",
    )


def _path(url: str, evidence_id: str) -> DiscoveredPath:
    return DiscoveredPath(
        url=url,
        status_code=200,
        content_length=10,
        redirect_location=None,
        source="unit-test",
        evidence_ids=[evidence_id],
        tags=[],
    )
