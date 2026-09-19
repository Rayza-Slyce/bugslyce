"""Investigation thread grouping tests."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

from bugslyce.core.models import (
    Candidate,
    DiscoveredPath,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.interpretation_collection import collect_interpretation_from_sources
from bugslyce.recon.interpretation_sources import artefact_sources_from_project_state
from bugslyce.recon.application_service_composition import (
    build_application_service_composition,
)
from bugslyce.recon.application_service_model import (
    build_application_service_model,
)
from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
)
from bugslyce.recon.deep_html_route_extraction import (
    build_deep_html_route_extraction,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.investigation_threads import (
    InvestigationThread,
    build_investigation_threads,
    render_investigation_threads_markdown,
    render_standard_investigation_workflow_runbook_section,
)
from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeObservationSemanticEvidence,
    NativeRedirectRelationship,
    NativeStructuredResponseFact,
)
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge
from bugslyce.triage.workflow_leads import WorkflowLead



def _assert_semantic_thread_id(value: str) -> None:
    assert value.startswith("THREAD-")
    suffix = value.removeprefix("THREAD-")
    assert len(suffix) == 64
    assert all(character in "0123456789abcdef" for character in suffix)


def test_high_port_http_and_multiple_services_generate_one_thread() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test/",
                hostname="example.test",
                status_code=200,
                title="Default",
                technologies=[],
                content_length=100,
                evidence_ids=["EVID-SVC-80"],
                tags=[],
            ),
            HTTPService(
                url="http://example.test:8080/",
                hostname="example.test",
                status_code=200,
                title="High port",
                technologies=[],
                content_length=120,
                evidence_ids=["EVID-SVC-8080"],
                tags=[],
            ),
        ]
    )
    candidates = [
        _candidate(
            "CAND-HP",
            "high_port_http_service",
            endpoints=["http://example.test:8080/"],
            evidence_ids=["EVID-CAND-HP"],
        )
    ]

    threads = build_investigation_threads(state, candidates)

    assert len(threads) == 1
    thread = threads[0]
    _assert_semantic_thread_id(thread.thread_id)
    assert thread.title == "High-port HTTP application review"
    assert thread.priority == "medium"
    assert (
        thread.summary
        == "A non-default HTTP port or multiple HTTP services may indicate a separate application surface."
    )
    assert "http://example.test:8080/" in thread.related_endpoints
    assert "EVID-SVC-8080" in thread.related_evidence_ids
    assert "CAND-HP" in thread.related_candidate_ids
    assert "Compare the high-port service with the default HTTP service." in (
        thread.suggested_manual_review_order
    )


def test_hidden_path_evidence_generates_hidden_path_thread() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/hidden",
                status_code=200,
                content_length=42,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-HIDDEN"],
                tags=[],
            )
        ]
    )

    thread = build_investigation_threads(state)[0]

    _assert_semantic_thread_id(thread.thread_id)
    assert thread.title == "Discovered hidden-path review"
    assert thread.category == "discovered_content"
    assert (
        thread.summary
        == "Hidden-looking discovered paths may deserve bounded manual review when linked to stronger context."
    )
    assert thread.related_endpoints == ("http://example.test/hidden",)
    assert thread.related_evidence_ids == ("EVID-PATH-HIDDEN",)
    assert "Review the collected response for the discovered path." in (
        thread.suggested_manual_review_order
    )


def test_repeated_response_family_weakens_hidden_path_attention() -> None:
    urls = (
        "http://example.test/api/dev",
        "http://example.test/api/test",
    )
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=500,
                content_length=42,
                redirect_location=None,
                source="native",
                evidence_ids=[f"EVID-PATH-{index}"],
                tags=[],
            )
            for index, url in enumerate(urls, start=1)
        ]
    )
    similarity = SimpleNamespace(
        groups=(
            SimpleNamespace(
                category="request_reflecting_template_group",
                requested_urls=urls,
                evidence_ids=("EVID-FAMILY-1", "EVID-FAMILY-2"),
            ),
        )
    )

    thread = build_investigation_threads(
        state,
        response_similarity_review=similarity,
    )[0]

    assert thread.priority == "low"
    assert thread.related_endpoints == urls
    assert set(thread.related_evidence_ids) == {
        "EVID-PATH-1",
        "EVID-PATH-2",
        "EVID-FAMILY-1",
        "EVID-FAMILY-2",
    }
    assert "response-family context" in thread.summary
    assert "weakens the lexical path-name signal" in thread.why_it_matters
    assert thread.limitation_codes == (
        "response_family_weakens_path_name_signal",
    )


def test_query_variant_family_does_not_weaken_query_free_hidden_path() -> None:
    url = "http://example.test/api/dev"
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=200,
                content_length=42,
                redirect_location=None,
                source="native",
                evidence_ids=["EVID-PATH"],
                tags=[],
            )
        ]
    )
    similarity = SimpleNamespace(
        groups=(
            SimpleNamespace(
                category="candidate_default_template_group",
                requested_urls=(
                    url + "?view=one",
                    url + "?view=two",
                ),
                evidence_ids=("EVID-QUERY",),
            ),
        )
    )

    thread = build_investigation_threads(
        state,
        response_similarity_review=similarity,
    )[0]

    assert thread.priority == "medium"
    assert thread.limitation_codes == ()
    assert "EVID-QUERY" not in thread.related_evidence_ids


def test_encoded_or_source_evidence_generates_artefact_thread() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="encoded_like_artifact",
                value="L2hpZGRlbi9mbGFn",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-ENC"],
                tags=["encoded_or_hidden_artifact"],
            )
        ]
    )
    leads = [
        _lead(
            "LEAD-0001",
            category="robots",
            lead_type="possible_transform",
            url="http://example.test/robots.txt",
            evidence_ids=("EVID-ART-ENC",),
        )
    ]

    thread = build_investigation_threads(state, review_leads=leads)[0]

    _assert_semantic_thread_id(thread.thread_id)
    assert thread.title == "Encoded or source artefact review"
    assert thread.category == "artefact_interpretation"
    assert (
        thread.summary
        == "Encoded-looking, hash-shaped, or source-level artefacts should be reviewed after their surrounding service and path context."
    )
    assert "EVID-ART-ENC" in thread.related_evidence_ids
    assert "LEAD-0001" in thread.related_lead_ids
    assert "Do not submit artefacts to online decoders or hash databases automatically." in (
        thread.suggested_manual_review_order
    )


def test_encoded_artifact_alone_does_not_create_source_thread() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://portal.example.test/reference",
                artifact_type="encoded_like_artifact",
                value="L2ludGVybmFsL3JlZmVyZW5jZQ==",
                source_file="reference.html",
                evidence_ids=["EVID-ENCODED"],
                tags=["encoded_or_hidden_artifact"],
            )
        ]
    )

    assert build_investigation_threads(state) == ()


def test_source_thread_uses_only_the_contributing_local_reference_provenance() -> None:
    source_endpoint = "https://portal.example.test/documents/"
    unrelated_endpoint = "https://portal.example.test/"
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url=unrelated_endpoint,
                artifact_type="html_comment",
                value="Routine page annotation.",
                source_file="homepage.html",
                evidence_ids=["EVID-UNRELATED-COMMENT"],
                tags=[],
            ),
            HTTPArtifact(
                url=source_endpoint,
                artifact_type="link",
                value="release-notes.txt",
                source_file="documents.html",
                evidence_ids=[
                    "EVID-LOCAL-REFERENCE-A",
                    "EVID-LOCAL-REFERENCE-B",
                ],
                tags=[],
            ),
        ]
    )
    collection = collect_interpretation_from_sources(
        artefact_sources_from_project_state(state)
    )
    contributing_lead = next(
        lead
        for lead in collection.review_leads
        if lead.raw_value == "release-notes.txt"
    )

    thread = build_investigation_threads(
        state,
        review_leads=[contributing_lead],
    )[0]

    assert contributing_lead.evidence_ids == (
        "EVID-LOCAL-REFERENCE-A",
        "EVID-LOCAL-REFERENCE-B",
    )
    assert thread.related_evidence_ids == (
        "EVID-LOCAL-REFERENCE-A",
        "EVID-LOCAL-REFERENCE-B",
    )
    assert thread.related_endpoints == (source_endpoint,)
    report_markdown = render_investigation_threads_markdown((thread,))
    runbook_markdown = render_standard_investigation_workflow_runbook_section(
        (thread,)
    )
    for markdown in (report_markdown, runbook_markdown):
        assert "EVID-LOCAL-REFERENCE-A" in markdown
        assert "EVID-LOCAL-REFERENCE-B" in markdown
        assert source_endpoint in markdown
        assert "EVID-UNRELATED-COMMENT" not in markdown
        assert f"`{unrelated_endpoint}`" not in markdown


def test_source_thread_unions_exact_provenance_from_deliberately_grouped_leads() -> None:
    first_endpoint = "https://portal.example.test/documents/"
    second_endpoint = "https://portal.example.test/archive/"
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://portal.example.test/",
                artifact_type="html_comment",
                value="Routine page annotation.",
                source_file="homepage.html",
                evidence_ids=["EVID-UNRELATED"],
                tags=[],
            )
        ]
    )
    first = _lead(
        "LEAD-SOURCE-A",
        category="html_source",
        lead_type="html_local_reference_review",
        url=first_endpoint,
        evidence_ids=("EVID-A", "EVID-SHARED"),
    )
    second = _lead(
        "LEAD-SOURCE-B",
        category="html_source",
        lead_type="html_local_reference_review",
        url=second_endpoint,
        evidence_ids=("EVID-B", "EVID-SHARED"),
    )

    first_build = build_investigation_threads(state, review_leads=[first, second])
    reversed_build = build_investigation_threads(state, review_leads=[second, first])
    thread = first_build[0]

    assert first_build == reversed_build
    assert thread.related_evidence_ids == ("EVID-A", "EVID-B", "EVID-SHARED")
    assert thread.related_endpoints == (second_endpoint, first_endpoint)
    assert thread.related_lead_ids == ("LEAD-SOURCE-A", "LEAD-SOURCE-B")
    assert "EVID-UNRELATED" not in thread.related_evidence_ids


def test_source_thread_without_exact_provenance_does_not_select_fallback_evidence() -> None:
    source_endpoint = "https://portal.example.test/documents/"
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://portal.example.test/",
                artifact_type="html_comment",
                value="Routine page annotation.",
                source_file="homepage.html",
                evidence_ids=["EVID-UNRELATED"],
                tags=[],
            )
        ]
    )
    lead = _lead(
        "LEAD-NO-PROVENANCE",
        category="html_source",
        lead_type="html_local_reference_review",
        url=source_endpoint,
    )

    thread = build_investigation_threads(state, review_leads=[lead])[0]

    assert thread.related_evidence_ids == ()
    assert thread.related_endpoints == (source_endpoint,)


def test_hidden_element_creates_source_context_without_encoded_guidance() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://portal.example.test/",
                artifact_type="html_comment",
                value="Review the deployment route before release",
                source_file="homepage.html",
                evidence_ids=["EVID-UNRELATED-COMMENT"],
                tags=["source_comment"],
            ),
            HTTPArtifact(
                url="https://portal.example.test/workflow",
                artifact_type="hidden_element",
                value="input type=hidden name=workflow_state",
                source_file="body-fetch-workflow.html",
                evidence_ids=["EVID-HIDDEN"],
                tags=["source_structure"],
            )
        ]
    )

    threads = build_investigation_threads(state)

    assert len(threads) == 1
    thread = threads[0]
    assert thread.title == "Source artefact review"
    assert thread.related_evidence_ids == ("EVID-HIDDEN",)
    assert thread.related_endpoints == ("https://portal.example.test/workflow",)
    assert "EVID-UNRELATED-COMMENT" not in thread.related_evidence_ids
    assert "https://portal.example.test/" not in thread.related_endpoints
    rendered = " ".join(
        (
            thread.title,
            thread.summary,
            *thread.suggested_manual_review_order,
        )
    ).lower()
    assert "encoded" not in rendered
    assert "decoder" not in rendered
    assert "valid credentials" not in rendered


def test_source_comment_without_transform_evidence_has_no_encoded_guidance() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://portal.example.test/",
                artifact_type="html_comment",
                value="Review the deployment route before release",
                source_file="homepage.html",
                evidence_ids=["EVID-COMMENT"],
                tags=["source_comment"],
            )
        ]
    )
    leads = [
        _lead(
            "LEAD-SOURCE",
            category="html_source",
            lead_type="html_comment_clue_review",
            url="https://portal.example.test/",
        )
    ]

    thread = build_investigation_threads(state, review_leads=leads)[0]
    rendered = " ".join(
        (thread.title, thread.summary, *thread.suggested_manual_review_order)
    ).lower()

    assert thread.title == "Source artefact review"
    assert "encoded" not in rendered
    assert "valid credentials" not in rendered


def test_credential_candidate_has_caution_without_encoded_guidance() -> None:
    candidate = _candidate(
        "CAND-CREDENTIAL",
        "credential_like_artifact_review",
        endpoints=["https://portal.example.test/source"],
        evidence_ids=["EVID-CREDENTIAL"],
    )

    thread = build_investigation_threads(
        _project_state(),
        candidates=[candidate],
    )[0]
    rendered = " ".join(
        (thread.title, thread.summary, *thread.suggested_manual_review_order)
    ).lower()

    assert thread.title == "Source artefact review"
    assert "do not treat source values as valid credentials" in rendered
    assert "encoded" not in rendered
    assert "decoder" not in rendered
    assert "hash-shaped" not in rendered


def test_encoded_candidate_has_no_credential_specific_caution() -> None:
    candidate = _candidate(
        "CAND-ENCODED",
        "encoded_artifact_review",
        endpoints=["https://portal.example.test/source"],
        evidence_ids=["EVID-ENCODED"],
    )

    thread = build_investigation_threads(
        _project_state(),
        candidates=[candidate],
    )[0]
    rendered = " ".join(
        (thread.title, thread.summary, *thread.suggested_manual_review_order)
    ).lower()

    assert thread.title == "Encoded or source artefact review"
    assert "validate encoded or hash-shaped artefacts locally" in rendered
    assert "valid credentials" not in rendered


def test_combined_encoded_and_credential_candidates_keep_each_caution_once() -> None:
    candidates = [
        _candidate(
            "CAND-ENCODED",
            "encoded_artifact_review",
            endpoints=["https://portal.example.test/source"],
            evidence_ids=["EVID-ENCODED"],
        ),
        _candidate(
            "CAND-CREDENTIAL",
            "credential_like_artifact_review",
            endpoints=["https://portal.example.test/source"],
            evidence_ids=["EVID-CREDENTIAL"],
        ),
    ]

    thread = build_investigation_threads(
        _project_state(),
        candidates=candidates,
    )[0]
    rendered = " ".join(thread.suggested_manual_review_order).lower()

    assert thread.title == "Encoded or source artefact review"
    assert rendered.count("validate encoded or hash-shaped artefacts locally") == 1
    assert rendered.count("do not treat source values as valid credentials") == 1


def test_hash_or_transform_lead_enables_encoded_guidance() -> None:
    lead = _lead(
        "LEAD-HASH",
        category="html_source",
        lead_type="possible_hash",
        url="https://portal.example.test/source",
    )

    thread = build_investigation_threads(
        _project_state(),
        review_leads=[lead],
    )[0]

    assert thread.title == "Encoded or source artefact review"
    assert "Validate encoded or hash-shaped artefacts locally." in (
        thread.suggested_manual_review_order
    )


def test_mixed_generic_and_meaningful_high_port_origins_stay_separate() -> None:
    generic_url = "https://generic.example.test:7443/"
    application_url = "https://application.example.test:8443/"
    state = _project_state(
        http_services=[
            HTTPService(
                url=generic_url,
                hostname="generic.example.test",
                status_code=200,
                title="It works!",
                technologies=[],
                content_length=100,
                evidence_ids=["EVID-GENERIC"],
                tags=[],
            ),
            HTTPService(
                url=application_url,
                hostname="application.example.test",
                status_code=200,
                title="Operations workspace",
                technologies=[],
                content_length=200,
                evidence_ids=["EVID-APPLICATION"],
                tags=[],
            ),
        ]
    )
    candidates = [
        _candidate(
            "CAND-GENERIC",
            "high_port_http_service",
            endpoints=[generic_url],
            evidence_ids=["EVID-GENERIC"],
        ),
        _candidate(
            "CAND-APPLICATION",
            "high_port_http_service",
            endpoints=[application_url],
            evidence_ids=["EVID-APPLICATION"],
        ),
    ]

    first = build_investigation_threads(state, candidates)
    second = build_investigation_threads(state, candidates)

    assert first == second
    assert len(first) == 2
    meaningful = next(
        thread for thread in first if thread.title == "High-port HTTP application review"
    )
    generic = next(
        thread for thread in first if thread.title == "Generic high-port HTTP service context"
    )
    assert meaningful.priority == "medium"
    assert meaningful.related_endpoints == (application_url,)
    assert meaningful.related_candidate_ids == ("CAND-APPLICATION",)
    assert generic.priority == "low"
    assert generic.related_endpoints == (generic_url,)
    assert generic.related_candidate_ids == ("CAND-GENERIC",)
    assert first.index(meaningful) < first.index(generic)
    generic_guidance = " ".join(generic.suggested_manual_review_order).lower()
    assert "encoded" not in generic_guidance
    assert "credential" not in generic_guidance


def test_multiple_high_port_origins_group_only_with_matching_priority() -> None:
    generic_urls = (
        "https://one.example.test:7443/",
        "https://two.example.test:8443/",
    )
    meaningful_urls = (
        "https://three.example.test:9443/",
        "https://four.example.test:10443/",
    )
    services = [
        *(
            HTTPService(
                url=url,
                hostname=url.split("//", 1)[1].split(":", 1)[0],
                status_code=200,
                title="It works!",
                technologies=[],
                content_length=100,
                evidence_ids=[f"EVID-GENERIC-{index}"],
                tags=[],
            )
            for index, url in enumerate(generic_urls, start=1)
        ),
        *(
            HTTPService(
                url=url,
                hostname=url.split("//", 1)[1].split(":", 1)[0],
                status_code=200,
                title="Team workspace",
                technologies=[],
                content_length=200,
                evidence_ids=[f"EVID-APP-{index}"],
                tags=[],
            )
            for index, url in enumerate(meaningful_urls, start=1)
        ),
    ]

    threads = build_investigation_threads(_project_state(http_services=services))

    assert len(threads) == 2
    meaningful = next(thread for thread in threads if thread.priority == "medium")
    generic = next(thread for thread in threads if thread.priority == "low")
    assert meaningful.related_endpoints == tuple(sorted(meaningful_urls))
    assert generic.related_endpoints == tuple(sorted(generic_urls))


def test_thread_order_and_ids_are_deterministic() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test:8080/",
                hostname="example.test",
                status_code=200,
                title=None,
                technologies=[],
                content_length=None,
                evidence_ids=["EVID-SVC"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/admin",
                status_code=200,
                content_length=None,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH"],
                tags=[],
            )
        ],
    )
    leads = [
        _lead(
            "LEAD-0003",
            category="html_source",
            lead_type="html_comment_clue_review",
            priority="high",
            related_artefact_types=("possible_base64",),
        )
    ]

    first = build_investigation_threads(state, review_leads=leads)
    second = build_investigation_threads(state, review_leads=leads)

    assert first == second
    assert len({thread.thread_id for thread in first}) == 3
    for thread in first:
        _assert_semantic_thread_id(thread.thread_id)
    assert [thread.title for thread in first] == [
        "Encoded or source artefact review",
        "High-port HTTP application review",
        "Discovered hidden-path review",
    ]
    assert first[0].priority == "high"

    markdown = render_investigation_threads_markdown(first)
    assert markdown.index(
        f"### {first[0].thread_id}: {first[0].title}"
    ) < markdown.index(
        f"### {first[1].thread_id}: {first[1].title}"
    )
    assert markdown.index(
        f"### {first[1].thread_id}: {first[1].title}"
    ) < markdown.index(
        f"### {first[2].thread_id}: {first[2].title}"
    )


def test_runbook_workflow_renderer_preserves_thread_order_and_core_fields() -> None:
    threads = build_investigation_threads(
        _project_state(
            http_services=[
                HTTPService(
                    url="http://example.test:8080/",
                    hostname="example.test",
                    status_code=200,
                    title=None,
                    technologies=[],
                    content_length=None,
                    evidence_ids=["EVID-SVC"],
                    tags=[],
                )
            ],
            discovered_paths=[
                DiscoveredPath(
                    url="http://example.test/admin",
                    status_code=200,
                    content_length=None,
                    redirect_location=None,
                    source="gobuster",
                    evidence_ids=["EVID-PATH"],
                    tags=[],
                )
            ],
        ),
        candidates=[
            _candidate(
                "CAND-ENC",
                "encoded_artifact_review",
                endpoints=["http://example.test/admin"],
                evidence_ids=["EVID-CAND-ENC"],
            )
        ],
        review_leads=[
            _lead(
                "LEAD-0001",
                category="html_source",
                lead_type="possible_transform",
                priority="high",
                related_artefact_types=("possible_base64",),
            )
        ],
    )

    markdown = render_standard_investigation_workflow_runbook_section(threads)
    empty = render_standard_investigation_workflow_runbook_section(())

    assert markdown.startswith("## Standard Investigation Workflow")
    assert "manual review prompts, not confirmed findings" in markdown
    assert "Offline Route/Source Review section" in markdown
    assert markdown.index(
        f"### {threads[0].thread_id}: {threads[0].title}"
    ) < markdown.index(
        f"### {threads[1].thread_id}: {threads[1].title}"
    )
    assert markdown.index(
        f"### {threads[1].thread_id}: {threads[1].title}"
    ) < markdown.index(
        f"### {threads[2].thread_id}: {threads[2].title}"
    )
    assert "* Related endpoints:" in markdown
    assert "`EVID-SVC`" in markdown
    assert "`LEAD-0001`" in markdown
    assert "`CAND-ENC`" in markdown
    assert "* Suggested manual review order:" in markdown
    assert "* Kill-switch guidance:" in markdown
    assert "No Standard Investigation Threads were generated" in empty


def test_standard_thread_renderers_include_context_guidance_without_reordering() -> None:
    threads = build_investigation_threads(
        _project_state(
            engagement_context="bug_bounty",
            http_services=[
                HTTPService(
                    url="http://example.test:8080/",
                    hostname="example.test",
                    status_code=200,
                    title=None,
                    technologies=[],
                    content_length=None,
                    evidence_ids=["EVID-SVC"],
                    tags=[],
                )
            ],
            discovered_paths=[
                DiscoveredPath(
                    url="http://example.test/admin",
                    status_code=200,
                    content_length=None,
                    redirect_location=None,
                    source="gobuster",
                    evidence_ids=["EVID-PATH"],
                    tags=[],
                )
            ],
        ),
        review_leads=[
            _lead(
                "LEAD-0001",
                category="html_source",
                lead_type="possible_transform",
                priority="high",
                related_artefact_types=("possible_base64",),
            )
        ],
    )

    report_markdown = render_investigation_threads_markdown(
        threads,
        engagement_context="bug_bounty",
    )
    runbook_markdown = render_standard_investigation_workflow_runbook_section(
        threads,
        engagement_context="bug_bounty",
    )

    assert len({thread.thread_id for thread in threads}) == 3
    for thread in threads:
        _assert_semantic_thread_id(thread.thread_id)
    assert [thread.title for thread in threads] == [
        "Encoded or source artefact review",
        "High-port HTTP application review",
        "Discovered hidden-path review",
    ]
    assert "In a bug bounty context, treat this as low-confidence metadata" in report_markdown
    assert "In a bug bounty context, treat this as low-confidence metadata" in runbook_markdown
    assert report_markdown.index(
        threads[0].thread_id
    ) < report_markdown.index(
        threads[1].thread_id
    )
    assert runbook_markdown.index(
        threads[0].thread_id
    ) < runbook_markdown.index(
        threads[1].thread_id
    )


def test_renderers_separate_subsumed_support_from_primary_attention() -> None:
    parent = InvestigationThread(
        thread_id="THREAD-" + "a" * 64,
        title="Primary account workflow",
        priority="high",
        category="account_workflow",
        summary="Primary workflow summary.",
        why_it_matters="Primary workflow rationale.",
        related_endpoints=("https://app.example.test/login",),
        related_evidence_ids=("EVID-PARENT",),
        related_candidate_ids=(),
        related_lead_ids=(),
        suggested_manual_review_order=("Review the workflow.",),
        kill_switch_guidance=None,
    )
    child = replace(
        parent,
        thread_id="THREAD-" + "b" * 64,
        title="Fetched login child",
        priority="medium",
        category="application_interface",
        summary="Generic fetched page.",
        why_it_matters="Generic page context.",
        related_evidence_ids=("EVID-CHILD",),
        suggested_manual_review_order=("Review retained page evidence.",),
        subsumed_by_thread_id=parent.thread_id,
        subsumption_reason=(
            "Generic fetched-page review is covered by the broader account workflow."
        ),
    )
    threads = (parent, child)

    markdown = render_investigation_threads_markdown(threads)
    runbook = render_standard_investigation_workflow_runbook_section(threads)

    primary_markdown, supporting_markdown = markdown.split(
        "### Subsumed Supporting Threads",
        1,
    )

    assert parent.title in primary_markdown
    assert child.title not in primary_markdown

    assert child.title in supporting_markdown
    assert child.thread_id in supporting_markdown
    assert parent.thread_id in supporting_markdown
    assert child.subsumption_reason in supporting_markdown
    assert "EVID-CHILD" in supporting_markdown

    assert parent.title in runbook
    assert child.title not in runbook


def test_renderer_includes_core_thread_fields_and_empty_state() -> None:
    thread = build_investigation_threads(
        _project_state(
            discovered_paths=[
                DiscoveredPath(
                    url="http://example.test/backup",
                    status_code=200,
                    content_length=None,
                    redirect_location=None,
                    source="gobuster",
                    evidence_ids=["EVID-PATH-BACKUP"],
                    tags=[],
                )
            ]
        ),
        candidates=[
            _candidate(
                "CAND-HIDDEN",
                "hidden_path_review",
                endpoints=["http://example.test/backup"],
                evidence_ids=["EVID-CAND-HIDDEN"],
            )
        ],
    )[0]

    markdown = render_investigation_threads_markdown((thread,))
    empty = render_investigation_threads_markdown(())

    assert markdown.startswith("## Investigation Threads")
    assert "These threads group related review signals" in markdown
    assert f"### {thread.thread_id}: Discovered hidden-path review" in markdown
    assert "- Priority: medium" in markdown
    assert "- Category: discovered_content" in markdown
    assert "`EVID-PATH-BACKUP`" in markdown
    assert "`CAND-HIDDEN`" in markdown
    assert "Review the collected response for the discovered path." in markdown
    assert "No investigation threads were generated" in empty
    assert "confirmed findings" in empty


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    engagement_context: str = "unknown",
) -> ProjectState:
    return ProjectState(
        project_name="thread-test",
        input_dir="/tmp/thread-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=http_services or [],
        endpoints=[],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-06-22T00:00:00Z",
        engagement_context=engagement_context,
    )


def _candidate(
    candidate_id: str,
    candidate_type: str,
    *,
    endpoints: list[str],
    evidence_ids: list[str],
) -> Candidate:
    return Candidate(
        id=candidate_id,
        candidate_type=candidate_type,
        title="Candidate",
        priority="medium",
        rationale="Review candidate.",
        affected_assets=[],
        affected_endpoints=endpoints,
        evidence_ids=evidence_ids,
        suggested_manual_validation=["Review manually."],
        kill_switch_guidance="Stop if low signal.",
    )


def _lead(
    lead_id: str,
    *,
    category: str,
    lead_type: str,
    priority: str = "medium",
    url: str | None = None,
    related_artefact_types: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
) -> ReviewLead:
    return ReviewLead(
        lead_id=lead_id,
        lead_type=lead_type,
        category=category,
        priority=priority,
        title="Review lead",
        explanation="Manual review recommended.",
        source_id="SRC-1",
        source_kind="robots_txt",
        source_label="robots",
        url=url,
        path=None,
        port=80,
        service="http",
        line_number=1,
        field_name="user-agent",
        item_type=None,
        raw_value="value",
        decoded_preview=None,
        nearby_keywords=(),
        related_artefact_types=related_artefact_types,
        suggested_manual_validation=("Review manually.",),
        evidence_ids=evidence_ids,
    )



def _package3_application_model(*, include_unrelated_origin: bool = False):
    structured_responses = [
        NativeStructuredResponseFact(
            request_url="https://app.example.test/api/search/",
            status_code=200,
            candidate_index=7,
            exchange_index=0,
            body_sha256="a" * 64,
        )
    ]
    if include_unrelated_origin:
        structured_responses.append(
            NativeStructuredResponseFact(
                request_url="https://other.example.test/api/status/",
                status_code=200,
                candidate_index=20,
                exchange_index=0,
                body_sha256="b" * 64,
            )
        )

    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=tuple(structured_responses),
        redirect_relationships=(
            NativeRedirectRelationship(
                source_url="https://app.example.test/api/search",
                raw_location="/api/search/",
                target_url="https://app.example.test/api/search/",
                candidate_index=8,
                exchange_index=0,
            ),
        ),
    )

    application_composition = build_application_service_composition(
        native_observation_evidence=native_evidence,
    )

    model = build_application_service_model(
        application_composition=application_composition,
        documentation_assertions=DocumentationAssertionExtractionResult(
            assertions=(),
            skipped_sources=(),
            sources_considered=0,
            sources_eligible=0,
        ),
        native_observation_evidence=native_evidence,
    )
    return model


def _application_model_for_thread_subjects(
    native_evidence: NativeObservationSemanticEvidence,
    *,
    html_target_url: str | None = None,
):
    html_extraction = None
    if html_target_url is not None:
        body = (
            f'<html><a href="{html_target_url}">reference</a></html>'
        ).encode("utf-8")
        source = DeepSourceRouteCollectedItem(
            url="https://www.example.test/docs/",
            method="GET",
            status_code=200,
            final_url="https://www.example.test/docs/",
            headers=(("Content-Type", "text/html"),),
            body_preview=body.decode("utf-8"),
            body_sha256=sha256(body).hexdigest(),
            body_bytes=len(body),
            elapsed_seconds=0.1,
            source="fixture",
            reason="fixture",
            evidence_ids=("EVID-HTML-REFERENCE",),
            body=body,
        )
        html_extraction = build_deep_html_route_extraction(
            DeepSourceRouteCollectionResult(
                collected=(source,),
                skipped=(),
                total_considered=1,
                total_collected=1,
                total_skipped=0,
            )
        )
    composition = build_application_service_composition(
        native_observation_evidence=native_evidence,
        html_extraction=html_extraction,
    )
    return build_application_service_model(
        application_composition=composition,
        documentation_assertions=DocumentationAssertionExtractionResult(
            assertions=(),
            skipped_sources=(),
            sources_considered=0,
            sources_eligible=0,
        ),
        native_observation_evidence=native_evidence,
    )


def test_mobile_association_declarations_seed_one_limited_application_thread() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="http://www.example.test/.well-known/assetlinks.json",
                status_code=200,
                candidate_index=1,
                exchange_index=0,
                body_sha256="a" * 64,
            ),
            NativeStructuredResponseFact(
                request_url="https://www.example.test/.well-known/assetlinks.json",
                status_code=200,
                candidate_index=2,
                exchange_index=0,
                body_sha256="b" * 64,
            ),
        ),
        mobile_association_declarations=(
            NativeMobileAssociationDeclaration(
                document_url="http://www.example.test/.well-known/assetlinks.json",
                platform="android",
                package_name="com.example.app",
                candidate_index=1,
                exchange_index=0,
                body_sha256="a" * 64,
            ),
            NativeMobileAssociationDeclaration(
                document_url="https://www.example.test/.well-known/assetlinks.json",
                platform="android",
                package_name="com.example.app",
                candidate_index=2,
                exchange_index=0,
                body_sha256="b" * 64,
            ),
        ),
    )
    model = _application_model_for_thread_subjects(native_evidence)

    threads = build_investigation_threads(
        _project_state(), application_service_model=model
    )

    mobile_threads = [
        thread for thread in threads if "com.example.app" in thread.title
    ]
    assert len(mobile_threads) == 1
    thread = mobile_threads[0]
    assert thread.related_endpoints == (
        "http://www.example.test/.well-known/assetlinks.json",
        "https://www.example.test/.well-known/assetlinks.json",
    )
    assert thread.related_native_observation_ids == (
        "native-observation:1:0",
        "native-observation:2:0",
    )
    assert "mobile_association_ownership_not_confirmed" in thread.limitation_codes
    assert not any(
        thread.title == "Observed structured application interface"
        and ".well-known/assetlinks.json" in thread.related_endpoints
        for thread in threads
    )


def test_structured_response_http_https_facts_group_by_host_and_path() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="http://app.example.test/api/search",
                status_code=200,
                candidate_index=1,
                exchange_index=0,
                body_sha256="a" * 64,
            ),
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search/",
                status_code=200,
                candidate_index=2,
                exchange_index=0,
                body_sha256="b" * 64,
            ),
        ),
    )
    threads = build_investigation_threads(
        _project_state(),
        application_service_model=_application_model_for_thread_subjects(native_evidence),
    )

    assert len(threads) == 1
    assert threads[0].related_endpoints == (
        "http://app.example.test/api/search",
        "https://app.example.test/api/search/",
    )
    assert threads[0].related_native_observation_ids == (
        "native-observation:1:0",
        "native-observation:2:0",
    )


def test_cross_host_redirects_group_by_target_origin_but_same_host_scheme_does_not() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        redirect_relationships=(
            NativeRedirectRelationship(
                source_url="https://www.example.test/account",
                raw_location="https://id.example.test/login",
                target_url="https://id.example.test/login",
                candidate_index=1,
                exchange_index=0,
            ),
            NativeRedirectRelationship(
                source_url="https://www.example.test/profile",
                raw_location="https://id.example.test/settings",
                target_url="https://id.example.test/settings",
                candidate_index=2,
                exchange_index=0,
            ),
            NativeRedirectRelationship(
                source_url="http://www.example.test/start",
                raw_location="https://www.example.test/start",
                target_url="https://www.example.test/start",
                candidate_index=3,
                exchange_index=0,
            ),
        ),
    )
    model = _application_model_for_thread_subjects(native_evidence)

    threads = build_investigation_threads(
        _project_state(), application_service_model=model
    )

    boundary_threads = [
        thread for thread in threads if "redirect" in thread.title.casefold()
    ]
    assert len(boundary_threads) == 1
    thread = boundary_threads[0]
    assert "id.example.test" in thread.title
    assert set(thread.related_endpoints) == {
        "https://www.example.test/account",
        "https://www.example.test/profile",
        "https://id.example.test/login",
        "https://id.example.test/settings",
    }
    assert len(thread.related_application_relation_ids) == 2
    assert thread.related_native_observation_ids == (
        "native-observation:1:0",
        "native-observation:2:0",
    )
    assert thread.related_evidence_ids == ()
    assert "native-observation:3:0" not in thread.related_native_observation_ids


def test_precise_referenced_api_graphql_route_seeds_conservative_thread() -> None:
    model = _application_model_for_thread_subjects(
        NativeObservationSemanticEvidence(),
        html_target_url="https://api.example.test/api/graphql/v1",
    )

    threads = build_investigation_threads(
        _project_state(), application_service_model=model
    )

    assert len(threads) == 1
    thread = threads[0]
    assert thread.title == "Referenced API/GraphQL interface"
    assert set(thread.related_endpoints) == {
        "https://api.example.test/api/graphql/v1",
        "https://www.example.test/docs/",
    }
    assert thread.related_application_relation_ids
    assert "referenced_interface_not_confirmed_reachable" in thread.limitation_codes


def test_generic_external_html_reference_does_not_seed_api_thread() -> None:
    model = _application_model_for_thread_subjects(
        NativeObservationSemanticEvidence(),
        html_target_url="https://cdn.example.test/fonts/main.woff2",
    )

    assert build_investigation_threads(
        _project_state(), application_service_model=model
    ) == ()


def test_application_subject_threads_are_permutation_stable() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="http://app.example.test/api/status/",
                status_code=200,
                candidate_index=1,
                exchange_index=0,
                body_sha256="a" * 64,
            ),
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/status/",
                status_code=200,
                candidate_index=2,
                exchange_index=0,
                body_sha256="b" * 64,
            ),
        ),
        redirect_relationships=(
            NativeRedirectRelationship(
                source_url="https://app.example.test/login",
                raw_location="https://id.example.test/login",
                target_url="https://id.example.test/login",
                candidate_index=3,
                exchange_index=0,
            ),
        ),
    )
    first_edge = HttpRouteRelationshipEdge(
        edge_type="redirect",
        source_url="https://app.example.test/start",
        target_url="https://id.example.test/start",
        evidence_ids=("EVID-REDIRECT-A",),
        raw_references=("https://id.example.test/start",),
        status_code=302,
    )
    second_edge = HttpRouteRelationshipEdge(
        edge_type="redirect",
        source_url="https://app.example.test/continue",
        target_url="https://id.example.test/continue",
        evidence_ids=("EVID-REDIRECT-B",),
        raw_references=("https://id.example.test/continue",),
        status_code=302,
    )

    def model(edges):
        composition = build_application_service_composition(
            native_observation_evidence=native_evidence,
            redirect_edges=edges,
        )
        return build_application_service_model(
            application_composition=composition,
            documentation_assertions=DocumentationAssertionExtractionResult(
                assertions=(),
                skipped_sources=(),
                sources_considered=0,
                sources_eligible=0,
            ),
            native_observation_evidence=native_evidence,
        )

    assert build_investigation_threads(
        _project_state(),
        application_service_model=model((first_edge, second_edge)),
    ) == build_investigation_threads(
        _project_state(),
        application_service_model=model((second_edge, first_edge)),
    )


def test_package3_semantic_thread_id_survives_unrelated_higher_ranked_thread() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="https://application.example.test:8443/",
                hostname="application.example.test",
                status_code=200,
                title="Operations workspace",
                technologies=[],
                content_length=200,
                evidence_ids=["EVID-APPLICATION"],
                tags=[],
            )
        ]
    )

    baseline = build_investigation_threads(state)
    baseline_thread = next(
        thread
        for thread in baseline
        if thread.title == "High-port HTTP application review"
    )

    expanded = build_investigation_threads(
        state,
        review_leads=[
            _lead(
                "LEAD-HIGH-UNRELATED",
                category="html_source",
                lead_type="possible_transform",
                priority="high",
                url="https://other.example.test/source",
                related_artefact_types=("possible_base64",),
                evidence_ids=("EVID-UNRELATED-HIGH",),
            )
        ],
    )
    expanded_thread = next(
        thread
        for thread in expanded
        if thread.title == "High-port HTTP application review"
    )

    assert baseline_thread.thread_id == expanded_thread.thread_id

    prefix = "THREAD-"
    assert baseline_thread.thread_id.startswith(prefix)
    semantic_suffix = baseline_thread.thread_id[len(prefix):]
    assert len(semantic_suffix) == 64
    assert all(character in "0123456789abcdef" for character in semantic_suffix)


def test_package3_native_application_evidence_composes_without_discovered_path() -> None:
    state = _project_state()
    model = _package3_application_model()

    assert state.discovered_paths == []

    threads = build_investigation_threads(
        state,
        application_service_model=model,
    )

    application_thread = next(
        thread
        for thread in threads
        if "https://app.example.test/api/search/" in thread.related_endpoints
    )

    assert application_thread.category == "application_interface"
    assert "structured" in application_thread.title.lower()

    relation_id = model.application_composition.relations[0].relation_id

    assert application_thread.related_native_observation_ids == (
        "native-observation:7:0",
        "native-observation:8:0",
    )
    assert application_thread.related_application_relation_ids == (
        relation_id,
    )
    assert application_thread.limitation_codes == (
        "redirect_destination_not_fetched",
        "structured_response_not_confirmed_api",
    )


def test_package3_unrelated_application_origin_does_not_change_thread_identity() -> None:
    state = _project_state()

    baseline = build_investigation_threads(
        state,
        application_service_model=_package3_application_model(),
    )
    expanded = build_investigation_threads(
        state,
        application_service_model=_package3_application_model(
            include_unrelated_origin=True,
        ),
    )

    baseline_thread = next(
        thread
        for thread in baseline
        if "https://app.example.test/api/search/" in thread.related_endpoints
    )
    expanded_thread = next(
        thread
        for thread in expanded
        if "https://app.example.test/api/search/" in thread.related_endpoints
    )
    unrelated_thread = next(
        thread
        for thread in expanded
        if "https://other.example.test/api/status/" in thread.related_endpoints
    )

    assert baseline_thread.thread_id == expanded_thread.thread_id
    assert unrelated_thread.thread_id != expanded_thread.thread_id


def test_account_workflow_subsumes_generic_fetched_page_attention_without_deleting_children() -> None:
    login_url = "https://market.example.test/login"
    signup_url = "https://market.example.test/signup"
    about_url = "https://market.example.test/about"

    workflow = WorkflowLead(
        title="Authentication and account workflow review",
        priority="high",
        category="account_workflow",
        summary="Observed account workflow context.",
        why_it_matters="Direct account-workflow evidence deserves bounded review.",
        suggested_manual_action="Review retained account workflow evidence.",
        representative_urls=(login_url,),
        covered_urls=(login_url, signup_url),
        evidence_ids=("EVID-WORKFLOW",),
        signal="account_workflow",
    )
    compatibility = (
        SimpleNamespace(
            lead_type="fetched_application_page",
            endpoints=(login_url,),
            evidence_ids=("EVID-PAGE-LOGIN",),
        ),
        SimpleNamespace(
            lead_type="fetched_application_page",
            endpoints=(signup_url,),
            evidence_ids=("EVID-PAGE-SIGNUP",),
        ),
        SimpleNamespace(
            lead_type="fetched_application_page",
            endpoints=(about_url,),
            evidence_ids=("EVID-PAGE-ABOUT",),
        ),
    )

    baseline = build_investigation_threads(
        _project_state(),
        compatibility_summary_leads=compatibility,
    )
    composed = build_investigation_threads(
        _project_state(),
        workflow_leads=(workflow,),
        compatibility_summary_leads=compatibility,
    )

    parent = next(
        thread for thread in composed
        if thread.category == "account_workflow"
    )
    login_child = next(
        thread for thread in composed
        if thread.related_endpoints == (login_url,)
        and thread.category == "application_interface"
    )
    signup_child = next(
        thread for thread in composed
        if thread.related_endpoints == (signup_url,)
        and thread.category == "application_interface"
    )
    about_child = next(
        thread for thread in composed
        if thread.related_endpoints == (about_url,)
        and thread.category == "application_interface"
    )

    baseline_by_endpoint = {
        thread.related_endpoints: thread.thread_id
        for thread in baseline
    }

    assert login_child.thread_id == baseline_by_endpoint[(login_url,)]
    assert signup_child.thread_id == baseline_by_endpoint[(signup_url,)]
    assert about_child.thread_id == baseline_by_endpoint[(about_url,)]

    assert login_child.subsumed_by_thread_id == parent.thread_id
    assert signup_child.subsumed_by_thread_id == parent.thread_id
    assert login_child.subsumption_reason is not None
    assert signup_child.subsumption_reason is not None
    assert "account workflow" in login_child.subsumption_reason.casefold()
    assert "account workflow" in signup_child.subsumption_reason.casefold()

    assert about_child.subsumed_by_thread_id is None
    assert about_child.subsumption_reason is None

    assert set(parent.related_evidence_ids) == {
        "EVID-WORKFLOW",
        "EVID-PAGE-LOGIN",
        "EVID-PAGE-SIGNUP",
    }


def test_package3_workflow_thread_retains_all_exact_evidence_references() -> None:
    evidence_ids = tuple(
        f"EVID-WORKFLOW-{index:02d}"
        for index in range(1, 14)
    )

    workflow = WorkflowLead(
        title="Account workflow review",
        priority="high",
        category="account_workflow",
        summary="Observed account workflow context.",
        why_it_matters="Account boundaries deserve bounded review.",
        suggested_manual_action="Review retained account workflow evidence.",
        representative_urls=("https://app.example.test/account",),
        covered_urls=("https://app.example.test/account",),
        evidence_ids=evidence_ids,
        signal="account_workflow",
    )

    thread = build_investigation_threads(
        _project_state(),
        workflow_leads=(workflow,),
    )[0]

    assert thread.related_evidence_ids == evidence_ids



def test_structured_response_query_identity_remains_distinct() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search?scope=user",
                status_code=200,
                candidate_index=101,
                exchange_index=0,
                body_sha256="1" * 64,
            ),
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search?scope=admin",
                status_code=200,
                candidate_index=102,
                exchange_index=0,
                body_sha256="2" * 64,
            ),
        ),
    )

    threads = build_investigation_threads(
        _project_state(),
        application_service_model=_application_model_for_thread_subjects(
            native_evidence
        ),
    )

    structured = tuple(
        thread
        for thread in threads
        if thread.title == "Observed structured application interface"
    )

    assert len(structured) == 2
    assert {
        thread.related_endpoints
        for thread in structured
    } == {
        ("https://app.example.test/api/search?scope=user",),
        ("https://app.example.test/api/search?scope=admin",),
    }


def test_structured_response_non_default_port_identity_remains_distinct() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/status",
                status_code=200,
                candidate_index=111,
                exchange_index=0,
                body_sha256="3" * 64,
            ),
            NativeStructuredResponseFact(
                request_url="https://app.example.test:8443/api/status",
                status_code=200,
                candidate_index=112,
                exchange_index=0,
                body_sha256="4" * 64,
            ),
        ),
    )

    threads = build_investigation_threads(
        _project_state(),
        application_service_model=_application_model_for_thread_subjects(
            native_evidence
        ),
    )

    structured = tuple(
        thread
        for thread in threads
        if thread.title == "Observed structured application interface"
    )

    assert len(structured) == 2
    assert {
        thread.related_endpoints
        for thread in structured
    } == {
        ("https://app.example.test/api/status",),
        ("https://app.example.test:8443/api/status",),
    }


def test_query_distinct_redirect_does_not_enrich_structured_subject() -> None:
    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search?scope=user",
                status_code=200,
                candidate_index=121,
                exchange_index=0,
                body_sha256="5" * 64,
            ),
        ),
        redirect_relationships=(
            NativeRedirectRelationship(
                source_url="https://app.example.test/api/search?scope=admin",
                raw_location="/login?scope=admin",
                target_url="https://app.example.test/login?scope=admin",
                candidate_index=122,
                exchange_index=0,
            ),
        ),
    )

    threads = build_investigation_threads(
        _project_state(),
        application_service_model=_application_model_for_thread_subjects(
            native_evidence
        ),
    )

    thread = next(
        item
        for item in threads
        if item.title == "Observed structured application interface"
    )

    assert thread.related_native_observation_ids == (
        "native-observation:121:0",
    )
    assert thread.related_application_relation_ids == ()
    assert thread.related_endpoints == (
        "https://app.example.test/api/search?scope=user",
    )


def test_mobile_subsumption_is_exact_observation_not_url_wide() -> None:
    document_url = "https://www.example.test/.well-known/assetlinks.json"

    native_evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url=document_url,
                status_code=200,
                candidate_index=131,
                exchange_index=0,
                body_sha256="6" * 64,
            ),
            NativeStructuredResponseFact(
                request_url=document_url,
                status_code=200,
                candidate_index=132,
                exchange_index=0,
                body_sha256="7" * 64,
            ),
        ),
        mobile_association_declarations=(
            NativeMobileAssociationDeclaration(
                document_url=document_url,
                platform="android",
                package_name="com.example.app",
                candidate_index=131,
                exchange_index=0,
                body_sha256="6" * 64,
            ),
        ),
    )

    threads = build_investigation_threads(
        _project_state(),
        application_service_model=_application_model_for_thread_subjects(
            native_evidence
        ),
    )

    mobile = tuple(
        thread
        for thread in threads
        if "com.example.app" in thread.title
    )
    structured = tuple(
        thread
        for thread in threads
        if thread.title == "Observed structured application interface"
    )

    assert len(mobile) == 1
    assert mobile[0].related_native_observation_ids == (
        "native-observation:131:0",
    )

    assert len(structured) == 1
    assert structured[0].related_endpoints == (document_url,)
    assert structured[0].related_native_observation_ids == (
        "native-observation:132:0",
    )

def _sem4_successful_content_review(
    url: str,
    body_preview: str,
    evidence_id: str,
):
    from bugslyce.recon.deep_successful_content import (
        SuccessfulDeepContentReview,
    )

    body = body_preview.encode("utf-8")
    return SuccessfulDeepContentReview(
        review_id="DEEP-CONTENT-SEM4",
        canonical_url=url,
        requested_urls=(url,),
        status_code=200,
        content_type="text/plain; version=0.0.4",
        body_bytes=len(body),
        body_sha256=sha256(body).hexdigest(),
        body_preview=body_preview,
        evidence_ids=(evidence_id,),
        artefact_references=("deep_source_route_collection.json",),
    )


def test_prometheus_exposition_content_gets_specific_canonical_thread_without_pathname_dependency() -> None:
    url = "https://app.example.test/internal/telemetry"
    evidence_id = "EVID-PROMETHEUS"

    review = _sem4_successful_content_review(
        url,
        """# HELP process_cpu_seconds_total Total user and system CPU time.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.5
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 104857600
""",
        evidence_id,
    )
    compatibility = SimpleNamespace(
        lead_type="successful_deep_content",
        endpoints=(url,),
        evidence_ids=(evidence_id,),
    )

    threads = build_investigation_threads(
        _project_state(),
        compatibility_summary_leads=(compatibility,),
        successful_content_reviews=(review,),
    )

    related = tuple(
        thread
        for thread in threads
        if evidence_id in thread.related_evidence_ids
    )

    assert len(related) == 1

    thread = related[0]
    assert thread.title == "Prometheus-style metrics exposition observed"
    assert thread.priority == "medium"
    assert thread.category == "application_interface"
    assert thread.related_endpoints == (url,)
    assert thread.related_evidence_ids == (evidence_id,)
    assert "metrics exposition" in thread.summary.casefold()
    assert "vulnerability" in thread.why_it_matters.casefold()
    assert "metrics_exposition_not_security_finding" in thread.limitation_codes


def test_metrics_pathname_without_exposition_content_stays_generic() -> None:
    url = "https://app.example.test/metrics"
    evidence_id = "EVID-ORDINARY-METRICS-PATH"

    review = _sem4_successful_content_review(
        url,
        "Service is healthy. No metrics exposition is present.",
        evidence_id,
    )
    compatibility = SimpleNamespace(
        lead_type="successful_deep_content",
        endpoints=(url,),
        evidence_ids=(evidence_id,),
    )

    threads = build_investigation_threads(
        _project_state(),
        compatibility_summary_leads=(compatibility,),
        successful_content_reviews=(review,),
    )

    related = tuple(
        thread
        for thread in threads
        if evidence_id in thread.related_evidence_ids
    )

    assert len(related) == 1

    thread = related[0]
    assert thread.title == "Successfully collected Deep content available offline"
    assert thread.priority == "medium"
    assert "prometheus" not in thread.title.casefold()
    assert "metrics_exposition_not_security_finding" not in thread.limitation_codes

def test_prometheus_promotion_splits_only_matching_review_from_generic_aggregate() -> None:
    prometheus_url = "https://app.example.test/internal/telemetry"
    ordinary_url = "https://app.example.test/public/notice.txt"

    prometheus = _sem4_successful_content_review(
        prometheus_url,
        """# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.5
""",
        "EVID-PROMETHEUS",
    )
    ordinary = _sem4_successful_content_review(
        ordinary_url,
        "Scheduled maintenance notice.",
        "EVID-ORDINARY",
    )

    compatibility = SimpleNamespace(
        lead_type="successful_deep_content",
        endpoints=(prometheus_url, ordinary_url),
        evidence_ids=("EVID-PROMETHEUS", "EVID-ORDINARY"),
    )

    threads = build_investigation_threads(
        _project_state(),
        compatibility_summary_leads=(compatibility,),
        successful_content_reviews=(prometheus, ordinary),
    )

    prometheus_thread = next(
        thread
        for thread in threads
        if thread.title == "Prometheus-style metrics exposition observed"
    )
    generic_thread = next(
        thread
        for thread in threads
        if thread.title == "Successfully collected Deep content available offline"
    )

    assert prometheus_thread.related_endpoints == (prometheus_url,)
    assert prometheus_thread.related_evidence_ids == ("EVID-PROMETHEUS",)

    assert generic_thread.related_endpoints == (ordinary_url,)
    assert generic_thread.related_evidence_ids == ("EVID-ORDINARY",)

    assert "EVID-ORDINARY" not in prometheus_thread.related_evidence_ids
    assert "EVID-PROMETHEUS" not in generic_thread.related_evidence_ids

