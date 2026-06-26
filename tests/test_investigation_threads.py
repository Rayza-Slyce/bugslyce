"""Investigation thread grouping tests."""

from __future__ import annotations

from bugslyce.core.models import (
    Candidate,
    DiscoveredPath,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.investigation_threads import (
    build_investigation_threads,
    render_investigation_threads_markdown,
    render_standard_investigation_workflow_runbook_section,
)


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
    assert thread.thread_id == "THREAD-0001"
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

    assert thread.thread_id == "THREAD-0001"
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
            lead_type="robots_unusual_user_agent_artefact_review",
            url="http://example.test/robots.txt",
            related_artefact_types=("possible_md5_shape",),
        )
    ]

    thread = build_investigation_threads(state, review_leads=leads)[0]

    assert thread.thread_id == "THREAD-0001"
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
    assert [thread.thread_id for thread in first] == [
        "THREAD-0001",
        "THREAD-0002",
        "THREAD-0003",
    ]
    assert [thread.title for thread in first] == [
        "High-port HTTP application review",
        "Discovered hidden-path review",
        "Encoded or source artefact review",
    ]
    assert first[2].priority == "high"

    markdown = render_investigation_threads_markdown(first)
    assert markdown.index("### THREAD-0001: High-port HTTP application review") < markdown.index(
        "### THREAD-0002: Discovered hidden-path review"
    )
    assert markdown.index("### THREAD-0002: Discovered hidden-path review") < markdown.index(
        "### THREAD-0003: Encoded or source artefact review"
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
    assert markdown.index("### THREAD-0001: High-port HTTP application review") < markdown.index(
        "### THREAD-0002: Discovered hidden-path review"
    )
    assert markdown.index("### THREAD-0002: Discovered hidden-path review") < markdown.index(
        "### THREAD-0003: Encoded or source artefact review"
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

    assert [thread.thread_id for thread in threads] == [
        "THREAD-0001",
        "THREAD-0002",
        "THREAD-0003",
    ]
    assert [thread.title for thread in threads] == [
        "High-port HTTP application review",
        "Discovered hidden-path review",
        "Encoded or source artefact review",
    ]
    assert "In a bug bounty context, treat this as low-confidence metadata" in report_markdown
    assert "In a bug bounty context, treat this as low-confidence metadata" in runbook_markdown
    assert report_markdown.index("THREAD-0001") < report_markdown.index("THREAD-0002")
    assert runbook_markdown.index("THREAD-0001") < runbook_markdown.index("THREAD-0002")


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
    assert "### THREAD-0001: Discovered hidden-path review" in markdown
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
    )
