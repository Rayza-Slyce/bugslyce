"""Cross-renderer regression tests for the concise operator hierarchy."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

from bugslyce.core.models import (
    Asset,
    Candidate,
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.interpretation_collection import collect_interpretation_from_sources
from bugslyce.recon.investigation_threads import (
    build_investigation_threads,
    render_standard_investigation_workflow_runbook_section,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
)
from bugslyce.reports.markdown import export_project_state_json, render_markdown_report
from bugslyce.reports.operator_summary import (
    OperatorSummaryLead,
    build_operator_summary,
)
from bugslyce.triage.candidates import generate_candidates
from bugslyce.triage.workflow_leads import (
    QUERY_PARAMETER_CONTEXTS,
    build_grouped_workflow_leads,
)


def test_structured_disclosures_make_manual_review_empty_state_truthful() -> None:
    collection = collect_interpretation_from_sources(
        (),
        referenced_direct_lead_count=2,
    )

    assert collection.referenced_direct_lead_count == 2
    assert "No interpretation review leads were generated from the provided evidence." not in (
        collection.manual_review_leads_markdown or ""
    )
    assert "listed once in the Operator Summary" in (
        collection.manual_review_leads_markdown or ""
    )


def test_true_manual_review_empty_state_remains_available() -> None:
    collection = collect_interpretation_from_sources(())

    assert collection.referenced_direct_lead_count == 0
    assert "No interpretation review leads were generated from the provided evidence." in (
        collection.manual_review_leads_markdown or ""
    )


def test_generic_high_port_service_is_low_priority_across_concise_layers() -> None:
    service_url = "https://service.example.test:7443/"
    state = _state(
        assets=[_asset("service.example.test")],
        http_services=[
            HTTPService(
                url="http://service.example.test/",
                hostname="service.example.test",
                status_code=200,
                title="Primary workspace",
                technologies=["HTTP"],
                content_length=2048,
                evidence_ids=["EVID-SERVICE-PRIMARY"],
                tags=[],
            ),
            HTTPService(
                url=service_url,
                hostname="service.example.test",
                status_code=200,
                title="It works!",
                technologies=["HTTP"],
                content_length=512,
                evidence_ids=["EVID-SERVICE-DEFAULT"],
                tags=[],
            )
        ],
    )

    candidates = generate_candidates(state)
    high_port = next(
        item for item in candidates if item.candidate_type == "high_port_http_service"
    )
    multiple_services = next(
        item for item in candidates if item.candidate_type == "multiple_http_services"
    )
    brief = build_human_triage_brief(state, candidates)
    threads = build_investigation_threads(state, candidates)
    runbook = render_standard_investigation_workflow_runbook_section(threads)
    report = render_markdown_report(
        state,
        candidates,
        human_triage_brief_markdown=render_human_triage_brief_markdown(brief),
        investigation_threads_markdown=runbook.replace(
            "## Standard Investigation Workflow",
            "## Investigation Threads",
            1,
        ),
    )

    assert high_port.priority == "low"
    assert multiple_services.priority == "low"
    assert not any(item.url == service_url for item in brief.start_here)
    assert any(item.url == service_url for item in brief.ignore_for_now)
    assert len(threads) == 1
    assert threads[0].priority == "low"
    assert "encoded-looking" not in " ".join(threads[0].suggested_manual_review_order).lower()
    assert "* Priority: low" in runbook
    medium_queue = report.split("### medium", 1)[1].split("### low", 1)[0]
    low_queue = report.split("### low", 1)[1].split("### kill_switch", 1)[0]
    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]
    low_signal = report.split("### Low-Signal / Avoid Rabbit Holes", 1)[1].split(
        "### Current Coverage",
        1,
    )[0]
    assert service_url not in review_first
    assert service_url in low_signal
    assert service_url not in medium_queue
    assert service_url in low_queue


def test_nondefault_high_port_application_remains_meaningful_across_layers() -> None:
    service_url = "https://workspace.example.test:7443/"
    state = _state(
        assets=[_asset("workspace.example.test")],
        http_services=[
            HTTPService(
                url=service_url,
                hostname="workspace.example.test",
                status_code=200,
                title="Operations workspace",
                technologies=["HTTP"],
                content_length=2048,
                evidence_ids=["EVID-SERVICE-APP"],
                tags=[],
            )
        ],
    )

    candidates = generate_candidates(state)
    high_port = next(
        item for item in candidates if item.candidate_type == "high_port_http_service"
    )
    brief = build_human_triage_brief(state, candidates)
    threads = build_investigation_threads(state, candidates)
    report = render_markdown_report(state, candidates)
    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]

    assert high_port.priority == "medium"
    assert any(item.url == service_url for item in brief.start_here)
    assert threads[0].priority == "medium"
    assert service_url in review_first


def test_mixed_high_port_origins_keep_per_origin_priority_across_layers() -> None:
    generic_url = "https://shared.example.test:7443/"
    application_url = "https://shared.example.test:8443/"
    state = _state(
        assets=[_asset("shared.example.test")],
        http_services=[
            HTTPService(
                url=generic_url,
                hostname="shared.example.test",
                status_code=200,
                title="It works!",
                technologies=["HTTP"],
                content_length=512,
                evidence_ids=["EVID-GENERIC"],
                tags=[],
            ),
            HTTPService(
                url=application_url,
                hostname="shared.example.test",
                status_code=200,
                title="Operations workspace",
                technologies=["HTTP"],
                content_length=2048,
                evidence_ids=["EVID-APPLICATION"],
                tags=[],
            ),
        ],
    )

    candidates = generate_candidates(state)
    high_port_candidates = {
        item.affected_endpoints[0]: item
        for item in candidates
        if item.candidate_type == "high_port_http_service"
    }
    brief = build_human_triage_brief(state, candidates)
    threads = build_investigation_threads(state, candidates)
    runbook = render_standard_investigation_workflow_runbook_section(threads)
    report = render_markdown_report(state, candidates)
    medium_queue = report.split("### medium", 1)[1].split("### low", 1)[0]
    low_queue = report.split("### low", 1)[1].split("### kill_switch", 1)[0]

    assert high_port_candidates[generic_url].priority == "low"
    assert high_port_candidates[application_url].priority == "medium"
    assert not any(
        item.candidate_type == "multiple_http_services" for item in candidates
    )
    assert any(item.url == application_url for item in brief.start_here)
    assert not any(item.url == generic_url for item in brief.start_here)
    assert any(item.url == generic_url for item in brief.ignore_for_now)
    meaningful = next(thread for thread in threads if thread.priority == "medium")
    generic = next(thread for thread in threads if thread.priority == "low")
    assert meaningful.related_endpoints == (application_url,)
    assert generic.related_endpoints == (generic_url,)
    assert runbook.index("High-port HTTP application review") < runbook.index(
        "Generic high-port HTTP service context"
    )
    assert application_url in medium_queue
    assert generic_url not in medium_queue
    assert generic_url in low_queue


def test_direct_structured_evidence_outranks_generic_service_inventory() -> None:
    service_url = "https://inventory.example.test:7443/"
    state = _state(
        assets=[_asset("inventory.example.test")],
        http_services=[
            HTTPService(
                url=service_url,
                hostname="inventory.example.test",
                status_code=200,
                title="It works!",
                technologies=["HTTP"],
                content_length=512,
                evidence_ids=["EVID-SERVICE-GENERIC"],
                tags=[],
            )
        ],
    )
    direct = OperatorSummaryLead(
        title="Structured configuration disclosure",
        why="Collected plaintext contains coherent operational directives.",
        endpoints=["https://inventory.example.test/configuration"],
        evidence_ids=["EVID-CONFIG-DIRECT"],
        next_action="Review the retained excerpt and source artefact locally.",
        signal="direct",
        score=94,
    )

    summary = build_operator_summary(
        state,
        generate_candidates(state),
        additional_leads=(direct,),
    )

    assert summary.review_first[0] == direct
    assert all(service_url not in item.endpoints for item in summary.review_first)
    assert any(service_url in item.endpoints for item in summary.low_signal)


def test_account_routes_and_forms_are_grouped_without_losing_detail() -> None:
    base = "https://accounts.example.test"
    form_urls = (
        f"{base}/signin",
        f"{base}/create-account",
        f"{base}/recover-access",
    )
    state = _state(
        endpoints=[
            _endpoint(form_urls[0], "EVID-ROUTE-SIGNIN"),
            _endpoint(form_urls[1], "EVID-ROUTE-CREATE"),
            _endpoint(form_urls[2], "EVID-ROUTE-RECOVER"),
            _endpoint(f"{base}/member/profile", "EVID-ROUTE-PROFILE"),
        ],
        discovered_paths=[
            DiscoveredPath(
                url=f"{base}/member/home",
                status_code=302,
                content_length=0,
                redirect_location="/signin",
                source="bounded-followup",
                evidence_ids=["EVID-REDIRECT"],
                tags=[],
            ),
            DiscoveredPath(
                url=f"{base}/member/profile",
                status_code=403,
                content_length=0,
                redirect_location=None,
                source="bounded-followup",
                evidence_ids=["EVID-ACCOUNT-BOUNDARY"],
                tags=[],
            ),
        ],
    )
    orchestration = _orchestration_with_forms(form_urls)

    brief = build_human_triage_brief(
        state,
        [],
        deep_orchestration=orchestration,
    )
    repeated = build_human_triage_brief(
        state,
        [],
        deep_orchestration=orchestration,
    )
    rendered = render_human_triage_brief_markdown(brief)
    workflow_items = [
        item for item in brief.start_here if item.category == "account_workflow"
    ]

    assert len(workflow_items) == 1
    workflow = workflow_items[0]
    assert all(url in workflow.value for url in form_urls)
    assert all(url in rendered for url in form_urls)
    assert "observed field names: email, password" in rendered
    assert "methods=post" in rendered
    assert "authentication redirects:" in rendered
    assert "access boundaries:" in rendered
    assert "directly observed" in workflow.why_it_matters.lower()
    assert "redirect" in workflow.why_it_matters.lower()
    assert "access-boundary" in workflow.why_it_matters.lower()
    assert "weakness" not in workflow.why_it_matters.lower()
    assert "EVID-FORM-RECOVER" in workflow.evidence_ids
    assert not any(item.category == "auth_route" for item in brief.start_here)
    assert rendered.count("Authentication and account workflow review") == 1
    assert len(orchestration.form_inventory.forms) == 3
    assert brief == repeated


def test_grouped_account_workflow_reduces_primary_report_cards_but_keeps_details() -> None:
    base = "https://identity.example.test"
    form_urls = (
        f"{base}/signin",
        f"{base}/create-account",
        f"{base}/recover-access",
    )
    state = _state(
        assets=[_asset("identity.example.test")],
        endpoints=[
            _endpoint(url, f"EVID-ROUTE-{index}")
            for index, url in enumerate(form_urls, start=1)
        ],
    )
    candidates = generate_candidates(state)
    orchestration = _orchestration_with_forms(form_urls)
    brief = build_human_triage_brief(
        state,
        candidates,
        deep_orchestration=orchestration,
    )
    report = render_markdown_report(
        state,
        candidates,
        human_triage_brief_markdown=render_human_triage_brief_markdown(brief),
    )
    concise = report.split("## Scope Summary", 1)[0]

    assert concise.count("Authentication and account workflow review") == 1
    assert "Auth/account route observed" not in concise
    assert all(url in concise for url in form_urls)
    detailed_json = export_project_state_json(state, candidates)
    assert all(url in detailed_json for url in form_urls)
    assert len(orchestration.form_inventory.forms) == 3


def test_repeated_numeric_object_references_create_one_cautious_lead() -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://records.example.test/record/view?record_id=101",
                "EVID-OBJECT-1",
                query_params=["record_id"],
            ),
            _endpoint(
                "https://records.example.test/record/history?record_id=202",
                "EVID-OBJECT-2",
                query_params=["record_id"],
            ),
        ]
    )

    brief = build_human_triage_brief(state, [])
    leads = [
        item
        for item in brief.start_here
        if item.category == "object_reference_surface"
    ]

    assert len(leads) == 1
    lead = leads[0]
    assert "record_id" in lead.value
    assert "retained responses and directly observed urls" in (
        lead.suggested_manual_action.lower()
    )
    assert lead.evidence_ids == ("EVID-OBJECT-1", "EVID-OBJECT-2")
    forbidden_claims = ("idor", "broken access control", "confirmed vulnerability")
    assert not any(term in (lead.why_it_matters + lead.suggested_manual_action).lower() for term in forbidden_claims)


def test_single_query_parameter_or_generic_id_word_is_not_a_primary_object_lead() -> None:
    state = _state(
        endpoints=[
            _endpoint(
                "https://records.example.test/record/view?record_id=101",
                "EVID-OBJECT-ONE",
                query_params=["record_id"],
            )
        ],
        http_artifacts=[
            HTTPArtifact(
                url="https://records.example.test/",
                artifact_type="keyword_hit",
                value="id",
                source_file="homepage.html",
                evidence_ids=["EVID-ID-WORD"],
                tags=[],
            )
        ],
    )

    brief = build_human_triage_brief(state, [])

    assert not any(
        item.category == "object_reference_surface" for item in brief.start_here
    )


def test_form_control_only_account_fields_do_not_create_object_reference_lead() -> None:
    parameters = tuple(
        _parameter(
            name,
            contexts=("form_control",),
            form_action_urls=(
                "https://identity.example.test/signin",
                "https://identity.example.test/create-account",
            ),
            source_urls=(
                "https://identity.example.test/signin",
                "https://identity.example.test/create-account",
            ),
            occurrence_count=2,
        )
        for name in ("user", "account", "member")
    )
    orchestration = _orchestration_with_parameters(parameters)

    leads = build_grouped_workflow_leads(_state(), orchestration)

    assert QUERY_PARAMETER_CONTEXTS.isdisjoint({"form_control"})
    assert not any(
        lead.category == "object_reference_surface" for lead in leads
    )


def test_form_action_query_parameter_can_create_direct_object_reference_lead() -> None:
    parameter = _parameter(
        "user_id",
        contexts=("form_action_query",),
        form_action_urls=(
            "https://records.example.test/lookup?user_id",
            "https://records.example.test/history?user_id",
        ),
        occurrence_count=2,
    )

    leads = build_grouped_workflow_leads(
        _state(),
        _orchestration_with_parameters((parameter,)),
    )
    lead = next(
        item for item in leads if item.category == "object_reference_surface"
    )

    assert "user_id" in lead.summary
    assert "lookup" in lead.summary
    assert "history" in lead.summary


def test_mixed_form_and_query_contexts_use_only_query_provenance() -> None:
    parameter = _parameter(
        "member_id",
        contexts=("form_control", "html_route_query"),
        form_action_urls=(
            "https://identity.example.test/signin",
            "https://identity.example.test/create-account",
        ),
        route_urls=(
            "https://records.example.test/detail?member_id",
            "https://records.example.test/history?member_id",
        ),
        source_urls=(
            "https://identity.example.test/signin",
            "https://identity.example.test/create-account",
        ),
        occurrence_count=8,
    )

    lead = next(
        item
        for item in build_grouped_workflow_leads(
            _state(),
            _orchestration_with_parameters((parameter,)),
        )
        if item.category == "object_reference_surface"
    )

    assert "records.example.test/detail" in lead.summary
    assert "records.example.test/history" in lead.summary
    assert "identity.example.test" not in lead.summary


def test_grouped_workflows_are_shared_with_bounded_deterministic_runbook() -> None:
    base = "https://portal.example.test"
    form_urls = (
        f"{base}/signin",
        f"{base}/create-account",
        f"{base}/recover-access",
    )
    state = _state(
        assets=[_asset("portal.example.test")],
        http_services=[
            HTTPService(
                url=f"{base}:7443/",
                hostname="portal.example.test",
                status_code=200,
                title="It works!",
                technologies=["HTTP"],
                content_length=512,
                evidence_ids=["EVID-GENERIC-SERVICE"],
                tags=[],
            )
        ],
        endpoints=[
            *(
                _endpoint(url, f"EVID-ACCOUNT-{index}")
                for index, url in enumerate(form_urls, start=1)
            ),
            _endpoint(f"{base}/record/view?record_id=101", "EVID-OBJECT-A"),
            _endpoint(f"{base}/record/history?record_id=202", "EVID-OBJECT-B"),
        ],
    )
    orchestration = _orchestration_with_forms(form_urls)
    first = build_grouped_workflow_leads(state, orchestration)
    second = build_grouped_workflow_leads(state, orchestration)
    candidates = generate_candidates(state)
    brief = build_human_triage_brief(
        state,
        candidates,
        deep_orchestration=orchestration,
        workflow_leads=first,
    )
    threads = build_investigation_threads(
        state,
        candidates,
        workflow_leads=first,
    )
    runbook = render_standard_investigation_workflow_runbook_section(threads)
    repeated_runbook = render_standard_investigation_workflow_runbook_section(
        build_investigation_threads(
            state,
            candidates,
            workflow_leads=second,
        )
    )

    assert first == second
    assert [lead.category for lead in first] == [
        "account_workflow",
        "object_reference_surface",
    ]
    assert sum(item.category == "account_workflow" for item in brief.start_here) == 1
    assert sum(
        item.category == "object_reference_surface" for item in brief.start_here
    ) == 1
    assert runbook.count("Authentication and account workflow review") == 1
    assert runbook.count("Repeated object-reference parameter surface") == 1
    assert runbook.index("Authentication and account workflow review") < runbook.index(
        "Repeated object-reference parameter surface"
    ) < runbook.index("Generic high-port HTTP service context")
    assert runbook.count("portal.example.test/record/") <= 4
    assert "confirmed vulnerability" not in runbook.lower()
    assert "idor" not in runbook.lower()
    assert runbook == repeated_runbook
    assert len(orchestration.form_inventory.forms) == 3


def test_encoded_review_steps_are_conditional_on_qualifying_evidence() -> None:
    generic_state = _state(
        http_services=[
            HTTPService(
                url="https://generic.example.test:7443/",
                hostname="generic.example.test",
                status_code=200,
                title="It works!",
                technologies=[],
                content_length=100,
                evidence_ids=["EVID-GENERIC"],
                tags=[],
            )
        ]
    )
    generic_threads = build_investigation_threads(generic_state)

    encoded_state = _state(
        http_artifacts=[
            HTTPArtifact(
                url="https://encoded.example.test/detail",
                artifact_type="encoded_like_artifact",
                value="QWxwaGFCZXRhMTIzNDU2Nzg5MEV4YW1wbGU=",
                source_file="body-fetch-detail.html",
                evidence_ids=["EVID-ENCODED"],
                tags=["encoded_or_hidden_artifact"],
            )
        ]
    )
    encoded_threads = build_investigation_threads(
        encoded_state,
        generate_candidates(encoded_state),
    )

    assert all(
        "encoded" not in " ".join(thread.suggested_manual_review_order).lower()
        for thread in generic_threads
    )
    assert "encoded" not in render_standard_investigation_workflow_runbook_section(
        generic_threads
    ).lower()
    assert any(
        "encoded" in (thread.title + " " + thread.summary).lower()
        for thread in encoded_threads
    )


def test_evidence_value_empty_state_is_scoped_and_sensitive_notice_is_once() -> None:
    state = _state()
    brief = build_human_triage_brief(state, [])
    populated_brief = SimpleNamespace(
        start_here=(
            SimpleNamespace(
                title="Direct structured review",
                priority="high",
                category="structured",
                source="direct",
                value="/bounded/value",
                why_it_matters="Direct evidence.",
                suggested_manual_action="Review locally.",
                evidence_ids=("EVID-DIRECT",),
                url="https://example.test/data",
                signal="direct",
            ),
        ),
        evidence_values=(),
        review_next=(),
        ignore_for_now=(),
        raw_evidence_pointers=(),
        evidence_cards=(),
    )

    empty_markdown = render_human_triage_brief_markdown(brief)
    populated_markdown = render_human_triage_brief_markdown(populated_brief)
    report = render_markdown_report(state, [])
    notice = (
        "Evidence directories and exported ZIP packs may retain complete response "
        "headers, cookie values, session identifiers, or tokens."
    )

    assert "No compact evidence values were promoted into this section." not in populated_markdown
    assert "this section" in populated_markdown
    assert "Direct structured review" in populated_markdown
    assert report.count(notice) == 1
    assert "No high-confidence manual triage leads" in empty_markdown


def test_exported_pack_preserves_primary_sensitive_evidence_notice(
    tmp_path: Path,
) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    report = render_markdown_report(_state(), [])
    (input_dir / "report.md").write_text(report, encoding="utf-8")
    (input_dir / "project_state.json").write_text("{}\n", encoding="utf-8")
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- example.test\n",
        encoding="utf-8",
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "example.test",
                "scope_file": "scope.md",
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        packed_report = archive.read("report.md").decode("utf-8")
    assert packed_report.count("## Sensitive Evidence Notice") == 1
    assert "complete response headers, cookie values, session identifiers, or tokens" in packed_report
    assert "delete or sanitise sensitive retained evidence" in packed_report


def _state(
    *,
    assets: list[Asset] | None = None,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="hierarchy-test",
        input_dir="/tmp/hierarchy-test",
        processed_files=[],
        scope_summary="Synthetic authorised scope.",
        assets=assets or [],
        http_services=http_services or [],
        endpoints=endpoints or [],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-19T00:00:00Z",
    )


def _asset(hostname: str) -> Asset:
    return Asset(
        hostname=hostname,
        in_scope=True,
        sources=["synthetic"],
        evidence_ids=["EVID-ASSET"],
        tags=[],
    )


def _endpoint(
    url: str,
    evidence_id: str,
    *,
    query_params: list[str] | None = None,
) -> Endpoint:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return Endpoint(
        url=url,
        hostname=parsed.hostname or "",
        path=parsed.path,
        query_params=query_params or [],
        evidence_ids=[evidence_id],
        tags=[],
    )


def _orchestration_with_forms(form_urls: tuple[str, ...]) -> SimpleNamespace:
    forms = tuple(
        SimpleNamespace(
            safe_document_urls=(url,),
            safe_resolved_action_url=url,
            methods=("post",),
            control_summary=SimpleNamespace(password_controls=1 if "signin" in url else 0),
            evidence_ids=(
                "EVID-FORM-SIGNIN"
                if "signin" in url
                else "EVID-FORM-CREATE"
                if "create-account" in url
                else "EVID-FORM-RECOVER",
            ),
        )
        for url in form_urls
    )
    parameters = tuple(
        SimpleNamespace(
            name=name,
            contexts=("form_control",),
            safe_form_action_urls=form_urls,
            safe_route_urls=(),
            safe_source_urls=form_urls,
            occurrence_count=len(form_urls),
            evidence_ids=(f"EVID-FIELD-{name.upper()}",),
        )
        for name in ("email", "password")
    )
    return SimpleNamespace(
        form_inventory=SimpleNamespace(forms=forms),
        parameter_inventory=SimpleNamespace(parameters=parameters),
        html_route_extraction=SimpleNamespace(routes=()),
        javascript_route_extraction=SimpleNamespace(candidates=()),
        redirect_auth_flow_review=SimpleNamespace(observations=()),
    )


def _orchestration_with_parameters(parameters: tuple[SimpleNamespace, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        form_inventory=SimpleNamespace(forms=()),
        parameter_inventory=SimpleNamespace(parameters=parameters),
        html_route_extraction=SimpleNamespace(routes=()),
        javascript_route_extraction=SimpleNamespace(candidates=()),
        redirect_auth_flow_review=SimpleNamespace(observations=()),
    )


def _parameter(
    name: str,
    *,
    contexts: tuple[str, ...],
    form_action_urls: tuple[str, ...] = (),
    route_urls: tuple[str, ...] = (),
    source_urls: tuple[str, ...] = (),
    occurrence_count: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        contexts=contexts,
        safe_form_action_urls=form_action_urls,
        safe_route_urls=route_urls,
        safe_source_urls=source_urls,
        occurrence_count=occurrence_count,
        evidence_ids=(f"EVID-PARAM-{name.upper()}",),
    )
