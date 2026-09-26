"""D2A: fixed-route local hosting and canonical browser projection contracts."""

from contextlib import contextmanager
from dataclasses import replace
from http.client import HTTPConnection
from importlib.resources import files
from pathlib import Path
import re
import subprocess
from threading import Thread

import pytest

from bugslyce.core.engagement_policy import EngagementPolicyAssessment
from bugslyce.cli import main
from bugslyce.dashboard.presentation import (
    ENDPOINT_PREVIEW_LIMIT,
    render_investigation_home,
    render_thread_detail,
)
from bugslyce.dashboard.read_model import (
    DashboardAuthoritySummary,
    DashboardProjectIdentity,
    DashboardReadModel,
    build_dashboard_read_model,
)
from bugslyce.dashboard.server import CONTENT_SECURITY_POLICY, DashboardHTTPServer, create_dashboard_server
from bugslyce.recon.collection_confidence import CollectionConfidenceNotice
from bugslyce.recon.investigation_threads import InvestigationThread
from bugslyce.reports.analysis_coverage import build_analysis_coverage
from bugslyce.reports.investigation_context import InvestigationContextAssembly
from bugslyce.reports.operator_report_view import OperatorReportView


def _thread(digit: str, **changes: object) -> InvestigationThread:
    return replace(InvestigationThread(
        thread_id="THREAD-" + digit * 64,
        title="Thread " + digit,
        priority="medium",
        category="application_interface",
        summary="A saved direct observation.",
        why_it_matters="The saved response merits bounded human review.",
        related_endpoints=("https://example.test/one",),
        related_evidence_ids=("EVID-ONE",),
        related_candidate_ids=(),
        related_lead_ids=(),
        suggested_manual_review_order=("Review the retained response.",),
        kill_switch_guidance="Deprioritise if the evidence is a normal template.",
    ), **changes)


def _model(
    threads: tuple[InvestigationThread, ...] | None,
    *,
    name: str = "Example project",
    context: str = "internal_authorised",
    authority: DashboardAuthoritySummary | None = None,
    notices: tuple[CollectionConfidenceNotice, ...] = (),
) -> DashboardReadModel:
    primary = None if threads is None else tuple(
        thread for thread in threads if thread.subsumed_by_thread_id is None
    )
    return DashboardReadModel(
        project=DashboardProjectIdentity(name, "example.test", context),
        investigation_threads=threads,
        primary_investigation_threads=primary,
        application_service_model=None,
        operator_report_view=OperatorReportView(
            InvestigationContextAssembly((), (), ()), build_analysis_coverage(())
        ),
        analysis_coverage_evidence=None,
        confidence_notices=notices,
        authority=authority or DashboardAuthoritySummary(None, None, None),
    )


@contextmanager
def _running(server: DashboardHTTPServer):
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def _request(server: DashboardHTTPServer, path: str, *, method: str = "GET", host: str | None = None):
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    headers = {"Host": host} if host is not None else {}
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    status, body, response_headers = response.status, response.read(), dict(response.getheaders())
    conn.close()
    return status, body, response_headers


def test_home_preserves_canonical_order_and_subsumed_child_is_not_primary():
    first = _thread("b", priority="low")
    child = _thread("c", subsumed_by_thread_id=first.thread_id,
                    subsumption_reason="Covered by the parent.")
    second = _thread("a", priority="high")
    html = render_investigation_home(_model((first, child, second))).decode()
    assert html.index("Thread b") < html.index("Thread a")
    assert "Thread c" not in html
    assert html.index("/thread/" + first.thread_id) < html.index("/thread/" + second.thread_id)


def test_native_and_application_support_does_not_look_unsupported():
    thread = _thread(
        "a", related_evidence_ids=(),
        related_native_observation_ids=tuple(f"native-observation:{i}:0" for i in range(35)),
        related_application_relation_ids=tuple(f"APP-RELATION-{i}" for i in range(35)),
    )
    html = render_investigation_home(_model((thread,))).decode()
    assert "Retained evidence <strong>0</strong>" in html
    assert "Native observations <strong>35</strong>" in html
    assert "Application relationships <strong>35</strong>" in html
    assert "Evidence: none" not in html
    assert "unsupported" not in html.lower()


def test_endpoint_preview_is_bounded_and_detail_preserves_all_values_in_order():
    endpoints = tuple(f"https://example.test/path/{i:02d}" for i in range(70))
    thread = _thread("a", related_endpoints=endpoints)
    model = _model((thread,))
    home = render_investigation_home(model).decode()
    detail = render_thread_detail(model, thread).decode()
    assert home.count('class="endpoint"') == ENDPOINT_PREVIEW_LIMIT
    assert "+65 more" in home
    assert endpoints[5] not in home
    assert detail.count('class="endpoint"') == 70
    assert all(detail.index(left) < detail.index(right) for left, right in zip(endpoints, endpoints[1:]))


def test_project_controlled_content_is_html_escaped_everywhere():
    malicious = '<script>alert("x")</script>'
    thread = _thread("a", title=malicious, summary=malicious,
                     why_it_matters=malicious, related_endpoints=(malicious,),
                     suggested_manual_review_order=(malicious,), kill_switch_guidance=malicious,
                     limitation_codes=(malicious,))
    model = _model((thread,), name=malicious)
    for body in (render_investigation_home(model), render_thread_detail(model, thread)):
        html = body.decode()
        assert malicious not in html
        assert "&lt;script&gt;" in html
        assert 'alert(&quot;x&quot;)' in html


def test_authority_coverage_and_canonical_absence_have_distinct_honest_states():
    absent = render_investigation_home(_model(None)).decode()
    empty = render_investigation_home(_model(())).decode()
    assert "Canonical priorities unavailable" in absent
    assert "No canonical priorities recorded" in empty
    assert "not an all-clear" in empty
    assert "Application model unavailable" in absent
    assert "Coverage snapshot unavailable" in absent
    assert "Private programme policy not bound · internal-authorised project" in absent
    assessment = EngagementPolicyAssessment(
        "complete_for_future_enforcement", (), "safe", "safe", "safe", "blocked"
    )
    safe = render_investigation_home(_model(
        (), context="bug_bounty",
        authority=DashboardAuthoritySummary(assessment, 20, 0),
    )).decode()
    assert "20 inclusion rules · 0 exclusion rules" in safe
    assert "does not grant execution authority" in safe
    assert "SECRET-HEADER" not in safe
    assert "private-rule-value" not in safe


def test_structured_confidence_notice_is_visible_as_collection_context_not_finding():
    notice = CollectionConfidenceNotice(
        "CONFIDENCE-ONE", "intentionally_bounded", "Scope-bound collection",
        "16 requests were withheld: programme_scope_unknown.",
        "Uncollected responses remain unknown.", "Deep source collection",
    )
    html = render_investigation_home(_model((_thread("a"),), notices=(notice,))).decode()
    assert "16 requests were withheld" in html
    assert "Collection context" in html
    assert "Scope-bound collection" in html
    assert html.index("Scope-bound collection") < html.index("Investigations</h2>")


def test_server_binds_only_loopback_and_has_fixed_routes_and_headers():
    model = _model((_thread("a"),))
    with _running(DashboardHTTPServer(model)) as server:
        assert server.server_address[0] == "127.0.0.1"
        assert server.url.startswith("http://127.0.0.1:")
        status, body, headers = _request(server, "/")
        assert status == 200 and b"Thread a" in body
        assert headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Content-Type-Options"] == "nosniff"
        css_status, css, _ = _request(server, "/assets/dashboard.css")
        assert css_status == 200 and b".thread-card" in css
        detail_status, detail, _ = _request(server, "/thread/" + model.investigation_threads[0].thread_id)
        assert detail_status == 200 and b"Review the retained response" in detail


@pytest.mark.parametrize("path", [
    "/project_state.json", "/bugslyce_project.json", "/etc/passwd",
    "/../etc/passwd", "/assets/../../etc/passwd", "/%2e%2e/etc/passwd",
    "//example.test/", "/?file=project_state.json", "/thread/THREAD-not-real",
])
def test_no_arbitrary_filesystem_route_or_directory_listing(path):
    with _running(DashboardHTTPServer(_model(()))) as server:
        status, body, _ = _request(server, path)
        assert status == 404
        assert body == b"Not found"


def test_rejects_nonlocal_host_header():
    with _running(DashboardHTTPServer(_model(()))) as server:
        status, _, _ = _request(server, "/", host="attacker.example")
        assert status == 400


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutation_methods_are_unreachable(method):
    with _running(DashboardHTTPServer(_model(()))) as server:
        status, body, headers = _request(server, "/", method=method)
        assert status == 405 and body == b""
        assert headers["Allow"] == "GET, HEAD"


def test_unsupported_method_is_plain_text_with_csp():
    with _running(DashboardHTTPServer(_model(()))) as server:
        status, body, headers = _request(server, "/", method="OPTIONS")
        assert status == 501 and body == b"Request refused"
        assert headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


def test_startup_loads_read_model_once_and_requests_do_not_reload(monkeypatch, tmp_path):
    marker = tmp_path / "unchanged.txt"
    marker.write_text("saved")
    calls = []
    model = _model((_thread("a"),))

    def load(project):
        calls.append(project)
        return model

    monkeypatch.setattr("bugslyce.dashboard.server.build_dashboard_read_model", load)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("subprocess started"))
    with _running(create_dashboard_server(tmp_path)) as server:
        for route in ("/", "/thread/" + model.investigation_threads[0].thread_id,
                      "/limitations", "/evidence", "/evidence/generic/page/1",
                      "/assets/dashboard.css"):
            assert _request(server, route)[0] == 200
        assert len(calls) == 1
    assert marker.read_text() == "saved"
    assert tuple(tmp_path.iterdir()) == (marker,)


def test_full_endpoint_detail_is_only_rendered_after_deliberate_request(monkeypatch):
    calls = []
    from bugslyce.dashboard import server as dashboard_server

    original = dashboard_server.render_thread_detail

    def render(model, thread, evidence_navigation=None):
        calls.append(thread.thread_id)
        return original(model, thread, evidence_navigation)

    monkeypatch.setattr(dashboard_server, "render_thread_detail", render)
    thread = _thread("a", related_endpoints=tuple(
        f"https://example.test/{index}" for index in range(70)
    ))
    with _running(DashboardHTTPServer(_model((thread,)))) as server:
        assert calls == []
        assert _request(server, "/")[0] == 200
        assert calls == []
        assert _request(server, "/thread/" + thread.thread_id)[0] == 200
        assert calls == [thread.thread_id]


def test_raw_root_does_not_adopt_adjacent_private_authority_files(tmp_path):
    (tmp_path / "engagement_policy.json").write_text("SECRET-HEADER")
    (tmp_path / "programme_scope.json").write_text("private-rule-value")
    model = build_dashboard_read_model(tmp_path)
    html = render_investigation_home(model).decode()
    assert model.authority.engagement_assessment is None
    assert model.authority.programme_include_rule_count is None
    assert "SECRET-HEADER" not in html
    assert "private-rule-value" not in html


def test_stylesheet_is_a_packaged_local_resource_without_remote_dependencies():
    css = files("bugslyce.dashboard").joinpath("static", "dashboard.css").read_text()
    assert ".thread-card" in css
    assert not re.search(r"@import|url\s*\(|https?://|cdn", css, re.IGNORECASE)
    html = render_investigation_home(_model(())).decode()
    assert 'href="/assets/dashboard.css"' in html
    assert "<script" not in html
    assert not re.search(r"https?://(?!example\.test)", html)


def test_invalid_model_refuses_before_opening_listener(monkeypatch, tmp_path):
    def refuse(project):
        raise ValueError("Malformed canonical snapshot")

    monkeypatch.setattr("bugslyce.dashboard.server.build_dashboard_read_model", refuse)
    with pytest.raises(ValueError, match="Malformed canonical snapshot"):
        create_dashboard_server(tmp_path)


def test_cli_launches_only_after_loading_and_closes_on_ctrl_c(monkeypatch, capsys, tmp_path):
    events = []

    class FakeServer:
        url = "http://127.0.0.1:7777/"

        def serve_forever(self, *, poll_interval):
            events.append(("serve", poll_interval))
            raise KeyboardInterrupt

        def server_close(self):
            events.append(("close",))

    def make_server(project, *, port):
        events.append(("load", project, port))
        return FakeServer()

    monkeypatch.setattr("bugslyce.cli.create_dashboard_server", make_server)
    assert main(["dashboard", str(tmp_path), "--port", "7777"]) == 0
    out = capsys.readouterr().out
    assert out.index("Loading saved dashboard state") < out.index("http://127.0.0.1:7777/")
    assert events == [("load", tmp_path, 7777), ("serve", 0.2), ("close",)]


def test_cli_reports_malformed_project_without_advertising_listener(monkeypatch, capsys, tmp_path):
    def refuse(project, *, port):
        raise ValueError("Malformed canonical snapshot")

    monkeypatch.setattr("bugslyce.cli.create_dashboard_server", refuse)
    assert main(["dashboard", str(tmp_path)]) == 2
    output = capsys.readouterr()
    assert "Loading saved dashboard state" in output.out
    assert "http://127.0.0.1" not in output.out
    assert "Malformed canonical snapshot" in output.err
    assert "No dashboard listener was opened" in output.err
