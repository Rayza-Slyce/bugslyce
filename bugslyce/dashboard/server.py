"""Fixed-route loopback host for the immutable dashboard projection."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
import re
from urllib.parse import urlsplit

from bugslyce.dashboard.application_view import (
    DOCUMENTATION_PAGE_SIZE,
    RELATION_PAGE_SIZE,
    ROUTE_PAGE_SIZE,
    build_application_navigation,
    page_count,
    render_application_home,
    render_documentation_page,
    render_origin_detail,
)
from bugslyce.dashboard.evidence_view import (
    GENERIC_PAGE_SIZE,
    NATIVE_PAGE_SIZE,
    RELATION_PAGE_SIZE as EVIDENCE_RELATION_PAGE_SIZE,
    SUPPORT_PAGE_SIZE,
    build_evidence_navigation,
    render_evidence_index,
    render_evidence_landing,
    render_generic_detail,
    render_native_detail,
    render_relation_detail,
)
from bugslyce.dashboard.presentation import (
    render_investigation_home,
    render_limitations,
    render_thread_detail,
)
from bugslyce.dashboard.read_model import DashboardReadModel, build_dashboard_read_model
from bugslyce.project_session import BugSlyceProject


LOOPBACK_HOST = "127.0.0.1"
_ORIGIN_PATH = re.compile(
    r"/application/origin/(APP-ORIGIN-[0-9a-f]{64})(?:/(routes|relations)/([1-9][0-9]{0,4}))?\Z"
)
_DOCUMENTATION_PATH = re.compile(r"/application/documentation/page/([1-9][0-9]{0,4})\Z")
_EVIDENCE_INDEX_PATH = re.compile(r"/evidence/(generic|native|application)/page/([1-9][0-9]{0,4})\Z")
_GENERIC_EVIDENCE_PATH = re.compile(r"/evidence/generic/id/([0-9a-f]{64})\Z")
_NATIVE_EVIDENCE_PATH = re.compile(r"/evidence/native/(0|[1-9][0-9]*)/(0|[1-9][0-9]*)\Z")
_RELATION_EVIDENCE_PATH = re.compile(
    r"/evidence/application/(APP-RELATION-[0-9a-f]{64})(?:/supports/([1-9][0-9]{0,4}))?\Z"
)
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; script-src 'none'; img-src 'none'; "
    "font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


class DashboardHTTPServer(HTTPServer):
    """Local, immutable pages only. There is no project-file route."""

    def __init__(self, model: DashboardReadModel, *, port: int = 0) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("Dashboard port must be an integer from 0 to 65535")
        self.dashboard_model = model
        self.stylesheet = (
            files("bugslyce.dashboard").joinpath("static", "dashboard.css").read_bytes()
        )
        self.home_page = render_investigation_home(model)
        self.limitations_page = render_limitations(model)
        self.application_navigation = build_application_navigation(model.application_service_model)
        self.evidence_navigation = build_evidence_navigation(model)
        self.evidence_home_page = render_evidence_landing(model, self.evidence_navigation)
        self.threads_by_path = {
            f"/thread/{thread.thread_id}": thread
            for thread in (model.investigation_threads or ())
        }
        super().__init__((LOOPBACK_HOST, port), _DashboardRequestHandler)

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self.server_port}/"


class _DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Even malformed/unsupported requests get a plain fixed body and CSP.
        self._send(code, b"Request refused", "text/plain; charset=utf-8")

    def _send(self, status: int, body: bytes, content_type: str, *, head: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _read_page(self, *, head: bool = False) -> None:
        if self.headers.get("Host") != f"{LOOPBACK_HOST}:{self.server.server_port}":
            self._send(400, b"Invalid local Host header", "text/plain; charset=utf-8", head=head)
            return
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
            return
        if parsed.path == "/":
            body, content_type = self.server.home_page, "text/html; charset=utf-8"
        elif parsed.path == "/limitations":
            body, content_type = self.server.limitations_page, "text/html; charset=utf-8"
        elif parsed.path == "/assets/dashboard.css":
            body, content_type = self.server.stylesheet, "text/css; charset=utf-8"
        elif parsed.path == "/evidence":
            body, content_type = self.server.evidence_home_page, "text/html; charset=utf-8"
        elif matched := _EVIDENCE_INDEX_PATH.fullmatch(parsed.path):
            domain, page = matched.group(1), int(matched.group(2))
            navigation = self.server.evidence_navigation
            count, size = {
                "generic": (len(navigation.generic or ()), GENERIC_PAGE_SIZE),
                "native": (len(navigation.native_sources), NATIVE_PAGE_SIZE),
                "application": (len(navigation.relations or ()), EVIDENCE_RELATION_PAGE_SIZE),
            }[domain]
            if page > page_count(count, size):
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_evidence_index(self.server.dashboard_model, navigation, domain, page)
            content_type = "text/html; charset=utf-8"
        elif matched := _GENERIC_EVIDENCE_PATH.fullmatch(parsed.path):
            navigation = self.server.evidence_navigation
            item = navigation.generic_by_locator.get(matched.group(1))
            if item is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_generic_detail(self.server.dashboard_model, navigation, item)
            content_type = "text/html; charset=utf-8"
        elif matched := _NATIVE_EVIDENCE_PATH.fullmatch(parsed.path):
            navigation = self.server.evidence_navigation
            identity = f"native-observation:{matched.group(1)}:{matched.group(2)}"
            source = navigation.native_by_id.get(identity)
            if source is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_native_detail(self.server.dashboard_model, navigation, source)
            content_type = "text/html; charset=utf-8"
        elif matched := _RELATION_EVIDENCE_PATH.fullmatch(parsed.path):
            navigation = self.server.evidence_navigation
            relation = navigation.relation_by_id.get(matched.group(1))
            page = int(matched.group(2)) if matched.group(2) else 1
            if relation is None or page > page_count(len(relation.supports), SUPPORT_PAGE_SIZE):
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_relation_detail(
                self.server.dashboard_model, navigation, relation, page=page
            )
            content_type = "text/html; charset=utf-8"
        elif parsed.path == "/application":
            body = render_application_home(
                self.server.dashboard_model, self.server.application_navigation
            )
            content_type = "text/html; charset=utf-8"
        elif parsed.path == "/application/documentation" or _DOCUMENTATION_PATH.fullmatch(parsed.path):
            if self.server.application_navigation.model is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            matched = _DOCUMENTATION_PATH.fullmatch(parsed.path)
            page = int(matched.group(1)) if matched else 1
            if page > page_count(
                len(self.server.application_navigation.documentation_items),
                DOCUMENTATION_PAGE_SIZE,
            ):
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_documentation_page(
                self.server.dashboard_model, self.server.application_navigation, page=page
            )
            content_type = "text/html; charset=utf-8"
        elif matched := _ORIGIN_PATH.fullmatch(parsed.path):
            origin = self.server.application_navigation.origin_for_id(matched.group(1))
            if origin is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            page = int(matched.group(3)) if matched.group(3) else 1
            routes_page = page if matched.group(2) == "routes" else 1
            relations_page = page if matched.group(2) == "relations" else 1
            if (
                routes_page > page_count(len(origin.routes), ROUTE_PAGE_SIZE)
                or relations_page > page_count(len(origin.relations), RELATION_PAGE_SIZE)
            ):
                self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
                return
            body = render_origin_detail(
                self.server.dashboard_model,
                self.server.application_navigation,
                origin,
                routes_page=routes_page,
                relations_page=relations_page,
            )
            content_type = "text/html; charset=utf-8"
        elif parsed.path in self.server.threads_by_path:
            body = render_thread_detail(
                self.server.dashboard_model,
                self.server.threads_by_path[parsed.path],
                self.server.evidence_navigation,
            )
            content_type = "text/html; charset=utf-8"
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8", head=head)
            return
        self._send(200, body, content_type, head=head)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._read_page()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._read_page(head=True)

    def _method_not_allowed(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._method_not_allowed()

    def log_message(self, format: str, *args: object) -> None:
        # Requests do not need to reveal project-controlled strings in the CLI.
        return


def create_dashboard_server(
    project: BugSlyceProject | Path, *, port: int = 0
) -> DashboardHTTPServer:
    """Load the accepted read model once, before binding the loopback listener."""

    model = build_dashboard_read_model(project)
    return DashboardHTTPServer(model, port=port)
