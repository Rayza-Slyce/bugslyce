"""Fixed-route loopback host for the immutable dashboard projection."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from bugslyce.dashboard.presentation import (
    render_investigation_home,
    render_limitations,
    render_thread_detail,
)
from bugslyce.dashboard.read_model import DashboardReadModel, build_dashboard_read_model
from bugslyce.project_session import BugSlyceProject


LOOPBACK_HOST = "127.0.0.1"
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
        elif parsed.path in self.server.threads_by_path:
            body = render_thread_detail(
                self.server.dashboard_model,
                self.server.threads_by_path[parsed.path],
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
