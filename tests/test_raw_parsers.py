"""Tests for structured raw recon artifact parsers."""

from __future__ import annotations

from pathlib import Path

from bugslyce.parsers.gobuster import parse_gobuster
from bugslyce.parsers.html import parse_html
from bugslyce.parsers.http_headers import parse_http_headers
from bugslyce.parsers.nmap import (
    NMAP_OUTPUT_DISCOVERY,
    NMAP_OUTPUT_SERVICE_VERSION,
    classify_nmap_output_role,
    parse_nmap_normal,
    parse_nmap_normal_with_host_peers,
)
from bugslyce.parsers.robots import parse_robots


def test_nmap_parser_extracts_varied_http_ssh_and_database_services(tmp_path: Path) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for api.example-bounty.test (192.0.2.25)",
                "PORT     STATE SERVICE VERSION",
                "8088/tcp open  http    Caddy 2.7",
                "2222/tcp open  ssh     OpenSSH 9.0",
                "5432/tcp open  postgresql PostgreSQL 15",
            ]
        ),
        encoding="utf-8",
    )

    records = parse_nmap_normal(source)

    assert [(record.port, record.service) for record in records] == [
        (8088, "http"),
        (2222, "ssh"),
        (5432, "postgresql"),
    ]
    assert all(record.host == "192.0.2.25" for record in records)
    assert records[0].product == "Caddy"
    assert records[0].version == "2.7"


def test_nmap_parser_preserves_reported_host_peer_relationships(tmp_path: Path) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "Nmap scan report for blog.thm (10.82.174.151)\n"
        "PORT   STATE SERVICE\n"
        "80/tcp open  http\n"
        "Nmap scan report for unrelated.thm (10.82.174.152)\n"
        "PORT     STATE SERVICE\n"
        "8080/tcp open  http\n",
        encoding="utf-8",
    )

    parsed = parse_nmap_normal_with_host_peers(source)

    assert [(item.host, item.port) for item in parsed.port_services] == [
        ("10.82.174.151", 80),
        ("10.82.174.152", 8080),
    ]
    assert [
        (item.reported_host, item.peer_host, item.source_file, item.report_line)
        for item in parsed.reported_host_peers
    ] == [
        ("blog.thm", "10.82.174.151", str(source), 1),
        ("unrelated.thm", "10.82.174.152", str(source), 4),
    ]


def test_nmap_parser_keeps_single_identity_report_forms_relation_free(
    tmp_path: Path,
) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "Nmap scan report for blog.thm\n"
        "PORT   STATE SERVICE\n"
        "80/tcp open  http\n"
        "Nmap scan report for 10.82.174.151\n"
        "PORT    STATE SERVICE\n"
        "443/tcp open  https\n",
        encoding="utf-8",
    )

    parsed = parse_nmap_normal_with_host_peers(source)

    assert [item.host for item in parsed.port_services] == [
        "blog.thm",
        "10.82.174.151",
    ]
    assert parsed.reported_host_peers == []


def test_nmap_output_role_uses_retained_table_shape_not_filename(tmp_path: Path) -> None:
    discovery = tmp_path / "unexpected-service-name.txt"
    service_version = tmp_path / "unexpected-discovery-name.txt"
    discovery.write_text(
        "Nmap scan report for app.example.test\n"
        "PORT     STATE SERVICE\n"
        "80/tcp   open  http\n",
        encoding="utf-8",
    )
    service_version.write_text(
        "Nmap scan report for app.example.test\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  ssh     OpenSSH 9.0\n",
        encoding="utf-8",
    )

    assert classify_nmap_output_role(discovery) == NMAP_OUTPUT_DISCOVERY
    assert (
        classify_nmap_output_role(service_version)
        == NMAP_OUTPUT_SERVICE_VERSION
    )


def test_nmap_parser_recognises_same_port_escaped_http_fingerprint(tmp_path: Path) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT     STATE SERVICE VERSION",
                "3000/tcp open  ppp?",
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port3000-TCP:V=7.94%I=7%D=7/31%Time=synthetic%P=x86_64-pc-linux-gnu%r(",
                'SF:GetRequest,123,"HTTP/1\\.1\\x20200\\x20OK\\r\\nContent-Type:\\x20text/html',
                'SF:\\r\\n\\r\\n<title>OWASP Juice Shop</title>")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = parse_nmap_normal(source)

    assert len(records) == 1
    assert records[0].service == "ppp?"
    assert "http_protocol_evidence" in records[0].tags


def test_nmap_http_fingerprint_recognition_is_port_local_and_requires_status_line(
    tmp_path: Path,
) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT     STATE SERVICE VERSION",
                "3000/tcp open  unknown",
                "4000/tcp open  unknown",
                "5000/tcp open  unknown HTTP-compatible product text",
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port3000-TCP:V=7.94%r(GetRequest,80,",
                'SF:"Content-Type: text/html\\r\\n\\r\\nHTTP documentation")',
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port4000-TCP:V=7.94%r(GetRequest,80,",
                'SF:"HTTP/1.1 404 Not Found\\r\\nContent-Type: text/html")',
                "Nmap scan report for 10.10.10.11",
                "PORT     STATE SERVICE VERSION",
                "4000/tcp open  unknown",
                "Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds; HTTP/1.1 200",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = {(record.host, record.port): record for record in parse_nmap_normal(source)}

    assert "http_protocol_evidence" not in records[("10.10.10.10", 3000)].tags
    assert "http_protocol_evidence" in records[("10.10.10.10", 4000)].tags
    assert "http_protocol_evidence" not in records[("10.10.10.10", 5000)].tags
    assert "http_protocol_evidence" not in records[("10.10.10.11", 4000)].tags


def test_nmap_http_fingerprint_requires_status_at_response_payload_start(
    tmp_path: Path,
) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT     STATE SERVICE VERSION",
                "3000/tcp open  unknown",
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port3000-TCP:V=7.94%r(GetRequest,100,",
                'SF:"non-HTTP preface; body says HTTP/1.1 200 OK\\r\\n")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = parse_nmap_normal(source)

    assert len(records) == 1
    assert "http_protocol_evidence" not in records[0].tags


def test_gobuster_parser_extracts_varied_paths_status_size_and_redirect(tmp_path: Path) -> None:
    source = tmp_path / "gobuster.txt"
    source.write_text(
        "\n".join(
            [
                "admin-panel (Status: 200) [Size: 415]",
                "archive (Status: 302) [Size: 0] [--> https://app.example-bounty.test/archive/]",
                "missing (Status: 404) [Size: 91]",
            ]
        ),
        encoding="utf-8",
    )

    records = parse_gobuster(source, "https://app.example-bounty.test/")

    assert records[0].url == "https://app.example-bounty.test/admin-panel"
    assert records[0].status_code == 200
    assert records[0].content_length == 415
    assert records[1].redirect_location == "https://app.example-bounty.test/archive/"
    assert records[2].status_code == 404


def test_http_header_parser_extracts_final_response_block(tmp_path: Path) -> None:
    source = tmp_path / "curl-headers-api.txt"
    source.write_text(
        "\n".join(
            [
                "HTTP/1.1 301 Moved Permanently",
                "Location: /api/",
                "",
                "HTTP/1.1 200 OK",
                "Server: ExampleServer",
                "Content-Type: application/json",
                "Content-Length: 128",
            ]
        ),
        encoding="utf-8",
    )

    parsed = parse_http_headers(source)

    assert parsed.status_code == 200
    assert parsed.server == "ExampleServer"
    assert parsed.content_type == "application/json"
    assert parsed.content_length == 128
    assert parsed.location is None


def test_robots_parser_extracts_generic_directives(tmp_path: Path) -> None:
    source = tmp_path / "robots-api.txt"
    source.write_text(
        "\n".join(
            [
                "User-Agent: CUSTOM_CRAWLER_PLACEHOLDER",
                "Allow: /public-api/",
                "Disallow: /internal-docs/",
            ]
        ),
        encoding="utf-8",
    )

    artifacts = parse_robots(source, "https://api.example-bounty.test/robots.txt")
    artifact_types = {artifact.artifact_type for artifact in artifacts}

    assert {"robots", "unusual_user_agent", "allow_rule", "disallow_rule"} <= artifact_types
    assert any(artifact.value == "CUSTOM_CRAWLER_PLACEHOLDER" for artifact in artifacts)


def test_html_parser_extracts_metadata_and_conservative_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "saved-page.html"
    source.write_text(
        """
        <html>
          <head>
            <title>Example Account Portal</title>
            <link href="/static/site.css" rel="stylesheet">
            <script src="/static/app.js"></script>
          </head>
          <body>
            <!-- backup token context placeholder -->
            <div hidden id="context-marker">ENCODEDLOOKINGPLACEHOLDER1234567890ABCD</div>
            <a href="/api/v1/users?id=1">API users</a>
            <form action="/account/login"><input type="password" name="password"></form>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/")
    artifact_types = {artifact.artifact_type for artifact in artifacts}

    assert {
        "page_title",
        "link",
        "script_or_asset",
        "html_comment",
        "hidden_element",
        "form",
        "input",
        "encoded_like_artifact",
        "keyword_hit",
    } <= artifact_types
    assert any(artifact.value == "Example Account Portal" for artifact in artifacts)


def test_html_parser_does_not_classify_url_path_fragments_as_encoded(tmp_path: Path) -> None:
    source = tmp_path / "template.html"
    source.write_text(
        """
        <html>
          <body>
            <a href="https://vimeo.example/channels/staffpicks/93951774">video</a>
            <script>const mediaPath = "com/channels/staffpicks/93951774";</script>
            <script>const token = "ObsJmP173N2X6dOrAgEAL0Vu";</script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/sitemap/")

    encoded_values = [
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    ]
    assert "com/channels/staffpicks/93951774" not in encoded_values
    assert "ObsJmP173N2X6dOrAgEAL0Vu" in encoded_values


def test_html_parser_does_not_extract_encoded_fragment_from_absolute_documentation_url(
    tmp_path: Path,
) -> None:
    source = tmp_path / "documentation-link.html"
    source.write_text(
        """
        <html><body>
          <a href="https://docs.example/reference/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789">
            Reference
          </a>
          <script>const standalone = "QWxwaGEvQmV0YStHYW1tYTEyMzQ1Njc4OTA=";</script>
          <script>const slashToken = "AbCdEfGhIjKlMnOp/QrStUvWxYz0123456789ABC";</script>
        </body></html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example.test/")
    encoded_values = {
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    }

    assert "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in encoded_values
    assert "QWxwaGEvQmV0YStHYW1tYTEyMzQ1Njc4OTA=" in encoded_values
    assert "AbCdEfGhIjKlMnOp/QrStUvWxYz0123456789ABC" in encoded_values


def test_html_parser_suppresses_encoded_matches_inside_href_and_src_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "reference-paths.html"
    source.write_text(
        """
        <html><body>
          <a href="/assets/bootstrapbundleminified">asset</a>
          <script src="//static.example.test/librarybundleminified"></script>
          <a href="https://docs.example.test/reference/DocumentationBundleMinified">docs</a>
          <p>AbCdEfGhIjKlMnOp/QrStUvWxYz012345</p>
        </body></html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example.test/")
    encoded_values = [
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    ]

    assert "bootstrapbundleminified" not in encoded_values
    assert "librarybundleminified" not in encoded_values
    assert "DocumentationBundleMinified" not in encoded_values
    assert "AbCdEfGhIjKlMnOp/QrStUvWxYz012345" in encoded_values


def test_html_keyword_matching_respects_token_boundaries(tmp_path: Path) -> None:
    source = tmp_path / "substrings.html"
    source.write_text(
        "<html><body>administrator apical keypad tokenization username-field password_reset</body></html>",
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/")

    assert not [
        artifact
        for artifact in artifacts
        if artifact.artifact_type == "keyword_hit"
    ]

def test_gobuster_parser_accepts_ansi_coloured_status_output(tmp_path: Path) -> None:
    source = tmp_path / "gobuster-ansi.txt"
    source.write_text(
        "robots.txt          \x1b[32m (Status: 200)\x1b[0m [Size: 31]\n",
        encoding="utf-8",
    )

    records = parse_gobuster(source, "http://127.0.0.1:8088/")

    assert len(records) == 1
    assert records[0].url == "http://127.0.0.1:8088/robots.txt"
    assert records[0].status_code == 200
    assert records[0].content_length == 31
