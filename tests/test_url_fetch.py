import threading
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from attack_flow_api.services.url_fetch import UrlFetchError, fetch_url_bounded


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            body = b"hello"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return

        if self.path == "/redirect-blocked":
            self.send_response(302)
            self.send_header("Location", "http://blocked.example/ok")
            self.end_headers()
            return

        if self.path == "/big":
            body = b"x" * 50
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003
        _ = (format, args)


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=1)


def test_fetch_url_bounded_returns_metadata_and_body(local_server):
    result = fetch_url_bounded(
        f"{local_server}/ok",
        allowed_schemes={"http", "https"},
        block_private_destinations=False,
        connect_timeout_seconds=1.0,
        read_timeout_seconds=1.0,
        max_redirects=2,
        max_response_bytes=100,
    )
    assert result.final_url.endswith("/ok")
    assert result.status_code == 200
    assert result.content_type == "text/plain"
    assert result.size_bytes == 5
    assert result.body == b"hello"


def test_fetch_url_bounded_follows_redirects_with_limit(local_server):
    result = fetch_url_bounded(
        f"{local_server}/redirect",
        allowed_schemes={"http", "https"},
        block_private_destinations=False,
        connect_timeout_seconds=1.0,
        read_timeout_seconds=1.0,
        max_redirects=2,
        max_response_bytes=100,
    )
    assert result.final_url.endswith("/ok")
    assert result.status_code == 200


def test_fetch_url_bounded_rejects_when_redirect_limit_exceeded(local_server):
    with pytest.raises(UrlFetchError) as exc:
        fetch_url_bounded(
            f"{local_server}/redirect",
            allowed_schemes={"http", "https"},
            block_private_destinations=False,
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            max_redirects=0,
            max_response_bytes=100,
        )
    assert exc.value.code == "redirect_limit_exceeded"


def test_fetch_url_bounded_enforces_max_response_size(local_server):
    with pytest.raises(UrlFetchError) as exc:
        fetch_url_bounded(
            f"{local_server}/big",
            allowed_schemes={"http", "https"},
            block_private_destinations=False,
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            max_redirects=1,
            max_response_bytes=10,
        )
    assert exc.value.code == "response_too_large"


def test_fetch_url_bounded_uses_ssrf_validation_for_scheme():
    with pytest.raises(UrlFetchError) as exc:
        fetch_url_bounded(
            "ftp://example.com/file",
            allowed_schemes={"http", "https"},
            block_private_destinations=True,
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            max_redirects=1,
            max_response_bytes=10,
        )
    assert exc.value.code == "invalid_url_scheme"


def test_fetch_url_bounded_revalidates_redirect_destination_and_blocks_unsafe_target(local_server):
    def fake_resolver(hostname, _port, family=0, type=0, proto=0, flags=0):
        _ = (family, type, proto, flags)
        if hostname == "blocked.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    with pytest.raises(UrlFetchError) as exc:
        fetch_url_bounded(
            f"{local_server}/redirect-blocked",
            allowed_schemes={"http", "https"},
            block_private_destinations=True,
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            max_redirects=2,
            max_response_bytes=100,
            resolver=fake_resolver,
        )
    assert exc.value.code == "unsafe_destination"
