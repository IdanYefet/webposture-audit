import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from webposture.cookie_audit import audit_cookies
from webposture.models import Severity


def run_server(cookie_headers):
    """Start a local HTTP server that sends the given Set-Cookie headers.

    Returns (server, url). The caller must call server.shutdown().
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for value in cookie_headers:
                self.send_header("Set-Cookie", value)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_insecure_cookie_reports_three_findings():
    server, url = run_server(["sid=abc123; Path=/"])
    try:
        findings = audit_cookies(url)
    finally:
        server.shutdown()
    assert len(findings) == 3
    assert all("'sid'" in f.title for f in findings)


def test_secure_cookie_has_no_findings():
    server, url = run_server(
        ["sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"]
    )
    try:
        findings = audit_cookies(url)
    finally:
        server.shutdown()
    assert findings == []


def test_missing_samesite_is_low_severity():
    server, url = run_server(["sid=abc123; Path=/; Secure; HttpOnly"])
    try:
        findings = audit_cookies(url)
    finally:
        server.shutdown()
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_each_cookie_is_checked_separately():
    server, url = run_server(
        ["a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Path=/"]
    )
    try:
        findings = audit_cookies(url)
    finally:
        server.shutdown()
    assert len(findings) == 3
    assert all("'b'" in f.title for f in findings)


def test_no_cookies_means_no_findings():
    server, url = run_server([])
    try:
        findings = audit_cookies(url)
    finally:
        server.shutdown()
    assert findings == []