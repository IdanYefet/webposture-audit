import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from webposture.http_headers_audit import audit_http_headers
from webposture.models import Severity


def run_server(headers):
    """Start a local HTTP server that replies with the given headers.

    Returns (server, url). The caller must call server.shutdown().
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()

        def log_message(self, *args):
            pass  # keep test output clean

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_all_headers_missing_reports_five_findings():
    server, url = run_server({})
    try:
        findings = audit_http_headers(url)
    finally:
        server.shutdown()
    assert len(findings) == 5


def test_hsts_missing_is_high_severity():
    server, url = run_server({})
    try:
        findings = audit_http_headers(url)
    finally:
        server.shutdown()
    hsts = [f for f in findings if "Strict-Transport-Security" in f.title]
    assert len(hsts) == 1
    assert hsts[0].severity == Severity.HIGH


def test_present_headers_are_not_reported():
    secure_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    server, url = run_server(secure_headers)
    try:
        findings = audit_http_headers(url)
    finally:
        server.shutdown()
    assert findings == []