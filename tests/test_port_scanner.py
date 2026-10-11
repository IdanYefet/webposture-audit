import socket

from webposture.models import Severity
from webposture.port_scanner import is_port_open, scan_ports


def start_local_server():
    """Open a listening socket on a free port and return (socket, port)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    return server, server.getsockname()[1]


def test_open_port_is_detected():
    server, port = start_local_server()
    try:
        assert is_port_open("127.0.0.1", port) is True
    finally:
        server.close()


def test_closed_port_is_not_detected():
    server, port = start_local_server()
    server.close()
    assert is_port_open("127.0.0.1", port) is False


def test_scan_reports_only_open_ports():
    server, port = start_local_server()
    try:
        findings = scan_ports("127.0.0.1", ports=[port])
    finally:
        server.close()
    assert len(findings) == 1
    assert str(port) in findings[0].title
    assert findings[0].severity == Severity.INFO