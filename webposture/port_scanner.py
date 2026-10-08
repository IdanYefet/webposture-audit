import socket
from concurrent.futures import ThreadPoolExecutor

from webposture.models import Finding, Severity

# Port number -> (service name, severity if open, why it matters)
COMMON_PORTS = {
    21: ("FTP", Severity.HIGH, "FTP sends credentials in plain text."),
    22: ("SSH", Severity.INFO, "Remote administration is exposed; make sure it is hardened."),
    23: ("Telnet", Severity.HIGH, "Telnet is unencrypted and obsolete."),
    25: ("SMTP", Severity.LOW, "Mail server exposed; check it is not an open relay."),
    53: ("DNS", Severity.LOW, "DNS service exposed; check for zone transfer and recursion."),
    80: ("HTTP", Severity.INFO, "Web server without encryption."),
    110: ("POP3", Severity.MEDIUM, "POP3 is unencrypted unless wrapped in TLS."),
    139: ("NetBIOS", Severity.MEDIUM, "Legacy Windows file sharing exposed."),
    143: ("IMAP", Severity.MEDIUM, "IMAP is unencrypted unless wrapped in TLS."),
    443: ("HTTPS", Severity.INFO, "Encrypted web server."),
    445: ("SMB", Severity.HIGH, "SMB has a long history of critical vulnerabilities."),
    3306: ("MySQL", Severity.HIGH, "Database should not be reachable from outside."),
    3389: ("RDP", Severity.HIGH, "Remote Desktop is a frequent ransomware entry point."),
    5432: ("PostgreSQL", Severity.HIGH, "Database should not be reachable from outside."),
    8080: ("HTTP-alt", Severity.INFO, "Alternative web server port."),
}


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Try a full TCP connection. Success means the port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports=None, timeout: float = 1.0, workers: int = 20) -> list[Finding]:
    """Scan the given ports in parallel and report the open ones."""
    ports = list(ports) if ports is not None else list(COMMON_PORTS)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda p: is_port_open(host, p, timeout), ports))

    findings = []
    for port, is_open in zip(ports, results):
        if not is_open:
            continue
        service, severity, reason = COMMON_PORTS.get(
            port, ("unknown", Severity.INFO, "Open port with an unrecognized service.")
        )
        findings.append(
            Finding(
                title=f"Open port {port}/tcp ({service})",
                severity=severity,
                description=reason,
                recommendation="Close the port if the service is not needed, or restrict access with a firewall.",
            )
        )
    return findings