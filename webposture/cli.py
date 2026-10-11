import argparse
from urllib.parse import urlparse

import requests

from webposture.cookie_audit import audit_cookies
from webposture.http_headers_audit import audit_http_headers
from webposture.models import Finding
from webposture.port_scanner import scan_ports
from webposture.report_generator import sort_findings, write_report


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line arguments the tool accepts."""
    parser = argparse.ArgumentParser(
        prog="webposture",
        description=(
            "Audit the security posture of a web application. "
            "Use only on targets you own or are explicitly authorized to test."
        ),
    )
    parser.add_argument(
        "url",
        help="Target URL, e.g. http://localhost:3000",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated ports to scan, e.g. 22,80,3000",
    )
    parser.add_argument(
        "--skip-ports",
        action="store_true",
        help="Do not run the port scan",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Write an HTML report to the reports folder",
    )
    return parser


def parse_ports(value):
    """Turn '22,80,3000' into [22, 80, 3000]. Returns None if no value."""
    if value is None:
        return None
    return [int(part) for part in value.split(",")]


def print_findings(target: str, findings: list[Finding]) -> None:
    """Print findings to the terminal, most serious first."""
    print(f"Target: {target}")
    print(f"Findings: {len(findings)}")
    print()
    for finding in sort_findings(findings):
        print(f"[{finding.severity.value.upper()}] {finding.title}")
        print(f"    Why it matters: {finding.description}")
        print(f"    Fix: {finding.recommendation}")
        print()


def main() -> int:
    """Run all audits and print the results. Returns an exit code."""
    args = build_parser().parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("Error: --ports must be numbers separated by commas")
        return 2

    host = urlparse(args.url).hostname
    if host is None:
        print("Error: URL must start with http:// or https://")
        return 2

    findings: list[Finding] = []
    try:
        findings += audit_http_headers(args.url, timeout=args.timeout)
        findings += audit_cookies(args.url, timeout=args.timeout)
    except requests.RequestException as error:
        print(f"Error: could not reach {args.url} ({type(error).__name__})")
        return 1

    if not args.skip_ports:
        findings += scan_ports(host, ports=ports)

    print_findings(args.url, findings)

    if args.report:
        path = write_report(args.url, findings)
        print(f"Report written to: {path}")
    return 0