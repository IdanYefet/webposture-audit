import requests

from webposture.models import Finding, Severity

# Each entry: header name -> (severity if missing, what it protects, how to fix)
EXPECTED_HEADERS = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Without HSTS, browsers may connect over plain HTTP, allowing traffic interception.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "Content-Security-Policy": (
        Severity.HIGH,
        "Without a CSP, the browser has no restriction on script sources, which makes XSS easier to exploit.",
        "Define a Content-Security-Policy that limits allowed script sources.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "The site can be embedded in a malicious iframe, enabling clickjacking.",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    ),
    "X-Content-Type-Options": (
        Severity.MEDIUM,
        "Browsers may guess the content type of responses (MIME sniffing).",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Full URLs may leak to third-party sites through the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
}


def audit_http_headers(url: str, timeout: int = 10) -> list[Finding]:
    """Request the URL and report which expected security headers are missing."""
    response = requests.get(url, timeout=timeout, allow_redirects=True)

    findings = []
    for header_name, (severity, description, recommendation) in EXPECTED_HEADERS.items():
        if header_name not in response.headers:
            findings.append(
                Finding(
                    title=f"Missing header: {header_name}",
                    severity=severity,
                    description=description,
                    recommendation=recommendation,
                )
            )
    return findings