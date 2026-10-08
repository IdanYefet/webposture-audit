import requests

from webposture.models import Finding, Severity


def audit_cookies(url: str, timeout: int = 10) -> list[Finding]:
    """Request the URL and check the security flags of every cookie it sets."""
    response = requests.get(url, timeout=timeout, allow_redirects=True)

    # Each Set-Cookie header is one cookie. We read the raw headers because
    # the parsed cookie jar does not keep flags like HttpOnly and SameSite.
    raw_cookies = response.raw.headers.getlist("Set-Cookie")

    findings = []
    for raw_cookie in raw_cookies:
        name = raw_cookie.split("=", 1)[0].strip()
        attributes = raw_cookie.lower()

        if "httponly" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    description="JavaScript can read this cookie, so an XSS flaw could steal it.",
                    recommendation="Add the HttpOnly attribute to the Set-Cookie header.",
                )
            )
        if "secure" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    description="The cookie can be sent over plain HTTP and intercepted.",
                    recommendation="Add the Secure attribute (requires the site to use HTTPS).",
                )
            )
        if "samesite" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    description="The cookie may be sent on cross-site requests, which helps CSRF attacks.",
                    recommendation="Add 'SameSite=Lax' or 'SameSite=Strict'.",
                )
            )
    return findings