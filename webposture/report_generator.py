from datetime import datetime
from html import escape
from pathlib import Path

from webposture.models import Finding, Severity

SEVERITY_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_COLORS = {
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#e67e22",
    Severity.LOW: "#f1c40f",
    Severity.INFO: "#3498db",
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings from most to least serious."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))


def build_html_report(target: str, findings: list[Finding]) -> str:
    """Build a self-contained HTML report for the given findings."""
    ordered = sort_findings(findings)
    counts = {s: sum(1 for f in ordered if f.severity == s) for s in SEVERITY_ORDER}

    summary = " | ".join(f"{s.value.upper()}: {counts[s]}" for s in SEVERITY_ORDER)

    rows = []
    for f in ordered:
        color = SEVERITY_COLORS[f.severity]
        rows.append(
            f'<div class="finding" style="border-left: 6px solid {color}">'
            f'<h3><span style="color:{color}">[{f.severity.value.upper()}]</span> {escape(f.title)}</h3>'
            f"<p><b>Why it matters:</b> {escape(f.description)}</p>"
            f"<p><b>Fix:</b> {escape(f.recommendation)}</p>"
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Posture Report - {escape(target)}</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 2rem auto; color: #222; }}
  .finding {{ background: #f7f7f7; padding: 0.5rem 1rem; margin: 1rem 0; }}
  .summary {{ font-size: 1.1rem; font-weight: bold; }}
</style>
</head>
<body>
<h1>Security Posture Report</h1>
<p><b>Target:</b> {escape(target)}<br>
<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M}</p>
<p class="summary">{summary}</p>
{"".join(rows) if rows else "<p>No findings.</p>"}
</body>
</html>"""


def write_report(target: str, findings: list[Finding], output_dir: str = "reports") -> Path:
    """Write the HTML report to disk and return its path."""
    folder = Path(output_dir)
    folder.mkdir(exist_ok=True)
    path = folder / f"report_{datetime.now():%Y%m%d_%H%M%S}.html"
    path.write_text(build_html_report(target, findings), encoding="utf-8")
    return path