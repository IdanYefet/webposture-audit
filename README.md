# webposture-audit

A command-line tool that audits the security posture of a web application:
HTTP security headers, cookie flags, and exposed TCP ports, with an optional HTML report.

> **Legal notice:** use only on systems you own or have explicit written permission to test.

## Features

- Checks for missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Checks `HttpOnly`, `Secure` and `SameSite` flags on every cookie the server sets
- Multi-threaded TCP connect port scanner with service labels and risk levels
- Findings sorted by severity, printed to the terminal or exported as an HTML report

## Installation

```bash
git clone https://github.com/<your-username>/webposture-audit.git
cd webposture-audit
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Usage

```bash
python -m webposture http://localhost:3000
python -m webposture http://localhost:3000 --ports 22,80,3000 --report
python -m webposture http://localhost:3000 --skip-ports
```

| Option | Description |
|---|---|
| `--ports` | Comma-separated ports to scan (default: common ports) |
| `--skip-ports` | Skip the port scan |
| `--report` | Write an HTML report to `reports/` |
| `--timeout` | HTTP timeout in seconds (default: 10) |

## Safe practice target

```bash
docker run -p 3000:3000 bkimminich/juice-shop
```

## Project structure

```
webposture/
├── cli.py                 # command-line interface
├── http_headers_audit.py  # security headers check
├── cookie_audit.py        # cookie flags check
├── port_scanner.py        # threaded TCP scanner
├── report_generator.py    # HTML report
└── models.py              # Finding and Severity
```

## Limitations

Checks presence of headers and flags only, not the quality of their values.
The port scan covers a fixed list of common ports unless `--ports` is given.