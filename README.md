from pathlib import Path

readme = r"""# CYBERRECON

## Web-Based Vulnerability Assessment and Reconnaissance System

**CyberRecon** is a Flask-based web security assessment platform developed as a final-year Computer Science and Engineering project. It performs **passive reconnaissance and security-configuration analysis** against authorized HTTP and HTTPS targets and presents the results as structured, understandable findings.

CyberRecon is designed for academic, educational, and defensive-security use. It does **not** perform exploitation, brute-force attacks, credential attacks, destructive payloads, or intrusive network scanning.

---

## Overview

Initial web-security assessment often requires several separate tasks: validating a target, resolving DNS, following redirects, inspecting HTTP response headers, checking browser-security controls, reviewing cookie attributes, and interpreting the results.

CyberRecon combines those tasks into one browser-based workflow:

```text
User
  ↓
Authentication
  ↓
Target Submission
  ↓
CSRF Validation
  ↓
Target Validation & Normalization
  ↓
DNS Resolution
  ↓
SSRF Destination Validation
  ↓
Controlled HTTP/HTTPS Request
  ↓
Redirect Validation
  ↓
Passive Reconnaissance
  ↓
18 Security Checks
  ↓
Severity / Confidence / CWE / OWASP Mapping
  ↓
Results
  ↓
SQLite Persistence
  ↓
History / Dashboard / Comparison / Report
```

---

## Features

### Target validation

CyberRecon validates and normalizes user input before making a network request.

Examples of accepted targets:

```text
example.com
www.example.com
https://example.com
http://example.com
https://example.com/path
https://example.com:8443
```

Validation includes:

- HTTP/HTTPS scheme validation
- hostname validation
- IPv4 and IPv6 validation
- port validation
- whitespace rejection
- embedded credential rejection
- URL path and query preservation
- fragment removal
- HTTPS preference for scheme-less targets

### Passive reconnaissance

CyberRecon collects information such as:

- normalized target
- domain
- resolved IP addresses
- HTTP status code
- final URL
- HTTPS status
- response time
- redirect count
- page title
- server information
- content type
- selected HTTP security headers
- `Set-Cookie` headers

The reconnaissance layer also handles:

- DNS failures
- connection and read timeouts
- TLS/SSL errors
- redirect limits
- safe redirect processing
- connection failures
- controlled HTTP fallback for scheme-less input

Explicit HTTPS targets are not silently downgraded to HTTP.

---

## Security Analysis

CyberRecon currently implements **18 passive security checks**.

| ID | Security Check | Severity |
|---|---|---|
| CR-001 | HTTPS Not Enabled | High |
| CR-002 | HSTS Header Missing or Disabled | Medium |
| CR-003 | Content Security Policy Missing | Medium |
| CR-004 | Clickjacking Protection Missing | Medium |
| CR-005 | MIME Sniffing Protection Missing | Low |
| CR-006 | Web Server Information Disclosed | Info |
| CR-007 | Technology Information Disclosed | Low |
| CR-008 | Referrer Policy Missing | Low |
| CR-009 | Permissions Policy Missing | Info |
| CR-010 | Unsafe Referrer Policy | Low |
| CR-011 | Potentially Weak CSP Directive | Medium |
| CR-012 | Wildcard CORS Policy Detected | Low |
| CR-013 | Cross-Origin Opener Policy Missing | Info |
| CR-014 | Cross-Origin Resource Policy Missing | Info |
| CR-015 | Cross-Origin Embedder Policy Missing | Info |
| CR-016 | Cookie Missing Secure Flag | Low |
| CR-017 | Cookie Missing HttpOnly Flag | Low |
| CR-018 | Cookie SameSite Attribute Missing | Low |

Each finding can contain:

- finding code
- name
- category
- severity
- confidence
- affected component
- CWE mapping
- OWASP mapping
- evidence
- description
- recommendation

> A CyberRecon finding is an observation based on passive evidence. It does not automatically prove that the target is exploitable.

---

## Authentication and User Isolation

CyberRecon includes account-based authentication using Flask sessions and Werkzeug password hashing.

Authentication features include:

- user registration
- login and logout
- password hashing
- protected routes
- safe post-login redirects
- session-based authentication
- user-specific scan ownership

Users can access only their own:

- scan history
- stored assessments
- reports
- dashboard analytics
- comparison candidates
- findings

---

## Scan History

CyberRecon stores assessments in SQLite.

Stored information includes:

- scan ID
- user ID
- target
- timestamp
- scan duration
- reconnaissance status
- analysis status
- HTTP status
- HTTPS status
- domain
- resolved IP
- final URL
- response time
- redirect count
- page title
- server information
- content type
- security findings

---

## Dashboard

The authenticated dashboard provides user-specific analytics such as:

- total scans
- successful scans
- failed scans
- unique targets
- success rate
- total findings
- severity counts
- recent assessments

---

## Historical Comparison

CyberRecon can compare two completed assessments of the same target.

Findings are classified as:

- **New**
- **Resolved**
- **Unchanged**

This supports a simple remediation workflow:

```text
Initial Scan
    ↓
Findings Identified
    ↓
Configuration Changes
    ↓
Second Scan
    ↓
CyberRecon Comparison
    ↓
New / Resolved / Unchanged
```

---

## Reports

Stored assessments can be exported as downloadable, print-friendly HTML reports.

Reports include:

- scan metadata
- target information
- severity summary
- reconnaissance information
- detailed findings
- confidence
- affected component
- CWE mapping
- OWASP mapping
- evidence
- description
- recommendation

The browser can also be used to save the HTML report as PDF.

---

## SSRF Protection

Because CyberRecon makes network requests to user-supplied targets, the application includes Server-Side Request Forgery protections.

By default, CyberRecon rejects non-public destinations including:

- loopback addresses
- private IPv4 ranges
- IPv6 loopback
- link-local addresses
- multicast addresses
- reserved addresses
- unspecified addresses

All resolved addresses are checked before a request is made.

Redirect destinations are also validated before CyberRecon follows them.

Example:

```text
Public Target
      ↓
302 Redirect
      ↓
http://127.0.0.1/admin
      ↓
BLOCKED
```

Private targets may be enabled explicitly for the controlled local demo:

```bash
CYBERRECON_ALLOW_PRIVATE_TARGETS=1
```

### SSRF limitation

CyberRecon validates DNS resolution immediately before the request, but the HTTP networking layer performs its own resolution during connection. Sophisticated DNS-rebinding or time-of-check/time-of-use scenarios remain an architectural limitation for high-security deployments.

---

## CSRF and Application Hardening

CyberRecon protects POST requests with session-bound CSRF tokens.

The application also includes security-focused configuration such as:

- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- HttpOnly session cookies
- SameSite session cookies
- optional Secure cookies
- optional HSTS
- request-size limits
- safe local redirects
- controlled error responses
- cache prevention for dynamic pages
- CSRF protection
- SSRF protection

---

## Controlled Demo Target

A controlled local target is included in:

```text
demo_target/app.py
```

It supports three profiles:

| Profile | Purpose |
|---|---|
| `missing` | Intentionally omits several security controls |
| `weak` | Includes deliberately weak configuration |
| `hardened` | Uses stronger headers and cookie attributes |

This allows CyberRecon to demonstrate:

```text
Detection
   ↓
Remediation
   ↓
Rescan
   ↓
Historical Comparison
```

without relying on unpredictable external websites.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Programming Language | Python 3.12 |
| Backend Framework | Flask |
| HTTP Client | Requests |
| Database | SQLite |
| Authentication | Flask Sessions + Werkzeug |
| Frontend | HTML5 + CSS3 |
| Templating | Jinja2 |
| Networking | Python `socket` |
| URL Processing | `urllib.parse` |
| Testing | pytest |
| Dependency Management | uv |
| WSGI Server | Gunicorn |
| Development Environment | WSL 2 / Ubuntu / VS Code |
| Version Control | Git + GitHub |

---

## Project Structure

```text
CyberRecon/
├── data/
│   └── .gitkeep
│
├── demo_target/
│   └── app.py
│
├── scripts/
│   ├── final_validation.py
│   └── project_audit.py
│
├── src/
│   └── cyberrecon/
│       ├── __init__.py
│       ├── app.py
│       ├── storage.py
│       │
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── assessment.py
│       │   ├── comparison.py
│       │   ├── reconnaissance.py
│       │   ├── security_analysis.py
│       │   └── target.py
│       │
│       ├── static/
│       │   └── css/
│       │       └── style.css
│       │
│       └── templates/
│           ├── compare.html
│           ├── dashboard.html
│           ├── history.html
│           ├── index.html
│           ├── login.html
│           ├── register.html
│           ├── report.html
│           ├── results.html
│           └── scan_detail.html
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_app_integration.py
│   ├── test_auth.py
│   ├── test_csrf.py
│   ├── test_production_config.py
│   ├── test_security_analysis.py
│   ├── test_security_hardening.py
│   ├── test_ssrf_protection.py
│   ├── test_storage.py
│   └── test_target.py
│
├── .env.example
├── .gitignore
├── .python-version
├── pyproject.toml
├── README.md
├── run.py
├── uv.lock
└── wsgi.py
```

Runtime databases, session secrets, virtual environments, caches, logs, backup files, and real environment files are excluded from Git.

---

## Requirements

- Python 3.12 or later
- `uv`
- Linux / WSL / another compatible Python environment
- modern web browser
- network access for authorized public targets

Check your versions:

```bash
python3 --version
uv --version
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ARraj14/CyberRecon.git
cd CyberRecon
```

Install and synchronize dependencies:

```bash
uv sync
```

---

## Running CyberRecon

### Development

```bash
uv run python run.py
```

Open:

```text
http://127.0.0.1:5000
```

### Production-style local run

CyberRecon exposes a WSGI application through `wsgi.py`.

```bash
uv run gunicorn \
  --workers 2 \
  --bind 127.0.0.1:8000 \
  --timeout 30 \
  wsgi:app
```

Open:

```text
http://127.0.0.1:8000
```

---

## Environment Configuration

CyberRecon reads configuration from environment variables.

Use `.env.example` as the reference.

| Variable | Purpose | Recommended Production Value |
|---|---|---|
| `CYBERRECON_SECRET_KEY` | Flask session signing secret | Strong random value |
| `CYBERRECON_DEBUG` | Development debug mode | `0` |
| `CYBERRECON_SECURE_COOKIES` | Secure session cookies | `1` when HTTPS is used |
| `CYBERRECON_ENABLE_HSTS` | Enable HSTS | `1` when HTTPS is correctly deployed |
| `CYBERRECON_ALLOW_PRIVATE_TARGETS` | Allow private/local targets | `0` |

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Do not commit real secrets.

---

## Controlled Local Demo

Start CyberRecon with private targets explicitly enabled:

```bash
CYBERRECON_ALLOW_PRIVATE_TARGETS=1 \
CYBERRECON_SECURE_COOKIES=0 \
CYBERRECON_ENABLE_HSTS=0 \
uv run python run.py
```

In another terminal, start the demo target:

```bash
CYBERRECON_DEMO_PROFILE=missing \
uv run python demo_target/app.py
```

Then assess:

```text
http://127.0.0.1:5001
```

Other profiles:

```bash
CYBERRECON_DEMO_PROFILE=weak uv run python demo_target/app.py
```

```bash
CYBERRECON_DEMO_PROFILE=hardened uv run python demo_target/app.py
```

---

## Testing

Run the full automated test suite:

```bash
uv run pytest -v
```

For concise output:

```bash
uv run pytest -q
```

The test suite covers:

- target validation and normalization
- security-analysis rules
- finding metadata
- authentication
- password hashing
- user ownership
- SQLite persistence
- dashboard behavior
- historical comparison
- Flask integration
- report generation
- CSRF protection
- application hardening
- SSRF protection
- redirect safety
- private-network blocking
- controlled demo behavior
- production configuration
- WSGI configuration

---

## Final Validation

Run the project validation utility:

```bash
uv run python scripts/final_validation.py
```

Run the final repository audit:

```bash
uv run python scripts/project_audit.py
```

These utilities check project structure, Python compilation, automated tests, routes, WSGI import, Git protections, SSRF defaults, dependencies, and repository cleanliness.

---

## Main Routes

| Route | Purpose |
|---|---|
| `/` | Homepage / target submission |
| `/register` | User registration |
| `/login` | Login |
| `/logout` | Logout |
| `/scan` | Run an assessment |
| `/dashboard` | User analytics |
| `/history` | Scan history |
| `/history/<scan_id>` | Stored assessment |
| `/history/<scan_id>/report` | Download assessment report |
| `/compare` | Historical comparison |

---

## Scope

CyberRecon is intentionally a **passive assessment system**.

It does not currently perform:

- brute-force attacks
- credential stuffing
- exploit execution
- SQL injection exploitation
- remote code execution
- malware delivery
- privilege escalation
- destructive payloads
- port scanning
- intrusive network scanning

---

## Known Limitations

- A missing security header is a configuration observation; the practical risk depends on application behavior and threat model.
- External target behavior can vary because of CDNs, DNS rotation, load balancing, geographic routing, rate limiting, and dynamic infrastructure.
- The current report format is downloadable HTML; PDF can be generated using the browser's Print / Save as PDF feature.
- SQLite is appropriate for this academic/local deployment, but a higher-concurrency production deployment would normally use a server-grade database.
- SSRF validation reduces exposure to private/internal targets, but advanced DNS-rebinding scenarios remain a limitation.

---

## Ethical Use

CyberRecon must only be used against:

- systems you own, or
- systems for which you have explicit authorization to perform security assessment.

The controlled local demo target is the recommended environment for demonstrations.

Unauthorized scanning may violate organizational policy or applicable law.

---

## Academic Context

**Project Title:** CyberRecon: Web-Based Vulnerability Assessment and Reconnaissance System  
**Program:** Final-Year Engineering Project — Computer Science and Engineering  
**Institution:** Bangalore College of Engineering and Technology  
**Affiliation:** Visvesvaraya Technological University, Belagavi  

### Project Team

- **Sujal Chettri** — 1BC23CS066
- **Rishi Raj** — 1BC23CS045
- **Kushagra Sarkar** — 1BC23CS029
- **Riyush Manya** — 1BC23CS047

### Project Guide

**Mrs. Rajitha K. R**  
Department of Computer Science and Engineering  
Bangalore College of Engineering and Technology

---

## Project Status

CyberRecon `v1.0.0` includes the complete final-stage passive assessment workflow:

- authentication
- user-specific data isolation
- target validation
- passive reconnaissance
- 18-rule security analysis
- severity and confidence classification
- CWE and OWASP mapping
- SQLite persistence
- scan history
- dashboard analytics
- historical comparison
- HTML reporting
- controlled demonstration target
- CSRF protection
- SSRF protection
- application hardening
- automated testing
- Gunicorn WSGI support
- final validation utilities

---

## Disclaimer

CyberRecon is an educational cybersecurity project. Findings are generated from observable passive evidence and should be independently reviewed before being used for production security decisions.
"""

out = Path("/mnt/data/README.md")
out.write_text(readme, encoding="utf-8")
print(f"Created: {out}")
print(f"Lines: {len(readme.splitlines())}")
