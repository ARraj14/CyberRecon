# CYBERRECON

## Web-Based Vulnerability Assessment and Reconnaissance System

**CYBERRECON** is a Flask-based web security assessment platform developed as a final-year Computer Science and Engineering project.

The system provides a structured interface for performing **passive reconnaissance and web-security configuration assessment** against authorized HTTP and HTTPS targets.

Rather than attempting exploitation, brute-force attacks, credential attacks, or intrusive network scanning, CyberRecon collects information available through normal DNS and HTTP/HTTPS communication and converts those observations into understandable security findings.

The platform includes target validation, reconnaissance, passive security analysis, OWASP/CWE mapping, confidence classification, persistent scan history, authentication, dashboard analytics, historical comparison, downloadable assessment reports, automated testing, CSRF protection, SSRF protection, and production WSGI configuration.

---

# Project Purpose

Initial web-security assessment often requires several separate activities:

- validating a target
- resolving its network address
- following HTTP redirects
- measuring response behavior
- inspecting HTTP security headers
- checking browser-security policies
- examining cookie attributes
- identifying exposed technology information
- interpreting observations
- documenting recommendations
- comparing previous assessments

CyberRecon combines these activities into one web-based workflow.

Its primary goal is to provide a transparent and educational assessment platform that can be understood, demonstrated, extended, and explained during academic evaluation.

CyberRecon is **not intended to replace professional penetration-testing tools** such as Burp Suite, OWASP ZAP, Nmap, or enterprise vulnerability scanners.

---

# Core Features

CyberRecon currently provides:

### Target Validation

CyberRecon validates and normalizes user-supplied targets before reconnaissance begins.

Supported targets:

```text
example.com
www.example.com
https://example.com
http://example.com
https://example.com/path
https://example.com:8443