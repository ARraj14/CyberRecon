"""
CyberRecon passive security-analysis engine.

The rules in this module interpret information already
collected during reconnaissance.

A finding represents an observed security condition.
It does not automatically prove exploitability.
"""


SECURITY_CHECK_COUNT = 18


MISSING_VALUES = {
    "",
    "not present",
    "not disclosed",
    "unavailable",
    "none",
}


def get_header(recon, header_name):
    """
    Return a normalized response-header value.

    Missing placeholder values used by CyberRecon
    are converted to None.
    """

    headers = recon.get(
        "headers",
        {},
    ) or {}

    value = headers.get(
        header_name
    )

    if value is None:
        return None

    value = str(value).strip()

    if value.lower() in MISSING_VALUES:
        return None

    return value


def create_finding(
    finding_id,
    name,
    category,
    severity,
    evidence,
    description,
    recommendation,
    confidence="Medium",
    affected_component="HTTP Response",
    cwe=None,
    owasp=None,
):
    """
    Return a standardized CyberRecon finding.
    """

    return {
        # Existing field preserved for compatibility.
        "id": finding_id,

        # Explicit field useful for storage/reporting.
        "finding_code": finding_id,

        "name": name,

        "category": category,

        "severity": severity,

        "confidence": confidence,

        "affected_component":
            affected_component,

        "cwe": cwe,

        "owasp": owasp,

        "evidence": evidence,

        "description": description,

        "recommendation":
            recommendation,
    }


def check_https(recon):
    """
    CR-001
    Detect targets ultimately served without HTTPS.
    """

    if recon.get(
        "https_enabled"
    ):
        return None

    return create_finding(
        finding_id="CR-001",

        name="HTTPS Not Enabled",

        category="Transport Security",

        severity="High",

        confidence="High",

        affected_component=(
            "Transport Layer"
        ),

        cwe="CWE-319",

        owasp=(
            "OWASP A02:2021 "
            "Cryptographic Failures"
        ),

        evidence=(
            "The final assessed URL was "
            "served over HTTP rather than HTTPS."
        ),

        description=(
            "Traffic delivered without HTTPS "
            "is not protected by TLS and may "
            "be exposed to interception or "
            "modification in transit."
        ),

        recommendation=(
            "Enable HTTPS using a valid TLS "
            "certificate and redirect HTTP "
            "traffic to HTTPS."
        ),
    )


def check_hsts(recon):
    """
    CR-002
    Check HTTPS responses for HSTS.
    """

    if not recon.get(
        "https_enabled"
    ):
        return None

    hsts = get_header(
        recon,
        "Strict-Transport-Security",
    )

    if hsts:

        if "max-age=0" not in hsts.lower():
            return None

        evidence = (
            "Strict-Transport-Security is "
            f"present but disables HSTS: {hsts}"
        )

    else:

        evidence = (
            "Strict-Transport-Security "
            "was not present in the response."
        )

    return create_finding(
        finding_id="CR-002",

        name="HSTS Header Missing or Disabled",

        category="Transport Security",

        severity="Medium",

        confidence="High",

        affected_component=(
            "HTTP Security Headers"
        ),

        cwe="CWE-319",

        owasp=(
            "OWASP A02:2021 "
            "Cryptographic Failures"
        ),

        evidence=evidence,

        description=(
            "HSTS instructs supported browsers "
            "to access the site using HTTPS and "
            "helps reduce protocol downgrade "
            "exposure."
        ),

        recommendation=(
            "Configure an appropriate "
            "Strict-Transport-Security header "
            "after confirming HTTPS is correctly "
            "deployed across the required scope."
        ),
    )


def check_csp(recon):
    """
    CR-003
    Check for an enforced CSP.
    """

    csp = get_header(
        recon,
        "Content-Security-Policy",
    )

    if csp:
        return None

    report_only = get_header(
        recon,
        "Content-Security-Policy-Report-Only",
    )

    if report_only:

        evidence = (
            "An enforced Content-Security-Policy "
            "was not present. A report-only "
            "policy was detected."
        )

    else:

        evidence = (
            "Content-Security-Policy "
            "was not present."
        )

    return create_finding(
        finding_id="CR-003",

        name="Content Security Policy Missing",

        category="Browser Security",

        severity="Medium",

        confidence="High",

        affected_component=(
            "HTTP Security Headers"
        ),

        cwe="CWE-693",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=evidence,

        description=(
            "Content Security Policy can restrict "
            "which resources a browser is allowed "
            "to load and can reduce the impact of "
            "some client-side injection attacks."
        ),

        recommendation=(
            "Define and test an appropriate "
            "Content-Security-Policy for the "
            "application. Avoid enabling directives "
            "that are not required."
        ),
    )


def check_clickjacking(recon):
    """
    CR-004
    Check for frame embedding protection.
    """

    x_frame_options = get_header(
        recon,
        "X-Frame-Options",
    )

    csp = get_header(
        recon,
        "Content-Security-Policy",
    )

    has_frame_ancestors = (
        csp is not None
        and "frame-ancestors"
        in csp.lower()
    )

    if (
        x_frame_options
        or has_frame_ancestors
    ):
        return None

    return create_finding(
        finding_id="CR-004",

        name=(
            "Clickjacking Protection Missing"
        ),

        category="Browser Security",

        severity="Medium",

        confidence="High",

        affected_component=(
            "Frame Embedding Policy"
        ),

        cwe="CWE-1021",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Neither X-Frame-Options nor "
            "a CSP frame-ancestors directive "
            "was detected."
        ),

        description=(
            "Without an appropriate framing "
            "policy, a page may be embeddable "
            "inside another site's frame. "
            "Whether this creates meaningful "
            "risk depends on application behavior."
        ),

        recommendation=(
            "Use CSP frame-ancestors and/or "
            "X-Frame-Options according to the "
            "application's framing requirements."
        ),
    )


def check_mime_sniffing(recon):
    """
    CR-005
    Check X-Content-Type-Options.
    """

    value = get_header(
        recon,
        "X-Content-Type-Options",
    )

    if (
        value
        and value.lower() == "nosniff"
    ):
        return None

    evidence = (
        "X-Content-Type-Options: nosniff "
        "was not detected."
    )

    if value:
        evidence = (
            "X-Content-Type-Options was present "
            f"with value: {value}"
        )

    return create_finding(
        finding_id="CR-005",

        name=(
            "MIME Sniffing Protection Missing"
        ),

        category="Browser Security",

        severity="Low",

        confidence="High",

        affected_component=(
            "HTTP Security Headers"
        ),

        cwe="CWE-693",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=evidence,

        description=(
            "The nosniff directive tells supported "
            "browsers not to reinterpret declared "
            "content types through MIME sniffing."
        ),

        recommendation=(
            "Configure X-Content-Type-Options "
            "with the value nosniff."
        ),
    )


def check_server_disclosure(recon):
    """
    CR-006
    Detect Server-header disclosure.
    """

    server = get_header(
        recon,
        "Server",
    )

    if not server:
        return None

    return create_finding(
        finding_id="CR-006",

        name=(
            "Web Server Information Disclosed"
        ),

        category="Information Disclosure",

        severity="Info",

        confidence="High",

        affected_component=(
            "Server Response Header"
        ),

        cwe="CWE-200",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            f"Server header disclosed: {server}"
        ),

        description=(
            "Server banners may reveal information "
            "about infrastructure or server "
            "technology. This is an informational "
            "observation and does not itself prove "
            "a vulnerability."
        ),

        recommendation=(
            "Review whether the Server header "
            "needs to expose implementation "
            "details and minimize unnecessary "
            "version information."
        ),
    )


def check_powered_by(recon):
    """
    CR-007
    Detect X-Powered-By disclosure.
    """

    powered_by = get_header(
        recon,
        "X-Powered-By",
    )

    if not powered_by:
        return None

    return create_finding(
        finding_id="CR-007",

        name=(
            "Technology Information Disclosed"
        ),

        category="Information Disclosure",

        severity="Low",

        confidence="High",

        affected_component=(
            "Application Response Header"
        ),

        cwe="CWE-200",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "X-Powered-By disclosed: "
            f"{powered_by}"
        ),

        description=(
            "Technology disclosure can provide "
            "additional implementation information "
            "to an observer."
        ),

        recommendation=(
            "Remove or suppress X-Powered-By "
            "when the information is not required."
        ),
    )


def check_referrer_policy(recon):
    """
    CR-008
    Check whether Referrer-Policy is configured.
    """

    value = get_header(
        recon,
        "Referrer-Policy",
    )

    if value:
        return None

    return create_finding(
        finding_id="CR-008",

        name="Referrer Policy Missing",

        category="Privacy and Browser Security",

        severity="Low",

        confidence="Medium",

        affected_component=(
            "HTTP Security Headers"
        ),

        cwe="CWE-200",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Referrer-Policy was not present."
        ),

        description=(
            "Referrer-Policy controls how much "
            "referrer information a browser sends "
            "when navigating to other resources."
        ),

        recommendation=(
            "Configure an appropriate Referrer-Policy "
            "such as strict-origin-when-cross-origin "
            "or a stricter policy if suitable."
        ),
    )


def check_permissions_policy(recon):
    """
    CR-009
    Observe whether Permissions-Policy is present.

    This header is application-dependent, therefore
    the finding is informational.
    """

    value = get_header(
        recon,
        "Permissions-Policy",
    )

    if value:
        return None

    return create_finding(
        finding_id="CR-009",

        name="Permissions Policy Missing",

        category="Browser Security",

        severity="Info",

        confidence="Low",

        affected_component=(
            "Browser Feature Policy"
        ),

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Permissions-Policy was not present."
        ),

        description=(
            "Permissions-Policy can restrict access "
            "to selected browser capabilities. "
            "Not every application requires this "
            "header, so this result is informational."
        ),

        recommendation=(
            "Review the browser capabilities used "
            "by the application and configure "
            "Permissions-Policy where restrictions "
            "would provide useful defense-in-depth."
        ),
    )


def check_unsafe_referrer_policy(recon):
    """
    CR-010
    Detect explicitly permissive referrer behavior.
    """

    value = get_header(
        recon,
        "Referrer-Policy",
    )

    if not value:
        return None

    policies = {
        part.strip().lower()
        for part in value.split(",")
    }

    if "unsafe-url" not in policies:
        return None

    return create_finding(
        finding_id="CR-010",

        name="Unsafe Referrer Policy",

        category="Privacy and Browser Security",

        severity="Low",

        confidence="High",

        affected_component=(
            "HTTP Security Headers"
        ),

        cwe="CWE-200",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            f"Referrer-Policy value: {value}"
        ),

        description=(
            "The unsafe-url policy can cause full "
            "URLs to be sent as referrer information "
            "during requests, increasing the chance "
            "of unintended information disclosure."
        ),

        recommendation=(
            "Use a more restrictive policy such as "
            "strict-origin-when-cross-origin unless "
            "application requirements dictate "
            "otherwise."
        ),
    )


def check_unsafe_csp(recon):
    """
    CR-011
    Detect potentially weak CSP script directives.
    """

    csp = get_header(
        recon,
        "Content-Security-Policy",
    )

    if not csp:
        return None

    lowered = csp.lower()

    unsafe_values = []

    if "'unsafe-inline'" in lowered:
        unsafe_values.append(
            "'unsafe-inline'"
        )

    if "'unsafe-eval'" in lowered:
        unsafe_values.append(
            "'unsafe-eval'"
        )

    if not unsafe_values:
        return None

    values = ", ".join(
        unsafe_values
    )

    return create_finding(
        finding_id="CR-011",

        name=(
            "Potentially Weak CSP Directive"
        ),

        category="Browser Security",

        severity="Medium",

        confidence="Medium",

        affected_component=(
            "Content Security Policy"
        ),

        cwe="CWE-693",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "CSP contains potentially permissive "
            f"directive value(s): {values}"
        ),

        description=(
            "unsafe-inline and unsafe-eval can "
            "reduce the protective strength of "
            "Content Security Policy. The actual "
            "security impact depends on the full "
            "policy and application behavior."
        ),

        recommendation=(
            "Review the CSP and replace unsafe "
            "script execution mechanisms with "
            "nonces, hashes, or other appropriate "
            "controls where practical."
        ),
    )


def check_cors_wildcard(recon):
    """
    CR-012
    Detect wildcard Access-Control-Allow-Origin.
    """

    origin = get_header(
        recon,
        "Access-Control-Allow-Origin",
    )

    if origin != "*":
        return None

    return create_finding(
        finding_id="CR-012",

        name="Wildcard CORS Policy Detected",

        category="Cross-Origin Security",

        severity="Low",

        confidence="Medium",

        affected_component=(
            "CORS Configuration"
        ),

        cwe="CWE-942",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Access-Control-Allow-Origin: *"
        ),

        description=(
            "The response permits cross-origin "
            "reading from any origin. This can be "
            "appropriate for intentionally public "
            "resources, so the finding does not "
            "automatically indicate a vulnerability."
        ),

        recommendation=(
            "Confirm that the resource is intended "
            "to be publicly readable cross-origin. "
            "If not, restrict allowed origins."
        ),
    )


def check_coop(recon):
    """
    CR-013
    Observe Cross-Origin-Opener-Policy.
    """

    value = get_header(
        recon,
        "Cross-Origin-Opener-Policy",
    )

    if value:
        return None

    return create_finding(
        finding_id="CR-013",

        name=(
            "Cross-Origin Opener Policy Missing"
        ),

        category="Cross-Origin Security",

        severity="Info",

        confidence="Low",

        affected_component=(
            "Cross-Origin Isolation"
        ),

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Cross-Origin-Opener-Policy "
            "was not present."
        ),

        description=(
            "COOP can isolate a document's browsing "
            "context from cross-origin documents. "
            "Its necessity depends on application "
            "design and required browser features."
        ),

        recommendation=(
            "Review whether the application benefits "
            "from cross-origin opener isolation and "
            "configure COOP when appropriate."
        ),
    )


def check_corp(recon):
    """
    CR-014
    Observe Cross-Origin-Resource-Policy.
    """

    value = get_header(
        recon,
        "Cross-Origin-Resource-Policy",
    )

    if value:
        return None

    return create_finding(
        finding_id="CR-014",

        name=(
            "Cross-Origin Resource Policy Missing"
        ),

        category="Cross-Origin Security",

        severity="Info",

        confidence="Low",

        affected_component=(
            "Cross-Origin Resource Policy"
        ),

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Cross-Origin-Resource-Policy "
            "was not present."
        ),

        description=(
            "CORP can control which origins are "
            "permitted to load a resource. "
            "It is application-dependent and is "
            "therefore reported informationally."
        ),

        recommendation=(
            "Review resource-sharing requirements "
            "and configure CORP where useful."
        ),
    )


def check_coep(recon):
    """
    CR-015
    Observe Cross-Origin-Embedder-Policy.
    """

    value = get_header(
        recon,
        "Cross-Origin-Embedder-Policy",
    )

    if value:
        return None

    return create_finding(
        finding_id="CR-015",

        name=(
            "Cross-Origin Embedder Policy Missing"
        ),

        category="Cross-Origin Security",

        severity="Info",

        confidence="Low",

        affected_component=(
            "Cross-Origin Isolation"
        ),

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Cross-Origin-Embedder-Policy "
            "was not present."
        ),

        description=(
            "COEP participates in browser "
            "cross-origin isolation. It is not "
            "required for every application, so "
            "this result is informational."
        ),

        recommendation=(
            "Enable COEP only where application "
            "requirements and resource-loading "
            "behavior support it."
        ),
    )


def cookies_missing_attribute(
    recon,
    attribute,
):
    """
    Return cookies that do not contain a selected
    security attribute.
    """

    cookies = recon.get(
        "set_cookies",
        [],
    ) or []

    missing = []

    attribute = (
        attribute.lower()
    )

    for cookie in cookies:

        lowered = (
            str(cookie).lower()
        )

        if attribute not in lowered:
            missing.append(
                str(cookie)
            )

    return missing


def cookie_names(cookie_headers):
    """
    Return only cookie names for safer evidence
    display rather than exposing cookie values.
    """

    names = []

    for cookie in cookie_headers:

        first_part = (
            cookie.split(
                ";",
                1,
            )[0]
        )

        name = (
            first_part.split(
                "=",
                1,
            )[0].strip()
        )

        if name:
            names.append(name)

    return names


def check_cookie_secure(recon):
    """
    CR-016
    Check HTTPS cookies for Secure.
    """

    if not recon.get(
        "https_enabled"
    ):
        return None

    missing = cookies_missing_attribute(
        recon,
        "; secure",
    )

    if not missing:
        return None

    names = cookie_names(
        missing
    )

    return create_finding(
        finding_id="CR-016",

        name="Cookie Missing Secure Flag",

        category="Session Security",

        severity="Low",

        confidence="Medium",

        affected_component="Cookies",

        cwe="CWE-614",

        owasp=(
            "OWASP A02:2021 "
            "Cryptographic Failures"
        ),

        evidence=(
            "Cookie(s) without Secure detected: "
            + ", ".join(names)
        ),

        description=(
            "Cookies without the Secure attribute "
            "may be transmitted over non-HTTPS "
            "connections if application behavior "
            "allows it. CyberRecon cannot determine "
            "whether each observed cookie contains "
            "sensitive information."
        ),

        recommendation=(
            "Apply the Secure attribute to cookies "
            "that should only be transmitted over "
            "HTTPS."
        ),
    )


def check_cookie_httponly(recon):
    """
    CR-017
    Check cookies for HttpOnly.
    """

    missing = cookies_missing_attribute(
        recon,
        "; httponly",
    )

    if not missing:
        return None

    names = cookie_names(
        missing
    )

    return create_finding(
        finding_id="CR-017",

        name="Cookie Missing HttpOnly Flag",

        category="Session Security",

        severity="Low",

        confidence="Medium",

        affected_component="Cookies",

        cwe="CWE-1004",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Cookie(s) without HttpOnly detected: "
            + ", ".join(names)
        ),

        description=(
            "HttpOnly prevents supported browsers "
            "from exposing a cookie through normal "
            "client-side JavaScript APIs. Some "
            "cookies legitimately require script "
            "access, so context is required."
        ),

        recommendation=(
            "Apply HttpOnly to authentication or "
            "session cookies that do not require "
            "JavaScript access."
        ),
    )


def check_cookie_samesite(recon):
    """
    CR-018
    Check cookies for SameSite.
    """

    missing = cookies_missing_attribute(
        recon,
        "samesite=",
    )

    if not missing:
        return None

    names = cookie_names(
        missing
    )

    return create_finding(
        finding_id="CR-018",

        name="Cookie SameSite Attribute Missing",

        category="Session Security",

        severity="Low",

        confidence="Medium",

        affected_component="Cookies",

        cwe="CWE-1275",

        owasp=(
            "OWASP A05:2021 "
            "Security Misconfiguration"
        ),

        evidence=(
            "Cookie(s) without an explicit "
            "SameSite attribute detected: "
            + ", ".join(names)
        ),

        description=(
            "SameSite controls when cookies are "
            "included with cross-site requests and "
            "can provide defense-in-depth against "
            "some cross-site request scenarios."
        ),

        recommendation=(
            "Set an appropriate SameSite value "
            "(Strict, Lax, or None where explicitly "
            "required) based on application behavior."
        ),
    )


def analyze_security(recon):
    """
    Run all passive CyberRecon security checks.
    """

    checks = [
        check_https,
        check_hsts,
        check_csp,
        check_clickjacking,
        check_mime_sniffing,
        check_server_disclosure,
        check_powered_by,
        check_referrer_policy,
        check_permissions_policy,
        check_unsafe_referrer_policy,
        check_unsafe_csp,
        check_cors_wildcard,
        check_coop,
        check_corp,
        check_coep,
        check_cookie_secure,
        check_cookie_httponly,
        check_cookie_samesite,
    ]

    findings = []

    for check in checks:

        finding = check(
            recon
        )

        if finding:
            findings.append(
                finding
            )

    return findings


def summarize_findings(findings):
    """
    Return finding totals by severity.
    """

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": len(findings),
    }

    for finding in findings:

        severity = finding.get(
            "severity"
        )

        if severity in summary:
            summary[severity] += 1

    return summary