def create_finding(
    finding_id,
    name,
    category,
    severity,
    evidence,
    description,
    recommendation,
):
    """
    Create a standardized CyberRecon security finding.
    """

    return {
        "id": finding_id,
        "name": name,
        "category": category,
        "severity": severity,
        "evidence": evidence,
        "description": description,
        "recommendation": recommendation,
    }


def analyze_security(recon):
    """
    Analyze reconnaissance data and generate
    passive web-security findings.
    """

    findings = []

    if not recon.get("reachable"):
        return findings

    headers = recon.get("headers", {})

    csp = headers.get(
        "Content-Security-Policy",
        "Not present",
    )

    hsts = headers.get(
        "Strict-Transport-Security",
        "Not present",
    )

    frame_options = headers.get(
        "X-Frame-Options",
        "Not present",
    )

    content_type_options = headers.get(
        "X-Content-Type-Options",
        "Not present",
    )

    server = headers.get(
        "Server",
        "Not present",
    )

    powered_by = headers.get(
        "X-Powered-By",
        "Not present",
    )

    # -------------------------------------------------
    # Check 1: HTTPS
    # -------------------------------------------------

    if not recon.get("https_enabled"):

        findings.append(
            create_finding(
                "CR-001",
                "HTTPS Not Enabled",
                "Transport Security",
                "High",
                f"Target uses {recon.get('target')}",
                (
                    "The target is being accessed over HTTP. "
                    "Traffic sent without HTTPS may be exposed "
                    "to interception or modification."
                ),
                (
                    "Enable HTTPS using a valid TLS certificate "
                    "and redirect HTTP requests to HTTPS."
                ),
            )
        )

    # -------------------------------------------------
    # Check 2: HSTS
    # -------------------------------------------------

    if (
        recon.get("https_enabled")
        and hsts == "Not present"
    ):

        findings.append(
            create_finding(
                "CR-002",
                "HSTS Header Missing",
                "Transport Security",
                "Medium",
                "Strict-Transport-Security header not present",
                (
                    "The website uses HTTPS but does not return "
                    "the Strict-Transport-Security header. "
                    "HSTS instructs browsers to use HTTPS for "
                    "future connections."
                ),
                (
                    "Configure the Strict-Transport-Security "
                    "header with an appropriate max-age value."
                ),
            )
        )

    # -------------------------------------------------
    # Check 3: Content Security Policy
    # -------------------------------------------------

    if csp == "Not present":

        findings.append(
            create_finding(
                "CR-003",
                "Content Security Policy Missing",
                "Browser Security",
                "Medium",
                "Content-Security-Policy header not present",
                (
                    "No Content-Security-Policy header was "
                    "observed. CSP can reduce the impact of "
                    "certain client-side injection attacks by "
                    "restricting permitted content sources."
                ),
                (
                    "Define and deploy a Content-Security-Policy "
                    "appropriate for the application's content "
                    "and external resources."
                ),
            )
        )

    # -------------------------------------------------
    # Check 4: Clickjacking protection
    # -------------------------------------------------

    csp_has_frame_ancestors = (
        csp != "Not present"
        and "frame-ancestors" in csp.lower()
    )

    if (
        frame_options == "Not present"
        and not csp_has_frame_ancestors
    ):

        findings.append(
            create_finding(
                "CR-004",
                "Clickjacking Protection Missing",
                "Browser Security",
                "Medium",
                (
                    "Neither X-Frame-Options nor CSP "
                    "frame-ancestors protection was detected"
                ),
                (
                    "The page may be permitted to load inside "
                    "frames on another website when no framing "
                    "restriction is configured."
                ),
                (
                    "Configure CSP frame-ancestors or an "
                    "appropriate X-Frame-Options header."
                ),
            )
        )

    # -------------------------------------------------
    # Check 5: MIME sniffing protection
    # -------------------------------------------------

    if (
        content_type_options == "Not present"
        or content_type_options.lower() != "nosniff"
    ):

        findings.append(
            create_finding(
                "CR-005",
                "MIME Sniffing Protection Missing",
                "Browser Security",
                "Low",
                (
                    "X-Content-Type-Options: "
                    f"{content_type_options}"
                ),
                (
                    "The response does not explicitly instruct "
                    "the browser to disable MIME-type sniffing."
                ),
                (
                    "Configure X-Content-Type-Options "
                    "with the value nosniff."
                ),
            )
        )

    # -------------------------------------------------
    # Check 6: Server disclosure
    # -------------------------------------------------

    if server != "Not present":

        findings.append(
            create_finding(
                "CR-006",
                "Web Server Information Disclosed",
                "Information Disclosure",
                "Info",
                f"Server: {server}",
                (
                    "The Server response header reveals "
                    "information about the web infrastructure."
                ),
                (
                    "Consider minimizing unnecessary server "
                    "information in HTTP response headers."
                ),
            )
        )

    # -------------------------------------------------
    # Check 7: Technology disclosure
    # -------------------------------------------------

    if powered_by != "Not present":

        findings.append(
            create_finding(
                "CR-007",
                "Technology Information Disclosed",
                "Information Disclosure",
                "Low",
                f"X-Powered-By: {powered_by}",
                (
                    "The X-Powered-By header reveals information "
                    "about the technology used by the application."
                ),
                (
                    "Remove or suppress unnecessary "
                    "X-Powered-By response headers."
                ),
            )
        )

    return findings


def summarize_findings(findings):
    """
    Count findings according to severity.
    """

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": len(findings),
    }

    for finding in findings:

        severity = finding.get("severity")

        if severity in summary:
            summary[severity] += 1

    return summary