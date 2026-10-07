from cyberrecon.scanner.security_analysis import (
    SECURITY_CHECK_COUNT,
    analyze_security,
    summarize_findings,
)


def build_recon(
    *,
    https_enabled=True,
    headers=None,
    cookies=None,
):
    """
    Construct a minimal reconnaissance result
    suitable for testing CyberRecon rules.
    """

    return {
        "target":
            "https://example.test",

        "domain":
            "example.test",

        "ip_address":
            "127.0.0.1",

        "reachable":
            True,

        "status_code":
            200,

        "final_url":
            (
                "https://example.test"
                if https_enabled
                else "http://example.test"
            ),

        "https_enabled":
            https_enabled,

        "response_time":
            10.0,

        "page_title":
            "Test Page",

        "server":
            "Not disclosed",

        "content_type":
            "text/html",

        "redirect_count":
            0,

        "headers":
            headers or {},

        "set_cookies":
            cookies or [],

        "fallback_used":
            False,

        "error_type":
            None,

        "error_message":
            None,
    }


def finding_codes(findings):
    """
    Return only CyberRecon rule IDs.
    """

    return {
        finding["finding_code"]
        for finding in findings
    }


def test_security_check_count():
    """
    v0.8 contains eighteen configured rules.
    """

    assert SECURITY_CHECK_COUNT == 18


def test_http_target_triggers_https_finding():

    recon = build_recon(
        https_enabled=False
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-001" in codes


def test_https_target_does_not_trigger_cr001():

    recon = build_recon(
        https_enabled=True
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-001" not in codes


def test_missing_hsts_on_https():

    recon = build_recon(
        https_enabled=True,
        headers={},
    )

    findings = analyze_security(
        recon
    )

    assert "CR-002" in finding_codes(
        findings
    )


def test_valid_hsts_removes_finding():

    recon = build_recon(
        headers={
            "Strict-Transport-Security":
                "max-age=31536000"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-002" not in finding_codes(
        findings
    )


def test_missing_csp_detected():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert "CR-003" in finding_codes(
        findings
    )


def test_enforced_csp_removes_missing_csp():

    recon = build_recon(
        headers={
            "Content-Security-Policy":
                "default-src 'self'"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-003" not in finding_codes(
        findings
    )


def test_report_only_csp_is_not_enforced_csp():

    recon = build_recon(
        headers={
            "Content-Security-Policy-Report-Only":
                "default-src 'self'"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-003" in finding_codes(
        findings
    )


def test_clickjacking_finding_when_unprotected():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert "CR-004" in finding_codes(
        findings
    )


def test_x_frame_options_prevents_cr004():

    recon = build_recon(
        headers={
            "X-Frame-Options":
                "DENY"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-004" not in finding_codes(
        findings
    )


def test_csp_frame_ancestors_prevents_cr004():

    recon = build_recon(
        headers={
            "Content-Security-Policy":
                "frame-ancestors 'none'"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-004" not in finding_codes(
        findings
    )


def test_nosniff_missing():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert "CR-005" in finding_codes(
        findings
    )


def test_valid_nosniff():

    recon = build_recon(
        headers={
            "X-Content-Type-Options":
                "nosniff"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-005" not in finding_codes(
        findings
    )


def test_server_information_disclosure():

    recon = build_recon(
        headers={
            "Server":
                "ExampleServer/1.0"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-006" in finding_codes(
        findings
    )


def test_powered_by_information_disclosure():

    recon = build_recon(
        headers={
            "X-Powered-By":
                "ExampleFramework"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-007" in finding_codes(
        findings
    )


def test_missing_referrer_policy():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert "CR-008" in finding_codes(
        findings
    )


def test_valid_referrer_policy():

    recon = build_recon(
        headers={
            "Referrer-Policy":
                "strict-origin-when-cross-origin"
        }
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-008" not in codes
    assert "CR-010" not in codes


def test_unsafe_referrer_policy():

    recon = build_recon(
        headers={
            "Referrer-Policy":
                "unsafe-url"
        }
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-008" not in codes
    assert "CR-010" in codes


def test_missing_permissions_policy():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert "CR-009" in finding_codes(
        findings
    )


def test_permissions_policy_present():

    recon = build_recon(
        headers={
            "Permissions-Policy":
                "camera=(), microphone=()"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-009" not in finding_codes(
        findings
    )


def test_weak_csp_unsafe_inline():

    recon = build_recon(
        headers={
            "Content-Security-Policy":
                (
                    "default-src 'self'; "
                    "script-src 'self' "
                    "'unsafe-inline'"
                )
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-011" in finding_codes(
        findings
    )


def test_weak_csp_unsafe_eval():

    recon = build_recon(
        headers={
            "Content-Security-Policy":
                (
                    "script-src 'self' "
                    "'unsafe-eval'"
                )
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-011" in finding_codes(
        findings
    )


def test_stronger_csp_does_not_trigger_cr011():

    recon = build_recon(
        headers={
            "Content-Security-Policy":
                (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "object-src 'none'"
                )
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-011" not in finding_codes(
        findings
    )


def test_cors_wildcard_detected():

    recon = build_recon(
        headers={
            "Access-Control-Allow-Origin":
                "*"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-012" in finding_codes(
        findings
    )


def test_specific_cors_origin_not_wildcard():

    recon = build_recon(
        headers={
            "Access-Control-Allow-Origin":
                "https://example.test"
        }
    )

    findings = analyze_security(
        recon
    )

    assert "CR-012" not in finding_codes(
        findings
    )


def test_missing_cross_origin_headers():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-013" in codes
    assert "CR-014" in codes
    assert "CR-015" in codes


def test_cross_origin_headers_present():

    recon = build_recon(
        headers={
            "Cross-Origin-Opener-Policy":
                "same-origin",

            "Cross-Origin-Resource-Policy":
                "same-origin",

            "Cross-Origin-Embedder-Policy":
                "require-corp",
        }
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-013" not in codes
    assert "CR-014" not in codes
    assert "CR-015" not in codes


def test_cookie_without_secure_on_https():

    recon = build_recon(
        https_enabled=True,

        cookies=[
            (
                "session=value; "
                "HttpOnly; "
                "SameSite=Lax"
            )
        ],
    )

    findings = analyze_security(
        recon
    )

    assert "CR-016" in finding_codes(
        findings
    )


def test_secure_cookie():

    recon = build_recon(
        cookies=[
            (
                "session=value; "
                "Secure; "
                "HttpOnly; "
                "SameSite=Lax"
            )
        ],
    )

    findings = analyze_security(
        recon
    )

    codes = finding_codes(
        findings
    )

    assert "CR-016" not in codes
    assert "CR-017" not in codes
    assert "CR-018" not in codes


def test_cookie_without_httponly():

    recon = build_recon(
        cookies=[
            (
                "session=value; "
                "Secure; "
                "SameSite=Lax"
            )
        ],
    )

    findings = analyze_security(
        recon
    )

    assert "CR-017" in finding_codes(
        findings
    )


def test_cookie_without_samesite():

    recon = build_recon(
        cookies=[
            (
                "session=value; "
                "Secure; "
                "HttpOnly"
            )
        ],
    )

    findings = analyze_security(
        recon
    )

    assert "CR-018" in finding_codes(
        findings
    )


def test_cookie_values_not_exposed_in_evidence():
    """
    CyberRecon should identify cookies by name,
    not display their values in finding evidence.
    """

    recon = build_recon(
        cookies=[
            "session=SUPER-SECRET-VALUE"
        ],
    )

    findings = analyze_security(
        recon
    )

    cookie_findings = [
        finding
        for finding in findings
        if finding["finding_code"]
        in {
            "CR-016",
            "CR-017",
            "CR-018",
        }
    ]

    assert cookie_findings

    for finding in cookie_findings:

        assert (
            "SUPER-SECRET-VALUE"
            not in finding["evidence"]
        )


def test_finding_metadata_exists():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    assert findings

    for finding in findings:

        assert "finding_code" in finding
        assert "name" in finding
        assert "category" in finding
        assert "severity" in finding

        assert (
            "confidence"
            in finding
        )

        assert (
            "affected_component"
            in finding
        )

        assert "cwe" in finding
        assert "owasp" in finding

        assert "evidence" in finding

        assert (
            "description"
            in finding
        )

        assert (
            "recommendation"
            in finding
        )


def test_summary_totals():

    recon = build_recon()

    findings = analyze_security(
        recon
    )

    summary = summarize_findings(
        findings
    )

    assert (
        summary["Total"]
        == len(findings)
    )

    calculated_total = (
        summary["High"]
        + summary["Medium"]
        + summary["Low"]
        + summary["Info"]
    )

    assert (
        calculated_total
        == summary["Total"]
    )