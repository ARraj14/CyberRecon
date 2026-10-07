import cyberrecon.app as app_module
import cyberrecon.storage as storage


def build_fake_assessment(
    scan_id,
    target="https://example.test",
    finding_code="CR-003",
):
    """
    Create a deterministic assessment so Flask
    integration tests never make external
    network requests.
    """

    finding = {
        "id":
            finding_code,

        "finding_code":
            finding_code,

        "name":
            "Content Security Policy Missing",

        "category":
            "Browser Security",

        "severity":
            "Medium",

        "confidence":
            "High",

        "affected_component":
            "HTTP Security Headers",

        "cwe":
            "CWE-693",

        "owasp":
            (
                "OWASP A05:2021 "
                "Security Misconfiguration"
            ),

        "evidence":
            (
                "Content-Security-Policy "
                "was not present."
            ),

        "description":
            "Integration test description.",

        "recommendation":
            "Integration test recommendation.",
    }


    return {
        "target":
            target,

        "recon": {
            "target":
                target,

            "domain":
                "example.test",

            "ip_address":
                "127.0.0.1",

            "reachable":
                True,

            "status_code":
                200,

            "final_url":
                target,

            "https_enabled":
                True,

            "response_time":
                12.5,

            "page_title":
                "Integration Test",

            "server":
                "IntegrationServer",

            "content_type":
                "text/html",

            "redirect_count":
                0,

            "headers": {
                "Content-Security-Policy":
                    "Not present",
            },

            "set_cookies":
                [],

            "fallback_used":
                False,

            "error_type":
                None,

            "error_message":
                None,
        },

        "findings": [
            finding
        ],

        "finding_summary": {
            "High":
                0,

            "Medium":
                1,

            "Low":
                0,

            "Info":
                0,

            "Total":
                1,
        },

        "metadata": {
            "scan_id":
                scan_id,

            "started_at":
                (
                    "08 Oct 2026, "
                    "10:30:00 AM IST"
                ),

            "duration_ms":
                30,

            "checks_performed":
                18,

            "recon_status":
                "Completed",

            "analysis_status":
                "Completed",
        },
    }


def test_home_is_public(
    client,
):
    """
    CyberRecon homepage remains publicly
    accessible.
    """

    response = client.get(
        "/"
    )

    assert response.status_code == 200


def test_dashboard_requires_login(
    client,
):
    """
    Dashboard must reject anonymous access.
    """

    response = client.get(
        "/dashboard"
    )

    assert response.status_code == 302

    assert (
        "/login"
        in response.headers[
            "Location"
        ]
    )


def test_history_requires_login(
    client,
):
    """
    Scan history requires authentication.
    """

    response = client.get(
        "/history"
    )

    assert response.status_code == 302


def test_compare_requires_login(
    client,
):
    """
    Historical comparison requires login.
    """

    response = client.get(
        "/compare"
    )

    assert response.status_code == 302


def test_scan_requires_login(
    client,
):
    """
    Anonymous users cannot start assessments.
    """

    response = client.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )

    assert response.status_code == 302


def test_authenticated_dashboard_loads(
    authenticated_client,
):
    """
    Logged-in users should see the dashboard.
    """

    response = (
        authenticated_client.get(
            "/dashboard"
        )
    )

    assert response.status_code == 200


def test_authenticated_history_loads(
    authenticated_client,
):
    """
    Logged-in users should see their history.
    """

    response = (
        authenticated_client.get(
            "/history"
        )
    )

    assert response.status_code == 200


def test_scan_route_saves_assessment(
    authenticated_client,
    monkeypatch,
):
    """
    A successful assessment should render and
    persist for the logged-in user.
    """

    fake_assessment = (
        build_fake_assessment(
            "CR-INTEG001"
        )
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            fake_assessment,
    )


    response = (
        authenticated_client.post(
            "/scan",
            data={
                "target":
                    "example.test"
            },
        )
    )


    assert response.status_code == 200

    assert (
        b"CR-INTEG001"
        in response.data
    )


    with (
        authenticated_client
        .session_transaction()
    ) as session:

        user_id = session[
            "user_id"
        ]


    stored = storage.get_scan_by_id(
        "CR-INTEG001",
        user_id,
    )


    assert stored is not None


def test_saved_scan_appears_in_history(
    authenticated_client,
    monkeypatch,
):
    """
    Newly saved assessments should appear
    through the history route.
    """

    assessment = build_fake_assessment(
        "CR-HISTORY1"
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            assessment,
    )


    authenticated_client.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )


    response = (
        authenticated_client.get(
            "/history"
        )
    )


    assert response.status_code == 200

    assert (
        b"CR-HISTORY1"
        in response.data
    )


def test_scan_detail_route(
    authenticated_client,
    monkeypatch,
):
    """
    Stored scan detail pages should load.
    """

    assessment = build_fake_assessment(
        "CR-DETAIL01"
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            assessment,
    )


    authenticated_client.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )


    response = (
        authenticated_client.get(
            "/history/CR-DETAIL01"
        )
    )


    assert response.status_code == 200

    assert (
        b"CR-DETAIL01"
        in response.data
    )

    assert (
        b"CWE-693"
        in response.data
    )


def test_report_download_route(
    authenticated_client,
    monkeypatch,
):
    """
    Stored assessments should produce a
    downloadable HTML report.
    """

    assessment = build_fake_assessment(
        "CR-REPORT01"
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            assessment,
    )


    authenticated_client.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )


    response = (
        authenticated_client.get(
            "/history/CR-REPORT01/report"
        )
    )


    assert response.status_code == 200

    assert (
        "attachment"
        in response.headers[
            "Content-Disposition"
        ]
    )

    assert (
        "CR-REPORT01"
        in response.headers[
            "Content-Disposition"
        ]
    )

    assert (
        b"CWE-693"
        in response.data
    )


def test_unknown_scan_returns_404(
    authenticated_client,
):
    """
    Unknown scan IDs should not cause server errors.
    """

    response = (
        authenticated_client.get(
            "/history/CR-NOTFOUND"
        )
    )

    assert response.status_code == 404


def test_user_cannot_access_other_users_scan(
    app,
    register_user,
    login_user,
    monkeypatch,
):
    """
    User-specific authorization must be enforced
    by the Flask route itself.
    """

    client_one = (
        app.test_client()
    )

    client_two = (
        app.test_client()
    )


    register_user(
        client_one,
        username="alice",
        email="alice@example.com",
    )

    login_user(
        client_one,
        email="alice@example.com",
    )


    assessment = build_fake_assessment(
        "CR-PRIVATE2"
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            assessment,
    )


    client_one.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )


    register_user(
        client_two,
        username="bob",
        email="bob@example.com",
    )

    login_user(
        client_two,
        email="bob@example.com",
    )


    response = client_two.get(
        "/history/CR-PRIVATE2"
    )


    assert response.status_code == 404


    report_response = (
        client_two.get(
            "/history/CR-PRIVATE2/report"
        )
    )


    assert (
        report_response.status_code
        == 404
    )


def test_compare_page_loads_without_selection(
    authenticated_client,
):
    """
    /compare should never fail merely because
    no baseline/current scan was selected.
    """

    response = (
        authenticated_client.get(
            "/compare"
        )
    )

    assert response.status_code == 200


def test_same_scan_comparison_rejected(
    authenticated_client,
    monkeypatch,
):
    """
    CyberRecon should reject comparison of
    a scan with itself.
    """

    assessment = build_fake_assessment(
        "CR-COMP0001"
    )


    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            assessment,
    )


    authenticated_client.post(
        "/scan",
        data={
            "target":
                "example.test"
        },
    )


    response = (
        authenticated_client.get(
            (
                "/compare?"
                "baseline=CR-COMP0001"
                "&current=CR-COMP0001"
            )
        )
    )


    assert response.status_code == 200

    assert (
        b"two different assessments"
        in response.data
    )


def test_two_scans_can_be_compared(
    authenticated_client,
):
    """
    Two assessments of the same normalized target
    should pass through the comparison route.
    """

    with (
        authenticated_client
        .session_transaction()
    ) as session:

        user_id = session[
            "user_id"
        ]


    first = build_fake_assessment(
        "CR-COMP0002"
    )

    second = build_fake_assessment(
        "CR-COMP0003"
    )


    storage.save_assessment(
        first,
        user_id,
    )

    storage.save_assessment(
        second,
        user_id,
    )


    response = (
        authenticated_client.get(
            (
                "/compare?"
                "baseline=CR-COMP0002"
                "&current=CR-COMP0003"
            )
        )
    )


    assert response.status_code == 200


def test_login_next_redirect(
    client,
    register_user,
):
    """
    A user redirected to login should return
    to their original protected page.
    """

    register_user(
        client
    )


    response = client.post(
        "/login?next=/history",
        data={
            "email":
                "test@example.com",

            "password":
                "Testpass123",

            "next":
                "/history",
        },
        follow_redirects=False,
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/history"
    )