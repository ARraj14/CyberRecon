import cyberrecon.storage as storage

from werkzeug.security import (
    generate_password_hash,
)


def build_assessment(
    scan_id,
    target="https://example.test",
    analysis_status="Completed",
):
    """
    Build a deterministic assessment for
    database testing.
    """

    findings = []

    if analysis_status == "Completed":

        findings = [
            {
                "id":
                    "CR-003",

                "finding_code":
                    "CR-003",

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
                    "Test description.",

                "recommendation":
                    "Test recommendation.",
            }
        ]


    return {
        "target":
            target,

        "recon": {
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
                10.5,

            "page_title":
                "Example Test",

            "server":
                "TestServer",

            "content_type":
                "text/html",

            "redirect_count":
                0,

            "headers":
                {},

            "set_cookies":
                [],
        },

        "findings":
            findings,

        "finding_summary": {
            "High":
                0,

            "Medium":
                len(findings),

            "Low":
                0,

            "Info":
                0,

            "Total":
                len(findings),
        },

        "metadata": {
            "scan_id":
                scan_id,

            "started_at":
                (
                    "08 Oct 2026, "
                    "10:00:00 AM IST"
                ),

            "duration_ms":
                25,

            "checks_performed":
                (
                    18
                    if analysis_status
                    == "Completed"
                    else 0
                ),

            "recon_status":
                "Completed",

            "analysis_status":
                analysis_status,
        },
    }


def create_test_user(
    username,
    email,
):
    """
    Create a test user and return its ID.
    """

    return storage.create_user(
        username,
        email,
        generate_password_hash(
            "Testpass123"
        ),
    )


def test_create_and_find_user(
    app,
):
    """
    User storage functions should return
    persisted account information.
    """

    user_id = create_test_user(
        "alice",
        "alice@example.com",
    )


    by_email = (
        storage.get_user_by_email(
            "alice@example.com"
        )
    )


    by_username = (
        storage.get_user_by_username(
            "alice"
        )
    )


    by_id = storage.get_user_by_id(
        user_id
    )


    assert (
        by_email["id"]
        == user_id
    )

    assert (
        by_username["email"]
        == "alice@example.com"
    )

    assert (
        by_id["username"]
        == "alice"
    )


def test_scan_saved_for_owner(
    app,
):
    """
    Stored scans must belong to the supplied
    user ID.
    """

    user_id = create_test_user(
        "alice",
        "alice@example.com",
    )


    assessment = build_assessment(
        "CR-TEST0001"
    )


    storage.save_assessment(
        assessment,
        user_id,
    )


    stored = storage.get_scan_by_id(
        "CR-TEST0001",
        user_id,
    )


    assert stored is not None

    assert (
        stored["scan"]["user_id"]
        == user_id
    )


def test_other_user_cannot_read_scan(
    app,
):
    """
    Knowing another user's scan ID must not
    provide access to that assessment.
    """

    alice_id = create_test_user(
        "alice",
        "alice@example.com",
    )

    bob_id = create_test_user(
        "bob",
        "bob@example.com",
    )


    storage.save_assessment(
        build_assessment(
            "CR-PRIVATE1"
        ),
        alice_id,
    )


    assert (
        storage.get_scan_by_id(
            "CR-PRIVATE1",
            bob_id,
        )
        is None
    )


def test_history_is_user_specific(
    app,
):
    """
    Scan history must be isolated by owner.
    """

    alice_id = create_test_user(
        "alice",
        "alice@example.com",
    )

    bob_id = create_test_user(
        "bob",
        "bob@example.com",
    )


    storage.save_assessment(
        build_assessment(
            "CR-ALICE001"
        ),
        alice_id,
    )


    storage.save_assessment(
        build_assessment(
            "CR-BOB00001"
        ),
        bob_id,
    )


    alice_history = (
        storage.get_scan_history(
            alice_id
        )
    )


    bob_history = (
        storage.get_scan_history(
            bob_id
        )
    )


    assert len(
        alice_history
    ) == 1

    assert len(
        bob_history
    ) == 1


    assert (
        alice_history[0]["scan_id"]
        == "CR-ALICE001"
    )

    assert (
        bob_history[0]["scan_id"]
        == "CR-BOB00001"
    )


def test_finding_metadata_is_persisted(
    app,
):
    """
    v0.8 finding metadata must survive
    database persistence.
    """

    user_id = create_test_user(
        "alice",
        "alice@example.com",
    )


    storage.save_assessment(
        build_assessment(
            "CR-META0001"
        ),
        user_id,
    )


    stored = storage.get_scan_by_id(
        "CR-META0001",
        user_id,
    )


    finding = stored[
        "findings"
    ][0]


    assert (
        finding["confidence"]
        == "High"
    )

    assert (
        finding["affected_component"]
        == "HTTP Security Headers"
    )

    assert (
        finding["cwe"]
        == "CWE-693"
    )

    assert (
        "OWASP A05"
        in finding["owasp"]
    )


def test_completed_scans_are_user_specific(
    app,
):
    """
    Comparison candidates must not contain
    another user's scans.
    """

    alice_id = create_test_user(
        "alice",
        "alice@example.com",
    )

    bob_id = create_test_user(
        "bob",
        "bob@example.com",
    )


    storage.save_assessment(
        build_assessment(
            "CR-ALICE002"
        ),
        alice_id,
    )


    storage.save_assessment(
        build_assessment(
            "CR-BOB00002"
        ),
        bob_id,
    )


    scans = (
        storage.get_completed_scans(
            alice_id
        )
    )


    assert len(scans) == 1

    assert (
        scans[0]["scan_id"]
        == "CR-ALICE002"
    )


def test_dashboard_statistics_are_user_specific(
    app,
):
    """
    Dashboard analytics must only count
    scans belonging to the logged-in user.
    """

    alice_id = create_test_user(
        "alice",
        "alice@example.com",
    )

    bob_id = create_test_user(
        "bob",
        "bob@example.com",
    )


    storage.save_assessment(
        build_assessment(
            "CR-ALICE003"
        ),
        alice_id,
    )


    storage.save_assessment(
        build_assessment(
            "CR-BOB00003"
        ),
        bob_id,
    )


    analytics = (
        storage.get_dashboard_analytics(
            alice_id
        )
    )


    assert (
        analytics["overview"][
            "total_scans"
        ]
        == 1
    )

    assert (
        analytics["severity"][
            "total_findings"
        ]
        == 1
    )


def test_failed_scan_can_be_saved(
    app,
):
    """
    Failed/skipped assessments must still
    persist correctly.
    """

    user_id = create_test_user(
        "alice",
        "alice@example.com",
    )


    assessment = build_assessment(
        "CR-FAILED01",
        analysis_status="Skipped",
    )


    assessment[
        "metadata"
    ][
        "recon_status"
    ] = "Failed"


    storage.save_assessment(
        assessment,
        user_id,
    )


    stored = storage.get_scan_by_id(
        "CR-FAILED01",
        user_id,
    )


    assert stored is not None

    assert (
        stored["scan"][
            "analysis_status"
        ]
        == "Skipped"
    )

    assert (
        stored["findings"]
        == []
    )