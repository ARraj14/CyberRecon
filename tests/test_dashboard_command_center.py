import sqlite3
from datetime import datetime, timedelta
import pytest
import cyberrecon.storage as storage


def make_assessment_data(scan_id, target="https://example.com", analysis_status="Completed", recon_status="Completed", findings=None):
    if findings is None:
        findings = [
            {
                "id": "CR-003",
                "finding_code": "CR-003",
                "name": "Content Security Policy Missing",
                "category": "Browser Security",
                "severity": "Medium",
                "confidence": "High",
                "affected_component": "HTTP Security Headers",
                "cwe": "CWE-693",
                "owasp": "OWASP A05:2021 Security Misconfiguration",
                "evidence": "Content-Security-Policy was not present.",
                "description": "Test description.",
                "recommendation": "Test recommendation.",
            }
        ]

    return {
        "target": target,
        "recon": {
            "domain": target.replace("https://", "").replace("http://", ""),
            "ip_address": "93.184.216.34",
            "reachable": True,
            "status_code": 200,
            "final_url": target,
            "https_enabled": True,
            "response_time": 15.0,
            "page_title": "Example Domain",
            "server": "ECS",
            "content_type": "text/html",
            "redirect_count": 0,
            "headers": {},
            "set_cookies": [],
        },
        "findings": findings,
        "finding_summary": {
            "High": sum(1 for f in findings if f.get("severity") == "High"),
            "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
            "Low": sum(1 for f in findings if f.get("severity") == "Low"),
            "Info": sum(1 for f in findings if f.get("severity") in ("Info", "Informational")),
            "Total": len(findings),
        },
        "metadata": {
            "scan_id": scan_id,
            "started_at": "08 Oct 2026, 10:00:00 AM IST",
            "duration_ms": 120,
            "checks_performed": 18 if analysis_status == "Completed" else 0,
            "recon_status": recon_status,
            "analysis_status": analysis_status,
        },
    }


def test_dashboard_empty_state_for_new_user(authenticated_client):
    """A fresh user with zero assessments should see the onboarding empty state."""
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "SECURITY ANALYTICS" in html
    assert "Security Command Center" in html
    assert "Welcome to CyberRecon Command Center" in html
    assert "Launch Your First Assessment" in html


def test_dashboard_renders_metrics_and_kpis(app, authenticated_client):
    """Assessments should correctly populate the 5 KPI cards."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        assert user is not None
        user_id = user["id"]

        data1 = make_assessment_data("CR-AAA1", target="https://target1.test", analysis_status="Completed", recon_status="Completed")
        storage.save_assessment(data1, user_id)

        data2 = make_assessment_data("CR-AAA2", target="https://target2.test", analysis_status="Failed", recon_status="Failed", findings=[])
        storage.save_assessment(data2, user_id)

    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Check KPI labels
    assert "TOTAL ASSESSMENTS" in html
    assert "SUCCESSFUL" in html
    assert "FAILED PROBES" in html
    assert "OBSERVED FINDINGS" in html
    assert "UNIQUE TARGETS" in html

    # Check that records render in table
    assert "target1.test" in html
    assert "CR-AAA1" in html
    assert "CR-AAA2" in html
    assert "Completed" in html
    assert "Failed" in html


def test_dashboard_timeframe_filtering(app, authenticated_client):
    """Timeframe query parameters (?range=24h, 7d, 30d, all) filter accurately."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        user_id = user["id"]

        # Store recent scan
        data_recent = make_assessment_data("CR-RECENT", target="https://recent.test")
        storage.save_assessment(data_recent, user_id)

        # Store older scan and manually adjust timestamp to 10 days ago
        data_old = make_assessment_data("CR-OLDER", target="https://older.test")
        storage.save_assessment(data_old, user_id)

        from datetime import timezone
        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(storage.DATABASE_PATH) as conn:
            conn.execute(
                "UPDATE scans SET created_at = ? WHERE scan_id = ?",
                (ten_days_ago, "CR-OLDER")
            )
            conn.commit()

    # 24h filter: only recent scan
    res_24h = authenticated_client.get("/dashboard?range=24h")
    assert res_24h.status_code == 200
    html_24h = res_24h.get_data(as_text=True)
    assert "CR-RECENT" in html_24h
    assert "CR-OLDER" not in html_24h

    # 7d filter: only recent scan
    res_7d = authenticated_client.get("/dashboard?range=7d")
    assert res_7d.status_code == 200
    html_7d = res_7d.get_data(as_text=True)
    assert "CR-RECENT" in html_7d
    assert "CR-OLDER" not in html_7d

    # 30d filter: both scans
    res_30d = authenticated_client.get("/dashboard?range=30d")
    assert res_30d.status_code == 200
    html_30d = res_30d.get_data(as_text=True)
    assert "CR-RECENT" in html_30d
    assert "CR-OLDER" in html_30d

    # All time filter: both scans
    res_all = authenticated_client.get("/dashboard?range=all")
    assert res_all.status_code == 200
    html_all = res_all.get_data(as_text=True)
    assert "CR-RECENT" in html_all
    assert "CR-OLDER" in html_all


def test_dashboard_user_isolation(app, client, register_user, login_user):
    """User A cannot see User B's scans or metrics on the dashboard."""
    # Register and login User A
    register_user(client, username="usera", email="usera@example.com", password="Password123")
    login_user(client, email="usera@example.com", password="Password123")

    with app.app_context():
        user_a = storage.get_user_by_email("usera@example.com")
        data_a = make_assessment_data("CR-USERA", target="https://target-a.test")
        storage.save_assessment(data_a, user_a["id"])

    # Logout User A
    client.post("/logout")

    # Register and login User B
    register_user(client, username="userb", email="userb@example.com", password="Password123")
    login_user(client, email="userb@example.com", password="Password123")

    with app.app_context():
        user_b = storage.get_user_by_email("userb@example.com")
        data_b = make_assessment_data("CR-USERB", target="https://target-b.test")
        storage.save_assessment(data_b, user_b["id"])

    # Inspect User B's dashboard
    res_b = client.get("/dashboard")
    assert res_b.status_code == 200
    html_b = res_b.get_data(as_text=True)

    assert "CR-USERB" in html_b
    assert "target-b.test" in html_b
    # Must NOT contain User A's data
    assert "CR-USERA" not in html_b
    assert "target-a.test" not in html_b


def test_dashboard_common_findings_and_insights(app, authenticated_client):
    """Test that common findings and operational insights render correctly."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        user_id = user["id"]

        findings = [
            {
                "id": "CR-001",
                "finding_code": "CR-001",
                "name": "Strict-Transport-Security Missing",
                "category": "Transport Security",
                "severity": "High",
                "confidence": "High",
                "affected_component": "HTTP Headers",
                "cwe": "CWE-319",
                "owasp": "OWASP A05:2021 Security Misconfiguration",
                "evidence": "No HSTS header.",
                "description": "Missing HSTS.",
                "recommendation": "Add HSTS.",
            },
            {
                "id": "CR-002",
                "finding_code": "CR-002",
                "name": "X-Frame-Options Missing",
                "category": "Clickjacking",
                "severity": "Medium",
                "confidence": "High",
                "affected_component": "HTTP Headers",
                "cwe": "CWE-1021",
                "owasp": "OWASP A05:2021 Security Misconfiguration",
                "evidence": "No X-Frame-Options.",
                "description": "Missing XFO.",
                "recommendation": "Add X-Frame-Options.",
            }
        ]

        data = make_assessment_data("CR-INSPECT", target="https://insights-target.test", findings=findings)
        storage.save_assessment(data, user_id)

    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Threat Landscape
    assert "Threat Landscape" in html
    assert "HIGH" in html
    assert "MEDIUM" in html

    # Common findings
    assert "Common Findings Intelligence" in html
    assert "CR-001" in html
    assert "Strict-Transport-Security Missing" in html

    # Operational Insights
    assert "Operational Security Insights" in html
    assert "TOP DETECTED MISCONFIGURATION" in html
    assert "HIGHEST EXPOSURE TARGET" in html
    assert "AUDITED FOOTPRINT" in html
    assert "LATEST COMPLETED AUDIT" in html
    assert "insights-target.test" in html


def test_navbar_remains_unmodified_on_dashboard(authenticated_client):
    """The navbar brand, search shortcut, navigation links, and theme toggle must be intact."""
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Brand and logo
    assert "CyberRecon" in html

    # Navigation items
    assert "Dashboard" in html
    assert "Scan History" in html
    assert "Compare" in html
    assert "New Assessment" in html
