import pytest
from unittest.mock import patch
import cyberrecon.storage as storage
from tests.test_app_integration import build_fake_assessment


def test_new_assessment_requires_login(client):
    """
    Unauthenticated users must be redirected to login when visiting /new.
    """
    response = client.get("/new")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert "next=" in response.headers["Location"]


def test_new_assessment_workspace_loads_for_authenticated_user(authenticated_client):
    """
    Authenticated users must receive the dedicated assessment workspace (200 OK).
    """
    response = authenticated_client.get("/new")
    assert response.status_code == 200
    assert b"New Security" in response.data
    assert b"Assessment" in response.data
    assert b"Target Configuration" in response.data
    assert b"18 Supported Security Checks" in response.data
    assert b"Authorization Confirmation" in response.data


def test_new_assessment_prefills_target_param(authenticated_client):
    """
    Visiting /new?target=custom.domain.test pre-fills the target input.
    """
    response = authenticated_client.get("/new?target=https://custom.domain.test")
    assert response.status_code == 200
    assert b"value=\"https://custom.domain.test\"" in response.data


def test_scan_get_anonymous_redirects_to_login(client):
    """
    Anonymous GET /scan must redirect safely to login instead of returning 405.
    """
    anon_resp = client.get("/scan")
    assert anon_resp.status_code == 302
    assert "/login" in anon_resp.headers["Location"]


def test_scan_get_authenticated_redirects_to_workspace(authenticated_client):
    """
    Authenticated GET /scan must redirect safely to /new workspace instead of returning 405.
    """
    auth_resp = authenticated_client.get("/scan")
    assert auth_resp.status_code == 302
    assert "/new" in auth_resp.headers["Location"]


def test_anonymous_scan_preserves_target_across_login(client):
    """
    Submitting a target from the public page redirects to login with next=/new?target=...
    """
    response = client.post(
        "/scan",
        data={"target": "example.org"},
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert "target=example.org" in response.headers["Location"] or "target%3Dexample.org" in response.headers["Location"]


def test_authenticated_scan_success(authenticated_client, monkeypatch):
    """
    Authenticated user scanning a valid target executes the assessment and renders results.
    """
    fake = build_fake_assessment(
        scan_id="CR-STAGE3-001",
        target="https://workspace-test.test",
    )
    monkeypatch.setattr(
        "cyberrecon.app.run_assessment",
        lambda target: fake,
    )

    response = authenticated_client.post(
        "/scan",
        data={"target": "https://workspace-test.test"},
    )
    assert response.status_code == 200
    assert b"workspace-test.test" in response.data


def test_authenticated_scan_value_error_re_renders_workspace(authenticated_client, monkeypatch):
    """
    When run_assessment raises ValueError (e.g. invalid target/SSRF), re-render workspace with error.
    """
    def raise_invalid(target):
        raise ValueError("Invalid target format or blocked IP address.")

    monkeypatch.setattr(
        "cyberrecon.app.run_assessment",
        raise_invalid,
    )

    response = authenticated_client.post(
        "/scan",
        data={"target": "invalid-target-value"},
    )
    assert response.status_code == 200
    assert b"Assessment Initiation Error" in response.data
    assert b"Invalid target format or blocked IP address." in response.data
    assert b"invalid-target-value" in response.data


def test_recent_targets_displayed_in_workspace(authenticated_client, monkeypatch):
    """
    Scan history populates recent target chips in the workspace.
    """
    fake_history = [
        {"target": "https://alpha.test", "scan_id": "CR-1"},
        {"target": "https://beta.test", "scan_id": "CR-2"},
    ]
    monkeypatch.setattr(
        "cyberrecon.app.get_scan_history",
        lambda uid: fake_history,
    )

    response = authenticated_client.get("/new")
    assert response.status_code == 200
    assert b"Recent Target Shortcuts" in response.data
    assert b"alpha.test" in response.data
    assert b"beta.test" in response.data


def test_landing_page_clearly_labels_demo_preview(client):
    """
    Public landing page at / must clearly label illustrative preview as sample/demo data.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert b"DEMO PREVIEW" in response.data or b"SAMPLE DATA" in response.data
    assert b"Simulated Output" in response.data
