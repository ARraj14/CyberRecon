import pytest


def test_navbar_profile_section_on_all_authenticated_pages(authenticated_client):
    """
    Every page accessible to an authenticated user must feature the exact
    unified navbar with the user profile section (avatar circle, username,
    and interactive dropdown menu).
    """
    authenticated_endpoints = [
        "/new",
        "/dashboard",
        "/history",
        "/compare",
        "/logout",
    ]

    for endpoint in authenticated_endpoints:
        response = authenticated_client.get(endpoint)
        assert response.status_code == 200, f"Expected 200 for {endpoint}, got {response.status_code}"
        html = response.data.decode("utf-8")

        # 1. Main Navigation Elements
        assert 'class="navbar"' in html or "class='navbar'" in html, f"Missing navbar on {endpoint}"
        assert 'Cyber<span>Recon</span>' in html or "Cyber<span>Recon</span>" in html, f"Missing brand on {endpoint}"
        assert 'id="cmd-palette-btn"' in html, f"Missing search/palette trigger on {endpoint}"
        assert 'nav-cta-btn' in html, f"Missing + New Assessment CTA button on {endpoint}"
        assert 'id="theme-toggle"' in html, f"Missing theme toggle on {endpoint}"

        # 2. Profile Section & Avatar
        assert 'id="user-dropdown-wrap"' in html, f"Missing user-dropdown-wrap on {endpoint}"
        assert 'id="avatar-btn"' in html, f"Missing avatar button on {endpoint}"
        assert 'class="avatar-circle"' in html, f"Missing avatar circle on {endpoint}"
        assert "T" in html, f"Missing user initial 'T' in avatar circle on {endpoint}"
        assert "testuser" in html, f"Missing username 'testuser' on {endpoint}"

        # 3. User Dropdown Menu
        assert 'id="user-dropdown-menu"' in html, f"Missing user dropdown menu on {endpoint}"
        assert "Session Active" in html, f"Missing Session Active status in dropdown on {endpoint}"
        assert "Scan History" in html, f"Missing Scan History in dropdown on {endpoint}"
        assert "Compare Scans" in html, f"Missing Compare Scans in dropdown on {endpoint}"
        assert "Sign Out" in html, f"Missing Sign Out in dropdown on {endpoint}"


def test_unauthenticated_navbar_does_not_show_profile_section(client):
    """
    Public / unauthenticated visitors must NOT see the user profile avatar or dropdown menu.
    """
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    assert 'id="user-dropdown-wrap"' not in html
    assert 'id="avatar-btn"' not in html
    assert 'id="user-dropdown-menu"' not in html
    assert "Login" in html
    assert "Register" in html


def test_navbar_profile_section_on_scan_detail_page(authenticated_client):
    """
    Scan detail page (/history/<scan_id>) must also display the full unified navbar and profile dropdown.
    """
    from tests.test_app_integration import build_fake_assessment
    from cyberrecon.storage import save_assessment

    with authenticated_client.session_transaction() as sess:
        user_id = sess["user_id"]

    fake_scan = build_fake_assessment("https://detail-test.local")
    fake_scan["metadata"]["scan_id"] = "CR-NAVPROF01"
    save_assessment(fake_scan, user_id=user_id)

    response = authenticated_client.get("/history/CR-NAVPROF01")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    assert 'id="avatar-btn"' in html
    assert 'class="avatar-circle"' in html
    assert 'id="user-dropdown-menu"' in html
    assert "Session Active" in html
    assert "testuser" in html

