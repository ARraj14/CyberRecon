import cyberrecon.app as app_module


def enable_csrf(app):
    """
    Enable CSRF validation for a dedicated test.
    """

    app.config[
        "CSRF_PROTECTION_ENABLED"
    ] = True


def get_csrf_token(
    client,
    path="/",
):
    """
    Load a rendered page and obtain the token
    created in its Flask session.
    """

    response = client.get(
        path
    )

    assert response.status_code == 200

    with client.session_transaction() as session:

        token = session.get(
            "_csrf_token"
        )

    assert token

    return token


def register_with_csrf(
    client,
    username="testuser",
    email="test@example.com",
    password="Testpass123",
):

    token = get_csrf_token(
        client,
        "/register",
    )

    return client.post(
        "/register",

        data={
            "csrf_token":
                token,

            "username":
                username,

            "email":
                email,

            "password":
                password,

            "confirm_password":
                password,
        },

        follow_redirects=False,
    )


def login_with_csrf(
    client,
    email="test@example.com",
    password="Testpass123",
):

    token = get_csrf_token(
        client,
        "/login",
    )

    return client.post(
        "/login",

        data={
            "csrf_token":
                token,

            "email":
                email,

            "password":
                password,
        },

        follow_redirects=False,
    )


def test_home_generates_csrf_token(
    app,
    client,
):

    enable_csrf(app)

    token = get_csrf_token(
        client
    )

    assert isinstance(
        token,
        str,
    )

    assert len(token) >= 32


def test_registration_without_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    response = client.post(
        "/register",

        data={
            "username":
                "alice",

            "email":
                "alice@example.com",

            "password":
                "Testpass123",

            "confirm_password":
                "Testpass123",
        },
    )

    assert response.status_code == 400

    assert (
        b"Invalid or missing CSRF token"
        in response.data
    )


def test_registration_with_invalid_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    get_csrf_token(
        client,
        "/register",
    )

    response = client.post(
        "/register",

        data={
            "csrf_token":
                "invalid-token",

            "username":
                "alice",

            "email":
                "alice@example.com",

            "password":
                "Testpass123",

            "confirm_password":
                "Testpass123",
        },
    )

    assert response.status_code == 400


def test_registration_with_valid_csrf_succeeds(
    app,
    client,
):

    enable_csrf(app)

    response = register_with_csrf(
        client
    )

    assert response.status_code == 200

    assert (
        b"Account created successfully"
        in response.data
    )


def test_login_without_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    response = client.post(
        "/login",

        data={
            "email":
                "test@example.com",

            "password":
                "Testpass123",
        },
    )

    assert response.status_code == 400


def test_login_with_valid_csrf_succeeds(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    response = login_with_csrf(
        client
    )

    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


def test_login_rotates_csrf_token(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    pre_login_token = get_csrf_token(
        client,
        "/login",
    )

    response = client.post(
        "/login",

        data={
            "csrf_token":
                pre_login_token,

            "email":
                "test@example.com",

            "password":
                "Testpass123",
        },

        follow_redirects=False,
    )

    assert response.status_code == 302

    with client.session_transaction() as session:

        post_login_token = session.get(
            "_csrf_token"
        )

    assert post_login_token

    assert (
        post_login_token
        != pre_login_token
    )


def test_scan_without_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    response = client.post(
        "/scan",

        data={
            "target":
                "example.test"
        },
    )

    assert response.status_code == 400


def test_scan_with_invalid_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    response = client.post(
        "/scan",

        data={
            "csrf_token":
                "incorrect-token",

            "target":
                "example.test",
        },
    )

    assert response.status_code == 400


def test_scan_with_valid_csrf_reaches_route(
    app,
    client,
    monkeypatch,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    fake_assessment = {
        "target":
            "https://example.test",

        "recon": {
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
                "https://example.test",

            "https_enabled":
                True,

            "response_time":
                10,

            "page_title":
                "CSRF Test",

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

            "fallback_used":
                False,

            "error_type":
                None,

            "error_message":
                None,
        },

        "findings":
            [],

        "finding_summary": {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
            "Total": 0,
        },

        "metadata": {
            "scan_id":
                "CR-CSRF0001",

            "started_at":
                "08 Oct 2026",

            "duration_ms":
                10,

            "checks_performed":
                18,

            "recon_status":
                "Completed",

            "analysis_status":
                "Completed",
        },
    }

    monkeypatch.setattr(
        app_module,
        "run_assessment",
        lambda target:
            fake_assessment,
    )

    token = get_csrf_token(
        client,
        "/",
    )

    response = client.post(
        "/scan",

        data={
            "csrf_token":
                token,

            "target":
                "example.test",
        },
    )

    assert response.status_code == 200

    assert (
        b"CR-CSRF0001"
        in response.data
    )


def test_csrf_token_can_be_sent_as_header(
    app,
    client,
):

    enable_csrf(app)

    token = get_csrf_token(
        client,
        "/register",
    )

    response = client.post(
        "/register",

        headers={
            "X-CSRF-Token":
                token,
        },

        data={
            "username":
                "headeruser",

            "email":
                "header@example.com",

            "password":
                "Testpass123",

            "confirm_password":
                "Testpass123",
        },
    )

    assert response.status_code == 200

    assert (
        b"Account created successfully"
        in response.data
    )



def test_logout_get_does_not_clear_session(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    response = client.get(
        "/logout"
    )

    assert response.status_code == 200

    assert (
        b"Confirm Logout"
        in response.data
    )

    with client.session_transaction() as session:

        assert session.get(
            "user_id"
        )

        assert session.get(
            "username"
        )


def test_logout_post_without_csrf_fails(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    response = client.post(
        "/logout",
        follow_redirects=False,
    )

    assert response.status_code == 400

    assert (
        b"Invalid or missing CSRF token"
        in response.data
    )

    with client.session_transaction() as session:

        assert session.get(
            "user_id"
        )


def test_logout_post_with_valid_csrf_clears_session(
    app,
    client,
):

    enable_csrf(app)

    register_with_csrf(
        client
    )

    login_with_csrf(
        client
    )

    token = get_csrf_token(
        client,
        "/logout",
    )

    response = client.post(
        "/logout",

        data={
            "csrf_token":
                token,
        },

        follow_redirects=False,
    )

    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/"
    )

    with client.session_transaction() as session:

        assert (
            "user_id"
            not in session
        )

        assert (
            "username"
            not in session
        )
