import cyberrecon.storage as storage


def test_registration_page_loads(
    client,
):
    """
    Registration page must be publicly available.
    """

    response = client.get(
        "/register"
    )

    assert response.status_code == 200

    assert (
        b"Create"
        in response.data
    )


def test_user_can_register(
    client,
    register_user,
):
    """
    Valid registration should create a user.
    """

    response = register_user(
        client
    )

    assert response.status_code == 200

    assert (
        b"Account created successfully"
        in response.data
    )


    user = storage.get_user_by_email(
        "test@example.com"
    )

    assert user is not None

    assert (
        user["username"]
        == "testuser"
    )


def test_password_is_not_stored_plaintext(
    client,
    register_user,
):
    """
    Passwords must be stored as hashes.
    """

    register_user(
        client
    )


    user = storage.get_user_by_email(
        "test@example.com"
    )


    assert user is not None

    assert (
        user["password_hash"]
        != "Testpass123"
    )

    assert (
        "Testpass123"
        not in user[
            "password_hash"
        ]
    )


def test_duplicate_email_rejected(
    client,
    register_user,
):
    """
    Two accounts cannot use the same email.
    """

    register_user(
        client
    )


    response = register_user(
        client,
        username="anotheruser",
        email="test@example.com",
    )


    assert response.status_code == 200

    assert (
        b"already registered"
        in response.data
    )


def test_duplicate_username_rejected(
    client,
    register_user,
):
    """
    Usernames must also be unique.
    """

    register_user(
        client
    )


    response = register_user(
        client,
        username="testuser",
        email="another@example.com",
    )


    assert response.status_code == 200

    assert (
        b"already registered"
        in response.data
    )


def test_short_password_rejected(
    client,
):
    """
    Passwords shorter than eight characters
    must fail validation.
    """

    response = client.post(
        "/register",
        data={
            "username":
                "testuser",

            "email":
                "test@example.com",

            "password":
                "short",

            "confirm_password":
                "short",
        },
    )


    assert response.status_code == 200

    assert (
        b"at least 8 characters"
        in response.data
    )


def test_password_confirmation_required(
    client,
):
    """
    Registration must reject mismatching passwords.
    """

    response = client.post(
        "/register",
        data={
            "username":
                "testuser",

            "email":
                "test@example.com",

            "password":
                "Testpass123",

            "confirm_password":
                "Different123",
        },
    )


    assert response.status_code == 200

    assert (
        b"Passwords do not match"
        in response.data
    )


def test_login_page_loads(
    client,
):
    """
    Login page must be publicly available.
    """

    response = client.get(
        "/login"
    )

    assert response.status_code == 200


def test_valid_login(
    client,
    register_user,
    login_user,
):
    """
    Correct credentials should create a session.
    """

    register_user(
        client
    )


    response = login_user(
        client
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


    with client.session_transaction() as session:

        assert (
            session["user_id"]
            is not None
        )

        assert (
            session["username"]
            == "testuser"
        )


def test_invalid_password_rejected(
    client,
    register_user,
    login_user,
):
    """
    Incorrect passwords must not authenticate.
    """

    register_user(
        client
    )


    response = login_user(
        client,
        password="WrongPassword123",
    )


    assert response.status_code == 200

    assert (
        b"Invalid email address or password"
        in response.data
    )


    with client.session_transaction() as session:

        assert (
            "user_id"
            not in session
        )


def test_unknown_email_rejected(
    client,
    login_user,
):
    """
    Unknown email addresses must not authenticate.
    """

    response = login_user(
        client,
        email="unknown@example.com",
    )


    assert response.status_code == 200

    assert (
        b"Invalid email address or password"
        in response.data
    )


def test_logout_clears_session(
    client,
    register_user,
    login_user,
):
    """
    Logout must destroy the login session.
    """

    register_user(
        client
    )

    login_user(
        client
    )


    response = client.post(
        "/logout"
    )


    assert response.status_code == 302


    with client.session_transaction() as session:

        assert (
            "user_id"
            not in session
        )

        assert (
            "username"
            not in session
        )


def test_logged_in_user_cannot_open_register(
    authenticated_client,
):
    """
    Logged-in users should be redirected away
    from registration.
    """

    response = (
        authenticated_client.get(
            "/register"
        )
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )


def test_logged_in_user_cannot_open_login(
    authenticated_client,
):
    """
    Already authenticated users should not
    receive another login form.
    """

    response = (
        authenticated_client.get(
            "/login"
        )
    )


    assert response.status_code == 302

    assert response.headers[
        "Location"
    ].endswith(
        "/dashboard"
    )