import pytest

import cyberrecon.storage as storage

from cyberrecon.app import create_app


@pytest.fixture
def app(
    tmp_path,
    monkeypatch,
):
    """
    Create an isolated CyberRecon Flask application
    for each test.

    Every test receives:
    - its own SQLite database
    - a deterministic Flask secret key
    - testing mode enabled

    The real development database is never modified.
    """

    test_database = (
        tmp_path
        / "cyberrecon_test.db"
    )

    monkeypatch.setattr(
        storage,
        "DATABASE_PATH",
        test_database,
    )

    monkeypatch.setenv(
        "CYBERRECON_SECRET_KEY",
        "cyberrecon-test-secret-key",
    )

    application = create_app()

    application.config.update(
        TESTING=True,
        SECRET_KEY=(
            "cyberrecon-test-secret-key"
        ),
    )

    yield application


@pytest.fixture
def client(app):
    """
    Flask test client.
    """

    return app.test_client()


@pytest.fixture
def register_user():
    """
    Helper for registering users through the
    actual CyberRecon registration route.
    """

    def _register(
        client,
        username="testuser",
        email="test@example.com",
        password="Testpass123",
    ):

        return client.post(
            "/register",
            data={
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

    return _register


@pytest.fixture
def login_user():
    """
    Helper for logging in through the
    CyberRecon login route.
    """

    def _login(
        client,
        email="test@example.com",
        password="Testpass123",
    ):

        return client.post(
            "/login",
            data={
                "email":
                    email,

                "password":
                    password,
            },
            follow_redirects=False,
        )

    return _login


@pytest.fixture
def authenticated_client(
    client,
    register_user,
    login_user,
):
    """
    Return a client with one authenticated user.
    """

    register_user(
        client
    )

    login_user(
        client
    )

    return client