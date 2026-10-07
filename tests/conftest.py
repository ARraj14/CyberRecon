import pytest

import cyberrecon.storage as storage

from cyberrecon.app import create_app


@pytest.fixture
def app(
    tmp_path,
    monkeypatch,
):
    """
    Create an isolated CyberRecon application.

    The real development SQLite database is never
    modified by the automated test suite.
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

    application = create_app(
        {
            "TESTING": True,

            "SECRET_KEY":
                "cyberrecon-test-secret-key",

            # Existing application tests focus on
            # their own behavior. CSRF has its own
            # dedicated suite.
            "CSRF_PROTECTION_ENABLED":
                False,
        }
    )

    yield application


@pytest.fixture
def client(app):

    return app.test_client()


@pytest.fixture
def register_user():

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

    register_user(
        client
    )

    login_user(
        client
    )

    return client