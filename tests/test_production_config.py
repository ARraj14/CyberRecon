import importlib
import sys

from pathlib import Path

import cyberrecon.storage as storage

from cyberrecon.app import create_app
from cyberrecon.scanner.target import (
    private_targets_allowed,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def test_wsgi_file_exists():
    """
    CyberRecon must provide a WSGI entry point
    for production application servers.
    """

    wsgi_file = (
        PROJECT_ROOT
        / "wsgi.py"
    )

    assert wsgi_file.exists()


def test_wsgi_exports_flask_application(
    tmp_path,
    monkeypatch,
):
    """
    Gunicorn must be able to import:

        wsgi:app

    The test uses an isolated SQLite database.
    """

    test_database = (
        tmp_path
        / "wsgi_test.db"
    )

    monkeypatch.setattr(
        storage,
        "DATABASE_PATH",
        test_database,
    )

    monkeypatch.setenv(
        "CYBERRECON_SECRET_KEY",
        "wsgi-production-test-secret",
    )


    # Force Python to import wsgi.py again.
    sys.modules.pop(
        "wsgi",
        None,
    )


    wsgi_module = (
        importlib.import_module(
            "wsgi"
        )
    )


    assert hasattr(
        wsgi_module,
        "app",
    )

    assert (
        wsgi_module.app
        is not None
    )

    assert (
        wsgi_module.app.name
        == "cyberrecon.app"
    )


def test_application_does_not_force_debug_mode(
    monkeypatch,
):
    """
    create_app() should not force Flask's
    debugger on.
    """

    monkeypatch.setenv(
        "CYBERRECON_SECRET_KEY",
        "production-test-secret",
    )


    app = create_app(
        {
            "TESTING":
                True,

            "DEBUG":
                False,

            "CSRF_PROTECTION_ENABLED":
                False,
        }
    )


    assert app.debug is False


def test_secure_cookie_can_be_enabled(
    monkeypatch,
):
    """
    HTTPS production deployments must be able
    to enable Secure session cookies.
    """

    monkeypatch.setenv(
        "CYBERRECON_SECRET_KEY",
        "production-test-secret",
    )

    monkeypatch.setenv(
        "CYBERRECON_SECURE_COOKIES",
        "1",
    )


    app = create_app(
        {
            "TESTING":
                True,

            "CSRF_PROTECTION_ENABLED":
                False,
        }
    )


    assert (
        app.config[
            "SESSION_COOKIE_SECURE"
        ]
        is True
    )


def test_secure_cookie_can_be_disabled_for_local_http(
    monkeypatch,
):
    """
    Local development remains possible over
    plain HTTP.
    """

    monkeypatch.setenv(
        "CYBERRECON_SECRET_KEY",
        "development-test-secret",
    )

    monkeypatch.setenv(
        "CYBERRECON_SECURE_COOKIES",
        "0",
    )


    app = create_app(
        {
            "TESTING":
                True,

            "CSRF_PROTECTION_ENABLED":
                False,
        }
    )


    assert (
        app.config[
            "SESSION_COOKIE_SECURE"
        ]
        is False
    )


def test_private_targets_disabled_by_default(
    monkeypatch,
):
    """
    Internal/private scanning must remain
    disabled unless explicitly enabled.
    """

    monkeypatch.delenv(
        "CYBERRECON_ALLOW_PRIVATE_TARGETS",
        raising=False,
    )


    assert (
        private_targets_allowed()
        is False
    )


def test_private_targets_can_be_enabled_for_demo(
    monkeypatch,
):
    """
    Controlled local demonstrations may
    explicitly enable private targets.
    """

    monkeypatch.setenv(
        "CYBERRECON_ALLOW_PRIVATE_TARGETS",
        "1",
    )


    assert (
        private_targets_allowed()
        is True
    )


def test_environment_example_exists():
    """
    Deployment configuration should include
    a safe environment-variable template.
    """

    environment_example = (
        PROJECT_ROOT
        / ".env.example"
    )


    assert environment_example.exists()


def test_environment_example_contains_secret_key():
    """
    The environment template must document
    production secret configuration.
    """

    contents = (
        PROJECT_ROOT
        / ".env.example"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "CYBERRECON_SECRET_KEY"
        in contents
    )


def test_environment_example_contains_secure_cookie_setting():

    contents = (
        PROJECT_ROOT
        / ".env.example"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "CYBERRECON_SECURE_COOKIES"
        in contents
    )


def test_environment_example_contains_hsts_setting():

    contents = (
        PROJECT_ROOT
        / ".env.example"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "CYBERRECON_ENABLE_HSTS"
        in contents
    )


def test_environment_example_contains_ssrf_policy():

    contents = (
        PROJECT_ROOT
        / ".env.example"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "CYBERRECON_ALLOW_PRIVATE_TARGETS"
        in contents
    )


def test_gitignore_exists():

    gitignore = (
        PROJECT_ROOT
        / ".gitignore"
    )


    assert gitignore.exists()


def test_real_environment_files_are_ignored():
    """
    Real environment files containing secrets
    should never be committed.
    """

    contents = (
        PROJECT_ROOT
        / ".gitignore"
    ).read_text(
        encoding="utf-8"
    )


    assert ".env" in contents

    assert (
        ".env.production"
        in contents
    )


def test_runtime_database_is_ignored():
    """
    User accounts and assessments must not
    accidentally enter Git history.
    """

    contents = (
        PROJECT_ROOT
        / ".gitignore"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "data/*.db"
        in contents
    )


def test_session_secret_is_ignored():
    """
    The locally generated Flask session secret
    must never be committed.
    """

    contents = (
        PROJECT_ROOT
        / ".gitignore"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "data/.session_secret"
        in contents
    )


def test_environment_example_is_not_ignored():
    """
    .env.example is documentation and should
    remain safe to commit.
    """

    contents = (
        PROJECT_ROOT
        / ".gitignore"
    ).read_text(
        encoding="utf-8"
    )


    lines = {
        line.strip()
        for line in contents.splitlines()
    }


    assert (
        ".env.example"
        not in lines
    )


def test_wsgi_source_uses_application_factory():
    """
    The production entry point should build
    CyberRecon through create_app().
    """

    contents = (
        PROJECT_ROOT
        / "wsgi.py"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        "create_app"
        in contents
    )

    assert (
        "app = create_app()"
        in contents
    )


def test_run_file_exists():
    """
    Development startup remains separate from
    the production WSGI entry point.
    """

    run_file = (
        PROJECT_ROOT
        / "run.py"
    )


    assert run_file.exists()


def test_run_file_binds_only_to_loopback():
    """
    The development server should not expose
    itself to the network by default.
    """

    contents = (
        PROJECT_ROOT
        / "run.py"
    ).read_text(
        encoding="utf-8"
    )


    assert (
        'host="127.0.0.1"'
        in contents
    )