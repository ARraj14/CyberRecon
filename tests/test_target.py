import pytest

from cyberrecon.scanner.target import (
    is_valid_hostname,
    normalize_target,
)


def test_valid_normal_domain():
    """
    A normal hostname should be accepted.
    """

    assert is_valid_hostname(
        "example.com"
    )


def test_valid_subdomain():
    """
    Subdomains should be accepted.
    """

    assert is_valid_hostname(
        "www.example.com"
    )


def test_valid_ipv4_address():
    """
    IPv4 targets should be accepted.
    """

    assert is_valid_hostname(
        "127.0.0.1"
    )


def test_localhost_is_valid():
    """
    localhost is intentionally supported because
    CyberRecon uses a controlled local test target.
    """

    assert is_valid_hostname(
        "localhost"
    )


def test_invalid_hostname_with_spaces():
    """
    Hostnames containing whitespace must fail.
    """

    assert not is_valid_hostname(
        "hello world.com"
    )


def test_invalid_hostname_label():
    """
    Hostname labels cannot begin with a hyphen.
    """

    assert not is_valid_hostname(
        "-example.com"
    )


def test_scheme_less_domain_uses_https():
    """
    CyberRecon should prefer HTTPS when the user
    enters only a hostname.
    """

    normalized = normalize_target(
        "example.com"
    )

    assert normalized == (
        "https://example.com"
    )


def test_existing_https_is_preserved():
    """
    Explicit HTTPS input must remain HTTPS.
    """

    normalized = normalize_target(
        "https://example.com"
    )

    assert normalized == (
        "https://example.com"
    )


def test_existing_http_is_preserved():
    """
    Explicit HTTP input must remain HTTP.
    """

    normalized = normalize_target(
        "http://example.com"
    )

    assert normalized == (
        "http://example.com"
    )


def test_localhost_with_port():
    """
    The controlled CyberRecon demo target uses
    localhost/127.0.0.1 with a custom port.
    """

    normalized = normalize_target(
        "127.0.0.1:5001"
    )

    assert normalized == (
        "https://127.0.0.1:5001"
    )


def test_http_local_demo_target():
    """
    Explicit HTTP must be respected for the
    local demonstration target.
    """

    normalized = normalize_target(
        "http://127.0.0.1:5001"
    )

    assert normalized == (
        "http://127.0.0.1:5001"
    )


def test_path_is_preserved():
    """
    URL paths should survive normalization.
    """

    normalized = normalize_target(
        "https://example.com/test"
    )

    assert normalized == (
        "https://example.com/test"
    )


def test_query_string_is_preserved():
    """
    Query parameters should survive normalization.
    """

    normalized = normalize_target(
        "https://example.com/"
        "?page=1"
    )

    assert normalized == (
        "https://example.com/"
        "?page=1"
    )


def test_fragment_is_removed():
    """
    Browser fragments should not be sent to the
    target and are removed during normalization.
    """

    normalized = normalize_target(
        "https://example.com/test#section"
    )

    assert normalized == (
        "https://example.com/test"
    )


def test_empty_target_fails():
    """
    Empty input must be rejected.
    """

    with pytest.raises(ValueError):

        normalize_target(
            ""
        )


def test_whitespace_only_target_fails():
    """
    Whitespace-only input must be rejected.
    """

    with pytest.raises(ValueError):

        normalize_target(
            "   "
        )


def test_unsupported_ftp_scheme_fails():
    """
    CyberRecon only supports HTTP/HTTPS.
    """

    with pytest.raises(ValueError):

        normalize_target(
            "ftp://example.com"
        )


def test_embedded_credentials_fail():
    """
    URLs containing embedded credentials should
    be rejected.
    """

    with pytest.raises(ValueError):

        normalize_target(
            "https://user:password@example.com"
        )


def test_invalid_port_fails():
    """
    Ports outside the valid TCP range should fail.
    """

    with pytest.raises(ValueError):

        normalize_target(
            "https://example.com:99999"
        )


def test_missing_hostname_fails():
    """
    A URL without a hostname must be rejected.
    """

    with pytest.raises(ValueError):

        normalize_target(
            "https://"
        )