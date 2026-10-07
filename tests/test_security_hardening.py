from cyberrecon.app import (
    is_safe_local_redirect,
)


def test_content_type_options_header(
    client,
):
    """
    CyberRecon should prevent MIME sniffing.
    """

    response = client.get(
        "/"
    )

    assert (
        response.headers[
            "X-Content-Type-Options"
        ]
        == "nosniff"
    )


def test_frame_options_header(
    client,
):
    """
    CyberRecon should not be frameable.
    """

    response = client.get(
        "/"
    )

    assert (
        response.headers[
            "X-Frame-Options"
        ]
        == "DENY"
    )


def test_referrer_policy_header(
    client,
):
    """
    CyberRecon should use a restrictive
    referrer policy.
    """

    response = client.get(
        "/"
    )

    assert (
        response.headers[
            "Referrer-Policy"
        ]
        == (
            "strict-origin-when-cross-origin"
        )
    )


def test_permissions_policy_header(
    client,
):
    """
    Browser features not required by CyberRecon
    should be disabled.
    """

    response = client.get(
        "/"
    )

    policy = response.headers[
        "Permissions-Policy"
    ]

    assert (
        "camera=()"
        in policy
    )

    assert (
        "microphone=()"
        in policy
    )

    assert (
        "geolocation=()"
        in policy
    )


def test_csp_header_exists(
    client,
):
    """
    CyberRecon should publish a CSP.
    """

    response = client.get(
        "/"
    )

    csp = response.headers[
        "Content-Security-Policy"
    ]

    assert (
        "default-src 'self'"
        in csp
    )

    assert (
        "frame-ancestors 'none'"
        in csp
    )


def test_dynamic_pages_not_cached(
    client,
):
    """
    Dynamic application pages should not be
    stored in shared browser caches.
    """

    response = client.get(
        "/"
    )

    assert (
        "no-store"
        in response.headers[
            "Cache-Control"
        ]
    )


def test_local_redirect_allowed():
    """
    Internal redirects are valid.
    """

    assert is_safe_local_redirect(
        "/history"
    )


def test_local_redirect_with_query_allowed():
    """
    Internal URLs may contain query parameters.
    """

    assert is_safe_local_redirect(
        "/compare?baseline=test"
    )


def test_external_https_redirect_rejected():
    """
    Login must not redirect users to an
    arbitrary external website.
    """

    assert not is_safe_local_redirect(
        "https://evil.example"
    )


def test_protocol_relative_redirect_rejected():
    """
    Protocol-relative external redirects must
    also be rejected.
    """

    assert not is_safe_local_redirect(
        "//evil.example"
    )


def test_non_absolute_redirect_rejected():
    """
    Redirect values must begin with /.
    """

    assert not is_safe_local_redirect(
        "evil.example"
    )


def test_empty_redirect_rejected():
    """
    Missing redirect values are invalid.
    """

    assert not is_safe_local_redirect(
        None
    )


def test_unknown_route_returns_controlled_404(
    client,
):
    """
    Unknown application resources should return
    a controlled error instead of a traceback.
    """

    response = client.get(
        "/this-route-does-not-exist"
    )

    assert response.status_code == 404

    assert (
        b"CyberRecon resource not found"
        in response.data
    )


def test_large_request_rejected(
    authenticated_client,
):
    """
    Excessively large request bodies should be
    rejected by Flask before normal processing.
    """

    huge_target = (
        "a" * (70 * 1024)
    )

    response = (
        authenticated_client.post(
            "/scan",
            data={
                "target":
                    huge_target
            },
        )
    )

    assert response.status_code == 413


def test_session_cookie_httponly(
    client,
    register_user,
    login_user,
):
    """
    Authentication cookies should not be directly
    accessible to browser JavaScript.
    """

    register_user(
        client
    )

    response = login_user(
        client
    )


    cookies = response.headers.getlist(
        "Set-Cookie"
    )


    assert cookies

    assert any(
        "HttpOnly" in cookie
        for cookie in cookies
    )


def test_session_cookie_samesite(
    client,
    register_user,
    login_user,
):
    """
    Session cookies should use SameSite=Lax.
    """

    register_user(
        client
    )

    response = login_user(
        client
    )


    cookies = response.headers.getlist(
        "Set-Cookie"
    )


    assert any(
        "SameSite=Lax"
        in cookie
        for cookie in cookies
    )