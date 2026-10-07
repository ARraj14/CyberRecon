import socket

import pytest

import cyberrecon.scanner.reconnaissance as reconnaissance
import cyberrecon.scanner.target as target_module

from cyberrecon.scanner.target import (
    UnsafeTargetError,
    private_targets_allowed,
    validate_network_destination,
)


def fake_dns_result(
    address,
):
    """
    Construct a socket.getaddrinfo-compatible result.
    """

    family = (
        socket.AF_INET6
        if ":" in address
        else socket.AF_INET
    )


    if family == socket.AF_INET6:

        sockaddr = (
            address,
            0,
            0,
            0,
        )

    else:

        sockaddr = (
            address,
            0,
        )


    return [
        (
            family,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            sockaddr,
        )
    ]


def set_dns_address(
    monkeypatch,
    address,
):

    monkeypatch.setattr(
        target_module.socket,
        "getaddrinfo",
        lambda *args, **kwargs:
            fake_dns_result(
                address
            ),
    )


def test_public_ipv4_allowed(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "93.184.216.34",
    )


    addresses = (
        validate_network_destination(
            "https://example.com",
            allow_private=False,
        )
    )


    assert addresses == [
        "93.184.216.34"
    ]


def test_loopback_ipv4_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "127.0.0.1",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://localhost:5001",
            allow_private=False,
        )


def test_private_10_network_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "10.0.0.10",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://internal.example",
            allow_private=False,
        )


def test_private_172_network_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "172.16.10.20",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://internal.example",
            allow_private=False,
        )


def test_private_192_network_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "192.168.1.10",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://internal.example",
            allow_private=False,
        )


def test_ipv6_loopback_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "::1",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://[::1]",
            allow_private=False,
        )


def test_link_local_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "169.254.169.254",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://metadata.example",
            allow_private=False,
        )


def test_unspecified_address_blocked(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "0.0.0.0",
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "http://invalid.example",
            allow_private=False,
        )


def test_mixed_public_private_dns_blocked(
    monkeypatch,
):
    """
    A hostname returning both public and private
    addresses must be rejected.
    """

    monkeypatch.setattr(
        target_module.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (
            fake_dns_result(
                "93.184.216.34"
            )
            +
            fake_dns_result(
                "127.0.0.1"
            )
        ),
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        validate_network_destination(
            "https://mixed.example",
            allow_private=False,
        )


def test_private_target_allowed_in_demo_mode(
    monkeypatch,
):

    set_dns_address(
        monkeypatch,
        "127.0.0.1",
    )


    addresses = (
        validate_network_destination(
            "http://127.0.0.1:5001",
            allow_private=True,
        )
    )


    assert addresses == [
        "127.0.0.1"
    ]


def test_private_environment_flag_disabled_by_default(
    monkeypatch,
):

    monkeypatch.delenv(
        "CYBERRECON_ALLOW_PRIVATE_TARGETS",
        raising=False,
    )


    assert (
        private_targets_allowed()
        is False
    )


def test_private_environment_flag_enables_demo_mode(
    monkeypatch,
):

    monkeypatch.setenv(
        "CYBERRECON_ALLOW_PRIVATE_TARGETS",
        "1",
    )


    assert (
        private_targets_allowed()
        is True
    )


def test_dns_failure_propagates(
    monkeypatch,
):

    def fail_dns(
        *args,
        **kwargs,
    ):

        raise socket.gaierror(
            "DNS failed"
        )


    monkeypatch.setattr(
        target_module.socket,
        "getaddrinfo",
        fail_dns,
    )


    with pytest.raises(
        socket.gaierror
    ):

        validate_network_destination(
            "https://does-not-exist.example",
            allow_private=False,
        )


class FakeRedirectResponse:

    status_code = 302

    headers = {
        "Location":
            "http://127.0.0.1/admin"
    }


class FakeFinalResponse:

    status_code = 200

    headers = {}


def test_redirect_to_private_destination_blocked_before_request(
    monkeypatch,
):
    """
    Critical SSRF regression test.

    CyberRecon receives a response from a public
    destination that attempts to redirect to localhost.

    The localhost destination must be rejected before
    a second HTTP request occurs.
    """

    requests_made = []


    class FakeSession:

        def __init__(self):

            self.headers = {}


        def get(
            self,
            url,
            **kwargs,
        ):

            requests_made.append(
                url
            )

            return FakeRedirectResponse()


    monkeypatch.setattr(
        reconnaissance.requests,
        "Session",
        FakeSession,
    )


    def fake_validation(
        url,
        allow_private=None,
    ):

        if "127.0.0.1" in url:

            raise UnsafeTargetError(
                "Private redirect blocked."
            )

        return [
            "93.184.216.34"
        ]


    monkeypatch.setattr(
        reconnaissance,
        "validate_network_destination",
        fake_validation,
    )


    with pytest.raises(
        UnsafeTargetError
    ):

        reconnaissance.perform_request(
            "https://public.example"
        )


    assert requests_made == [
        "https://public.example"
    ]


def test_public_redirect_can_be_followed(
    monkeypatch,
):
    """
    A safe public-to-public redirect should continue
    normally.
    """

    requests_made = []


    class PublicRedirectResponse:

        status_code = 302

        headers = {
            "Location":
                "https://second.example/final"
        }


    class FinalResponse:

        status_code = 200

        headers = {}


    class FakeSession:

        def __init__(self):

            self.headers = {}


        def get(
            self,
            url,
            **kwargs,
        ):

            requests_made.append(
                url
            )


            if len(
                requests_made
            ) == 1:

                return (
                    PublicRedirectResponse()
                )


            return FinalResponse()


    monkeypatch.setattr(
        reconnaissance.requests,
        "Session",
        FakeSession,
    )


    monkeypatch.setattr(
        reconnaissance,
        "validate_network_destination",
        lambda url, allow_private=None:
            [
                "93.184.216.34"
            ],
    )


    result = (
        reconnaissance.perform_request(
            "https://first.example"
        )
    )


    assert result[
        "redirect_count"
    ] == 1


    assert result[
        "final_url"
    ] == (
        "https://second.example/final"
    )


    assert requests_made == [
        "https://first.example",
        "https://second.example/final",
    ]