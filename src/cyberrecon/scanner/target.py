import ipaddress
import os
import re
import socket

from urllib.parse import (
    SplitResult,
    urlsplit,
    urlunsplit,
)


class UnsafeTargetError(ValueError):
    """
    Raised when a URL resolves to an address that
    CyberRecon is not permitted to request.
    """


def has_explicit_scheme(raw_target):
    """
    Determine whether the user explicitly supplied
    HTTP or HTTPS.
    """

    if not isinstance(
        raw_target,
        str,
    ):
        return False

    target = raw_target.strip().lower()

    return (
        target.startswith(
            "http://"
        )
        or target.startswith(
            "https://"
        )
    )


def is_valid_hostname(hostname):
    """
    Validate a hostname or IP address.

    localhost is syntactically valid because it is
    useful for CyberRecon's controlled development
    target.

    Whether CyberRecon is actually allowed to connect
    to localhost is handled separately by the SSRF
    protection policy.
    """

    if not hostname:
        return False

    hostname = hostname.strip()

    if not hostname:
        return False

    if any(
        character.isspace()
        for character in hostname
    ):
        return False


    # -----------------------------------------------------
    # IP ADDRESS
    # -----------------------------------------------------

    try:

        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:

        pass


    # -----------------------------------------------------
    # LOCALHOST
    # -----------------------------------------------------

    if hostname.lower() == "localhost":
        return True


    # -----------------------------------------------------
    # IDNA / DOMAIN NAME
    # -----------------------------------------------------

    try:

        ascii_hostname = (
            hostname
            .encode("idna")
            .decode("ascii")
        )

    except UnicodeError:

        return False


    if len(ascii_hostname) > 253:
        return False


    if ascii_hostname.endswith("."):

        ascii_hostname = (
            ascii_hostname[:-1]
        )


    if not ascii_hostname:
        return False


    labels = ascii_hostname.split(".")


    label_pattern = re.compile(
        r"^[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}"
        r"[A-Za-z0-9])?$"
    )


    for label in labels:

        if not label:
            return False

        if len(label) > 63:
            return False

        if not label_pattern.fullmatch(
            label
        ):
            return False


    return True


def normalize_target(raw_target):
    """
    Validate and normalize a user-supplied HTTP/HTTPS
    target.

    Behaviour:
    - trims surrounding whitespace
    - rejects internal whitespace
    - prefers HTTPS if no scheme is supplied
    - allows only HTTP/HTTPS
    - rejects credentials embedded in URLs
    - validates hostname/IP
    - validates ports
    - preserves path and query string
    - removes URL fragments
    """

    if not isinstance(
        raw_target,
        str,
    ):
        raise ValueError(
            "Target must be a string."
        )


    target = raw_target.strip()


    if not target:

        raise ValueError(
            "Enter a target domain or URL."
        )


    if any(
        character.isspace()
        for character in target
    ):

        raise ValueError(
            "Target must not contain whitespace."
        )


    if "://" not in target:

        target = (
            "https://"
            + target
        )


    parsed = urlsplit(
        target
    )


    scheme = parsed.scheme.lower()


    if scheme not in {
        "http",
        "https",
    }:

        raise ValueError(
            "Only HTTP and HTTPS targets "
            "are supported."
        )


    if (
        parsed.username is not None
        or parsed.password is not None
    ):

        raise ValueError(
            "URLs containing embedded "
            "credentials are not allowed."
        )


    hostname = parsed.hostname


    if not hostname:

        raise ValueError(
            "Target hostname is missing."
        )


    if not is_valid_hostname(
        hostname
    ):

        raise ValueError(
            "Target hostname or IP address "
            "is invalid."
        )


    # Accessing parsed.port performs urllib's
    # numeric/range validation.
    try:

        port = parsed.port

    except ValueError as error:

        raise ValueError(
            "Target contains an invalid port."
        ) from error


    # -----------------------------------------------------
    # NORMALIZE HOSTNAME
    # -----------------------------------------------------

    try:

        ip_object = ipaddress.ip_address(
            hostname
        )

        normalized_hostname = str(
            ip_object
        )


        if ip_object.version == 6:

            normalized_hostname = (
                f"[{normalized_hostname}]"
            )


    except ValueError:

        normalized_hostname = (
            hostname
            .encode("idna")
            .decode("ascii")
            .lower()
        )


    netloc = normalized_hostname


    if port is not None:

        netloc = (
            f"{netloc}:{port}"
        )


    normalized = SplitResult(
        scheme=scheme,
        netloc=netloc,
        path=parsed.path,
        query=parsed.query,
        fragment="",
    )


    return urlunsplit(
        normalized
    )


def private_targets_allowed():
    """
    Return True only when the operator has explicitly
    enabled private/local target access.

    This option exists for the controlled CyberRecon
    demonstration environment.

    It should remain disabled in normal deployments.
    """

    return (
        os.environ.get(
            "CYBERRECON_ALLOW_PRIVATE_TARGETS",
            "0",
        )
        == "1"
    )


def resolve_target_addresses(hostname):
    """
    Resolve all IPv4/IPv6 addresses currently returned
    for a hostname.

    socket.gaierror is intentionally allowed to propagate
    so the reconnaissance layer can report DNS failures
    separately from SSRF-policy failures.
    """

    results = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM,
    )


    addresses = []


    for result in results:

        sockaddr = result[4]

        if not sockaddr:
            continue


        address = sockaddr[0]


        if (
            address
            not in addresses
        ):

            addresses.append(
                address
            )


    if not addresses:

        raise socket.gaierror(
            "No addresses returned by DNS."
        )


    return addresses


def describe_blocked_address(
    ip_object,
):
    """
    Produce a human-readable reason for rejecting
    a non-public destination.
    """

    if ip_object.is_loopback:

        return "loopback"


    if ip_object.is_link_local:

        return "link-local"


    if ip_object.is_multicast:

        return "multicast"


    if ip_object.is_unspecified:

        return "unspecified"


    if ip_object.is_reserved:

        return "reserved"


    if ip_object.is_private:

        return "private"


    return "non-public"


def validate_network_destination(
    target_url,
    allow_private=None,
):
    """
    Resolve and validate a URL before CyberRecon makes
    a network request.

    In normal mode every resolved address must be a
    globally routable address.

    This blocks destinations such as:
    - 127.0.0.0/8
    - ::1
    - RFC1918 private networks
    - link-local addresses
    - multicast addresses
    - unspecified/reserved/non-global ranges

    All DNS answers are inspected. A hostname that
    resolves to both public and private addresses is
    rejected rather than selecting only the public one.
    """

    normalized_url = normalize_target(
        target_url
    )


    parsed = urlsplit(
        normalized_url
    )


    hostname = parsed.hostname


    if hostname is None:

        raise ValueError(
            "Target hostname is missing."
        )


    if allow_private is None:

        allow_private = (
            private_targets_allowed()
        )


    addresses = resolve_target_addresses(
        hostname
    )


    if allow_private:

        return addresses


    for address in addresses:

        try:

            ip_object = (
                ipaddress.ip_address(
                    address
                )
            )

        except ValueError as error:

            raise UnsafeTargetError(
                "Target resolved to an "
                "invalid IP address."
            ) from error


        if not ip_object.is_global:

            reason = (
                describe_blocked_address(
                    ip_object
                )
            )


            raise UnsafeTargetError(
                "CyberRecon blocked the target "
                "because it resolves to a "
                f"{reason} network address: "
                f"{address}"
            )


    return addresses