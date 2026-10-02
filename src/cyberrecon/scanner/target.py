from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse


def is_valid_hostname(hostname):
    """
    Validate a hostname, IPv4 address, IPv6 address,
    or localhost target.
    """

    if not hostname:
        return False

    if hostname.lower() == "localhost":
        return True

    # Check whether the hostname is an IP address.
    try:
        ip_address(hostname)
        return True
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    ascii_hostname = ascii_hostname.rstrip(".")

    if len(ascii_hostname) > 253:
        return False

    labels = ascii_hostname.split(".")

    if len(labels) < 2:
        return False

    for label in labels:

        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not all(
            character.isalnum() or character == "-"
            for character in label
        ):
            return False

    return True


def normalize_target(target):
    """
    Validate and normalize a user-supplied web target.
    """

    if not target:
        raise ValueError("Target cannot be empty.")

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if any(character.isspace() for character in target):
        raise ValueError(
            "The target must not contain spaces."
        )

    # HTTPS is preferred when no scheme is supplied.
    if not target.lower().startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    parsed_target = urlparse(target)

    if parsed_target.scheme.lower() not in (
        "http",
        "https",
    ):
        raise ValueError(
            "Only HTTP and HTTPS targets are supported."
        )

    if not parsed_target.hostname:
        raise ValueError(
            "Please enter a valid URL or hostname."
        )

    if (
        parsed_target.username is not None
        or parsed_target.password is not None
    ):
        raise ValueError(
            "Credentials inside target URLs are not supported."
        )

    # Accessing parsed_target.port raises ValueError
    # when an invalid port is supplied.
    try:
        parsed_target.port
    except ValueError:
        raise ValueError(
            "The target contains an invalid port number."
        )

    if not is_valid_hostname(
        parsed_target.hostname
    ):
        raise ValueError(
            "Please enter a valid hostname or IP address."
        )

    normalized_target = urlunparse(
        (
            parsed_target.scheme.lower(),
            parsed_target.netloc,
            parsed_target.path,
            "",
            parsed_target.query,
            "",
        )
    )

    return normalized_target