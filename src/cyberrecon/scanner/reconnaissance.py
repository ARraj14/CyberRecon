import socket
import time
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests


class TitleParser(HTMLParser):
    """
    Extract the HTML page title.
    """

    def __init__(self):
        super().__init__()

        self.inside_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):

        if tag.lower() == "title":
            self.inside_title = True

    def handle_endtag(self, tag):

        if tag.lower() == "title":
            self.inside_title = False

    def handle_data(self, data):

        if self.inside_title:
            self.title += data


def get_page_title(html):
    """
    Extract a page title from HTML content.
    """

    parser = TitleParser()

    try:

        # Limit the amount of HTML processed.
        parser.feed(html[:200000])

        title = parser.title.strip()

        return title if title else "Not detected"

    except Exception:
        return "Not detected"


def resolve_ip(hostname):
    """
    Resolve a hostname to an IP address.
    """

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        # Prefer IPv4 for display when available.
        for address in addresses:

            if address[0] == socket.AF_INET:
                return address[4][0]

        if addresses:
            return addresses[0][4][0]

    except socket.gaierror:
        pass

    return None


def failure_result(
    target,
    hostname,
    ip_address,
    error_type,
    message,
):
    """
    Return a consistent reconnaissance failure result.
    """

    return {
        "target": target,
        "domain": hostname,

        "ip_address": (
            ip_address
            if ip_address
            else "Unable to resolve"
        ),

        "reachable": False,
        "status_code": "Unavailable",
        "final_url": target,

        "https_enabled": (
            urlparse(target).scheme == "https"
        ),

        "response_time": "Unavailable",
        "page_title": "Unavailable",
        "server": "Unavailable",
        "content_type": "Unavailable",

        "redirect_count": 0,

        "headers": {},

        # Used later for cookie-security checks.
        "set_cookies": [],

        "fallback_used": False,

        "error_type": error_type,
        "error_message": message,

        # Kept for compatibility with existing templates.
        "error": message,
    }


def perform_request(target):
    """
    Send an HTTP request using a controlled
    requests session.
    """

    session = requests.Session()

    # Prevent excessive redirect loops.
    session.max_redirects = 5

    headers = {
        "User-Agent": (
            "CyberRecon/0.8 "
            "Web Security Assessment Platform"
        )
    }

    return session.get(
        target,
        headers=headers,
        timeout=(4, 8),
        allow_redirects=True,
    )


def get_set_cookie_headers(response):
    """
    Return individual Set-Cookie headers when
    available.

    Keeping cookies separately is important because
    multiple Set-Cookie headers may exist in one
    response.
    """

    try:

        raw_headers = response.raw.headers

        if hasattr(raw_headers, "getlist"):

            cookies = raw_headers.getlist(
                "Set-Cookie"
            )

            if cookies:
                return cookies

        if hasattr(raw_headers, "get_all"):

            cookies = raw_headers.get_all(
                "Set-Cookie"
            )

            if cookies:
                return cookies

    except Exception:
        pass


    cookie_header = response.headers.get(
        "Set-Cookie"
    )

    if cookie_header:
        return [cookie_header]

    return []


def collect_selected_headers(response):
    """
    Collect response headers used by CyberRecon's
    passive security-analysis rules.
    """

    selected_header_names = [
        "Server",
        "Content-Type",
        "X-Powered-By",

        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",

        "Strict-Transport-Security",

        "X-Frame-Options",
        "X-Content-Type-Options",

        "Referrer-Policy",
        "Permissions-Policy",

        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",

        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",

        "Cache-Control",
        "Pragma",

        "Set-Cookie",
    ]


    selected_headers = {}


    for header_name in selected_header_names:

        selected_headers[
            header_name
        ] = response.headers.get(
            header_name,
            "Not present",
        )


    return selected_headers


def run_reconnaissance(
    target,
    allow_http_fallback=False,
):
    """
    Perform passive reconnaissance against an
    authorized web target.
    """

    parsed_target = urlparse(target)

    hostname = parsed_target.hostname

    ip_address = resolve_ip(hostname)


    # Stop early when DNS resolution fails.
    if not ip_address:

        return failure_result(
            target,
            hostname,
            None,
            "DNS Resolution Failed",
            (
                "CyberRecon could not resolve "
                "the target hostname."
            ),
        )


    fallback_used = False

    request_target = target

    start_time = time.perf_counter()


    try:

        try:

            response = perform_request(
                request_target
            )

        except (
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
        ) as first_error:

            # When the user entered only a hostname,
            # CyberRecon initially tries HTTPS.
            #
            # HTTP fallback is allowed only when the
            # original input did not explicitly request
            # HTTPS.

            if (
                allow_http_fallback
                and request_target.startswith(
                    "https://"
                )
            ):

                request_target = (
                    "http://"
                    + request_target[
                        len("https://"):
                    ]
                )

                response = perform_request(
                    request_target
                )

                fallback_used = True

            else:
                raise first_error


        end_time = time.perf_counter()


        response_time = round(
            (
                end_time
                - start_time
            )
            * 1000,
            2,
        )


        final_url = response.url


        final_scheme = urlparse(
            final_url
        ).scheme.lower()


        response_text = response.text


        selected_headers = (
            collect_selected_headers(
                response
            )
        )


        set_cookies = (
            get_set_cookie_headers(
                response
            )
        )


        return {
            "target": target,

            "domain": hostname,

            "ip_address": ip_address,

            "reachable": True,

            "status_code":
                response.status_code,

            "final_url":
                final_url,

            "https_enabled": (
                final_scheme == "https"
            ),

            "response_time":
                response_time,

            "page_title":
                get_page_title(
                    response_text
                ),

            "server":
                response.headers.get(
                    "Server",
                    "Not disclosed",
                ),

            "content_type":
                response.headers.get(
                    "Content-Type",
                    "Not disclosed",
                ),

            "redirect_count":
                len(
                    response.history
                ),

            "fallback_used":
                fallback_used,

            "error_type":
                None,

            "error_message":
                None,

            "headers":
                selected_headers,

            # Kept separately so later security rules
            # can safely inspect individual cookies.
            "set_cookies":
                set_cookies,
        }


    except requests.exceptions.Timeout:

        return failure_result(
            target,
            hostname,
            ip_address,
            "Connection Timeout",
            (
                "The target did not respond within "
                "the configured timeout period."
            ),
        )


    except requests.exceptions.SSLError:

        return failure_result(
            target,
            hostname,
            ip_address,
            "TLS/SSL Error",
            (
                "CyberRecon could not establish "
                "a valid TLS/SSL connection."
            ),
        )


    except requests.exceptions.TooManyRedirects:

        return failure_result(
            target,
            hostname,
            ip_address,
            "Too Many Redirects",
            (
                "The target exceeded CyberRecon's "
                "redirect limit."
            ),
        )


    except requests.exceptions.ConnectionError:

        return failure_result(
            target,
            hostname,
            ip_address,
            "Connection Failed",
            (
                "CyberRecon could not establish "
                "a connection to the target."
            ),
        )


    except requests.exceptions.RequestException:

        return failure_result(
            target,
            hostname,
            ip_address,
            "HTTP Request Failed",
            (
                "An error occurred while requesting "
                "the target."
            ),
        )