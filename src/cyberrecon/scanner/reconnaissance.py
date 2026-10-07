import time

from html.parser import HTMLParser
from urllib.parse import (
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests

from cyberrecon.scanner.target import (
    UnsafeTargetError,
    normalize_target,
    validate_network_destination,
)


REQUEST_TIMEOUT = (
    4,
    8,
)

MAX_REDIRECTS = 5

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308,
}


SELECTED_HEADERS = [
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


class PageTitleParser(
    HTMLParser
):
    """
    Small HTML parser used only to extract
    the first page title.
    """

    def __init__(self):

        super().__init__()

        self.in_title = False

        self.title_parts = []


    def handle_starttag(
        self,
        tag,
        attrs,
    ):

        if tag.lower() == "title":

            self.in_title = True


    def handle_endtag(
        self,
        tag,
    ):

        if tag.lower() == "title":

            self.in_title = False


    def handle_data(
        self,
        data,
    ):

        if self.in_title:

            self.title_parts.append(
                data
            )


    def get_title(self):

        title = " ".join(
            self.title_parts
        )

        title = " ".join(
            title.split()
        )

        return (
            title
            if title
            else "Not available"
        )


def extract_page_title(
    response,
):
    """
    Extract a page title only for HTML responses.

    Parsing is intentionally limited so a very large
    remote page is not unnecessarily processed.
    """

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
        .lower()
    )


    if "html" not in content_type:

        return "Not available"


    try:

        parser = PageTitleParser()

        parser.feed(
            response.text[
                :200000
            ]
        )

        return parser.get_title()


    except Exception:

        return "Not available"


def collect_selected_headers(
    response,
):
    """
    Return the HTTP response headers used by the
    CyberRecon passive security engine.
    """

    headers = {}


    for header_name in (
        SELECTED_HEADERS
    ):

        value = response.headers.get(
            header_name
        )


        headers[
            header_name
        ] = (
            value
            if value
            else "Not present"
        )


    return headers


def get_set_cookie_headers(
    response,
):
    """
    Retrieve Set-Cookie header lines while preserving
    separate cookies where the HTTP library allows it.
    """

    raw_headers = getattr(
        response.raw,
        "headers",
        None,
    )


    if raw_headers is not None:

        getlist = getattr(
            raw_headers,
            "getlist",
            None,
        )


        if callable(getlist):

            values = getlist(
                "Set-Cookie"
            )

            if values:

                return list(
                    values
                )


        get_all = getattr(
            raw_headers,
            "get_all",
            None,
        )


        if callable(get_all):

            values = get_all(
                "Set-Cookie"
            )

            if values:

                return list(
                    values
                )


    combined = response.headers.get(
        "Set-Cookie"
    )


    if combined:

        return [
            combined
        ]


    return []


def build_http_fallback_url(
    target_url,
):
    """
    Convert HTTPS to HTTP while preserving the rest
    of the URL.
    """

    parsed = urlsplit(
        target_url
    )


    return urlunsplit(
        (
            "http",
            parsed.netloc,
            parsed.path,
            parsed.query,
            "",
        )
    )


def perform_request(
    target_url,
):
    """
    Perform a request chain manually.

    Automatic redirects are intentionally disabled.

    Before every network request CyberRecon:
    1. resolves the destination
    2. applies the SSRF destination policy
    3. sends one request
    4. inspects any Location header
    5. validates the redirect destination before
       following it

    This prevents a public URL from simply redirecting
    CyberRecon to a blocked private/internal address.
    """

    session = requests.Session()


    session.headers.update(
        {
            "User-Agent":
                (
                    "CyberRecon/0.10 "
                    "Web Security Assessment Platform"
                )
        }
    )


    current_url = normalize_target(
        target_url
    )


    redirect_count = 0

    visited_urls = set()

    start_time = (
        time.perf_counter()
    )


    while True:

        # -------------------------------------------------
        # REDIRECT LOOP PROTECTION
        # -------------------------------------------------

        if current_url in visited_urls:

            raise requests.exceptions.TooManyRedirects(
                "Redirect loop detected."
            )


        visited_urls.add(
            current_url
        )


        # -------------------------------------------------
        # SSRF DESTINATION VALIDATION
        # -------------------------------------------------

        resolved_addresses = (
            validate_network_destination(
                current_url
            )
        )


        # -------------------------------------------------
        # SINGLE HTTP REQUEST
        # -------------------------------------------------

        response = session.get(
            current_url,

            timeout=REQUEST_TIMEOUT,

            allow_redirects=False,
        )


        # -------------------------------------------------
        # MANUAL REDIRECT PROCESSING
        # -------------------------------------------------

        if (
            response.status_code
            in REDIRECT_STATUS_CODES
            and response.headers.get(
                "Location"
            )
        ):

            if (
                redirect_count
                >= MAX_REDIRECTS
            ):

                raise (
                    requests
                    .exceptions
                    .TooManyRedirects(
                        "Maximum redirect "
                        "limit exceeded."
                    )
                )


            location = (
                response.headers[
                    "Location"
                ]
            )


            next_url = urljoin(
                current_url,
                location,
            )


            next_url = normalize_target(
                next_url
            )


            # Critical SSRF control:
            #
            # Validate the redirect destination before
            # any request is sent to it.
            validate_network_destination(
                next_url
            )


            redirect_count += 1

            current_url = next_url

            continue


        elapsed_ms = round(
            (
                time.perf_counter()
                - start_time
            )
            * 1000,
            2,
        )


        return {
            "response":
                response,

            "elapsed_ms":
                elapsed_ms,

            "redirect_count":
                redirect_count,

            "final_url":
                current_url,

            "resolved_addresses":
                resolved_addresses,
        }


def build_success_result(
    target_url,
    request_result,
    fallback_used,
):
    """
    Convert a successful request into the standard
    CyberRecon reconnaissance dictionary.
    """

    response = request_result[
        "response"
    ]


    final_url = request_result[
        "final_url"
    ]


    resolved_addresses = (
        request_result[
            "resolved_addresses"
        ]
    )


    parsed_final_url = urlsplit(
        final_url
    )


    selected_headers = (
        collect_selected_headers(
            response
        )
    )


    server = response.headers.get(
        "Server"
    )


    content_type = (
        response.headers.get(
            "Content-Type"
        )
    )


    return {
        "target":
            target_url,

        "domain":
            (
                parsed_final_url.hostname
                or "Unavailable"
            ),

        "ip_address":
            (
                resolved_addresses[0]
                if resolved_addresses
                else "Unavailable"
            ),

        "reachable":
            True,

        "status_code":
            response.status_code,

        "final_url":
            final_url,

        "https_enabled":
            (
                parsed_final_url.scheme
                .lower()
                == "https"
            ),

        "response_time":
            request_result[
                "elapsed_ms"
            ],

        "page_title":
            extract_page_title(
                response
            ),

        "server":
            (
                server
                if server
                else "Not disclosed"
            ),

        "content_type":
            (
                content_type
                if content_type
                else "Not disclosed"
            ),

        "redirect_count":
            request_result[
                "redirect_count"
            ],

        "headers":
            selected_headers,

        "set_cookies":
            get_set_cookie_headers(
                response
            ),

        "fallback_used":
            fallback_used,

        "error_type":
            None,

        "error_message":
            None,
    }


def build_failure_result(
    target_url,
    error_type,
    error_message,
    fallback_used=False,
):
    """
    Produce a consistent reconnaissance failure result.
    """

    try:

        parsed = urlsplit(
            target_url
        )

        domain = (
            parsed.hostname
            or "Unavailable"
        )

    except Exception:

        domain = "Unavailable"


    return {
        "target":
            target_url,

        "domain":
            domain,

        "ip_address":
            "Unavailable",

        "reachable":
            False,

        "status_code":
            "Unavailable",

        "final_url":
            target_url,

        "https_enabled":
            False,

        "response_time":
            "Unavailable",

        "page_title":
            "Unavailable",

        "server":
            "Unavailable",

        "content_type":
            "Unavailable",

        "redirect_count":
            0,

        "headers":
            {},

        "set_cookies":
            [],

        "fallback_used":
            fallback_used,

        "error_type":
            error_type,

        "error_message":
            error_message,
    }


def perform_reconnaissance(
    target_url,
    allow_http_fallback=False,
):
    """
    Run CyberRecon passive web reconnaissance.

    Scheme-less targets are normally normalized to HTTPS
    by the target module. The assessment controller may
    permit one HTTP fallback when the user did not
    explicitly specify a scheme.

    An explicitly supplied HTTPS URL is never silently
    downgraded to HTTP.
    """

    try:

        result = perform_request(
            target_url
        )


        return build_success_result(
            target_url,
            result,
            fallback_used=False,
        )


    # =====================================================
    # SSRF BLOCK
    # =====================================================

    except UnsafeTargetError as error:

        return build_failure_result(
            target_url,

            "Blocked Target",

            str(error),
        )


    # =====================================================
    # DNS FAILURE
    # =====================================================

    except OSError as error:

        # socket.gaierror derives from OSError.
        #
        # requests network errors are handled below,
        # therefore this primarily catches destination
        # resolution failures from the validation layer.

        if (
            error.__class__.__name__
            == "gaierror"
        ):

            return build_failure_result(
                target_url,

                "DNS Resolution Error",

                (
                    "CyberRecon could not resolve "
                    "the target hostname."
                ),
            )


        return build_failure_result(
            target_url,

            "Network Error",

            str(error),
        )


    # =====================================================
    # TLS / SSL FAILURE
    # =====================================================

    except requests.exceptions.SSLError as error:

        if allow_http_fallback:

            fallback_url = (
                build_http_fallback_url(
                    target_url
                )
            )


            try:

                result = perform_request(
                    fallback_url
                )


                return build_success_result(
                    fallback_url,
                    result,
                    fallback_used=True,
                )


            except UnsafeTargetError as fallback_error:

                return build_failure_result(
                    fallback_url,

                    "Blocked Target",

                    str(
                        fallback_error
                    ),

                    fallback_used=True,
                )


            except Exception as fallback_error:

                return build_failure_result(
                    fallback_url,

                    "Connection Error",

                    str(
                        fallback_error
                    ),

                    fallback_used=True,
                )


        return build_failure_result(
            target_url,

            "TLS/SSL Error",

            str(error),
        )


    # =====================================================
    # TIMEOUT
    # =====================================================

    except requests.exceptions.Timeout:

        return build_failure_result(
            target_url,

            "Timeout",

            (
                "The target did not respond "
                "within the configured timeout."
            ),
        )


    # =====================================================
    # TOO MANY REDIRECTS / REDIRECT LOOP
    # =====================================================

    except (
        requests
        .exceptions
        .TooManyRedirects
    ) as error:

        return build_failure_result(
            target_url,

            "Too Many Redirects",

            str(error),
        )


    # =====================================================
    # CONNECTION FAILURE
    # =====================================================

    except requests.exceptions.ConnectionError as error:

        if allow_http_fallback:

            fallback_url = (
                build_http_fallback_url(
                    target_url
                )
            )


            try:

                result = perform_request(
                    fallback_url
                )


                return build_success_result(
                    fallback_url,
                    result,
                    fallback_used=True,
                )


            except UnsafeTargetError as fallback_error:

                return build_failure_result(
                    fallback_url,

                    "Blocked Target",

                    str(
                        fallback_error
                    ),

                    fallback_used=True,
                )


            except Exception as fallback_error:

                return build_failure_result(
                    fallback_url,

                    "Connection Error",

                    str(
                        fallback_error
                    ),

                    fallback_used=True,
                )


        return build_failure_result(
            target_url,

            "Connection Error",

            str(error),
        )


    # =====================================================
    # INVALID REDIRECT / URL
    # =====================================================

    except ValueError as error:

        return build_failure_result(
            target_url,

            "Redirect Validation Error",

            str(error),
        )


    # =====================================================
    # GENERIC REQUEST FAILURE
    # =====================================================

    except requests.exceptions.RequestException as error:

        return build_failure_result(
            target_url,

            "Request Error",

            str(error),
        )


    except Exception as error:

        return build_failure_result(
            target_url,

            "Unexpected Reconnaissance Error",

            str(error),
        )