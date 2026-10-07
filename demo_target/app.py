import os

from flask import (
    Flask,
    make_response,
)


app = Flask(__name__)


def get_profile():
    """
    Return the active CyberRecon demo profile.

    Supported profiles:
    - missing
    - weak
    - hardened
    """

    profile = os.environ.get(
        "CYBERRECON_DEMO_PROFILE",
        "missing",
    )

    profile = profile.strip().lower()

    if profile not in {
        "missing",
        "weak",
        "hardened",
    }:
        return "missing"

    return profile


def build_page(profile):
    """
    Build the demonstration HTML page.
    """

    descriptions = {
        "missing": (
            "Most browser-security headers are "
            "intentionally absent."
        ),

        "weak": (
            "Several security controls are present "
            "but deliberately configured weakly."
        ),

        "hardened": (
            "Security headers and cookie attributes "
            "are configured with stronger values."
        ),
    }

    return f"""
    <!DOCTYPE html>

    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>
            CyberRecon Controlled Demo Target
        </title>

        <style>

            body {{
                margin: 0;

                min-height: 100vh;

                display: flex;

                align-items: center;

                justify-content: center;

                background: #07111c;

                color: #d8e2ec;

                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;
            }}


            .card {{
                width: min(
                    700px,
                    90%
                );

                padding: 40px;

                border:
                    1px solid #1c4050;

                border-radius: 12px;

                background: #0c1927;
            }}


            h1 {{
                margin-top: 0;
            }}


            .profile {{
                display: inline-block;

                margin-top: 10px;

                padding:
                    8px
                    12px;

                border-radius: 6px;

                background: #14293a;

                color: #4bdca9;

                font-family: monospace;

                text-transform: uppercase;
            }}


            p {{
                color: #91a4b8;

                line-height: 1.7;
            }}


            code {{
                color: #4bdca9;
            }}

        </style>

    </head>


    <body>


        <main class="card">

            <h1>
                CyberRecon Controlled Demo Target
            </h1>


            <div class="profile">
                {profile}
            </div>


            <p>
                {descriptions[profile]}
            </p>


            <p>

                This application exists only as a
                controlled local target for testing
                CyberRecon's passive security-analysis
                rules.

            </p>


            <p>

                Active profile:

                <code>
                    {profile}
                </code>

            </p>

        </main>


    </body>

    </html>
    """


@app.route("/")
def home():
    """
    Serve a controlled response with different
    security configurations depending on the
    selected demonstration profile.
    """

    profile = get_profile()

    response = make_response(
        build_page(profile)
    )


    # =====================================================
    # PROFILE 1: MISSING CONTROLS
    # =====================================================

    if profile == "missing":

        # Wildcard CORS is intentionally enabled.
        response.headers[
            "Access-Control-Allow-Origin"
        ] = "*"


        # Demonstration cookie intentionally lacks:
        #
        # Secure
        # HttpOnly
        # SameSite
        #
        # This lets CyberRecon identify cookie
        # configuration observations.

        response.set_cookie(
            "demo_session",
            "controlled-demo-value",
        )


    # =====================================================
    # PROFILE 2: WEAK CONTROLS
    # =====================================================

    elif profile == "weak":

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "script-src "
            "'self' "
            "'unsafe-inline' "
            "'unsafe-eval'"
        )


        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"


        response.headers[
            "X-Frame-Options"
        ] = "SAMEORIGIN"


        response.headers[
            "Referrer-Policy"
        ] = "unsafe-url"


        response.headers[
            "Access-Control-Allow-Origin"
        ] = "*"


        response.set_cookie(
            "demo_session",
            "controlled-demo-value",
        )


    # =====================================================
    # PROFILE 3: HARDENED CONTROLS
    # =====================================================

    elif profile == "hardened":

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )


        response.headers[
            "X-Frame-Options"
        ] = "DENY"


        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"


        response.headers[
            "Referrer-Policy"
        ] = (
            "strict-origin-when-cross-origin"
        )


        response.headers[
            "Permissions-Policy"
        ] = (
            "geolocation=(), "
            "camera=(), "
            "microphone=()"
        )


        response.headers[
            "Cross-Origin-Opener-Policy"
        ] = "same-origin"


        response.headers[
            "Cross-Origin-Resource-Policy"
        ] = "same-origin"


        response.headers[
            "Cross-Origin-Embedder-Policy"
        ] = "require-corp"


        response.set_cookie(
            "demo_session",
            "controlled-demo-value",

            secure=True,

            httponly=True,

            samesite="Lax",
        )


    return response


@app.route("/health")
def health():
    """
    Simple local health check.
    """

    return {
        "application":
            "CyberRecon Controlled Demo Target",

        "profile":
            get_profile(),

        "status":
            "online",
    }


if __name__ == "__main__":

    profile = get_profile()

    print()
    print(
        "CyberRecon Controlled Demo Target"
    )

    print(
        f"Security profile: {profile}"
    )

    print(
        "Listening on: "
        "http://127.0.0.1:5001"
    )

    print()

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
    )