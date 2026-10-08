import hmac
import os
import re
import secrets
import sqlite3

from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from cyberrecon.scanner.assessment import run_assessment
from cyberrecon.scanner.comparison import compare_assessments

from cyberrecon.storage import (
    create_user,
    get_completed_scans,
    get_dashboard_analytics,
    get_scan_by_id,
    get_scan_history,
    get_user_by_email,
    get_user_by_username,
    initialize_database,
    save_assessment,
)


# =========================================================
# APPLICATION SECURITY HELPERS
# =========================================================


def get_secret_key():
    """
    Return a stable Flask session secret.

    Production:
        CYBERRECON_SECRET_KEY=<strong random secret>

    Development:
        data/.session_secret
    """

    environment_key = os.environ.get(
        "CYBERRECON_SECRET_KEY"
    )

    if environment_key:
        return environment_key

    project_root = (
        Path(__file__).resolve().parents[2]
    )

    secret_file = (
        project_root
        / "data"
        / ".session_secret"
    )

    secret_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if secret_file.exists():
        stored_key = secret_file.read_text(
            encoding="utf-8"
        ).strip()

        if stored_key:
            try:
                secret_file.chmod(0o600)
            except OSError:
                pass

            return stored_key

    secret_key = secrets.token_hex(32)

    secret_file.write_text(
        secret_key,
        encoding="utf-8",
    )

    try:
        secret_file.chmod(0o600)
    except OSError:
        pass

    return secret_key


def login_required(view_function):
    """
    Require an authenticated CyberRecon session.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if session.get("user_id") is None:
            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


def is_safe_local_redirect(target):
    """
    Permit only local application redirects.
    """

    if not target:
        return False

    parsed = urlsplit(target)

    if parsed.scheme:
        return False

    if parsed.netloc:
        return False

    if not target.startswith("/"):
        return False

    if target.startswith("//"):
        return False

    return True


# =========================================================
# CSRF PROTECTION
# =========================================================


def generate_csrf_token():
    """
    Return the CSRF token stored in the current session.

    A cryptographically random token is generated if
    the session does not already contain one.
    """

    token = session.get("_csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


def validate_csrf_token(submitted_token):
    """
    Compare the submitted CSRF token with the token
    stored in the user's session.
    """

    stored_token = session.get(
        "_csrf_token"
    )

    if not stored_token:
        return False

    if not submitted_token:
        return False

    if not isinstance(
        submitted_token,
        str,
    ):
        return False

    try:
        return hmac.compare_digest(
            stored_token,
            submitted_token,
        )

    except TypeError:
        return False


# =========================================================
# APPLICATION FACTORY
# =========================================================


def create_app(test_config=None):

    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=get_secret_key(),

        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",

        SESSION_COOKIE_SECURE=(
            os.environ.get(
                "CYBERRECON_SECURE_COOKIES",
                "0",
            )
            == "1"
        ),

        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=8
        ),

        MAX_CONTENT_LENGTH=64 * 1024,

        # Enabled by default in the real application.
        CSRF_PROTECTION_ENABLED=True,
    )

    if test_config:
        app.config.update(
            test_config
        )

    initialize_database()


    # =====================================================
    # CSRF VALIDATION
    # =====================================================

    @app.before_request
    def protect_post_requests():
        """
        Validate all POST requests.

        This automatically protects present and future
        CyberRecon POST routes unless explicitly disabled
        in the test configuration.
        """

        if not app.config.get(
            "CSRF_PROTECTION_ENABLED",
            True,
        ):
            return None

        if request.method != "POST":
            return None

        submitted_token = (
            request.form.get(
                "csrf_token"
            )
            or request.headers.get(
                "X-CSRF-Token"
            )
        )

        if not validate_csrf_token(
            submitted_token
        ):
            return (
                "Invalid or missing CSRF token.",
                400,
            )

        return None


    # =====================================================
    # SECURITY RESPONSE HEADERS
    # =====================================================

    @app.after_request
    def apply_security_headers(response):

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Referrer-Policy"
        ] = (
            "strict-origin-when-cross-origin"
        )

        response.headers[
            "Permissions-Policy"
        ] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'"
        )

        if request.endpoint != "static":

            response.headers[
                "Cache-Control"
            ] = (
                "no-store, "
                "no-cache, "
                "must-revalidate, "
                "max-age=0"
            )

            response.headers[
                "Pragma"
            ] = "no-cache"

        if (
            request.is_secure
            and os.environ.get(
                "CYBERRECON_ENABLE_HSTS",
                "0",
            )
            == "1"
        ):

            response.headers[
                "Strict-Transport-Security"
            ] = (
                "max-age=31536000; "
                "includeSubDomains"
            )

        return response


    # =====================================================
    # ERROR HANDLERS
    # =====================================================

    @app.errorhandler(404)
    def not_found(error):

        return (
            "CyberRecon resource not found.",
            404,
        )


    @app.errorhandler(413)
    def request_too_large(error):

        return (
            "Request exceeds CyberRecon's "
            "allowed size limit.",
            413,
        )


    @app.errorhandler(500)
    def internal_error(error):

        return (
            "CyberRecon encountered an "
            "internal application error.",
            500,
        )


    # =====================================================
    # TEMPLATE CONTEXT
    # =====================================================

    @app.context_processor
    def inject_global_template_values():

        return {
            "current_user_id":
                session.get("user_id"),

            "current_username":
                session.get("username"),

            "csrf_token":
                generate_csrf_token(),
        }


    # =====================================================
    # HOME
    # =====================================================

    @app.route("/")
    def home():

        return render_template(
            "index.html"
        )


    # =====================================================
    # REGISTER
    # =====================================================

    @app.route(
        "/register",
        methods=[
            "GET",
            "POST",
        ],
    )
    def register():

        if session.get("user_id"):
            return redirect(
                url_for("dashboard")
            )

        error = None
        success = None

        if request.method == "POST":

            username = (
                request.form.get(
                    "username",
                    "",
                ).strip()
            )

            email = (
                request.form.get(
                    "email",
                    "",
                )
                .strip()
                .lower()
            )

            password = request.form.get(
                "password",
                "",
            )

            confirm_password = (
                request.form.get(
                    "confirm_password",
                    "",
                )
            )

            if not username:

                error = (
                    "Username is required."
                )

            elif not re.fullmatch(
                r"[A-Za-z0-9_-]{3,30}",
                username,
            ):

                error = (
                    "Username must be 3–30 "
                    "characters and contain only "
                    "letters, numbers, underscores "
                    "or hyphens."
                )

            elif not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                email,
            ):

                error = (
                    "Enter a valid email address."
                )

            elif len(password) < 8:

                error = (
                    "Password must contain at "
                    "least 8 characters."
                )

            elif (
                password
                != confirm_password
            ):

                error = (
                    "Passwords do not match."
                )

            elif get_user_by_username(
                username
            ):

                error = (
                    "That username is already "
                    "registered."
                )

            elif get_user_by_email(
                email
            ):

                error = (
                    "That email address is "
                    "already registered."
                )

            else:

                password_hash = (
                    generate_password_hash(
                        password
                    )
                )

                try:

                    create_user(
                        username,
                        email,
                        password_hash,
                    )

                    success = (
                        "Account created successfully. "
                        "You can now log in."
                    )

                except sqlite3.IntegrityError:

                    error = (
                        "That username or email "
                        "is already registered."
                    )

        return render_template(
            "register.html",
            error=error,
            success=success,
        )


    # =====================================================
    # LOGIN
    # =====================================================

    @app.route(
        "/login",
        methods=[
            "GET",
            "POST",
        ],
    )
    def login():

        if session.get("user_id"):

            return redirect(
                url_for("dashboard")
            )

        error = None

        if request.method == "POST":

            email = (
                request.form.get(
                    "email",
                    "",
                )
                .strip()
                .lower()
            )

            password = request.form.get(
                "password",
                "",
            )

            user = get_user_by_email(
                email
            )

            if (
                user is None
                or not check_password_hash(
                    user["password_hash"],
                    password,
                )
            ):

                error = (
                    "Invalid email address "
                    "or password."
                )

            else:

                next_url = (
                    request.form.get(
                        "next"
                    )
                    or request.args.get(
                        "next"
                    )
                )

                # Clearing the session also invalidates
                # the pre-login CSRF token.
                session.clear()

                session.permanent = True

                session["user_id"] = (
                    user["id"]
                )

                session["username"] = (
                    user["username"]
                )

                # Generate a fresh authenticated-session
                # CSRF token.
                generate_csrf_token()

                if is_safe_local_redirect(
                    next_url
                ):

                    return redirect(
                        next_url
                    )

                return redirect(
                    url_for(
                        "dashboard"
                    )
                )

        return render_template(
            "login.html",
            error=error,
        )


    # =====================================================
    # LOGOUT
    # =====================================================

    @app.route(
        "/logout",
        methods=[
            "GET",
            "POST",
        ],
    )
    @login_required
    def logout():

        # GET only renders the confirmation page.
        # Session state is changed only by POST.
        # Global POST CSRF middleware validates the
        # token before this route executes.

        if request.method == "GET":

            return render_template(
                "logout.html"
            )

        session.clear()

        return redirect(
            url_for("home")
        )


    # =====================================================
    # RUN ASSESSMENT
    # =====================================================

    @app.route(
        "/scan",
        methods=["POST"],
    )
    @login_required
    def scan():

        target = request.form.get(
            "target",
            "",
        )

        try:

            assessment = run_assessment(
                target
            )

            save_assessment(
                assessment,
                session["user_id"],
            )

            return render_template(
                "results.html",
                **assessment,
            )

        except ValueError as error:

            return render_template(
                "index.html",
                error=str(error),
                target=target,
            )


    # =====================================================
    # DASHBOARD
    # =====================================================

    @app.route("/dashboard")
    @login_required
    def dashboard():

        analytics = (
            get_dashboard_analytics(
                session["user_id"]
            )
        )

        return render_template(
            "dashboard.html",
            analytics=analytics,
        )


    # =====================================================
    # HISTORY
    # =====================================================

    @app.route("/history")
    @login_required
    def history():

        scans = get_scan_history(
            session["user_id"]
        )

        return render_template(
            "history.html",
            scans=scans,
        )


    # =====================================================
    # ARCHIVED SCAN
    # =====================================================

    @app.route(
        "/history/<scan_id>"
    )
    @login_required
    def scan_detail(scan_id):

        stored_assessment = (
            get_scan_by_id(
                scan_id,
                session["user_id"],
            )
        )

        if stored_assessment is None:

            return (
                "Stored assessment not found.",
                404,
            )

        return render_template(
            "scan_detail.html",

            scan=stored_assessment[
                "scan"
            ],

            findings=stored_assessment[
                "findings"
            ],
        )


    # =====================================================
    # REPORT
    # =====================================================

    @app.route(
        "/history/<scan_id>/report"
    )
    @login_required
    def assessment_report(scan_id):

        stored_assessment = (
            get_scan_by_id(
                scan_id,
                session["user_id"],
            )
        )

        if stored_assessment is None:

            return (
                "Stored assessment not found.",
                404,
            )

        scan_data = (
            stored_assessment[
                "scan"
            ]
        )

        findings = (
            stored_assessment[
                "findings"
            ]
        )

        severity_summary = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
            "Total": len(findings),
        }

        for finding in findings:

            severity = finding.get(
                "severity"
            )

            if severity in severity_summary:

                severity_summary[
                    severity
                ] += 1

        rendered_report = (
            render_template(
                "report.html",

                scan=scan_data,

                findings=findings,

                severity_summary=(
                    severity_summary
                ),
            )
        )

        response = make_response(
            rendered_report
        )

        filename = (
            f"CyberRecon_"
            f"{scan_id}_Report.html"
        )

        response.headers[
            "Content-Disposition"
        ] = (
            f'attachment; '
            f'filename="{filename}"'
        )

        response.headers[
            "Content-Type"
        ] = (
            "text/html; charset=utf-8"
        )

        return response


    # =====================================================
    # HISTORICAL COMPARISON
    # =====================================================

    @app.route("/compare")
    @login_required
    def compare_scans():

        user_id = session[
            "user_id"
        ]

        scans = get_completed_scans(
            user_id
        )

        baseline_id = request.args.get(
            "baseline"
        )

        current_id = request.args.get(
            "current"
        )

        comparison = None
        comparison_error = None

        if (
            baseline_id
            and current_id
        ):

            baseline_assessment = (
                get_scan_by_id(
                    baseline_id,
                    user_id,
                )
            )

            current_assessment = (
                get_scan_by_id(
                    current_id,
                    user_id,
                )
            )

            if (
                baseline_assessment
                is None
                or current_assessment
                is None
            ):

                comparison_error = (
                    "One or both stored "
                    "assessments could not "
                    "be found."
                )

            elif (
                baseline_id
                == current_id
            ):

                comparison_error = (
                    "Please select two "
                    "different assessments."
                )

            else:

                try:

                    comparison = (
                        compare_assessments(
                            baseline_assessment,
                            current_assessment,
                        )
                    )

                except ValueError as error:

                    comparison_error = str(
                        error
                    )

        return render_template(
            "compare.html",

            scans=scans,

            comparison=comparison,

            comparison_error=(
                comparison_error
            ),

            selected_baseline=(
                baseline_id
            ),

            selected_current=(
                current_id
            ),
        )


    return app