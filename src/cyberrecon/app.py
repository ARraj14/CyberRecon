import os
import re
import secrets

from functools import wraps
from pathlib import Path

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

from cyberrecon.scanner.assessment import (
    run_assessment,
)

from cyberrecon.scanner.comparison import (
    compare_assessments,
)

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

def get_secret_key():
    """
    Return a stable secret key for Flask sessions.

    Production can supply CYBERRECON_SECRET_KEY.
    During local development, CyberRecon creates
    a persistent random key inside the data folder.
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
        return secret_file.read_text(
            encoding="utf-8"
        ).strip()

    secret_key = secrets.token_hex(32)

    secret_file.write_text(
        secret_key,
        encoding="utf-8",
    )

    return secret_key

def login_required(view_function):

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

def create_app():

    app = Flask(__name__)
    
    app.config["SECRET_KEY"] = get_secret_key()

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    initialize_database()
    
    @app.context_processor
    def inject_current_user():

        return {
            "current_user_id":
                session.get("user_id"),

            "current_username":
                session.get("username"),
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

        analytics = get_dashboard_analytics(
            session["user_id"]
        )
        
        return render_template(
            "dashboard.html",
            analytics=analytics,
        )


    # =====================================================
    # SCAN HISTORY
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
    # STORED SCAN DETAILS
    # =====================================================

    @app.route(
        "/history/<scan_id>"
    )
    @login_required
    def scan_detail(scan_id):

        stored_assessment = get_scan_by_id(
            scan_id,
            session["user_id"],
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
    # DOWNLOADABLE HTML REPORT
    # =====================================================

    @app.route(
        "/history/<scan_id>/report"
    )
    @login_required
    def assessment_report(scan_id):

        stored_assessment = get_scan_by_id(
            scan_id,
            session["user_id"],
        )

        if stored_assessment is None:

            return (
                "Stored assessment not found.",
                404,
            )


        scan = stored_assessment[
            "scan"
        ]

        findings = stored_assessment[
            "findings"
        ]


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

            if (
                severity
                in severity_summary
            ):

                severity_summary[
                    severity
                ] += 1


        rendered_report = (
            render_template(
                "report.html",

                scan=scan,

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
            "text/html; "
            "charset=utf-8"
        )


        return response


    # =====================================================
    # HISTORICAL COMPARISON
    # =====================================================

    @app.route("/compare")
    @login_required
    def compare_scans():

        scans = get_completed_scans(
            session["user_id"]
        )

        baseline_assessment = get_scan_by_id(
            baseline_id,
            session["user_id"],
        )

        current_assessment = get_scan_by_id(
            current_id,
            session["user_id"],
        )


        comparison = None

        comparison_error = None


        if (
            baseline_id
            and current_id
        ):

            baseline_assessment = (
                get_scan_by_id(
                    baseline_id
                )
            )

            current_assessment = (
                get_scan_by_id(
                    current_id
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
                    "assessments could "
                    "not be found."
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


    # =====================================================
    # USER REGISTRATION
    # =====================================================

    @app.route(
        "/register",
        methods=[
            "GET",
            "POST",
        ],
    )
    def register():

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


            password = (
                request.form.get(
                    "password",
                    "",
                )
            )


            confirm_password = (
                request.form.get(
                    "confirm_password",
                    "",
                )
            )


            # ---------------------------------------------
            # USERNAME VALIDATION
            # ---------------------------------------------

            if not username:

                error = (
                    "Username is required."
                )


            elif not re.fullmatch(
                r"[A-Za-z0-9_-]{3,30}",
                username,
            ):

                error = (
                    "Username must be "
                    "3–30 characters and "
                    "contain only letters, "
                    "numbers, underscores "
                    "or hyphens."
                )


            # ---------------------------------------------
            # EMAIL VALIDATION
            # ---------------------------------------------

            elif not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                email,
            ):

                error = (
                    "Enter a valid "
                    "email address."
                )


            # ---------------------------------------------
            # PASSWORD VALIDATION
            # ---------------------------------------------

            elif len(password) < 8:

                error = (
                    "Password must contain "
                    "at least 8 characters."
                )


            elif (
                password
                != confirm_password
            ):

                error = (
                    "Passwords do not match."
                )


            # ---------------------------------------------
            # DUPLICATE USER CHECK
            # ---------------------------------------------

            elif get_user_by_username(
                username
            ):

                error = (
                    "That username is "
                    "already registered."
                )


            elif get_user_by_email(
                email
            ):

                error = (
                    "That email address is "
                    "already registered."
                )


            # ---------------------------------------------
            # CREATE USER
            # ---------------------------------------------

            else:

                password_hash = (
                    generate_password_hash(
                        password
                    )
                )


                create_user(
                    username,
                    email,
                    password_hash,
                )


                success = (
                    "Account created "
                    "successfully. "
                    "You can now log in."
                )


        return render_template(
            "register.html",

            error=error,

            success=success,
        )
        
    @app.route(
    "/login",
    methods=["GET", "POST"],
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

                session.clear()

                session["user_id"] = (
                    user["id"]
                )

                session["username"] = (
                    user["username"]
                )

                next_url = (
                    request.form.get("next")
                    or request.args.get("next")
                )

                if (
                    next_url
                    and next_url.startswith("/")
                    and not next_url.startswith("//")
                ):
                    return redirect(next_url)

                return redirect(
                    url_for("dashboard")
                )

        return render_template(
            "login.html",
            error=error,
        )


    @app.route("/logout")
    def logout():

        session.clear()

        return redirect(
            url_for("home")
        )


    return app