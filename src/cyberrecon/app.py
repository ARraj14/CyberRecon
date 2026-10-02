from flask import (
    Flask,
    render_template,
    request,
)

from cyberrecon.scanner.assessment import (
    run_assessment,
)

from cyberrecon.storage import (
    get_scan_history,
    initialize_database,
    save_assessment,
)


def create_app():
    app = Flask(__name__)

    initialize_database()

    @app.route("/")
    def home():
        return render_template(
            "index.html"
        )

    @app.route(
        "/scan",
        methods=["POST"],
    )
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
                assessment
            )

            return render_template(
                "results.html",
                **assessment,
            )

        except ValueError as error:
            return render_template(
                "index.html",
                error=str(error),
            )

    @app.route("/history")
    def history():
        scans = get_scan_history()

        return render_template(
            "history.html",
            scans=scans,
        )

    return app