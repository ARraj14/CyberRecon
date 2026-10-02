from flask import Flask, render_template, request

from cyberrecon.scanner.assessment import (
    run_assessment,
)


def create_app():
    app = Flask(__name__)

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

            return render_template(
                "results.html",
                **assessment,
            )

        except ValueError as error:

            return render_template(
                "index.html",
                error=str(error),
            )

    return app