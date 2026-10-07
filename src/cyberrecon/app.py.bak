from flask import (
    Flask,
    make_response,
    render_template,
    request,
)

from cyberrecon.scanner.assessment import (
    run_assessment,
)

from cyberrecon.storage import (
    get_completed_scans,
    get_dashboard_analytics,
    get_scan_by_id,
    get_scan_history,
    initialize_database,
    save_assessment,
)

from cyberrecon.scanner.comparison import (
    compare_assessments,
)


def create_app():
    app = Flask(__name__)

    initialize_database()
    
    @app.route("/dashboard")
    def dashboard():

        analytics = get_dashboard_analytics()

        return render_template(
            "dashboard.html",
            analytics=analytics,
        )

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
    
    @app.route("/history/<scan_id>")
    def scan_detail(scan_id):

        stored_assessment = get_scan_by_id(
            scan_id
        )

        if stored_assessment is None:
            return (
                "Stored assessment not found.",
                404,
            )

        return render_template(
            "scan_detail.html",
            scan=stored_assessment["scan"],
            findings=stored_assessment["findings"],
        )
    
    @app.route("/history/<scan_id>/report")
    def assessment_report(scan_id):

        stored_assessment = get_scan_by_id(
            scan_id
        )

        if stored_assessment is None:
            return (
                "Stored assessment not found.",
                404,
            )

        scan = stored_assessment["scan"]
        findings = stored_assessment["findings"]

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

        rendered_report = render_template(
            "report.html",
            scan=scan,
            findings=findings,
            severity_summary=severity_summary,
        )

        response = make_response(
            rendered_report
        )

        filename = (
            f"CyberRecon_{scan_id}_Report.html"
        )

        response.headers[
            "Content-Disposition"
        ] = (
            f'attachment; filename="{filename}"'
        )

        response.headers[
            "Content-Type"
        ] = "text/html; charset=utf-8"

        return response
    
    @app.route("/compare")
    def compare_scans():
    
        scans = get_completed_scans()
    
        baseline_id = request.args.get(
            "baseline"
        )
    
        current_id = request.args.get(
            "current"
        )
    
        comparison = None
        comparison_error = None
    
        if baseline_id and current_id:
    
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
                baseline_assessment is None
                or current_assessment is None
            ):
                comparison_error = (
                    "One or both stored assessments "
                    "could not be found."
                )
    
            elif baseline_id == current_id:
                comparison_error = (
                    "Please select two different assessments."
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
            comparison_error=comparison_error,
            selected_baseline=baseline_id,
            selected_current=current_id,
        )
            
    return app


    