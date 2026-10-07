import time
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from cyberrecon.scanner.target import (
    normalize_target,
)

from cyberrecon.scanner.reconnaissance import (
    run_reconnaissance,
)

from cyberrecon.scanner.security_analysis import (
    SECURITY_CHECK_COUNT,
    analyze_security,
    summarize_findings,
)

def generate_scan_id():
    """
    Generate a short unique CyberRecon scan ID.
    """

    unique_part = uuid.uuid4().hex[:8].upper()

    return f"CR-{unique_part}"


def run_assessment(raw_target):
    """
    Execute the CyberRecon assessment pipeline.
    """

    assessment_start = time.perf_counter()

    started_at = datetime.now(
        ZoneInfo("Asia/Kolkata")
    )

    scan_id = generate_scan_id()

    # Detect whether the user supplied the protocol.
    explicit_scheme = raw_target.strip().lower().startswith(
        ("http://", "https://")
    )

    normalized_target = normalize_target(
        raw_target
    )

    reconnaissance = run_reconnaissance(
        normalized_target,
        allow_http_fallback=not explicit_scheme,
    )

    if reconnaissance.get("reachable"):

        findings = analyze_security(
            reconnaissance
        )

        checks_performed = SECURITY_CHECK_COUNT

        analysis_status = "Completed"

    else:

        findings = []

        checks_performed = 0

        analysis_status = "Skipped"

    finding_summary = summarize_findings(
        findings
    )

    assessment_end = time.perf_counter()

    duration_ms = round(
        (
            assessment_end
            - assessment_start
        )
        * 1000,
        2,
    )

    metadata = {
        "scan_id": scan_id,

        "started_at": started_at.strftime(
            "%d %b %Y, %I:%M:%S %p %Z"
        ),

        "duration_ms": duration_ms,

        "checks_performed":
            checks_performed,

        "recon_status": (
            "Completed"
            if reconnaissance.get("reachable")
            else "Failed"
        ),

        "analysis_status":
            analysis_status,
    }

    return {
        "target": normalized_target,
        "recon": reconnaissance,
        "findings": findings,
        "finding_summary": finding_summary,
        "metadata": metadata,
    }