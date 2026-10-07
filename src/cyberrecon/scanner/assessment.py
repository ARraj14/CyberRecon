import time

from datetime import datetime
from uuid import uuid4
from zoneinfo import ZoneInfo

from cyberrecon.scanner.reconnaissance import (
    perform_reconnaissance,
)

from cyberrecon.scanner.security_analysis import (
    SECURITY_CHECK_COUNT,
    analyze_security,
    summarize_findings,
)

from cyberrecon.scanner.target import (
    has_explicit_scheme,
    normalize_target,
)


INDIA_TIMEZONE = ZoneInfo(
    "Asia/Kolkata"
)


def generate_scan_id():
    """
    Generate a short human-readable CyberRecon scan ID.
    """

    return (
        "CR-"
        + uuid4()
        .hex[:8]
        .upper()
    )


def current_ist_timestamp():
    """
    Return the current timestamp in Indian Standard Time.
    """

    current_time = datetime.now(
        INDIA_TIMEZONE
    )

    return current_time.strftime(
        "%d %b %Y, %I:%M:%S %p IST"
    )


def run_assessment(
    raw_target,
):
    """
    Execute the complete CyberRecon assessment pipeline.

    Stages:
    1. validate and normalize target
    2. passive reconnaissance
    3. security analysis
    4. summarize findings
    5. return structured metadata
    """

    started_at = (
        current_ist_timestamp()
    )


    scan_id = (
        generate_scan_id()
    )


    timer_start = (
        time.perf_counter()
    )


    explicit_scheme = (
        has_explicit_scheme(
            raw_target
        )
    )


    normalized_target = (
        normalize_target(
            raw_target
        )
    )


    reconnaissance = (
        perform_reconnaissance(
            normalized_target,

            allow_http_fallback=(
                not explicit_scheme
            ),
        )
    )


    if reconnaissance[
        "reachable"
    ]:

        findings = (
            analyze_security(
                reconnaissance
            )
        )


        finding_summary = (
            summarize_findings(
                findings
            )
        )


        recon_status = (
            "Completed"
        )


        analysis_status = (
            "Completed"
        )


        checks_performed = (
            SECURITY_CHECK_COUNT
        )


    else:

        findings = []


        finding_summary = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
            "Total": 0,
        }


        recon_status = "Failed"

        analysis_status = "Skipped"

        checks_performed = 0


    duration_ms = round(
        (
            time.perf_counter()
            - timer_start
        )
        * 1000,
        2,
    )


    metadata = {
        "scan_id":
            scan_id,

        "started_at":
            started_at,

        "duration_ms":
            duration_ms,

        "checks_performed":
            checks_performed,

        "recon_status":
            recon_status,

        "analysis_status":
            analysis_status,
    }


    return {
        "target":
            normalized_target,

        "recon":
            reconnaissance,

        "findings":
            findings,

        "finding_summary":
            finding_summary,

        "metadata":
            metadata,
    }