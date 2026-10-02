def _finding_map(findings):
    """
    Convert a list of stored findings into a
    dictionary indexed by finding code.
    """

    return {
        finding["finding_code"]: finding
        for finding in findings
    }


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def compare_assessments(
    baseline_assessment,
    current_assessment,
):
    """
    Compare two stored CyberRecon assessments.
    """

    baseline_scan = baseline_assessment["scan"]
    current_scan = current_assessment["scan"]

    if baseline_scan["target"] != current_scan["target"]:
        raise ValueError(
            "Only assessments of the same target can be compared."
        )

    baseline_findings = _finding_map(
        baseline_assessment["findings"]
    )

    current_findings = _finding_map(
        current_assessment["findings"]
    )

    baseline_codes = set(
        baseline_findings.keys()
    )

    current_codes = set(
        current_findings.keys()
    )

    new_codes = (
        current_codes
        - baseline_codes
    )

    resolved_codes = (
        baseline_codes
        - current_codes
    )

    unchanged_codes = (
        baseline_codes
        & current_codes
    )

    new_findings = [
        current_findings[code]
        for code in sorted(new_codes)
    ]

    resolved_findings = [
        baseline_findings[code]
        for code in sorted(resolved_codes)
    ]

    unchanged_findings = [
        current_findings[code]
        for code in sorted(unchanged_codes)
    ]

    baseline_response = _safe_float(
        baseline_scan.get("response_time")
    )

    current_response = _safe_float(
        current_scan.get("response_time")
    )

    response_difference = None

    if (
        baseline_response is not None
        and current_response is not None
    ):
        response_difference = round(
            current_response
            - baseline_response,
            2,
        )

    return {
        "baseline": baseline_scan,
        "current": current_scan,

        "new_findings": new_findings,
        "resolved_findings":
            resolved_findings,
        "unchanged_findings":
            unchanged_findings,

        "summary": {
            "new": len(new_findings),
            "resolved":
                len(resolved_findings),
            "unchanged":
                len(unchanged_findings),
            "baseline_total":
                len(baseline_findings),
            "current_total":
                len(current_findings),
        },

        "response_difference":
            response_difference,
    }