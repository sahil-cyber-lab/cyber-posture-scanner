def compare_scans(previous_scan, current_scan):
    """
    Compare two completed scans belonging to the same target.
    """

    previous_findings = {
        (
            finding.title,
            finding.port,
            finding.service,
            finding.product,
            finding.version
        )
        for finding in previous_scan.findings.all()
    }

    current_findings = {
        (
            finding.title,
            finding.port,
            finding.service,
            finding.product,
            finding.version
        )
        for finding in current_scan.findings.all()
    }

    new_findings = current_findings - previous_findings
    resolved_findings = previous_findings - current_findings
    unchanged_findings = current_findings & previous_findings

    score_change = (
        current_scan.score - previous_scan.score
    )

    return {
        "previous_score": previous_scan.score,
        "current_score": current_scan.score,
        "score_change": score_change,

        "previous_risk": previous_scan.risk_level,
        "current_risk": current_scan.risk_level,

        "previous_total_risk": previous_scan.total_risk,
        "current_total_risk": current_scan.total_risk,

        "new_findings": list(new_findings),
        "resolved_findings": list(resolved_findings),
        "unchanged_findings": list(unchanged_findings),

        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "unchanged_count": len(unchanged_findings),
    }


def get_posture_trends(scans):
    """
    Generate historical security posture data.

    Scans should belong to the same user and target.
    """

    scans = scans.order_by("created_at")

    trend_data = []

    for scan in scans:

        finding_count = scan.findings.count()

        trend_data.append({
            "scan_id": scan.id,
            "target": scan.target,
            "score": scan.score,
            "risk_level": scan.risk_level,
            "total_risk": scan.total_risk,
            "finding_count": finding_count,
            "created_at": scan.created_at,
        })

    return trend_data


def get_posture_summary(scans):
    """
    Generate a summary of the security posture history.
    """

    scans = list(scans.order_by("created_at"))

    if not scans:
        return {
            "total_scans": 0,
            "first_score": None,
            "current_score": None,
            "score_change": None,
            "first_risk": None,
            "current_risk": None,
            "first_total_risk": None,
            "current_total_risk": None,
        }

    first_scan = scans[0]
    current_scan = scans[-1]

    return {
        "total_scans": len(scans),

        "first_score": first_scan.score,
        "current_score": current_scan.score,

        "score_change": (
            current_scan.score -
            first_scan.score
        ),

        "first_risk": first_scan.risk_level,
        "current_risk": current_scan.risk_level,

        "first_total_risk": first_scan.total_risk,
        "current_total_risk": current_scan.total_risk,
    }