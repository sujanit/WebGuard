
SEVERITY_POINTS = {
    "High": 10,
    "Medium": 6,
    "Low": 3,
    "Info": 1
}


def calculate_risk(findings):

    score = 0

    for finding in findings:
        severity = finding.get("severity", "Info")
        score += SEVERITY_POINTS.get(severity, 1)

    if score >= 30:
        risk_level = "Critical"

    elif score >= 20:
        risk_level = "High"

    elif score >= 10:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }
