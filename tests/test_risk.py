
from webguard.risk import calculate_risk


def test_low_risk():
    findings = [{"severity": "Low"}]

    result = calculate_risk(findings)

    assert result["risk_score"] == 3
    assert result["risk_level"] == "Low"


def test_medium_risk():
    findings = [
        {"severity": "Medium"},
        {"severity": "Low"}
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 9
    assert result["risk_level"] == "Low"


def test_high_risk():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"}
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 16
    assert result["risk_level"] == "Medium"


def test_critical_risk():
    findings = [
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "High"}
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 30
    assert result["risk_level"] == "Critical"


def test_empty_findings():
    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
