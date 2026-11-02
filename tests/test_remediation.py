import pytest

import webguard.remediation as remediation


@pytest.fixture
def temporary_tracker(tmp_path, monkeypatch):
    report_dir = tmp_path / "reports"
    tracker_file = report_dir / "remediation-tracker.json"

    monkeypatch.setattr(remediation, "REPORT_DIR", report_dir)
    monkeypatch.setattr(remediation, "TRACKER_FILE", tracker_file)

    return tracker_file


def sample_finding():
    return {
        "title": "Missing Content Security Policy",
        "severity": "Medium",
        "evidence": "CSP header not found"
    }


def test_register_findings(temporary_tracker):
    tracker = remediation.register_findings([sample_finding()])

    assert len(tracker) == 1

    finding = next(iter(tracker.values()))

    assert finding["title"] == "Missing Content Security Policy"
    assert finding["status"] == "Open"


def test_update_remediation(temporary_tracker):
    tracker = remediation.register_findings([sample_finding()])
    finding_id = next(iter(tracker))

    updated = remediation.update_remediation(
        finding_id,
        "Fixed",
        "Security header configured."
    )

    assert updated["status"] == "Fixed"
    assert updated["notes"] == "Security header configured."


def test_invalid_status(temporary_tracker):
    tracker = remediation.register_findings([sample_finding()])
    finding_id = next(iter(tracker))

    with pytest.raises(ValueError):
        remediation.update_remediation(
            finding_id,
            "Completed"
        )


def test_missing_finding_id(temporary_tracker):
    with pytest.raises(ValueError):
        remediation.update_remediation(
            "INVALID123",
            "Fixed"
        )


def test_remediation_summary(temporary_tracker):
    tracker = remediation.register_findings([sample_finding()])
    finding_id = next(iter(tracker))

    remediation.update_remediation(
        finding_id,
        "Fixed"
    )

    summary = remediation.get_remediation_summary()

    assert summary["total"] == 1
    assert summary["fixed"] == 1
    assert summary["open"] == 0