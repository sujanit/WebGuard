
import json
import hashlib
from pathlib import Path

REPORT_DIR = Path("reports")
TRACKER_FILE = REPORT_DIR / "remediation-tracker.json"

VALID_STATUSES = [
    "Open",
    "In Progress",
    "Fixed"
]


def generate_finding_id(finding):
    """Generate a stable ID for a security finding."""

    identity = (
        str(finding.get("title", "Unknown"))
        + "|"
        + str(finding.get("evidence", ""))
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:12].upper()


def load_tracker():
    """Load existing remediation tracking data."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not TRACKER_FILE.exists():
        return {}

    try:
        data = json.loads(
            TRACKER_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError("Invalid tracker format")

        return data

    except (json.JSONDecodeError, ValueError):
        raise ValueError(
            "Remediation tracker is invalid. "
            "Back it up before repairing it."
        )


def save_tracker(data):
    """Save remediation tracking data."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    TRACKER_FILE.write_text(
        json.dumps(data, indent=4),
        encoding="utf-8"
    )

    return TRACKER_FILE


def register_findings(findings):
    """Register newly discovered vulnerabilities."""

    tracker = load_tracker()

    for finding in findings:

        finding_id = generate_finding_id(finding)

        if finding_id not in tracker:
            tracker[finding_id] = {
                "finding_id": finding_id,
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "Info"),
                "status": "Open",
                "notes": ""
            }

    save_tracker(tracker)

    return tracker


def update_remediation(finding_id, status, notes=""):
    """Update the remediation status of a finding."""

    if status not in VALID_STATUSES:
        raise ValueError(
            "Status must be Open, In Progress, or Fixed."
        )

    tracker = load_tracker()

    if finding_id not in tracker:
        raise ValueError("Finding ID not found.")

    tracker[finding_id]["status"] = status
    tracker[finding_id]["notes"] = notes

    save_tracker(tracker)

    return tracker[finding_id]


def get_remediation_summary():
    """Get remediation statistics."""

    tracker = load_tracker()

    summary = {
        "total": len(tracker),
        "open": 0,
        "in_progress": 0,
        "fixed": 0
    }

    for finding in tracker.values():

        status = finding.get("status", "Open")

        if status == "Open":
            summary["open"] += 1

        elif status == "In Progress":
            summary["in_progress"] += 1

        elif status == "Fixed":
            summary["fixed"] += 1

    return summary
