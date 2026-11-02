import csv
from pathlib import Path

from webguard.remediation import load_tracker

REPORT_DIR = Path("reports")


def export_remediation_csv():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    tracker = load_tracker()

    output_file = REPORT_DIR / "remediation-report.csv"

    fields = [
        "finding_id",
        "title",
        "severity",
        "status",
        "notes"
    ]

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()

        for finding_id, finding in tracker.items():
            writer.writerow({
                "finding_id": finding_id,
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "Info"),
                "status": finding.get("status", "Open"),
                "notes": finding.get("notes", "")
            })

    return output_file


if __name__ == "__main__":
    try:
        output = export_remediation_csv()

        print("Remediation CSV exported successfully!")
        print(f"File location: {output}")

    except (OSError, ValueError) as error:
        print(f"Export failed: {error}")