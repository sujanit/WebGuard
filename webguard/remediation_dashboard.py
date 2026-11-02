from pathlib import Path
from html import escape

from webguard.remediation import (
    load_tracker,
    get_remediation_summary
)

REPORT_DIR = Path("reports")


def generate_remediation_dashboard():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    tracker = load_tracker()
    summary = get_remediation_summary()

    total = summary["total"]
    fixed = summary["fixed"]

    progress = round((fixed / total) * 100) if total else 0

    rows = ""

    for finding_id, finding in tracker.items():
        title = escape(str(finding.get("title", "Unknown")))
        severity = escape(str(finding.get("severity", "Info")))
        status = escape(str(finding.get("status", "Open")))
        notes = escape(str(finding.get("notes", "")))
        safe_id = escape(str(finding_id))

        status_class = status.lower().replace(" ", "-")
        severity_class = severity.lower()

        rows += f"""
        <tr>
            <td>{safe_id}</td>
            <td>{title}</td>
            <td>
                <span class="severity {severity_class}">
                    {severity}
                </span>
            </td>
            <td>
                <span class="status {status_class}">
                    {status}
                </span>
            </td>
            <td>{notes or "No notes"}</td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="5">No remediation findings available.</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WebGuard Remediation Dashboard</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #101827;
                color: white;
                margin: 0;
                padding: 30px;
            }}

            h1 {{
                color: #38bdf8;
            }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 15px;
                margin: 25px 0;
            }}

            .card {{
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
            }}

            .card h2 {{
                font-size: 30px;
                margin: 10px 0;
            }}

            .progress-container {{
                background: #334155;
                height: 22px;
                border-radius: 20px;
                overflow: hidden;
                margin: 15px 0;
            }}

            .progress-bar {{
                height: 100%;
                width: {progress}%;
                background: #22c55e;
                text-align: center;
                color: #07130b;
                font-weight: bold;
                line-height: 22px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
                margin-top: 20px;
            }}

            th, td {{
                padding: 13px;
                border-bottom: 1px solid #475569;
                text-align: left;
            }}

            th {{
                background: #334155;
            }}

            .status, .severity {{
                padding: 5px 9px;
                border-radius: 5px;
                font-size: 12px;
                font-weight: bold;
            }}

            .fixed, .low {{
                background: #166534;
            }}

            .open, .high {{
                background: #991b1b;
            }}

            .in-progress, .medium {{
                background: #854d0e;
            }}

            .info {{
                background: #1d4ed8;
            }}

            .footer {{
                margin-top: 30px;
                color: #94a3b8;
                font-size: 13px;
            }}
        </style>
    </head>

    <body>

        <h1>WebGuard</h1>
        <p>Vulnerability Remediation Management Dashboard</p>

        <div class="cards">

            <div class="card">
                <p>Total Findings</p>
                <h2>{total}</h2>
            </div>

            <div class="card">
                <p>Open</p>
                <h2>{summary["open"]}</h2>
            </div>

            <div class="card">
                <p>In Progress</p>
                <h2>{summary["in_progress"]}</h2>
            </div>

            <div class="card">
                <p>Fixed</p>
                <h2>{fixed}</h2>
            </div>

        </div>

        <h2>Remediation Progress</h2>

        <p>{progress}% completed</p>

        <div class="progress-container">
            <div class="progress-bar">{progress}%</div>
        </div>

        <h2>Finding Details</h2>

        <table>
            <tr>
                <th>Finding ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Remediation Notes</th>
            </tr>

            {rows}

        </table>

        <div class="footer">
            WebGuard Automated Web Application Security Assessment Tool
        </div>

    </body>
    </html>
    """

    output = REPORT_DIR / "remediation-dashboard.html"

    output.write_text(
        html_content,
        encoding="utf-8"
    )

    return output


if __name__ == "__main__":
    dashboard = generate_remediation_dashboard()

    print("Remediation dashboard generated:")
    print(dashboard)