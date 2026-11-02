
import csv
import json
from pathlib import Path
from datetime import datetime, timezone
from html import escape

REPORT_DIR = Path("reports")


def prepare_report(report):
    """Prepare report data and severity distribution."""

    findings = report.get("findings", [])

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Info")
        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    prepared = report.copy()
    prepared["findings_count"] = len(findings)
    prepared["severity_counts"] = severity_counts
    prepared["risk_score"] = report.get("risk_score", 0)
    prepared["risk_level"] = report.get(
        "risk_level", "Not calculated"
    )

    return prepared


def save_json(report):
    """Save security report as JSON."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    prepared = prepare_report(report)
    output = REPORT_DIR / "webguard-report.json"

    output.write_text(
        json.dumps(prepared, indent=4),
        encoding="utf-8"
    )

    return output


def save_csv(report):
    """Export security findings as CSV."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    output = REPORT_DIR / "webguard-report.csv"

    fieldnames = [
        "Finding",
        "Severity",
        "Confidence",
        "Evidence",
        "Remediation"
    ]

    with output.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for finding in report.get("findings", []):
            writer.writerow({
                "Finding": finding.get("title", "Unknown"),
                "Severity": finding.get("severity", "Info"),
                "Confidence": finding.get("confidence", "Unknown"),
                "Evidence": finding.get("evidence", ""),
                "Remediation": finding.get("remediation", "")
            })

    return output


def save_history(report):
    """Save scan history."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    history_file = REPORT_DIR / "scan-history.json"

    entry = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": report.get("target", "Unknown"),
        "status_code": report.get("status_code"),
        "findings_count": report.get(
            "findings_count",
            len(report.get("findings", []))
        ),
        "risk_score": report.get("risk_score", 0),
        "risk_level": report.get("risk_level", "Unknown")
    }

    if history_file.exists():
        try:
            history = json.loads(
                history_file.read_text(encoding="utf-8")
            )

            if not isinstance(history, list):
                raise ValueError("Invalid history format")

        except (json.JSONDecodeError, ValueError):
            raise ValueError(
                "Scan history file is invalid. "
                "Back it up before repairing it."
            )
    else:
        history = []

    history.append(entry)

    history_file.write_text(
        json.dumps(history, indent=4),
        encoding="utf-8"
    )

    return history_file


def compare_scans(history_file, target):
    """Compare the latest two saved scans."""

    history = json.loads(
        Path(history_file).read_text(encoding="utf-8")
    )

    matching_scans = [
        scan for scan in history
        if scan.get("target") == target
    ]

    if len(matching_scans) < 2:
        return None

    previous = matching_scans[-2]
    current = matching_scans[-1]

    return calculate_comparison(previous, current)


def calculate_comparison(previous, current):
    """Calculate differences between two scans."""

    previous_findings = int(previous.get("findings_count", 0))
    current_findings = int(current.get("findings_count", 0))

    previous_risk = float(previous.get("risk_score", 0))
    current_risk = float(current.get("risk_score", 0))

    findings_change = current_findings - previous_findings
    risk_change = current_risk - previous_risk

    if previous_risk > 0:
        improvement_percentage = (
            (previous_risk - current_risk)
            / previous_risk
        ) * 100
    else:
        improvement_percentage = 0

    if risk_change < 0:
        status = "Improved"
    elif risk_change > 0:
        status = "Worsened"
    else:
        status = "Unchanged"

    return {
        "previous_findings": previous_findings,
        "current_findings": current_findings,
        "findings_change": findings_change,
        "previous_risk": previous_risk,
        "current_risk": current_risk,
        "risk_change": risk_change,
        "previous_risk_level": previous.get(
            "risk_level", "Unknown"
        ),
        "current_risk_level": current.get(
            "risk_level", "Unknown"
        ),
        "improvement_percentage": round(
            improvement_percentage, 2
        ),
        "status": status
    }


def compare_current_with_history(report):
    """Compare the current scan with the latest saved scan."""

    history_file = REPORT_DIR / "scan-history.json"

    if not history_file.exists():
        return None

    try:
        history = json.loads(
            history_file.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        return None

    matching_scans = [
        scan for scan in history
        if scan.get("target") == report.get("target")
    ]

    if not matching_scans:
        return None

    previous = matching_scans[-1]

    current = {
        "target": report.get("target"),
        "findings_count": len(report.get("findings", [])),
        "risk_score": report.get("risk_score", 0),
        "risk_level": report.get("risk_level", "Unknown")
    }

    return calculate_comparison(previous, current)


def build_scan_trend_svg(target):
    """Generate risk trend chart using saved scan history."""

    history_file = REPORT_DIR / "scan-history.json"

    if not history_file.exists():
        return "<p>No scan history available.</p>"

    try:
        history = json.loads(
            history_file.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        return "<p>Unable to read scan history.</p>"

    scans = [
        scan for scan in history
        if scan.get("target") == target
    ][-10:]

    if not scans:
        return "<p>No scans available for this target.</p>"

    width = 700
    height = 280
    left = 60
    right = 30
    top = 30
    bottom = 50

    scores = [
        float(scan.get("risk_score", 0))
        for scan in scans
    ]

    maximum = max(max(scores), 10)

    chart_width = width - left - right
    chart_height = height - top - bottom

    points = []

    for index, score in enumerate(scores):
        x = left + (
            index * chart_width / max(len(scores) - 1, 1)
        )

        y = top + chart_height - (
            score / maximum * chart_height
        )

        points.append((x, y))

    coordinates = " ".join(
        f"{x:.1f},{y:.1f}"
        for x, y in points
    )

    circles = ""
    labels = ""

    for index, (x, y) in enumerate(points):
        circles += f"""
        <circle cx="{x}" cy="{y}" r="6"
                fill="#2563eb"
                stroke="white"
                stroke-width="2">
            <title>Scan {index + 1}: Risk score {scores[index]}</title>
        </circle>
        """

        labels += f"""
        <text x="{x}" y="{height - 15}"
              text-anchor="middle"
              font-size="12"
              fill="#64748b">
            {index + 1}
        </text>
        """

    grid_lines = ""

    for fraction in (0, 0.25, 0.5, 0.75, 1):
        y = top + chart_height * (1 - fraction)
        value = maximum * fraction

        grid_lines += f"""
        <line x1="{left}" y1="{y}"
              x2="{width-right}" y2="{y}"
              stroke="#e2e8f0"
              stroke-dasharray="4 4"/>

        <text x="{left-10}" y="{y+4}"
              text-anchor="end"
              font-size="11"
              fill="#64748b">
            {value:.0f}
        </text>
        """

    return f"""
    <div style="width:100%;overflow-x:auto;">
        <svg viewBox="0 0 {width} {height}"
             role="img"
             aria-label="Risk score trend chart"
             style="width:100%;min-width:450px;">

            {grid_lines}

            <line x1="{left}" y1="{top}"
                  x2="{left}" y2="{height-bottom}"
                  stroke="#94a3b8"/>

            <line x1="{left}" y1="{height-bottom}"
                  x2="{width-right}" y2="{height-bottom}"
                  stroke="#94a3b8"/>

            <polyline points="{coordinates}"
                      fill="none"
                      stroke="#2563eb"
                      stroke-width="3"
                      stroke-linejoin="round"
                      stroke-linecap="round"/>

            {circles}
            {labels}

        </svg>
    </div>

    <p style="color:#64748b;">
        Latest {len(scans)} scans.
        Horizontal axis: Scan number.
        Vertical axis: Risk score.
    </p>
    """


def save_html(report):
    """Generate professional HTML security dashboard."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    prepared = prepare_report(report)

    findings = prepared["findings"]
    severity_counts = prepared["severity_counts"]

    risk_score = prepared["risk_score"]
    risk_level = escape(str(prepared["risk_level"]))

    target_value = str(report.get("target", "Unknown"))
    target = escape(target_value)

    status_code = escape(
        str(report.get("status_code", "Unknown"))
    )

    scan_time = datetime.now().strftime(
        "%d %b %Y, %I:%M %p"
    )

    trend_chart = build_scan_trend_svg(target_value)

    comparison = compare_current_with_history(report)

    if comparison:

        comparison_status = escape(comparison["status"])

        comparison_color = {
            "Improved": "#15803d",
            "Worsened": "#dc2626",
            "Unchanged": "#64748b"
        }.get(comparison["status"], "#64748b")

        comparison_html = f"""
        <div class="comparison-grid">

            <div class="comparison-card">
                <h3>Previous Risk</h3>
                <p>{comparison["previous_risk"]}</p>
                <span>{escape(str(comparison["previous_risk_level"]))}</span>
            </div>

            <div class="comparison-card">
                <h3>Current Risk</h3>
                <p>{comparison["current_risk"]}</p>
                <span>{escape(str(comparison["current_risk_level"]))}</span>
            </div>

            <div class="comparison-card">
                <h3>Risk Change</h3>
                <p>{comparison["risk_change"]:+g}</p>
                <span>{comparison["improvement_percentage"]}% improvement</span>
            </div>

            <div class="comparison-card">
                <h3>Findings Change</h3>
                <p>{comparison["findings_change"]:+d}</p>
                <span>Previous: {comparison["previous_findings"]} |
                Current: {comparison["current_findings"]}</span>
            </div>

        </div>

        <div class="assessment"
             style="border-left:5px solid {comparison_color};">

            <h3 style="color:{comparison_color};">
                Assessment: {comparison_status}
            </h3>

            <p>
                {escape(comparison_status)} compared with
                the previous recorded scan based on the
                custom risk score.
            </p>

        </div>
        """

    else:
        comparison_html = """
        <p>
            Not enough previous scans are available
            for comparison. Run another scan to enable
            scan-to-scan comparison.
        </p>
        """

    severity_cards = ""

    for severity, count in severity_counts.items():
        severity_cards += f"""
        <div class="severity-card {severity.lower()}">
            <h3>{severity}</h3>
            <p>{count}</p>
        </div>
        """

    findings_rows = ""

    for index, finding in enumerate(findings, start=1):

        title = escape(str(finding.get("title", "Unknown")))
        severity = escape(
            str(finding.get("severity", "Info"))
        )
        confidence = escape(
            str(finding.get("confidence", "Unknown"))
        )
        evidence = escape(
            str(finding.get("evidence", "Not provided"))
        )
        remediation = escape(
            str(finding.get("remediation", "No recommendation"))
        )

        findings_rows += f"""
        <tr>
            <td>{index}</td>
            <td>{title}</td>
            <td>
                <span class="tag {severity.lower()}">
                    {severity}
                </span>
            </td>
            <td>{confidence}</td>
            <td>{evidence}</td>
            <td>{remediation}</td>
        </tr>
        """

    if not findings_rows:
        findings_rows = """
        <tr>
            <td colspan="6" class="empty">
                No security findings detected.
            </td>
        </tr>
        """

    html_content = f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>WebGuard Security Dashboard</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            color: #1e293b;
        }}

        header {{
            background: #0f172a;
            color: white;
            padding: 28px 5%;
        }}

        header h1 {{
            margin: 0;
            font-size: 30px;
        }}

        header p {{
            color: #94a3b8;
        }}

        main {{
            width: 92%;
            max-width: 1400px;
            margin: 30px auto;
        }}

        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }}

        .section h2 {{
            margin-top: 0;
            color: #0f172a;
        }}

        .overview {{
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(180px, 1fr)
            );
            gap: 18px;
        }}

        .metric {{
            padding: 22px;
            background: #f8fafc;
            border-radius: 10px;
            border-left: 5px solid #2563eb;
        }}

        .metric h3 {{
            margin: 0;
            font-size: 28px;
            overflow-wrap: anywhere;
        }}

        .metric p {{
            color: #64748b;
        }}

        .severity-grid,
        .comparison-grid {{
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(150px, 1fr)
            );
            gap: 15px;
        }}

        .severity-card {{
            padding: 16px;
            border-radius: 10px;
            text-align: center;
        }}

        .severity-card h3 {{
            margin: 0;
        }}

        .severity-card p {{
            font-size: 30px;
            font-weight: bold;
            margin: 10px 0 0;
        }}

        .critical {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .high {{
            background: #ffedd5;
            color: #9a3412;
        }}

        .medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .low {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .info {{
            background: #e2e8f0;
            color: #334155;
        }}

        .comparison-card {{
            padding: 18px;
            background: #f8fafc;
            border-radius: 10px;
        }}

        .comparison-card h3 {{
            font-size: 15px;
            color: #64748b;
        }}

        .comparison-card p {{
            font-size: 27px;
            font-weight: bold;
            margin: 8px 0;
        }}

        .comparison-card span {{
            font-size: 13px;
            color: #64748b;
        }}

        .assessment {{
            margin-top: 20px;
            padding: 15px 20px;
            background: #f8fafc;
            border-radius: 8px;
        }}

        .tag {{
            padding: 5px 9px;
            border-radius: 5px;
            font-weight: bold;
            display: inline-block;
        }}

        .table-container {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 900px;
        }}

        th, td {{
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}

        th {{
            background: #f8fafc;
        }}

        td {{
            line-height: 1.5;
        }}

        .empty {{
            text-align: center;
            padding: 30px;
        }}

        .scan-info p {{
            overflow-wrap: anywhere;
        }}

        footer {{
            text-align: center;
            padding: 25px;
            color: #64748b;
        }}

        @media (max-width: 600px) {{
            header h1 {{
                font-size: 23px;
            }}

            .section {{
                padding: 17px;
            }}
        }}
    </style>
</head>

<body>

    <header>
        <h1>WebGuard Security Dashboard</h1>
        <p>Automated Web Application Security Assessment</p>
    </header>

    <main>

        <section class="section">
            <h2>Executive Summary</h2>

            <div class="overview">

                <div class="metric">
                    <h3>{risk_score}</h3>
                    <p>Risk Score (heuristic)</p>
                </div>

                <div class="metric">
                    <h3>{risk_level}</h3>
                    <p>Risk Level</p>
                </div>

                <div class="metric">
                    <h3>{len(findings)}</h3>
                    <p>Total Findings</p>
                </div>

                <div class="metric">
                    <h3>{status_code}</h3>
                    <p>HTTP Status</p>
                </div>

            </div>
        </section>

        <section class="section scan-info">
            <h2>Scan Information</h2>

            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Time:</strong> {scan_time}</p>
            <p><strong>Scope:</strong> Local loopback target only</p>
        </section>

        <section class="section">
            <h2>Severity Distribution</h2>

            <div class="severity-grid">
                {severity_cards}
            </div>
        </section>

        <section class="section">
            <h2>Scan-to-Scan Comparison</h2>
            {comparison_html}
        </section>

        <section class="section">
            <h2>Risk Score Trend</h2>
            {trend_chart}
        </section>

        <section class="section">
            <h2>Security Findings</h2>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Finding</th>
                            <th>Severity</th>
                            <th>Confidence</th>
                            <th>Evidence</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>

                    <tbody>
                        {findings_rows}
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <footer>
        WebGuard v1.0.0 |
        Automated Security Assessment Tool
    </footer>

</body>
</html>
"""

    output = REPORT_DIR / "webguard-report.html"

    output.write_text(
        html_content,
        encoding="utf-8"
    )

    return output
