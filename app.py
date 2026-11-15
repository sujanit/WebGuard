
from flask import Flask, render_template, jsonify
from database import connect_database, get_scan_history, close_database

app = Flask(__name__)


def load_scans(limit=100):
    connected = False

    try:
        connect_database()
        connected = True
        return get_scan_history(limit=limit)

    except Exception as error:
        print("Database error:", error)
        return []

    finally:
        if connected:
            close_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/cn")
def cn_dashboard():
    return render_template("cn_dashboard.html")


@app.route("/flat")
def flat_dashboard():
    return render_template("flat_dashboard.html")

@app.route("/fswd")
def fswd_dashboard():
    return render_template("fswd_dashboard.html")


@app.route("/api/scans")
def api_scans():
    scans = load_scans()
    return jsonify(scans)


@app.route("/api/stats")
def api_stats():
    scans = load_scans()

    total_scans = len(scans)

    high_risk_scans = sum(
        1 for scan in scans
        if scan.get("risk_level") in ["High", "Critical"]
    )

    total_findings = sum(
        scan.get(
            "findings_count",
            len(scan.get("findings", []))
        )
        for scan in scans
    )

    latest_scan = scans[0] if scans else None

    return jsonify({
        "total_scans": total_scans,
        "high_risk_scans": high_risk_scans,
        "total_findings": total_findings,
        "latest_scan": latest_scan
    })


@app.route("/scan/<scan_id>")
def scan_details(scan_id):
    scans = load_scans()

    selected_scan = next(
        (
            scan for scan in scans
            if scan.get("_id") == scan_id
        ),
        None
    )

    if selected_scan is None:
        return "Scan not found", 404

    return render_template(
        "scan_details.html",
        scan=selected_scan
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
