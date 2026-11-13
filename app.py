
from flask import Flask, jsonify, render_template, abort
from database import connect_database, get_scan_history, close_database

app = Flask(__name__)


def load_scans():
    """Load scan history from MongoDB Atlas."""
    connected = False

    try:
        connect_database()
        connected = True

        scans = get_scan_history(limit=100)

        return scans

    finally:
        if connected:
            close_database()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/scans")
def get_scans():
    try:
        scans = load_scans()
        return jsonify(scans)

    except Exception:
        app.logger.exception("Unable to retrieve scans")
        return jsonify({
            "error": "Unable to retrieve scan history"
        }), 500


@app.route("/api/stats")
def get_stats():
    try:
        scans = load_scans()

        total_scans = len(scans)

        high_risk = sum(
            1 for scan in scans
            if scan.get("risk_level") in ("High", "Critical")
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
            "high_risk_scans": high_risk,
            "total_findings": total_findings,
            "latest_scan": latest_scan
        })

    except Exception:
        app.logger.exception("Unable to retrieve statistics")
        return jsonify({
            "error": "Unable to retrieve statistics"
        }), 500


@app.route("/scan/<scan_id>")
def scan_details(scan_id):
    try:
        scans = load_scans()

        selected_scan = next(
            (
                scan for scan in scans
                if scan.get("_id") == scan_id
            ),
            None
        )

        if selected_scan is None:
            abort(404)

        return render_template(
            "scan_details.html",
            scan=selected_scan
        )

    except Exception:
        app.logger.exception("Unable to load scan details")
        abort(500)


@app.errorhandler(404)
def not_found(error):
    return "Scan not found.", 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
