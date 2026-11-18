
import ipaddress
from urllib.parse import urldefrag, urlsplit

import requests
from flask import (
    Flask,
    render_template,
    jsonify,
    request
)
from pymongo.errors import PyMongoError

from webguard.scanner import scan_target

from webguard.config import (
    ALLOWED_SCAN_ORIGINS,
    RENDER_DASHBOARD_HOST
)

from database import (
    connect_database,
    get_scan_history,
    get_availability_dashboard,
    get_service_history,
    save_scan_result
)
from webguard.availability_monitor import (
    AvailabilityMonitor,
    load_monitored_services
)

app = Flask(__name__)
MONITORED_SERVICES = load_monitored_services()
availability_monitor = AvailabilityMonitor(MONITORED_SERVICES)
availability_monitor.start()


def _request_host():
    try:
        host = urlsplit(f"//{request.host}").hostname
    except ValueError:
        return None

    return host.lower() if host else None


def _is_loopback_address(address):
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return False

    if isinstance(parsed_address, ipaddress.IPv6Address):
        parsed_address = parsed_address.ipv4_mapped or parsed_address

    return parsed_address.is_loopback


def is_local_dashboard_request():
    host = _request_host()

    return (
        host is not None
        and (host.lower() == "localhost" or _is_loopback_address(host))
        and _is_loopback_address(request.remote_addr or "")
    )


def is_render_dashboard_request():
    return _request_host() == RENDER_DASHBOARD_HOST


def load_scans(limit=100):
    try:
        connect_database()
        return get_scan_history(limit=limit)

    except Exception as error:
        print("Database error:", error)
        return []


@app.route("/")
def home():
    local_request = is_local_dashboard_request()
    render_request = is_render_dashboard_request() and bool(ALLOWED_SCAN_ORIGINS)
    scan_target_default = (
        ALLOWED_SCAN_ORIGINS[0] + "/"
        if render_request
        else "http://127.0.0.1:3000/#/"
    )

    return render_template(
        "index.html",
        scan_enabled=local_request or render_request,
        render_scan_enabled=render_request,
        scan_target_default=scan_target_default
    )


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
    return jsonify(load_scans())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    local_request = is_local_dashboard_request()
    render_request = is_render_dashboard_request()

    if not (local_request or render_request):
        return jsonify({
            "error": "Scanning is only available from a local WebGuard instance."
        }), 403

    data = request.get_json(silent=True)
    target = data.get("target") if isinstance(data, dict) else None

    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "Enter a target URL to scan."}), 400

    target = target.strip()

    if len(target) > 2048:
        return jsonify({"error": "Target URL is too long."}), 400

    target, _ = urldefrag(target)

    try:
        report = scan_target(
            target,
            allowed_origins=ALLOWED_SCAN_ORIGINS if render_request else (),
            allow_loopback=local_request
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except requests.RequestException:
        return jsonify({"error": "The target could not be reached."}), 502

    history_saved = True

    try:
        connect_database()
        save_scan_result(report)
    except (ValueError, PyMongoError):
        history_saved = False

    return jsonify({
        "report": report,
        "history_saved": history_saved,
        "message": (
            "Scan completed and added to history."
            if history_saved
            else "Scan completed, but could not be saved to history. Check MongoDB credentials and configuration."
        )
    })


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


@app.route("/api/availability")
def api_availability():
    if not MONITORED_SERVICES:
        return jsonify({
            "services": [],
            "events": [],
            "message": "Configure MONITORED_SERVICES_JSON to start monitoring."
        })

    try:
        return jsonify(get_availability_dashboard(MONITORED_SERVICES))
    except (ValueError, PyMongoError):
        app.logger.exception("Unable to load availability data.")
        return jsonify({
            "error": "Availability data is temporarily unavailable."
        }), 503


@app.route("/api/availability/<service_id>/history")
def api_availability_history(service_id):
    if not any(
        service["service_id"] == service_id
        for service in MONITORED_SERVICES
    ):
        return jsonify({"error": "Monitored service not found."}), 404

    try:
        return jsonify(get_service_history(service_id))
    except (ValueError, PyMongoError):
        app.logger.exception("Unable to load service history.")
        return jsonify({
            "error": "Service history is temporarily unavailable."
        }), 503


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
