import pytest

from app import app
from webguard.config import ALLOWED_SCAN_ORIGINS
from webguard.scanner import validate_target


@pytest.mark.parametrize("path", ["/", "/cn", "/flat", "/fswd"])
def test_dashboards_are_public_without_authentication_config(path, monkeypatch):
    monkeypatch.delenv("WEBGUARD_USERNAME", raising=False)
    monkeypatch.delenv("WEBGUARD_PASSWORD", raising=False)

    response = app.test_client().get(path)

    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


def test_home_page_enables_scanning_for_local_requests():
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b'id="scanTarget"' in response.data
    assert b'value="http://127.0.0.1:3000/#/"' in response.data
    assert b'placeholder="http://127.0.0.1:3000/#/"' in response.data
    assert b'<button type="submit">Scan target</button>' in response.data
    assert b"Scans are limited to localhost and loopback targets." in response.data


def test_home_page_enables_scanning_for_render_target():
    response = app.test_client().get(
        "/",
        headers={"Host": "webguard-2prs.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 200
    target = ALLOWED_SCAN_ORIGINS[0] + "/"
    assert f'value="{target}"'.encode() in response.data
    assert b'<button type="submit">Scan target</button>' in response.data
    assert b"Render scans are restricted to" in response.data


def test_home_page_disables_scanning_for_unrecognized_hosted_requests():
    response = app.test_client().get(
        "/",
        headers={"Host": "other.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 200
    assert b'<button type="submit" disabled>Scan target</button>' in response.data
    assert b"Scanning is available only when WebGuard runs locally." in response.data


def test_render_scan_rejects_loopback_target():
    response = app.test_client().post(
        "/api/scan",
        json={"target": "http://127.0.0.1:3000"},
        headers={"Host": "webguard-2prs.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 400
    assert "Target must be localhost, loopback, or an explicitly allowed origin." in response.json["error"]


def test_scan_endpoint_rejects_non_loopback_targets():
    response = app.test_client().post(
        "/api/scan",
        json={"target": "https://example.com"}
    )

    assert response.status_code == 400
    assert "explicitly allowed origin" in response.json["error"]


def test_local_scan_saves_result_to_history(monkeypatch):
    report = {
        "target": "http://127.0.0.1:3000/",
        "findings_count": 0,
        "risk_level": "Low"
    }
    saved_reports = []
    scanned_targets = []

    def scan_target(target, allowed_origins=(), allow_loopback=True):
        validate_target(
            target,
            allowed_origins=allowed_origins,
            allow_loopback=allow_loopback
        )
        scanned_targets.append(target)
        return report

    monkeypatch.setattr("app.scan_target", scan_target)
    monkeypatch.setattr("app.connect_database", lambda: None)
    monkeypatch.setattr("app.save_scan_result", saved_reports.append)

    response = app.test_client().post(
        "/api/scan",
        json={"target": "http://127.0.0.1:3000/#/"}
    )

    assert response.status_code == 200
    assert response.json["report"] == report
    assert response.json["history_saved"] is True
    assert scanned_targets == [report["target"]]
    assert saved_reports == [report]


def test_render_scan_is_limited_to_allowlisted_origin(monkeypatch):
    target = ALLOWED_SCAN_ORIGINS[0] + "/"
    report = {
        "target": target,
        "findings_count": 1,
        "risk_level": "Medium"
    }

    def scan_target(url, allowed_origins=(), allow_loopback=True):
        validate_target(
            url,
            allowed_origins=allowed_origins,
            allow_loopback=allow_loopback
        )
        return report

    monkeypatch.setattr("app.scan_target", scan_target)
    monkeypatch.setattr("app.connect_database", lambda: None)
    monkeypatch.setattr("app.save_scan_result", lambda result: None)

    response = app.test_client().post(
        "/api/scan",
        json={"target": target},
        headers={"Host": "webguard-2prs.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 200
    assert response.json["report"] == report


def test_scan_returns_report_when_history_save_fails(monkeypatch):
    report = {
        "target": "http://127.0.0.1:3000",
        "findings_count": 1,
        "risk_level": "Medium"
    }

    def fail_to_save(result):
        raise ValueError("database unavailable")

    monkeypatch.setattr("app.scan_target", lambda target, **kwargs: report)
    monkeypatch.setattr("app.connect_database", lambda: None)
    monkeypatch.setattr("app.save_scan_result", fail_to_save)

    response = app.test_client().post(
        "/api/scan",
        json={"target": report["target"]}
    )

    assert response.status_code == 200
    assert response.json["report"] == report
    assert response.json["history_saved"] is False
    assert "Check MongoDB credentials and configuration." in response.json["message"]


def test_availability_endpoint_explains_when_no_services_are_configured(monkeypatch):
    monkeypatch.setattr("app.MONITORED_SERVICES", [])

    response = app.test_client().get("/api/availability")

    assert response.status_code == 200
    assert response.json["services"] == []
    assert "MONITORED_SERVICES_JSON" in response.json["message"]


def test_availability_endpoint_returns_service_status(monkeypatch):
    services = [{
        "service_id": "service-1",
        "name": "API",
        "url": "https://api.example.com/health"
    }]
    dashboard = {
        "services": [{**services[0], "state": "Healthy"}],
        "events": []
    }

    monkeypatch.setattr("app.MONITORED_SERVICES", services)
    monkeypatch.setattr(
        "app.get_availability_dashboard",
        lambda configured_services: dashboard
    )

    response = app.test_client().get("/api/availability")

    assert response.status_code == 200
    assert response.json == dashboard


def test_availability_history_rejects_unconfigured_service():
    response = app.test_client().get("/api/availability/not-configured/history")

    assert response.status_code == 404
    assert response.json["error"] == "Monitored service not found."
