import pytest

from app import app
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


def test_home_page_disables_scanning_for_hosted_requests():
    response = app.test_client().get(
        "/",
        headers={"Host": "webguard-2prs.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 200
    assert b'<button type="submit" disabled>Scan target</button>' in response.data
    assert b"Scanning is available only when WebGuard runs locally." in response.data


def test_scan_endpoint_rejects_hosted_requests():
    response = app.test_client().post(
        "/api/scan",
        json={"target": "http://127.0.0.1:3000"},
        headers={"Host": "webguard-2prs.onrender.com"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )

    assert response.status_code == 403


def test_scan_endpoint_rejects_non_loopback_targets():
    response = app.test_client().post(
        "/api/scan",
        json={"target": "https://example.com"}
    )

    assert response.status_code == 400
    assert "Only localhost and loopback targets are allowed." in response.json["error"]


def test_local_scan_saves_result_to_history(monkeypatch):
    report = {
        "target": "http://127.0.0.1:3000/",
        "findings_count": 0,
        "risk_level": "Low"
    }
    saved_reports = []
    scanned_targets = []

    def scan_target(target):
        validate_target(target)
        scanned_targets.append(target)
        return report

    monkeypatch.setattr("app.scan_target", scan_target)
    monkeypatch.setattr("app.connect_database", lambda: None)
    monkeypatch.setattr("app.save_scan_result", saved_reports.append)
    monkeypatch.setattr("app.close_database", lambda: None)

    response = app.test_client().post(
        "/api/scan",
        json={"target": "http://127.0.0.1:3000/#/"}
    )

    assert response.status_code == 200
    assert response.json["report"] == report
    assert response.json["history_saved"] is True
    assert scanned_targets == [report["target"]]
    assert saved_reports == [report]
