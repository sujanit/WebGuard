import pytest

from app import app


@pytest.mark.parametrize("path", ["/", "/cn", "/flat", "/fswd"])
def test_dashboards_are_public_without_authentication_config(path, monkeypatch):
    monkeypatch.delenv("WEBGUARD_USERNAME", raising=False)
    monkeypatch.delenv("WEBGUARD_PASSWORD", raising=False)

    response = app.test_client().get(path)

    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers


def test_home_page_shows_scan_target_placeholder():
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b'id="scanTarget"' in response.data
    assert b'placeholder="http://localhost:3000"' in response.data
    assert b'<button type="button" disabled>Scan target</button>' in response.data
    assert b"Scanning is not available from the hosted dashboard yet." in response.data
