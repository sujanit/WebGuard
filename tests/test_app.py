import pytest

from app import app


@pytest.mark.parametrize("path", ["/", "/cn", "/flat", "/fswd"])
def test_dashboards_are_public_without_authentication_config(path, monkeypatch):
    monkeypatch.delenv("WEBGUARD_USERNAME", raising=False)
    monkeypatch.delenv("WEBGUARD_PASSWORD", raising=False)

    response = app.test_client().get(path)

    assert response.status_code == 200
    assert "WWW-Authenticate" not in response.headers
