
import pytest

from webguard.scanner import validate_target


def test_localhost_is_allowed():
    assert validate_target("http://localhost:3000") is True


def test_loopback_ip_is_allowed():
    assert validate_target("http://127.0.0.1:3000") is True


def test_external_target_is_rejected():
    with pytest.raises(ValueError):
        validate_target("https://example.com")


def test_invalid_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_target("ftp://localhost")


def test_url_with_path_is_rejected():
    with pytest.raises(ValueError):
        validate_target("http://127.0.0.1:3000/login")


def test_url_with_credentials_is_rejected():
    with pytest.raises(ValueError):
        validate_target("http://user:pass@localhost:3000")
