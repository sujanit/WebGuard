
import pytest

from webguard.config import ALLOWED_SCAN_ORIGINS
from webguard.scanner import validate_target


def test_localhost_is_allowed():
    assert validate_target("http://localhost:3000") is True


def test_loopback_ip_is_allowed():
    assert validate_target("http://127.0.0.1:3000") is True


def test_external_target_is_rejected():
    with pytest.raises(ValueError):
        validate_target("https://example.com")


def test_allowlisted_external_origin_is_allowed():
    assert validate_target(
        ALLOWED_SCAN_ORIGINS[0] + "/",
        allowed_origins=ALLOWED_SCAN_ORIGINS,
        allow_loopback=False
    ) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://food-delivery-0db3.onrender.com/",
        "https://food-delivery-0db3.onrender.com:444/",
        "https://example.com/"
    ]
)
def test_non_allowlisted_origins_are_rejected(url):
    with pytest.raises(ValueError):
        validate_target(
            url,
            allowed_origins=ALLOWED_SCAN_ORIGINS,
            allow_loopback=False
        )


def test_render_mode_rejects_loopback_targets():
    with pytest.raises(ValueError):
        validate_target(
            "http://127.0.0.1:3000",
            allowed_origins=ALLOWED_SCAN_ORIGINS,
            allow_loopback=False
        )


def test_invalid_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_target("ftp://localhost")


def test_url_with_path_is_rejected():
    with pytest.raises(ValueError):
        validate_target("http://127.0.0.1:3000/login")


def test_url_with_credentials_is_rejected():
    with pytest.raises(ValueError):
        validate_target("http://user:pass@localhost:3000")
