
import pytest

from webguard.flat_engine import FlatEngine


@pytest.fixture
def engine():
    return FlatEngine()


# URL validation tests

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:3000",
    "https://localhost",
    "http://localhost:5000",
    "https://127.0.0.1:8080",
])

def test_valid_urls(engine, url):
    assert engine.validate_url_pattern(url) is True


@pytest.mark.parametrize("url", [
    "ftp://localhost",
    "localhost:3000",
    "http://",
    "https://",
    "http://invalid url",
    "",
])

def test_invalid_urls(engine, url):
    assert engine.validate_url_pattern(url) is False


# HTTP header validation tests

@pytest.mark.parametrize("header", [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Type",
])

def test_valid_headers(engine, header):
    assert engine.validate_header_name(header) is True


@pytest.mark.parametrize("header", [
    "",
    "Content Security Policy",
    "Header:",
    "Invalid@Header",
    "Header Name",
])

def test_invalid_headers(engine, header):
    assert engine.validate_header_name(header) is False

# DFA URL Scheme Validation Tests

@pytest.mark.parametrize("url", [
    "http://localhost",
    "http://127.0.0.1:3000",
    "https://localhost",
    "https://127.0.0.1:8080",
])
def test_dfa_accepts_http_schemes(engine, url):
    assert engine.validate_url_scheme_dfa(url) is True


@pytest.mark.parametrize("url", [
    "ftp://localhost",
    "file:///etc/passwd",
    "invalid-url",
    "htp://localhost",
    "",
])
def test_dfa_rejects_invalid_schemes(engine, url):
    assert engine.validate_url_scheme_dfa(url) is False
