
from requests import Response
from requests.cookies import create_cookie

from webguard.checks import inspect_headers, inspect_cookies


# Test 1: Detect missing security headers
def test_missing_security_headers():
    headers = {
        "Content-Type": "text/html"
    }

    findings = inspect_headers(headers)

    assert len(findings) == 6


# Test 2: No findings when all security headers exist
def test_present_security_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()"
    }

    findings = inspect_headers(headers)

    assert len(findings) == 0


# Test 3: Detect cookies missing security attributes
def test_cookie_missing_security_attributes():
    response = Response()

    response.cookies.set_cookie(
        create_cookie(
            name="sessionid",
            value="test-value",
            rest={}
        )
    )

    findings = inspect_cookies(response)

    assert len(findings) == 1
    assert "Secure" in findings[0]["evidence"]
    assert "HttpOnly" in findings[0]["evidence"]
    assert "SameSite" in findings[0]["evidence"]


# Test 4: No findings when cookie security attributes exist
def test_cookie_with_security_attributes():
    response = Response()

    response.cookies.set_cookie(
        create_cookie(
            name="sessionid",
            value="test-value",
            secure=True,
            rest={
                "HttpOnly": True,
                "SameSite": "Strict"
            }
        )
    )

    findings = inspect_cookies(response)

    assert len(findings) == 0
