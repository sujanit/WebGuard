
import ipaddress
from urllib.parse import urlparse

import requests

from webguard.checks import (
    inspect_headers,
    inspect_cookies,
    inspect_https,
    inspect_http_methods,
    inspect_server_information
)

from webguard.risk import calculate_risk

from webguard.config import (
    REQUEST_TIMEOUT,
    VERIFY_TLS,
    FOLLOW_REDIRECTS
)


def validate_target(url):

    parsed = urlparse(url)

    # Allow only HTTP and HTTPS
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "Only HTTP and HTTPS URLs are allowed."
        )

    # Validate hostname
    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    # Reject embedded credentials
    if parsed.username or parsed.password:
        raise ValueError(
            "Credentials in URLs are not allowed."
        )

    host = parsed.hostname.lower()

    # Allow localhost or literal loopback IP addresses
    is_localhost = host == "localhost"

    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False

    if not (is_localhost or is_loopback):
        raise ValueError(
            "Only localhost and loopback targets are allowed."
        )

    # Only allow base URLs
    if (
        parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Enter only the base URL without paths or query parameters."
        )

    return True


def scan_target(url):

    validate_target(url)

    session = requests.Session()

    # Ignore inherited proxy configuration
    session.trust_env = False

    try:

        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=FOLLOW_REDIRECTS,
            verify=VERIFY_TLS
        )

        # Analyze security headers
        header_findings = inspect_headers(
            response.headers
        )

        # Analyze cookies
        cookie_findings = inspect_cookies(
            response
        )

        # Analyze HTTPS configuration
        https_findings = inspect_https(
            url
        )

        # Analyze HTTP methods
        method_findings = inspect_http_methods(
            response
        )

        # Analyze server information
        server_findings = inspect_server_information(
            response
        )

        # Combine findings
        all_findings = (
            header_findings
            + cookie_findings
            + https_findings
            + method_findings
            + server_findings
        )

        # Calculate risk
        risk = calculate_risk(all_findings)

        return {
            "target": url,
            "status_code": response.status_code,
            "findings_count": len(all_findings),
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "findings": all_findings,
            "scope": "Local loopback target only"
        }

    finally:
        session.close()
