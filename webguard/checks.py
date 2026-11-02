
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Helps prevent content injection attacks."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Enforces HTTPS connections."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Helps prevent MIME-type sniffing."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Helps protect against clickjacking."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls referrer information sharing."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Controls access to browser features."
    }
}


def inspect_headers(headers):
    findings = []

    for header, details in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "title": f"Missing {header}",
                "severity": details["severity"],
                "confidence": "High",
                "evidence": f"Response did not include {header}.",
                "remediation": details["description"]
            })

    return findings


def inspect_cookies(response):
    findings = []

    for cookie in response.cookies:
        missing = []

        # Read cookie attributes case-insensitively
        rest = {
            str(key).lower(): value
            for key, value in cookie._rest.items()
        }

        # Secure attribute
        if not cookie.secure:
            missing.append("Secure")

        # HttpOnly attribute
        if "httponly" not in rest:
            missing.append("HttpOnly")

        # SameSite attribute
        if "samesite" not in rest:
            missing.append("SameSite")

        if missing:
            findings.append({
                "title": f"Cookie security review: {cookie.name}",
                "severity": "Low",
                "confidence": "Medium",
                "evidence": (
                    f"Cookie '{cookie.name}' is missing or does not "
                    f"expose: {', '.join(missing)}"
                ),
                "remediation": (
                    "Review the cookie's purpose and configure "
                    "appropriate Secure, HttpOnly and SameSite attributes."
                )
            })

    return findings
def inspect_https(url):
    findings = []

    if not url.lower().startswith("https://"):
        findings.append({
            "title": "HTTPS Not Enabled",
            "severity": "Medium",
            "confidence": "High",
            "evidence": "The target is using HTTP instead of HTTPS.",
            "remediation": (
                "Configure HTTPS with a valid TLS certificate "
                "to protect data in transit."
            )
        })

    return findings
def inspect_http_methods(response):
    findings = []

    allowed_methods = response.headers.get("Allow", "")

    risky_methods = ["TRACE", "PUT", "DELETE", "CONNECT"]

    for method in risky_methods:
        if method in allowed_methods.upper():
            findings.append({
                "title": f"Potentially Risky HTTP Method: {method}",
                "severity": "Medium",
                "confidence": "Medium",
                "evidence": (
                    f"The server advertises the {method} HTTP method."
                ),
                "remediation": (
                    f"Disable {method} if it is not required "
                    "for the application's functionality."
                )
            })

    return findings
def inspect_server_information(response):
    findings = []

    information_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version"
    ]

    for header in information_headers:
        value = response.headers.get(header)

        if value:
            findings.append({
                "title": f"Server Information Disclosure: {header}",
                "severity": "Low",
                "confidence": "High",
                "evidence": f"{header}: {value}",
                "remediation": (
                    "Remove unnecessary server identification "
                    "headers to reduce information exposure."
                )
            })

    return findings
