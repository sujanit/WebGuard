# WebGuard v1.1.0

**A Python-based local web application security scanner with FLAT Engine and Finite State Machine integration.**

## Overview

WebGuard is a Python-based security scanner designed to identify common web application security misconfigurations in locally hosted applications.

It analyzes HTTP responses, identifies missing security headers, evaluates cookie security and generates risk assessments with remediation suggestions.

## Features

- Security header analysis
- Cookie security checks
- HTTPS configuration detection
- HTTP response analysis
- Risk scoring and severity classification
- JSON, CSV and HTML report generation
- Scan history tracking
- FLAT Engine integration
- Regular-expression-based URL and header validation
- DFA-based HTTP/HTTPS scheme validation
- FSM-based scan lifecycle management

## FLAT Engine – v1.1.0

The FLAT Engine introduces formal language concepts into WebGuard:

- Regular Expressions (RE): URL and HTTP header-name validation.
- Deterministic Finite Automaton (DFA): HTTP and HTTPS scheme validation.
- Finite State Machine (FSM): Scan workflow tracking.

### Scan workflow

`INITIALIZED → VALIDATING → SCANNING → ANALYZING → REPORTING → COMPLETED`

## Technology Stack

- Python
- Requests
- Regular Expressions
- Finite Automata
- Finite State Machines
- Pytest
- Docker
- OWASP Juice Shop

## Installation

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd WebGuard

python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Start the local OWASP Juice Shop testing environment:

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Run WebGuard in another terminal:

```bash
python main.py --target http://127.0.0.1:3000 --format all --history
```

## Example Scan Results

| Metric | Result |
|---|---|
| Target | 127.0.0.1:3000 |
| HTTP Status | 200 |
| Findings | 5 |
| Risk Score | 24 |
| Risk Level | High |
| FLAT Engine | 1.1.0 |
| Scan Status | COMPLETED |

*Example results from a local OWASP Juice Shop test. Risk scoring is WebGuard's own heuristic, not CVSS.*

## Testing

Run the automated test suite:

```bash
python -m pytest -v
```

Latest recorded result: **54 tests passed.**

## Security Scope

WebGuard is designed for local testing environments. Its target validation restricts scanning to localhost and loopback IP addresses.

Only scan applications you own or have explicit permission to test.

## Version History

### v1.1.0
- Integrated FLAT Engine.
- Added DFA-based scheme validation.
- Added FSM scan lifecycle management.
- Added scan-state history metadata.
- Updated scan reporting integration.

## Author

**Sujan S**

GitHub: Add your GitHub profile link here.

---

*WebGuard – Local Web Application Security Scanner*