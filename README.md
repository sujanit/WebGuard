# WebGuard v1.1.0

**A Python web application security scanner and service availability monitor with finite-state-machine integration.**

## Overview

WebGuard scans web applications for common security misconfigurations and periodically checks configured public service endpoints for availability.

It analyzes HTTP responses, identifies missing security headers, evaluates cookie security and generates risk assessments with remediation suggestions.

## Features

- Security header analysis
- Cookie security checks
- HTTPS configuration detection
- HTTP response analysis
- Risk scoring and severity classification
- JSON, CSV and HTML report generation
- Scan history tracking
- Periodic HTTP service availability monitoring with response-time measurements
- Healthy, Slow, Unavailable, Recovering, and Restored service states
- Availability change notifications and per-service history
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

## MongoDB Atlas

1. Create an Atlas cluster and a database user.
2. In **Network Access**, allow your current IP address.
3. In the cluster's **Connect** dialog, choose **Drivers** and copy the Python connection string.
4. Copy `.env.example` to `.env`, then set `MONGODB_URI` to that connection string and replace its username, password, and cluster host. URL-encode special characters in the password. Keep `.env` private; it is ignored by Git.

   ```powershell
   Copy-Item .env.example .env
   ```

5. Optionally change `MONGODB_DATABASE` (defaults to `webguard`).

Install dependencies, then verify the connection from the project directory:

```powershell
python -c "from database import connect_database, close_database; connect_database(); close_database()"
```

The Flask dashboard reuses its MongoClient connection pool while running and closes it when the process exits.

## Service Availability Monitoring

Set `MONITORED_SERVICES_JSON` to a JSON array of named health-check URLs. Configure this variable in Render's environment settings for the deployed app, or in your local `.env` file:

```text
MONITORED_SERVICES_JSON=[{"name":"Public API","url":"https://api.example.com/health"},{"name":"Status Page","url":"https://status.example.com/"}]
```

Only configure public HTTP(S) endpoints that you own or are authorized to monitor. The monitor rejects private/reserved destinations, URL credentials, query strings, and fragments, and does not follow redirects. Keep credentials out of health-check URLs.

Checks start when the app process starts and repeat every 60 seconds. Each request has a 5-second timeout; successful responses taking more than 1 second are classified as **Slow**. Connection failures and HTTP errors (status 400 or above) are **Unavailable**. After an outage, one successful check is **Recovering** and two consecutive successful checks mark the service **Restored**; the next check classifies it as **Healthy** or **Slow**. A maximum of 20 services can be configured.

The dashboard refreshes its service state and event notifications every 15 seconds. Use **View** to open recent per-service check history. Check history is stored in MongoDB Atlas and expires after 30 days. With no configured services, the dashboard displays setup instructions instead of performing checks.

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

Latest recorded result: **87 tests passed.**

## Security Scope

The local scanner accepts localhost and loopback targets. The hosted Render dashboard is restricted to the exact origin listed in `webguard/config.py`; it rejects loopback and other external targets.

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

GitHub:https://github.com/sujanit
---

*WebGuard – Local Web Application Security Scanner*
 