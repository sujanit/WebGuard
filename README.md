
# WebGuard
### Automated Web Application Security Assessment Tool

WebGuard is a Python-based web application security assessment tool designed to identify common web security misconfigurations, evaluate security risks, and generate detailed security reports.

It is developed as a cybersecurity learning and portfolio project using OWASP Juice Shop as a local testing environment.

## Features

- HTTP security header analysis
- Cookie security flag inspection
- HTTPS scheme detection
- HTTP Allow header inspection
- Server header information detection
- Localhost-only target validation
- Custom risk scoring and severity classification
- HTML, JSON and CSV security reports
- Scan history and scan comparison
- Security event logging
- Vulnerability remediation tracking
- Remediation dashboard with progress visualization
- Remediation report export
- Automated unit testing

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Requests | HTTP communication |
| Pytest | Automated testing |
| HTML/CSS | Report dashboards |
| JSON | Report and tracker storage |
| CSV | Report export |
| Docker | Local testing environment |
| OWASP Juice Shop | Vulnerable test application |

## Project Structure

```text
WebGuard/
│
├── webguard/
│   ├── __init__.py
│   ├── checks.py
│   ├── scanner.py
│   ├── reporter.py
│   ├── risk.py
│   ├── logger.py
│   ├── config.py
│   ├── remediation.py
│   ├── remediation_cli.py
│   ├── remediation_dashboard.py
│   └── remediation_export.py
│
├── tests/
│   ├── test_checks.py
│   ├── test_risk.py
│   ├── test_scanner.py
│   └── test_remediation.py
│
├── reports/
├── logs/
├── main.py
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd WebGuard
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Start the Testing Environment

Install Docker Desktop and start OWASP Juice Shop:

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Keep the container running while testing.

## Usage

### Run a security assessment

```bash
python main.py --target http://127.0.0.1:3000 --format all --history
```

### Generate remediation dashboard

```bash
python -m webguard.remediation_dashboard
```

### Export remediation report

```bash
python -m webguard.remediation_export
```

### View remediation findings

```bash
python -m webguard.remediation_cli --list
```

### Update remediation status

```bash
python -m webguard.remediation_cli --update FINDING_ID Fixed --notes "Security configuration reviewed and corrected."
```

### Run automated tests

```bash
python -m pytest -v
```

## Generated Reports

WebGuard generates:

- `webguard-report.json` – Structured security findings
- `webguard-report.html` – Security assessment dashboard
- `webguard-report.csv` – Findings in spreadsheet format
- `scan-history.json` – Previous scan records
- `remediation-tracker.json` – Remediation tracking information
- `remediation-dashboard.html` – Remediation progress dashboard
- `remediation-report.csv` – Remediation export

## Risk Assessment

WebGuard uses a custom heuristic risk scoring system to classify findings into:

- Critical
- High
- Medium
- Low

The score is a project-specific prioritization mechanism and is not a CVSS score.

## Security and Limitations

- The scanner is restricted to localhost and loopback targets.
- Redirect following is disabled.
- The scanner performs non-invasive checks.
- HTTP method inspection relies on the server's `Allow` response header.
- HTTPS scheme detection does not constitute a complete TLS certificate assessment.
- Findings indicate potential security misconfigurations and require manual verification.
- A remediation status marked Fixed must be independently verified.

Only use WebGuard against systems you own or have explicit permission to assess.

## Future Enhancements

- Additional OWASP security checks
- More detailed TLS configuration assessment
- Interactive remediation management
- Enhanced vulnerability classification
- PDF report generation
- Improved dashboard analytics

## Author

**Sujan S**

Cybersecurity | Ethical Hacking | Python Development

## Disclaimer

WebGuard is an educational cybersecurity project intended for authorized security testing and learning. The developer is not responsible for unauthorized use.
