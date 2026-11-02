
import argparse
import sys
import requests

from webguard.scanner import scan_target

from webguard.reporter import (
    save_json,
    save_html,
    save_csv,
    save_history,
    compare_scans
)

from webguard.logger import get_logger

from webguard.remediation import (
    register_findings,
    get_remediation_summary
)


def display_banner():
    print("\n" + "=" * 40)
    print("       WEBGUARD SECURITY SCANNER")
    print("=" * 40)


def display_findings(report):
    """Display security findings in the terminal."""

    findings = report.get("findings", [])

    print("\n" + "=" * 40)
    print("          SECURITY FINDINGS")
    print("=" * 40)

    if not findings:
        print("\nNo security findings detected.")
        return

    for index, finding in enumerate(findings, start=1):

        print(f"\n[{index}] {finding.get('title', 'Unknown')}")
        print(f"Severity    : {finding.get('severity', 'Info')}")
        print(f"Confidence  : {finding.get('confidence', 'Unknown')}")
        print(f"Evidence    : {finding.get('evidence', 'Not available')}")
        print(f"Remediation : {finding.get('remediation', 'Not available')}")


def display_remediation_summary():
    """Display vulnerability remediation statistics."""

    summary = get_remediation_summary()

    print("\n" + "=" * 40)
    print("       REMEDIATION SUMMARY")
    print("=" * 40)

    print(f"Total Tracked Findings : {summary['total']}")
    print(f"Open                   : {summary['open']}")
    print(f"In Progress            : {summary['in_progress']}")
    print(f"Fixed                  : {summary['fixed']}")


def display_comparison(comparison):
    """Display scan comparison results."""

    print("\n" + "=" * 40)
    print("        SCAN COMPARISON")
    print("=" * 40)

    if comparison is None:
        print("Not enough previous scans for comparison.")
        return

    print(
        f"Previous Risk Score : {comparison['previous_risk']}"
    )

    print(
        f"Current Risk Score  : {comparison['current_risk']}"
    )

    print(
        f"Risk Change         : {comparison['risk_change']:+g}"
    )

    print(
        f"Previous Findings   : {comparison['previous_findings']}"
    )

    print(
        f"Current Findings    : {comparison['current_findings']}"
    )

    print(
        f"Findings Change     : {comparison['findings_change']:+d}"
    )

    print(
        f"Improvement         : {comparison['improvement_percentage']}%"
    )

    print(
        f"Assessment          : {comparison['status']}"
    )


def main():

    parser = argparse.ArgumentParser(
        description="WebGuard Automated Web Application Security Scanner"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Localhost or loopback target URL"
    )

    parser.add_argument(
        "--format",
        choices=["json", "html", "csv", "all"],
        default="all",
        help="Report output format"
    )

    parser.add_argument(
        "--history",
        action="store_true",
        help="Save scan history and display comparison"
    )

    args = parser.parse_args()

    logger = get_logger()

    logger.info("WebGuard application started")
    logger.info("Target selected: %s", args.target)
    logger.info("Report format: %s", args.format)

    display_banner()

    print(f"\nTarget: {args.target}")
    print(f"Report Format: {args.format}")

    print("\nStarting security assessment...\n")

    logger.info("Starting security assessment")

    try:

        # Step 1: Execute security scan
        report = scan_target(args.target)

        logger.info("HTTP request completed successfully")

        # Step 2: Register detected vulnerabilities
        tracker = register_findings(
            report.get("findings", [])
        )

        logger.info(
            "Remediation tracker updated: %s findings",
            len(tracker)
        )

        # Step 3: Display findings
        display_findings(report)

        # Step 4: Generate selected reports
        generated_reports = []

        if args.format in ("json", "all"):

            json_file = save_json(report)
            generated_reports.append(json_file)

            logger.info(
                "JSON report generated: %s",
                json_file
            )

        if args.format in ("html", "all"):

            html_file = save_html(report)
            generated_reports.append(html_file)

            logger.info(
                "HTML report generated: %s",
                html_file
            )

        if args.format in ("csv", "all"):

            csv_file = save_csv(report)
            generated_reports.append(csv_file)

            logger.info(
                "CSV report generated: %s",
                csv_file
            )

        # Step 5: Save history after HTML generation.
        # This allows the HTML dashboard to compare the
        # current scan against the previous saved scan.
        comparison = None

        if args.history:

            history_file = save_history(report)

            logger.info(
                "Scan history saved: %s",
                history_file
            )

            comparison = compare_scans(
                history_file,
                args.target
            )

        # Step 6: Display remediation summary
        display_remediation_summary()

        # Step 7: Display scan comparison
        if args.history:
            display_comparison(comparison)

        # Step 8: Display risk assessment
        print("\n" + "=" * 40)
        print("        ASSESSMENT SUMMARY")
        print("=" * 40)

        print(
            f"HTTP Status : {report.get('status_code', 'Unknown')}"
        )

        print(
            f"Risk Score  : {report.get('risk_score', 0)}"
        )

        print(
            f"Risk Level  : {report.get('risk_level', 'Unknown')}"
        )

        print(
            f"Findings    : {report.get('findings_count', 0)}"
        )

        # Step 9: Display generated report paths
        print("\n" + "=" * 40)
        print("        GENERATED REPORTS")
        print("=" * 40)

        for report_file in generated_reports:
            print(f"[+] {report_file}")

        print("[+] reports/remediation-tracker.json")

        if args.history:
            print("[+] reports/scan-history.json")

        print("\nSecurity assessment completed successfully.")

        logger.info("Security assessment completed successfully")

    except ValueError as error:

        logger.error("Validation error: %s", error)

        print(f"\n[!] Validation Error: {error}")

        sys.exit(1)

    except requests.RequestException as error:

        logger.error("HTTP request failed: %s", error)

        print(f"\n[!] HTTP request failed: {error}")

        sys.exit(1)

    except OSError as error:

        logger.error("File operation failed: %s", error)

        print(f"\n[!] File Error: {error}")

        sys.exit(1)

    except Exception as error:

        logger.exception("Unexpected application error")

        print(f"\n[!] Unexpected Error: {error}")

        sys.exit(1)


if __name__ == "__main__":
    main()
