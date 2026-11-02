import argparse

from webguard.remediation import (
    load_tracker,
    update_remediation,
    get_remediation_summary
)


def list_findings():
    tracker = load_tracker()

    if not tracker:
        print("No findings registered yet.")
        return

    print("\n========== REMEDIATION FINDINGS ==========\n")

    for finding_id, finding in tracker.items():
        print(f"Finding ID : {finding_id}")
        print(f"Title      : {finding.get('title', 'Unknown')}")
        print(f"Severity   : {finding.get('severity', 'Info')}")
        print(f"Status     : {finding.get('status', 'Open')}")
        print(f"Notes      : {finding.get('notes', '')}")
        print("-" * 45)


def show_summary():
    summary = get_remediation_summary()

    print("\n========== REMEDIATION SUMMARY ==========")
    print(f"Total Findings      : {summary['total']}")
    print(f"Open                : {summary['open']}")
    print(f"In Progress         : {summary['in_progress']}")
    print(f"Fixed               : {summary['fixed']}")


def main():
    parser = argparse.ArgumentParser(
        description="WebGuard Remediation Management"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List all registered findings"
    )

    parser.add_argument(
        "--update",
        nargs=2,
        metavar=("FINDING_ID", "STATUS"),
        help="Update finding status"
    )

    parser.add_argument(
        "--notes",
        default="",
        help="Add remediation notes"
    )

    args = parser.parse_args()

    try:
        if args.update:
            finding_id, status = args.update

            finding = update_remediation(
                finding_id,
                status,
                args.notes
            )

            print("\nRemediation updated successfully!")
            print(f"Finding : {finding['title']}")
            print(f"Status  : {finding['status']}")
            print(f"Notes   : {finding['notes']}")

        elif args.list:
            list_findings()

        else:
            parser.print_help()

        show_summary()

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()