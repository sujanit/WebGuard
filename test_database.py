from database import (
    connect_database,
    get_scan_history,
    close_database
)

try:
    connect_database()

    scans = get_scan_history()

    print("\nWEBGUARD MONGODB SCAN HISTORY")
    print("=" * 40)

    for scan in scans:
        print("\nTarget:", scan.get("target"))
        print("Risk Score:", scan.get("risk_score"))
        print("Risk Level:", scan.get("risk_level"))
        print("Findings:", scan.get("findings_count"))
        print("Scan Status:", scan.get("scan_status"))

    print("\nTotal scans:", len(scans))

finally:
    close_database()