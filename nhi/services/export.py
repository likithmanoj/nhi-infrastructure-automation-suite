import csv
import json


def export_inventory(inventory, filename):
    with open(filename, "w") as inventory_file:
        json.dump(inventory, inventory_file, default=str)
        return filename


def export_findings_to_csv(findings: list[dict], filepath: str) -> str:
    """Exports evaluated findings to a user-specified CSV file path."""
    if not findings:
        print("[!] No findings available to export to CSV.")
        return filepath

    headers = list({k for finding in findings for k in finding.keys()})

    priority_order = [
        "IdentityName",
        "IdentityType",
        "RuleID",
        "Severity",
        "Finding",
        "PolicyName",
        "RemediationEligible",
        "Action",
        "Resource",
    ]
    sorted_headers = [h for h in priority_order if h in headers] + [
        h for h in headers if h not in priority_order
    ]

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sorted_headers, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)

    print(f"[*] Findings exported to CSV: {filepath}")
    return filepath