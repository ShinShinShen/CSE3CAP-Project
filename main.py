# This will be the beginning of our project, starting from this python file.
# --------------------------------------
#  FireFind CLI - Firewall Risk Identification Tool
# --------------------------------------

#test one
# Temporary module imports (to be implemented by teammates)
try:
    import rule_parser
    import rule_checker
except ImportError as e:
    print(f"Error importing modules: {e}")
    exit(1)

import argparse

def main():
    parser_cli = argparse.ArgumentParser(description="FireFind CLI - Firewall Risk Identification Tool")

    parser_cli.add_argument("-f", "--file", required=True, help="Path to firewall rule CSV/XLSX file")
    parser_cli.add_argument("-v", "--vendor", required=True, choices=["fortinet", "sophos", "checkpoint", "barracuda"], help="Vendor type for normalization")
    parser_cli.add_argument("--csv", action="store_true", help="Generate CSV report")
    parser_cli.add_argument("--pdf", action="store_true", help="Generate PDF report")

    args = parser_cli.parse_args()

    print("\n📥 File Provided:", args.file)
    print("🏷️ Vendor:", args.vendor)

    if args.csv:
        print("📝 Will generate CSV output")
    if args.pdf:
        print("📄 Will generate PDF output")

    # Parse the file into rules
    rules = rule_parser.parse_csv(args.file)

    # Check rules for risks
    findings = rule_checker.run_checker(rules)

    print("\n Findings Summary:")
    for rule_id, issues in findings.items():
        print(f"\nRule ID: {rule_id}")
        for issue in issues:
            print(f"  - Issue: {issue['issue']}, Severity: {issue['severity']}")

if __name__ == "__main__":
    main()
