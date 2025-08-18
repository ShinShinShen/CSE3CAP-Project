import argparse
import os
from config.config_loader import load_config
#import parser.rule_parser as rule_parser
#import checker.rule_checker as rule_checker
from checker import rule_checker
from parser import rule_parser


def main():
    # CLI arguments
    parser = argparse.ArgumentParser(description="Firewall Risk Identification Tool - FireFind")
    parser.add_argument("-f", "--file", required=True, help="Path to vendor CSV export")
    parser.add_argument("-v", "--vendor", help="Vendor name (optional, auto-detect if not provided)")
    args = parser.parse_args()

    # Load configuration from JSON
    config = load_config()

    # Step 1: Detect vendor (if not given)
    if args.vendor:
        vendor = args.vendor.lower()
    else:
        vendor = rule_parser.detect_vendor(args.file)

    print(f"\n File Provided: {os.path.basename(args.file)}")
    print(f" Vendor Detected: {vendor}")

    # Step 2: Parse CSV using vendor mapping
    try:
        rules = rule_parser.parse_csv(args.file)
    except NotImplementedError as e:
        print(f" {e}")
        return
    except Exception as e:
        print(f" Error parsing file: {e}")
        return

    # Step 3: Run risk checks
    results = rule_checker.run_checker(rules)

    # Step 4: Display findings
    print("\n Risk Analysis Results:")
    for rule_id, findings in results.items():
        if findings:
            print(f"\nRule: {rule_id}")
            for finding in findings:
                print(f"  - [{finding['severity']}] {finding['issue']}")
        else:
            print(f"\nRule: {rule_id} -  No issues found")

if __name__ == "__main__":
    main()
