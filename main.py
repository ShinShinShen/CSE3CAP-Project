import argparse
import os
import curses
from config.config_loader import load_config
from file_browser.file_browser_with_subwindow import file_browser
from checker import rule_checker
from parser import rule_parser
import csv

# -----------------------
# Helper functions
# -----------------------

def start_menu():
    print("\n==========================================")
    print("    Welcome to FireFind - Firewall CLI")
    print("==========================================\n")
    print("Please select an option:")
    print("1. Open File Browser to select firewall file (CSV/XLSX)")
    print("2. Exit\n")

    while True:
        choice = input("Enter your choice (1-2): ").strip()
        if choice == "1":
            return "browse"
        elif choice == "2":
            return "exit"
        else:
            print("Invalid choice, please enter 1 or 2.")

def export_findings_to_csv(results, output_path):
    """
    Writes the findings dictionary to a CSV file.
    Each row corresponds to a single finding for a rule.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["rule_id", "issue", "severity"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rule_id, findings in results.items():
            if not findings:
                writer.writerow({"rule_id": rule_id, "issue": "No issues found", "severity": ""})
            else:
                for finding in findings:
                    writer.writerow({
                        "rule_id": rule_id,
                        "issue": finding["issue"],
                        "severity": finding["severity"]
                    })

    print(f"\nTechnical findings exported to {output_path}")

# -----------------------
# Main program
# -----------------------

def main():
    parser_args = argparse.ArgumentParser(description="Firewall Risk Identification Tool - FireFind")
    parser_args.add_argument("-f", "--file", help="Path to vendor file (CSV/XLSX)")
    parser_args.add_argument("-v", "--vendor", help="Vendor name (optional, auto-detect)")
    args = parser_args.parse_args()

    config = load_config()

    # -------------------------
    # If a file is provided via CLI
    # -------------------------
    if args.file:
        file_path = args.file
        vendor = args.vendor.lower() if args.vendor else rule_parser.detect_vendor(file_path)
        print(f"\n File Provided: {os.path.basename(file_path)}")
        print(f" Vendor Detected: {vendor}")

        try:
            rules = rule_parser.parse_file(file_path, vendor=vendor)
        except Exception as e:
            print(f"Error parsing file: {e}")
            return

        if not rules:
            print("No rules found in the file.")
            return

        results = rule_checker.run_checker(rules)

        # Display results in CLI
        print("\n Risk Analysis Results:")
        for rule_id, findings in results.items():
            if findings:
                print(f"\nRule: {rule_id}")
                for finding in findings:
                    print(f"  - [{finding['severity']}] {finding['issue']}")
            else:
                print(f"\nRule: {rule_id} - No issues found")

        # Export to CSV
        output_file = os.path.join("output", f"{os.path.splitext(os.path.basename(file_path))[0]}_findings.csv")
        export_findings_to_csv(results, output_file)
        return

    # -------------------------
    # No file: use interactive CLI + file browser
    # -------------------------
    while True:
        user_choice = start_menu()
        if user_choice == "exit":
            print("Goodbye!")
            return
        elif user_choice == "browse":
            try:
                file_path = curses.wrapper(file_browser, os.getcwd())
            except Exception as e:
                print(f"File browser error: {e}")
                continue

            if file_path is None:
                continue

        vendor = args.vendor.lower() if args.vendor else rule_parser.detect_vendor(file_path)
        print(f"\n File Provided: {os.path.basename(file_path)}")
        print(f" Vendor Detected: {vendor}")

        try:
            rules = rule_parser.parse_file(file_path, vendor=vendor)
        except Exception as e:
            print(f"Error parsing file: {e}")
            continue

        if not rules:
            print("No rules found in the file. Returning to main menu.")
            continue

        results = rule_checker.run_checker(rules)

        print("\n Risk Analysis Results:")
        for rule_id, findings in results.items():
            if findings:
                print(f"\nRule: {rule_id}")
                for finding in findings:
                    print(f"  - [{finding['severity']}] {finding['issue']}")
            else:
                print(f"\nRule: {rule_id} - No issues found")

        output_file = os.path.join("output", f"{os.path.splitext(os.path.basename(file_path))[0]}_findings.csv")
        export_findings_to_csv(results, output_file)

        args.vendor = None

#  Entry point
if __name__ == "__main__":
    main()
