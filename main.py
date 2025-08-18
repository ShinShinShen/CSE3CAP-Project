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
    print("1. Open File Browser to select firewall CSV")
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
    # Ensure output folder exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["rule_id", "issue", "severity"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rule_id, findings in results.items():
            if not findings:
                # Row indicating no issues
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
    # CLI arguments
    parser_args = argparse.ArgumentParser(description="Firewall Risk Identification Tool - FireFind")
    parser_args.add_argument("-f", "--file", help="Path to vendor CSV export")  # optional now
    parser_args.add_argument("-v", "--vendor", help="Vendor name (optional, auto-detect)")
    args = parser_args.parse_args()

    # Load configuration from JSON
    config = load_config()

    # If a file is provided via CLI, just process it once and exit
    if args.file:
        file_path = args.file
        vendor = args.vendor.lower() if args.vendor else rule_parser.detect_vendor(file_path)
        print(f"\nFile Provided: {os.path.basename(file_path)}")
        print(f"Vendor Detected: {vendor}")

        try:
            rules = rule_parser.parse_csv(file_path)
        except Exception as e:
            print(f"Error parsing file: {e}")
            return

        if not rules:
            print("No rules found in the file.")
            return

        results = rule_checker.run_checker(rules)

        # Display findings
        print("\nRisk Analysis Results:")
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

        return  # Exit after processing CLI file

    # -------------------------
    # No file provided: enter menu loop
    # -------------------------
    while True:
        # Show menu before opening file browser
        user_choice = start_menu()
        if user_choice == "exit":
            print("Goodbye!")
            return
        elif user_choice == "browse":
            file_path = curses.wrapper(file_browser, os.getcwd())
            if file_path is None:
                continue  # user canceled, back to menu

        # Step 1: Detect vendor
        vendor = args.vendor.lower() if args.vendor else rule_parser.detect_vendor(file_path)
        print(f"\nFile Provided: {os.path.basename(file_path)}")
        print(f"Vendor Detected: {vendor}")

        # Step 2: Parse CSV
        try:
            rules = rule_parser.parse_csv(file_path)
        except Exception as e:
            print(f"Error parsing file: {e}")
            continue  # back to menu

        if not rules:
            print("No rules found in the file. Returning to main menu.")
            continue

        # Step 3: Run risk checks
        results = rule_checker.run_checker(rules)

        # Step 4: Display findings
        print("\nRisk Analysis Results:")
        for rule_id, findings in results.items():
            if findings:
                print(f"\nRule: {rule_id}")
                for finding in findings:
                    print(f"  - [{finding['severity']}] {finding['issue']}")
            else:
                print(f"\nRule: {rule_id} - No issues found")

        # Step 5: Export to CSV
        output_file = os.path.join("output", f"{os.path.splitext(os.path.basename(file_path))[0]}_findings.csv")
        export_findings_to_csv(results, output_file)

        # Reset args.vendor for next iteration if menu is used again
        args.vendor = None

if __name__ == "__main__":
    main()
