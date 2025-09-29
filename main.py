import argparse
import os
import curses
import csv
from config.config_loader import load_config
from file_browser.file_browser_with_subwindow import file_browser
from checker import rule_checker
from parser_utils import rule_parser
from report.pdf_report import PDFReport


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
    """Writes findings dictionary to a CSV file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["rule_id", "issue", "field", "value", "severity", "category"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rule_id, findings in results.items():
            if not findings:
                writer.writerow({
                    "rule_id": rule_id,
                    "issue": "No issues found",
                    "field": "-",
                    "value": "-",
                    "severity": "",
                    "category": "-"
                })
            else:
                for finding in findings:
                    writer.writerow({
                        "rule_id": rule_id,
                        "issue": finding["issue"],
                        "field": finding.get("field", "-"),
                        "value": finding.get("value", "-"),
                        "severity": finding["severity"],
                        "category": finding.get("category", "-")
                    })

    print(f"\n Technical findings exported to {output_path}")


def export_findings_to_pdf(results, file_path, output_pdf, vendor=None):
    """Generate PDF report from findings."""
    findings = []
    severity_count = {}
    category_count = {}

    for rid, issues in results.items():
        if not issues:
            findings.append({
                "rule_id": rid,
                "issue_type": "No issues found",
                "field": "-",
                "value": "-",
                "severity": "INFO",
                "category": "-"
            })
            severity_count["INFO"] = severity_count.get("INFO", 0) + 1
        else:
            for f in issues:
                findings.append({
                    "rule_id": rid,
                    "issue_type": f.get("issue", ""),
                    "field": f.get("field", "-"),
                    "value": f.get("value", "-"),
                    "severity": f.get("severity", "UNKNOWN"),
                    "category": f.get("category", "-")
                })
                sev = f["severity"].upper()
                severity_count[sev] = severity_count.get(sev, 0) + 1
                cat = f.get("category", "-")
                category_count[cat] = category_count.get(cat, 0) + 1

    total_rules = len(results)
    total_risks = sum(1 for f in findings if f["issue_type"] != "No issues found")

    pdf = PDFReport()
    pdf.add_page()
    pdf.add_summary(os.path.basename(file_path), total_rules, total_risks, severity_count, vendor)
    pdf.add_charts(severity_count, category_count)
    pdf.add_table(findings)
    pdf.output(output_pdf)

    print(f" PDF report exported to {output_pdf}")


def process_file(file_path, vendor=None):
    vendor = vendor.lower() if vendor else rule_parser.detect_vendor(file_path)
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

    print("\n Risk Analysis Results:")
    for rule_id, findings in results.items():
        if findings:
            print(f"\nRule: {rule_id}")
            for finding in findings:
                print(
                    f"  - [{finding['severity']}] {finding['issue']} "
                    f"(Field: {finding.get('field','-')} | "
                    f"Value: {finding.get('value','-')} | "
                    f"Category: {finding.get('category','-')})"
                )
        else:
            print(f"\nRule: {rule_id} - No issues found")

    base_name = os.path.splitext(os.path.basename(file_path))[0]
    csv_path = os.path.join("output", f"{base_name}_findings.csv")
    pdf_path = os.path.join("output", f"{base_name}_report.pdf")

    export_findings_to_csv(results, csv_path)
    export_findings_to_pdf(results, file_path, pdf_path, vendor)


def main():
    parser_args = argparse.ArgumentParser(description="Firewall Risk Identification Tool - FireFind")
    parser_args.add_argument("-f", "--file", help="Path to vendor file (CSV/XLSX)")
    parser_args.add_argument("-v", "--vendor", help="Vendor name (optional, auto-detect)")
    args = parser_args.parse_args()

    if args.file:
        process_file(args.file, args.vendor)
        return

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

            process_file(file_path, args.vendor)
            args.vendor = None


if __name__ == "__main__":
    main()
