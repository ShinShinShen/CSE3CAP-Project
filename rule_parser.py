import csv
import os
from config.config_loader import load_config

# Load JSON config at the top
config = load_config()


def detect_vendor(file_path):
    """
    Detects vendor type based on the CSV headers and config vendor mappings.
    """
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        headers = [h.strip().lower() for h in next(csv.reader(csvfile))]

    for vendor, mapping in config.data["vendor_mappings"].items():
        for required_header in mapping.get("detect_headers_any", []):
            if required_header.lower() in headers:
                return vendor
    return None


def parse_csv(file_path, vendor=None):
    """
    Parses CSV rules into a standardised format using vendor mappings from config.
    """
    if not vendor:
        vendor = detect_vendor(file_path)
    if not vendor:
        print(" Could not detect vendor.")
        return []

    print(f" Vendor Detected: {vendor}")

    mappings = config.data["vendor_mappings"].get(vendor)
    if not mappings:
        print(f" No vendor mapping found for: {vendor}")
        return []

    columns_map = mappings.get("columns", {})
    defaults = mappings.get("defaults", {})

    rules = []
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                parsed_rule = {}
                for standard_field, vendor_fields in columns_map.items():
                    value = ""
                    for vendor_field in vendor_fields:
                        if vendor_field in row and row[vendor_field].strip():
                            value = row[vendor_field].strip()
                            break
                    if not value:
                        value = defaults.get(standard_field, "")
                    parsed_rule[standard_field] = value
                rules.append(parsed_rule)
    except Exception as e:
        print(f" Error parsing file: {e}")
        return []

    return rules
