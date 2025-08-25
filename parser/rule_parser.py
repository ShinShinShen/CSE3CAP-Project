import csv
import os
import pandas as pd  # NEW: for XLSX support
from config.config_loader import load_config

# Load JSON config at the top
config = load_config()


def detect_vendor(file_path):
    """
    Detects vendor type based on the headers and config vendor mappings.
    Works for both CSV and XLSX files.
    """
    headers = []

    # Handle CSV
    if file_path.endswith(".csv"):
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            headers = [h.strip().lower() for h in next(csv.reader(csvfile))]

    # Handle XLSX
    elif file_path.endswith(".xlsx"):
        df = pd.read_excel(file_path, sheet_name=0, dtype=str)
        # Find the header row (Fortinet files have metadata above headers)
        for i, row in df.iterrows():
            if any(str(cell).strip().lower() in ["id", "action", "source", "destination", "service"] for cell in row.values):
                headers = [str(h).strip().lower() for h in row.values]
                break

    # Vendor detection using config
    for vendor, mapping in config.data["vendor_mappings"].items():
        for required_header in mapping.get("detect_headers_any", []):
            if required_header.lower() in headers:
                return vendor
    return None


def parse_file(file_path, vendor=None):
    """
    Parses rules into a standardized format using vendor mappings from config.
    Supports both CSV and XLSX input files.
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
        if file_path.endswith(".csv"):
            # Standard CSV parsing
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

        elif file_path.endswith(".xlsx"):
            # Excel parsing with pandas
            df = pd.read_excel(file_path, sheet_name=0, dtype=str)
            # Find the header row
            header_row_index = None
            for i, row in df.iterrows():
                if any(str(cell).strip().lower() in ["id", "action", "source", "destination", "service"] for cell in row.values):
                    header_row_index = i
                    break

            if header_row_index is None:
                print(" Could not find header row in XLSX.")
                return []

            df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=header_row_index)
            df = df.fillna("")  # Replace NaN with empty strings

            for _, row in df.iterrows():
                parsed_rule = {}
                for standard_field, vendor_fields in columns_map.items():
                    value = ""
                    for vendor_field in vendor_fields:
                        if vendor_field in df.columns and str(row[vendor_field]).strip():
                            value = str(row[vendor_field]).strip()
                            break
                    if not value:
                        value = defaults.get(standard_field, "")
                    parsed_rule[standard_field] = value
                rules.append(parsed_rule)

    except Exception as e:
        print(f" Error parsing file: {e}")
        return []

    return rules
