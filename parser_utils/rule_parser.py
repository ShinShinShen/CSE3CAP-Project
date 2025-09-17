import csv
import pandas as pd
import re
from config.config_loader import load_config

config = load_config()

def detect_vendor(file_path):
    """Detect vendor type based on headers (CSV or XLSX)."""
    headers = []

    if file_path.endswith(".csv"):
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            reader = list(csv.reader(csvfile))

        # Flatten first rows for detection
        flat = [str(cell).strip().lower() for row in reader[:15] for cell in row]

        # Detect Client3 CSV by marker row
        if any("ipv4 local in policy" in cell for cell in flat):
            return "client3_csv"

        headers = [h.strip().lower() for h in reader[0]]

    elif file_path.endswith(".xlsx"):
        df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=None, engine="openpyxl")
        for _, row in df.iterrows():
            row_lower = [str(cell).strip().lower() for cell in row.values]
            if "seq #" in row_lower and "action" in row_lower:
                headers = row_lower
                break

    for vendor, mapping in config.data["vendor_mappings"].items():
        for required in mapping.get("detect_headers_any", []):
            if required.lower() in headers:
                return vendor
    return None


def get_col_value(row, df, field, mappings):
    """Fetch the value for a logical field (id, name, srcaddr, etc.) using vendor mappings."""
    for alias in mappings.get(field, []):
        alias = alias.lower().strip()
        if alias in df.columns:
            val = str(row.get(alias, "")).strip()
            if val and val.lower() not in ["nan", "none"]:
                return val
    return ""


def extract_port(service_str):
    """Extract first numeric port from a service string (e.g., 'TCP_3389' -> '3389')."""
    if not service_str:
        return ""
    match = re.search(r"(\d+)", service_str)
    if match:
        return match.group(1)
    return ""


def parse_file(file_path, vendor=None):
    """Parse CSV/XLSX into normalized firewall rules using vendor mappings."""
    if not vendor:
        vendor = detect_vendor(file_path)
    if not vendor:
        print(" Could not detect vendor.")
        return []

    print(f" Vendor Detected: {vendor}")

    mappings = config.data["vendor_mappings"].get(vendor, {}).get("columns", {})
    if not mappings:
        print(f" No vendor mapping found for: {vendor}")
        return []

    rules = []

    try:
        # ---------------- Client3 CSV ----------------
        if file_path.endswith(".csv") and vendor == "client3_csv":
            with open(file_path, newline='', encoding="utf-8") as csvfile:
                reader = list(csv.reader(csvfile))

            start_index = None
            for i, row in enumerate(reader):
                row_lower = [str(c).strip().lower() for c in row]
                if any("ipv4 local in policy" in cell for cell in row_lower):
                    start_index = i + 1
                    break

            if start_index is None:
                print("No IPv4 Local In Policy section found.")
                return []

            headers = [h.strip().lower() for h in reader[start_index]]
            df = pd.DataFrame(reader[start_index+1:], columns=headers)
            df = df.fillna("")

            id_field = "policyid"
            if id_field not in df.columns:
                print(" No policyid column in IPv4 Local In Policy section")
                return []

            df = df[df[id_field].astype(str).str.strip().str.isdigit()]

            for _, row in df.iterrows():
                rid = row.get("policyid", "").strip()
                if not rid.isdigit():
                    continue

                service_val = row.get("service", "").strip()

                rules.append({
                    "id": rid,
                    "name": row.get("comments", ""),
                    "srcaddr": row.get("srcaddr", ""),
                    "dstaddr": row.get("dstaddr", ""),
                    "service": service_val,
                    "dst_port": extract_port(service_val),
                    "action": row.get("action", ""),
                    "log": row.get("log", "log all sessions"),
                    "comment": row.get("comments", ""),
                    "status": row.get("status", "enable"),
                    "srcaddr_negate": row.get("srcaddr-negate", ""),
                    "dstaddr_negate": row.get("dstaddr-negate", ""),
                    "service_negate": row.get("service-negate", ""),
                    "vendor": vendor
                })

        # ---------------- Other CSV (Fortinet, etc.) ----------------
        elif file_path.endswith(".csv"):
            df = pd.read_csv(file_path, dtype=str)
            df = df.fillna("")
            df.columns = [str(c).strip().lower() for c in df.columns]

            id_field = None
            for alias in mappings.get("id", []):
                if alias.lower() in df.columns:
                    id_field = alias.lower()
                    break
            if not id_field:
                return []

            df = df[df[id_field].astype(str).str.strip().str.isdigit()]

            grouped = {}
            for _, row in df.iterrows():
                rid = get_col_value(row, df, "id", mappings)
                if not rid or not rid.isdigit():
                    continue

                if rid not in grouped:
                    grouped[rid] = {
                        "id": rid,
                        "name": get_col_value(row, df, "name", mappings),
                        "srcaddr": set(),
                        "dstaddr": set(),
                        "service": set(),
                        "action": get_col_value(row, df, "action", mappings),
                        "log": get_col_value(row, df, "log", mappings),
                        "comment": get_col_value(row, df, "comment", mappings),
                        "risk_rating": get_col_value(row, df, "risk_rating", mappings),
                        "status": get_col_value(row, df, "status", mappings),
                        "srcaddr_negate": get_col_value(row, df, "srcaddr_negate", mappings),
                        "dstaddr_negate": get_col_value(row, df, "dstaddr_negate", mappings),
                        "service_negate": get_col_value(row, df, "service_negate", mappings),
                        "vendor": vendor
                    }

                src = get_col_value(row, df, "srcaddr", mappings)
                if src: grouped[rid]["srcaddr"].add(src)

                dst = get_col_value(row, df, "dstaddr", mappings)
                if dst: grouped[rid]["dstaddr"].add(dst)

                svc = get_col_value(row, df, "service", mappings)
                if svc: grouped[rid]["service"].add(svc)

            for rid, rule in grouped.items():
                service_str = ", ".join(sorted(rule["service"]))
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "srcaddr": ", ".join(sorted(rule["srcaddr"])),
                    "dstaddr": ", ".join(sorted(rule["dstaddr"])),
                    "service": service_str,
                    "dst_port": extract_port(service_str),
                    "action": rule["action"],
                    "log": rule["log"],
                    "comment": rule["comment"],
                    "risk_rating": rule["risk_rating"],
                    "status": rule["status"],
                    "srcaddr_negate": rule["srcaddr_negate"],
                    "dstaddr_negate": rule["dstaddr_negate"],
                    "service_negate": rule["service_negate"],
                    "vendor": rule["vendor"]
                })

        # ---------------- XLSX ----------------
        elif file_path.endswith(".xlsx"):
            df_all = pd.read_excel(file_path, sheet_name=0, dtype=str, header=None, engine="openpyxl")

            first_header_idx = None
            for i, row in df_all.iterrows():
                row_lower = [str(cell).strip().lower() for cell in row.values]
                if "seq #" in row_lower and "action" in row_lower:
                    first_header_idx = i
                    break

            if first_header_idx is None:
                return []

            df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=first_header_idx, engine="openpyxl")
            df = df.fillna("")
            df.columns = [str(c).strip().lower() for c in df.columns]
            df = df.loc[:, ~df.columns.str.contains("^unnamed")]
            df = df[~df['seq #'].str.contains("seq #", case=False, na=False)]

            id_field = None
            for alias in mappings.get("id", []):
                if alias.lower() in df.columns:
                    id_field = alias.lower()
                    break
            if not id_field:
                return []

            df = df[df[id_field].astype(str).str.strip() != ""]

            grouped = {}
            for _, row in df.iterrows():
                rid = get_col_value(row, df, "id", mappings)
                if not rid or not rid.isdigit():
                    continue

                if rid not in grouped:
                    grouped[rid] = {
                        "id": rid,
                        "name": get_col_value(row, df, "name", mappings),
                        "srcaddr": set(),
                        "dstaddr": set(),
                        "service": set(),
                        "action": get_col_value(row, df, "action", mappings),
                        "log": get_col_value(row, df, "log", mappings),
                        "comment": get_col_value(row, df, "comment", mappings),
                        "risk_rating": get_col_value(row, df, "risk_rating", mappings),
                        "status": get_col_value(row, df, "status", mappings),
                        "srcaddr_negate": get_col_value(row, df, "srcaddr_negate", mappings),
                        "dstaddr_negate": get_col_value(row, df, "dstaddr_negate", mappings),
                        "service_negate": get_col_value(row, df, "service_negate", mappings),
                        "vendor": vendor
                    }

                src = get_col_value(row, df, "srcaddr", mappings)
                if src: grouped[rid]["srcaddr"].add(src)

                dst = get_col_value(row, df, "dstaddr", mappings)
                if dst: grouped[rid]["dstaddr"].add(dst)

                svc = get_col_value(row, df, "service", mappings)
                if svc: grouped[rid]["service"].add(svc)

            for rid, rule in grouped.items():
                service_str = ", ".join(sorted(rule["service"]))
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "srcaddr": ", ".join(sorted(rule["srcaddr"])),
                    "dstaddr": ", ".join(sorted(rule["dstaddr"])),
                    "service": service_str,
                    "dst_port": extract_port(service_str),
                    "action": rule["action"],
                    "log": rule["log"],
                    "comment": rule["comment"],
                    "risk_rating": rule["risk_rating"],
                    "status": rule["status"],
                    "srcaddr_negate": rule["srcaddr_negate"],
                    "dstaddr_negate": rule["dstaddr_negate"],
                    "service_negate": rule["service_negate"],
                    "vendor": rule["vendor"]
                })

    except Exception as e:
        print(f" Error parsing file: {e}")
        return []

    return rules
