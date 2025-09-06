import csv
import pandas as pd
from config.config_loader import load_config

config = load_config()

def detect_vendor(file_path):
    """Detect vendor type based on headers (CSV or XLSX)."""
    headers = []

    if file_path.endswith(".csv"):
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            headers = [h.strip().lower() for h in next(csv.reader(csvfile))]

    elif file_path.endswith(".xlsx"):
        df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=None)
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
    """Fetch the value for a logical field (id, name, srcaddr, log, etc.) using vendor mappings."""
    for alias in mappings.get(field, []):
        alias = alias.lower().strip()
        if alias in df.columns:
            val = str(row.get(alias, "")).strip()
            if val and val.lower() not in ["nan", "none"]:
                return val.lower()

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
        # ---------------- CSV ----------------
        if file_path.endswith(".csv"):
            df = pd.read_csv(file_path, dtype=str)
            df = df.fillna("")
            df.columns = [str(c).strip().lower() for c in df.columns]

            # Only keep numeric IDs
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
                    }

                src = get_col_value(row, df, "srcaddr", mappings)
                if src: grouped[rid]["srcaddr"].add(src)

                dst = get_col_value(row, df, "dstaddr", mappings)
                if dst: grouped[rid]["dstaddr"].add(dst)

                svc = get_col_value(row, df, "service", mappings)
                if svc: grouped[rid]["service"].add(svc)

            for rid, rule in grouped.items():
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "srcaddr": ", ".join(sorted(rule["srcaddr"])),
                    "dstaddr": ", ".join(sorted(rule["dstaddr"])),
                    "service": ", ".join(sorted(rule["service"])),
                    "action": rule["action"],
                    "log": rule["log"],
                    "comment": rule["comment"],
                    "risk_rating": rule["risk_rating"],
                })

        # ---------------- XLSX ----------------
        elif file_path.endswith(".xlsx"):
            df_all = pd.read_excel(file_path, sheet_name=0, dtype=str, header=None)
            header_row_index = None

            # Find header row
            for i, row in df_all.iterrows():
                row_lower = [str(cell).strip().lower() for cell in row.values]
                if "seq #" in row_lower and "action" in row_lower:
                    header_row_index = i
                    break

            if header_row_index is None:
                return []

            # Reload from header row down
            df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=header_row_index)
            df = df.fillna("")
            df.columns = [str(c).strip().lower() for c in df.columns]

            # Drop junk "Unnamed" columns
            df = df.loc[:, ~df.columns.str.contains("^unnamed")]

            # Only keep numeric IDs
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
                    }

                src = get_col_value(row, df, "srcaddr", mappings)
                if src: grouped[rid]["srcaddr"].add(src)

                dst = get_col_value(row, df, "dstaddr", mappings)
                if dst: grouped[rid]["dstaddr"].add(dst)

                svc = get_col_value(row, df, "service", mappings)
                if svc: grouped[rid]["service"].add(svc)

            for rid, rule in grouped.items():
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "srcaddr": ", ".join(sorted(rule["srcaddr"])),
                    "dstaddr": ", ".join(sorted(rule["dstaddr"])),
                    "service": ", ".join(sorted(rule["service"])),
                    "action": rule["action"],
                    "log": rule["log"],
                    "comment": rule["comment"],
                    "risk_rating": rule["risk_rating"],
                })

    except Exception as e:
        print(f" Error parsing file: {e}")
        return []

    return rules
