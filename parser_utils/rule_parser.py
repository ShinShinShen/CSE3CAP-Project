import csv
import pandas as pd
import re
import os
from config.config_loader import load_config

config = load_config()


def detect_vendor(file_path):
    """Detect vendor type based on filename first, then headers (CSV or XLSX)."""
    file_name = os.path.basename(file_path).lower()

    if "client1" in file_name:
        return "client 1 or 3 xlsx"
    if "client2" in file_name:
        return "client2"
    if "client3" in file_name:
        if file_path.endswith(".csv"):
            return "client3_csv"
        if file_path.endswith(".xlsx"):
            return "client 1 or 3 xlsx"
    if "checkpoint" in file_name or "check-point" in file_name:
        return "checkpoint"

    return None


def get_col_value(row, df, field, mappings, vendor=None):
    """Fetch logical field values, apply normalization, return lowercase."""
    for alias in mappings.get(field, []):
        alias = alias.lower().strip()
        if alias in df.columns:
            val = str(row.get(alias, "")).strip()
            if val and val.lower() not in ["nan", "none"]:
                vendor_norms = config.data["vendor_mappings"].get(vendor, {}).get("normalization", {})
                if field in vendor_norms:
                    normalized = vendor_norms[field].get(val.lower())
                    if normalized:
                        return normalized.lower()
                return val.lower()
    return ""


def extract_port(service_str):
    """Extract first numeric port from a service string (e.g., 'TCP_3389' -> '3389')."""
    if not service_str:
        return ""
    match = re.search(r"(\d+)", service_str)
    return match.group(1) if match else ""


def parse_file(file_path, vendor=None):
    """Parse CSV/XLSX into normalized firewall rules using vendor mappings."""
    if not vendor:
        vendor = detect_vendor(file_path)
    if not vendor:
        print("❌ Could not detect vendor.")
        return []

    print(f"✅ Vendor Detected: {vendor}")

    mappings = config.data["vendor_mappings"].get(vendor, {}).get("columns", {})
    if not mappings:
        print(f"❌ No vendor mapping found for: {vendor}")
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
                print("❌ No IPv4 Local In Policy section found.")
                return []

            headers = [h.strip().lower() for h in reader[start_index]]
            df = pd.DataFrame(reader[start_index + 1:], columns=headers).fillna("")

            if "policyid" not in df.columns:
                print("❌ No policyid column in IPv4 Local In Policy section")
                return []

            df = df[df["policyid"].astype(str).str.strip().str.isdigit()]

            for _, row in df.iterrows():
                rid = row.get("policyid", "").strip()
                if not rid.isdigit():
                    continue
                service_val = row.get("service", "").strip()

                rules.append({
                    "id": rid,
                    "name": row.get("comments", "").lower(),
                    "srcaddr": row.get("srcaddr", "").lower(),
                    "dstaddr": row.get("dstaddr", "").lower(),
                    "service": service_val.lower(),
                    "dst_port": extract_port(service_val),
                    "action": row.get("action", "").lower(),
                    "log": row.get("log", "log all sessions").lower(),
                    "comment": row.get("comments", "").lower(),
                    "status": get_col_value(row, df, "status", mappings, vendor) or "enable",
                    "vendor": vendor
                })

        # ---------------- Check Point CSV (raw parsing) ----------------
        elif file_path.endswith(".csv") and vendor == "checkpoint":
            rules = []
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv.reader(f, delimiter=",", quotechar='"')
                rows = list(reader)

                #skip header
                for line in rows[1:]:
                    if not line or not line[0].strip():
                        continue

                    # use csv.reader on the single string in column A
                    parts = next(csv.reader([line[0]], delimiter=",", quotechar='"'))

                    while len(parts) < 10:
                        parts.append("")


                    num, name, source, destination, service, action, track, install_on, enabled, comments = parts

                    rules.append({
                       "id": num,
                        "name": name.lower(),
                        "srcaddr": source.lower(),
                        "dstaddr": destination.lower(),
                        "service": service.lower(),
                        "dst_port": extract_port(service),
                        "action": action.lower(),
                        "log": track.lower(),
                        "comment": comments.lower(),
                        "status": "enable" if enabled.lower() in ["true", "yes", "1"] else "disable",
                        "vendor": vendor
                    })

            print("📑 Parsed first checkpoint rule:", rules[0] if rules else "None")
            return rules

        # ---------------- Generic CSV (Client1, etc.) ----------------
        elif file_path.endswith(".csv"):
            df = pd.read_csv(file_path, dtype=str, delimiter=",", quotechar='"', engine="python").fillna("")
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
                rid = get_col_value(row, df, "id", mappings, vendor)
                if not rid:
                    continue
                if rid not in grouped:
                    grouped[rid] = {
                        "id": rid,
                        "name": get_col_value(row, df, "name", mappings, vendor),
                        "srcaddr": set(),
                        "dstaddr": set(),
                        "service": set(),
                        "action": get_col_value(row, df, "action", mappings, vendor),
                        "log": get_col_value(row, df, "log", mappings, vendor),
                        "comment": get_col_value(row, df, "comment", mappings, vendor),
                        "risk_rating": get_col_value(row, df, "risk_rating", mappings, vendor),
                        "status": get_col_value(row, df, "status", mappings, vendor) or "enable",
                        "vendor": vendor
                    }
                src = get_col_value(row, df, "srcaddr", mappings, vendor)
                if src: grouped[rid]["srcaddr"].add(src)
                dst = get_col_value(row, df, "dstaddr", mappings, vendor)
                if dst: grouped[rid]["dstaddr"].add(dst)
                svc = get_col_value(row, df, "service", mappings, vendor)
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
                    "vendor": rule["vendor"]
                })

        # ---------------- XLSX ----------------
        elif file_path.endswith(".xlsx"):
            if vendor == "client2":
                df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=0, engine="openpyxl").fillna("")
                df.columns = [str(c).strip().lower() for c in df.columns]
            else:
                df_all = pd.read_excel(file_path, sheet_name=0, dtype=str, header=None, engine="openpyxl")

                first_header_idx = None
                for i, row in df_all.iterrows():
                    row_lower = [str(cell).strip().lower() for cell in row.values]
                    if "seq #" in row_lower and "action" in row_lower:
                        first_header_idx = i
                        break
                if first_header_idx is None:
                    return []

                df = pd.read_excel(file_path, sheet_name=0, dtype=str, header=first_header_idx, engine="openpyxl").fillna("")
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
                rid = get_col_value(row, df, "id", mappings, vendor)
                if not rid or not str(rid).isdigit():
                    continue

                if rid not in grouped:
                    grouped[rid] = {
                        "id": rid,
                        "name": get_col_value(row, df, "name", mappings, vendor),
                        "srcaddr": set(),
                        "dstaddr": set(),
                        "service": set(),
                        "action": get_col_value(row, df, "action", mappings, vendor),
                        "log": get_col_value(row, df, "log", mappings, vendor),
                        "comment": get_col_value(row, df, "comment", mappings, vendor),
                        "risk_rating": get_col_value(row, df, "risk_rating", mappings, vendor),
                        "status": get_col_value(row, df, "status", mappings, vendor) or "enable",
                        "vendor": vendor
                    }

                src = get_col_value(row, df, "srcaddr", mappings, vendor)
                if src: grouped[rid]["srcaddr"].add(src)
                dst = get_col_value(row, df, "dstaddr", mappings, vendor)
                if dst: grouped[rid]["dstaddr"].add(dst)
                svc = get_col_value(row, df, "service", mappings, vendor)
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
                    "vendor": rule["vendor"]
                })

    except Exception as e:
        print(f"❌ Error parsing file: {e}")
        return []

    return rules
