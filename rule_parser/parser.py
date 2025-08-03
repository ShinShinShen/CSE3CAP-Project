import csv
import os

def detect_vendor(file_path):
    filename = os.path.basename(file_path).lower()

    #All possible vendors that can be called in this project
    if "fortinet" in filename:
        return "fortinet"
    elif "sophos" in filename:
        return "sophos"
    elif "checkpoint" in filename:
        return "checkpoint"
    elif "watchguard" in filename:
        return "watchguard"
    elif "barracuda" in filename:
        return "barracuda"

    #checking csv files for patterns that match hardcoded rules
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)

            header_set = set(h.lower() for h in headers)

            if "policyid" in header_set and "srcintf" in header_set:
                return "fortinet"        
            elif "rule id" in header_set and "service" in header_set:
                return "sophos"        
            
            #These are the only policies I can find so far, will add more later
    except Exception:
        pass

    return "unknown vendor policy"

def parse_csv(file_path):
    vendor = detect_vendor(file_path)

    if vendor == "fortinet":
        return parse_fortinet_csv(file_path)
    else:
        raise NotImplementedError(f"Parser not yet implemented for type {vendor}, try again later =)")
    
def parse_fortinet_csv(file_path):
    normalized_rules = []

    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rule = {
                "id": row.get("id"),
                "source": row.get("src_ip", "").lower(),
                "destination": row.get("dst_ip", "").lower(),
                "src_port": row.get("src_port", "").lower(),
                "dst_port": row.get("dst_port", "").lower(),
                "protocol": row.get("protocol", "").upper(),
                "action": row.get("action", "").lower(),
                "comment": row.get("comment", ""),
                "vendor": "fortinet"
            }
            normalized_rules.append(rule)
            #specific to fortinet
            #appending to array should be fine for now, if theres performance issues will fix 
    return normalized_rules