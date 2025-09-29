import re
from config.config_loader import load_config

# Load JSON config
config = load_config()

# ✅ Load service port map from JSON instead of hardcoding
SERVICE_PORT_MAP = config.data.get("service_port_map", {})

def evaluate_severity(issue_type, vendor=None):
    """Gets severity from JSON config based on vendor or global risk_rules."""
    if vendor and "vendor_mappings" in config.data:
        vendor_rules = config.data["vendor_mappings"].get(vendor, {}).get("risk_rules", {})
        if issue_type in vendor_rules:
            return vendor_rules[issue_type].get("severity", "UNKNOWN")
    return config.data.get("risk_rules", {}).get(issue_type, {}).get("severity", "UNKNOWN")

def evaluate_category(issue_type, vendor=None):
    """Gets category from JSON config based on vendor or global risk_rules."""
    if vendor and "vendor_mappings" in config.data:
        vendor_rules = config.data["vendor_mappings"].get(vendor, {}).get("risk_rules", {})
        if issue_type in vendor_rules:
            return vendor_rules[issue_type].get("category", "Uncategorized")
    return config.data.get("risk_rules", {}).get(issue_type, {}).get("category", "Uncategorized")

def normalize_service(service_value):
    """Convert service names into port numbers when possible."""
    service_value = str(service_value).lower()
    return SERVICE_PORT_MAP.get(service_value, service_value)

def check_rule(rule, vendor=None):
    """Runs all risk checks dynamically from JSON config."""
    findings = []

    # ✅ Skip rules that are disabled in the CSV
    if rule.get("status", "").lower() == "disable":
        return findings

    # ✅ Choose vendor-specific rules if available
    risk_rules = {}
    if vendor and "vendor_mappings" in config.data:
        risk_rules = config.data["vendor_mappings"].get(vendor, {}).get("risk_rules", {})

    # Fallback to global rules if vendor-specific not found
    if not risk_rules:
        risk_rules = config.data.get("risk_rules", {})

    for rule_name, rule_details in risk_rules.items():
        if not rule_details.get("enabled", False):
            continue

        # ✅ Special case: broad_ip_range → use OR logic and values from JSON
        if rule_name.lower() == "broad_ip_range":
            action_value = str(rule.get("action", "")).lower()
            allowed_actions = [a.lower() for a in rule_details.get("action_scope", [])]
            risky_values = [v.lower() for v in rule_details.get("values", [])]

            if action_value in allowed_actions:
                for field in ["srcaddr", "dstaddr", "src_address", "dst_address"]:
                    val = str(rule.get(field, "")).strip().lower()
                    if not val:
                        continue

                    tokens = re.split(r"[\s,;]+", val)
                    tokens = [t.strip() for t in tokens if t.strip()]

                    if any(t in risky_values for t in tokens):
                        findings.append({
                            "issue": rule_name,
                            "field": field,
                            "value": rule.get(field, ""),
                            "severity": evaluate_severity(rule_name, vendor),
                            "category": evaluate_category(rule_name, vendor)
                        })
            continue  # skip default logic for this rule

        # -----------------------------
        # Normal rules (AND logic)
        # -----------------------------
        match_criteria = rule_details.get("match", {})
        match_ports = rule_details.get("match_ports", {})
        required_fields = rule_details.get("required_fields", [])
        bad_names = rule_details.get("bad_names", [])
        empty_values = rule_details.get("empty_values", [])
        action_scope = rule_details.get("action_scope", [])

        match_ok = True
        matched_fields = []

        # ✅ Match field values
        for field, values in match_criteria.items():
            rule_value = str(rule.get(field, "")).lower()
            values_normalized = [v.lower() for v in values]

            # Negate logic
            if field == "srcaddr" and rule.get("srcaddr_negate", "").lower() == "enable":
                match_ok = False
                break
            if field == "dstaddr" and rule.get("dstaddr_negate", "").lower() == "enable":
                match_ok = False
                break
            if field == "service" and rule.get("service_negate", "").lower() == "enable":
                match_ok = False
                break

            if field == "service":
                tokens = re.split(r"[\s,;]+", rule_value)
                tokens = [t.strip() for t in tokens if t.strip()]
                matched = [t for t in tokens if t in values_normalized]
            elif field == "log":
                matched = [rule_value] if rule_value in values_normalized else []
            elif field in ["src_address", "dst_address"]:
                matched = [rule_value] if rule_value in values_normalized else []
            else:
                tokens = re.split(r"[\s,;]+", rule_value)
                tokens = [t.strip() for t in tokens if t.strip()]
                matched = [t for t in tokens if t in values_normalized]

            if matched:
                for m in matched:
                    matched_fields.append((field, m))
            else:
                match_ok = False
                break

        # ✅ Match port values
        for field, ports in match_ports.items():
            values = []
            if field == "service":
                service_field = str(rule.get("service", ""))
                service_parts = re.split(r"[\s,;]+", service_field)
                values = [normalize_service(s.strip()) for s in service_parts if s.strip()]
                if rule.get("service_negate", "").lower() == "enable":
                    match_ok = False
                    break
            elif field == "dst_port":
                values = [str(rule.get("dst_port", "")).lower()]
            else:
                values = [str(rule.get(field, "")).lower()]

            if any(v in [p.lower() for p in ports] for v in values):
                for v in values:
                    if v in [p.lower() for p in ports]:
                        matched_fields.append((field, v))
            else:
                match_ok = False
                break

        # ✅ Required fields check
        if required_fields and any(not str(rule.get(field, "")).strip() for field in required_fields):
            for f in required_fields:
                if not str(rule.get(f, "")).strip():
                    findings.append({
                        "issue": rule_name,
                        "field": f,
                        "value": "",
                        "severity": evaluate_severity(rule_name, vendor),
                        "category": evaluate_category(rule_name, vendor)
                    })
            continue

        # ✅ Bad names check
        if bad_names and str(rule.get("name", "")).lower() in [b.lower() for b in bad_names]:
            findings.append({
                "issue": rule_name,
                "field": "name",
                "value": rule.get("name", ""),
                "severity": evaluate_severity(rule_name, vendor),
                "category": evaluate_category(rule_name, vendor)
            })
            continue

        # ✅ Empty values check
        if empty_values and str(rule.get(rule_details.get("field", ""), "")).lower() in [v.lower() for v in empty_values]:
            target_field = rule_details.get("field", "")
            findings.append({
                "issue": rule_name,
                "field": target_field,
                "value": rule.get(target_field, ""),
                "severity": evaluate_severity(rule_name, vendor),
                "category": evaluate_category(rule_name, vendor)
            })
            continue

        # ✅ Action scope check
        if action_scope and str(rule.get("action", "").lower()) not in [a.lower() for a in action_scope]:
            match_ok = False

        if match_ok:
            if matched_fields:
                for f, v in matched_fields:
                    findings.append({
                        "issue": rule_name,
                        "field": f,
                        "value": v,
                        "severity": evaluate_severity(rule_name, vendor),
                        "category": evaluate_category(rule_name, vendor)
                    })
            else:
                findings.append({
                    "issue": rule_name,
                    "field": "unspecified",
                    "value": "",
                    "severity": evaluate_severity(rule_name, vendor),
                    "category": evaluate_category(rule_name, vendor)
                })

    return findings

def run_checker(rules, vendor=None):
    """Runs check_rule() on each parsed firewall rule."""
    results = {}
    for idx, rule in enumerate(rules, start=1):
        rule_vendor = rule.get("vendor", vendor)
        results[idx] = check_rule(rule, rule_vendor)
    return results
