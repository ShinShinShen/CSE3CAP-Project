import re
from config.config_loader import load_config

# Load JSON config
config = load_config()

# ✅ Load service port map from JSON instead of hardcoding
SERVICE_PORT_MAP = config.data.get("service_port_map", {})

def evaluate_severity(issue_type):
    """Gets severity from JSON config based on risk_rules."""
    risk_rules = config.data.get("risk_rules", {})
    return risk_rules.get(issue_type, {}).get("severity", "UNKNOWN")

def normalize_service(service_value):
    """Convert service names into port numbers when possible."""
    service_value = str(service_value).lower()
    return SERVICE_PORT_MAP.get(service_value, service_value)

def check_rule(rule):
    """Runs all risk checks dynamically from JSON config."""
    findings = []
    risk_rules = config.data.get("risk_rules", {})

    for rule_name, rule_details in risk_rules.items():
        if not rule_details.get("enabled", False):
            continue

        match_criteria = rule_details.get("match", {})
        match_ports = rule_details.get("match_ports", {})
        required_fields = rule_details.get("required_fields", [])
        bad_names = rule_details.get("bad_names", [])
        empty_values = rule_details.get("empty_values", [])
        action_scope = rule_details.get("action_scope", [])

        match_ok = True
        matched_fields = []  # track which fields actually matched

        # ✅ Match field values
        for field, values in match_criteria.items():
            rule_value = str(rule.get(field, "")).lower()
            values_normalized = [v.lower() for v in values]

            if field == "service":
                # Split service field into tokens (space, comma, semicolon, line breaks)
                tokens = re.split(r"[\s,;]+", rule_value)
                tokens = [t.strip() for t in tokens if t.strip()]
                matched = [t for t in tokens if t in values_normalized]

            elif field == "log":
                # For log field, compare full string (don’t split "no log")
                matched = [rule_value] if rule_value in values_normalized else []

            else:
                # Default: check full string against values
                matched = [rule_value] if rule_value in values_normalized else []

            if matched:
                for m in matched:
                    matched_fields.append((field, m))
            else:
                match_ok = False
                break

        # ✅ Match port values (service OR dst_port)
        for field, ports in match_ports.items():
            values = []

            if field == "service":
                service_field = str(rule.get("service", ""))
                # Split by spaces, commas, semicolons, or line breaks
                service_parts = re.split(r"[\s,;]+", service_field)
                values = [normalize_service(s.strip()) for s in service_parts if s.strip()]

            elif field == "dst_port":
                values = [str(rule.get("dst_port", "")).lower()]

            else:
                values = [str(rule.get(field, "")).lower()]

            # Check if any part matches
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
                        "severity": evaluate_severity(rule_name)
                    })
            continue

        # ✅ Bad names check
        if bad_names and str(rule.get("name", "")).lower() in [b.lower() for b in bad_names]:
            findings.append({
                "issue": rule_name,
                "field": "name",
                "value": rule.get("name", ""),
                "severity": evaluate_severity(rule_name)
            })
            continue

        # ✅ Empty values check
        if empty_values and str(rule.get(rule_details.get("field", ""), "")).lower() in [v.lower() for v in empty_values]:
            target_field = rule_details.get("field", "")
            findings.append({
                "issue": rule_name,
                "field": target_field,
                "value": rule.get(target_field, ""),
                "severity": evaluate_severity(rule_name)
            })
            continue

        # ✅ Action scope check
        if action_scope and str(rule.get("action", "")).lower() not in [a.lower() for a in action_scope]:
            match_ok = False

        # ✅ Append if still matched
        if match_ok:
            if matched_fields:
                # record all matched fields + their values
                for f, v in matched_fields:
                    findings.append({
                        "issue": rule_name,
                        "field": f,
                        "value": v,
                        "severity": evaluate_severity(rule_name)
                    })
            else:
                findings.append({
                    "issue": rule_name,
                    "field": "unspecified",
                    "value": "",
                    "severity": evaluate_severity(rule_name)
                })

    return findings

def run_checker(rules):
    """Runs check_rule() on each parsed firewall rule."""
    results = {}
    for idx, rule in enumerate(rules, start=1):
        results[idx] = check_rule(rule)
    return results
