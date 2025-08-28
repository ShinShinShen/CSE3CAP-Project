from config.config_loader import load_config

# Load JSON config
config = load_config()

# Map common service names to ports
SERVICE_PORT_MAP = {
    "ssh": "22",
    "rdp": "3389",
    "rdp-tcp": "3389",
    "telnet": "23",
    "http": "80",
    "https": "443",
    "smtp": "25",
    "smtp-secure": "587"
}

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

        # ✅ Match field values (substring check)
        for field, values in match_criteria.items():
            rule_value = str(rule.get(field, "")).lower()
            if not any(v.lower() in rule_value for v in values):
                match_ok = False
                break

        # ✅ Match port values (using normalized service name → port)
        for field, ports in match_ports.items():
            value = normalize_service(rule.get("service", ""))
            if value not in [p.lower() for p in ports]:
                match_ok = False
                break

        # ✅ Required fields check (only flag if missing)
        if required_fields and any(not str(rule.get(field, "")).strip() for field in required_fields):
            findings.append({
                "issue": rule_name,
                "severity": evaluate_severity(rule_name)
            })
            continue

        # ✅ Bad names check
        if bad_names and str(rule.get("name", "")).lower() in [b.lower() for b in bad_names]:
            findings.append({
                "issue": rule_name,
                "severity": evaluate_severity(rule_name)
            })
            continue

        # ✅ Empty values check
        if empty_values and str(rule.get(rule_details.get("field", ""), "")).lower() in [v.lower() for v in empty_values]:
            findings.append({
                "issue": rule_name,
                "severity": evaluate_severity(rule_name)
            })
            continue

        # ✅ Action scope check
        if action_scope and str(rule.get("action", "")).lower() not in [a.lower() for a in action_scope]:
            match_ok = False

        # ✅ Append if still matched
        if match_ok:
            findings.append({
                "issue": rule_name,
                "severity": evaluate_severity(rule_name)
            })

    return findings

def run_checker(rules):
    """Runs check_rule() on each parsed firewall rule."""
    results = {}
    for idx, rule in enumerate(rules, start=1):
        results[idx] = check_rule(rule)
    return results
