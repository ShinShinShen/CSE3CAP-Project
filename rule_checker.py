from config.config_loader import load_config

# Load JSON config at the top
config = load_config()

def evaluate_severity(issue_type):
    """
    Gets severity from JSON config based on risk_rules.
    """
    risk_rules = config.data.get("risk_rules", {})
    return risk_rules.get(issue_type, {}).get("severity", "UNKNOWN")


def check_rule(rule):
    """
    Runs all risk checks dynamically from JSON config.
    """
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

        # Match field values
        match_ok = True
        for field, values in match_criteria.items():
            if str(rule.get(field, "")).lower() not in [v.lower() for v in values]:
                match_ok = False
                break

        # Match port values
        for field, ports in match_ports.items():
            if str(rule.get(field, "")).lower() not in [p.lower() for p in ports]:
                match_ok = False
                break

        # Required fields check
        if required_fields and any(not rule.get(field, "").strip() for field in required_fields):
            match_ok = True

        # Bad names check
        if bad_names and str(rule.get("name", "")).lower() in [b.lower() for b in bad_names]:
            match_ok = True

        # Empty values check
        if empty_values and str(rule.get(rule_details.get("field", ""), "")).lower() in [v.lower() for v in empty_values]:
            match_ok = True

        # Action scope check
        if action_scope and str(rule.get("action", "")).lower() not in [a.lower() for a in action_scope]:
            match_ok = False

        if match_ok:
            findings.append({
                "issue": rule_name,
                "severity": evaluate_severity(rule_name)
            })

    return findings


def run_checker(rules):
    """
    Runs check_rule() on each parsed firewall rule.
    """
    results = {}
    for idx, rule in enumerate(rules, start=1):
        results[idx] = check_rule(rule)
    return results
