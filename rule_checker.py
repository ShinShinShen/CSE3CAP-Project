# rule_checker.py
# --------------------------------------
# Rule Checker - Identifies risky rules and scores severity
# --------------------------------------

def evaluate_severity(issue_type):
    """
    Assign a severity level based on the type of issue.
    """
    severity_map = {
        "allow_all": "HIGH",
        "no_logging": "MEDIUM",
        "admin_port_exposed": "CRITICAL",
        "broad_ip_range": "HIGH",
        "missing_name": "LOW",
        "incomplete_rule": "HIGH",
        "redundant_rule": "LOW",
        "untagged_rule": "INFO"
    }
    return severity_map.get(issue_type, "UNKNOWN")


def check_rule(rule):
    """
    Run all risk checks on a single rule and return a list of findings.
    """
    findings = []

    name = rule.get("name", "").lower()
    src = rule.get("srcaddr", "").lower()
    dst = rule.get("dstaddr", "").lower()
    action = rule.get("action", "").lower()
    service = rule.get("service", "").lower()
    logging = rule.get("log", "").lower()
    tag = rule.get("tag", "").lower()
    src_port = rule.get("src_port", "").lower()
    dst_port = rule.get("dst_port", "").lower()

    #  Check 1: Allow-All Rule
    # Logic: If src, dst, and action are too open
    if action == "accept" and src in ["all", "any"] and dst in ["all", "any"]:
        findings.append({
            "issue": "Allow All Rule",
            "type": "allow_all",
            "severity": evaluate_severity("allow_all")
        })

    #  Check 2: Missing Logging
    if logging in ["no", "false", "", "none"]:
        findings.append({
            "issue": "No Logging Enabled",
            "type": "no_logging",
            "severity": evaluate_severity("no_logging")
        })

    #  Check 3: Admin Ports Exposed
    admin_ports = ["22", "3389", "23"]  # SSH, RDP, Telnet
    if dst_port in admin_ports:
        findings.append({
            "issue": "Admin Port Exposed",
            "type": "admin_port_exposed",
            "severity": evaluate_severity("admin_port_exposed")
        })

    #  Check 4: Broad Source/Destination IP Range
    if src in ["0.0.0.0/0", "any"] or dst in ["0.0.0.0/0", "any"]:
        findings.append({
            "issue": "Broad IP Range Detected",
            "type": "broad_ip_range",
            "severity": evaluate_severity("broad_ip_range")
        })

    #  Check 5: Malformed or Incomplete Rules
    required_fields = [src, dst, action, service]
    if any(field in ["", "none", "null"] for field in required_fields):
        findings.append({
            "issue": "Malformed or Incomplete Rule",
            "type": "incomplete_rule",
            "severity": evaluate_severity("incomplete_rule")
        })

    #  Check 6: Missing or Generic Name
    if name.strip() == "" or name in ["rule1", "rule2", "default", "unnamed"]:
        findings.append({
            "issue": "Missing or Generic Name",
            "type": "missing_name",
            "severity": evaluate_severity("missing_name")
        })

    #  Optional Check 7: Shadowed or Redundant Rules (simple placeholder)
    if src == dst:
        findings.append({
            "issue": "Redundant Rule (source equals destination)",
            "type": "redundant_rule",
            "severity": evaluate_severity("redundant_rule")
        })

    #  Optional Check 8: Tagging or Categorization
    if tag == "" or tag == "none":
        findings.append({
            "issue": "Missing Tag or Category",
            "type": "untagged_rule",
            "severity": evaluate_severity("untagged_rule")
        })

    return findings


def run_checker(rules):
    """
    Check a list of rules and return a dict of rule findings.
    Each rule’s findings are indexed by rule ID or name.
    """
    results = {}

    for rule in rules:
        rule_id = rule.get("id", rule.get("name", "unnamed_rule"))
        results[rule_id] = check_rule(rule)

    return results
