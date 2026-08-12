from parser import load_alert
from detector import detect_ioc
from abuseipdb import check_ip
from ti_formatter import format_abuseipdb
from mitre import enrich_mitre
from context_builder import build_context
from ai import analyze_alert
from report import generate_report, save_report
from ip_utils import is_private_ip
from risk_engine import calculate_risk
from incident_classifier import classify_incident
from evidence import build_evidence


# ============================================================
# BUILD READABLE WAZUH ALERT
# ============================================================

def build_alert_text(alert):

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = alert.get("mitre", {})

    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])

    mitre_info = enrich_mitre(mitre_ids)

    mitre_text = ""

    for item in mitre_info:
        mitre_text += f"""
Technique: {item.get("name", "N/A")}
Tactic: {item.get("tactic", "N/A")}
Description: {item.get("description", "N/A")}
Mitigation: {item.get("mitigation", "N/A")}

"""

    return f"""
Rule ID: {rule.get("id", "N/A")}
Rule Level: {rule.get("level", "N/A")}
Description: {rule.get("description", "N/A")}

Agent: {agent.get("name", "N/A")}

Source IP: {alert.get("srcip", "N/A")}

Timestamp: {alert.get("timestamp", "N/A")}

MITRE IDs: {", ".join(mitre_ids)}

MITRE Tactics: {", ".join(mitre_tactics)}

Cybersecurity Knowledge

{mitre_text}
"""


# ============================================================
# PRINT RISK ASSESSMENT
# ============================================================

def print_risk_assessment(risk):

    print("\n========== RISK ASSESSMENT ==========\n")

    print(f"Risk Score : {risk.get('score', 0)}/100")
    print(f"Risk Level : {risk.get('level', 'UNKNOWN')}")
    print(f"Incident Status : {risk.get('status', 'UNKNOWN')}")
    print(f"Confidence : {risk.get('confidence', 'UNKNOWN')}")

    factors = risk.get("factors", [])

    if factors:
        print("\nRisk Factors:\n")

        for factor in factors:
            print(f"- {factor}")


# ============================================================
# PRINT INCIDENT CLASSIFICATION
# ============================================================

def print_classification(classification):

    print("\n========== INCIDENT CLASSIFICATION ==========\n")

    print(
        f"Incident Type : "
        f"{classification.get('incident_type', 'UNKNOWN')}"
    )

    print(
        f"Attack Category : "
        f"{classification.get('attack_category', 'UNKNOWN')}"
    )

    print(
        f"Primary Technique : "
        f"{classification.get('primary_technique', 'UNKNOWN')}"
    )

    print(
        f"Protocol : "
        f"{classification.get('protocol', 'UNKNOWN')}"
    )


# ============================================================
# PRINT EVIDENCE
# ============================================================

def print_evidence(evidence):

    print("\n========== EVIDENCE ASSESSMENT ==========\n")

    print("Confirmed Evidence:\n")

    for item in evidence.get("confirmed", []):
        print(f"- {item}")

    print("\nSuspicious Observations:\n")

    for item in evidence.get("suspicious", []):
        print(f"- {item}")

    print("\nUnconfirmed:\n")

    for item in evidence.get("unconfirmed", []):
        print(f"- {item}")


# ============================================================
# BUILD REPORT CONTEXT
# ============================================================

def build_report_context(
    alert_text,
    threat_intelligence,
    risk,
    classification,
    evidence
):

    factors = "\n".join(
        f"- {x}"
        for x in risk.get("factors", [])
    )

    confirmed = "\n".join(
        f"- {x}"
        for x in evidence.get("confirmed", [])
    )

    suspicious = "\n".join(
        f"- {x}"
        for x in evidence.get("suspicious", [])
    )

    unconfirmed = "\n".join(
        f"- {x}"
        for x in evidence.get("unconfirmed", [])
    )

    return f"""
{alert_text}

========== Threat Intelligence ==========

{threat_intelligence}

========== RISK ASSESSMENT ==========

Risk Score : {risk.get("score", 0)}/100
Risk Level : {risk.get("level", "UNKNOWN")}
Incident Status : {risk.get("status", "UNKNOWN")}
Confidence : {risk.get("confidence", "UNKNOWN")}

Risk Factors:

{factors}

========== INCIDENT CLASSIFICATION ==========

Incident Type : {classification.get("incident_type", "UNKNOWN")}
Attack Category : {classification.get("attack_category", "UNKNOWN")}
Primary Technique : {classification.get("primary_technique", "UNKNOWN")}
Protocol : {classification.get("protocol", "UNKNOWN")}

========== EVIDENCE ASSESSMENT ==========

Confirmed Evidence:

{confirmed}

Suspicious Observations:

{suspicious}

Unconfirmed:

{unconfirmed}
"""


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def get_threat_intelligence(source_ip):

    abuse_score = 0

    if not source_ip:

        return (
            """
========== Threat Intelligence ==========

Source IP : N/A

Lookup Status : SKIPPED
""",
            0
        )

    ioc_type = detect_ioc(source_ip)

    if ioc_type != "IP":

        return (
            f"""
========== Threat Intelligence ==========

IOC : {source_ip}
IOC Type : {ioc_type}

Threat Intelligence :
Not available for this IOC type.

Lookup Status : SKIPPED
""",
            0
        )

    # --------------------------------------------------------
    # PRIVATE IP
    # --------------------------------------------------------

    if is_private_ip(source_ip):

        return (
            f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

IP Type : Private Internal Address

Threat Intelligence : Not Applicable

Reason :
Private IP addresses are not indexed by public
Threat Intelligence platforms.

Threat Rating : 🔵 INTERNAL

Lookup Status : SKIPPED
""",
            0
        )

    # --------------------------------------------------------
    # PUBLIC IP
    # --------------------------------------------------------

    print("\nChecking AbuseIPDB...\n")

    try:

        result = check_ip(source_ip)

        formatted = format_abuseipdb(result)

        data = result.get("data", {})

        abuse_score = data.get(
            "abuseConfidenceScore",
            0
        )

        return formatted, abuse_score

    except Exception as error:

        return (
            f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

Lookup Status : FAILED

Reason :
AbuseIPDB lookup could not be completed.

Error :
{error}
""",
            0
        )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. LOAD ALERT
    # --------------------------------------------------------

    alert = load_alert(
        "sample_alerts/ssh_bruteforce.json"
    )

    # --------------------------------------------------------
    # 2. READABLE ALERT
    # --------------------------------------------------------

    alert_text = build_alert_text(alert)

    print("\n========== WAZUH ALERT ==========\n")
    print(alert_text)

    # --------------------------------------------------------
    # 3. SOURCE IP
    # --------------------------------------------------------

    source_ip = alert.get(
        "srcip",
        ""
    )

    # --------------------------------------------------------
    # 4. THREAT INTELLIGENCE
    # --------------------------------------------------------

    threat_intelligence, abuse_score = (
        get_threat_intelligence(source_ip)
    )

    print(threat_intelligence)

    # --------------------------------------------------------
    # 5. MITRE
    # --------------------------------------------------------

    mitre = alert.get(
        "mitre",
        {}
    )

    mitre_ids = mitre.get(
        "id",
        []
    )

    # --------------------------------------------------------
    # 6. RULE LEVEL
    # --------------------------------------------------------

    rule = alert.get(
        "rule",
        {}
    )

    rule_level = rule.get(
        "level",
        0
    )

    try:
        rule_level = int(rule_level)

    except (TypeError, ValueError):
        rule_level = 0

    # --------------------------------------------------------
    # 7. RISK ASSESSMENT
    # --------------------------------------------------------

    risk_assessment = calculate_risk(
        rule_level,
        source_ip,
        abuse_score,
        mitre_ids
    )

    print_risk_assessment(
        risk_assessment
    )

    # --------------------------------------------------------
    # 8. INCIDENT CLASSIFICATION
    # --------------------------------------------------------

    classification = classify_incident(
        alert
    )

    print_classification(
        classification
    )

    # --------------------------------------------------------
    # 9. EVIDENCE
    # --------------------------------------------------------

    evidence = build_evidence(
        alert,
        threat_intelligence,
        risk_assessment,
        classification
    )

    print_evidence(
        evidence
    )

    # --------------------------------------------------------
    # 10. AI CONTEXT
    # --------------------------------------------------------

    context = build_context(
        alert_text,
        threat_intelligence,
        risk_assessment,
        classification,
        evidence
    )

    # --------------------------------------------------------
    # 11. AI ANALYSIS
    # --------------------------------------------------------

    print("\n========== AI SOC ANALYSIS ==========\n")

    try:

        analysis = analyze_alert(
            context
        )

        print(analysis)

    except Exception as error:

        print(
            "AI analysis could not be completed."
        )

        print(
            f"Error: {error}"
        )

        analysis = f"""
## AI SOC Analysis

AI analysis could not be completed.

Error:
{error}

The deterministic SOC assessment remains available.
"""

    # --------------------------------------------------------
    # 12. REPORT CONTEXT
    # --------------------------------------------------------

    report_context = build_report_context(
        alert_text,
        threat_intelligence,
        risk_assessment,
        classification,
        evidence
    )

    # --------------------------------------------------------
    # 13. GENERATE REPORT
    # --------------------------------------------------------

    report = generate_report(
        report_context,
        analysis
    )

    # --------------------------------------------------------
    # 14. SAVE REPORT
    # --------------------------------------------------------

    filepath = save_report(
        report
    )

    print(
        f"\nReport Saved Successfully!\n"
        f"{filepath}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()