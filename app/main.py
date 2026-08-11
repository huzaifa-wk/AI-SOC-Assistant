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
# FORMAT RISK ASSESSMENT
# ============================================================

def print_risk_assessment(risk_assessment):

    print("\n========== RISK ASSESSMENT ==========\n")

    print(
        f"Risk Score : "
        f"{risk_assessment.get('score', 0)}/100"
    )

    print(
        f"Risk Level : "
        f"{risk_assessment.get('level', 'UNKNOWN')}"
    )

    print(
        f"Incident Status : "
        f"{risk_assessment.get('status', 'UNKNOWN')}"
    )

    print(
        f"Confidence : "
        f"{risk_assessment.get('confidence', 'UNKNOWN')}"
    )

    factors = risk_assessment.get("factors", [])

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
    risk_assessment,
    classification,
    evidence
):

    report_context = f"""
{alert_text}

========== Threat Intelligence ==========

{threat_intelligence}

========== RISK ASSESSMENT ==========

Risk Score : {risk_assessment.get("score", 0)}/100
Risk Level : {risk_assessment.get("level", "UNKNOWN")}
Incident Status : {risk_assessment.get("status", "UNKNOWN")}
Confidence : {risk_assessment.get("confidence", "UNKNOWN")}

Risk Factors:

"""

    for factor in risk_assessment.get("factors", []):
        report_context += f"- {factor}\n"

    report_context += f"""

========== INCIDENT CLASSIFICATION ==========

Incident Type : {classification.get("incident_type", "UNKNOWN")}
Attack Category : {classification.get("attack_category", "UNKNOWN")}
Primary Technique : {classification.get("primary_technique", "UNKNOWN")}
Protocol : {classification.get("protocol", "UNKNOWN")}

========== EVIDENCE ASSESSMENT ==========

Confirmed Evidence:

"""

    for item in evidence.get("confirmed", []):
        report_context += f"- {item}\n"

    report_context += """

Suspicious Observations:

"""

    for item in evidence.get("suspicious", []):
        report_context += f"- {item}\n"

    report_context += """

Unconfirmed:

"""

    for item in evidence.get("unconfirmed", []):
        report_context += f"- {item}\n"

    return report_context


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # 1. LOAD WAZUH ALERT
    # ========================================================

    alert = load_alert(
        "sample_alerts/ssh_bruteforce.json"
    )

    # ========================================================
    # 2. BUILD READABLE ALERT
    # ========================================================

    alert_text = build_alert_text(alert)

    print("\n========== WAZUH ALERT ==========\n")
    print(alert_text)

    # ========================================================
    # 3. EXTRACT SOURCE IP
    # ========================================================

    source_ip = alert.get("srcip", "")

    # ========================================================
    # 4. DETECT IOC
    # ========================================================

    ioc_type = detect_ioc(source_ip)

    # ========================================================
    # 5. INITIALIZE THREAT INTELLIGENCE VARIABLES
    # ========================================================

    threat_intelligence = ""

    abuse_score = 0

    abuse_result = None

    # ========================================================
    # 6. THREAT INTELLIGENCE
    # ========================================================

    if ioc_type == "IP":

        # ----------------------------------------------------
        # PRIVATE INTERNAL IP
        # ----------------------------------------------------

        if is_private_ip(source_ip):

            threat_intelligence = f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

IP Type : Private Internal Address

Threat Intelligence : Not Applicable

Reason :
Private IP addresses are not indexed by public
Threat Intelligence platforms.

Threat Rating : 🔵 INTERNAL

Lookup Status : SKIPPED
"""

            print(threat_intelligence)

            # Private IP has no AbuseIPDB score.
            abuse_score = 0

        # ----------------------------------------------------
        # PUBLIC IP
        # ----------------------------------------------------

        else:

            print("\nChecking AbuseIPDB...\n")

            try:

                abuse_result = check_ip(source_ip)

                threat_intelligence = format_abuseipdb(
                    abuse_result
                )

                print(threat_intelligence)

                # --------------------------------------------
                # EXTRACT ABUSEIPDB SCORE
                # --------------------------------------------

                data = abuse_result.get(
                    "data",
                    {}
                )

                abuse_score = data.get(
                    "abuseConfidenceScore",
                    0
                )

            except Exception as error:

                threat_intelligence = f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

Lookup Status : FAILED

Reason :
AbuseIPDB lookup could not be completed.

Error :
{error}
"""

                print(threat_intelligence)

                abuse_score = 0

    else:

        threat_intelligence = f"""
========== Threat Intelligence ==========

IOC : {source_ip}

IOC Type : {ioc_type}

Threat Intelligence :
Not available for this IOC type.

Lookup Status : SKIPPED
"""

        print(threat_intelligence)

        abuse_score = 0

    # ========================================================
    # 7. MITRE IDS
    # ========================================================

    mitre = alert.get("mitre", {})

    mitre_ids = mitre.get("id", [])

    # ========================================================
    # 8. DETERMINISTIC RISK ENGINE
    # ========================================================

    rule = alert.get("rule", {})

    rule_level = rule.get("level", 0)

    try:
        rule_level = int(rule_level)
    except (TypeError, ValueError):
     rule_level = 0


    risk_assessment = calculate_risk(
    rule_level,
    source_ip,
    abuse_score,
    mitre_ids
)

    print_risk_assessment(
        risk_assessment
    )

    # ========================================================
    # 9. INCIDENT CLASSIFICATION
    # ========================================================

    classification = classify_incident(
        alert
    )

    print_classification(
        classification
    )

    # ========================================================
    # 10. EVIDENCE ENGINE
    # ========================================================

    evidence = build_evidence(
        alert,
        threat_intelligence,
        risk_assessment,
        classification
    )

    print_evidence(
        evidence
    )

    # ========================================================
    # 11. BUILD COMPLETE AI CONTEXT
    # ========================================================

    context = build_context(
        alert_text,
        threat_intelligence,
        risk_assessment,
        classification,
        evidence
    )

    # ========================================================
    # 12. AI SOC ANALYSIS
    # ========================================================

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

AI analysis could not be completed because the AI provider
returned an error.

Error:
{error}

The deterministic SOC assessment remains available in this report.
"""

    # ========================================================
    # 13. BUILD COMPLETE REPORT DATA
    # ========================================================

    report_alert_text = build_report_context(
        alert_text,
        threat_intelligence,
        risk_assessment,
        classification,
        evidence
    )

    # ========================================================
    # 14. GENERATE REPORT
    # ========================================================

    report = generate_report(
        report_alert_text,
        analysis
    )

    # ========================================================
    # 15. SAVE REPORT
    # ========================================================

    filepath = save_report(
        report
    )

    print(
        f"\nReport Saved Successfully!\n"
        f"{filepath}"
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()