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


def build_alert_text(alert):

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = alert.get("mitre", {})

    mitre_ids = mitre.get("id", [])

    mitre_info = enrich_mitre(mitre_ids)

    mitre_text = ""

    for item in mitre_info:

        mitre_text += f"""
Technique: {item['name']}
Tactic: {item['tactic']}
Description: {item['description']}
Mitigation: {item['mitigation']}

"""

    return f"""
Rule ID: {rule.get("id", "N/A")}
Rule Level: {rule.get("level", "N/A")}
Description: {rule.get("description", "N/A")}

Agent: {agent.get("name", "N/A")}

Source IP: {alert.get("srcip", "N/A")}

Timestamp: {alert.get("timestamp", "N/A")}

MITRE IDs: {", ".join(mitre.get("id", []))}

MITRE Tactics: {", ".join(mitre.get("tactic", []))}

Cybersecurity Knowledge

{mitre_text}
"""


def main():

    # =========================================================
    # 1. LOAD WAZUH ALERT
    # =========================================================

    alert = load_alert("sample_alerts/ssh_bruteforce.json")

    # =========================================================
    # 2. CONVERT ALERT TO READABLE TEXT
    # =========================================================

    alert_text = build_alert_text(alert)
    
    # =========================================================
    # CLASSIFY THE INCIDENT
    # =========================================================
    
    incident_classification = classify_incident(alert)

    print("\n========== WAZUH ALERT ==========\n")
    print(alert_text)

    # =========================================================
    # 3. EXTRACT SOURCE IP
    # =========================================================

    source_ip = alert.get("srcip", "")

    # =========================================================
    # 4. DETECT IOC TYPE
    # =========================================================

    ioc_type = detect_ioc(source_ip)

    threat_intelligence = ""

    # Default AbuseIPDB score
    abuse_score = 0

    # =========================================================
    # 5. THREAT INTELLIGENCE
    # =========================================================

    if ioc_type == "IP":

        # -----------------------------------------------------
        # PRIVATE IP
        # -----------------------------------------------------

        if is_private_ip(source_ip):

            abuse_score = 0

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

        # -----------------------------------------------------
        # PUBLIC IP
        # -----------------------------------------------------

        else:

            print("\nChecking AbuseIPDB...\n")

            result = check_ip(source_ip)

            # Extract AbuseIPDB confidence score
            abuse_score = result.get(
                "data",
                {}
            ).get(
                "abuseConfidenceScore",
                0
            )

            threat_intelligence = format_abuseipdb(result)

            print(threat_intelligence)

    else:

        threat_intelligence = """
========== Threat Intelligence ==========

IOC Type : UNKNOWN

Threat Intelligence : Not Available

Lookup Status : SKIPPED
"""

        print(threat_intelligence)

    # =========================================================
    # 6. RISK ENGINE
    # =========================================================

    mitre_ids = alert.get(
        "mitre",
        {}
    ).get(
        "id",
        []
    )

    rule_level = alert.get(
        "rule",
        {}
    ).get(
        "level",
        0
    )

    risk_assessment = calculate_risk(
        rule_level,
        source_ip,
        abuse_score,
        mitre_ids
    )

    # =========================================================
    # 7. DISPLAY RISK ASSESSMENT
    # =========================================================

    print("\n========== RISK ASSESSMENT ==========\n")

    print(
    f"Risk Score : {risk_assessment['score']}/100"
)

    print(
    f"Risk Level : {risk_assessment['level']}"
)

    print(
    f"Incident Status : {risk_assessment['status']}"
)

    print(
    f"Confidence : {risk_assessment['confidence']}"
)

    print("\nRisk Factors:\n")

    for factor in risk_assessment["factors"]:
        print(f"- {factor}")
    
    # =========================================================
        # 8. DISPLAY INCIDENT CLASSIFICATION
    # =========================================================
    
    print("\n========== INCIDENT CLASSIFICATION ==========\n")

    print(
    f"Incident Type : "
    f"{incident_classification['incident_type']}"
)

    print(
    f"Attack Category : "
    f"{incident_classification['attack_category']}"
)

    print(
    f"Primary Technique : "
    f"{incident_classification['primary_technique']}"
)

    print(
    f"Protocol : "
    f"{incident_classification['protocol']}"
)

    # =========================================================
    # 9. BUILD AI CONTEXT
    # =========================================================

    context = build_context(
    alert_text,
    threat_intelligence,
    risk_assessment,
    incident_classification
)

    # =========================================================
    # 10. AI SOC ANALYSIS
    # =========================================================

    print("\n========== AI SOC ANALYSIS ==========\n")

    analysis = analyze_alert(context)

    print(analysis)

    # =========================================================
    # 11. GENERATE REPORT
    # =========================================================

    report = generate_report(
        alert_text
        + "\n"
        + threat_intelligence,
        analysis
    )

    # =========================================================
    # 12. SAVE REPORT
    # =========================================================

    filepath = save_report(report)

    print(
        f"\nReport Saved Successfully!\n"
        f"{filepath}"
    )


if __name__ == "__main__":
    main()