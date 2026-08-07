from parser import load_alert
from detector import detect_ioc
from abuseipdb import check_ip
from ti_formatter import format_abuseipdb
from mitre import enrich_mitre
from context_builder import build_context
from ai import analyze_alert
from report import generate_report, save_report
from ip_utils import is_private_ip


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

    # ============================
    # Load Wazuh Alert
    # ============================

    alert = load_alert("sample_alerts/ssh_bruteforce.json")

    # Convert JSON into readable text

    alert_text = build_alert_text(alert)

    print("========== WAZUH ALERT ==========\n")
    print(alert_text)

    # ============================
    # Extract IOC
    # ============================

    source_ip = alert.get("srcip", "")
    ioc_type = detect_ioc(source_ip)

    threat_intelligence = ""

    # ============================
    # Threat Intelligence
    # ============================

    if ioc_type == "IP":

        # Private IP
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

        # Public IP
        else:

            print("\nChecking AbuseIPDB...\n")

            result = check_ip(source_ip)

            threat_intelligence = format_abuseipdb(result)

            print(threat_intelligence)

    else:

        threat_intelligence = f"""
========== Threat Intelligence ==========

IOC Type : {ioc_type}

Threat Intelligence Lookup is currently supported
only for IP addresses.

Lookup Status : SKIPPED
"""

        print(threat_intelligence)

    # ============================
    # Build AI Context
    # ============================

    context = build_context(
        alert_text,
        threat_intelligence
    )

    # ============================
    # AI Analysis
    # ============================

    print("\n========== AI SOC ANALYSIS ==========\n")

    analysis = analyze_alert(context)

    print(analysis)

    # ============================
    # Generate Report
    # ============================

    report = generate_report(
        alert_text + "\n" + threat_intelligence,
        analysis
    )

    filepath = save_report(report)

    print("\nReport Saved Successfully!")
    print(filepath)


if __name__ == "__main__":
    main()