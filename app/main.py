from parser import load_alert
from detector import detect_ioc
from abuseipdb import check_ip
from ti_formatter import format_abuseipdb
from mitre import enrich_mitre
from context_builder import build_context
from ai import analyze_alert
from report import generate_report, save_report


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

    # Load Wazuh Alert
    alert = load_alert("sample_alerts/ssh_bruteforce.json")

    # Convert JSON to readable text
    alert_text = build_alert_text(alert)

    print("========== WAZUH ALERT ==========\n")
    print(alert_text)

    # Automatically extract IOC
    source_ip = alert.get("srcip", "")

    ioc_type = detect_ioc(source_ip)

    threat_intelligence = ""

    if ioc_type == "IP":

        print("\nChecking AbuseIPDB...\n")

        result = check_ip(source_ip)

        threat_intelligence = format_abuseipdb(result)

        print(threat_intelligence)

    # Build AI Context
    context = build_context(
        alert_text,
        threat_intelligence
    )

    print("\n========== AI SOC ANALYSIS ==========\n")

    analysis = analyze_alert(context)

    print(analysis)

    report = generate_report(
        alert_text + "\n" + threat_intelligence,
        analysis
    )

    filepath = save_report(report)

    print(f"\nReport Saved:\n{filepath}")


if __name__ == "__main__":
    main()