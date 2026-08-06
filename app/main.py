from parser import load_alert
from ai import analyze_alert
from report import generate_report, save_report

def build_alert_text(alert):

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = alert.get("mitre", {})

    return f"""
Rule ID: {rule.get("id", "N/A")}
Rule Level: {rule.get("level", "N/A")}
Description: {rule.get("description", "N/A")}

Agent: {agent.get("name", "N/A")}

Source IP: {alert.get("srcip", "N/A")}

Timestamp: {alert.get("timestamp", "N/A")}

MITRE IDs: {", ".join(mitre.get("id", []))}

MITRE Tactics: {", ".join(mitre.get("tactic", []))}
"""


def main():

    alert = load_alert("sample_alerts/ssh_bruteforce.json")

    alert_text = build_alert_text(alert)

    print("========== WAZUH ALERT ==========\n")
    print(alert_text)

    print("\n========== AI SOC ANALYSIS ==========\n")

    analysis = analyze_alert(alert_text)
    report = generate_report(alert_text, analysis)

    filepath = save_report(report)

    print(analysis)
    print("\nReport saved successfully!")

    print(filepath)

    print(analysis)


if __name__ == "__main__":
    main()