from mitre import enrich_mitre


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