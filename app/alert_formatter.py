from mitre import enrich_mitre


def _safe_list(value):
    """
    Convert a Wazuh field into a clean list of strings.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return []

        return [value]

    return [str(value).strip()]


def build_alert_text(alert):
    """
    Build a human-readable representation of a Wazuh alert.

    Includes:
    - Rule information
    - Agent information
    - Source IP
    - Timestamp
    - MITRE techniques
    - MITRE enrichment
    """

    if not isinstance(alert, dict):
        raise ValueError(
            "Alert must be a dictionary."
        )

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    mitre = alert.get("mitre") or {}

    if not isinstance(rule, dict):
        rule = {}

    if not isinstance(agent, dict):
        agent = {}

    if not isinstance(mitre, dict):
        mitre = {}

    # --------------------------------------------------------
    # BASIC ALERT DATA
    # --------------------------------------------------------

    rule_id = rule.get("id", "N/A")

    rule_level = rule.get(
        "level",
        "N/A"
    )

    # IMPORTANT:
    # Keep Wazuh rule description separate from
    # MITRE technique descriptions.
    rule_description = rule.get(
        "description",
        "N/A"
    )

    agent_name = agent.get(
        "name",
        "N/A"
    )

    source_ip = alert.get(
        "srcip",
        "N/A"
    )

    timestamp = alert.get(
        "timestamp",
        "N/A"
    )

    # --------------------------------------------------------
    # MITRE DATA
    # --------------------------------------------------------

    mitre_ids = _safe_list(
        mitre.get("id")
    )

    mitre_tactics = _safe_list(
        mitre.get("tactic")
    )

    # --------------------------------------------------------
    # MITRE ENRICHMENT
    # --------------------------------------------------------

    mitre_info = enrich_mitre(
        mitre_ids
    )

    mitre_sections = []

    for item in mitre_info:

        if not isinstance(item, dict):
            continue

        technique_name = item.get(
            "name",
            "N/A"
        )

        technique_tactic = item.get(
            "tactic",
            "N/A"
        )

        technique_description = item.get(
            "description",
            "N/A"
        )

        technique_mitigation = item.get(
            "mitigation",
            "N/A"
        )

        mitre_sections.append(
            "\n".join(
                [
                    f"Technique: {technique_name}",
                    f"Tactic: {technique_tactic}",
                    f"Description: {technique_description}",
                    f"Mitigation: {technique_mitigation}",
                ]
            )
        )

    if mitre_sections:

        mitre_text = "\n\n".join(
            mitre_sections
        )

    else:

        mitre_text = (
            "No MITRE enrichment available."
        )

    # --------------------------------------------------------
    # FINAL ALERT TEXT
    # --------------------------------------------------------

    return f"""
Rule ID: {rule_id}
Rule Level: {rule_level}
Description: {rule_description}

Agent: {agent_name}

Source IP: {source_ip}

Timestamp: {timestamp}

MITRE IDs: {", ".join(mitre_ids) or "N/A"}

MITRE Tactics: {", ".join(mitre_tactics) or "N/A"}

Cybersecurity Knowledge

{mitre_text}
""".strip()