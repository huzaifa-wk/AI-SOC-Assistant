def classify_incident(alert):
    """
    Classify a security alert into an incident type,
    attack category, primary MITRE technique, and protocol.
    """

    rule = alert.get("rule", {})
    mitre = alert.get("mitre", {})

    description = rule.get("description", "").lower()
    mitre_ids = mitre.get("id", [])

    # Ensure MITRE IDs are always handled as a list
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    # ========================================================
    # SSH BRUTE FORCE / PASSWORD GUESSING
    # ========================================================

    if (
        "T1110.001" in mitre_ids
        or "password guessing" in description
        or "authentication failures" in description
    ):
        return {
            "incident_type": "SSH Brute Force",
            "attack_category": "Credential Attack",
            "primary_technique": "T1110.001 - Password Guessing",
            "protocol": "SSH",
        }

    # ========================================================
    # SSH REMOTE ACCESS / LATERAL MOVEMENT
    # ========================================================

    if "T1021.004" in mitre_ids:
        return {
            "incident_type": "SSH Remote Access",
            "attack_category": "Lateral Movement",
            "primary_technique": "T1021.004 - SSH",
            "protocol": "SSH",
        }

    # ========================================================
    # UNKNOWN INCIDENT
    # ========================================================

    return {
        "incident_type": "Unknown",
        "attack_category": "Unclassified",
        "primary_technique": "Unknown",
        "protocol": "Unknown",
    }