def build_evidence(
    alert,
    threat_intelligence,
    risk_assessment,
    classification
):
    """
    Build evidence-based incident context.

    Separates confirmed evidence from suspicious observations
    and unconfirmed possibilities.
    """

    rule = alert.get("rule", {})
    source_ip = alert.get("srcip", "N/A")

    # ========================================================
    # CONFIRMED EVIDENCE
    # ========================================================

    confirmed = [
        f"Wazuh rule {rule.get('id', 'N/A')} generated the alert.",
        f"Rule description: {rule.get('description', 'N/A')}.",
        f"Rule level: {rule.get('level', 'N/A')}.",
        f"Source IP observed: {source_ip}.",
    ]

    mitre_ids = alert.get("mitre", {}).get("id", [])

    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    if mitre_ids:
        confirmed.append(
            "MITRE techniques associated with the alert: "
            f"{', '.join(mitre_ids)}."
        )

    # ========================================================
    # SUSPICIOUS OBSERVATIONS
    # ========================================================

    suspicious = [
        "The observed authentication failures may indicate "
        "password-guessing activity.",
        "The activity requires investigation to determine whether "
        "the source is authorized or compromised.",
    ]

    # ========================================================
    # UNCONFIRMED
    # ========================================================

    unconfirmed = [
        "Successful authentication has not been confirmed.",
        "Credential compromise has not been confirmed.",
        "Lateral movement has not been confirmed.",
        "Command execution has not been confirmed.",
        "Host compromise has not been confirmed.",
    ]

    # ========================================================
    # BUILD EVIDENCE OBJECT
    # ========================================================

    return {
        "confirmed": confirmed,
        "suspicious": suspicious,
        "unconfirmed": unconfirmed,

        "risk_level": risk_assessment.get(
            "level",
            "UNKNOWN"
        ),

        "risk_score": risk_assessment.get(
            "score",
            0
        ),

        "incident_status": risk_assessment.get(
            "status",
            "UNKNOWN"
        ),

        "confidence": risk_assessment.get(
            "confidence",
            "UNKNOWN"
        ),

        "incident_type": classification.get(
            "incident_type",
            "UNKNOWN"
        ),

        "attack_category": classification.get(
            "attack_category",
            "UNKNOWN"
        ),
    }