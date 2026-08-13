def build_evidence(
    alert,
    threat_intelligence,
    risk_assessment,
    classification
):
    """
    Build an evidence-based incident assessment.

    Separates:
        - Confirmed evidence
        - Suspicious observations
        - Unconfirmed possibilities

    The function does not determine compromise.
    It only organizes evidence already present
    in the incident data.
    """

    # ========================================================
    # VALIDATE INPUTS
    # ========================================================

    if not isinstance(alert, dict):
        alert = {}

    if not isinstance(risk_assessment, dict):
        risk_assessment = {}

    if not isinstance(classification, dict):
        classification = {}

    rule = alert.get(
        "rule",
        {}
    )

    if not isinstance(rule, dict):
        rule = {}

    source_ip = alert.get(
        "srcip",
        "N/A"
    )

    if not source_ip:
        source_ip = "N/A"

    # ========================================================
    # CONFIRMED EVIDENCE
    # ========================================================

    confirmed = [
        (
            f"Wazuh rule "
            f"{rule.get('id', 'N/A')} "
            f"generated the alert."
        ),
        (
            f"Rule description: "
            f"{rule.get('description', 'N/A')}."
        ),
        (
            f"Rule level: "
            f"{rule.get('level', 'N/A')}."
        ),
        (
            f"Source IP observed: "
            f"{source_ip}."
        ),
    ]

    # ========================================================
    # MITRE TECHNIQUES
    # ========================================================

    mitre = alert.get(
        "mitre",
        {}
    )

    if not isinstance(mitre, dict):
        mitre = {}

    mitre_ids = mitre.get(
        "id",
        []
    )

    if isinstance(mitre_ids, str):

        mitre_ids = [
            mitre_ids
        ]

    elif not isinstance(
        mitre_ids,
        (list, tuple, set)
    ):

        mitre_ids = []

    normalized_mitre_ids = [
        str(mitre_id).strip().upper()
        for mitre_id in mitre_ids
        if mitre_id
    ]

    if normalized_mitre_ids:

        confirmed.append(
            "MITRE techniques associated with "
            "the alert: "
            f"{', '.join(normalized_mitre_ids)}."
        )

    # ========================================================
    # SUSPICIOUS OBSERVATIONS
    # ========================================================

    suspicious = [
        (
            "The observed authentication failures "
            "may indicate password-guessing activity."
        ),
        (
            "The activity requires investigation to "
            "determine whether the source is authorized "
            "or potentially compromised."
        ),
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