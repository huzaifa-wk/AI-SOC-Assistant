def classify_incident(alert):
    """
    Classify a security alert into:

    - Incident type
    - Attack category
    - Primary MITRE technique
    - Protocol

    Classification is based only on evidence present
    in the supplied alert.
    """

    if not isinstance(alert, dict):
        return {
            "incident_type": "Unknown",
            "attack_category": "Unclassified",
            "primary_technique": "Unknown",
            "protocol": "Unknown",
        }

    rule = alert.get(
        "rule",
        {}
    )

    mitre = alert.get(
        "mitre",
        {}
    )

    if not isinstance(rule, dict):
        rule = {}

    if not isinstance(mitre, dict):
        mitre = {}

    # ========================================================
    # RULE DESCRIPTION
    # ========================================================

    description = str(
        rule.get(
            "description",
            ""
        )
    ).strip().lower()

    # ========================================================
    # MITRE TECHNIQUES
    # ========================================================

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

    mitre_ids = {
        str(mitre_id).strip().upper()
        for mitre_id in mitre_ids
        if mitre_id
    }

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
            "primary_technique": (
                "T1110.001 - Password Guessing"
            ),
            "protocol": "SSH",
        }

    # ========================================================
    # SSH REMOTE ACCESS / LATERAL MOVEMENT
    # ========================================================

    if "T1021.004" in mitre_ids:

        return {
            "incident_type": "SSH Remote Access",
            "attack_category": "Lateral Movement",
            "primary_technique": (
                "T1021.004 - SSH"
            ),
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