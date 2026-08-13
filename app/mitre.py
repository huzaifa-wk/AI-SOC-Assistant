MITRE_DATABASE = {
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Attackers attempt to guess passwords "
            "for valid user accounts."
        ),
        "mitigation": (
            "Use MFA, account lockout policies, "
            "and strong passwords."
        ),
    },

    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": (
            "Attackers use SSH to move laterally "
            "or remotely access systems."
        ),
        "mitigation": (
            "Restrict SSH access, use key authentication, "
            "and monitor login attempts."
        ),
    },
}


def enrich_mitre(mitre_ids):
    """
    Enrich MITRE ATT&CK technique IDs with
    local SOC knowledge.

    Unknown or unsupported technique IDs are
    safely ignored.
    """

    if not isinstance(mitre_ids, (list, tuple)):
        return []

    enriched = []

    for mitre_id in mitre_ids:

        if not isinstance(mitre_id, str):
            continue

        mitre_id = mitre_id.strip().upper()

        technique = MITRE_DATABASE.get(
            mitre_id
        )

        if technique:
            enriched.append(
                technique.copy()
            )

    return enriched