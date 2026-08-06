MITRE_DATABASE = {

    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Attackers attempt to guess passwords for valid user accounts.",
        "mitigation": "Use MFA, account lockout policies, and strong passwords."
    },

    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": "Attackers use SSH to move laterally or remotely access systems.",
        "mitigation": "Restrict SSH access, use key authentication, monitor login attempts."
    }

}


def enrich_mitre(mitre_ids):

    enriched = []

    for mitre_id in mitre_ids:

        if mitre_id in MITRE_DATABASE:

            enriched.append(MITRE_DATABASE[mitre_id])

    return enriched