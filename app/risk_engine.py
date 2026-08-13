from ip_utils import is_private_ip


def calculate_risk(
    rule_level,
    source_ip,
    abuse_score,
    mitre_ids
):
    """
    Calculate a deterministic SOC risk assessment.

    The risk score represents the severity and indicators
    associated with the alert. It does NOT confirm compromise.

    Returns:
        dict:
            score
            level
            status
            confidence
            factors
    """

    score = 0
    factors = []

    # ========================================================
    # NORMALIZE INPUTS
    # ========================================================

    try:
        rule_level = int(rule_level)
    except (TypeError, ValueError):
        rule_level = 0

    rule_level = max(
        0,
        rule_level
    )

    try:
        abuse_score = int(abuse_score)
    except (TypeError, ValueError):
        abuse_score = 0

    abuse_score = max(
        0,
        min(abuse_score, 100)
    )

    if isinstance(mitre_ids, (list, tuple, set)):
        normalized_mitre_ids = {
            str(mitre_id).strip().upper()
            for mitre_id in mitre_ids
            if mitre_id
        }
    else:
        normalized_mitre_ids = set()

    # ========================================================
    # WAZUH RULE SEVERITY
    # ========================================================

    if rule_level >= 10:

        score += 30

        factors.append(
            "Wazuh Rule Level 10+: +30"
        )

    elif rule_level >= 7:

        score += 20

        factors.append(
            "Wazuh Rule Level 7-9: +20"
        )

    elif rule_level >= 4:

        score += 10

        factors.append(
            "Wazuh Rule Level 4-6: +10"
        )

    # ========================================================
    # SOURCE IP CLASSIFICATION
    # ========================================================

    if source_ip and is_private_ip(source_ip):

        score += 5

        factors.append(
            "Private Internal IP: +5"
        )

    else:

        score += 15

        factors.append(
            "Public IP: +15"
        )

    # ========================================================
    # ABUSEIPDB REPUTATION
    # ========================================================

    if abuse_score >= 80:

        score += 25

        factors.append(
            "AbuseIPDB Score 80%+: +25"
        )

    elif abuse_score >= 50:

        score += 15

        factors.append(
            "AbuseIPDB Score 50-79%: +15"
        )

    elif abuse_score >= 20:

        score += 5

        factors.append(
            "AbuseIPDB Score 20-49%: +5"
        )

    else:

        factors.append(
            f"AbuseIPDB Score {abuse_score}%: +0"
        )

    # ========================================================
    # MITRE ATT&CK TECHNIQUES
    # ========================================================

    if "T1110.001" in normalized_mitre_ids:

        score += 10

        factors.append(
            "MITRE T1110.001 Password Guessing: +10"
        )

    if "T1021.004" in normalized_mitre_ids:

        score += 10

        factors.append(
            "MITRE T1021.004 SSH: +10"
        )

    # ========================================================
    # CAP SCORE
    # ========================================================

    score = min(
        score,
        100
    )

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 70:

        level = "CRITICAL"

    elif score >= 50:

        level = "HIGH"

    elif score >= 30:

        level = "MEDIUM"

    else:

        level = "LOW"

    # ========================================================
    # INCIDENT STATUS
    # ========================================================

    # Risk scoring does not prove compromise.
    # Failed authentication remains suspicious unless
    # additional evidence confirms malicious activity.

    status = "SUSPICIOUS"

    # ========================================================
    # CONFIDENCE
    # ========================================================

    if (
        rule_level >= 10
        and "T1110.001" in normalized_mitre_ids
        and "T1021.004" in normalized_mitre_ids
    ):

        confidence = "MEDIUM"

    else:

        confidence = "LOW"

    # ========================================================
    # RETURN ASSESSMENT
    # ========================================================

    return {
        "score": score,
        "level": level,
        "status": status,
        "confidence": confidence,
        "factors": factors
    }