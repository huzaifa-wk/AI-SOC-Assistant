from ip_utils import is_private_ip


def calculate_risk(rule_level, source_ip, abuse_score, mitre_ids):

    score = 0
    factors = []

    # =========================================================
    # 1. WAZUH RULE SEVERITY
    # =========================================================

    if rule_level >= 10:
        score += 30
        factors.append("Wazuh Rule Level 10+: +30")

    elif rule_level >= 7:
        score += 20
        factors.append("Wazuh Rule Level 7-9: +20")

    elif rule_level >= 4:
        score += 10
        factors.append("Wazuh Rule Level 4-6: +10")

    else:
        score += 5
        factors.append("Wazuh Rule Level 0-3: +5")

    # =========================================================
    # 2. IP CLASSIFICATION
    # =========================================================

    if is_private_ip(source_ip):

        score += 5
        factors.append("Private Internal IP: +5")

    else:

        score += 15
        factors.append("Public IP: +15")

    # =========================================================
    # 3. ABUSEIPDB REPUTATION
    # =========================================================

    if abuse_score >= 75:

        score += 25
        factors.append("AbuseIPDB Score 75-100%: +25")

    elif abuse_score >= 50:

        score += 15
        factors.append("AbuseIPDB Score 50-74%: +15")

    elif abuse_score >= 25:

        score += 10
        factors.append("AbuseIPDB Score 25-49%: +10")

    elif abuse_score > 0:

        score += 5
        factors.append("AbuseIPDB Score 1-24%: +5")

    else:

        factors.append("AbuseIPDB Score 0%: +0")

    # =========================================================
    # 4. MITRE TECHNIQUES
    # =========================================================

    if "T1110.001" in mitre_ids:

        score += 10
        factors.append(
            "MITRE T1110.001 Password Guessing: +10"
        )

    if "T1021.004" in mitre_ids:

        score += 10
        factors.append(
            "MITRE T1021.004 SSH: +10"
        )

    # =========================================================
    # 5. LIMIT SCORE TO 100
    # =========================================================

    score = min(score, 100)

    # =========================================================
    # 6. DETERMINE RISK LEVEL
    # =========================================================

    if score >= 75:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # =========================================================
    # 7. RETURN COMPLETE RISK ASSESSMENT
    # =========================================================

    return {
        "score": score,
        "level": risk_level,
        "factors": factors
    }