def get_threat_rating(score):
    """
    Convert an AbuseIPDB confidence score into
    a readable SOC threat-intelligence rating.

    Important:
        This rating represents the AbuseIPDB reputation
        score only. It does not independently prove that
        an IP is malicious or benign.

    Score ranges:
        0       -> SAFE
        1-25    -> LOW
        26-75   -> MEDIUM
        76-100  -> HIGH
    """

    try:
        score = int(score)

    except (TypeError, ValueError):
        score = 0

    # Keep the score within the valid AbuseIPDB range.
    score = max(
        0,
        min(score, 100)
    )

    if score == 0:
        return "🟢 SAFE"

    if score <= 25:
        return "🟡 LOW"

    if score <= 75:
        return "🟠 MEDIUM"

    return "🔴 HIGH"