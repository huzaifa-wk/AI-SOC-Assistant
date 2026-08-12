def get_threat_rating(score):
    """
    Convert an AbuseIPDB confidence score into
    a readable SOC threat rating.
    """

    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

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