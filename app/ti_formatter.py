from threat_rating import get_threat_rating


def format_abuseipdb(result):
    """
    Format an AbuseIPDB response into readable SOC
    threat-intelligence information.

    Args:
        result: AbuseIPDB API response dictionary.

    Returns:
        str: Formatted threat-intelligence report.
    """

    if not isinstance(result, dict):
        return """
========== Threat Intelligence ==========

Lookup Status : FAILED

Reason :
Invalid AbuseIPDB response.
""".strip()

    data = result.get("data", {})

    if not isinstance(data, dict):
        data = {}

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    ip_address = (
        data.get("ipAddress")
        or "Unknown"
    )

    country = (
        data.get("countryCode")
        or "Unknown"
    )

    isp = (
        data.get("isp")
        or "Unknown"
    )

    usage = (
        data.get("usageType")
        or "Unknown"
    )

    # --------------------------------------------------------
    # ABUSE SCORE
    # --------------------------------------------------------

    try:
        score = int(
            data.get(
                "abuseConfidenceScore",
                0
            )
        )
    except (TypeError, ValueError):
        score = 0

    score = max(
        0,
        min(score, 100)
    )

    # --------------------------------------------------------
    # REPORT INFORMATION
    # --------------------------------------------------------

    try:
        reports = int(
            data.get(
                "totalReports",
                0
            )
        )
    except (TypeError, ValueError):
        reports = 0

    whitelisted = data.get(
        "isWhitelisted",
        False
    )

    last_report = (
        data.get("lastReportedAt")
        or "Never Reported"
    )

    # --------------------------------------------------------
    # THREAT RATING
    # --------------------------------------------------------

    rating = get_threat_rating(
        score
    )

    # --------------------------------------------------------
    # FORMATTED REPORT
    # --------------------------------------------------------

    return f"""
========== Threat Intelligence ==========

IP Address : {ip_address}

Country : {country}

ISP : {isp}

Usage Type : {usage}

Abuse Confidence Score : {score}%

Threat Rating : {rating}

Total Reports : {reports}

Whitelisted : {whitelisted}

Last Report : {last_report}

Lookup Status : ✔ COMPLETED
""".strip()