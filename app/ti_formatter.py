from threat_rating import get_threat_rating

def format_abuseipdb(result):

    data = result.get("data", {})

    country = data.get("countryCode") or "Unknown"
    isp = data.get("isp") or "Unknown"
    usage = data.get("usageType") or "Unknown"
    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    whitelisted = data.get("isWhitelisted", False)
    last_report = data.get("lastReportedAt") or "Never Reported"

    if score == 0:
        rating = "🟢 SAFE"
    elif score <= 25:
        rating = "🟡 LOW"
    elif score <= 75:
        rating = "🟠 MEDIUM"
    else:
        rating = "🔴 HIGH"

    return f"""
========== Threat Intelligence ==========

IP Address : {data.get("ipAddress", "Unknown")}

Country : {country}

ISP : {isp}

Usage Type : {usage}

Abuse Confidence Score : {score}%

Threat Rating : {rating}

Total Reports : {reports}

Whitelisted : {whitelisted}

Last Report : {last_report}

Lookup Status : ✔ COMPLETED
"""

    return report