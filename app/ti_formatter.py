from threat_rating import get_threat_rating

def format_abuseipdb(data):

    data = data.get("data", {})
    
    score = data.get("abuseConfidenceScore", 0)

    rating = get_threat_rating(score)

    report = f"""
========== Threat Intelligence ==========

IP Address : {data.get("ipAddress", "N/A")}

Country : {data.get("countryCode", "N/A")}

ISP : {data.get("isp", "N/A")}

Usage Type : {data.get("usageType", "N/A")}

Abuse Confidence Score : {data.get("abuseConfidenceScore", "N/A")}%

Threat Rating : {rating}

Total Reports : {data.get("totalReports", "N/A")}

Whitelisted : {data.get("isWhitelisted", "N/A")}

Last Report : {data.get("lastReportedAt", "N/A")}

"""

    return report