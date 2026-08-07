import requests

from config import ABUSEIPDB_API_KEY


def check_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    return response.json()