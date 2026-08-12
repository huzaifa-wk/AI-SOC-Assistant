import requests

from config import ABUSEIPDB_API_KEY


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip):
    """
    Query AbuseIPDB for reputation information about an IP address.

    Raises:
        requests.RequestException: If the API request fails.
    """

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    response = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=10,
    )

    response.raise_for_status()

    return response.json()