import requests

from config import ABUSEIPDB_API_KEY


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT = 10
ABUSEIPDB_MAX_AGE_DAYS = 90


def check_ip(ip):
    """
    Query AbuseIPDB for reputation information about an IP address.

    Args:
        ip: IP address to investigate.

    Returns:
        dict: AbuseIPDB API response.

    Raises:
        ValueError: If the IP or API key is missing.
        requests.RequestException: If the API request fails.
        requests.HTTPError: If AbuseIPDB returns an HTTP error.
    """

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    if not isinstance(ip, str) or not ip.strip():
        raise ValueError(
            "A valid IP address is required."
        )

    if not ABUSEIPDB_API_KEY:
        raise ValueError(
            "ABUSEIPDB_API_KEY is not configured."
        )

    ip = ip.strip()

    # --------------------------------------------------------
    # REQUEST CONFIGURATION
    # --------------------------------------------------------

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
    }

    # --------------------------------------------------------
    # API REQUEST
    # --------------------------------------------------------

    response = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=ABUSEIPDB_TIMEOUT,
    )

    # Raise an exception for 4xx/5xx responses.
    response.raise_for_status()

    # --------------------------------------------------------
    # RESPONSE VALIDATION
    # --------------------------------------------------------

    result = response.json()

    if not isinstance(result, dict):
        raise ValueError(
            "AbuseIPDB returned an invalid response."
        )

    return result