from detector import detect_ioc
from abuseipdb import check_ip
from ti_formatter import format_abuseipdb
from ip_utils import is_private_ip


def get_threat_intelligence(source_ip):
    """
    Perform threat-intelligence lookup for an IOC.

    Returns:
        tuple[str, int]:
            Threat-intelligence report text and AbuseIPDB score.
    """

    # --------------------------------------------------------
    # No source IP
    # --------------------------------------------------------

    if not source_ip:
        return (
            """
========== Threat Intelligence ==========

Source IP : N/A

Lookup Status : SKIPPED
""",
            0
        )

    # --------------------------------------------------------
    # Detect IOC type
    # --------------------------------------------------------

    ioc_type = detect_ioc(source_ip)

    if ioc_type != "IP":
        return (
            f"""
========== Threat Intelligence ==========

IOC : {source_ip}

IOC Type : {ioc_type}

Threat Intelligence :
Not available for this IOC type.

Lookup Status : SKIPPED
""",
            0
        )

    # --------------------------------------------------------
    # Private internal IP
    # --------------------------------------------------------

    if is_private_ip(source_ip):
        return (
            f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

IP Type : Private Internal Address

Threat Intelligence : Not Applicable

Reason :
Private IP addresses are not indexed by public
Threat Intelligence platforms.

Threat Rating : 🔵 INTERNAL

Lookup Status : SKIPPED
""",
            0
        )

    # --------------------------------------------------------
    # Public IP → AbuseIPDB
    # --------------------------------------------------------

    print("\nChecking AbuseIPDB...\n")

    try:
        result = check_ip(source_ip)

        formatted_report = format_abuseipdb(result)

        data = result.get("data", {})

        abuse_score = data.get(
            "abuseConfidenceScore",
            0
        )

        try:
            abuse_score = int(abuse_score)
        except (TypeError, ValueError):
            abuse_score = 0

        return formatted_report, abuse_score

    # --------------------------------------------------------
    # AbuseIPDB failure
    # --------------------------------------------------------

    except Exception as error:
        return (
            f"""
========== Threat Intelligence ==========

IP Address : {source_ip}

Lookup Status : FAILED

Reason :
AbuseIPDB lookup could not be completed.

Error :
{error}
""",
            0
        )