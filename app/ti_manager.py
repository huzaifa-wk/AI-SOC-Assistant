from detector import detect_ioc
from abuseipdb import check_ip
from ti_formatter import format_abuseipdb
from ip_utils import is_private_ip


def _normalize_score(value):
    """
    Convert an AbuseIPDB score into a safe integer.

    Invalid values return 0.
    """

    try:
        score = int(value)
    except (TypeError, ValueError):
        return 0

    return max(0, min(score, 100))


def get_threat_intelligence(source_ip):
    """
    Perform threat-intelligence lookup for an IOC.

    Processing flow:

        IOC
         ↓
        Detect IOC type
         ↓
        Private IP?
        ↓
        AbuseIPDB lookup
         ↓
        Formatted TI report

    Returns:
        tuple[str, int]:
            Threat-intelligence report text
            AbuseIPDB abuse confidence score
    """

    # --------------------------------------------------------
    # NORMALIZE INPUT
    # --------------------------------------------------------

    if not isinstance(source_ip, str):
        source_ip = ""

    source_ip = source_ip.strip()

    # --------------------------------------------------------
    # NO SOURCE IP
    # --------------------------------------------------------

    if not source_ip:
        return (
            """
========== Threat Intelligence ==========

Source IP : N/A

Lookup Status : SKIPPED
""".strip(),
            0,
        )

    # --------------------------------------------------------
    # IOC DETECTION
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
""".strip(),
            0,
        )

    # --------------------------------------------------------
    # PRIVATE / INTERNAL IP
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
""".strip(),
            0,
        )

    # --------------------------------------------------------
    # PUBLIC IP → ABUSEIPDB
    # --------------------------------------------------------

    print("\nChecking AbuseIPDB...\n")

    try:
        result = check_ip(source_ip)

        if not isinstance(result, dict):
            raise ValueError(
                "Invalid AbuseIPDB response."
            )

        formatted_report = format_abuseipdb(
            result
        )

        data = result.get(
            "data",
            {}
        )

        if not isinstance(data, dict):
            data = {}

        abuse_score = _normalize_score(
            data.get(
                "abuseConfidenceScore",
                0
            )
        )

        return (
            formatted_report,
            abuse_score,
        )

    # --------------------------------------------------------
    # ABUSEIPDB FAILURE
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
""".strip(),
            0,
        )