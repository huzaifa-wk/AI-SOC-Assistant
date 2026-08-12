import ipaddress
import re


# ============================================================
# IOC DETECTION
# ============================================================

def detect_ioc(ioc):
    """
    Detect the type of an IOC.

    Supported types:
    - IP address
    - Domain
    - MD5
    - SHA1
    - SHA256
    """

    if not isinstance(ioc, str):
        return "UNKNOWN"

    ioc = ioc.strip()

    if not ioc:
        return "UNKNOWN"

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:
        ipaddress.ip_address(ioc)
        return "IP"

    except ValueError:
        pass

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if re.fullmatch(domain_pattern, ioc):
        return "DOMAIN"

    # --------------------------------------------------------
    # HASHES
    # --------------------------------------------------------

    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "MD5"

    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "SHA1"

    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "SHA256"

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    return "UNKNOWN"