import ipaddress
import re


# ============================================================
# IOC PATTERNS
# ============================================================

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

MD5_PATTERN = re.compile(
    r"^[0-9a-fA-F]{32}$"
)

SHA1_PATTERN = re.compile(
    r"^[0-9a-fA-F]{40}$"
)

SHA256_PATTERN = re.compile(
    r"^[0-9a-fA-F]{64}$"
)


# ============================================================
# IOC DETECTION
# ============================================================

def detect_ioc(ioc):
    """
    Detect the type of an Indicator of Compromise (IOC).

    Supported IOC types:
        - IP
        - DOMAIN
        - MD5
        - SHA1
        - SHA256
        - UNKNOWN
    """

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

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

    if DOMAIN_PATTERN.fullmatch(ioc):
        return "DOMAIN"

    # --------------------------------------------------------
    # HASHES
    # --------------------------------------------------------

    if MD5_PATTERN.fullmatch(ioc):
        return "MD5"

    if SHA1_PATTERN.fullmatch(ioc):
        return "SHA1"

    if SHA256_PATTERN.fullmatch(ioc):
        return "SHA256"

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    return "UNKNOWN"