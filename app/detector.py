import re


def detect_ioc(ioc):

    ioc = ioc.strip()

    # IPv4 Address
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, ioc):
        return "IP"

    # Domain
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(domain_pattern, ioc):
        return "DOMAIN"

    # MD5 Hash
    if len(ioc) == 32 and all(c in "0123456789abcdefABCDEF" for c in ioc):
        return "MD5"

    # SHA1 Hash
    if len(ioc) == 40 and all(c in "0123456789abcdefABCDEF" for c in ioc):
        return "SHA1"

    # SHA256 Hash
    if len(ioc) == 64 and all(c in "0123456789abcdefABCDEF" for c in ioc):
        return "SHA256"

    return "UNKNOWN"