import ipaddress


def is_private_ip(ip):
    """
    Determine whether an IP address is private/internal.

    Args:
        ip: IPv4 or IPv6 address.

    Returns:
        bool:
            True  -> private/internal address
            False -> public, invalid, or empty address
    """

    if not isinstance(ip, str):
        return False

    ip = ip.strip()

    if not ip:
        return False

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return False

    return address.is_private