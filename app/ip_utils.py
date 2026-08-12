import ipaddress


def is_private_ip(ip):
    """
    Return True if the supplied IP address is private.

    Invalid or empty values return False.
    """

    if not isinstance(ip, str):
        return False

    ip = ip.strip()

    if not ip:
        return False

    try:
        return ipaddress.ip_address(ip).is_private

    except ValueError:
        return False