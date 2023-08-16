from ipaddress import IPv4Address, IPv6Address
import re


def is_ipv4_address(ip_address: str) -> bool:
    """Return True if address is a valid IPv4 address."""
    try:
        IPv4Address(ip_address)
        return True
    except ValueError:
        return False


def is_ipv6_address(ip_address: str) -> bool:
    """Return True if address is a valid IPv6 address."""
    try:
        IPv6Address(ip_address)
        return True
    except ValueError:
        return False


def is_mac_address(mac_address: str) -> bool:
    """Return True if address is a valid MAC address."""
    if re.match(
        "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()
    ):
        return True
    return False
