import ipaddress
import urllib.parse
from fastapi import HTTPException, status

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud IMDS (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string belongs to a private, loopback, link-local, or restricted network.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return True
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        # Not a raw IP address (could be a domain name or invalid string)
        return False


def validate_outbound_target(target: str) -> str:
    """
    Validates a target IP address or URL host to prevent SSRF.
    Raises HTTPException 400 Bad Request if the target resolves to a restricted/private network.
    """
    cleaned_target = target.strip()
    
    # Check if target is a URL
    if cleaned_target.startswith("http://") or cleaned_target.startswith("https://"):
        parsed = urllib.parse.urlparse(cleaned_target)
        hostname = parsed.hostname or ""
    else:
        hostname = cleaned_target

    if is_private_or_restricted_ip(hostname):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Safeguard Violation: Target '{cleaned_target}' points to a restricted private or loopback IP range.",
        )
    return cleaned_target
