"""CyberShield AI — Part 07: IP & Hostname Security Validation (SSRF Protection)

Enforces strict destination safety boundaries to prevent Server-Side Request Forgery (SSRF).
Detects and rejects loopback, private RFC 1918, link-local, carrier-grade NAT, multicast,
unspecified, reserved, documentation, and cloud metadata destinations across both IPv4 and IPv6,
including IPv4-mapped IPv6, decimal/octal/hex IP representations, and internal hostname patterns.
Resolves DNS hostnames safely under explicit timeouts, inspects all returned A/AAAA records,
and strictly fails closed if any address is non-public or if resolution fails.
"""

import ipaddress
import re
import socket
from typing import List, Optional, Tuple, Set, Union
from app.schemas.url_scan import SSRFValidationResult

# Explicit cloud metadata IP addresses
METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack link-local metadata
    "169.254.0.1",      # Oracle Cloud Infrastructure metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}

# Explicit cloud metadata hostnames
METADATA_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "metadata.azure.com",
    "management.azure.com",
}

# Suffixes for internal / non-routable top-level and pseudo-domains
INTERNAL_TLDS: Tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".priv",
    ".private",
    ".home.arpa",
    ".localhost",
)

# Additional non-public IP networks not covered by standard ipaddress attributes
ADDITIONAL_RESTRICTED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Carrier-Grade NAT (CGNAT)
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 TEST-NET-1 (Documentation)
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 TEST-NET-2 (Documentation)
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 TEST-NET-3 (Documentation)
    ipaddress.ip_network("198.18.0.0/15"),     # RFC 2544 Benchmarking tests
    ipaddress.ip_network("192.88.99.0/24"),    # RFC 3068 6to4 relay anycast
    ipaddress.ip_network("192.175.48.0/24"),   # RFC 7535 AS112-v4
    ipaddress.ip_network("255.255.255.255/32"),# Limited broadcast
    ipaddress.ip_network("2001:db8::/32"),     # RFC 3849 IPv6 Documentation
    ipaddress.ip_network("64:ff9b:1::/48"),    # RFC 8215 Local-Use IPv4/IPv6 Translation
]


def parse_ip_safely(target: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Attempt to parse target into an IPv4Address or IPv6Address safely.
    
    Handles standard notation, bracketed IPv6, and alternative representations (octal/hex/decimal).
    """
    clean = target.strip()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    # 1. Standard ipaddress parse
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # 2. Check integer representation (e.g. 2130706433 for 127.0.0.1)
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # 3. Check socket.inet_aton for octal or hex formats (e.g., 0177.0.0.1, 0x7f.0.0.1)
    try:
        packed = socket.inet_aton(clean)
        # Verify it wasn't just a host string that happened to pass on some platforms
        if "." in clean:
            return ipaddress.IPv4Address(packed)
    except (socket.error, ValueError, OSError):
        pass

    return None


def evaluate_ip_safety(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, Optional[str], dict]:
    """Check an IP address against all restricted ranges.
    
    Returns:
        (is_safe, blocked_reason, category_flags)
    """
    flags = {
        "is_loopback": False,
        "is_private": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_reserved": False,
        "is_metadata": False,
    }

    # Handle IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    actual_ip = ip
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        actual_ip = ip.ipv4_mapped

    ip_str = str(actual_ip)

    # Cloud metadata explicit match
    if ip_str in METADATA_IPS:
        flags["is_metadata"] = True
        flags["is_link_local"] = True
        return False, f"Prohibited cloud metadata IP address: {ip_str}", flags

    # Link-local check (must precede generic is_private check)
    if actual_ip.is_link_local:
        flags["is_link_local"] = True
        return False, f"Prohibited link-local network address: {ip_str}", flags

    # Loopback check
    if actual_ip.is_loopback:
        flags["is_loopback"] = True
        return False, f"Prohibited loopback address: {ip_str}", flags

    # Private RFC1918 / ULA check
    if actual_ip.is_private:
        flags["is_private"] = True
        return False, f"Prohibited private RFC1918 / ULA network address: {ip_str}", flags

    # Multicast check
    if actual_ip.is_multicast:
        flags["is_multicast"] = True
        return False, f"Prohibited multicast address: {ip_str}", flags

    # Unspecified check (0.0.0.0, ::)
    if actual_ip.is_unspecified:
        flags["is_reserved"] = True
        return False, f"Prohibited unspecified address (0.0.0.0/::): {ip_str}", flags

    # Reserved check
    if actual_ip.is_reserved:
        flags["is_reserved"] = True
        return False, f"Prohibited reserved/special-use address: {ip_str}", flags

    # Check additional restricted networks (CGNAT, documentation, benchmarking)
    for net in ADDITIONAL_RESTRICTED_NETWORKS:
        if actual_ip in net:
            flags["is_reserved"] = True
            return False, f"Prohibited restricted/documentation network ({net}): {ip_str}", flags

    return True, None, flags


def resolve_hostname_all_ips(hostname: str, timeout_seconds: float = 2.0) -> Tuple[List[str], Optional[str]]:
    """Safely resolve hostname to all A and AAAA records under strict timeout.
    
    Returns:
        (resolved_ips, error_message)
    """
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        results = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        ips = []
        for res in results:
            ip_cand = res[4][0]
            if ip_cand not in ips:
                ips.append(ip_cand)
        return ips, None
    except socket.gaierror as e:
        return [], f"DNS resolution failed (gaierror): {str(e)}"
    except socket.timeout:
        return [], f"DNS resolution timed out after {timeout_seconds}s"
    except Exception as e:
        return [], f"DNS resolution encountered error: {str(e)}"
    finally:
        socket.setdefaulttimeout(orig_timeout)


def validate_destination_safety(
    hostname_or_ip: str,
    port: Optional[int] = None,
    resolve_dns: bool = False,
    dns_timeout: float = 2.0
) -> SSRFValidationResult:
    """Validate a destination hostname or IP against SSRF and internal routing risks.
    
    Args:
        hostname_or_ip: The target host or IP string.
        port: Destination port if specified.
        resolve_dns: Whether to perform safe preflight DNS resolution check.
        dns_timeout: Timeout in seconds for DNS queries.
        
    Returns:
        SSRFValidationResult detailing safety decision and risk factors.
    """
    clean_target = hostname_or_ip.strip().rstrip(".").lower()

    if not clean_target:
        return SSRFValidationResult(
            is_safe=False,
            target_type="hostname",
            hostname_or_ip=hostname_or_ip,
            blocked_reason="Target hostname or IP is empty."
        )

    # 1. Check if the target is directly an IP address
    parsed_ip = parse_ip_safely(clean_target)
    if parsed_ip is not None:
        is_safe, reason, flags = evaluate_ip_safety(parsed_ip)
        return SSRFValidationResult(
            is_safe=is_safe,
            target_type="ip",
            hostname_or_ip=str(parsed_ip),
            resolved_ips=[str(parsed_ip)],
            blocked_reason=reason,
            is_loopback=flags["is_loopback"],
            is_private=flags["is_private"],
            is_link_local=flags["is_link_local"],
            is_multicast=flags["is_multicast"],
            is_reserved=flags["is_reserved"],
            is_metadata_endpoint=flags["is_metadata"]
        )

    # 2. Hostname Static Syntax & Blacklist Checks
    # Exact localhost check
    if clean_target == "localhost" or clean_target.endswith(".localhost"):
        return SSRFValidationResult(
            is_safe=False,
            target_type="hostname",
            hostname_or_ip=clean_target,
            blocked_reason="Localhost hostname destination is strictly prohibited.",
            is_loopback=True
        )

    # Internal / non-public domain suffix check
    for internal_tld in INTERNAL_TLDS:
        if clean_target == internal_tld[1:] or clean_target.endswith(internal_tld):
            return SSRFValidationResult(
                is_safe=False,
                target_type="hostname",
                hostname_or_ip=clean_target,
                blocked_reason=f"Internal / non-public domain suffix '{internal_tld}' is prohibited.",
                is_private=True
            )

    # Cloud metadata hostname check
    if clean_target in METADATA_HOSTNAMES:
        return SSRFValidationResult(
            is_safe=False,
            target_type="hostname",
            hostname_or_ip=clean_target,
            blocked_reason=f"Prohibited cloud metadata hostname '{clean_target}'.",
            is_metadata_endpoint=True
        )

    # 3. Optional Safe Pre-Flight DNS Resolution Check
    if resolve_dns:
        resolved_ips, error = resolve_hostname_all_ips(clean_target, timeout_seconds=dns_timeout)
        if error is not None:
            # Resolution failed or timed out — fail closed!
            return SSRFValidationResult(
                is_safe=False,
                target_type="hostname",
                hostname_or_ip=clean_target,
                blocked_reason=f"DNS resolution security check failed: {error}"
            )

        if not resolved_ips:
            return SSRFValidationResult(
                is_safe=False,
                target_type="hostname",
                hostname_or_ip=clean_target,
                blocked_reason="DNS returned 0 valid address records."
            )

        # Inspect ALL resolved IP records (defense against mixed DNS answers & rebinding)
        for ip_str in resolved_ips:
            parsed_res_ip = parse_ip_safely(ip_str)
            if parsed_res_ip is None:
                return SSRFValidationResult(
                    is_safe=False,
                    target_type="hostname",
                    hostname_or_ip=clean_target,
                    resolved_ips=resolved_ips,
                    blocked_reason=f"DNS resolved unparseable IP record: {ip_str}"
                )

            ip_safe, ip_reason, flags = evaluate_ip_safety(parsed_res_ip)
            if not ip_safe:
                return SSRFValidationResult(
                    is_safe=False,
                    target_type="hostname",
                    hostname_or_ip=clean_target,
                    resolved_ips=resolved_ips,
                    blocked_reason=f"DNS resolved to prohibited destination ({ip_str}): {ip_reason}",
                    is_loopback=flags["is_loopback"],
                    is_private=flags["is_private"],
                    is_link_local=flags["is_link_local"],
                    is_multicast=flags["is_multicast"],
                    is_reserved=flags["is_reserved"],
                    is_metadata_endpoint=flags["is_metadata"]
                )

        # All resolved IPs are public and valid
        return SSRFValidationResult(
            is_safe=True,
            target_type="hostname",
            hostname_or_ip=clean_target,
            resolved_ips=resolved_ips
        )

    # If DNS resolution was not requested, target passed all static hostname and IP tests
    return SSRFValidationResult(
        is_safe=True,
        target_type="hostname",
        hostname_or_ip=clean_target
    )
