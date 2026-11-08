"""CyberShield AI — Part 09: DNS & Domain Investigation Service

Provides structured, safe DNS queries for A, AAAA, CNAME, MX, and NS records.
Enforces timeouts, response bounds, distinct error classification (NXDOMAIN, TIMEOUT,
SERVFAIL, EMPTY_ANSWER, UNAVAILABLE), and re-validates all resolved addresses
against the Part 07 SSRF security guard.
"""

import socket
import struct
import time
import re
import urllib.parse
from typing import List, Tuple, Optional, Set
from datetime import datetime, timezone

from app.schemas.common import TechnicalFinding, TechnicalLimitation, FindingSeverity
from app.services.dns.models import DNSInvestigationResult, DNSStatus
from app.services.url_investigation.ssrf_guard import parse_ip_safely, evaluate_ip_safety


def extract_clean_domain(target: str) -> str:
    """Extract and sanitize a clean domain or hostname from an input string."""
    clean = target.strip()
    if "://" in clean:
        try:
            parsed = urllib.parse.urlsplit(clean)
            clean = parsed.hostname or clean
        except Exception:
            clean = clean.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0]
    else:
        clean = clean.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    # Strip port if present
    if ":" in clean and not (clean.startswith("[") and clean.endswith("]")):
        # Could be host:port or IPv6
        if clean.count(":") == 1:
            clean = clean.split(":", 1)[0]

    return clean.strip("[]").rstrip(".").lower()


def _build_dns_query_packet(name: str, qtype: int, tx_id: int = 0x1A2B) -> bytes:
    """Construct a standard DNS query UDP packet."""
    parts = name.strip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii", errors="replace") for p in parts) + b"\x00"
    # Header: ID, Flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    # Question: QNAME + QTYPE + QCLASS(IN=1)
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_dns_labels(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse DNS name from packet data with compression pointer support."""
    labels = []
    jumped = False
    original_offset = offset
    max_hops = 10
    hops = 0

    while offset < len(data) and hops < max_hops:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Pointer check (top 2 bits set: 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer_offset
            hops += 1
            continue

        offset += 1
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def query_dns_record_type(
    domain: str,
    qtype_num: int,
    nameserver: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 2.0
) -> Tuple[List[str], Optional[DNSStatus], Optional[str]]:
    """Query a specific DNS record type via UDP.
    
    Args:
        domain: Target domain name.
        qtype_num: 15 for MX, 2 for NS, 5 for CNAME, etc.
        nameserver: DNS resolver server.
        port: DNS port (default 53).
        timeout: Query timeout in seconds.
        
    Returns:
        (results, error_status, error_message)
    """
    try:
        query = _build_dns_query_packet(domain, qtype_num)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (nameserver, port))
            response, _ = sock.recvfrom(2048)

        if len(response) < 12:
            return [], DNSStatus.SERVFAIL, "Truncated DNS header received"

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:12])
        rcode = flags & 0x000F

        if rcode == 3:
            return [], DNSStatus.NXDOMAIN, f"Domain '{domain}' does not exist (NXDOMAIN)"
        elif rcode == 2:
            return [], DNSStatus.SERVFAIL, "Server failure (SERVFAIL)"
        elif rcode != 0:
            return [], DNSStatus.SERVFAIL, f"DNS error response RCODE={rcode}"

        offset = 12
        # Skip question section
        for _ in range(qdcount):
            _, offset = _parse_dns_labels(response, offset)
            offset += 4  # Skip QTYPE and QCLASS

        records = []
        for _ in range(ancount):
            if offset >= len(response):
                break
            _, offset = _parse_dns_labels(response, offset)
            if offset + 10 > len(response):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            rdata_start = offset
            offset += rdlength

            if rtype == qtype_num:
                if qtype_num == 15:  # MX
                    if rdlength > 2:
                        pref = struct.unpack("!H", response[rdata_start:rdata_start + 2])[0]
                        mx_host, _ = _parse_dns_labels(response, rdata_start + 2)
                        # RFC 7505 / RFC 1035: root domain exchange target is canonically "."
                        mx_target = mx_host if mx_host else "."
                        records.append(f"{pref} {mx_target}")
                elif qtype_num in (2, 5):  # NS or CNAME
                    target_name, _ = _parse_dns_labels(response, rdata_start)
                    if target_name:
                        records.append(target_name)

        return records, None, None

    except socket.timeout:
        return [], DNSStatus.TIMEOUT, f"DNS query for {domain} timed out after {timeout}s"
    except socket.gaierror as gai_err:
        return [], DNSStatus.UNAVAILABLE, f"DNS lookup failed: {str(gai_err)}"
    except Exception as exc:
        return [], DNSStatus.UNAVAILABLE, f"DNS resolution error: {str(exc)}"


def resolve_a_and_aaaa_records(
    domain: str,
    timeout: float = 2.0,
    max_records: int = 20
) -> Tuple[List[str], List[str], List[str], DNSStatus, Optional[str]]:
    """Resolve A, AAAA, and CNAME records using the operating system resolver.
    
    Returns:
        (a_records, aaaa_records, cname_records, status, error_detail)
    """
    orig_timeout = socket.getdefaulttimeout()
    a_records: List[str] = []
    aaaa_records: List[str] = []
    cname_records: List[str] = []

    try:
        socket.setdefaulttimeout(timeout)

        # 1. Resolve IPv4 (A records)
        try:
            results_v4 = socket.getaddrinfo(
                domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM, flags=socket.AI_CANONNAME
            )
            for res in results_v4:
                ip = res[4][0]
                if ip not in a_records and len(a_records) < max_records:
                    a_records.append(ip)
                if res[3] and res[3].lower() != domain.lower() and res[3] not in cname_records:
                    cname_records.append(res[3])
        except socket.gaierror as gai_v4:
            # Check for NXDOMAIN indicator
            if gai_v4.errno in (11001, getattr(socket, "EAI_NONAME", -2)):
                return [], [], [], DNSStatus.NXDOMAIN, f"Domain '{domain}' does not exist (NXDOMAIN)"
            elif gai_v4.errno in (11002, getattr(socket, "EAI_AGAIN", -3)):
                return [], [], [], DNSStatus.SERVFAIL, f"DNS server temporary failure (SERVFAIL) for '{domain}'"

        # 2. Resolve IPv6 (AAAA records)
        try:
            results_v6 = socket.getaddrinfo(
                domain, None, family=socket.AF_INET6, type=socket.SOCK_STREAM
            )
            for res in results_v6:
                ip = res[4][0]
                if ip not in aaaa_records and len(aaaa_records) < max_records:
                    aaaa_records.append(ip)
        except (socket.gaierror, socket.timeout):
            pass  # Absence of AAAA is normal for IPv4-only domains

        if not a_records and not aaaa_records:
            return [], [], [], DNSStatus.EMPTY_ANSWER, f"Domain '{domain}' returned 0 address records"

        return a_records, aaaa_records, cname_records, DNSStatus.SUCCESS, None

    except socket.timeout:
        return [], [], [], DNSStatus.TIMEOUT, f"DNS resolution timed out after {timeout}s"
    except Exception as exc:
        return [], [], [], DNSStatus.UNAVAILABLE, f"DNS resolution encountered an error: {str(exc)}"
    finally:
        socket.setdefaulttimeout(orig_timeout)


def investigate_dns(
    target: str,
    timeout_seconds: float = 2.0,
    max_records: int = 20,
    query_auxiliary_records: bool = True
) -> DNSInvestigationResult:
    """Execute complete Part 09 DNS Investigation.
    
    1. Sanitizes domain name.
    2. Resolves A and AAAA records via OS resolver under timeout.
    3. Queries auxiliary MX and NS records if enabled.
    4. Re-validates ALL resolved addresses through the Part 07 SSRF guard.
    5. Returns structured DNSInvestigationResult with findings and limitations.
    
    Args:
        target: Hostname, domain, or URL.
        timeout_seconds: Timeout per lookup operation.
        max_records: Maximum records collected per type.
        query_auxiliary_records: Whether to query MX and NS records.
        
    Returns:
        Structured DNSInvestigationResult.
    """
    start_time = time.perf_counter()
    domain = extract_clean_domain(target)
    findings: List[TechnicalFinding] = []
    limitations: List[TechnicalLimitation] = []

    if not domain or len(domain) > 253:
        elapsed = (time.perf_counter() - start_time) * 1000
        return DNSInvestigationResult(
            domain=domain or target,
            status=DNSStatus.INVALID_DOMAIN,
            query_time_ms=round(elapsed, 2),
            notes="Invalid domain syntax or length exceeds 253 characters."
        )

    # 1. Resolve A, AAAA, and CNAME
    a_recs, aaaa_recs, cnames, dns_status, error_msg = resolve_a_and_aaaa_records(
        domain, timeout=timeout_seconds, max_records=max_records
    )

    all_ips = a_recs + aaaa_recs
    is_safe = True
    blocked_reason = None

    # Handle resolution error/failure states cleanly
    if dns_status != DNSStatus.SUCCESS:
        elapsed = (time.perf_counter() - start_time) * 1000
        # Failure is not proof of malice or safety; record limitation
        limitations.append(
            TechnicalLimitation(
                module="dns",
                reason=f"DNS resolution outcome: {dns_status.value} ({error_msg})",
                impact="Unable to inspect resolved IP infrastructure or establish network trust signals."
            )
        )
        return DNSInvestigationResult(
            domain=domain,
            status=dns_status,
            query_time_ms=round(elapsed, 2),
            a_records=[],
            aaaa_records=[],
            cname_records=[],
            all_resolved_ips=[],
            is_destination_safe=True,  # No unsafe IP reached
            findings=findings,
            limitations=limitations,
            notes=error_msg
        )

    # 2. SSRF Protection: Re-validate EVERY resolved IP
    for ip_str in all_ips:
        parsed_ip = parse_ip_safely(ip_str)
        if parsed_ip is None:
            is_safe = False
            blocked_reason = f"Unparseable resolved IP: {ip_str}"
            break

        ip_safe, ip_reason, flags = evaluate_ip_safety(parsed_ip)
        if not ip_safe:
            is_safe = False
            blocked_reason = f"Resolved IP {ip_str} prohibited: {ip_reason}"
            findings.append(
                TechnicalFinding(
                    module="dns",
                    check_name="SSRF_PROHIBITED_DNS_DESTINATION",
                    severity=FindingSeverity.HIGH,
                    title="Prohibited Internal / Private IP Resolved",
                    description=f"Domain resolved to restricted network address ({ip_str}). {ip_reason}",
                    evidence={"domain": domain, "resolved_ip": ip_str, "flags": flags},
                    remediation="Reject connection to internal or private IP destinations."
                )
            )
            break

    # If any IP violated SSRF, mark status as SSRF_BLOCKED
    if not is_safe:
        dns_status = DNSStatus.SSRF_BLOCKED

    # 3. Optional auxiliary MX and NS queries
    mx_records: List[str] = []
    ns_records: List[str] = []

    if query_auxiliary_records and dns_status == DNSStatus.SUCCESS:
        # MX Query
        mxs, mx_err, _ = query_dns_record_type(domain, qtype_num=15, timeout=timeout_seconds)
        if mxs:
            mx_records = mxs[:max_records]
        elif mx_err == DNSStatus.TIMEOUT:
            limitations.append(
                TechnicalLimitation(
                    module="dns",
                    reason="MX record query timed out",
                    impact="Mail exchanger infrastructure could not be analyzed."
                )
            )

        # NS Query
        nss, ns_err, _ = query_dns_record_type(domain, qtype_num=2, timeout=timeout_seconds)
        if nss:
            ns_records = nss[:max_records]
        elif ns_err == DNSStatus.TIMEOUT:
            limitations.append(
                TechnicalLimitation(
                    module="dns",
                    reason="NS record query timed out",
                    impact="Authoritative name servers could not be verified."
                )
            )

    # Add technical findings for domain characteristics
    if len(all_ips) > 5:
        findings.append(
            TechnicalFinding(
                module="dns",
                check_name="FAST_FLUX_OR_HIGH_IP_DIVERSITY",
                severity=FindingSeverity.LOW,
                title="High IP Address Count Detected",
                description=f"Domain resolved to {len(all_ips)} distinct IP addresses. While common in CDNs, fast-flux malicious networks also rotate multiple addresses.",
                evidence={"resolved_count": len(all_ips), "ips": all_ips},
                remediation="Correlate with ASN and CDN indicators."
            )
        )

    elapsed = (time.perf_counter() - start_time) * 1000

    return DNSInvestigationResult(
        domain=domain,
        status=dns_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        query_time_ms=round(elapsed, 2),
        a_records=a_recs,
        aaaa_records=aaaa_recs,
        cname_records=cnames,
        mx_records=mx_records,
        ns_records=ns_records,
        all_resolved_ips=all_ips,
        is_destination_safe=is_safe,
        blocked_reason=blocked_reason,
        findings=findings,
        limitations=limitations,
        notes=f"Resolved {len(a_recs)} IPv4 and {len(aaaa_recs)} IPv6 records."
    )

