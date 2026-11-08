"""CyberShield AI — Part 11: TLS & SSL Certificate Analysis Service

Inspects HTTPS certificates, validates certificate chains, checks hostname/SAN matching,
measures expiration dates, evaluates cipher strength and TLS protocol versions,
and represents external revocation and Certificate Transparency checks honestly.
"""

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple, Callable
import urllib.parse

from app.schemas.common import TechnicalFinding, TechnicalLimitation, FindingSeverity
from app.services.tls_analysis.models import (
    TLSStatus,
    TLSCertificateInfo,
    TLSConnectionInfo,
    TLSAnalysisResult,
)
from app.services.url_investigation.ssrf_guard import (
    validate_destination_safety,
    parse_ip_safely,
    evaluate_ip_safety,
)


def _format_x509_name(name_tuples: Tuple) -> Dict[str, str]:
    """Convert pyOpenSSL / standard ssl nested tuple format to flat dict."""
    result: Dict[str, str] = {}
    for item in name_tuples:
        for key, val in item:
            result[key] = val
    return result


def _parse_cert_date(date_str: Optional[str]) -> Tuple[Optional[str], Optional[datetime]]:
    """Parse certificate date string into ISO 8601 string and datetime object."""
    if not date_str:
        return None, None
    try:
        ts = ssl.cert_time_to_seconds(date_str)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat(), dt
    except Exception:
        return date_str, None


def _check_san_matches(hostname: str, san_list: List[str], common_name: Optional[str]) -> bool:
    """Check if requested hostname matches any SAN or Common Name with wildcard support."""
    clean_host = hostname.strip().rstrip(".").lower()
    candidates = [san.strip().rstrip(".").lower() for san in san_list]
    if common_name and not candidates:
        candidates.append(common_name.strip().rstrip(".").lower())

    for cand in candidates:
        if cand == clean_host:
            return True
        if cand.startswith("*."):
            suffix = cand[1:]  # .example.com
            host_parts = clean_host.split(".")
            cand_parts = cand.split(".")
            # Wildcards only match one level: *.example.com matches sub.example.com, not deep.sub.example.com
            if len(host_parts) == len(cand_parts) and clean_host.endswith(suffix):
                return True
    return False


def parse_peer_certificate(cert_dict: dict, requested_host: str) -> TLSCertificateInfo:
    """Extract structured TLSCertificateInfo from an ssl peer certificate dictionary."""
    subject = _format_x509_name(cert_dict.get("subject", ()))
    issuer = _format_x509_name(cert_dict.get("issuer", ()))

    valid_from_iso, valid_from_dt = _parse_cert_date(cert_dict.get("notBefore"))
    valid_to_iso, valid_to_dt = _parse_cert_date(cert_dict.get("notAfter"))

    now = datetime.now(timezone.utc)
    is_expired = False
    days_to_expiration = None
    if valid_to_dt:
        is_expired = valid_to_dt < now
        days_to_expiration = int((valid_to_dt - now).total_seconds() / 86400)

    san_list: List[str] = []
    for san_type, san_val in cert_dict.get("subjectAltName", ()):
        if san_type == "DNS":
            san_list.append(san_val)

    common_name = subject.get("commonName")
    san_matches = _check_san_matches(requested_host, san_list, common_name)

    serial = cert_dict.get("serialNumber")
    version = cert_dict.get("version")

    return TLSCertificateInfo(
        subject=subject,
        issuer=issuer,
        valid_from=valid_from_iso,
        valid_to=valid_to_iso,
        is_expired=is_expired,
        days_to_expiration=days_to_expiration,
        san_list=san_list,
        san_matches=san_matches,
        serial_number=str(serial) if serial is not None else None,
        version=version
    )


def inspect_tls_certificate(
    hostname: str,
    port: int = 443,
    pinned_ip: Optional[str] = None,
    timeout_seconds: float = 3.0,
    socket_factory: Optional[Callable[..., Any]] = None
) -> TLSAnalysisResult:
    """Perform comprehensive, safe TLS certificate and cipher inspection.
    
    Args:
        hostname: Target domain or hostname.
        port: TLS port (default 443).
        pinned_ip: Optional pre-verified safe IP address to connect to.
        timeout_seconds: Socket timeout.
        socket_factory: Optional hook producing (sock, ssl_context) for testing.
        
    Returns:
        Structured TLSAnalysisResult with certificate details, ciphers, and findings.
    """
    clean_host = hostname.strip()
    if "://" in clean_host:
        parsed = urllib.parse.urlsplit(clean_host)
        clean_host = parsed.hostname or clean_host
        if parsed.port:
            port = parsed.port
    clean_host = clean_host.rstrip(".").lower()

    findings: List[TechnicalFinding] = []
    limitations: List[TechnicalLimitation] = []

    # 1. SSRF Destination Validation: Validate target IP strictly before socket creation
    target_ip: Optional[str] = None
    if pinned_ip:
        parsed_pinned = parse_ip_safely(pinned_ip)
        if parsed_pinned is None:
            return TLSAnalysisResult(
                hostname=clean_host,
                port=port,
                status=TLSStatus.SSRF_BLOCKED,
                is_valid=False,
                is_trusted=False,
                verification_error=f"Supplied pinned IP '{pinned_ip}' is unparseable",
                findings=[
                    TechnicalFinding(
                        module="tls",
                        check_name="SSRF_DESTINATION_BLOCKED_IN_TLS",
                        severity=FindingSeverity.CRITICAL,
                        title="Unparseable Pinned IP Destination Blocked",
                        description=f"Supplied pinned IP '{pinned_ip}' is not a valid IPv4 or IPv6 address.",
                        evidence={"hostname": clean_host, "pinned_ip": pinned_ip},
                        remediation="Do not connect to unparseable IP addresses."
                    )
                ]
            )
        is_safe, blocked_reason, flags = evaluate_ip_safety(parsed_pinned)
        if not is_safe:
            return TLSAnalysisResult(
                hostname=clean_host,
                port=port,
                status=TLSStatus.SSRF_BLOCKED,
                is_valid=False,
                is_trusted=False,
                verification_error=f"Supplied pinned IP {pinned_ip} prohibited: {blocked_reason}",
                findings=[
                    TechnicalFinding(
                        module="tls",
                        check_name="SSRF_DESTINATION_BLOCKED_IN_TLS",
                        severity=FindingSeverity.CRITICAL,
                        title="Prohibited Pinned IP Destination Blocked in TLS Inspection",
                        description=f"Supplied pinned IP '{pinned_ip}' targets a prohibited network: {blocked_reason}",
                        evidence={"hostname": clean_host, "pinned_ip": pinned_ip, "flags": flags},
                        remediation="Do not connect to private, loopback, link-local, or cloud metadata IP destinations."
                    )
                ]
            )
        target_ip = str(parsed_pinned)
    else:
        ssrf_res = validate_destination_safety(
            hostname_or_ip=clean_host,
            port=port,
            resolve_dns=True,
            dns_timeout=timeout_seconds
        )
        if not ssrf_res.is_safe:
            return TLSAnalysisResult(
                hostname=clean_host,
                port=port,
                status=TLSStatus.SSRF_BLOCKED,
                is_valid=False,
                is_trusted=False,
                verification_error=ssrf_res.blocked_reason or "SSRF destination prohibited",
                findings=[
                    TechnicalFinding(
                        module="tls",
                        check_name="SSRF_DESTINATION_BLOCKED_IN_TLS",
                        severity=FindingSeverity.CRITICAL,
                        title="Prohibited Destination Blocked in TLS Inspection",
                        description=f"SSRF guard blocked connection to '{clean_host}': {ssrf_res.blocked_reason}",
                        evidence={"hostname": clean_host, "reason": ssrf_res.blocked_reason},
                        remediation="Do not connect to private or metadata addresses."
                    )
                ]
            )
        if not ssrf_res.resolved_ips:
            return TLSAnalysisResult(
                hostname=clean_host,
                port=port,
                status=TLSStatus.UNAVAILABLE,
                is_valid=False,
                is_trusted=False,
                verification_error="DNS resolution produced 0 valid address records."
            )
        target_ip = ssrf_res.resolved_ips[0]

    # Offline disclosure limitations (honesty in reporting)
    limitations.append(
        TechnicalLimitation(
            module="tls",
            reason="Certificate revocation (OCSP/CRL) not checked in offline mode",
            impact="Revoked certificates may not be detected without live CA query."
        )
    )
    limitations.append(
        TechnicalLimitation(
            module="tls",
            reason="Certificate Transparency (CT) logs not queried in offline mode",
            impact="Issuance log presence cannot be verified independently."
        )
    )

    # 2. Establish Verified TLS Handshake
    try:
        if socket_factory:
            raw_sock, ctx = socket_factory(clean_host, port, target_ip, timeout_seconds)
            ssock = ctx.wrap_socket(raw_sock, server_hostname=clean_host)
        else:
            try:
                import certifi
                ctx = ssl.create_default_context(cafile=certifi.where())
            except Exception:
                ctx = ssl.create_default_context()
            raw_sock = socket.create_connection((target_ip, port), timeout=timeout_seconds)
            ssock = ctx.wrap_socket(raw_sock, server_hostname=clean_host)

        with ssock:
            cert_dict = ssock.getpeercert()
            cipher_info = ssock.cipher()
            tls_ver = ssock.version()
            alpn = ssock.selected_alpn_protocol()

        cert_details = parse_peer_certificate(cert_dict, clean_host)
        conn_details = TLSConnectionInfo(
            tls_version=tls_ver,
            cipher_name=cipher_info[0] if cipher_info else None,
            cipher_bits=cipher_info[2] if cipher_info else None,
            alpn_protocol=alpn
        )

        status = TLSStatus.VALID
        ca_trust = "TRUSTED_CA"

        # Check for certificate expiration
        if cert_details.is_expired:
            status = TLSStatus.EXPIRED
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="EXPIRED_TLS_CERTIFICATE",
                    severity=FindingSeverity.HIGH,
                    title="Expired TLS Certificate",
                    description=f"Certificate expired on {cert_details.valid_to}.",
                    evidence={"valid_to": cert_details.valid_to},
                    remediation="Renew and install an active, valid TLS certificate."
                )
            )
        elif cert_details.days_to_expiration is not None and cert_details.days_to_expiration <= 14:
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="TLS_CERTIFICATE_EXPIRING_SOON",
                    severity=FindingSeverity.LOW,
                    title="TLS Certificate Expiring Soon",
                    description=f"Certificate expires in {cert_details.days_to_expiration} days ({cert_details.valid_to}).",
                    evidence={"days_remaining": cert_details.days_to_expiration},
                    remediation="Plan certificate renewal prior to expiration."
                )
            )

        # Check for SAN mismatch
        if not cert_details.san_matches:
            status = TLSStatus.HOSTNAME_MISMATCH
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="TLS_HOSTNAME_MISMATCH",
                    severity=FindingSeverity.HIGH,
                    title="Certificate Name Mismatch",
                    description=f"The certificate SANs ({', '.join(cert_details.san_list[:5])}) do not match '{clean_host}'.",
                    evidence={"hostname": clean_host, "san_list": cert_details.san_list},
                    remediation="Issue certificate matching the exact domain name or appropriate wildcard."
                )
            )

        # Informational note on valid certificate (trust principle: HTTPS != legitimate business)
        if status == TLSStatus.VALID:
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="VALID_TRANSPORT_ENCRYPTION",
                    severity=FindingSeverity.INFO,
                    title="Valid TLS Transport Encryption",
                    description="Certificate is valid and chained to a recognized CA. Note: Transport encryption protects confidentiality in transit; it does not guarantee the business legitimacy or freedom from fraud of the domain owner.",
                    evidence={"issuer": cert_details.issuer, "subject": cert_details.subject},
                    remediation="Transport security is valid."
                )
            )

        # Check weak cipher / protocol
        if conn_details.cipher_bits and conn_details.cipher_bits < 128:
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="WEAK_TLS_CONFIGURATION",
                    severity=FindingSeverity.MEDIUM,
                    title="Weak Cipher Suite Negotiated",
                    description=f"Negotiated cipher '{conn_details.cipher_name}' provides only {conn_details.cipher_bits} bits of key strength.",
                    evidence={"cipher": conn_details.cipher_name, "bits": conn_details.cipher_bits},
                    remediation="Disable weak ciphers and require modern AES-GCM or ChaCha20-Poly1305 ciphers."
                )
            )

        return TLSAnalysisResult(
            hostname=clean_host,
            port=port,
            status=status,
            is_valid=(status == TLSStatus.VALID),
            is_trusted=True,
            certificate=cert_details,
            connection=conn_details,
            ca_trust_status=ca_trust,
            findings=findings,
            limitations=limitations
        )

    except ssl.SSLCertVerificationError as ssl_ver_err:
        err_msg = str(ssl_ver_err).lower()
        ca_trust = "UNTRUSTED_CA"
        status = TLSStatus.UNTRUSTED_CHAIN

        if "self-signed" in err_msg or "self signed" in err_msg:
            status = TLSStatus.SELF_SIGNED
            ca_trust = "SELF_SIGNED"
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="SELF_SIGNED_TLS_CERTIFICATE",
                    severity=FindingSeverity.HIGH,
                    title="Self-Signed Certificate Detected",
                    description="The certificate is self-signed and not signed by a recognized Certificate Authority.",
                    evidence={"error": str(ssl_ver_err)},
                    remediation="Obtain a valid certificate from a publicly trusted CA (e.g. Let's Encrypt)."
                )
            )
        elif "expired" in err_msg:
            status = TLSStatus.EXPIRED
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="EXPIRED_TLS_CERTIFICATE",
                    severity=FindingSeverity.HIGH,
                    title="Expired TLS Certificate",
                    description="The server certificate is expired.",
                    evidence={"error": str(ssl_ver_err)},
                    remediation="Renew and deploy an active certificate."
                )
            )
        elif "hostname" in err_msg or "doesn't match" in err_msg:
            status = TLSStatus.HOSTNAME_MISMATCH
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="TLS_HOSTNAME_MISMATCH",
                    severity=FindingSeverity.HIGH,
                    title="Certificate Name Mismatch",
                    description="The certificate does not match the requested hostname.",
                    evidence={"error": str(ssl_ver_err)},
                    remediation="Ensure certificate covers the requested domain."
                )
            )
        else:
            findings.append(
                TechnicalFinding(
                    module="tls",
                    check_name="UNTRUSTED_CERTIFICATE_CHAIN",
                    severity=FindingSeverity.HIGH,
                    title="Untrusted Certificate Chain",
                    description=f"Certificate chain validation failed: {str(ssl_ver_err)}",
                    evidence={"error": str(ssl_ver_err)},
                    remediation="Ensure intermediate certificates are installed."
                )
            )

        return TLSAnalysisResult(
            hostname=clean_host,
            port=port,
            status=status,
            is_valid=False,
            is_trusted=False,
            ca_trust_status=ca_trust,
            verification_error=str(ssl_ver_err),
            findings=findings,
            limitations=limitations
        )

    except socket.timeout:
        limitations.append(
            TechnicalLimitation(
                module="tls",
                reason=f"TLS handshake timed out after {timeout_seconds}s",
                impact="Unable to inspect TLS certificate."
            )
        )
        return TLSAnalysisResult(
            hostname=clean_host,
            port=port,
            status=TLSStatus.TIMEOUT,
            is_valid=False,
            is_trusted=False,
            verification_error=f"TLS handshake timed out after {timeout_seconds}s",
            limitations=limitations
        )
    except (socket.error, ConnectionRefusedError, ssl.SSLError) as conn_err:
        limitations.append(
            TechnicalLimitation(
                module="tls",
                reason=f"TLS connection failure: {str(conn_err)}",
                impact="Target does not support HTTPS or connection refused."
            )
        )
        return TLSAnalysisResult(
            hostname=clean_host,
            port=port,
            status=TLSStatus.HANDSHAKE_FAILED,
            is_valid=False,
            is_trusted=False,
            verification_error=f"TLS connection error: {str(conn_err)}",
            limitations=limitations
        )
    except Exception as exc:
        return TLSAnalysisResult(
            hostname=clean_host,
            port=port,
            status=TLSStatus.UNAVAILABLE,
            is_valid=False,
            is_trusted=False,
            verification_error=f"Unexpected TLS inspection error: {str(exc)}",
            limitations=limitations
        )

