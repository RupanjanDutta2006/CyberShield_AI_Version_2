"""CyberShield AI — Part 10: Safe Redirect Analysis Service

Inspects HTTP redirect behavior safely using controlled single-hop requests,
verified IP-pinning, destination SSRF validation at every hop, loop detection,
and bounds enforcement without executing active scripts or downloading untrusted bodies.
"""

import time
import urllib.parse
from typing import List, Optional, Callable
import httpx

from app.schemas.common import TechnicalFinding, TechnicalLimitation, FindingSeverity
from app.services.url_investigation.validation import validate_url_input
from app.services.url_investigation.normalization import normalize_url
from app.services.url_investigation.ssrf_guard import validate_destination_safety
from app.services.redirects.models import RedirectHopRecord, RedirectAnalysisResult
from app.services.redirects.transport import PinnedHTTPTransport

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
DEFAULT_USER_AGENT = "CyberShield-Security-Auditor/1.0 (Defensive URL Scanner)"


def trace_redirects(
    url: str,
    max_redirects: int = 5,
    timeout_per_hop: float = 3.0,
    total_timeout: float = 10.0,
    client_factory: Optional[Callable[[str], httpx.Client]] = None
) -> RedirectAnalysisResult:
    """Safely trace HTTP redirect chains with per-hop destination validation and IP pinning.
    
    Args:
        url: Starting URL to investigate.
        max_redirects: Maximum allowed redirects before aborting.
        timeout_per_hop: Timeout in seconds for an individual request.
        total_timeout: Overall timeout budget for the entire redirect traversal.
        client_factory: Optional factory producing httpx.Client for testing/mocking.
        
    Returns:
        Structured RedirectAnalysisResult.
    """
    start_time = time.perf_counter()
    hops: List[RedirectHopRecord] = []
    visited_urls: List[str] = []
    findings: List[TechnicalFinding] = []
    limitations: List[TechnicalLimitation] = []

    current_url = url
    stopped_reason = "FINAL_DESTINATION_REACHED"
    destination_ip_safe = True
    has_circular = False

    while len(hops) <= max_redirects:
        # Check overall timeout budget
        elapsed_total = time.perf_counter() - start_time
        if elapsed_total > total_timeout:
            stopped_reason = "TOTAL_TIMEOUT_EXCEEDED"
            limitations.append(
                TechnicalLimitation(
                    module="redirects",
                    reason=f"Redirect inspection exceeded overall timeout budget of {total_timeout}s",
                    impact="Chain inspection terminated early."
                )
            )
            break

        hop_idx = len(hops)

        # 1. Part 05 Input Validation
        val_res = validate_url_input(current_url)
        if not val_res.is_valid:
            stopped_reason = "INVALID_REDIRECT_TARGET"
            destination_ip_safe = False
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    is_safe=False,
                    blocked_reason=f"Invalid URL structure: {val_res.error_message}"
                )
            )
            findings.append(
                TechnicalFinding(
                    module="redirects",
                    check_name="MALFORMED_REDIRECT_TARGET",
                    severity=FindingSeverity.HIGH,
                    title="Malformed or Unsupported Redirect Destination",
                    description=f"Redirect chain attempted to navigate to invalid URL: {current_url}",
                    evidence={"url": current_url, "error_code": val_res.error_code},
                    remediation="Do not follow unvalidated redirect destinations."
                )
            )
            break

        # 2. Part 06 Normalization
        norm_res = normalize_url(val_res.raw_input)
        canonical_current = norm_res.normalized_url

        # 3. Detect Circular Redirect Loops
        if canonical_current in visited_urls:
            has_circular = True
            stopped_reason = "REDIRECT_LOOP_DETECTED"
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    is_safe=True,
                    blocked_reason="Circular redirect loop detected"
                )
            )
            findings.append(
                TechnicalFinding(
                    module="redirects",
                    check_name="CIRCULAR_REDIRECT_LOOP",
                    severity=FindingSeverity.MEDIUM,
                    title="Circular Redirect Loop Detected",
                    description=f"The URL redirects back to previously visited destination: {current_url}",
                    evidence={"visited_chain": visited_urls, "loop_target": current_url},
                    remediation="Inspect server-side routing configuration to eliminate redirect loops."
                )
            )
            break

        # 4. Part 07 SSRF Guard (with DNS resolution)
        ssrf_res = validate_destination_safety(
            hostname_or_ip=norm_res.hostname,
            port=norm_res.port,
            resolve_dns=True,
            dns_timeout=timeout_per_hop
        )

        if not ssrf_res.is_safe:
            destination_ip_safe = False
            stopped_reason = "SSRF_BLOCKED_HOP"
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    is_safe=False,
                    blocked_reason=ssrf_res.blocked_reason or "Prohibited destination"
                )
            )
            findings.append(
                TechnicalFinding(
                    module="redirects",
                    check_name="SSRF_REDIRECT_PREVENTED",
                    severity=FindingSeverity.CRITICAL,
                    title="Prohibited Internal / Metadata Destination Blocked in Redirect",
                    description=f"Redirect target '{current_url}' attempted to reach prohibited destination: {ssrf_res.blocked_reason}",
                    evidence={"url": current_url, "blocked_reason": ssrf_res.blocked_reason},
                    remediation="Strictly block requests attempting to reach private, loopback, or metadata services."
                )
            )
            break

        # 5. Extract Pinned IP
        if not ssrf_res.resolved_ips:
            stopped_reason = "DNS_RESOLUTION_FAILED"
            destination_ip_safe = False
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    is_safe=False,
                    blocked_reason="No resolved IP address available for destination"
                )
            )
            break

        pinned_ip = ssrf_res.resolved_ips[0]

        # 6. Execute Controlled Request with IP Pinning
        visited_urls.append(canonical_current)
        req_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close"
        }

        try:
            if client_factory:
                client = client_factory(pinned_ip)
            else:
                transport = PinnedHTTPTransport(pinned_ip=pinned_ip, verify=True)
                client = httpx.Client(
                    transport=transport,
                    follow_redirects=False,
                    timeout=timeout_per_hop,
                    trust_env=False
                )

            with client:
                resp = client.get(current_url, headers=req_headers)
                status_code = resp.status_code
                loc_header = resp.headers.get("Location")
                captured_headers = {k: v for k, v in resp.headers.items() if len(v) < 256}

                hop_record = RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=status_code,
                    resolved_ip=pinned_ip,
                    location_header=loc_header,
                    is_safe=True,
                    response_headers=captured_headers
                )
                hops.append(hop_record)

                # Check if this response is a redirect
                if status_code in REDIRECT_STATUS_CODES and loc_header:
                    if len(hops) >= max_redirects:
                        stopped_reason = "MAX_REDIRECTS_EXCEEDED"
                        findings.append(
                            TechnicalFinding(
                                module="redirects",
                                check_name="EXCESSIVE_REDIRECT_CHAIN",
                                severity=FindingSeverity.LOW,
                                title="Excessive Redirect Chain Length",
                                description=f"URL exceeded maximum redirect limit ({max_redirects} hops). Long chains are often used in traffic-redirection networks to evade scanners.",
                                evidence={"hop_count": len(hops), "max_allowed": max_redirects},
                                remediation="Review intermediate redirectors and reduce unnecessary hops."
                            )
                        )
                        break

                    # Resolve relative or absolute target
                    next_url = urllib.parse.urljoin(current_url, loc_header)

                    # Security finding: HTTPS to HTTP downgrade detection
                    if current_url.lower().startswith("https:") and next_url.lower().startswith("http:"):
                        findings.append(
                            TechnicalFinding(
                                module="redirects",
                                check_name="INSECURE_REDIRECT_DOWNGRADE",
                                severity=FindingSeverity.HIGH,
                                title="Insecure HTTPS to HTTP Downgrade in Redirect",
                                description=f"Redirect chain downgraded security from HTTPS to unencrypted HTTP ({next_url}).",
                                evidence={"source_url": current_url, "target_url": next_url},
                                remediation="Enforce HTTPS throughout the entire redirect chain."
                            )
                        )

                    current_url = next_url
                    continue
                else:
                    # Non-redirect response reached (e.g. 200, 403, 404)
                    stopped_reason = "FINAL_DESTINATION_REACHED"
                    break

        except httpx.ConnectTimeout:
            stopped_reason = "CONNECT_TIMEOUT"
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    resolved_ip=pinned_ip,
                    is_safe=True,
                    blocked_reason=f"Connection timed out after {timeout_per_hop}s"
                )
            )
            limitations.append(
                TechnicalLimitation(
                    module="redirects",
                    reason=f"Connection to {current_url} timed out",
                    impact="Target endpoint was unreachable."
                )
            )
            break
        except httpx.ConnectError as conn_err:
            stopped_reason = "CONNECTION_FAILED"
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    resolved_ip=pinned_ip,
                    is_safe=True,
                    blocked_reason=f"Connection failed: {str(conn_err)}"
                )
            )
            limitations.append(
                TechnicalLimitation(
                    module="redirects",
                    reason=f"Connection failure on {current_url}",
                    impact="Cannot inspect endpoint response."
                )
            )
            break
        except Exception as exc:
            stopped_reason = "REQUEST_ERROR"
            err_msg = str(exc) if str(exc) else exc.__class__.__name__
            hops.append(
                RedirectHopRecord(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    resolved_ip=pinned_ip,
                    is_safe=True,
                    blocked_reason=f"Request error: {err_msg}"
                )
            )
            break

    # Determine final destination URL
    final_url = hops[-1].url if hops and hops[-1].status_code not in REDIRECT_STATUS_CODES and hops[-1].status_code > 0 else (current_url if hops else None)

    return RedirectAnalysisResult(
        initial_url=url,
        final_url=final_url,
        hop_count=len(hops),
        hops=hops,
        has_circular_redirect=has_circular,
        destination_ip_safe=destination_ip_safe,
        stopped_reason=stopped_reason,
        findings=findings,
        limitations=limitations
    )

