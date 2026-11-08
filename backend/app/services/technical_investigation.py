"""CyberShield AI — Technical Website Investigation Coordinator (Stage 3: Parts 09–12)

Orchestrates technical website investigation modules:
- Part 09: DNS & Domain Investigation
- Part 10: Safe Redirect Analysis
- Part 11: TLS & SSL Certificate Analysis
- Part 12: HTTP Security Headers Analysis

Fails closed on SSRF violations, enforces verified IP pinning, aggregates technical findings,
and maps cleanly to existing TechnicalFindingsSummary schema.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.common import TechnicalFinding, TechnicalLimitation, AnalysisStatus
from app.schemas.url_scan import TechnicalFindingsSummary
from app.services.url_investigation.validation import validate_url_input
from app.services.url_investigation.normalization import normalize_url
from app.services.url_investigation.ssrf_guard import validate_destination_safety
from app.services.dns import investigate_dns, DNSInvestigationResult
from app.services.redirects import trace_redirects, RedirectAnalysisResult
from app.services.tls_analysis import inspect_tls_certificate, TLSAnalysisResult, TLSStatus
from app.services.security_headers import analyze_security_headers_from_dict, SecurityHeaderAnalysisResult


class TechnicalInvestigationResult(BaseModel):
    """Aggregated outcome of complete Stage 3 Technical Website Investigation."""
    target_url: str = Field(..., description="Target URL analyzed")
    status: AnalysisStatus = Field(default=AnalysisStatus.COMPLETED, description="Overall analysis status")
    dns: Optional[DNSInvestigationResult] = Field(default=None, description="Part 09 DNS investigation")
    redirects: Optional[RedirectAnalysisResult] = Field(default=None, description="Part 10 Safe redirect analysis")
    tls: Optional[TLSAnalysisResult] = Field(default=None, description="Part 11 TLS analysis")
    headers: Optional[SecurityHeaderAnalysisResult] = Field(default=None, description="Part 12 Security headers analysis")
    all_findings: List[TechnicalFinding] = Field(default_factory=list, description="All accumulated technical findings")
    all_limitations: List[TechnicalLimitation] = Field(default_factory=list, description="All accumulated technical limitations")

    def to_technical_findings_summary(self) -> TechnicalFindingsSummary:
        """Convert into backward-compatible TechnicalFindingsSummary for unified reports."""
        return TechnicalFindingsSummary(
            dns=self.dns.to_dns_finding_details() if self.dns else None,
            redirects=self.redirects.to_redirect_finding_details() if self.redirects else None,
            tls=self.tls.to_tls_finding_details() if self.tls else None,
            headers=self.headers.to_security_header_finding_details() if self.headers else None,
            detailed_findings=self.all_findings
        )


def investigate_technical_website(
    url: str,
    max_redirects: int = 5,
    timeout_per_step: float = 3.0,
    client_factory: Optional[Any] = None,
    socket_factory: Optional[Any] = None
) -> TechnicalInvestigationResult:
    """Execute complete Stage 3 Technical Website Investigation (Parts 09–12).
    
    1. Validates and normalizes input URL.
    2. Runs SSRF safety gate. If blocked, aborts immediately.
    3. Part 09: Resolves DNS and auxiliary records.
    4. Part 10: Traces redirect chain using verified-IP pinning.
    5. Part 11: Inspects TLS certificate if destination uses HTTPS.
    6. Part 12: Evaluates passive security headers from final response.
    7. Aggregates all technical findings and limitations.
    
    Args:
        url: Target URL to investigate.
        max_redirects: Maximum redirect hops allowed.
        timeout_per_step: Timeout in seconds for individual operations.
        client_factory: Optional mock client factory for testing.
        socket_factory: Optional mock socket factory for testing.
        
    Returns:
        TechnicalInvestigationResult containing complete technical intelligence.
    """
    findings: List[TechnicalFinding] = []
    limitations: List[TechnicalLimitation] = []

    # 1. Intake Validation
    val_res = validate_url_input(url)
    if not val_res.is_valid:
        return TechnicalInvestigationResult(
            target_url=url,
            status=AnalysisStatus.FAILED,
            all_limitations=[
                TechnicalLimitation(
                    module="technical_investigation",
                    reason=f"URL input rejected: {val_res.error_message}",
                    impact="Technical investigation aborted."
                )
            ]
        )

    # 2. Normalization
    norm_res = normalize_url(val_res.raw_input)

    # 3. Destination Safety Check
    ssrf_res = validate_destination_safety(
        hostname_or_ip=norm_res.hostname,
        port=norm_res.port,
        resolve_dns=True,
        dns_timeout=timeout_per_step
    )
    if not ssrf_res.is_safe:
        return TechnicalInvestigationResult(
            target_url=norm_res.normalized_url,
            status=AnalysisStatus.FAILED,
            all_limitations=[
                TechnicalLimitation(
                    module="technical_investigation",
                    reason=f"Target prohibited by SSRF guard: {ssrf_res.blocked_reason}",
                    impact="Outbound technical investigation blocked."
                )
            ]
        )

    pinned_ip = ssrf_res.resolved_ips[0] if ssrf_res.resolved_ips else None

    # 4. Part 09: DNS Investigation
    dns_res = investigate_dns(
        norm_res.hostname,
        timeout_seconds=timeout_per_step,
        query_auxiliary_records=True
    )
    findings.extend(dns_res.findings)
    limitations.extend(dns_res.limitations)

    # If DNS was blocked by SSRF, stop outbound queries
    if not dns_res.is_destination_safe:
        return TechnicalInvestigationResult(
            target_url=norm_res.normalized_url,
            status=AnalysisStatus.PARTIAL,
            dns=dns_res,
            all_findings=findings,
            all_limitations=limitations
        )

    # 5. Part 10: Safe Redirect Analysis
    redirect_res = trace_redirects(
        norm_res.normalized_url,
        max_redirects=max_redirects,
        timeout_per_hop=timeout_per_step,
        client_factory=client_factory
    )
    findings.extend(redirect_res.findings)
    limitations.extend(redirect_res.limitations)

    # 6. Part 11: TLS Analysis (if initial or final URL is HTTPS)
    final_target = redirect_res.final_url or norm_res.normalized_url
    final_norm = normalize_url(final_target)
    tls_res = None

    if final_norm.scheme == "https":
        # Check if redirect chain reached an unsafe destination or was blocked by SSRF
        if not redirect_res.destination_ip_safe or any(not hop.is_safe for hop in redirect_res.hops):
            tls_res = TLSAnalysisResult(
                hostname=final_norm.hostname,
                port=final_norm.port or 443,
                status=TLSStatus.SSRF_BLOCKED,
                is_valid=False,
                is_trusted=False,
                verification_error="TLS inspection skipped: redirect chain targeted an unsafe or prohibited destination",
                limitations=[
                    TechnicalLimitation(
                        module="tls",
                        reason="Redirect chain blocked by SSRF guard",
                        impact="TLS connection was not attempted to unsafe destination."
                    )
                ]
            )
        else:
            # Obtain the final hop's validated destination IP from redirect analysis
            final_hop_ip = None
            if redirect_res.hops and redirect_res.hops[-1].resolved_ip:
                final_hop_ip = redirect_res.hops[-1].resolved_ip

            # If final validated IP is unavailable, do NOT fall back to initial IP!
            if not final_hop_ip:
                tls_res = TLSAnalysisResult(
                    hostname=final_norm.hostname,
                    port=final_norm.port or 443,
                    status=TLSStatus.UNAVAILABLE,
                    is_valid=False,
                    is_trusted=False,
                    verification_error="Final redirect destination IP is unavailable",
                    limitations=[
                        TechnicalLimitation(
                            module="tls",
                            reason="Final redirect destination IP is unavailable; fallback to initial target IP is disallowed",
                            impact="TLS analysis could not be completed."
                        )
                    ]
                )
            else:
                # Pass the final validated IP strictly to inspect_tls_certificate
                tls_res = inspect_tls_certificate(
                    hostname=final_norm.hostname,
                    port=final_norm.port or 443,
                    pinned_ip=final_hop_ip,
                    timeout_seconds=timeout_per_step,
                    socket_factory=socket_factory
                )
        findings.extend(tls_res.findings)
        limitations.extend(tls_res.limitations)

    # 7. Part 12: Security Headers Analysis (from final hop headers if available)
    header_res = None
    if redirect_res.hops and redirect_res.hops[-1].response_headers:
        final_headers = redirect_res.hops[-1].response_headers
        final_status = redirect_res.hops[-1].status_code
        header_res = analyze_security_headers_from_dict(
            headers=final_headers,
            url=final_target,
            status_code=final_status
        )
        findings.extend(header_res.findings)
        limitations.extend(header_res.limitations)

    # 8. Derive overall analysis status from component outcomes (B5-F08)
    dns_status_str = getattr(dns_res.status, "value", str(dns_res.status))
    has_dns_error = dns_status_str not in ("SUCCESS", "NXDOMAIN", "EMPTY_ANSWER")
    has_redirect_error = (
        redirect_res.stopped_reason not in ("FINAL_DESTINATION_REACHED", "MAX_REDIRECTS_EXCEEDED")
        or not redirect_res.destination_ip_safe
    )

    has_tls_error = False
    if final_norm.scheme == "https":
        if tls_res is None or tls_res.status in (
            TLSStatus.UNAVAILABLE,
            TLSStatus.TIMEOUT,
            TLSStatus.HANDSHAKE_FAILED,
            TLSStatus.SSRF_BLOCKED,
        ):
            has_tls_error = True

    has_header_error = header_res is None

    if has_dns_error and has_redirect_error:
        overall_status = AnalysisStatus.FAILED
    elif has_dns_error or has_redirect_error or has_tls_error or has_header_error:
        overall_status = AnalysisStatus.PARTIAL
    else:
        overall_status = AnalysisStatus.COMPLETED

    return TechnicalInvestigationResult(
        target_url=norm_res.normalized_url,
        status=overall_status,
        dns=dns_res,
        redirects=redirect_res,
        tls=tls_res,
        headers=header_res,
        all_findings=findings,
        all_limitations=limitations
    )

