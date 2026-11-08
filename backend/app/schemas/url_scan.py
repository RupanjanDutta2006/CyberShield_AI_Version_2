"""CyberShield AI — URL Scan Schemas

Defines request and technical finding contracts for URL and domain scans.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl
from app.schemas.common import AnalysisStatus, TechnicalFinding, TechnicalLimitation


class URLScanRequest(BaseModel):
    """Client request model for URL investigation."""
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="Target URL or domain to investigate",
        examples=["https://example.com/login"]
    )
    force_refresh: bool = Field(
        default=False,
        description="Whether to bypass cache and execute fresh inspection"
    )


class DNSFindingDetails(BaseModel):
    """DNS inspection details."""
    domain: str
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    has_valid_dns: Optional[bool] = Field(
        default=None,
        description="Whether DNS resolved valid records (None=unchecked, True=valid, False=invalid/NXDOMAIN)"
    )
    notes: Optional[str] = None


class RedirectHop(BaseModel):
    """A single hop in a redirect chain."""
    hop_number: int
    url: str
    status_code: int
    resolved_ip: Optional[str] = None


class RedirectFindingDetails(BaseModel):
    """Redirect chain inspection details."""
    initial_url: str
    final_url: Optional[str] = None
    hop_count: int = 0
    hops: List[RedirectHop] = Field(default_factory=list)
    has_circular_redirect: Optional[bool] = Field(
        default=None,
        description="Whether circular redirect loops were detected (None=unchecked, True=loop detected, False=no loop)"
    )
    destination_ip_safe: Optional[bool] = Field(
        default=None,
        description="Whether destination IP was checked and confirmed safe (None=unchecked, True=safe, False=unsafe/SSRF prohibited)"
    )


class TLSFindingDetails(BaseModel):
    """TLS certificate and trust chain findings."""
    hostname: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    is_expired: Optional[bool] = Field(
        default=None,
        description="Whether certificate is expired (None=unchecked, True=expired, False=valid)"
    )
    days_to_expiration: Optional[int] = None
    san_matches: Optional[bool] = Field(
        default=None,
        description="Whether SANs match hostname (None=unchecked, True=matches, False=mismatch)"
    )
    san_list: List[str] = Field(default_factory=list)
    weak_algorithm_detected: Optional[bool] = Field(
        default=None,
        description="Whether weak signature or cipher was found (None=unchecked, True=weak, False=robust)"
    )
    ca_trust_status: str = "unknown"
    certificate_transparency_present: Optional[bool] = None


class SecurityHeaderFindingDetails(BaseModel):
    """Passive HTTP security headers analysis."""
    hsts_present: Optional[bool] = Field(
        default=None,
        description="Whether HSTS header is present (None=unchecked, True=present, False=absent)"
    )
    csp_present: Optional[bool] = Field(
        default=None,
        description="Whether CSP header is present (None=unchecked, True=present, False=absent)"
    )
    x_frame_options_present: Optional[bool] = Field(
        default=None,
        description="Whether X-Frame-Options is present (None=unchecked, True=present, False=absent)"
    )
    x_content_type_options_present: Optional[bool] = Field(
        default=None,
        description="Whether X-Content-Type-Options is present (None=unchecked, True=present, False=absent)"
    )
    missing_recommended_headers: List[str] = Field(default_factory=list)
    server_banner: Optional[str] = None


class TechnicalFindingsSummary(BaseModel):
    """Aggregated technical inspection container."""
    dns: Optional[DNSFindingDetails] = None
    redirects: Optional[RedirectFindingDetails] = None
    tls: Optional[TLSFindingDetails] = None
    headers: Optional[SecurityHeaderFindingDetails] = None
    detailed_findings: List[TechnicalFinding] = Field(default_factory=list)


# =============================================================================
# Batch 2 — URL Investigation Pipeline Models (Parts 05–08)
# =============================================================================

class URLValidationResult(BaseModel):
    """Result of Part 05 URL Input Validation."""
    is_valid: bool = Field(..., description="Whether the input is structurally valid and permitted")
    raw_input: str = Field(..., description="Original input provided to the validator")
    error_code: Optional[str] = Field(default=None, description="Standardized error code if invalid")
    error_message: Optional[str] = Field(default=None, description="Safe user-facing error message without credential leakage")
    sanitized_input: Optional[str] = Field(default=None, description="Input string with credentials or illegal tokens redacted")
    parsed_scheme: Optional[str] = Field(default=None, description="Extracted URL scheme (e.g. http, https)")
    parsed_hostname: Optional[str] = Field(default=None, description="Extracted hostname")
    parsed_port: Optional[int] = Field(default=None, description="Explicit port number if specified and valid")
    has_credentials: bool = Field(default=False, description="Whether embedded credentials were detected in input")


class URLNormalizationResult(BaseModel):
    """Result of Part 06 URL Normalization."""
    original_url: str = Field(..., description="Submitted URL before normalization")
    normalized_url: str = Field(..., description="Canonical normalized URL representation (preserves exact path slashes)")
    scheme: str = Field(..., description="Canonical lowercase scheme")
    hostname: str = Field(..., description="Canonical lowercase hostname")
    unicode_hostname: Optional[str] = Field(default=None, description="Unicode (IDN) representation of hostname")
    punycode_hostname: Optional[str] = Field(default=None, description="ASCII Punycode representation of hostname (xn--)")
    is_idn: bool = Field(default=False, description="Whether the hostname uses internationalized characters")
    port: Optional[int] = Field(default=None, description="Non-default port number (omitted if standard 80/443)")
    path: str = Field(default="/", description="Normalized URL path (preserving repeated slashes to maintain request semantics)")
    display_path: Optional[str] = Field(default=None, description="Collapsed path for UI display only; never used for HTTP request dispatch")
    query: Optional[str] = Field(default=None, description="Normalized query string")
    fragment: Optional[str] = Field(default=None, description="URL fragment identifier if present")
    registrable_domain: Optional[str] = Field(default=None, description="Registrable domain (eTLD+1) extracted via PSL rules, or None if unknown/bare suffix")


class SSRFValidationResult(BaseModel):
    """Result of Part 07 IP & Hostname Security Validation (SSRF Protection)."""
    is_safe: bool = Field(..., description="Whether the destination is confirmed safe from SSRF/internal network risks")
    target_type: str = Field(default="hostname", description="'hostname' or 'ip'")
    hostname_or_ip: str = Field(..., description="The hostname or IP evaluated")
    resolved_ips: List[str] = Field(default_factory=list, description="All resolved IP addresses inspected")
    blocked_reason: Optional[str] = Field(default=None, description="Reason for rejection if blocked")
    is_loopback: bool = Field(default=False, description="Whether address resolves to loopback range (127.0.0.0/8, ::1)")
    is_private: bool = Field(default=False, description="Whether address resolves to RFC1918 or private range")
    is_link_local: bool = Field(default=False, description="Whether address resolves to link-local range (169.254.0.0/16, fe80::/10)")
    is_multicast: bool = Field(default=False, description="Whether address resolves to multicast range")
    is_reserved: bool = Field(default=False, description="Whether address resolves to reserved/special-purpose range")
    is_metadata_endpoint: bool = Field(default=False, description="Whether address resolves to cloud metadata endpoint")


class URLPreFlightResult(BaseModel):
    """Result of Batch 2 Complete URL Investigation Pre-Flight Pipeline."""
    submitted_url: str = Field(..., description="Raw URL submitted for investigation")
    validation: URLValidationResult = Field(..., description="Part 05 Input validation result")
    normalization: Optional[URLNormalizationResult] = Field(default=None, description="Part 06 URL normalization result")
    ssrf_validation: Optional[SSRFValidationResult] = Field(default=None, description="Part 07 SSRF safety result")
    heuristic_findings: List[TechnicalFinding] = Field(default_factory=list, description="Part 08 Suspicious pattern indicators")
    is_eligible_for_scan: bool = Field(default=False, description="Whether URL passed all preflight checks safely")
    gate_status: str = Field(default="BLOCKED", description="'PASSED_PREFLIGHT', 'INVALID_INPUT', 'SSRF_BLOCKED', or 'REJECTED'")


# =============================================================================
# Batch 3 — Technical Website Investigation Pipeline Models (Parts 09–12)
# Re-exported dynamically via PEP 562 to avoid circular dependencies with services
# =============================================================================

def __getattr__(name: str):
    if name in ("DNSInvestigationResult", "DNSStatus"):
        from app.services.dns.models import DNSInvestigationResult, DNSStatus
        return locals()[name]
    if name in ("RedirectAnalysisResult", "RedirectHopRecord"):
        from app.services.redirects.models import RedirectAnalysisResult, RedirectHopRecord
        return locals()[name]
    if name in ("TLSAnalysisResult", "TLSCertificateInfo", "TLSConnectionInfo", "TLSStatus"):
        from app.services.tls_analysis.models import TLSAnalysisResult, TLSCertificateInfo, TLSConnectionInfo, TLSStatus
        return locals()[name]
    if name in ("SecurityHeaderAnalysisResult", "SingleHeaderAnalysis", "HeaderEvaluationStatus"):
        from app.services.security_headers.models import SecurityHeaderAnalysisResult, SingleHeaderAnalysis, HeaderEvaluationStatus
        return locals()[name]
    if name == "TechnicalInvestigationResult":
        from app.services.technical_investigation import TechnicalInvestigationResult
        return TechnicalInvestigationResult
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__():
    batch3_exports = [
        "DNSInvestigationResult", "DNSStatus",
        "RedirectAnalysisResult", "RedirectHopRecord",
        "TLSAnalysisResult", "TLSCertificateInfo", "TLSConnectionInfo", "TLSStatus",
        "SecurityHeaderAnalysisResult", "SingleHeaderAnalysis", "HeaderEvaluationStatus",
        "TechnicalInvestigationResult",
    ]
    return sorted(set(list(globals().keys()) + batch3_exports))





