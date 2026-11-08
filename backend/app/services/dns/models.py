"""CyberShield AI — Part 09: DNS Investigation Models

Data contracts and schemas for DNS resolution, record queries, and SSRF validation.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.schemas.common import TechnicalFinding, TechnicalLimitation
from app.schemas.url_scan import DNSFindingDetails


class DNSStatus(str, Enum):
    """Standardized DNS resolution status outcomes."""
    SUCCESS = "SUCCESS"
    NXDOMAIN = "NXDOMAIN"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    EMPTY_ANSWER = "EMPTY_ANSWER"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_DOMAIN = "INVALID_DOMAIN"
    SSRF_BLOCKED = "SSRF_BLOCKED"


class DNSInvestigationResult(BaseModel):
    """Complete structured findings from DNS investigation (Part 09)."""
    domain: str = Field(..., description="Investigated domain or hostname")
    status: DNSStatus = Field(..., description="High-level resolution outcome")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of the lookup"
    )
    query_time_ms: float = Field(default=0.0, description="Elapsed lookup time in milliseconds")
    a_records: List[str] = Field(default_factory=list, description="Resolved IPv4 addresses (A records)")
    aaaa_records: List[str] = Field(default_factory=list, description="Resolved IPv6 addresses (AAAA records)")
    cname_records: List[str] = Field(default_factory=list, description="Canonical names (CNAME records)")
    mx_records: List[str] = Field(default_factory=list, description="Mail exchanger records (MX records)")
    ns_records: List[str] = Field(default_factory=list, description="Name server records (NS records)")
    all_resolved_ips: List[str] = Field(default_factory=list, description="Combined list of all resolved A and AAAA IPs")
    is_destination_safe: bool = Field(default=True, description="Whether all resolved IPs passed SSRF evaluation")
    blocked_reason: Optional[str] = Field(default=None, description="SSRF block reason if any resolved IP was prohibited")
    findings: List[TechnicalFinding] = Field(default_factory=list, description="Technical observations and security indicators")
    limitations: List[TechnicalLimitation] = Field(default_factory=list, description="Documented investigation constraints")
    notes: Optional[str] = Field(default=None, description="Additional context or diagnostics")

    def to_dns_finding_details(self) -> DNSFindingDetails:
        """Convert into backward-compatible DNSFindingDetails for unified threat reports."""
        return DNSFindingDetails(
            domain=self.domain,
            a_records=self.a_records,
            aaaa_records=self.aaaa_records,
            mx_records=self.mx_records,
            ns_records=self.ns_records,
            has_valid_dns=self.status == DNSStatus.SUCCESS and len(self.all_resolved_ips) > 0,
            notes=self.notes or (f"DNS lookup status: {self.status.value}" + (f" - Blocked: {self.blocked_reason}" if self.blocked_reason else ""))
        )

