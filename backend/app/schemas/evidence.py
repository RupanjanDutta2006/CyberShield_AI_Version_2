"""CyberShield AI — Standardized Evidence Schemas (Part 13)

Defines unified evidence data models, check status enums, evidence authority tiers,
and coverage metrics for aggregating investigation findings across all modules.
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    """Operational state of an individual security check or module investigation."""
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PARTIAL = "PARTIAL"


class EvidenceAuthority(str, Enum):
    """Trustworthiness and verification level of an evidence source."""
    AUTHORITATIVE = "AUTHORITATIVE"      # Verified external feed, crypto failure, direct network rejection
    CORROBORATED = "CORROBORATED"        # Multiple independent sources confirming identical observation
    HEURISTIC = "HEURISTIC"              # Pattern matching, statistical anomaly, missing defense header
    UNKNOWN = "UNKNOWN"                  # Unrecognized or unverified provenance


class StandardSeverity(str, Enum):
    """Normalized four-tier severity classification for technical indicators."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceCategory(str, Enum):
    """Functional origin category of observed security indicators."""
    URL_SYNTAX = "url_syntax"
    HEURISTIC = "heuristic"
    DNS = "dns"
    REDIRECT = "redirect"
    TLS = "tls"
    SECURITY_HEADERS = "security_headers"
    THREAT_INTEL = "threat_intel"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM = "system"


class StandardizedEvidenceItem(BaseModel):
    """A single normalized, provenance-tracked security observation or indicator."""
    finding_id: str = Field(..., description="Unique deterministic identifier for this evidence item")
    category: EvidenceCategory = Field(..., description="Functional source category")
    severity: StandardSeverity = Field(..., description="Normalized 4-tier severity")
    title: str = Field(..., description="Human-readable title of the observation")
    description: str = Field(..., description="Detailed technical or operational explanation")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Sanitized key-value supporting evidence")
    source_module: str = Field(..., description="Originating module or service name")
    source_authority: EvidenceAuthority = Field(default=EvidenceAuthority.HEURISTIC, description="Provenance authority level")
    observed_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 UTC timestamp of actual upstream observation, or None if unknown/unrecorded"
    )
    normalized_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp when standardized/normalized"
    )
    check_status: CheckStatus = Field(default=CheckStatus.COMPLETED, description="Status of the inspection check")
    relevant_target: Optional[str] = Field(default=None, description="Specific URL, domain, or IP evaluated")
    original_references: List[str] = Field(default_factory=list, description="Original source finding IDs or check names")
    correlations: List[str] = Field(default_factory=list, description="Correlated indicators or shared infrastructure nodes")
    is_conflicting: bool = Field(default=False, description="Whether this finding contradicts another observation")
    conflict_details: Optional[str] = Field(default=None, description="Details of the conflicting observation if present")


class EvidenceCoverage(BaseModel):
    """Audit of which checks were completed, unavailable, failed, or skipped."""
    completed: List[str] = Field(default_factory=list, description="Modules/checks that finished successfully")
    unavailable: List[str] = Field(default_factory=list, description="Modules/checks that were offline or unavailable")
    failed: List[str] = Field(default_factory=list, description="Modules/checks that encountered unrecoverable runtime errors")
    skipped: List[str] = Field(default_factory=list, description="Modules/checks skipped due to prerequisites or policy")
    not_applicable: List[str] = Field(default_factory=list, description="Checks not applicable to the target (e.g. TLS for plain HTTP)")
    partial: List[str] = Field(default_factory=list, description="Modules that completed partially")
    coverage_ratio: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Fraction of applicable checks successfully executed"
    )


class EvidenceCollection(BaseModel):
    """Aggregate collection of standardized evidence items and investigation metadata."""
    target: str = Field(..., description="Submitted target identifier or sanitized URL")
    collected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC collection timestamp"
    )
    items: List[StandardizedEvidenceItem] = Field(default_factory=list, description="Standardized evidence items")
    coverage: EvidenceCoverage = Field(default_factory=EvidenceCoverage, description="Investigation execution coverage")
    correlated_domains: List[str] = Field(default_factory=list, description="Unique domains involved across checks")
    correlated_ips: List[str] = Field(default_factory=list, description="Unique IP addresses resolved across checks")
    limitations: List[str] = Field(default_factory=list, description="Operational boundaries or omitted inspections")

