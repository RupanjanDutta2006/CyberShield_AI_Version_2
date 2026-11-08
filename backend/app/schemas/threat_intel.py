"""CyberShield AI — Threat Intelligence Schemas

Shared contract for Member 4 (Threat Intelligence, Database & Frontend Engineer).
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ThreatIntelSourceResult(BaseModel):
    """Normalized response from an individual threat intelligence provider."""
    source: str = Field(
        ...,
        description="Provider name (e.g. URLhaus, Google Safe Browsing, OpenPhish)"
    )
    checked_at: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of lookup"
    )
    match: bool = Field(
        ...,
        description="Whether target was identified as a known threat"
    )
    threat_type: Optional[str] = Field(
        default=None,
        description="Classification of threat if matched (e.g. phishing, malware, c2)"
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Supporting feed data, tags, or report URLs"
    )
    source_status: str = Field(
        default="available",
        description="Status of feed lookup (e.g. available, rate_limited, timeout, error, not_configured)"
    )
    investigation_mode: Optional[str] = Field(
        default=None,
        description="Investigation mode: LIVE_QUERIED, LOCAL_CORPUS_ONLY, NOT_CONFIGURED, TIMEOUT, FAILED, UNAVAILABLE"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Known limitations (e.g. feed only reflects reported malware URLs)"
    )


class ThreatIntelLookupRequest(BaseModel):
    """Internal or API request for threat intelligence lookup."""
    target: str = Field(..., description="Target URL, domain, or IP")
    target_type: str = Field(default="url", description="url, domain, or ip")


class ThreatIntelSummary(BaseModel):
    """Aggregated threat intelligence summary."""
    total_sources_queried: int = 0
    matched_sources_count: int = 0
    sources: List[ThreatIntelSourceResult] = Field(default_factory=list)
    has_authoritative_match: bool = False

