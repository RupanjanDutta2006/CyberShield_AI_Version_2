"""CyberShield AI — Severity & Indicator Classification Models (Part 14)

Defines data structures for classified indicators, evidence authority weights,
and deduplicated indicator aggregation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
)


class ClassifiedIndicator(BaseModel):
    """An individual security indicator with decoupled severity, authority, and weight."""
    indicator_id: str = Field(..., description="Unique deterministic identifier")
    title: str = Field(..., description="Indicator title")
    category: EvidenceCategory = Field(..., description="Functional source category")
    severity: StandardSeverity = Field(..., description="Inherent potential harm or risk")
    authority: EvidenceAuthority = Field(..., description="Provenance authority level")
    base_weight: int = Field(default=0, ge=0, le=100, description="Inherent severity weight (0-100)")
    effective_weight: float = Field(default=0.0, ge=0.0, le=100.0, description="Authority-calibrated weight")
    source_modules: List[str] = Field(default_factory=list, description="Originating modules")
    corroboration_count: int = Field(default=1, ge=1, description="Number of distinct sources confirming issue")
    underlying_issue_key: str = Field(..., description="Grouping key to prevent double counting")
    is_authoritative_threat: bool = Field(default=False, description="Whether indicator is definitive proof of malice")
    is_heuristic_only: bool = Field(default=True, description="Whether indicator is purely heuristic")
    explanation: str = Field(..., description="Classification rationale")


class IndicatorClassificationResult(BaseModel):
    """Outcome of classifying a set of standardized evidence items."""
    classified_indicators: List[ClassifiedIndicator] = Field(default_factory=list)
    total_indicators: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    info_severity_count: int = 0
    authoritative_threat_count: int = 0
    has_authoritative_malicious_evidence: bool = False
    max_indicator_severity: StandardSeverity = StandardSeverity.INFORMATIONAL
    deduplicated_issue_count: int = 0

