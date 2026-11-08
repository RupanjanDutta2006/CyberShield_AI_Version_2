"""CyberShield AI — Deterministic Risk Engine Schemas (Part 15)

Defines models for risk rules, scoring outcomes, contributing factors,
and explainability breakdowns.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.common import RiskClassification
from app.schemas.evidence import StandardSeverity, EvidenceAuthority


class ContributingFactor(BaseModel):
    """An individual finding that directly contributed to the risk verdict."""
    indicator_id: str
    title: str
    severity: StandardSeverity
    authority: EvidenceAuthority
    weight_contribution: float
    reason: str


class TriggeredRule(BaseModel):
    """An auditable rule executed during deterministic risk evaluation."""
    rule_id: str
    rule_name: str
    description: str
    matched: bool
    applied_classification: Optional[RiskClassification] = None


class DeterministicRiskResult(BaseModel):
    """Authoritative outcome of deterministic risk engine evaluation."""
    classification: RiskClassification = Field(..., description="5-tier authoritative verdict")
    score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Deterministic risk score (0-100), or None if inconclusive"
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Evidence coverage and data completeness score (0.0 to 1.0)"
    )
    method: str = Field(
        default="deterministic_rule_engine_v1",
        description="Methodology and version reference"
    )
    explanation: str = Field(..., description="Plain-language justification for the verdict")
    summary: str = Field(..., description="Executive verdict summary")
    contributing_factors: List[ContributingFactor] = Field(default_factory=list)
    triggered_rules: List[TriggeredRule] = Field(default_factory=list)
    coverage_ratio: float = Field(default=1.0, ge=0.0, le=1.0)
    has_conflicting_evidence: bool = False
    conflict_notes: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)

