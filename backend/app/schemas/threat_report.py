"""CyberShield AI — Unified Threat Report Schema

Master shared contract combining technical findings, threat intelligence,
AI scam analysis, deterministic risk engine assessment, and Web3 integrity.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from app.schemas.common import (
    RiskClassification,
    ScanType,
    AnalysisStatus,
    TechnicalFinding,
)
from app.schemas.ai_analysis import MessageAnalysisResponse
from app.schemas.threat_intel import ThreatIntelSourceResult
from app.schemas.blockchain import ReportIntegrityMetadata
from app.schemas.evidence import EvidenceCoverage


class SubmittedInput(BaseModel):
    """Normalized intake representation of the investigated target."""
    type: ScanType = Field(..., description="Target category: url, domain, message")
    value: str = Field(..., description="Normalized URL, domain, or sanitized message excerpt")
    normalized_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of normalization"
    )


class RiskAssessment(BaseModel):
    """Deterministic risk classification and explainable scoring."""
    classification: RiskClassification = Field(
        default=RiskClassification.INCONCLUSIVE,
        description="Authoritative 5-tier classification"
    )
    score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "Prototype heuristic score from 0 (no score-raising indicators observed in checks performed; "
            "does not prove the website is safe) to 100 (maximum risk / confirmed threat indicators), "
            "or None if inconclusive"
        )
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Heuristic confidence score between 0.0 and 1.0 reflecting the authority and strength "
            "of observed findings (minimum 0.85 for Confirmed Malicious). Distinct from physical "
            "evidence coverage ratio, which is reported separately in evidence_coverage.coverage_ratio."
        )
    )
    method: str = Field(
        default="deterministic_rule_engine_v1",
        description="Auditable engine methodology reference"
    )
    summary: str = Field(
        default="Analysis pending",
        description="Concise, non-technical explanation of the risk verdict"
    )


class PersistenceMetadata(BaseModel):
    """Off-chain database storage metadata."""
    stored_at: Optional[str] = None
    database_id: Optional[str] = None
    retrieval_count: int = 0


class UnifiedThreatReport(BaseModel):
    """Master Versioned Threat Intelligence & Digital Trust Report."""
    schema_version: str = Field(
        default="1.0.0",
        description="Semantic version of the report contract"
    )
    scan_id: str = Field(
        ...,
        description="Unique UUIDv4 identifying this investigation"
    )
    status: AnalysisStatus = Field(
        default=AnalysisStatus.COMPLETED,
        description="Status of the overall analysis"
    )
    submitted_input: SubmittedInput = Field(
        ...,
        description="Normalized target metadata"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC generation timestamp"
    )
    risk: RiskAssessment = Field(
        default_factory=RiskAssessment,
        description="Deterministic risk classification and scores"
    )
    evidence_coverage: Optional[EvidenceCoverage] = Field(
        default=None,
        description="Detailed audit of completed, unavailable, and failed checks"
    )
    technical_findings: List[TechnicalFinding] = Field(
        default_factory=list,
        description="All deterministic technical findings (DNS, TLS, Headers, Redirects)"
    )
    threat_intelligence: List[ThreatIntelSourceResult] = Field(
        default_factory=list,
        description="Results from queried threat intelligence feeds"
    )
    ai_analysis: Optional[MessageAnalysisResponse] = Field(
        default=None,
        description="AI social-engineering analysis (if scam message was analyzed)"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable precautions and security guidance"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Omitted, failed, or out-of-scope inspection limits"
    )
    report_integrity: ReportIntegrityMetadata = Field(
        default_factory=ReportIntegrityMetadata,
        description="Blockchain commitment and verification metadata"
    )
    persistence_metadata: Optional[PersistenceMetadata] = Field(
        default=None,
        description="Off-chain database record tracking"
    )

