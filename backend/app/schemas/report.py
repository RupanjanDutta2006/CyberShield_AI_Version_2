"""CyberShield AI — Report Generator Schemas (Part 16)

Provides helper contracts, report generation parameters, and re-exports
for the unified threat report pipeline.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.threat_report import (
    UnifiedThreatReport,
    RiskAssessment,
    SubmittedInput,
    PersistenceMetadata,
)
from app.schemas.common import RiskClassification, ScanType, AnalysisStatus, TechnicalFinding
from app.schemas.evidence import EvidenceCoverage


class ReportGenerationRequest(BaseModel):
    """Parameters passed to the unified threat report generator."""
    target: str = Field(..., description="Target URL, domain, or message under investigation")
    target_type: ScanType = Field(default=ScanType.URL, description="Category of input")
    scan_id: Optional[str] = Field(default=None, description="Optional custom scan ID (generated if omitted)")


__all__ = [
    "ReportGenerationRequest",
    "UnifiedThreatReport",
    "RiskAssessment",
    "SubmittedInput",
    "PersistenceMetadata",
    "RiskClassification",
    "ScanType",
    "AnalysisStatus",
    "TechnicalFinding",
    "EvidenceCoverage",
]

