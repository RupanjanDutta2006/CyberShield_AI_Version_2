"""CyberShield AI — Schemas Package

Exports shared contracts for Member 1, 2, 3, and 4.
"""

from app.schemas.common import (
    RiskClassification,
    ScanType,
    AnalysisStatus,
    FindingSeverity,
    VerificationStatus,
    TechnicalFinding,
    TechnicalLimitation,
)
from app.schemas.url_scan import (
    URLScanRequest,
    DNSFindingDetails,
    RedirectHop,
    RedirectFindingDetails,
    TLSFindingDetails,
    SecurityHeaderFindingDetails,
    TechnicalFindingsSummary,
    URLValidationResult,
    URLNormalizationResult,
    SSRFValidationResult,
    URLPreFlightResult,
)
from app.schemas.ai_analysis import (
    ObservedIndicator,
    ExtractedIndicators,
    MessageAnalysisRequest,
    MessageAnalysisResponse,
)
from app.schemas.threat_intel import (
    ThreatIntelSourceResult,
    ThreatIntelLookupRequest,
    ThreatIntelSummary,
)
from app.schemas.blockchain import (
    ReportIntegrityMetadata,
    ReportRegistrationRequest,
    ReportRegistrationResponse,
    ReportVerificationRequest,
    ReportVerificationResponse,
)
from app.schemas.threat_report import (
    SubmittedInput,
    RiskAssessment,
    PersistenceMetadata,
    UnifiedThreatReport,
)
from app.schemas.evidence import (
    CheckStatus,
    EvidenceAuthority,
    StandardSeverity,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)
from app.schemas.risk import (
    ContributingFactor,
    TriggeredRule,
    DeterministicRiskResult,
)
from app.schemas.report import (
    ReportGenerationRequest,
)

__all__ = [
    "RiskClassification",
    "ScanType",
    "AnalysisStatus",
    "FindingSeverity",
    "VerificationStatus",
    "TechnicalFinding",
    "TechnicalLimitation",
    "URLScanRequest",
    "DNSFindingDetails",
    "RedirectHop",
    "RedirectFindingDetails",
    "TLSFindingDetails",
    "SecurityHeaderFindingDetails",
    "TechnicalFindingsSummary",
    "URLValidationResult",
    "URLNormalizationResult",
    "SSRFValidationResult",
    "URLPreFlightResult",
    "DNSInvestigationResult",
    "DNSStatus",
    "RedirectAnalysisResult",
    "RedirectHopRecord",
    "TLSAnalysisResult",
    "TLSCertificateInfo",
    "TLSConnectionInfo",
    "TLSStatus",
    "SecurityHeaderAnalysisResult",
    "SingleHeaderAnalysis",
    "HeaderEvaluationStatus",
    "TechnicalInvestigationResult",
    "ObservedIndicator",
    "ExtractedIndicators",
    "MessageAnalysisRequest",
    "MessageAnalysisResponse",
    "ThreatIntelSourceResult",
    "ThreatIntelLookupRequest",
    "ThreatIntelSummary",
    "ReportIntegrityMetadata",
    "ReportRegistrationRequest",
    "ReportRegistrationResponse",
    "ReportVerificationRequest",
    "ReportVerificationResponse",
    "SubmittedInput",
    "RiskAssessment",
    "PersistenceMetadata",
    "UnifiedThreatReport",
    "CheckStatus",
    "EvidenceAuthority",
    "StandardSeverity",
    "EvidenceCategory",
    "StandardizedEvidenceItem",
    "EvidenceCoverage",
    "EvidenceCollection",
    "ContributingFactor",
    "TriggeredRule",
    "DeterministicRiskResult",
    "ReportGenerationRequest",
    "DNSInvestigationResult",
    "DNSStatus",
    "RedirectAnalysisResult",
    "RedirectHopRecord",
    "TLSAnalysisResult",
    "TLSCertificateInfo",
    "TLSConnectionInfo",
    "TLSStatus",
    "SecurityHeaderAnalysisResult",
    "SingleHeaderAnalysis",
    "HeaderEvaluationStatus",
    "TechnicalInvestigationResult",
]


def __getattr__(name: str):
    """Dynamically resolve Batch 3 investigation schemas to eliminate circular imports."""
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
    return sorted(set(list(globals().keys()) + __all__))



