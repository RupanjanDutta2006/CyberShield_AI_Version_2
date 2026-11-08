"""CyberShield AI — Final Risk Report Generator (Part 16)

Assembles standardized evidence, deterministic risk evaluations, threat intelligence,
and AI analysis into a unified, versioned threat intelligence report.
"""

import uuid
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timezone

from app.schemas.common import (
    RiskClassification,
    ScanType,
    AnalysisStatus,
    FindingSeverity,
    TechnicalFinding,
    VerificationStatus,
)
from app.schemas.threat_report import (
    UnifiedThreatReport,
    RiskAssessment,
    SubmittedInput,
)
from app.schemas.threat_intel import ThreatIntelSourceResult, ThreatIntelSummary
from app.schemas.ai_analysis import MessageAnalysisResponse
from app.schemas.blockchain import ReportIntegrityMetadata
from app.schemas.evidence import (
    EvidenceCollection,
    EvidenceCategory,
    StandardSeverity,
    CheckStatus,
)
from app.schemas.risk import DeterministicRiskResult
from app.services.evidence.normalizer import (
    normalize_evidence,
    redact_sensitive_url_and_params,
)
from app.services.risk_engine.engine import evaluate_risk


def _map_standard_severity_to_finding_severity(sev: StandardSeverity) -> FindingSeverity:
    """Map standardized 4-tier severity enum to common finding severity enum."""
    if sev == StandardSeverity.HIGH:
        return FindingSeverity.HIGH
    if sev == StandardSeverity.MEDIUM:
        return FindingSeverity.MEDIUM
    if sev == StandardSeverity.LOW:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def generate_recommendations(
    classification: RiskClassification,
    collection: EvidenceCollection,
    risk_result: DeterministicRiskResult,
) -> List[str]:
    """Generate deterministic, evidence-grounded security recommendations."""
    recs: List[str] = []

    # 1. Primary verdict guidance
    if classification == RiskClassification.CONFIRMED_MALICIOUS:
        recs.append("DO NOT interact with this website. Block all network traffic and email communication from this domain immediately.")
        recs.append("If credentials or financial details were previously submitted on this site, change affected passwords and notify security teams immediately.")
    elif classification == RiskClassification.HIGH_RISK:
        recs.append("Avoid entering credentials, personal information, or financial details on this site. Significant threat indicators detected.")
        recs.append("Do not download or execute files from this destination.")
    elif classification == RiskClassification.SUSPICIOUS:
        recs.append("Exercise caution before trusting this website. Verify the identity of the organization via official, independent channels.")
        recs.append("Check the domain spelling carefully for deceptive character substitutions or suspicious subdomains.")
    elif classification == RiskClassification.LOW_RISK:
        recs.append("No significant malicious indicators were observed in the checks performed. Maintain standard digital hygiene.")
        recs.append("Always verify that you are connecting over HTTPS before submitting private information.")
    else:  # INCONCLUSIVE
        recs.append("Security checks were incomplete or target infrastructure could not be reached. Treat this destination as unverified.")
        recs.append("Re-scan the target once network connectivity is restored or after verifying that the domain is actively registered.")

    # 2. Finding-specific recommendations
    for item in collection.items:
        title_lower = item.title.lower()
        if "tls" in title_lower or "certificate" in title_lower or item.category == EvidenceCategory.TLS:
            if item.severity in (StandardSeverity.HIGH, StandardSeverity.MEDIUM):
                tls_rec = "The website lacks a valid, trusted TLS certificate. Do not submit sensitive data over unencrypted or untrusted connections."
                if tls_rec not in recs:
                    recs.append(tls_rec)
        if "hsts" in title_lower or "content-security-policy" in title_lower or item.category == EvidenceCategory.SECURITY_HEADERS:
            hdr_rec = "Website administrators should configure strict transport security (HSTS) and content security policies (CSP) to defend against injection attacks."
            if hdr_rec not in recs and len(recs) < 5:
                recs.append(hdr_rec)
        if "brand" in title_lower or "impersonation" in title_lower or "punycode" in title_lower:
            brand_rec = "Inspect the URL carefully for homograph spoofing or misleading brand name characters."
            if brand_rec not in recs:
                recs.append(brand_rec)
        if "redirect" in title_lower and ("loop" in title_lower or "circular" in title_lower):
            redir_rec = "Investigate server redirect rules to resolve circular HTTP redirection loops."
            if redir_rec not in recs:
                recs.append(redir_rec)
        if item.category == EvidenceCategory.AI_ANALYSIS:
            ai_rec = "Be alert for psychological pressure tactics, urgency cues, or unsolicited credential requests."
            if ai_rec not in recs:
                recs.append(ai_rec)

    return recs


def build_threat_report(
    target: str,
    target_type: ScanType = ScanType.URL,
    scan_id: Optional[str] = None,
    collection: Optional[EvidenceCollection] = None,
    risk_result: Optional[DeterministicRiskResult] = None,
    threat_intel: Optional[Union[ThreatIntelSummary, List[ThreatIntelSourceResult]]] = None,
    ai_analysis: Optional[MessageAnalysisResponse] = None,
) -> UnifiedThreatReport:
    """Build a complete, schema-valid UnifiedThreatReport from evidence and risk evaluations.
    
    Args:
        target: Target URL, domain, or message.
        target_type: Category of input (URL, DOMAIN, MESSAGE).
        scan_id: Optional UUIDv4 string (generated if omitted).
        collection: Standardized evidence collection from Part 13.
        risk_result: Deterministic risk outcome from Part 15.
        threat_intel: Threat intelligence results from Member 4.
        ai_analysis: AI scam analysis from Member 2.
        
    Returns:
        UnifiedThreatReport adhering strictly to master shared schema.
    """
    sid = scan_id or str(uuid.uuid4())
    sanitized_target = redact_sensitive_url_and_params(target)

    # If collection is omitted, generate an empty/inconclusive collection
    if collection is None:
        collection = normalize_evidence(target=sanitized_target)

    # If risk_result is omitted, evaluate from collection
    if risk_result is None:
        risk_result = evaluate_risk(collection)

    # Convert standardized evidence items to TechnicalFinding models
    technical_findings: List[TechnicalFinding] = []
    for item in collection.items:
        # Exclude AI analysis and Threat Intel from technical_findings list
        # (they belong in their dedicated schema fields)
        if item.category in (EvidenceCategory.AI_ANALYSIS, EvidenceCategory.THREAT_INTEL):
            continue
        technical_findings.append(TechnicalFinding(
            module=item.source_module,
            check_name=item.finding_id,
            severity=_map_standard_severity_to_finding_severity(item.severity),
            title=item.title,
            description=item.description,
            evidence=item.evidence or None,
            remediation=None,
        ))

    # Process threat intelligence
    ti_sources: List[ThreatIntelSourceResult] = []
    if threat_intel is not None:
        if isinstance(threat_intel, ThreatIntelSummary):
            ti_sources = threat_intel.sources
        elif isinstance(threat_intel, list):
            ti_sources = threat_intel

    # Determine status
    if risk_result.classification == RiskClassification.INCONCLUSIVE:
        if collection.coverage.coverage_ratio == 0:
            analysis_status = AnalysisStatus.FAILED
        else:
            analysis_status = AnalysisStatus.PARTIAL
    else:
        analysis_status = AnalysisStatus.COMPLETED

    # Build recommendations
    recommendations = generate_recommendations(risk_result.classification, collection, risk_result)

    # Build limitations list
    limitations: List[str] = list(collection.limitations)
    if risk_result.has_conflicting_evidence and risk_result.conflict_notes:
        limitations.append(f"[conflict] {risk_result.conflict_notes}")

    # Build master UnifiedThreatReport
    return UnifiedThreatReport(
        schema_version="1.0.0",
        scan_id=sid,
        status=analysis_status,
        submitted_input=SubmittedInput(
            type=target_type,
            value=sanitized_target,
            normalized_at=datetime.now(timezone.utc).isoformat(),
        ),
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk=RiskAssessment(
            classification=risk_result.classification,
            score=risk_result.score,
            confidence=risk_result.confidence,
            method=risk_result.method,
            summary=risk_result.explanation,
        ),
        evidence_coverage=collection.coverage,
        technical_findings=technical_findings,
        threat_intelligence=ti_sources,
        ai_analysis=ai_analysis,
        recommendations=recommendations,
        limitations=limitations,
        report_integrity=ReportIntegrityMetadata(
            verification_status=VerificationStatus.NOT_REGISTERED,
            report_hash=None,
            blockchain_network=None,
            contract_address=None,
            transaction_hash=None,
        ),
        persistence_metadata=None,
    )


def assemble_unified_threat_report(
    target: str,
    target_type: ScanType = ScanType.URL,
    scan_id: Optional[str] = None,
    preflight: Optional[Any] = None,
    technical_investigation: Optional[Any] = None,
    threat_intel: Optional[Union[ThreatIntelSummary, List[ThreatIntelSourceResult]]] = None,
    ai_analysis: Optional[MessageAnalysisResponse] = None,
    custom_limitations: Optional[List[str]] = None,
) -> UnifiedThreatReport:
    """End-to-end assembly pipeline: Normalization -> Severity -> Risk Engine -> Unified Report.
    
    Executes Parts 13, 14, 15, and 16 sequentially in memory without making outbound network
    requests or AI provider calls.
    """
    # Part 13: Evidence Collection & Normalization
    collection = normalize_evidence(
        target=target,
        preflight=preflight,
        technical_investigation=technical_investigation,
        threat_intel=threat_intel,
        ai_analysis=ai_analysis,
        custom_limitations=custom_limitations,
    )

    # Part 14 & 15: Severity Classification & Deterministic Risk Evaluation
    risk_result = evaluate_risk(collection)

    # Part 16: Final Report Assembly
    return build_threat_report(
        target=target,
        target_type=target_type,
        scan_id=scan_id,
        collection=collection,
        risk_result=risk_result,
        threat_intel=threat_intel,
        ai_analysis=ai_analysis,
    )

