"""CyberShield AI — Unified Threat Report Generator Tests (Part 16 & Cross-Part Integration)

Validates schema compliance, deterministic report assembly, evidence-grounded
recommendations, blockchain placeholders, and end-to-end pipeline integration.
"""

import uuid
import pytest
from app.schemas.common import (
    RiskClassification,
    ScanType,
    AnalysisStatus,
    VerificationStatus,
    TechnicalFinding,
    FindingSeverity,
)
from app.schemas.threat_report import UnifiedThreatReport
from app.schemas.threat_intel import ThreatIntelSourceResult
from app.schemas.ai_analysis import MessageAnalysisResponse, ObservedIndicator
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)
from app.services.report_generator.builder import (
    build_threat_report,
    assemble_unified_threat_report,
    generate_recommendations,
)
from app.services.risk_engine.engine import evaluate_risk


def test_build_report_for_all_five_risk_classifications():
    """Verify valid UnifiedThreatReport construction across all 5 risk tiers."""
    tiers = [
        RiskClassification.LOW_RISK,
        RiskClassification.SUSPICIOUS,
        RiskClassification.HIGH_RISK,
        RiskClassification.CONFIRMED_MALICIOUS,
        RiskClassification.INCONCLUSIVE,
    ]

    for tier in tiers:
        # Mock corresponding evidence
        if tier == RiskClassification.CONFIRMED_MALICIOUS:
            items = [
                StandardizedEvidenceItem(
                    finding_id="ti_01",
                    category=EvidenceCategory.THREAT_INTEL,
                    severity=StandardSeverity.HIGH,
                    title="Malware Verified on Threat Feed",
                    description="Feed match.",
                    source_module="threat_intel_urlhaus",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                )
            ]
            coverage = EvidenceCoverage(completed=["threat_intel"], coverage_ratio=1.0)
        elif tier == RiskClassification.HIGH_RISK:
            items = [
                StandardizedEvidenceItem(
                    finding_id="h_01",
                    category=EvidenceCategory.HEURISTIC,
                    severity=StandardSeverity.HIGH,
                    title="Target Brand in Subdomain",
                    description="Impersonation.",
                    source_module="url_heuristics",
                    source_authority=EvidenceAuthority.HEURISTIC,
                ),
                StandardizedEvidenceItem(
                    finding_id="h_02",
                    category=EvidenceCategory.HEURISTIC,
                    severity=StandardSeverity.HIGH,
                    title="Punycode Homograph",
                    description="Spoofing.",
                    source_module="url_heuristics",
                    source_authority=EvidenceAuthority.HEURISTIC,
                ),
            ]
            coverage = EvidenceCoverage(completed=["url_heuristics"], coverage_ratio=1.0)
        elif tier == RiskClassification.SUSPICIOUS:
            items = [
                StandardizedEvidenceItem(
                    finding_id="h_01",
                    category=EvidenceCategory.HEURISTIC,
                    severity=StandardSeverity.MEDIUM,
                    title="Suspicious TLD",
                    description="Abuse TLD.",
                    source_module="url_heuristics",
                    source_authority=EvidenceAuthority.HEURISTIC,
                )
            ]
            coverage = EvidenceCoverage(completed=["url_heuristics"], coverage_ratio=1.0)
        elif tier == RiskClassification.LOW_RISK:
            items = []
            coverage = EvidenceCoverage(completed=["dns", "redirects", "tls", "headers"], coverage_ratio=1.0)
        else:  # INCONCLUSIVE
            items = []
            coverage = EvidenceCoverage(completed=[], failed=["dns"], coverage_ratio=0.0)

        coll = EvidenceCollection(
            target="https://test-target.test",
            items=items,
            coverage=coverage,
        )
        risk_res = evaluate_risk(coll)
        assert risk_res.classification == tier

        report = build_threat_report(
            target="https://test-target.test",
            target_type=ScanType.URL,
            collection=coll,
            risk_result=risk_res,
        )

        assert isinstance(report, UnifiedThreatReport)
        assert report.schema_version == "1.0.0"
        assert report.risk.classification == tier
        assert report.report_integrity.verification_status == VerificationStatus.NOT_REGISTERED
        assert report.report_integrity.report_hash is None
        assert len(report.recommendations) > 0


def test_unique_scan_id_and_submitted_input_sanitization():
    """Verify unique UUIDv4 generation and sensitive query parameter redaction."""
    raw_url = "https://bank.test/login?token=supersecret&user=bob"
    report1 = assemble_unified_threat_report(target=raw_url)
    report2 = assemble_unified_threat_report(target=raw_url)

    assert report1.scan_id != report2.scan_id
    # Valid UUIDv4
    uuid.UUID(report1.scan_id, version=4)
    uuid.UUID(report2.scan_id, version=4)

    # Redaction
    assert "supersecret" not in report1.submitted_input.value
    assert "token=%5BREDACTED%5D" in report1.submitted_input.value or "token=[REDACTED]" in report1.submitted_input.value
    assert "user=bob" in report1.submitted_input.value


def test_separation_of_ai_and_technical_findings():
    """Verify AI social engineering is stored in ai_analysis and not mixed into technical_findings."""
    ai_resp = MessageAnalysisResponse(
        category="phishing",
        risk_level="high_risk",
        confidence=0.85,
        observed_indicators=[
            ObservedIndicator(
                indicator="Urgent Security Verification",
                evidence="Click immediately",
                reason="Induces panic",
            )
        ],
        explanation="Deceptive alert mimicking security provider.",
        recommendations=["Do not reply"],
        limitations=["Sender unverified"],
    )

    report = assemble_unified_threat_report(
        target="https://phish.test",
        ai_analysis=ai_resp,
    )

    assert report.ai_analysis is not None
    assert report.ai_analysis.category == "phishing"
    # technical_findings should NOT contain the AI analysis finding directly
    assert all(tf.module != "ai_scam_model" for tf in report.technical_findings)


def test_end_to_end_cross_part_pipeline_with_threat_intel():
    """Verify complete end-to-end integration with mock threat intelligence match."""
    ti_feeds = [
        ThreatIntelSourceResult(
            source="URLhaus",
            checked_at="2026-11-07T12:00:00Z",
            match=True,
            threat_type="malware_download",
            evidence=["active_payload"],
            source_status="available",
        )
    ]

    report = assemble_unified_threat_report(
        target="https://malicious-drop.test/download.exe",
        threat_intel=ti_feeds,
    )

    assert report.risk.classification == RiskClassification.CONFIRMED_MALICIOUS
    assert report.risk.score is not None and report.risk.score >= 90
    assert len(report.threat_intelligence) == 1
    assert report.threat_intelligence[0].source == "URLhaus"
    assert any("DO NOT interact" in rec for rec in report.recommendations)


def test_security_gate_scan_url_remains_disabled():
    """Verify /api/v1/scan-url remains strictly HTTP 501 Not Implemented."""
    from starlette.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.post("/api/v1/scan-url", json={"url": "https://example.com"})
    assert resp.status_code == 501
    assert "Security Gate" in resp.json()["detail"] or "gated" in resp.json()["detail"]

