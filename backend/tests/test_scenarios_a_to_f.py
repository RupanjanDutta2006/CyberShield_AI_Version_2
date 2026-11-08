"""CyberShield AI — Batch 4 Master Scenarios A through F Test Suite (B4-F01)

Validates the complete deterministic risk assessment engine across all 6 canonical
Batch 4 operational scenarios (A–F):
- Scenario A: Clear Benign Target (LOW_RISK)
- Scenario B: Suspicious Heuristic Target (SUSPICIOUS)
- Scenario C: High-Risk Infrastructure Cluster (HIGH_RISK)
- Scenario D: Confirmed Malicious via Authoritative Intelligence (CONFIRMED_MALICIOUS)
- Scenario E: Inconclusive on Critical Check Failure (INCONCLUSIVE)
- Scenario F: Conflicting Evidence Reconciliation (CONFIRMED_MALICIOUS with Conflict Disclosure)
"""

import pytest
from app.schemas.common import RiskClassification, ScanType, VerificationStatus
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)
from app.schemas.threat_intel import ThreatIntelSourceResult
from app.services.risk_engine.engine import evaluate_risk
from app.services.report_generator.builder import assemble_unified_threat_report


def make_test_collection(
    items=None,
    completed=None,
    failed=None,
    unavailable=None,
    coverage_ratio=1.0,
    target="https://scenario-test.example.com",
    limitations=None,
) -> EvidenceCollection:
    """Helper to assemble controlled EvidenceCollection for Scenario testing."""
    return EvidenceCollection(
        target=target,
        items=items or [],
        coverage=EvidenceCoverage(
            completed=completed or ["url_preflight", "dns_investigation", "redirect_analysis", "tls_analysis", "security_headers"],
            failed=failed or [],
            unavailable=unavailable or [],
            coverage_ratio=coverage_ratio,
        ),
        limitations=limitations or [],
    )


class TestBatch4ScenariosAToF:
    """Comprehensive test suite for Scenarios A through F."""

    def test_scenario_a_clear_benign_target(self):
        """Scenario A: Clearly benign target with full check coverage produces LOW_RISK.
        
        - All 5 baseline investigation checks complete successfully.
        - Zero security findings or threat feed flags.
        - Classification must be LOW_RISK.
        - Score must be strictly between 0 and 24.
        """
        coll = make_test_collection(
            items=[],
            completed=["url_preflight", "dns_investigation", "redirect_analysis", "tls_analysis", "security_headers"],
            coverage_ratio=1.0,
            target="https://benign-corporate-portal.com",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.LOW_RISK
        assert result.score is not None
        assert 0 <= result.score <= 24
        assert result.confidence is not None and result.confidence >= 0.90
        assert result.coverage_ratio == 1.0
        assert result.has_conflicting_evidence is False
        assert len(result.contributing_factors) == 0
        assert any(r.rule_id == "RULE-05-LOW-RISK" and r.matched for r in result.triggered_rules)

    def test_scenario_b_suspicious_heuristic_target(self):
        """Scenario B: Target with a single moderate heuristic anomaly produces SUSPICIOUS.
        
        - Target has a suspicious high-abuse TLD or unusual redirect pattern.
        - No authoritative threat feed matches.
        - Classification must be SUSPICIOUS.
        - Score must be strictly between 25 and 64.
        """
        item = StandardizedEvidenceItem(
            finding_id="h_suspicious_tld",
            category=EvidenceCategory.HEURISTIC,
            severity=StandardSeverity.MEDIUM,
            title="Suspicious Top-Level Domain Detected",
            description="Domain uses a top-level domain frequently associated with abuse.",
            source_module="url_heuristics",
            source_authority=EvidenceAuthority.HEURISTIC,
            raw_evidence={"tld": ".xyz"},
        )
        coll = make_test_collection(
            items=[item],
            target="https://check-account.xyz",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.SUSPICIOUS
        assert result.score is not None
        assert 25 <= result.score <= 64
        assert len(result.contributing_factors) >= 1
        assert any(r.rule_id == "RULE-04-SUSPICIOUS" and r.matched for r in result.triggered_rules)

    def test_scenario_c_high_risk_infrastructure_cluster(self):
        """Scenario C: Multiple independent high-severity indicators produce HIGH_RISK.
        
        - Raw IP host + Brand impersonation in subdomain + Punycode homograph.
        - No authoritative threat feed matches yet.
        - Classification must be HIGH_RISK.
        - Score must be strictly between 65 and 89.
        """
        item1 = StandardizedEvidenceItem(
            finding_id="h_brand_subdomain",
            category=EvidenceCategory.HEURISTIC,
            severity=StandardSeverity.HIGH,
            title="Financial Brand Name in Subdomain",
            description="Subdomain impersonates legitimate banking institution.",
            source_module="url_heuristics",
            source_authority=EvidenceAuthority.HEURISTIC,
        )
        item2 = StandardizedEvidenceItem(
            finding_id="h_punycode",
            category=EvidenceCategory.HEURISTIC,
            severity=StandardSeverity.HIGH,
            title="Punycode Homograph Domain Detected",
            description="Internationalized domain name mimics recognized brand.",
            source_module="url_normalization",
            source_authority=EvidenceAuthority.HEURISTIC,
        )
        coll = make_test_collection(
            items=[item1, item2],
            target="https://paypal.com.account-update.test",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.HIGH_RISK
        assert result.score is not None
        assert 65 <= result.score <= 89
        assert len(result.contributing_factors) >= 2
        assert any(r.rule_id == "RULE-03-HIGH-RISK" and r.matched for r in result.triggered_rules)

    def test_scenario_d_confirmed_malicious_authoritative_intel(self):
        """Scenario D: Verified threat intelligence match produces CONFIRMED_MALICIOUS.
        
        - Verified URLhaus payload download or Safe Browsing hit.
        - Classification must be CONFIRMED_MALICIOUS.
        - Score must be >= 90.
        - Calibrated confidence must be >= 0.85 regardless of partial coverage.
        """
        ti_item = StandardizedEvidenceItem(
            finding_id="ti_urlhaus_active",
            category=EvidenceCategory.THREAT_INTEL,
            severity=StandardSeverity.HIGH,
            title="Target Flagged on URLhaus Threat Feed",
            description="Active malware dropper host verified by security community.",
            source_module="threat_intel_urlhaus",
            source_authority=EvidenceAuthority.AUTHORITATIVE,
            is_authoritative_threat=True,
        )
        # Even with partial coverage (e.g. 0.40 completed), authoritative threat guarantees confidence >= 0.85
        coll = make_test_collection(
            items=[ti_item],
            completed=["url_preflight", "threat_intel"],
            coverage_ratio=0.40,
            target="https://malware-payload-distributor.test/dropper.exe",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.CONFIRMED_MALICIOUS
        assert result.score is not None
        assert result.score >= 90
        assert result.confidence is not None and result.confidence >= 0.85
        assert result.coverage_ratio == 0.40  # Coverage ratio accurately reflects physical completed checks
        assert any(r.rule_id == "RULE-02-CONFIRMED-MALICIOUS" and r.matched for r in result.triggered_rules)

    def test_scenario_e_inconclusive_on_critical_failure(self):
        """Scenario E: Critical DNS resolution failure yields INCONCLUSIVE.
        
        - DNS resolution failed or timed out.
        - Zero authoritative threat intelligence indicators.
        - Classification must be INCONCLUSIVE.
        - Numeric score must be None (not 0, to avoid false sense of safety).
        """
        coll = make_test_collection(
            items=[],
            completed=["url_preflight"],
            failed=["dns_investigation"],
            unavailable=["redirect_analysis", "tls_analysis", "security_headers"],
            coverage_ratio=0.20,
            target="https://unresolvable-dead-domain.test",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.INCONCLUSIVE
        assert result.score is None
        assert result.coverage_ratio == 0.20
        assert any(r.rule_id == "RULE-01-INCONCLUSIVE" and r.matched for r in result.triggered_rules)
        assert "DNS" in result.explanation or "coverage" in result.explanation.lower()

    def test_scenario_f_conflicting_evidence_reconciliation(self):
        """Scenario F: Conflicting evidence (valid TLS + authoritative threat feed match).
        
        - Target has a valid, properly configured TLS certificate.
        - Target simultaneously matches an authoritative threat feed (e.g. malware distribution).
        - Authoritative malicious verdict MUST be preserved (CONFIRMED_MALICIOUS).
        - Conflict MUST be disclosed and documented in notes/limitations.
        """
        auth_threat = StandardizedEvidenceItem(
            finding_id="ti_safe_browsing_phish",
            category=EvidenceCategory.THREAT_INTEL,
            severity=StandardSeverity.HIGH,
            title="Target Listed on Google Safe Browsing",
            description="Active credential phishing portal verified.",
            source_module="threat_intel_safebrowsing",
            source_authority=EvidenceAuthority.AUTHORITATIVE,
            is_authoritative_threat=True,
            is_conflicting=True,
            conflict_details="Site presents a valid SSL/TLS certificate while hosting verified phishing content.",
        )
        tls_benign = StandardizedEvidenceItem(
            finding_id="tls_valid_cert",
            category=EvidenceCategory.TLS,
            severity=StandardSeverity.INFORMATIONAL,
            title="Valid TLS Certificate Issued by Let's Encrypt",
            description="Certificate chain is valid and unexpired.",
            source_module="tls_analysis",
            source_authority=EvidenceAuthority.HEURISTIC,
            is_conflicting=True,
            conflict_details="Valid certificate present on confirmed hostile host.",
        )
        coll = make_test_collection(
            items=[auth_threat, tls_benign],
            completed=["url_preflight", "dns_investigation", "redirect_analysis", "tls_analysis", "security_headers"],
            coverage_ratio=1.0,
            target="https://secure-phishing-login.example.com",
        )
        result = evaluate_risk(coll)

        assert result.classification == RiskClassification.CONFIRMED_MALICIOUS
        assert result.score is not None and result.score >= 90
        assert result.has_conflicting_evidence is True
        assert result.conflict_notes is not None
        assert "certificate" in result.conflict_notes.lower() or "conflicting" in result.conflict_notes.lower()
