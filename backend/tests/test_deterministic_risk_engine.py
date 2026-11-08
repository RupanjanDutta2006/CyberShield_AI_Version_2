"""CyberShield AI — Deterministic Risk Engine Unit Tests (Part 15)

Validates the 16 mandatory test cases:
1. Clearly benign evidence -> LOW_RISK
2. One suspicious heuristic -> SUSPICIOUS
3. Multiple independent suspicious indicators -> HIGH_RISK
4. Multiple significant indicators -> HIGH_RISK
5. Authoritative malicious intelligence match -> CONFIRMED_MALICIOUS
6. AI-only malicious claim -> NOT CONFIRMED_MALICIOUS (High Risk or Suspicious capped)
7. No threat-intelligence match -> Not automatically safe
8. Valid TLS with suspicious evidence -> Suspicious/High Risk preserved
9. Missing TLS evidence -> Documented in limitations, does not fail closed
10. DNS unavailable -> INCONCLUSIVE
11. Redirect check failed -> Documented, handled gracefully
12. Conflicting authoritative and heuristic evidence -> Disclosed, authoritative threat preserved
13. Mostly unavailable checks -> INCONCLUSIVE
14. Empty evidence -> INCONCLUSIVE
15. Duplicate correlated findings -> Deduplicated, not double-counted
16. Same evidence evaluated repeatedly produces identical output -> 100% Deterministic
"""

import pytest
from app.schemas.common import RiskClassification
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)
from app.services.risk_engine.engine import evaluate_risk


def make_collection(
    items=None,
    completed=None,
    failed=None,
    unavailable=None,
    limitations=None,
    coverage_ratio=1.0,
    target="https://example.com"
):
    """Helper to assemble controlled EvidenceCollection test fixtures."""
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


# Case 1: Clearly benign evidence
def test_case_01_clearly_benign_evidence():
    """Verify clean evidence with all checks completed produces LOW_RISK."""
    coll = make_collection(items=[])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.LOW_RISK
    assert res.score is not None
    assert 0 <= res.score <= 24
    assert "No significant malicious indicators" in res.explanation


# Case 2: One suspicious heuristic
def test_case_02_one_suspicious_heuristic():
    """Verify single heuristic finding produces SUSPICIOUS classification."""
    item = StandardizedEvidenceItem(
        finding_id="h_tld",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.MEDIUM,
        title="Suspicious Top-Level Domain",
        description="Target uses high-abuse TLD.",
        source_module="heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[item])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.SUSPICIOUS
    assert res.score is not None
    assert 25 <= res.score <= 64
    assert any(cf.indicator_id.startswith("ind_heuristic") for cf in res.contributing_factors)


# Case 3: Multiple independent suspicious indicators
def test_case_03_multiple_independent_suspicious_indicators():
    """Verify multiple independent suspicious indicators produce HIGH_RISK."""
    item1 = StandardizedEvidenceItem(
        finding_id="h_brand",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Target Brand Name in Subdomain",
        description="Impersonates known financial institution.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    item2 = StandardizedEvidenceItem(
        finding_id="h_puny",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Punycode Homograph Domain Detected",
        description="IDN homograph mimics legitimate brand.",
        source_module="url_normalization",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[item1, item2])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.HIGH_RISK
    assert res.score is not None
    assert 65 <= res.score <= 89


# Case 4: Multiple significant indicators
def test_case_04_multiple_significant_indicators():
    """Verify 1 High + 2 Medium indicators produce HIGH_RISK."""
    item1 = StandardizedEvidenceItem(
        finding_id="h_ip_host",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Raw IP Address Used as Hostname",
        description="URL uses raw IP instead of domain name.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    item2 = StandardizedEvidenceItem(
        finding_id="d_nrd",
        category=EvidenceCategory.DNS,
        severity=StandardSeverity.MEDIUM,
        title="Newly Registered Domain Anomaly",
        description="Domain registered within last 48 hours.",
        source_module="dns_investigation",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    item3 = StandardizedEvidenceItem(
        finding_id="r_loop",
        category=EvidenceCategory.REDIRECT,
        severity=StandardSeverity.MEDIUM,
        title="Abnormal Redirect Pattern",
        description="Multiple intermediate redirect hops.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[item1, item2, item3])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.HIGH_RISK
    assert res.score is not None
    assert res.score >= 65


# Case 5: Authoritative malicious intelligence match
def test_case_05_authoritative_malicious_intelligence_match():
    """Verify verified threat intel match produces CONFIRMED_MALICIOUS and calibrated confidence >= 0.85."""
    ti_item = StandardizedEvidenceItem(
        finding_id="ti_urlhaus",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.HIGH,
        title="Target Listed on Threat Feed: URLhaus",
        description="Active payload download URL verified.",
        source_module="threat_intel_urlhaus",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
    )
    coll = make_collection(items=[ti_item])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.CONFIRMED_MALICIOUS
    assert res.score is not None
    assert res.score >= 90
    assert res.confidence is not None and res.confidence >= 0.85
    assert any(rule.rule_id == "RULE-02-CONFIRMED-MALICIOUS" and rule.matched for rule in res.triggered_rules)

    # Distinguish calibrated confidence from physical coverage ratio (P15-F01, P15-F02)
    coll_partial = make_collection(items=[ti_item], coverage_ratio=0.20)
    res_partial = evaluate_risk(coll_partial)
    assert res_partial.classification == RiskClassification.CONFIRMED_MALICIOUS
    assert res_partial.confidence == 0.85  # Calibrated minimum confidence for confirmed malicious
    assert res_partial.coverage_ratio == 0.20  # Physical coverage ratio distinct from confidence


# Case 6: AI-only malicious claim
def test_case_06_ai_only_malicious_claim():
    """Verify AI model opinion CANNOT produce CONFIRMED_MALICIOUS on its own."""
    ai_item = StandardizedEvidenceItem(
        finding_id="ai_claim",
        category=EvidenceCategory.AI_ANALYSIS,
        severity=StandardSeverity.HIGH,
        title="AI Scam Indicator: High Probability Phishing",
        description="LLM believes this is a phishing scam.",
        source_module="ai_scam_model",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[ai_item])
    res = evaluate_risk(coll)
    # Must NOT be Confirmed Malicious
    assert res.classification != RiskClassification.CONFIRMED_MALICIOUS
    assert res.classification in (RiskClassification.SUSPICIOUS, RiskClassification.HIGH_RISK)
    # Score must be capped below 76
    assert res.score <= 75


# Case 7: No threat-intelligence match
def test_case_07_no_threat_intelligence_match():
    """Verify a clean threat intel lookup does not declare a suspicious target safe."""
    ti_clean = StandardizedEvidenceItem(
        finding_id="ti_clean",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.INFORMATIONAL,
        title="Threat Intelligence Feed Clean: URLhaus",
        description="No current record in URLhaus.",
        source_module="threat_intel_urlhaus",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
    )
    suspicious_heuristic = StandardizedEvidenceItem(
        finding_id="h_brand",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Brand Impersonation in Path",
        description="Keyword paypal in unauthenticated path.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[ti_clean, suspicious_heuristic])
    res = evaluate_risk(coll)
    # Suspicious heuristic must not be washed away by clean feed
    assert res.classification in (RiskClassification.SUSPICIOUS, RiskClassification.HIGH_RISK)


# Case 8: Valid TLS with suspicious evidence
def test_case_08_valid_tls_with_suspicious_evidence():
    """Verify valid TLS certificate does NOT lower or suppress suspicious evidence."""
    tls_valid = StandardizedEvidenceItem(
        finding_id="tls_ok",
        category=EvidenceCategory.TLS,
        severity=StandardSeverity.INFORMATIONAL,
        title="Valid TLS Certificate Present",
        description="Certificate is valid and trusted.",
        source_module="tls_analysis",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
    )
    heuristic = StandardizedEvidenceItem(
        finding_id="h_susp",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Punycode Homograph Domain Detected",
        description="Mimics google.com using Cyrillic characters.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[tls_valid, heuristic])
    res = evaluate_risk(coll)
    # TLS valid must not reduce risk to Low
    assert res.classification in (RiskClassification.SUSPICIOUS, RiskClassification.HIGH_RISK)


# Case 9: Missing TLS evidence
def test_case_09_missing_tls_evidence():
    """Verify missing TLS check is documented in limitations and does not fail closed unless malicious."""
    coll = make_collection(
        items=[],
        completed=["url_preflight", "dns_investigation", "redirect_analysis", "security_headers"],
        unavailable=["tls_analysis"],
        limitations=["[tls] Target uses plain HTTP; TLS inspection not applicable."],
        coverage_ratio=0.80,
    )
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.LOW_RISK
    assert any("[tls]" in lim for lim in res.limitations)


# Case 10: DNS unavailable
def test_case_10_dns_unavailable():
    """Verify that critical DNS lookup failure produces INCONCLUSIVE."""
    coll = make_collection(
        items=[],
        completed=["url_preflight"],
        failed=["dns_investigation"],
        limitations=["[dns] DNS query returned TIMEOUT"],
        coverage_ratio=0.33,
    )
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.INCONCLUSIVE
    assert res.score is None
    assert "Inconclusive" in res.explanation


# Case 11: Redirect check failed
def test_case_11_redirect_check_failed():
    """Verify redirect check network failure with minimal other data yields INCONCLUSIVE."""
    coll = make_collection(
        items=[],
        completed=["url_preflight"],
        failed=["redirect_analysis"],
        limitations=["[redirects] Connect timeout"],
        coverage_ratio=0.33,
    )
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.INCONCLUSIVE
    assert res.score is None


# Case 12: Conflicting authoritative and heuristic evidence
def test_case_12_conflicting_evidence():
    """Verify conflicting evidence is disclosed while authoritative threat classification is preserved."""
    ti_item = StandardizedEvidenceItem(
        finding_id="ti_match",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.HIGH,
        title="Target Listed on Threat Feed: URLhaus",
        description="Malware confirmed.",
        source_module="threat_intel_urlhaus",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
        is_conflicting=True,
        conflict_details="Feed reports active threat while other feeds report clean.",
    )
    coll = make_collection(items=[ti_item])
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.CONFIRMED_MALICIOUS
    assert res.has_conflicting_evidence is True
    assert res.conflict_notes is not None


# Case 13: Mostly unavailable checks
def test_case_13_mostly_unavailable_checks():
    """Verify mostly unavailable checks (< 40% coverage) produce INCONCLUSIVE."""
    coll = make_collection(
        items=[],
        completed=["url_preflight"],
        unavailable=["dns_investigation", "redirect_analysis", "tls_analysis", "security_headers"],
        coverage_ratio=0.20,
    )
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.INCONCLUSIVE
    assert res.score is None


# Case 14: Empty evidence
def test_case_14_empty_evidence():
    """Verify completely empty evidence produces INCONCLUSIVE."""
    coll = make_collection(
        items=[],
        completed=[],
        failed=[],
        unavailable=[],
        coverage_ratio=0.0,
    )
    res = evaluate_risk(coll)
    assert res.classification == RiskClassification.INCONCLUSIVE
    assert res.score is None


# Case 15: Duplicate correlated findings
def test_case_15_duplicate_correlated_findings():
    """Verify duplicate correlated findings do not inflate risk score."""
    item1 = StandardizedEvidenceItem(
        finding_id="h1",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Content-Security-Policy",
        description="CSP not set.",
        source_module="security_headers",
    )
    item2 = StandardizedEvidenceItem(
        finding_id="h2",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Content-Security-Policy",
        description="CSP not set.",
        source_module="redirects",
    )
    coll = make_collection(items=[item1, item2])
    res = evaluate_risk(coll)
    # Both items refer to same issue; contributing factors should be 1
    assert len(res.contributing_factors) == 1


# Case 16: Same evidence evaluated repeatedly produces identical output
def test_case_16_deterministic_repeatability():
    """Verify identical input evaluated multiple times yields 100% deterministic output."""
    item = StandardizedEvidenceItem(
        finding_id="h_brand",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Target Brand Name in Subdomain",
        description="Impersonates known financial institution.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    coll = make_collection(items=[item])
    res1 = evaluate_risk(coll)
    res2 = evaluate_risk(coll)
    res3 = evaluate_risk(coll)

    assert res1.classification == res2.classification == res3.classification
    assert res1.score == res2.score == res3.score
    assert res1.confidence == res2.confidence == res3.confidence
    assert res1.explanation == res2.explanation == res3.explanation
    assert res1.summary == res2.summary == res3.summary
    assert len(res1.contributing_factors) == len(res2.contributing_factors) == len(res3.contributing_factors)

