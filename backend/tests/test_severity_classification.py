"""CyberShield AI — Severity & Indicator Classification Unit Tests (Part 14)

Validates indicator severity ratings, evidence authority decoupling,
independent corroboration enforcement, deduplication of correlated issues,
and determinism across input orderings.
"""

import pytest
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    StandardizedEvidenceItem,
    CheckStatus,
)
from app.services.severity.classifier import (
    classify_indicators,
    derive_underlying_issue_key,
    BASE_WEIGHTS,
    AUTHORITY_MULTIPLIERS,
)


def test_base_weights_and_multipliers():
    """Verify calibrated weights and multipliers are strictly bounded."""
    assert BASE_WEIGHTS[StandardSeverity.INFORMATIONAL] == 0
    assert BASE_WEIGHTS[StandardSeverity.LOW] == 10
    assert BASE_WEIGHTS[StandardSeverity.MEDIUM] == 25
    assert BASE_WEIGHTS[StandardSeverity.HIGH] == 50

    assert AUTHORITY_MULTIPLIERS[EvidenceAuthority.AUTHORITATIVE] == 1.0
    assert AUTHORITY_MULTIPLIERS[EvidenceAuthority.CORROBORATED] == 0.85
    assert AUTHORITY_MULTIPLIERS[EvidenceAuthority.HEURISTIC] == 0.60
    assert AUTHORITY_MULTIPLIERS[EvidenceAuthority.UNKNOWN] == 0.30


def test_deduplicate_identical_underlying_issues():
    """Verify multiple findings for the same underlying issue are consolidated without false corroboration."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="HSTS header was not returned in HTTP response.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header on Final Redirect Destination",
        description="Final destination omitted HSTS header.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
    )

    result = classify_indicators([item1, item2])
    assert result.total_indicators == 2
    assert result.deduplicated_issue_count == 1
    assert len(result.classified_indicators) == 1

    consolidated = result.classified_indicators[0]
    assert consolidated.underlying_issue_key == "header:missing_hsts"
    # Lacking proven independent provenance, corroboration_count remains 1 and authority is HEURISTIC
    assert consolidated.corroboration_count == 1
    assert consolidated.authority == EvidenceAuthority.HEURISTIC
    assert set(consolidated.source_modules) == {"security_headers", "redirect_tracer"}
    # Effective weight: 10 * 0.60 = 6.0 (not inflated to 8.5)
    assert consolidated.effective_weight == 6.0


def test_human_reproduced_probe_same_original_references_does_not_corroborate():
    """Verify exact human-reproduced finding: same original_references across modules must NOT produce CORROBORATED."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="HSTS header was not returned in HTTP response.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["same_underlying_observation"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header on Final Redirect Destination",
        description="Final destination omitted HSTS header.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["same_underlying_observation"],
    )

    result = classify_indicators([item1, item2])
    assert len(result.classified_indicators) == 1
    ind = result.classified_indicators[0]

    # Must NOT be promoted to CORROBORATED
    assert ind.authority == EvidenceAuthority.HEURISTIC
    assert ind.corroboration_count == 1
    assert ind.effective_weight == 6.0
    assert set(ind.source_modules) == {"security_headers", "redirect_tracer"}


def test_shared_correlations_across_modules_does_not_corroborate():
    """Verify shared correlation identifiers across modules prevent false corroboration."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="HSTS header was not returned.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ref_headers_01"],
        correlations=["corr_shared_hop_node"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header on Redirect",
        description="Redirect omitted HSTS.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ref_redirect_02"],
        correlations=["corr_shared_hop_node"],
    )

    result = classify_indicators([item1, item2])
    ind = result.classified_indicators[0]
    # Shared correlation links items into 1 dependent component
    assert ind.corroboration_count == 1
    assert ind.authority == EvidenceAuthority.HEURISTIC
    assert ind.effective_weight == 6.0


def test_distinct_demonstrably_independent_provenance_corroborates():
    """Verify distinct, demonstrably independent provenance across modules produces CORROBORATED authority."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="Passive headers analysis noted lack of HSTS.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["headers:passive_scan_port_443"],
        correlations=["corr_endpoint_headers"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header on Final Redirect Destination",
        description="Redirect engine traced final hop and noted lack of HSTS.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["redirect:final_destination_tracer"],
        correlations=["corr_redirect_chain_dest"],
    )

    result = classify_indicators([item1, item2])
    ind = result.classified_indicators[0]
    # Independent modules + disjoint provenance -> promotes to CORROBORATED
    assert ind.corroboration_count == 2
    assert ind.authority == EvidenceAuthority.CORROBORATED
    assert ind.effective_weight == 8.5  # 10 * 0.85
    assert set(ind.source_modules) == {"security_headers", "redirect_tracer"}


def test_same_module_duplicate_observations_do_not_corroborate():
    """Verify multiple observations originating from the same module cannot establish corroboration."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="Observation 1.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["headers:check_hsts_1"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="Observation 2.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["headers:check_hsts_2"],
    )

    result = classify_indicators([item1, item2])
    ind = result.classified_indicators[0]
    # Same module cannot corroborate itself
    assert ind.corroboration_count == 1
    assert ind.authority == EvidenceAuthority.HEURISTIC
    assert ind.effective_weight == 6.0


def test_missing_or_insufficient_provenance_does_not_corroborate():
    """Verify that observations lacking provenance cannot falsely claim independent corroboration."""
    item1 = StandardizedEvidenceItem(
        finding_id="item_01",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header",
        description="No provenance recorded.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=[],
        correlations=[],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="item_02",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header",
        description="No provenance recorded.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=[],
        correlations=[],
    )

    result = classify_indicators([item1, item2])
    ind = result.classified_indicators[0]
    assert ind.corroboration_count == 1
    assert ind.authority == EvidenceAuthority.HEURISTIC
    assert ind.effective_weight == 6.0


def test_input_order_reversal_determinism():
    """Verify that classification outcomes are 100% deterministic and independent of input ordering."""
    item_a = StandardizedEvidenceItem(
        finding_id="item_a",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="Headers observation.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ref_a"],
    )
    item_b = StandardizedEvidenceItem(
        finding_id="item_b",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing HSTS Header on Final Destination",
        description="Redirect observation.",
        source_module="redirect_tracer",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ref_b"],
    )
    item_c = StandardizedEvidenceItem(
        finding_id="item_c",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.HIGH,
        title="Brand Impersonation in Domain",
        description="Heuristic observation.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ref_c"],
    )

    forward = classify_indicators([item_a, item_b, item_c])
    reversed_order = classify_indicators([item_c, item_b, item_a])
    shuffled = classify_indicators([item_b, item_c, item_a])

    # Assert exact model equality across all ordering permutations
    assert forward.model_dump() == reversed_order.model_dump() == shuffled.model_dump()
    assert [i.indicator_id for i in forward.classified_indicators] == [i.indicator_id for i in reversed_order.classified_indicators]


def test_corroboration_with_heuristic_and_technical():
    """Verify corroboration between URL pattern heuristic and DNS indicator with distinct provenance."""
    item1 = StandardizedEvidenceItem(
        finding_id="h_01",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.MEDIUM,
        title="Suspicious Brand Name Keyword in Subdomain",
        description="Subdomain contains 'paypal' on unrelated registrable domain.",
        source_module="url_heuristics",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["url_heuristics:brand_subdomain"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="d_01",
        category=EvidenceCategory.DNS,
        severity=StandardSeverity.MEDIUM,
        title="Suspicious Brand Name Keyword in Subdomain",
        description="DNS zone matches suspicious branding keyword.",
        source_module="dns_investigation",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["dns:zone_name_check"],
    )

    result = classify_indicators([item1, item2])
    assert result.deduplicated_issue_count == 1
    consolidated = result.classified_indicators[0]
    assert consolidated.corroboration_count == 2
    assert consolidated.authority == EvidenceAuthority.CORROBORATED
    assert consolidated.effective_weight == round(25 * 0.85, 2)  # 21.25


def test_authoritative_threat_intel_match_classification():
    """Verify authoritative threat intelligence matches are recognized as authoritative threats."""
    ti_item = StandardizedEvidenceItem(
        finding_id="ti_01",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.HIGH,
        title="Target Listed on Threat Feed: URLhaus",
        description="URLhaus lists active malware URL.",
        source_module="threat_intel_urlhaus",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
        original_references=["feed_urlhaus_id_9999"],
    )

    result = classify_indicators([ti_item])
    assert result.has_authoritative_malicious_evidence is True
    assert result.authoritative_threat_count == 1
    assert result.high_severity_count == 1

    classified = result.classified_indicators[0]
    assert classified.is_authoritative_threat is True
    assert classified.is_heuristic_only is False
    assert classified.effective_weight == 50.0  # 50 * 1.0


def test_ti_cross_feed_provenance_preservation():
    """Verify multiple distinct TI feeds produce distinct classified indicators and do not silently merge."""
    ti_urlhaus = StandardizedEvidenceItem(
        finding_id="ti_urlhaus_01",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.HIGH,
        title="Target Listed on Threat Feed: URLhaus",
        description="URLhaus reports active malware payload.",
        source_module="threat_intel_urlhaus",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
        original_references=["urlhaus:match_123"],
    )
    ti_phishtank = StandardizedEvidenceItem(
        finding_id="ti_phishtank_01",
        category=EvidenceCategory.THREAT_INTEL,
        severity=StandardSeverity.HIGH,
        title="Target Listed on Threat Feed: PhishTank",
        description="PhishTank reports active credential harvesting.",
        source_module="threat_intel_phishtank",
        source_authority=EvidenceAuthority.AUTHORITATIVE,
        original_references=["phishtank:verified_456"],
    )

    result = classify_indicators([ti_urlhaus, ti_phishtank])
    # Must NOT silently merge the two distinct feeds into one indicator
    assert result.deduplicated_issue_count == 2
    assert len(result.classified_indicators) == 2
    assert result.authoritative_threat_count == 2
    assert result.has_authoritative_malicious_evidence is True

    feed_keys = {ind.underlying_issue_key for ind in result.classified_indicators}
    assert "threat_intel:malicious_match:threat_intel_urlhaus" in feed_keys
    assert "threat_intel:malicious_match:threat_intel_phishtank" in feed_keys


def test_ai_opinion_remains_strictly_heuristic():
    """Verify that an AI scam finding rated HIGH severity CANNOT be classified as authoritative."""
    ai_item = StandardizedEvidenceItem(
        finding_id="ai_01",
        category=EvidenceCategory.AI_ANALYSIS,
        severity=StandardSeverity.HIGH,
        title="AI Scam Indicator: Credential Phishing Solicitation",
        description="LLM concluded high likelihood of phishing.",
        source_module="ai_scam_model",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["ai:prompt_eval_step_3"],
    )

    result = classify_indicators([ai_item])
    assert result.high_severity_count == 1
    # MUST NOT be classified as authoritative threat
    assert result.has_authoritative_malicious_evidence is False
    assert result.authoritative_threat_count == 0

    classified = result.classified_indicators[0]
    assert classified.authority == EvidenceAuthority.HEURISTIC
    assert classified.is_authoritative_threat is False
    assert classified.is_heuristic_only is True
    assert classified.effective_weight == 30.0  # 50 * 0.60


def test_missing_headers_are_low_severity():
    """Verify missing HTTP security headers are classified with LOW or INFO severity."""
    item = StandardizedEvidenceItem(
        finding_id="hdr_csp",
        category=EvidenceCategory.SECURITY_HEADERS,
        severity=StandardSeverity.LOW,
        title="Missing Content-Security-Policy (CSP) Header",
        description="CSP not present.",
        source_module="security_headers",
        source_authority=EvidenceAuthority.HEURISTIC,
        original_references=["headers:csp_check"],
    )
    result = classify_indicators([item])
    assert result.low_severity_count == 1
    assert result.high_severity_count == 0
    assert result.classified_indicators[0].effective_weight == 6.0  # 10 * 0.6
