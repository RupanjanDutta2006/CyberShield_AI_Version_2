"""CyberShield AI — Evidence Collection & Standardization Unit & Regression Tests (Part 13)

Validates complete normalization, coverage accounting, sensitive data redaction,
timestamp provenance, deduplication, and all 30 mandatory regression test cases.
"""

import pytest
from typing import Any
from app.schemas.common import TechnicalFinding, FindingSeverity, AnalysisStatus, TechnicalLimitation
from app.schemas.url_scan import (
    URLPreFlightResult,
    URLValidationResult,
    URLNormalizationResult,
    SSRFValidationResult,
)
from app.schemas.threat_intel import ThreatIntelSourceResult, ThreatIntelSummary
from app.schemas.ai_analysis import MessageAnalysisResponse, ObservedIndicator, ExtractedIndicators
from app.schemas.evidence import (
    CheckStatus,
    EvidenceAuthority,
    StandardSeverity,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCollection,
)
from app.services.evidence.normalizer import (
    normalize_evidence,
    redact_sensitive_url_and_params,
    redact_sensitive_evidence,
    redact_sensitive_dict,
    map_severity_to_standard,
    _upsert_evidence_item,
    _resolve_coverage_states,
)
from app.services.dns.models import DNSInvestigationResult, DNSStatus
from app.services.tls_analysis.models import TLSAnalysisResult, TLSStatus
from app.services.redirects.models import RedirectAnalysisResult, RedirectHopRecord
from app.services.security_headers.models import (
    SecurityHeaderAnalysisResult,
    SingleHeaderAnalysis,
    HeaderEvaluationStatus,
)
from app.services.technical_investigation import TechnicalInvestigationResult


# =============================================================================
# Baseline & Sanitization Tests
# =============================================================================

def test_redact_sensitive_url_parameters():
    """Verify that credentials, tokens, passwords, and API keys are redacted from URLs."""
    raw_url = "https://example.com/login?token=secret123&user=alice&password=mypassword&api_key=xyz987"
    sanitized = redact_sensitive_url_and_params(raw_url)
    assert "secret123" not in sanitized
    assert "mypassword" not in sanitized
    assert "xyz987" not in sanitized
    assert "user=alice" in sanitized
    assert "token=%5BREDACTED%5D" in sanitized or "token=[REDACTED]" in sanitized


def test_redact_sensitive_dictionary():
    """Verify recursive redaction in nested evidence dictionaries."""
    data = {
        "target": "https://bank.test?auth=tok789",
        "nested": {
            "password": "plain_password",
            "safe_val": 42
        },
        "items": ["https://site.test?key=topsecret", "normal_string"]
    }
    clean = redact_sensitive_dict(data)
    assert clean["nested"]["password"] == "[REDACTED]"
    assert clean["nested"]["safe_val"] == 42
    assert "tok789" not in str(clean)
    assert "topsecret" not in str(clean)


def test_map_severity_to_standard():
    """Verify standard severity level mapping."""
    assert map_severity_to_standard(FindingSeverity.INFO) == StandardSeverity.INFORMATIONAL
    assert map_severity_to_standard(FindingSeverity.LOW) == StandardSeverity.LOW
    assert map_severity_to_standard(FindingSeverity.MEDIUM) == StandardSeverity.MEDIUM
    assert map_severity_to_standard(FindingSeverity.HIGH) == StandardSeverity.HIGH
    assert map_severity_to_standard(FindingSeverity.CRITICAL) == StandardSeverity.HIGH
    assert map_severity_to_standard("high") == StandardSeverity.HIGH
    assert map_severity_to_standard(None) == StandardSeverity.INFORMATIONAL


# =============================================================================
# 30 Mandatory Regression Test Cases
# =============================================================================

# 1. DNS SUCCESS
def test_01_dns_success():
    dns_res = DNSInvestigationResult(
        domain="example.com",
        status=DNSStatus.SUCCESS,
        timestamp="2026-11-07T10:00:00Z",
        a_records=["93.184.216.34"],
        aaaa_records=["2606:2800:220:1:248:1893:25c8:1946"],
    )
    ti = TechnicalInvestigationResult(target_url="https://example.com", dns=dns_res)
    col = normalize_evidence("https://example.com", technical_investigation=ti)
    assert "dns_investigation" in col.coverage.completed
    assert "93.184.216.34" in col.correlated_ips
    assert "2606:2800:220:1:248:1893:25c8:1946" in col.correlated_ips


# 2. DNS EMPTY_ANSWER
def test_02_dns_empty_answer():
    dns_res = DNSInvestigationResult(
        domain="no-records.example",
        status=DNSStatus.EMPTY_ANSWER,
        timestamp="2026-11-07T10:00:00Z",
    )
    ti = TechnicalInvestigationResult(target_url="https://no-records.example", dns=dns_res)
    col = normalize_evidence("https://no-records.example", technical_investigation=ti)
    assert "dns_investigation" in col.coverage.completed
    assert "dns_investigation" not in col.coverage.failed
    assert "dns_investigation" not in col.coverage.partial


# 3. DNS NXDOMAIN
def test_03_dns_nxdomain():
    dns_res = DNSInvestigationResult(
        domain="nonexistent.example",
        status=DNSStatus.NXDOMAIN,
        timestamp="2026-11-07T10:00:00Z",
    )
    ti = TechnicalInvestigationResult(target_url="https://nonexistent.example", dns=dns_res)
    col = normalize_evidence("https://nonexistent.example", technical_investigation=ti)
    assert "dns_investigation" in col.coverage.completed
    nx_items = [it for it in col.items if it.category == EvidenceCategory.DNS and "NXDOMAIN" in it.title]
    assert len(nx_items) == 1
    assert nx_items[0].severity == StandardSeverity.MEDIUM
    assert nx_items[0].source_authority == EvidenceAuthority.AUTHORITATIVE


# 4. DNS TIMEOUT and SERVFAIL
def test_04_dns_timeout_and_servfail():
    for status_val in (DNSStatus.TIMEOUT, DNSStatus.SERVFAIL):
        dns_res = DNSInvestigationResult(domain="broken.example", status=status_val)
        ti = TechnicalInvestigationResult(target_url="https://broken.example", dns=dns_res)
        col = normalize_evidence("https://broken.example", technical_investigation=ti)
        assert "dns_investigation" in col.coverage.failed
        assert any(status_val.value in lim for lim in col.limitations)


# 5. DNS UNAVAILABLE and SSRF_BLOCKED
def test_05_dns_unavailable_and_ssrf_blocked():
    # UNAVAILABLE
    dns_unavail = DNSInvestigationResult(domain="unavail.example", status=DNSStatus.UNAVAILABLE)
    ti1 = TechnicalInvestigationResult(target_url="https://unavail.example", dns=dns_unavail)
    col1 = normalize_evidence("https://unavail.example", technical_investigation=ti1)
    assert "dns_investigation" in col1.coverage.unavailable

    # SSRF_BLOCKED
    dns_ssrf = DNSInvestigationResult(
        domain="rebind.internal",
        status=DNSStatus.SSRF_BLOCKED,
        all_resolved_ips=["127.0.0.1"],
        is_destination_safe=False,
        blocked_reason="Resolves to loopback range 127.0.0.1",
    )
    ti2 = TechnicalInvestigationResult(target_url="https://rebind.internal", dns=dns_ssrf)
    col2 = normalize_evidence("https://rebind.internal", technical_investigation=ti2)
    assert "dns_investigation" in col2.coverage.failed
    ssrf_items = [it for it in col2.items if it.category == EvidenceCategory.DNS and "SSRF" in it.title]
    assert len(ssrf_items) == 1
    assert ssrf_items[0].severity == StandardSeverity.HIGH
    assert ssrf_items[0].source_authority == EvidenceAuthority.AUTHORITATIVE


# 6. TLS VALID
def test_06_tls_valid():
    tls_res = TLSAnalysisResult(
        hostname="example.com",
        status=TLSStatus.VALID,
        is_valid=True,
        is_trusted=True,
    )
    ti = TechnicalInvestigationResult(target_url="https://example.com", tls=tls_res)
    col = normalize_evidence("https://example.com", technical_investigation=ti)
    assert "tls_analysis" in col.coverage.completed


# 7. TLS UNTRUSTED_CHAIN
def test_07_tls_untrusted_chain():
    tls_res = TLSAnalysisResult(
        hostname="untrusted.example",
        status=TLSStatus.UNTRUSTED_CHAIN,
        is_valid=False,
        is_trusted=False,
        findings=[TechnicalFinding(
            module="tls_analysis",
            check_name="UNTRUSTED_ROOT_CA",
            severity=FindingSeverity.HIGH,
            title="Untrusted Certificate Authority",
            description="Cert does not chain to trusted root",
        )]
    )
    ti = TechnicalInvestigationResult(target_url="https://untrusted.example", tls=tls_res)
    col = normalize_evidence("https://untrusted.example", technical_investigation=ti)
    assert "tls_analysis" in col.coverage.completed
    assert any(it.severity == StandardSeverity.HIGH and it.source_authority == EvidenceAuthority.AUTHORITATIVE for it in col.items)


# 8. TLS SELF_SIGNED, EXPIRED, HOSTNAME_MISMATCH
def test_08_tls_self_signed_expired_hostname_mismatch():
    for status_val in (TLSStatus.SELF_SIGNED, TLSStatus.EXPIRED, TLSStatus.HOSTNAME_MISMATCH):
        tls_res = TLSAnalysisResult(
            hostname="bad-tls.example",
            status=status_val,
            is_valid=False,
            findings=[TechnicalFinding(
                module="tls_analysis",
                check_name=f"TLS_{status_val.value}",
                severity=FindingSeverity.HIGH,
                title=f"TLS Defect: {status_val.value}",
                description="Certificate defect detected",
            )]
        )
        ti = TechnicalInvestigationResult(target_url="https://bad-tls.example", tls=tls_res)
        col = normalize_evidence("https://bad-tls.example", technical_investigation=ti)
        assert "tls_analysis" in col.coverage.completed
        assert any(it.severity == StandardSeverity.HIGH for it in col.items)


# 9. TLS TIMEOUT and HANDSHAKE_FAILED
def test_09_tls_timeout_and_handshake_failed():
    for status_val in (TLSStatus.TIMEOUT, TLSStatus.HANDSHAKE_FAILED):
        tls_res = TLSAnalysisResult(hostname="broken-tls.example", status=status_val)
        ti = TechnicalInvestigationResult(target_url="https://broken-tls.example", tls=tls_res)
        col = normalize_evidence("https://broken-tls.example", technical_investigation=ti)
        assert "tls_analysis" in col.coverage.failed
        assert "tls_analysis" not in col.coverage.completed


# 10. TLS NOT_HTTPS and UNAVAILABLE
def test_10_tls_not_https_and_unavailable():
    # NOT_HTTPS -> not_applicable
    tls_http = TLSAnalysisResult(hostname="plain.example", status=TLSStatus.NOT_HTTPS)
    ti1 = TechnicalInvestigationResult(target_url="http://plain.example", tls=tls_http)
    col1 = normalize_evidence("http://plain.example", technical_investigation=ti1)
    assert "tls_analysis" in col1.coverage.not_applicable
    assert "tls_analysis" not in col1.coverage.completed

    # UNAVAILABLE -> unavailable
    tls_unavail = TLSAnalysisResult(hostname="unavail.example", status=TLSStatus.UNAVAILABLE)
    ti2 = TechnicalInvestigationResult(target_url="https://unavail.example", tls=tls_unavail)
    col2 = normalize_evidence("https://unavail.example", technical_investigation=ti2)
    assert "tls_analysis" in col2.coverage.unavailable


# 11. Redirect FINAL_DESTINATION_REACHED
def test_11_redirect_final_destination_reached():
    r_res = RedirectAnalysisResult(
        initial_url="https://a.test",
        final_url="https://b.test",
        hop_count=1,
        stopped_reason="FINAL_DESTINATION_REACHED",
    )
    ti = TechnicalInvestigationResult(target_url="https://a.test", redirects=r_res)
    col = normalize_evidence("https://a.test", technical_investigation=ti)
    assert "redirect_analysis" in col.coverage.completed


# 12. Redirect REDIRECT_LOOP_DETECTED
def test_12_redirect_loop_detected():
    r_res = RedirectAnalysisResult(
        initial_url="https://loop.test",
        stopped_reason="REDIRECT_LOOP_DETECTED",
        has_circular_redirect=True,
        findings=[TechnicalFinding(
            module="redirects",
            check_name="REDIRECT_LOOP",
            severity=FindingSeverity.HIGH,
            title="Circular Redirect Loop Detected",
            description="Loop detected",
        )]
    )
    ti = TechnicalInvestigationResult(target_url="https://loop.test", redirects=r_res)
    col = normalize_evidence("https://loop.test", technical_investigation=ti)
    assert "redirect_analysis" in col.coverage.completed
    assert any(it.severity == StandardSeverity.HIGH for it in col.items)


# 13. Redirect MAX_REDIRECTS_EXCEEDED
def test_13_redirect_max_redirects_exceeded():
    r_res = RedirectAnalysisResult(
        initial_url="https://long-chain.test",
        stopped_reason="MAX_REDIRECTS_EXCEEDED",
        hop_count=5,
    )
    ti = TechnicalInvestigationResult(target_url="https://long-chain.test", redirects=r_res)
    col = normalize_evidence("https://long-chain.test", technical_investigation=ti)
    assert "redirect_analysis" in col.coverage.partial
    assert "redirect_analysis" not in col.coverage.completed


# 14. Redirect SSRF_BLOCKED_HOP and INVALID_REDIRECT_TARGET
def test_14_redirect_ssrf_blocked_hop_and_invalid_target():
    # SSRF_BLOCKED_HOP
    r_ssrf = RedirectAnalysisResult(
        initial_url="https://bounce.test",
        final_url="http://169.254.169.254",
        stopped_reason="SSRF_BLOCKED_HOP",
        destination_ip_safe=False,
    )
    ti1 = TechnicalInvestigationResult(target_url="https://bounce.test", redirects=r_ssrf)
    col1 = normalize_evidence("https://bounce.test", technical_investigation=ti1)
    assert "redirect_analysis" in col1.coverage.failed
    ssrf_items = [it for it in col1.items if it.category == EvidenceCategory.REDIRECT and "SSRF" in it.title]
    assert len(ssrf_items) == 1
    assert ssrf_items[0].severity == StandardSeverity.HIGH
    assert ssrf_items[0].source_authority == EvidenceAuthority.AUTHORITATIVE

    # INVALID_REDIRECT_TARGET
    r_inv = RedirectAnalysisResult(initial_url="https://inv.test", stopped_reason="INVALID_REDIRECT_TARGET")
    ti2 = TechnicalInvestigationResult(target_url="https://inv.test", redirects=r_inv)
    col2 = normalize_evidence("https://inv.test", technical_investigation=ti2)
    assert "redirect_analysis" in col2.coverage.failed


# 15. Redirect timeout, connection failure, DNS failure, and REQUEST_ERROR
def test_15_redirect_failures():
    for reason in ("TOTAL_TIMEOUT_EXCEEDED", "CONNECT_TIMEOUT", "CONNECTION_FAILED", "DNS_RESOLUTION_FAILED", "REQUEST_ERROR"):
        r_res = RedirectAnalysisResult(initial_url="https://fail.test", stopped_reason=reason)
        ti = TechnicalInvestigationResult(target_url="https://fail.test", redirects=r_res)
        col = normalize_evidence("https://fail.test", technical_investigation=ti)
        assert "redirect_analysis" in col.coverage.failed
        assert "redirect_analysis" not in col.coverage.completed


# 16. All TI feeds unavailable
def test_16_all_ti_feeds_unavailable():
    sources = [
        ThreatIntelSourceResult(source="FeedA", checked_at="2026-11-07T12:00:00Z", match=False, source_status="timeout"),
        ThreatIntelSourceResult(source="FeedB", checked_at="2026-11-07T12:00:00Z", match=False, source_status="rate_limited"),
    ]
    col = normalize_evidence("https://test.example", threat_intel=sources)
    assert "threat_intelligence" not in col.coverage.completed
    assert "threat_intelligence" in col.coverage.failed or "threat_intelligence" in col.coverage.unavailable


# 17. Mixed TI success and failure
def test_17_mixed_ti_success_and_failure():
    sources = [
        ThreatIntelSourceResult(source="URLhaus", checked_at="2026-11-07T12:00:00Z", match=False, source_status="available"),
        ThreatIntelSourceResult(source="Google Safe Browsing", checked_at="2026-11-07T12:00:00Z", match=False, source_status="rate_limited"),
    ]
    col = normalize_evidence("https://test.example", threat_intel=sources)
    assert "threat_intelligence" in col.coverage.partial
    assert "threat_intelligence" not in col.coverage.completed


# 18. TI positive match with conservative authority
def test_18_ti_positive_match_with_conservative_authority():
    # Recognized feed -> AUTHORITATIVE
    src_known = [ThreatIntelSourceResult(source="URLhaus", checked_at="2026-11-07T12:00:00Z", match=True, threat_type="malware")]
    col1 = normalize_evidence("https://bad.example", threat_intel=src_known)
    assert col1.items[0].source_authority == EvidenceAuthority.AUTHORITATIVE

    # Unrecognized feed -> UNKNOWN authority
    src_unknown = [ThreatIntelSourceResult(source="CustomUntrustedFeed", checked_at="2026-11-07T12:00:00Z", match=True, threat_type="phishing")]
    col2 = normalize_evidence("https://bad.example", threat_intel=src_unknown)
    assert col2.items[0].source_authority == EvidenceAuthority.UNKNOWN


# 19. TI no-match is not interpreted as safe
def test_19_ti_no_match_not_interpreted_as_safe():
    sources = [ThreatIntelSourceResult(source="URLhaus", checked_at="2026-11-07T12:00:00Z", match=False)]
    col = normalize_evidence("https://example.com", threat_intel=sources)
    item = col.items[0]
    assert item.severity == StandardSeverity.INFORMATIONAL
    assert item.source_authority == EvidenceAuthority.HEURISTIC
    assert "does not guarantee safety" in item.description


# 20. Nested-list redaction
def test_20_nested_list_redaction():
    nested_data = {
        "depth1": [
            "safe_string",
            [
                ["https://site.test/auth?token=my_secret_token_123"],
                {"api_key": "private_key_abc"}
            ]
        ]
    }
    cleaned = redact_sensitive_evidence(nested_data)
    assert "my_secret_token_123" not in str(cleaned)
    assert "private_key_abc" not in str(cleaned)
    assert cleaned["depth1"][1][1]["api_key"] == "[REDACTED]"
    assert "token=%5BREDACTED%5D" in cleaned["depth1"][1][0][0] or "token=[REDACTED]" in cleaned["depth1"][1][0][0]


# 21. URL userinfo redaction
def test_21_url_userinfo_redaction():
    url_with_creds = "https://admin:superpassword@gateway.example.com:8443/api?token=tok456&user=alice"
    sanitized = redact_sensitive_url_and_params(url_with_creds)
    assert "superpassword" not in sanitized
    assert "tok456" not in sanitized
    assert "admin:[REDACTED]@gateway.example.com:8443" in sanitized or "[REDACTED]@gateway.example.com:8443" in sanitized
    assert "user=alice" in sanitized
    assert "gateway.example.com:8443" in sanitized


# 22. Sensitive key-name variants
def test_22_sensitive_key_name_variants():
    data = {
        "client_secret": "sec1",
        "refresh_token": "ref2",
        "private_key": "priv3",
        "api-key": "ak4",
        "access-token": "at5",
        "session_id": "sid6",
        "otp": "123456",
        "username": "safe_alice",
        "host": "legit.example"
    }
    cleaned = redact_sensitive_dict(data)
    assert cleaned["client_secret"] == "[REDACTED]"
    assert cleaned["refresh_token"] == "[REDACTED]"
    assert cleaned["private_key"] == "[REDACTED]"
    assert cleaned["api-key"] == "[REDACTED]"
    assert cleaned["access-token"] == "[REDACTED]"
    assert cleaned["session_id"] == "[REDACTED]"
    assert cleaned["otp"] == "[REDACTED]"
    # Non-sensitive fields preserved
    assert cleaned["username"] == "safe_alice"
    assert cleaned["host"] == "legit.example"


# 23. Upstream timestamp preservation
def test_23_upstream_timestamp_preservation():
    ts = "2026-11-07T08:15:30Z"
    dns_res = DNSInvestigationResult(domain="example.com", status=DNSStatus.NXDOMAIN, timestamp=ts)
    ti = TechnicalInvestigationResult(target_url="https://example.com", dns=dns_res)
    col = normalize_evidence("https://example.com", technical_investigation=ti)
    assert col.items[0].observed_at == ts


# 24. Unknown timestamp does not become a fabricated observation timestamp
def test_24_unknown_timestamp_not_fabricated():
    ai_resp = MessageAnalysisResponse(
        category="spam",
        risk_level="low_risk",
        observed_indicators=[ObservedIndicator(indicator="mild_urgency", evidence="soon", reason="timing")],
        explanation="Benign notice",
    )
    col = normalize_evidence("https://notice.example", ai_analysis=ai_resp)
    # AI scam analysis does not provide an external RFC observation timestamp -> observed_at is None
    assert col.items[0].observed_at is None
    # normalized_at is accurately set to current normalization time
    assert col.items[0].normalized_at is not None


# 25. Deduplication preserves all original references
def test_25_deduplication_preserves_all_original_references():
    items_dict = {}
    item1 = StandardizedEvidenceItem(
        finding_id="dup_finding_01",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.MEDIUM,
        title="Duplicate Issue",
        description="First occurrence",
        source_module="module_a",
        original_references=["ref_alpha", "ref_shared"],
        correlations=["domain1.test"],
    )
    item2 = StandardizedEvidenceItem(
        finding_id="dup_finding_01",
        category=EvidenceCategory.HEURISTIC,
        severity=StandardSeverity.MEDIUM,
        title="Duplicate Issue",
        description="Second occurrence",
        source_module="module_b",
        original_references=["ref_shared", "ref_beta"],
        correlations=["domain2.test"],
    )
    _upsert_evidence_item(items_dict, item1)
    _upsert_evidence_item(items_dict, item2)

    assert len(items_dict) == 1
    merged = items_dict["dup_finding_01"]
    assert set(merged.original_references) == {"ref_alpha", "ref_shared", "ref_beta"}
    assert set(merged.correlations) == {"domain1.test", "domain2.test"}


# 26. Conflicting evidence remains distinguishable
def test_26_conflicting_evidence_distinguishable():
    sources = [
        ThreatIntelSourceResult(source="URLhaus", checked_at="2026-11-07T12:00:00Z", match=True, threat_type="malware"),
        ThreatIntelSourceResult(source="OpenPhish", checked_at="2026-11-07T12:00:00Z", match=False),
    ]
    col = normalize_evidence("https://conflicting.example", threat_intel=sources)
    assert len(col.items) == 2
    for item in col.items:
        assert item.is_conflicting is True
        assert "opposing findings" in item.conflict_details


# 27. Duplicate coverage identifiers do not inflate coverage
def test_27_duplicate_coverage_identifiers_do_not_inflate_coverage():
    preflight = URLPreFlightResult(
        submitted_url="https://example.com",
        validation=URLValidationResult(is_valid=True, raw_input="https://example.com"),
    )
    col = normalize_evidence("https://example.com", preflight=preflight)
    # Even if "url_preflight" is recorded in preflight, coverage completed is a set
    assert col.coverage.completed.count("url_preflight") == 1
    assert 0.0 <= col.coverage.coverage_ratio <= 1.0


# 28. NOT_APPLICABLE is excluded from applicable coverage
def test_28_not_applicable_excluded_from_applicable_coverage():
    tls_not_https = TLSAnalysisResult(hostname="example.com", status=TLSStatus.NOT_HTTPS)
    dns_ok = DNSInvestigationResult(domain="example.com", status=DNSStatus.SUCCESS)
    ti = TechnicalInvestigationResult(target_url="http://example.com", dns=dns_ok, tls=tls_not_https)
    col = normalize_evidence("http://example.com", technical_investigation=ti)

    assert "tls_analysis" in col.coverage.not_applicable
    assert "dns_investigation" in col.coverage.completed
    # Verify tls_analysis is excluded from applicable denominator
    applicable_modules = set(col.coverage.completed) | set(col.coverage.unavailable) | set(col.coverage.failed) | set(col.coverage.partial)
    assert "tls_analysis" not in applicable_modules
    # 1 completed (dns) out of 4 applicable (dns, redirects, headers, threat_intel) = 0.25 (would be 0.20 if tls_analysis were included)
    assert col.coverage.coverage_ratio == 0.25


# 29. Failed and skipped checks are not counted as completed
def test_29_failed_and_skipped_checks_not_counted_as_completed():
    dns_fail = DNSInvestigationResult(domain="example.com", status=DNSStatus.TIMEOUT)
    ti = TechnicalInvestigationResult(target_url="https://example.com", dns=dns_fail)
    col = normalize_evidence("https://example.com", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.failed
    assert "dns_investigation" not in col.coverage.completed
    assert col.coverage.coverage_ratio == 0.0


# 30. Missing modules never imply a clean result
def test_30_missing_modules_never_imply_clean_result():
    # Only target URL, no modules executed
    col = normalize_evidence("https://empty.example")
    assert len(col.coverage.completed) == 0
    assert col.coverage.coverage_ratio == 0.0
    assert len(col.items) == 0
    assert "threat_intelligence" in col.coverage.unavailable


# =============================================================================
# Defect A & B Regression Tests (Final Coverage-State Corrections)
# =============================================================================

def make_headers_result(
    target_url: str = "https://example.com",
    is_reachable: bool = True,
    status_code: int = 200,
    hsts_status: Any = HeaderEvaluationStatus.VALID,
    csp_status: Any = HeaderEvaluationStatus.VALID,
    xcto_status: Any = HeaderEvaluationStatus.VALID,
    xfo_status: Any = HeaderEvaluationStatus.VALID,
    rp_status: Any = HeaderEvaluationStatus.VALID,
    findings=None,
    limitations=None,
) -> SecurityHeaderAnalysisResult:
    return SecurityHeaderAnalysisResult.model_construct(
        target_url=target_url,
        is_reachable=is_reachable,
        status_code=status_code,
        hsts=SingleHeaderAnalysis.model_construct(
            header_name="Strict-Transport-Security",
            status=hsts_status,
            is_present=(hsts_status not in (HeaderEvaluationStatus.MISSING, HeaderEvaluationStatus.UNAVAILABLE, None, "")),
        ),
        csp=SingleHeaderAnalysis.model_construct(
            header_name="Content-Security-Policy",
            status=csp_status,
            is_present=(csp_status not in (HeaderEvaluationStatus.MISSING, HeaderEvaluationStatus.UNAVAILABLE, None, "")),
        ),
        x_content_type_options=SingleHeaderAnalysis.model_construct(
            header_name="X-Content-Type-Options",
            status=xcto_status,
            is_present=(xcto_status not in (HeaderEvaluationStatus.MISSING, HeaderEvaluationStatus.UNAVAILABLE, None, "")),
        ),
        x_frame_options=SingleHeaderAnalysis.model_construct(
            header_name="X-Frame-Options",
            status=xfo_status,
            is_present=(xfo_status not in (HeaderEvaluationStatus.MISSING, HeaderEvaluationStatus.UNAVAILABLE, None, "")),
        ),
        referrer_policy=SingleHeaderAnalysis.model_construct(
            header_name="Referrer-Policy",
            status=rp_status,
            is_present=(rp_status not in (HeaderEvaluationStatus.MISSING, HeaderEvaluationStatus.UNAVAILABLE, None, "")),
        ),
        findings=findings or [],
        limitations=limitations or [],
    )


# --- Defect A: Coordinator PARTIAL Status and Missing Sub-results ---

def test_coordinator_partial_after_dns_ssrf_abort():
    """When coordinator status is PARTIAL due to unsafe DNS, downstream modules are SKIPPED."""
    dns_res = DNSInvestigationResult(
        domain="malicious.local",
        status=DNSStatus.SSRF_BLOCKED,
        is_destination_safe=False,
    )
    ti = TechnicalInvestigationResult(
        target_url="https://malicious.local",
        status=AnalysisStatus.PARTIAL,
        dns=dns_res,
        redirects=None,
        tls=None,
        headers=None,
        all_limitations=[
            TechnicalLimitation(
                module="technical_investigation",
                reason="DNS resolution resolved to unsafe target 127.0.0.1; aborting downstream checks.",
                impact="Downstream inspection omitted",
            )
        ],
    )
    col = normalize_evidence("https://malicious.local", technical_investigation=ti)

    # DNS failed due to SSRF
    assert "dns_investigation" in col.coverage.failed
    # Downstream modules must be SKIPPED due to safety abort
    assert "redirect_analysis" in col.coverage.skipped
    assert "tls_analysis" in col.coverage.skipped
    assert "security_headers" in col.coverage.skipped
    # Not completed, not unavailable, not partial
    for mod in ["redirect_analysis", "tls_analysis", "security_headers"]:
        assert mod not in col.coverage.completed
        assert mod not in col.coverage.unavailable
        assert mod not in col.coverage.partial


def test_coordinator_partial_without_abort_evidence():
    """When coordinator is PARTIAL without abort evidence, missing modules are UNAVAILABLE, not SKIPPED."""
    dns_res = DNSInvestigationResult(
        domain="example.com",
        status=DNSStatus.SUCCESS,
        is_destination_safe=True,
    )
    ti = TechnicalInvestigationResult(
        target_url="https://example.com",
        status=AnalysisStatus.PARTIAL,
        dns=dns_res,
        redirects=None,
        tls=None,
        headers=None,
        all_limitations=[],
    )
    col = normalize_evidence("https://example.com", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.completed
    # Missing sub-results must be UNAVAILABLE, not assumed SKIPPED
    assert "redirect_analysis" in col.coverage.unavailable
    assert "tls_analysis" in col.coverage.unavailable
    assert "security_headers" in col.coverage.unavailable
    assert "redirect_analysis" not in col.coverage.skipped
    assert "tls_analysis" not in col.coverage.skipped
    assert "security_headers" not in col.coverage.skipped


def test_coordinator_failed_with_missing_downstream_results():
    """When coordinator is FAILED due to preflight SSRF rejection, downstream modules are SKIPPED."""
    ti = TechnicalInvestigationResult(
        target_url="https://127.0.0.1",
        status=AnalysisStatus.FAILED,
        dns=None,
        redirects=None,
        tls=None,
        headers=None,
        all_limitations=[
            TechnicalLimitation(
                module="technical_investigation",
                reason="Pre-flight safety validation rejected target https://127.0.0.1 (SSRF protection).",
                impact="All inspection modules aborted",
            )
        ],
    )
    col = normalize_evidence("https://127.0.0.1", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.skipped
    assert "redirect_analysis" in col.coverage.skipped
    assert "tls_analysis" in col.coverage.skipped
    assert "security_headers" in col.coverage.skipped
    assert len(col.coverage.completed) == 0


def test_coordinator_completed_with_unexpectedly_missing_subresult():
    """When coordinator is COMPLETED but a sub-result is None, that module is UNAVAILABLE."""
    dns_res = DNSInvestigationResult(domain="example.com", status=DNSStatus.SUCCESS, is_destination_safe=True)
    tls_res = TLSAnalysisResult(hostname="example.com", status=TLSStatus.VALID)
    ti = TechnicalInvestigationResult(
        target_url="https://example.com",
        status=AnalysisStatus.COMPLETED,
        dns=dns_res,
        redirects=None,  # unexpectedly omitted
        tls=tls_res,
        headers=None,
    )
    col = normalize_evidence("https://example.com", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.completed
    assert "tls_analysis" in col.coverage.completed
    assert "redirect_analysis" in col.coverage.unavailable
    assert "security_headers" in col.coverage.unavailable
    assert "redirect_analysis" not in col.coverage.skipped


def test_module_explicit_failure_remains_failed_when_coordinator_partial():
    """When a module explicitly fails (e.g. TIMEOUT), it remains FAILED even if coordinator is PARTIAL."""
    dns_res = DNSInvestigationResult(domain="timeout.example", status=DNSStatus.TIMEOUT)
    ti = TechnicalInvestigationResult(
        target_url="https://timeout.example",
        status=AnalysisStatus.PARTIAL,
        dns=dns_res,
    )
    col = normalize_evidence("https://timeout.example", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.failed
    assert "dns_investigation" not in col.coverage.completed
    assert "dns_investigation" not in col.coverage.partial


def test_batch3_coordinator_compatible():
    """Verify full end-to-end compatibility with complete Batch 3 TechnicalInvestigationResult."""
    dns_res = DNSInvestigationResult(domain="secure.example", status=DNSStatus.SUCCESS, is_destination_safe=True)
    redir_res = RedirectAnalysisResult(
        initial_url="https://secure.example",
        final_url="https://secure.example/",
        hop_count=0,
        stopped_reason="FINAL_DESTINATION_REACHED",
        destination_ip_safe=True,
    )
    tls_res = TLSAnalysisResult(hostname="secure.example", status=TLSStatus.VALID)
    hdr_res = make_headers_result(target_url="https://secure.example", is_reachable=True)
    ti = TechnicalInvestigationResult(
        target_url="https://secure.example",
        status=AnalysisStatus.COMPLETED,
        dns=dns_res,
        redirects=redir_res,
        tls=tls_res,
        headers=hdr_res,
    )
    col = normalize_evidence("https://secure.example", technical_investigation=ti)

    assert "dns_investigation" in col.coverage.completed
    assert "redirect_analysis" in col.coverage.completed
    assert "tls_analysis" in col.coverage.completed
    assert "security_headers" in col.coverage.completed
    assert col.coverage.coverage_ratio > 0.0


# --- Defect B: Security Headers Reachability & Header Status ---

def test_headers_reachable_all_valid():
    """Reachable headers with all 5 valid directives is marked COMPLETED."""
    hdr = make_headers_result(is_reachable=True)
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.completed
    assert "security_headers" not in col.coverage.failed
    assert "security_headers" not in col.coverage.unavailable


def test_headers_reachable_with_missing_headers():
    """Reachable headers with MISSING directives is COMPLETED and findings are retained."""
    finding = TechnicalFinding(
        module="security_headers",
        check_name="missing_csp",
        title="Missing Content-Security-Policy",
        severity=FindingSeverity.LOW,
        description="Missing Content-Security-Policy header",
    )
    hdr = make_headers_result(
        is_reachable=True,
        csp_status=HeaderEvaluationStatus.MISSING,
        findings=[finding],
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.completed
    assert any("missing_csp" in item.finding_id.lower() or "content-security-policy" in item.title.lower() for item in col.items)


def test_headers_reachable_with_weak_or_malformed():
    """Reachable headers with WEAK or MALFORMED directives is COMPLETED and findings are retained."""
    finding = TechnicalFinding(
        module="security_headers",
        check_name="weak_hsts",
        title="Weak HSTS Directive",
        severity=FindingSeverity.MEDIUM,
        description="max-age is below recommended 1 year",
    )
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.WEAK,
        csp_status=HeaderEvaluationStatus.MALFORMED,
        findings=[finding],
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.completed
    assert any("weak_hsts" in item.finding_id.lower() or "weak hsts" in item.title.lower() for item in col.items)


def test_headers_unreachable_not_completed():
    """Unreachable headers endpoint (is_reachable=False) is marked FAILED, never COMPLETED."""
    hdr = make_headers_result(
        is_reachable=False,
        status_code=None,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.failed
    assert "security_headers" not in col.coverage.completed
    assert "security_headers" not in col.coverage.unavailable


def test_headers_all_unavailable_not_completed():
    """Reachable endpoint but all headers UNAVAILABLE is marked UNAVAILABLE, not COMPLETED."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.UNAVAILABLE,
        csp_status=HeaderEvaluationStatus.UNAVAILABLE,
        xcto_status=HeaderEvaluationStatus.UNAVAILABLE,
        xfo_status=HeaderEvaluationStatus.UNAVAILABLE,
        rp_status=HeaderEvaluationStatus.UNAVAILABLE,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.unavailable
    assert "security_headers" not in col.coverage.completed


def test_headers_mixed_available_and_unavailable():
    """Reachable endpoint with mix of evaluated and UNAVAILABLE headers is marked PARTIAL."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.VALID,
        csp_status=HeaderEvaluationStatus.MISSING,
        xcto_status=HeaderEvaluationStatus.UNAVAILABLE,
        xfo_status=HeaderEvaluationStatus.UNAVAILABLE,
        rp_status=HeaderEvaluationStatus.UNAVAILABLE,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.partial
    assert "security_headers" not in col.coverage.completed
    assert "security_headers" not in col.coverage.unavailable


def test_headers_no_findings_does_not_mean_valid():
    """Zero findings on an un-evaluated (UNAVAILABLE) headers analysis does not imply clean/completed."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.UNAVAILABLE,
        csp_status=HeaderEvaluationStatus.UNAVAILABLE,
        xcto_status=HeaderEvaluationStatus.UNAVAILABLE,
        xfo_status=HeaderEvaluationStatus.UNAVAILABLE,
        rp_status=HeaderEvaluationStatus.UNAVAILABLE,
        findings=[],
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.unavailable
    assert "security_headers" not in col.coverage.completed
    assert len(col.items) == 0


def test_headers_normalization_preserves_findings_and_limitations():
    """Verify findings and limitations in security headers are faithfully retained in evidence collection."""
    f1 = TechnicalFinding(
        module="security_headers",
        check_name="missing_csp",
        title="Missing CSP",
        severity=FindingSeverity.MEDIUM,
        description="No Content Security Policy present",
    )
    lim = TechnicalLimitation(
        module="security_headers",
        reason="Truncated after 5 redirects",
        impact="Some headers may not reflect final hop",
    )
    hdr = make_headers_result(
        is_reachable=True,
        findings=[f1],
        limitations=[lim],
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert any("missing_csp" in item.finding_id.lower() or "missing csp" in item.title.lower() for item in col.items)
    assert any("truncated after 5 redirects" in l.lower() for l in col.limitations)


# =============================================================================
# Defect 1 Regression Tests: Coverage State Precedence & Conflict Resolution
# =============================================================================

def test_coverage_same_identifier_in_completed_and_failed_resolves_to_failed():
    """An explicit failure must never be masked by completed; resolves to FAILED."""
    lims = []
    cov = _resolve_coverage_states(
        completed_checks=["dns_investigation"],
        failed_checks=["dns_investigation"],
        unavailable_checks=[],
        partial_checks=[],
        skipped_checks=[],
        not_applicable_checks=[],
        limitations=lims,
    )
    assert "dns_investigation" in cov.failed
    assert "dns_investigation" not in cov.completed
    assert cov.coverage_ratio == 0.0
    assert any("[coverage] Conflicting coverage states for 'dns_investigation'" in l for l in lims)
    assert any("resolved conservatively to 'failed'" in l for l in lims)


def test_coverage_same_identifier_in_completed_and_unavailable_resolves_to_unavailable():
    """Same identifier in completed and unavailable must not falsely complete; resolves to UNAVAILABLE."""
    lims = []
    cov = _resolve_coverage_states(
        completed_checks=["tls_analysis"],
        failed_checks=[],
        unavailable_checks=["tls_analysis"],
        partial_checks=[],
        skipped_checks=[],
        not_applicable_checks=[],
        limitations=lims,
    )
    assert "tls_analysis" in cov.unavailable
    assert "tls_analysis" not in cov.completed
    assert cov.coverage_ratio == 0.0
    assert any("[coverage] Conflicting coverage states for 'tls_analysis'" in l for l in lims)
    assert any("resolved conservatively to 'unavailable'" in l for l in lims)


def test_coverage_same_identifier_in_partial_and_failed_resolves_to_failed():
    """Same identifier in partial and failed must resolve to FAILED."""
    lims = []
    cov = _resolve_coverage_states(
        completed_checks=[],
        failed_checks=["redirect_analysis"],
        unavailable_checks=[],
        partial_checks=["redirect_analysis"],
        skipped_checks=[],
        not_applicable_checks=[],
        limitations=lims,
    )
    assert "redirect_analysis" in cov.failed
    assert "redirect_analysis" not in cov.partial
    assert cov.coverage_ratio == 0.0
    assert any("[coverage] Conflicting coverage states for 'redirect_analysis'" in l for l in lims)
    assert any("resolved conservatively to 'failed'" in l for l in lims)


def test_coverage_same_identifier_in_multiple_states_resolves_to_exactly_one_final_state():
    """Identifier present in completed, partial, unavailable, and failed resolves to exactly one final state: FAILED."""
    lims = []
    cov = _resolve_coverage_states(
        completed_checks=["security_headers"],
        failed_checks=["security_headers"],
        unavailable_checks=["security_headers"],
        partial_checks=["security_headers"],
        skipped_checks=[],
        not_applicable_checks=[],
        limitations=lims,
    )
    # Exactly one final state: failed
    assert "security_headers" in cov.failed
    assert "security_headers" not in cov.completed
    assert "security_headers" not in cov.unavailable
    assert "security_headers" not in cov.partial
    total_occurrences = (
        cov.completed.count("security_headers")
        + cov.failed.count("security_headers")
        + cov.unavailable.count("security_headers")
        + cov.partial.count("security_headers")
        + cov.skipped.count("security_headers")
        + cov.not_applicable.count("security_headers")
    )
    assert total_occurrences == 1
    assert any("resolved conservatively to 'failed'" in l for l in lims)


def test_coverage_normal_non_conflicting_remains_unchanged():
    """Normal non-conflicting check identifiers resolve to their exact categories with no conflict logged."""
    lims = []
    cov = _resolve_coverage_states(
        completed_checks=["dns_investigation"],
        failed_checks=["redirect_analysis"],
        unavailable_checks=["threat_intelligence"],
        partial_checks=["security_headers"],
        skipped_checks=["ai_analysis"],
        not_applicable_checks=["tls_analysis"],
        limitations=lims,
    )
    assert cov.completed == ["dns_investigation"]
    assert cov.failed == ["redirect_analysis"]
    assert cov.unavailable == ["threat_intelligence"]
    assert cov.partial == ["security_headers"]
    assert cov.skipped == ["ai_analysis"]
    assert cov.not_applicable == ["tls_analysis"]
    # Ratio: (1 + 0.5) / 4 applicable = 1.5 / 4 = 0.38
    assert cov.coverage_ratio == 0.38
    # No conflict limitations should be logged
    assert not any("[coverage] Conflicting coverage states" in l for l in lims)


# =============================================================================
# Defect 2 Regression Tests: Unknown Security Header Status Handling
# =============================================================================

def test_headers_all_five_statuses_valid_completed():
    """All five security headers having VALID status resolves to COMPLETED."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.VALID,
        csp_status=HeaderEvaluationStatus.VALID,
        xcto_status=HeaderEvaluationStatus.VALID,
        xfo_status=HeaderEvaluationStatus.VALID,
        rp_status=HeaderEvaluationStatus.VALID,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.completed
    assert "security_headers" not in col.coverage.partial
    assert "security_headers" not in col.coverage.unavailable


def test_headers_one_unknown_and_four_valid_partial():
    """One unknown status and four valid statuses resolves to PARTIAL, never COMPLETED."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.VALID,
        csp_status=HeaderEvaluationStatus.VALID,
        xcto_status="CUSTOM_UNKNOWN_STATE",
        xfo_status=HeaderEvaluationStatus.VALID,
        rp_status=HeaderEvaluationStatus.VALID,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.partial
    assert "security_headers" not in col.coverage.completed
    assert any("unrecognized or invalid evaluation status: 'CUSTOM_UNKNOWN_STATE'" in l for l in col.limitations)


def test_headers_all_five_statuses_unknown_unavailable():
    """All five security headers having unknown statuses resolves to UNAVAILABLE."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status="BOGUS_STATUS_1",
        csp_status="BOGUS_STATUS_2",
        xcto_status="BOGUS_STATUS_3",
        xfo_status="BOGUS_STATUS_4",
        rp_status="BOGUS_STATUS_5",
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.unavailable
    assert "security_headers" not in col.coverage.completed
    assert "security_headers" not in col.coverage.partial
    assert any("[security_headers] All HTTP security header evaluations were unavailable or invalid" in l for l in col.limitations)


def test_headers_empty_or_none_status_never_completed():
    """Empty string or None status values are treated as unknown/invalid and never yield COMPLETED."""
    hdr_none = make_headers_result(
        is_reachable=True,
        hsts_status=None,
        csp_status="",
        xcto_status=None,
        xfo_status="",
        rp_status=None,
    )
    col_none = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr_none,
    ))
    assert "security_headers" in col_none.coverage.unavailable
    assert "security_headers" not in col_none.coverage.completed

    # Mix of valid and None -> PARTIAL, never COMPLETED
    hdr_mix = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.VALID,
        csp_status=None,
        xcto_status=HeaderEvaluationStatus.VALID,
        xfo_status="",
        rp_status=HeaderEvaluationStatus.VALID,
    )
    col_mix = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr_mix,
    ))
    assert "security_headers" in col_mix.coverage.partial
    assert "security_headers" not in col_mix.coverage.completed


def test_headers_unknown_status_plus_unavailable_never_completed():
    """Mix of unknown status and UNAVAILABLE resolves to UNAVAILABLE, never COMPLETED."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.UNAVAILABLE,
        csp_status="STRANGE_STATUS",
        xcto_status=HeaderEvaluationStatus.UNAVAILABLE,
        xfo_status="WEIRD_DIRECTIVE_RESULT",
        rp_status=HeaderEvaluationStatus.UNAVAILABLE,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.unavailable
    assert "security_headers" not in col.coverage.completed
    assert "security_headers" not in col.coverage.partial


def test_headers_missing_weak_malformed_remain_observed_and_completed():
    """All 5 headers present in observed statuses (VALID, WEAK, MALFORMED, MISSING) resolves to COMPLETED."""
    hdr = make_headers_result(
        is_reachable=True,
        hsts_status=HeaderEvaluationStatus.WEAK,
        csp_status=HeaderEvaluationStatus.MISSING,
        xcto_status=HeaderEvaluationStatus.MALFORMED,
        xfo_status=HeaderEvaluationStatus.VALID,
        rp_status=HeaderEvaluationStatus.MISSING,
    )
    col = normalize_evidence("https://example.com", technical_investigation=TechnicalInvestigationResult(
        target_url="https://example.com",
        headers=hdr,
    ))
    assert "security_headers" in col.coverage.completed
    assert "security_headers" not in col.coverage.partial
    assert "security_headers" not in col.coverage.unavailable
