"""CyberShield AI — Schema & Contract Unit Tests

Validates Pydantic schema validation, default values, serialization,
and enum invariants across all shared integration contracts.
"""

import json
import pytest
from pydantic import ValidationError
from app.schemas import (
    RiskClassification,
    ScanType,
    AnalysisStatus,
    FindingSeverity,
    VerificationStatus,
    URLScanRequest,
    MessageAnalysisRequest,
    MessageAnalysisResponse,
    ObservedIndicator,
    ThreatIntelSourceResult,
    ReportRegistrationRequest,
    ReportVerificationResponse,
    ReportIntegrityMetadata,
    SubmittedInput,
    RiskAssessment,
    UnifiedThreatReport,
    DNSFindingDetails,
    RedirectFindingDetails,
    TLSFindingDetails,
    SecurityHeaderFindingDetails,
)


def test_risk_classification_enum_values():
    """Verify the 5 exact mandatory risk classifications are defined."""
    assert RiskClassification.LOW_RISK.value == "Low Risk"
    assert RiskClassification.SUSPICIOUS.value == "Suspicious"
    assert RiskClassification.HIGH_RISK.value == "High Risk"
    assert RiskClassification.CONFIRMED_MALICIOUS.value == "Confirmed Malicious"
    assert RiskClassification.INCONCLUSIVE.value == "Inconclusive"
    assert len(RiskClassification) == 5


def test_url_scan_request_valid():
    """Test valid URL scan requests."""
    req = URLScanRequest(url="https://secure-banking.test/login")
    assert req.url == "https://secure-banking.test/login"
    assert req.force_refresh is False


def test_url_scan_request_invalid_too_short():
    """Test rejection of empty or excessively short URLs."""
    with pytest.raises(ValidationError):
        URLScanRequest(url="ab")


def test_message_analysis_contract():
    """Test Member 2 AI scam message analysis contracts."""
    req = MessageAnalysisRequest(
        message_text="URGENT: Your account is locked. Provide OTP to verify immediately."
    )
    assert "URGENT" in req.message_text

    res = MessageAnalysisResponse(
        category="credential_harvesting",
        risk_level="high_risk",
        confidence=0.88,
        observed_indicators=[
            ObservedIndicator(
                indicator="Urgent OTP solicitation",
                evidence="Provide OTP to verify immediately",
                reason="Legitimate providers never ask for OTP directly"
            )
        ],
        explanation="The message simulates an urgent emergency to coerce OTP disclosure.",
        recommendations=["Do not reply", "Do not share OTP"],
        limitations=["Sender phone number cannot be cryptographically verified from text alone"]
    )
    assert res.category == "credential_harvesting"
    assert len(res.observed_indicators) == 1
    assert res.confidence == 0.88


def test_threat_intel_contract():
    """Test Member 4 threat intelligence normalized response contract."""
    ti = ThreatIntelSourceResult(
        source="URLhaus",
        checked_at="2026-11-07T12:00:00Z",
        match=True,
        threat_type="malware_download",
        evidence=["Tagged as Emotet payload host"],
        source_status="available",
        limitations=[]
    )
    assert ti.source == "URLhaus"
    assert ti.match is True
    assert ti.threat_type == "malware_download"


def test_blockchain_verification_contract():
    """Test Member 3 blockchain verification response contract."""
    res = ReportVerificationResponse(
        report_id="rep-12345",
        computed_canonical_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        on_chain_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        is_valid=True,
        verification_status=VerificationStatus.VERIFIED_VALID,
        explanation="Cryptographic report hash matches immutable blockchain record."
    )
    assert res.is_valid is True
    assert res.verification_status == VerificationStatus.VERIFIED_VALID


def test_unified_threat_report_lifecycle():
    """Test complete UnifiedThreatReport assembly and JSON round-trip."""
    report = UnifiedThreatReport(
        scan_id="scan-uuid-001",
        submitted_input=SubmittedInput(
            type=ScanType.URL,
            value="https://suspicious-portal.test"
        ),
        risk=RiskAssessment(
            classification=RiskClassification.SUSPICIOUS,
            score=45,
            confidence=0.75,
            summary="Suspicious domain age combined with missing security headers."
        )
    )

    # Validate defaults
    assert report.schema_version == "1.0.0"
    assert report.status == AnalysisStatus.COMPLETED
    assert report.report_integrity.verification_status == VerificationStatus.NOT_REGISTERED
    assert report.report_integrity.report_hash is None

    # Test serialization to JSON and back
    json_data = report.model_dump_json()
    parsed = json.loads(json_data)
    assert parsed["scan_id"] == "scan-uuid-001"
    assert parsed["risk"]["classification"] == "Suspicious"
    assert parsed["risk"]["score"] == 45


def test_security_boolean_defaults_and_explicit_states():
    """Verify security booleans default to None (unknown/unchecked) rather than True (F-02)."""
    # 1. Unchecked / default state: all security assessment booleans must be None
    redirect = RedirectFindingDetails(initial_url="https://example.com")
    assert redirect.destination_ip_safe is None, "destination_ip_safe must default to None when unchecked"
    assert redirect.has_circular_redirect is None

    dns = DNSFindingDetails(domain="example.com")
    assert dns.has_valid_dns is None, "has_valid_dns must default to None when unchecked"

    tls = TLSFindingDetails(hostname="example.com")
    assert tls.is_expired is None
    assert tls.san_matches is None
    assert tls.weak_algorithm_detected is None

    headers = SecurityHeaderFindingDetails()
    assert headers.hsts_present is None
    assert headers.csp_present is None
    assert headers.x_frame_options_present is None
    assert headers.x_content_type_options_present is None

    # 2. Explicit safe state
    safe_redirect = RedirectFindingDetails(
        initial_url="https://example.com",
        final_url="https://example.com",
        destination_ip_safe=True
    )
    assert safe_redirect.destination_ip_safe is True

    # 3. Explicit unsafe state
    unsafe_redirect = RedirectFindingDetails(
        initial_url="https://example.com",
        final_url="http://169.254.169.254/latest/meta-data",
        destination_ip_safe=False
    )
    assert unsafe_redirect.destination_ip_safe is False


def test_lazy_schema_imports_and_dir_support():
    """Batch 3 Finalization: Verify dynamic schema imports, __getattr__, and __dir__ support."""
    import app.schemas as schemas_pkg
    import app.schemas.url_scan as url_scan_pkg

    # 1. Named imports through dynamic module getattr
    from app.schemas import (
        DNSInvestigationResult,
        RedirectAnalysisResult,
        TLSAnalysisResult,
        SecurityHeaderAnalysisResult,
        TechnicalInvestigationResult,
    )
    assert DNSInvestigationResult is not None
    assert RedirectAnalysisResult is not None
    assert TLSAnalysisResult is not None
    assert SecurityHeaderAnalysisResult is not None
    assert TechnicalInvestigationResult is not None

    # 2. dir(app.schemas) contains batch 3 symbols
    schemas_dir = dir(schemas_pkg)
    for expected_symbol in [
        "DNSInvestigationResult",
        "RedirectAnalysisResult",
        "TLSAnalysisResult",
        "SecurityHeaderAnalysisResult",
        "TechnicalInvestigationResult",
    ]:
        assert expected_symbol in schemas_dir

    # 3. dir(app.schemas.url_scan) contains batch 3 symbols
    url_scan_dir = dir(url_scan_pkg)
    assert "RedirectAnalysisResult" in url_scan_dir
    assert "TechnicalInvestigationResult" in url_scan_dir


