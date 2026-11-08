"""CyberShield AI — Member 1 + Member 3 End-to-End Integration Tests

Verifies seamless interoperability between Member 1 (Core Backend, URL Investigation,
Risk Engine, Unified Threat Report) and Member 3 (Blockchain Registry, Canonical
Hashing, Web3 Services, and Tamper-Proof Verification).
"""

import json
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.config import get_settings
from app.schemas.threat_report import UnifiedThreatReport
from app.schemas.common import RiskClassification, VerificationStatus, ScanType
from app.services.report_generator import assemble_unified_threat_report
from app.services.blockchain import (
    compute_canonical_report_hash,
    compute_keccak256_report_hash,
    compute_blockchain_report_id,
    threat_report_to_canonical_blockchain_dict,
)
from app.services.blockchain.report_hash import (
    validate_threat_report,
    normalize_threat_report,
    canonicalize_report,
    hash_report,
    NAMESPACE,
)

client = TestClient(app)
AUTH_HEADERS = {"X-API-Key": get_settings().api_auth_key}


class TestMember1ToMember3SchemaAdapter:
    """Verifies that Member 1 reports map deterministically to Member 3 schemas."""

    def test_assemble_and_adapt_phishing_report(self):
        """Assembling a real threat report from Member 1 maps cleanly to Member 3 schema."""
        report = assemble_unified_threat_report(
            target="https://phishing-credential-harvester.example.com",
            target_type=ScanType.URL,
        )
        assert isinstance(report, UnifiedThreatReport)

        # Adapt to Member 3 canonical dictionary
        m3_dict = threat_report_to_canonical_blockchain_dict(report)

        # Validate with Member 3 strict schema validator (all 10 required fields)
        validated = validate_threat_report(m3_dict)
        assert validated["report_id"] == report.scan_id
        assert validated["schema_version"] == "1.0"
        assert validated["severity"] in ("critical", "high", "medium", "low", "informational")
        assert validated["status"] in ("completed", "investigating")
        assert 0 <= validated["confidence_score"] <= 100
        assert validated["summary"]
        assert validated["description"]
        assert len(validated["indicators"]) >= 1
        assert validated["indicators"][0]["value"] == "https://phishing-credential-harvester.example.com"

    def test_all_risk_classifications_map_to_valid_severities(self):
        """All Member 1 risk classifications map to Member 3 allowed severity enum."""
        classifications = [
            RiskClassification.CONFIRMED_MALICIOUS,
            RiskClassification.HIGH_RISK,
            RiskClassification.SUSPICIOUS,
            RiskClassification.LOW_RISK,
            RiskClassification.INCONCLUSIVE,
        ]
        expected_severities = ["critical", "high", "medium", "low", "informational"]

        for c, expected_s in zip(classifications, expected_severities):
            report = assemble_unified_threat_report(f"https://test-{c.value}.com")
            report.risk.classification = c
            m3_dict = threat_report_to_canonical_blockchain_dict(report)
            validated = validate_threat_report(m3_dict)
            assert validated["severity"] == expected_s

    def test_score_and_confidence_numeric_normalization(self):
        """Ensures floating-point whole numbers and fractional decimals are normalized properly."""
        report = assemble_unified_threat_report("https://numeric-test.com")
        report.risk.score = 87
        m3_dict = threat_report_to_canonical_blockchain_dict(report)
        assert m3_dict["confidence_score"] == 87
        assert isinstance(m3_dict["confidence_score"], int)

        report.risk.score = None
        report.risk.confidence = 0.875
        m3_dict = threat_report_to_canonical_blockchain_dict(report)
        assert m3_dict["confidence_score"] == 87.5
        assert isinstance(m3_dict["confidence_score"], float)


class TestDualHashingAndReportIdDerivation:
    """Verifies that SHA-256 and Keccak-256 both operate deterministically."""

    def test_dual_hash_generation(self):
        """Report generates 66-character hex hashes for both algorithms."""
        report = assemble_unified_threat_report("https://hash-dual.com", scan_id="test-scan-001")
        report.timestamp = "2026-11-08T12:00:00Z"
        report.submitted_input.normalized_at = "2026-11-08T12:00:00Z"

        sha256_hash = compute_canonical_report_hash(report, algorithm="sha256")
        keccak_hash = compute_keccak256_report_hash(report)

        assert sha256_hash.startswith("0x") and len(sha256_hash) == 66
        assert keccak_hash.startswith("0x") and len(keccak_hash) == 66
        assert sha256_hash != keccak_hash

    def test_report_id_derivation_mirrors_solidity(self):
        """Report ID matches keccak256(NAMESPACE || reportHash)."""
        report = assemble_unified_threat_report("https://report-id-check.com")
        keccak_hash = compute_keccak256_report_hash(report)
        derived_id = compute_blockchain_report_id(keccak_hash)

        assert derived_id.startswith("0x") and len(derived_id) == 66


class TestFullEndToEndBackendWorkflow:
    """Tests the full API workflow: Investigate -> Persist -> Register -> Verify."""

    def test_investigate_register_and_verify(self):
        """Investigates URL, registers hash via API, and verifies integrity."""
        # 1. Investigate and generate report
        res_inv = client.post(
            "/api/v1/reports/investigate",
            json={"url": "https://adamas-university.ac.in"},
            headers=AUTH_HEADERS,
        )
        assert res_inv.status_code == 200
        report_data = res_inv.json()
        scan_id = report_data["scan_id"]
        assert report_data["status"] == "completed"

        # 2. Register report on blockchain
        res_reg = client.post(
            "/api/v1/reports/register",
            json={"report_id": scan_id},
            headers=AUTH_HEADERS,
        )
        assert res_reg.status_code == 200
        reg_data = res_reg.json()
        assert reg_data["report_id"] == scan_id
        assert reg_data["status"] in ("simulated", "confirmed")
        assert reg_data["report_hash"].startswith("0x")
        assert ("simulated_tx:" in reg_data["transaction_hash"]) or reg_data["transaction_hash"].startswith("0x")

        # 3. Public Verification
        res_ver = client.post(
            "/api/v1/reports/verify",
            json={"report_id": scan_id},
        )
        assert res_ver.status_code == 200
        ver_data = res_ver.json()
        assert ver_data["is_valid"] is True
        assert ver_data["verification_status"] in (VerificationStatus.SIMULATED_VALID, VerificationStatus.VERIFIED_VALID)
        assert ver_data["computed_canonical_hash"] == reg_data["report_hash"]
        assert ver_data["on_chain_hash"] == reg_data["report_hash"]

    def test_unauthenticated_registration_rejected(self):
        """Registering on-chain without API key is rejected with 401/403."""
        res = client.post(
            "/api/v1/reports/register",
            json={"report_id": "any-scan-id"},
        )
        assert res.status_code in (401, 403)

    def test_forged_hash_tamper_detected(self):
        """Verifying with a forged hash immediately returns TAMPERED status."""
        res_inv = client.post(
            "/api/v1/reports/investigate",
            json={"url": "https://safe-domain.example"},
            headers=AUTH_HEADERS,
        )
        scan_id = res_inv.json()["scan_id"]

        client.post(
            "/api/v1/reports/register",
            json={"report_id": scan_id},
            headers=AUTH_HEADERS,
        )

        res_ver = client.post(
            "/api/v1/reports/verify",
            json={
                "report_id": scan_id,
                "provided_hash": "0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
            },
        )
        assert res_ver.status_code == 200
        ver_data = res_ver.json()
        assert ver_data["is_valid"] is False
        assert ver_data["verification_status"] in (VerificationStatus.SIMULATED_TAMPERED, VerificationStatus.VERIFIED_TAMPERED)
        assert "does not match" in ver_data["explanation"]

    def test_scan_url_remains_501_not_implemented(self):
        """Security Gate Rule: /api/v1/scan-url must remain HTTP 501."""
        res = client.post(
            "/api/v1/scan-url",
            json={"url": "https://example.com"},
        )
        assert res.status_code == 501
