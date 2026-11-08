import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.blockchain_verifier import ReportVerifier
from threat_intel.normalization import URLNormalizer
from threat_intel.services.reputation import ReputationAssessor
from threat_intel.schemas import NormalizedThreatIndicator

client = TestClient(app)


def test_url_normalizer():
    # Test valid standard URL
    meta = URLNormalizer.normalize_target("http://example.com/login?param=1")
    assert meta["domain"] == "example.com"
    assert meta["hostname"] == "example.com"
    assert meta["normalized_url"] == "http://example.com/login?param=1"
    assert "hxxp://example[.]com" in meta["defanged_url"]

    # Test raw domain input without scheme defaults to https://
    meta2 = URLNormalizer.normalize_target("threat-actor.org/c2/beacon")
    assert meta2["domain"] == "threat-actor.org"
    assert meta2["normalized_url"].startswith("https://")

    # Test IP literal detection
    meta_ip = URLNormalizer.normalize_target("http://192.168.1.1:8080/shell")
    assert meta_ip["is_ip_literal"] is True
    assert meta_ip["port"] == 8080


def test_reputation_assessor_scoring():
    # Confirmed malicious
    target_meta = {
        "hostname": "malware-download.xyz",
        "domain": "malware-download.xyz",
        "tld": "xyz",
        "is_ip_literal": False,
        "port": 80
    }
    indicators = [
        NormalizedThreatIndicator(
            provider="URLhaus",
            indicator_type="url",
            indicator_value="http://malware-download.xyz",
            status="match_found",
            matched=True,
            verified=True,
            details={"threat": "malware_download"}
        )
    ]
    assessment = ReputationAssessor.evaluate(target_meta, indicators)
    assert assessment.risk_level == "Critical"
    assert assessment.risk_score >= 90
    assert len(assessment.evidence) > 0
    assert len(assessment.recommendations) > 0


def test_report_canonical_hash_and_verification():
    report_data = {
        "scan_id": "test-uuid-1",
        "target": "https://example.com",
        "risk_level": "Low",
        "risk_score": 10,
        "summary": "Clean destination."
    }

    # Generate initial hash
    initial_hash = ReportVerifier.calculate_hash(report_data)
    assert len(initial_hash) == 64

    # Verify matching data
    is_valid, recalc_hash, notes = ReportVerifier.verify_report_integrity(initial_hash, report_data)
    assert is_valid is True
    assert recalc_hash == initial_hash

    # Verify tampered data detection
    tampered_data = dict(report_data)
    tampered_data["summary"] = "Tampered fraudulent summary."
    is_valid_tampered, tampered_hash, _ = ReportVerifier.verify_report_integrity(initial_hash, tampered_data)
    assert is_valid_tampered is False
    assert tampered_hash != initial_hash


def test_api_system_status():
    resp = client.get("/api/v1/system/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "database_type" in data
    assert len(data["providers"]) >= 3


def test_api_url_scan_clean_synthetic():
    resp = client.post("/api/v1/scans/url", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert data["target"] == "https://example.com"
    assert data["status"] == "completed"
    assert data["risk_level"] in ["Low", "Unknown"]
    assert data["report"] is not None
    assert len(data["report"]["report_hash"]) == 64


def test_api_message_scan():
    content = "URGENT: Your bank account will be suspended within 24 hours. Verify your login password immediately."
    resp = client.post("/api/v1/scans/message", json={"content": content})
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_type"] == "message"
    assert data["risk_level"] in ["High", "Critical"]
    assert data["risk_score"] >= 70
    assert len(data["message_indicators"]) >= 2


def test_api_report_verification_endpoint():
    # Scan clean URL first
    scan_resp = client.post("/api/v1/scans/url", json={"url": "https://example.org"})
    assert scan_resp.status_code == 200
    report_id = scan_resp.json()["report"]["report_id"]

    # Verify report integrity
    verify_resp = client.post(f"/api/v1/reports/{report_id}/verify", json={})
    assert verify_resp.status_code == 200
    ver_data = verify_resp.json()
    assert ver_data["is_valid"] is True
    assert ver_data["verification_status"] == "locally_hashed"

    # Test tampering detection
    tamper_resp = client.post(
        f"/api/v1/reports/{report_id}/verify",
        json={"simulated_tampered_summary": "Injected malicious text altering record."}
    )
    assert tamper_resp.status_code == 200
    tamper_data = tamper_resp.json()
    assert tamper_data["is_valid"] is False
    assert tamper_data["verification_status"] == "verification_failed"
