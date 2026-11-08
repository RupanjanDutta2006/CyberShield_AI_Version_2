"""CyberShield AI — Part 17 Core API Integration Tests

Tests end-to-end FastAPI routing, request limits, structured error handling,
security gate enforcement, report persistence, on-chain registration, authentication, and verification.
"""

import pytest
from starlette.testclient import TestClient
from app.main import app
from app.schemas.threat_report import UnifiedThreatReport
from app.services.report_generator import assemble_unified_threat_report

client = TestClient(app)

AUTH_HEADERS = {"X-API-Key": "cybershield-auth-key-2026"}
BEARER_HEADERS = {"Authorization": "Bearer cybershield-auth-key-2026"}


class TestSystemEndpoints:
    """Tests for health and OpenAPI endpoints."""

    def test_health_check(self):
        """API v1 health check returns 200 OK."""
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_security_gate_scan_url_disabled(self):
        """Live /scan-url endpoint remains safely disabled under Security Gate rules."""
        res = client.post("/api/v1/scan-url", json={"url": "https://example.com"})
        assert res.status_code == 501
        assert "Security Gate rules" in res.json()["detail"]


class TestEndpointAuthentication:
    """Tests for API Key and Bearer token security enforcement (B5-F01)."""

    def test_unauthenticated_request_rejected(self):
        """Sensitive endpoints require authentication and return 401 Unauthorized."""
        res = client.get("/api/v1/history")
        assert res.status_code == 401
        assert "Authentication required" in res.json()["detail"]
        assert "WWW-Authenticate" in res.headers

        res_scan = client.get("/api/v1/scans/any-id")
        assert res_scan.status_code == 401

        res_inv = client.post("/api/v1/reports/investigate", json={"url": "https://example.com"})
        assert res_inv.status_code == 401

        res_reg = client.post("/api/v1/reports/register", json={"report_id": "any-id"})
        assert res_reg.status_code == 401

    def test_invalid_api_key_forbidden(self):
        """Providing an invalid API key returns 403 Forbidden."""
        res = client.get("/api/v1/history", headers={"X-API-Key": "wrong-key-value"})
        assert res.status_code == 403
        assert "Forbidden" in res.json()["detail"]

    def test_bearer_token_authentication_success(self):
        """Valid Bearer token authorizes sensitive endpoint."""
        res = client.get("/api/v1/history", headers=BEARER_HEADERS)
        assert res.status_code == 200

    def test_fail_closed_when_auth_secret_missing(self):
        """Server fails closed with 500 when authentication key is unconfigured."""
        from unittest.mock import patch
        from app.core.config import get_settings
        with patch.object(get_settings(), "api_auth_key", ""):
            res = client.get("/api/v1/history", headers=AUTH_HEADERS)
            assert res.status_code == 500

    def test_reject_default_key_in_production(self):
        """Server fails closed in production when default development key is retained."""
        from unittest.mock import patch
        from app.core.config import get_settings
        with patch.object(get_settings(), "environment", "production"):
            res = client.get("/api/v1/history", headers=AUTH_HEADERS)
            assert res.status_code == 500

    def test_public_endpoints_accessible_without_auth(self):
        """Public investigation endpoints do not require authentication."""
        # Preflight
        res_pre = client.post("/api/v1/url/preflight", json={"url": "https://example.com"})
        assert res_pre.status_code == 200

        # Message analysis
        res_msg = client.post(
            "/api/v1/analyze-message",
            json={"message_text": "Informational update regarding your meeting at 3pm."}
        )
        assert res_msg.status_code == 200

        # Verification endpoint is public for tamper verification
        res_ver = client.post("/api/v1/reports/verify", json={"report_id": "nonexistent-id"})
        assert res_ver.status_code == 200
        assert res_ver.json()["verification_status"] == "not_found"


class TestMessageAnalysisEndpoint:
    """Tests for /api/v1/analyze-message."""

    def test_analyze_scam_message_success(self):
        """Post a phishing message and receive structured analysis."""
        payload = {
            "message_text": "URGENT: Your account has been suspended! Verify your credentials at https://auth-secure.test immediately.",
            "sender_hint": "admin@bank-alert.com"
        }
        res = client.post("/api/v1/analyze-message", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] == "high_risk"
        assert len(data["observed_indicators"]) >= 2
        assert len(data["recommendations"]) > 0

    def test_analyze_message_validation_failure(self):
        """Posting invalid or short text triggers 422 validation error."""
        res = client.post("/api/v1/analyze-message", json={"message_text": "hi"})
        assert res.status_code == 422
        assert res.json()["error"] == "ValidationError"


class TestReportEndpointsAndWorkflow:
    """Tests for report generation, retrieval, persistence, registration, and verification."""

    def test_full_investigate_and_generate_report(self):
        """Test POST /api/v1/reports/investigate with safe external URL."""
        res = client.post(
            "/api/v1/reports/investigate",
            json={"url": "https://example.com"},
            headers=AUTH_HEADERS,
        )
        assert res.status_code == 200
        report_data = res.json()
        assert "scan_id" in report_data
        assert "risk" in report_data
        assert "evidence_coverage" in report_data
        assert "technical_findings" in report_data
        assert "threat_intelligence" in report_data

        scan_id = report_data["scan_id"]

        # Retrieve via GET /scans/{scan_id}
        res_get = client.get(f"/api/v1/scans/{scan_id}", headers=AUTH_HEADERS)
        assert res_get.status_code == 200
        assert res_get.json()["scan_id"] == scan_id

    def test_ssrf_blocked_investigation(self):
        """Attempting to investigate a private IP triggers SSRF safety block and omits outbound calls."""
        res = client.post(
            "/api/v1/reports/investigate",
            json={"url": "http://127.0.0.1:8080/admin"},
            headers=AUTH_HEADERS,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["risk"]["classification"] in ("Confirmed Malicious", "High Risk", "Inconclusive")
        assert any("SSRF" in lim for lim in data["limitations"])

    def test_get_nonexistent_scan_returns_404(self):
        """Querying unknown scan_id returns 404."""
        res = client.get("/api/v1/scans/unknown-uuid-9999", headers=AUTH_HEADERS)
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

    def test_history_pagination(self):
        """GET /api/v1/history returns paginated results."""
        res = client.get("/api/v1/history?limit=5&offset=0", headers=AUTH_HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert "total" in data
        assert "items" in data
        assert data["limit"] == 5
        assert data["offset"] == 0

    def test_blockchain_register_and_verify_flow(self):
        """Complete workflow: generate report -> register on-chain -> verify integrity."""
        # 1. Investigate and generate report
        res_gen = client.post(
            "/api/v1/reports/investigate",
            json={"url": "https://example.com/blockchain-test"},
            headers=AUTH_HEADERS,
        )
        assert res_gen.status_code == 200
        scan_id = res_gen.json()["scan_id"]

        # 2. Register on-chain (simulation mode)
        res_reg = client.post(
            "/api/v1/reports/register",
            json={"report_id": scan_id},
            headers=AUTH_HEADERS,
        )
        assert res_reg.status_code == 200
        reg_data = res_reg.json()
        assert reg_data["report_id"] == scan_id
        assert reg_data["status"] in ("simulated", "confirmed")
        assert ("simulated_tx:" in reg_data["transaction_hash"]) or reg_data["transaction_hash"].startswith("0x")

        # 3. Verify against blockchain (simulation or live EVM mode)
        res_ver = client.post(
            "/api/v1/reports/verify",
            json={"report_id": scan_id}
        )
        assert res_ver.status_code == 200
        ver_data = res_ver.json()
        assert ver_data["is_valid"] is True
        assert ver_data["verification_status"] in ("simulated_valid", "verified_valid")
        assert ver_data["computed_canonical_hash"] == reg_data["report_hash"]

    def test_register_nonexistent_report_returns_404(self):
        """Registering unknown scan_id returns 404."""
        res = client.post(
            "/api/v1/reports/register",
            json={"report_id": "ghost-scan-000"},
            headers=AUTH_HEADERS,
        )
        assert res.status_code == 404
