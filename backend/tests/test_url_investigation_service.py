"""CyberShield AI — Batch 2 URL Investigation Service Integration Tests

Tests end-to-end preflight pipeline (Parts 05–08) and API v1 endpoint behavior.
Verifies fail-closed gating on invalid input, loopback/private/metadata destinations,
and heuristic indicator generation with zero outbound network activity.
"""

import pytest
from starlette.testclient import TestClient
from fastapi import status

from app.main import app
from app.services.url_investigation.service import investigate_url_preflight


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app, raise_server_exceptions=False)


class TestURLInvestigationService:
    """Test suite for integrated URL investigation service."""

    def test_preflight_valid_public_url(self):
        """Test clean public URL passes all preflight checks."""
        res = investigate_url_preflight("https://example.com/dashboard")
        assert res.is_eligible_for_scan is True
        assert res.gate_status == "PASSED_PREFLIGHT"
        assert res.validation.is_valid is True
        assert res.normalization is not None
        assert res.normalization.hostname == "example.com"
        assert res.ssrf_validation is not None
        assert res.ssrf_validation.is_safe is True

    def test_preflight_invalid_input_fails_closed(self):
        """Test invalid input (unsupported scheme) fails closed."""
        res = investigate_url_preflight("gopher://old-service.floodgap.com")
        assert res.is_eligible_for_scan is False
        assert res.gate_status == "INVALID_INPUT"
        assert res.validation.is_valid is False
        assert res.validation.error_code == "UNSUPPORTED_SCHEME"
        assert res.normalization is None
        assert res.ssrf_validation is None

    def test_preflight_ssrf_loopback_blocked(self):
        """Test loopback target is blocked by SSRF guard."""
        res = investigate_url_preflight("http://127.0.0.1:8000/internal-admin")
        assert res.is_eligible_for_scan is False
        assert res.gate_status == "SSRF_BLOCKED"
        assert res.ssrf_validation is not None
        assert res.ssrf_validation.is_safe is False
        assert res.ssrf_validation.is_loopback is True

    def test_preflight_ssrf_cloud_metadata_blocked(self):
        """Test cloud metadata target is blocked by SSRF guard."""
        res = investigate_url_preflight("http://169.254.169.254/latest/meta-data/")
        assert res.is_eligible_for_scan is False
        assert res.gate_status == "SSRF_BLOCKED"
        assert res.ssrf_validation is not None
        assert res.ssrf_validation.is_safe is False
        assert res.ssrf_validation.is_metadata_endpoint is True

    def test_preflight_ssrf_internal_hostname_blocked(self):
        """Test internal domain suffix is blocked by SSRF guard."""
        res = investigate_url_preflight("http://database.cluster.internal/query")
        assert res.is_eligible_for_scan is False
        assert res.gate_status == "SSRF_BLOCKED"
        assert res.ssrf_validation is not None
        assert res.ssrf_validation.is_safe is False
        assert res.ssrf_validation.is_private is True

    def test_preflight_heuristics_aggregation(self):
        """Test suspicious patterns are aggregated into findings."""
        url = "http://account-login.verify.bank.com:1337/update?url=http://phish.xyz"
        res = investigate_url_preflight(url)
        assert res.is_eligible_for_scan is True  # Public host, but has indicators
        check_names = [f.check_name for f in res.heuristic_findings]
        assert "DECEPTIVE_BRAND_KEYWORDS" in check_names
        assert "UNUSUAL_PORT_SPECIFIED" in check_names
        assert "SUSPICIOUS_OPEN_REDIRECT_PARAM" in check_names

    def test_api_preflight_endpoint_valid_url(self, client: TestClient):
        """Test POST /api/v1/url/preflight endpoint with valid URL."""
        response = client.post("/api/v1/url/preflight", json={"url": "https://example.com/login"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["gate_status"] == "PASSED_PREFLIGHT"
        assert data["is_eligible_for_scan"] is True
        assert data["validation"]["is_valid"] is True
        assert data["normalization"]["normalized_url"] == "https://example.com/login"

    def test_api_preflight_endpoint_ssrf_target(self, client: TestClient):
        """Test POST /api/v1/url/preflight endpoint with SSRF target."""
        response = client.post("/api/v1/url/preflight", json={"url": "http://127.0.0.1:8080/admin"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["gate_status"] == "SSRF_BLOCKED"
        assert data["is_eligible_for_scan"] is False
        assert data["ssrf_validation"]["is_safe"] is False

    def test_api_scan_url_still_returns_501(self, client: TestClient):
        """Test POST /api/v1/scan-url remains disabled with HTTP 501."""
        response = client.post("/api/v1/scan-url", json={"url": "https://example.com"})
        assert response.status_code == status.HTTP_501_NOT_IMPLEMENTED
        data = response.json()
        assert "detail" in data
        assert "gated" in data["detail"].lower()

