"""CyberShield AI — URL & Domain Scanner Audit Regression Suite

Verifies evidence-based threat detection, RFC 2606 synthetic domain handling,
scheme-less domain normalization, provider timeout resiliency, and legitimate
domain verification across all 18 test scenarios from the audit specification.
"""

import unittest.mock as mock
import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestURLScannerAuditScenarios:
    """Complete 18-scenario regression test suite for the URL & Domain Scanner."""

    # -------------------------------------------------------------------------
    # Part 1A: Suspicious Synthetic URLs (RFC 2606 .example)
    # -------------------------------------------------------------------------

    def test_scenario_01_account_suspended_synthetic_url(self):
        """1. http://account-suspended.example/restore -> High/Critical risk, account suspension lure."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://account-suspended.example/restore"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 70
        assert data["risk_score"] != 0, "Synthetic lure must NOT be marked Clean (0/100)"
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "account suspension" in ev or "restore" in ev

    def test_scenario_02_free_prize_claim_synthetic_url(self):
        """2. http://free-prize-claim.example/reward -> High/Critical risk, prize claim lure."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://free-prize-claim.example/reward"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 70
        assert data["risk_score"] != 0, "Synthetic lure must NOT be marked Clean (0/100)"
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "prize" in ev or "reward" in ev

    def test_scenario_03_secure_bank_login_synthetic_url(self):
        """3. http://secure-bank-login.example/verify -> Critical risk, unencrypted banking login & verify."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://secure-bank-login.example/verify"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 80
        assert data["risk_score"] != 25, "Must NOT be weak baseline score 25"
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "bank" in ev or "login" in ev or "verify" in ev

    def test_scenario_04_wallet_security_check_synthetic_url(self):
        """4. http://wallet-security-check.example/login -> Critical risk, unencrypted wallet login."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://wallet-security-check.example/login"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 80
        assert data["risk_score"] != 25, "Must NOT be weak baseline score 25"
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "wallet" in ev or "security" in ev or "login" in ev

    # -------------------------------------------------------------------------
    # Part 1B: Suspicious Synthetic Domains (Domain-only inputs)
    # -------------------------------------------------------------------------

    def test_scenario_05_secure_bank_verify_synthetic_domain(self):
        """5. secure-bank-verify.example -> High risk, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "secure-bank-verify.example"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 65
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "bank" in ev or "verify" in ev or "synthetic" in ev

    def test_scenario_06_parcel_tracking_payment_synthetic_domain(self):
        """6. parcel-tracking-payment.example -> High risk, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "parcel-tracking-payment.example"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 65
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "tracking" in ev or "parcel" in ev or "payment" in ev

    def test_scenario_07_customer_login_verification_synthetic_domain(self):
        """7. customer-login-verification.example -> High risk, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "customer-login-verification.example"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 65
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "login" in ev or "verification" in ev or "customer" in ev

    # -------------------------------------------------------------------------
    # Part 1C: Legitimate Public Domains (Domain-only inputs)
    # -------------------------------------------------------------------------

    def test_scenario_08_google_com_legitimate_domain(self):
        """8. google.com -> Low risk clean, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "google.com"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    def test_scenario_09_microsoft_com_legitimate_domain(self):
        """9. microsoft.com -> Low risk clean, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "microsoft.com"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    def test_scenario_10_wikipedia_org_legitimate_domain(self):
        """10. wikipedia.org -> Low risk clean, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "wikipedia.org"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    def test_scenario_11_iana_org_legitimate_domain(self):
        """11. iana.org -> Low risk clean, must NOT produce Internal Server Error (500)."""
        resp = client.post("/api/v1/scans/url", json={"url": "iana.org"})
        assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    # -------------------------------------------------------------------------
    # Additional Required Scenarios (12 - 18)
    # -------------------------------------------------------------------------

    def test_scenario_12_legitimate_https_url(self):
        """12. Legitimate HTTPS URL -> Low risk."""
        resp = client.post("/api/v1/scans/url", json={"url": "https://example.com/"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    def test_scenario_13_suspicious_raw_ip_url(self):
        """13. Suspicious raw IP URL with non-standard port and admin path -> Critical/High risk."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://185.220.101.5:8080/admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 70
        ev = " ".join(data["report"]["evidence"]).lower()
        assert "raw ip address" in ev

    def test_scenario_14_malformed_url_returns_422(self):
        """14. Malformed URL syntax -> Returns clean HTTP 422 Client Error, never HTTP 500."""
        resp = client.post("/api/v1/scans/url", json={"url": "http://[invalid-url::"})
        assert resp.status_code == 422
        assert "Invalid URL structure" in resp.json().get("detail", "")

    def test_scenario_15_domain_with_no_scheme(self):
        """15. Domain with no scheme (github.com) -> Auto-normalizes and completes cleanly."""
        resp = client.post("/api/v1/scans/url", json={"url": "github.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["normalized_target"] == "https://github.com/"
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20

    def test_scenario_16_dns_resolution_failure(self):
        """16. DNS resolution failure -> Handled gracefully without crash, surfaces failure evidence."""
        resp = client.post("/api/v1/scans/url", json={"url": "https://nonexistent-domain-xyz-123456789.com/"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"

    def test_scenario_17_simulated_threat_intel_timeout(self):
        """17. Simulated provider timeout -> Handled gracefully, marked unavailable, scan completes."""
        with mock.patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Connection timed out")):
            resp = client.post("/api/v1/scans/url", json={"url": "https://public-test-timeout-target.org/"})
            assert resp.status_code == 200
            data = resp.json()
            prov_statuses = [p["status"] for p in data.get("providers_checked", [])]
            assert "unavailable" in prov_statuses

    def test_scenario_18_simulated_missing_api_key(self):
        """18. Simulated missing API key -> Provider marked not_configured, scan completes."""
        with mock.patch("threat_intel.config.threat_config.PHISHTANK_APP_KEY", None):
            resp = client.post("/api/v1/scans/url", json={"url": "https://public-test-key-target.org/"})
            assert resp.status_code == 200
            data = resp.json()
            pt = next((p for p in data.get("providers_checked", []) if p["provider"] == "PhishTank"), None)
            assert pt is not None
            assert pt["status"] == "not_configured"

