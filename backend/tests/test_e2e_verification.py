"""End-to-End System Verification for CyberShield AI Master Platform."""

import sys
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_system_status():
    resp = client.get("/api/v1/system/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ["healthy", "degraded"]
    print("\n[OK] System Status:", data["status"], "Database:", data["database_type"])


def test_e2e_indian_electricity_bill_scam():
    content = (
        "URGENT: Your electricity power supply will be disconnected tonight at 9:30 PM "
        "due to unpaid bill of Rs 3,420. Call electricity officer at +91-9876543210 "
        "or visit https://bijli-bill-payment.in to pay immediately."
    )
    resp = client.post("/api/v1/scans/message", json={"content": content})
    assert resp.status_code == 200
    data = resp.json()

    print("\n[OK] Message Scan Results:")
    print("  Engine:", data.get("analysis_engine"))
    print("  Risk Level:", data.get("risk_level"))
    print("  Risk Score:", data.get("risk_score"))
    print("  Summary:", data["report"]["summary"][:80], "...")
    print("  Report Hash:", data["report"]["report_hash"])
    print("  Indicators:", len(data["message_indicators"]))

    assert data["risk_level"] in ["Critical", "High", "Medium"]
    assert len(data["report"]["report_hash"]) == 64

    # Check report verification
    report_id = data["report"]["report_id"]
    v_resp = client.post(f"/api/v1/reports/{report_id}/verify", json={})
    assert v_resp.status_code == 200
    v_data = v_resp.json()
    assert v_data["is_valid"] is True
    print("  Cryptographic Integrity:", v_data["verification_status"], "(Verified: True)")


def test_e2e_member2_direct_endpoint():
    payload = {
        "message": "Congratulations! Selected for part-time Amazon job. Earn Rs 5000 daily on Telegram. Deposit mandatory registration fee of Rs 1500.",
        "message_type": "job_offer"
    }
    resp = client.post("/api/v1/analyze-message", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    print("\n[OK] Member 2 Compatibility Endpoint:")
    print("  Category:", data["category"])
    print("  Risk Level:", data["risk_level"])
    print("  Confidence:", data["confidence"])
    print("  Observed Indicators:", len(data["observed_indicators"]))
    assert data["risk_level"] in ["high_risk", "suspicious"]


if __name__ == "__main__":
    test_system_status()
    test_e2e_indian_electricity_bill_scam()
    test_e2e_member2_direct_endpoint()
    print("\n>>> ALL E2E VERIFICATIONS SUCCEEDED PERFECTLY! <<<")
