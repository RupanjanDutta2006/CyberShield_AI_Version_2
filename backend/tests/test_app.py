"""CyberShield AI — Application Foundation & Routing Tests

Tests OpenAPI documentation generation, error handling structure,
Early Security Gate enforcement (501 on gated scan endpoint),
and 422 input validation.
"""

from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_openapi_json_generation():
    """Verify OpenAPI JSON specification is generated correctly."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert data["info"]["title"] == "CyberShield AI API"
    assert data["info"]["version"] == "1.0.0"
    assert "/health" in data["paths"]
    assert "/api/v1/health" in data["paths"]
    assert "/api/v1/scan-url" in data["paths"]
    assert "/api/v1/analyze-message" in data["paths"]
    assert "/api/v1/scans/{scan_id}" in data["paths"]
    assert "/api/v1/history" in data["paths"]
    assert "/api/v1/reports" in data["paths"]
    assert "/api/v1/reports/register" in data["paths"]
    assert "/api/v1/reports/verify" in data["paths"]


def test_swagger_and_redoc_ui():
    """Verify interactive documentation endpoints are accessible."""
    docs_res = client.get("/docs")
    assert docs_res.status_code == 200

    redoc_res = client.get("/redoc")
    assert redoc_res.status_code == 200


def test_early_security_gate_scan_url_disabled():
    """Verify Early Security Gate rule: live outbound scanning is disabled in Batch 1.
    Must return 501 Not Implemented with explicit rationale.
    """
    response = client.post(
        "/api/v1/scan-url",
        json={"url": "https://example.com/test", "force_refresh": False}
    )
    assert response.status_code == 501
    data = response.json()
    assert data["error"] == "HTTPException"
    assert data["status_code"] == 501
    assert "disabled under Security Gate rules" in data["detail"]
    assert "preflight" in data["detail"]


def test_integrated_routes_operational():
    """Verify Batch 5 integrated routes are functional, return structured responses, and handle errors."""
    # Analyze message endpoint returns 200 OK with structured response
    res_msg = client.post(
        "/api/v1/analyze-message",
        json={"message_text": "Sample test phishing message content with login link"}
    )
    assert res_msg.status_code == 200
    assert "category" in res_msg.json()
    assert "risk_level" in res_msg.json()

    auth_headers = {"X-API-Key": "cybershield-auth-key-2026"}

    # Scan lookup returns 404 for unknown report ID
    res_scan = client.get("/api/v1/scans/dummy-scan-id", headers=auth_headers)
    assert res_scan.status_code == 404

    # History returns 200 OK with paginated structure
    res_hist = client.get("/api/v1/history", headers=auth_headers)
    assert res_hist.status_code == 200
    assert "total" in res_hist.json()
    assert "items" in res_hist.json()

    # Registration returns 404 for nonexistent report
    res_reg = client.post(
        "/api/v1/reports/register",
        json={"report_id": "dummy-id"},
        headers=auth_headers,
    )
    assert res_reg.status_code == 404

    # Verification returns 200 with not_found status for unknown ID
    res_ver = client.post(
        "/api/v1/reports/verify",
        json={"report_id": "dummy-id"}
    )
    assert res_ver.status_code == 200
    assert res_ver.json()["is_valid"] is False
    assert res_ver.json()["verification_status"] == "not_found"


def test_validation_error_structured_format():
    """Verify 422 validation errors conform to structured error format."""
    # Sending empty body to /api/v1/scan-url triggers RequestValidationError
    response = client.post("/api/v1/scan-url", json={})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "ValidationError"
    assert data["status_code"] == 422
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert "timestamp" in data
    assert "path" in data


def test_not_found_endpoint():
    """Verify standard 404 structured response."""
    response = client.get("/api/v1/non-existent-route")
    assert response.status_code == 404
    data = response.json()
    assert data["error"] == "HTTPException"
    assert data["status_code"] == 404
    assert data["path"] == "/api/v1/non-existent-route"


def test_unhandled_exception_sanitization():
    """Verify unhandled exceptions return sanitized 500 JSON with error_id and zero secret leaks."""
    def error_endpoint():
        raise RuntimeError("Secret leaked token: sk-live-SECRET12345 in db://user:pass@host/db")

    app.add_api_route("/test-unhandled-error", error_endpoint)

    client_no_raise = TestClient(app, raise_server_exceptions=False)
    response = client_no_raise.get("/test-unhandled-error")
    assert response.status_code == 500
    data = response.json()
    assert data["error"] == "InternalServerError"
    assert data["status_code"] == 500
    assert "error_id" in data
    assert len(data["error_id"]) == 12
    # Ensure raw exception message containing secret is never leaked
    assert "SECRET12345" not in response.text
    assert "db://" not in response.text
    assert "An internal server error occurred" in data["detail"]


def test_http_exception_detail_sanitization():
    """Verify HTTPException details containing sensitive data are sanitized (F-04)."""
    from fastapi import HTTPException

    def sensitive_500_endpoint():
        raise HTTPException(
            status_code=500,
            detail="Database connection failure: postgres://admin:SECRET_PASS_999@internal.db:5432/core"
        )

    def sensitive_400_endpoint():
        raise HTTPException(
            status_code=400,
            detail="Malformed request query: api_key=SECRET_API_KEY_777 is expired"
        )

    app.add_api_route("/test-sensitive-500", sensitive_500_endpoint)
    app.add_api_route("/test-sensitive-400", sensitive_400_endpoint)

    client_no_raise = TestClient(app, raise_server_exceptions=False)

    # Test 500 HTTPException masking
    res_500 = client_no_raise.get("/test-sensitive-500")
    assert res_500.status_code == 500
    data_500 = res_500.json()
    assert "SECRET_PASS_999" not in res_500.text
    assert "postgres://" not in res_500.text
    assert "error_id" in data_500
    assert "An internal server error occurred" in data_500["detail"]

    # Test 400 HTTPException sensitive string sanitization
    res_400 = client_no_raise.get("/test-sensitive-400")
    assert res_400.status_code == 400
    data_400 = res_400.json()
    assert "SECRET_API_KEY_777" not in res_400.text
    assert data_400["detail"] == "Invalid request or parameter."
    assert "error_id" in data_400
