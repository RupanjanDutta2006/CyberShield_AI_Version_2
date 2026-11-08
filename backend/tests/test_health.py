"""CyberShield AI — Health Check Endpoint Tests

Verifies that root and versioned health checks respond with 200 OK,
valid timestamp, and required schema attributes without external dependencies.
"""

from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_health_endpoint():
    """Verify GET /health returns 200 OK with correct status payload."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "CyberShield AI API"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data


def test_api_v1_health_endpoint():
    """Verify GET /api/v1/health returns 200 OK with identical healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "CyberShield AI API"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data

