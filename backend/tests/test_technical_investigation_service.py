"""CyberShield AI — Technical Investigation Service & Endpoints Tests

Tests the coordinated technical website investigation pipeline (Parts 09–12)
and API endpoints exposed on /api/v1/investigate/*.
"""

import pytest
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient
from fastapi import status
import httpx

from app.main import app
from app.services.dns.models import DNSStatus
from app.schemas.url_scan import SSRFValidationResult
from app.services.redirects.models import RedirectAnalysisResult, RedirectHopRecord
from app.services.technical_investigation import investigate_technical_website


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app, raise_server_exceptions=False)


class TestTechnicalInvestigationPipeline:
    """Test suite for integrated Stage 3 Technical Website Investigation."""

    def test_full_technical_pipeline_success(self):
        """Test coordinated execution of DNS, redirects, TLS, and headers on valid target."""
        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        fake_resp = httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Server": "TestServer",
            }
        )

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(lambda req: fake_resp)
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        fake_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert Root"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = fake_cert
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.selected_alpn_protocol.return_value = "h2"
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        def fake_socket_factory(host, port, ip, timeout):
            return MagicMock(), mock_ctx

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("socket.getaddrinfo", return_value=[(2, 1, 6, "example.com", ("93.184.215.14", 0))]), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "https://example.com/login",
                client_factory=fake_client_factory,
                socket_factory=fake_socket_factory
            )
            assert result.status == "completed"
            assert result.dns is not None
            assert result.redirects is not None
            assert result.tls is not None
            assert result.headers is not None
            assert result.headers.hsts.status == "VALID"

            # Check legacy summary conversion
            summary = result.to_technical_findings_summary()
            assert summary.dns is not None
            assert summary.dns.has_valid_dns is True
            assert summary.tls is not None
            assert summary.headers is not None
            assert summary.headers.hsts_present is True

    def test_pipeline_aborts_on_ssrf_prohibited_destination(self):
        """Test technical investigation stops when target is prohibited by SSRF guard."""
        unsafe_ssrf = SSRFValidationResult(
            is_safe=False,
            hostname_or_ip="127.0.0.1",
            blocked_reason="Prohibited loopback destination",
            is_loopback=True
        )

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=unsafe_ssrf):
            result = investigate_technical_website("http://127.0.0.1:8000/internal")
            assert result.status == "failed"
            assert result.dns is None
            assert result.redirects is None
            assert len(result.all_limitations) == 1
            assert "SSRF guard" in result.all_limitations[0].reason

    def test_api_investigate_dns_endpoint(self, client: TestClient):
        """Test POST /api/v1/investigate/dns."""
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 0))]), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):
            resp = client.post("/api/v1/investigate/dns", json={"url": "https://example.com"})
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            assert data["domain"] == "example.com"
            assert data["status"] == "SUCCESS"
            assert "93.184.215.14" in data["a_records"]

    def test_api_investigate_technical_endpoint_ssrf_protection(self, client: TestClient):
        """Test POST /api/v1/investigate/technical with loopback target fails safely."""
        resp = client.post("/api/v1/investigate/technical", json={"url": "http://127.0.0.1:8000"})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["status"] == "failed"
        assert any("SSRF guard" in lim["reason"] for lim in data["all_limitations"])

    def test_scan_url_remains_gated_501(self, client: TestClient):
        """Verify that /api/v1/scan-url remains strictly gated with HTTP 501."""
        resp = client.post("/api/v1/scan-url", json={"url": "https://example.com"})
        assert resp.status_code == status.HTTP_501_NOT_IMPLEMENTED
        assert "disabled under Security Gate rules" in resp.json()["detail"]

    # =========================================================================
    # Finding F-01 Regression Tests: Final Hop Validated IP for TLS Inspection
    # =========================================================================

    def test_f01_redirect_to_new_hostname_passes_final_hop_ip_to_tls(self):
        """F-01 Regression: TLS inspection receives the final hop's IP, not initial IP."""
        initial_ip = "93.184.215.14"
        final_ip = "104.26.11.228"

        mock_responses = {
            "https://start.com/": httpx.Response(301, headers={"Location": "https://finish.com/"}),
            "https://finish.com/": httpx.Response(200, headers={"Content-Type": "text/html"}),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(lambda req: mock_responses[str(req.url)])
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        def fake_destination_safety(hostname_or_ip, port=None, resolve_dns=True, dns_timeout=2.0):
            if "finish" in hostname_or_ip:
                return SSRFValidationResult(is_safe=True, hostname_or_ip=hostname_or_ip, resolved_ips=[final_ip])
            return SSRFValidationResult(is_safe=True, hostname_or_ip=hostname_or_ip, resolved_ips=[initial_ip])

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "finish.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "finish.com"),),
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.selected_alpn_protocol.return_value = None
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        socket_spy = MagicMock(return_value=(MagicMock(), mock_ctx))

        with patch("app.services.technical_investigation.validate_destination_safety", side_effect=fake_destination_safety), \
             patch("app.services.redirects.service.validate_destination_safety", side_effect=fake_destination_safety), \
             patch("app.services.dns.service.resolve_a_and_aaaa_records", return_value=([initial_ip], [], [], "SUCCESS", None)), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "https://start.com",
                client_factory=fake_client_factory,
                socket_factory=socket_spy
            )
            assert result.status in ("completed", "partial")
            assert result.redirects.final_url == "https://finish.com/"
            assert result.tls is not None
            assert result.tls.hostname == "finish.com"
            assert result.tls.status == "VALID"
            # Verify socket_spy was called with final_ip ("104.26.11.228"), NEVER initial_ip!
            socket_spy.assert_called_once()
            called_args = socket_spy.call_args[0]
            assert called_args[0] == "finish.com"       # hostname for SNI
            assert called_args[2] == final_ip           # final hop's IP, NOT initial_ip!

    def test_f01_missing_final_hop_ip_does_not_fallback_to_initial_ip(self):
        """F-01 Regression: Missing final-hop IP returns UNAVAILABLE without fallback."""
        initial_ip = "93.184.215.14"

        socket_spy = MagicMock()

        # Real RedirectAnalysisResult with a final hop lacking resolved_ip
        mock_redirect_result = RedirectAnalysisResult(
            initial_url="https://start.com",
            final_url="https://finish.com",
            hop_count=1,
            hops=[
                RedirectHopRecord(
                    hop_number=0,
                    url="https://finish.com",
                    status_code=200,
                    resolved_ip=None,  # Missing final hop IP!
                    is_safe=True
                )
            ],
            destination_ip_safe=True,
            stopped_reason="FINAL_DESTINATION_REACHED"
        )

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="start.com", resolved_ips=[initial_ip])

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.technical_investigation.trace_redirects", return_value=mock_redirect_result), \
             patch("app.services.dns.service.resolve_a_and_aaaa_records", return_value=([initial_ip], [], [], "SUCCESS", None)), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "https://start.com",
                socket_factory=socket_spy
            )
            assert result.tls is not None
            assert result.tls.status == "UNAVAILABLE"
            assert "unavailable" in result.tls.verification_error.lower()
            # Socket factory must NEVER be called with initial_ip!
            socket_spy.assert_not_called()

    def test_f01_redirect_to_unsafe_destination_never_triggers_tls_connection(self):
        """F-01 Regression: Redirect to unsafe destination aborts TLS without connecting."""
        socket_spy = MagicMock()

        mock_redirect_result = RedirectAnalysisResult(
            initial_url="https://start.com",
            final_url="https://192.168.1.1/admin",
            hop_count=1,
            hops=[
                RedirectHopRecord(
                    hop_number=0,
                    url="https://192.168.1.1/admin",
                    status_code=0,
                    resolved_ip="192.168.1.1",
                    is_safe=False,
                    blocked_reason="Prohibited private IP"
                )
            ],
            destination_ip_safe=False,  # SSRF unsafe!
            stopped_reason="SSRF_BLOCKED_HOP"
        )

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="start.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.technical_investigation.trace_redirects", return_value=mock_redirect_result), \
             patch("app.services.dns.service.resolve_a_and_aaaa_records", return_value=(["93.184.215.14"], [], [], "SUCCESS", None)), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "https://start.com",
                socket_factory=socket_spy
            )
            assert result.tls is not None
            assert result.tls.status == "SSRF_BLOCKED"
            # Zero TLS connections attempted
            socket_spy.assert_not_called()

    # =========================================================================
    # Finding B5-F08 Regression Tests: Accurate Status Derivation
    # =========================================================================

    def test_b5_f08_tls_unavailable_yields_partial_status(self):
        """B5-F08 Regression: When TLS analysis fails or is unavailable, status is PARTIAL, not COMPLETED."""
        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        fake_resp = httpx.Response(
            200,
            headers={"Content-Type": "text/html"}
        )

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(lambda req: fake_resp)
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        # Socket factory raises exception simulating TLS connection timeout
        def failing_socket_factory(host, port, ip, timeout):
            raise TimeoutError("Simulated TLS handshake timeout")

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("socket.getaddrinfo", return_value=[(2, 1, 6, "example.com", ("93.184.215.14", 0))]), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "https://example.com/tls-fail",
                client_factory=fake_client_factory,
                socket_factory=failing_socket_factory
            )
            # Status must be PARTIAL because TLS failed
            assert result.status == "partial"
            assert result.tls is not None
            assert result.tls.status in ("TIMEOUT", "HANDSHAKE_FAILED", "UNAVAILABLE")

    def test_b5_f08_redirect_failure_yields_partial_status(self):
        """B5-F08 Regression: When redirect tracing encounters connection errors, status is PARTIAL."""
        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        def failing_client_factory(pinned_ip: str):
            def handler(req):
                raise httpx.ConnectTimeout("Simulated HTTP connection timeout")
            mock_transport = httpx.MockTransport(handler)
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("socket.getaddrinfo", return_value=[(2, 1, 6, "example.com", ("93.184.215.14", 0))]), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "http://example.com/redirect-fail",
                client_factory=failing_client_factory
            )
            assert result.status == "partial"
            assert result.redirects.stopped_reason in ("CONNECT_TIMEOUT", "CONNECTION_FAILED", "REQUEST_ERROR")

    def test_b5_f08_dns_and_redirect_failure_yields_failed_status(self):
        """B5-F08 Regression: When both DNS and redirects fail, overall status is FAILED."""
        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        def failing_client_factory(pinned_ip: str):
            def handler(req):
                raise httpx.ConnectTimeout("Connect failed")
            return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)

        with patch("app.services.technical_investigation.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf), \
             patch("app.services.dns.service.resolve_a_and_aaaa_records", return_value=([], [], [], DNSStatus.TIMEOUT, "DNS timed out")), \
             patch("app.services.dns.service.query_dns_record_type", return_value=([], None, None)):

            result = investigate_technical_website(
                "http://example.com/total-fail",
                client_factory=failing_client_factory
            )
            assert result.status == "failed"



