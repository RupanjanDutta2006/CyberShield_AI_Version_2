"""CyberShield AI — Part 12: HTTP Security Headers Analysis Tests

Tests evaluation of HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
missing headers, weak configurations, malformed values, server banner disclosures,
and serialization compatibility.
"""

import pytest
from unittest.mock import patch
import httpx

from app.services.security_headers.models import (
    HeaderEvaluationStatus,
    SecurityHeaderAnalysisResult,
)
from app.services.security_headers.service import (
    analyze_security_headers_from_dict,
    fetch_and_analyze_security_headers,
)


class TestSecurityHeaders:
    """Test suite for Part 12 HTTP Security Headers."""

    def test_all_robust_security_headers(self):
        """Test ideal security header configuration."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://trusted.cdn.com",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Server": "Cloudflare",
        }
        res = analyze_security_headers_from_dict(headers, url="https://example.com", status_code=200)
        assert res.is_reachable is True
        assert res.hsts.status == HeaderEvaluationStatus.VALID
        assert res.csp.status == HeaderEvaluationStatus.VALID
        assert res.x_content_type_options.status == HeaderEvaluationStatus.VALID
        assert res.x_frame_options.status == HeaderEvaluationStatus.VALID
        assert res.referrer_policy.status == HeaderEvaluationStatus.VALID
        assert res.server_banner == "Server: Cloudflare"
        # Zero findings since everything is robust
        assert len(res.findings) == 0

    def test_missing_security_headers(self):
        """Test identification of missing security headers on HTTPS."""
        headers = {
            "Content-Type": "text/html",
        }
        res = analyze_security_headers_from_dict(headers, url="https://insecure-site.com", status_code=200)
        assert res.hsts.status == HeaderEvaluationStatus.MISSING
        assert res.csp.status == HeaderEvaluationStatus.MISSING
        assert res.x_content_type_options.status == HeaderEvaluationStatus.MISSING
        assert res.x_frame_options.status == HeaderEvaluationStatus.MISSING
        assert res.referrer_policy.status == HeaderEvaluationStatus.MISSING

        check_names = [f.check_name for f in res.findings]
        assert "MISSING_HSTS_HEADER" in check_names
        assert "MISSING_CSP_HEADER" in check_names
        assert "MISSING_X_CONTENT_TYPE_OPTIONS" in check_names
        assert "MISSING_X_FRAME_OPTIONS" in check_names

    def test_weak_and_malformed_hsts(self):
        """Test weak duration and malformed HSTS headers."""
        # Weak max-age (1000 seconds < 10886400)
        res_weak = analyze_security_headers_from_dict(
            {"Strict-Transport-Security": "max-age=1000"},
            url="https://example.com"
        )
        assert res_weak.hsts.status == HeaderEvaluationStatus.WEAK
        assert any(f.check_name == "WEAK_HSTS_MAX_AGE" for f in res_weak.findings)

        # Malformed max-age
        res_malformed = analyze_security_headers_from_dict(
            {"Strict-Transport-Security": "includeSubDomains"},
            url="https://example.com"
        )
        assert res_malformed.hsts.status == HeaderEvaluationStatus.MALFORMED
        assert any(f.check_name == "MALFORMED_HSTS_HEADER" for f in res_malformed.findings)

    def test_weak_csp_unsafe_directives(self):
        """Test detection of unsafe-inline and unsafe-eval in CSP."""
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        }
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        assert res.csp.status == HeaderEvaluationStatus.WEAK
        csp_findings = [f for f in res.findings if f.check_name == "WEAK_CSP_CONFIGURATION"]
        assert len(csp_findings) == 1
        assert "'unsafe-inline'" in csp_findings[0].evidence["weak_directives"]

    def test_malformed_x_content_type_options(self):
        """Test non-standard X-Content-Type-Options value."""
        headers = {"X-Content-Type-Options": "sniff"}
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        assert res.x_content_type_options.status == HeaderEvaluationStatus.MALFORMED
        assert any(f.check_name == "MALFORMED_X_CONTENT_TYPE_OPTIONS" for f in res.findings)

    def test_deprecated_x_frame_options(self):
        """Test deprecated X-Frame-Options value (ALLOW-FROM)."""
        headers = {"X-Frame-Options": "ALLOW-FROM https://partner.com"}
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        assert res.x_frame_options.status == HeaderEvaluationStatus.WEAK
        assert any(f.check_name == "WEAK_X_FRAME_OPTIONS" for f in res.findings)

    def test_insecure_referrer_policy(self):
        """Test detection of unsafe-url in Referrer-Policy."""
        headers = {"Referrer-Policy": "unsafe-url"}
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        assert res.referrer_policy.status == HeaderEvaluationStatus.WEAK
        assert any(f.check_name == "INSECURE_REFERRER_POLICY" for f in res.findings)

    def test_verbose_server_banner_disclosure(self):
        """Test detection of granular software version numbers in Server header."""
        headers = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        assert res.server_banner == "Server: Apache/2.4.41 (Ubuntu); X-Powered-By: PHP/7.4.3"
        banner_findings = [f for f in res.findings if f.check_name == "VERBOSE_SERVER_BANNER_DISCLOSED"]
        assert len(banner_findings) == 1

    def test_unreachable_endpoint_handling(self):
        """Test unreachable target returns UNAVAILABLE without crashing."""
        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(httpx.ConnectError("Connection refused"))
            )
            return httpx.Client(transport=mock_transport)

        res = fetch_and_analyze_security_headers(
            "https://unreachable-endpoint.com",
            pinned_ip="198.51.100.20",
            client_factory=fake_client_factory
        )
        assert res.is_reachable is False
        assert res.hsts.status == HeaderEvaluationStatus.UNAVAILABLE
        assert len(res.limitations) > 0

    def test_legacy_security_header_finding_details_conversion(self):
        """Test serialization to SecurityHeaderFindingDetails."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        res = analyze_security_headers_from_dict(headers, url="https://example.com")
        legacy = res.to_security_header_finding_details()
        assert legacy.hsts_present is True
        assert legacy.csp_present is True
        assert legacy.x_content_type_options_present is True
        assert legacy.x_frame_options_present is True
        assert len(legacy.missing_recommended_headers) == 0

    def test_security_headers_rejects_unsafe_pinned_ip_before_network_access(self):
        """Batch 3 Finalization: Security headers service rejects unsafe/malformed pinned IPs."""
        unsafe_ips = ["127.0.0.1", "169.254.169.254", "192.168.1.1", "10.0.0.1", "invalid_ip"]
        for bad_ip in unsafe_ips:
            res = fetch_and_analyze_security_headers(
                "https://secure-target.com",
                pinned_ip=bad_ip
            )
            assert res.is_reachable is False
            assert res.hsts.status == HeaderEvaluationStatus.UNAVAILABLE
            assert len(res.limitations) > 0
            assert "Prohibited pinned IP" in res.limitations[0].reason

    def test_security_headers_uses_pinned_transport_and_preserves_sni_and_host(self):
        """Batch 3 Finalization: Security headers service uses PinnedHTTPTransport directly."""
        from unittest.mock import MagicMock
        import httpcore
        mock_core_resp = MagicMock(spec=httpcore.Response)
        mock_core_resp.status = 200
        mock_core_resp.headers = [
            (b"strict-transport-security", b"max-age=31536000"),
            (b"x-content-type-options", b"nosniff")
        ]
        mock_core_resp.stream = (c for c in [b"body"])

        with patch("httpcore.ConnectionPool.handle_request", return_value=mock_core_resp) as mock_handle:
            res = fetch_and_analyze_security_headers(
                "https://headers.example.com",
                pinned_ip="93.184.215.14"
            )
            assert res.is_reachable is True
            assert res.hsts.status == HeaderEvaluationStatus.VALID
            assert res.x_content_type_options.status == HeaderEvaluationStatus.VALID
            mock_handle.assert_called_once()
            core_req = mock_handle.call_args[0][0]
            assert core_req.url.host == b"headers.example.com"
            assert dict(core_req.headers).get(b"Host") == b"headers.example.com" or dict(core_req.headers).get(b"host") == b"headers.example.com"

