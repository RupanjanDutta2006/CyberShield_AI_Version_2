"""CyberShield AI — Part 11: TLS & SSL Certificate Analysis Tests

Tests valid certificates, expired certificates, self-signed certificates,
hostname mismatches, invalid chains, TLS timeouts, and non-crashing failure handling.
"""

import ssl
import socket
import pytest
from unittest.mock import patch, MagicMock

from app.services.tls_analysis.models import TLSStatus, TLSAnalysisResult
from app.services.tls_analysis.service import inspect_tls_certificate, parse_peer_certificate
from app.schemas.url_scan import SSRFValidationResult


class TestTLSAnalysis:
    """Test suite for Part 11 TLS Analysis."""

    def test_valid_tls_certificate(self):
        """Test inspection of a valid, trusted TLS certificate."""
        fake_cert = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Example Org"),)),
            "issuer": ((("commonName", "DigiCert Global Root G2"),), (("organizationName", "DigiCert Inc"),)),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "serialNumber": "1234567890ABCDEF",
            "version": 3,
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

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("example.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.VALID
            assert result.is_valid is True
            assert result.is_trusted is True
            assert result.certificate is not None
            assert result.certificate.san_matches is True
            assert result.certificate.is_expired is False
            assert result.certificate.subject.get("commonName") == "example.com"
            assert result.connection.tls_version == "TLSv1.3"
            assert result.connection.cipher_bits == 256
            # Valid certificate finding present
            valid_findings = [f for f in result.findings if f.check_name == "VALID_TRANSPORT_ENCRYPTION"]
            assert len(valid_findings) == 1

    def test_expired_certificate_handling(self):
        """Test expired certificate verification error produces EXPIRED status and finding."""
        def fake_socket_factory(host, port, ip, timeout):
            mock_ctx = MagicMock()
            err = ssl.SSLCertVerificationError("certificate has expired")
            mock_ctx.wrap_socket.side_effect = err
            return MagicMock(), mock_ctx

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="expired.badssl.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("expired.badssl.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.EXPIRED
            assert result.is_valid is False
            assert result.is_trusted is False
            expired_findings = [f for f in result.findings if f.check_name == "EXPIRED_TLS_CERTIFICATE"]
            assert len(expired_findings) == 1
            assert expired_findings[0].severity == "high"

    def test_self_signed_certificate_handling(self):
        """Test self-signed certificate produces SELF_SIGNED status and finding."""
        def fake_socket_factory(host, port, ip, timeout):
            mock_ctx = MagicMock()
            err = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
            mock_ctx.wrap_socket.side_effect = err
            return MagicMock(), mock_ctx

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="self-signed.badssl.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("self-signed.badssl.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.SELF_SIGNED
            assert result.is_valid is False
            assert result.ca_trust_status == "SELF_SIGNED"
            self_signed_findings = [f for f in result.findings if f.check_name == "SELF_SIGNED_TLS_CERTIFICATE"]
            assert len(self_signed_findings) == 1
            assert self_signed_findings[0].severity == "high"

    def test_hostname_mismatch_handling(self):
        """Test certificate hostname mismatch produces HOSTNAME_MISMATCH status."""
        def fake_socket_factory(host, port, ip, timeout):
            mock_ctx = MagicMock()
            err = ssl.SSLCertVerificationError("hostname 'phish.com' doesn't match 'legit.com'")
            mock_ctx.wrap_socket.side_effect = err
            return MagicMock(), mock_ctx

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="phish.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("phish.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.HOSTNAME_MISMATCH
            assert result.is_valid is False
            mismatch_findings = [f for f in result.findings if f.check_name == "TLS_HOSTNAME_MISMATCH"]
            assert len(mismatch_findings) == 1
            assert mismatch_findings[0].severity == "high"

    def test_untrusted_chain_handling(self):
        """Test untrusted root / incomplete chain produces UNTRUSTED_CHAIN."""
        def fake_socket_factory(host, port, ip, timeout):
            mock_ctx = MagicMock()
            err = ssl.SSLCertVerificationError("unable to get local issuer certificate")
            mock_ctx.wrap_socket.side_effect = err
            return MagicMock(), mock_ctx

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="untrusted-root.badssl.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("untrusted-root.badssl.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.UNTRUSTED_CHAIN
            assert result.is_valid is False

    def test_tls_timeout_handling(self):
        """Test TLS timeout returns TIMEOUT without crashing."""
        def fake_socket_factory(host, port, ip, timeout):
            raise socket.timeout("TLS handshake timed out")

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="slow.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("slow.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.TIMEOUT
            assert result.is_valid is False
            assert len(result.limitations) > 0

    def test_tls_connection_refused_no_crash(self):
        """Test connection failure handled safely without crashing pipeline."""
        def fake_socket_factory(host, port, ip, timeout):
            raise ConnectionRefusedError("Connection refused")

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="no-ssl.com", resolved_ips=["104.16.1.1"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("no-ssl.com", socket_factory=fake_socket_factory)
            assert result.status == TLSStatus.HANDSHAKE_FAILED
            assert result.is_valid is False

    def test_honesty_in_external_checks(self):
        """Test that offline limitations disclose unqueried OCSP/CRL and CT logs."""
        fake_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = fake_cert
        mock_ssock.cipher.return_value = ("AES256-GCM", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.selected_alpn_protocol.return_value = None
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        def fake_socket_factory(host, port, ip, timeout):
            return MagicMock(), mock_ctx

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.tls_analysis.service.validate_destination_safety", return_value=safe_ssrf):
            result = inspect_tls_certificate("example.com", socket_factory=fake_socket_factory)
            assert result.revocation_status == "NOT_CHECKED_OFFLINE_MODE"
            assert result.certificate_transparency == "UNAVAILABLE_EXTERNAL_LOGS_NOT_QUERIED"
            limitation_reasons = [lim.reason for lim in result.limitations]
            assert any("revocation" in r.lower() for r in limitation_reasons)
            assert any("transparency" in r.lower() for r in limitation_reasons)

    def test_legacy_tls_finding_details_conversion(self):
        """Test serialization to legacy TLSFindingDetails."""
        res = TLSAnalysisResult(
            hostname="example.com",
            status=TLSStatus.VALID,
            is_valid=True,
            is_trusted=True,
            ca_trust_status="TRUSTED_CA"
        )
        legacy = res.to_tls_finding_details()
        assert legacy.hostname == "example.com"
        assert legacy.ca_trust_status == "trusted_ca"
        assert legacy.certificate_transparency_present is None

    # =========================================================================
    # Finding F-02 Regression Tests: Validation of Supplied pinned_ip
    # =========================================================================

    def test_supplied_pinned_ip_private_rejected_without_socket_creation(self):
        """F-02 Regression: Private pinned IP is rejected and socket is never created."""
        socket_spy = MagicMock()
        res = inspect_tls_certificate(
            hostname="example.com",
            pinned_ip="192.168.1.100",
            socket_factory=socket_spy
        )
        assert res.status == TLSStatus.SSRF_BLOCKED
        assert res.is_valid is False
        assert "prohibited" in res.verification_error.lower()
        # Socket factory must NEVER be called
        socket_spy.assert_not_called()
        ssrf_findings = [f for f in res.findings if f.check_name == "SSRF_DESTINATION_BLOCKED_IN_TLS"]
        assert len(ssrf_findings) == 1
        assert ssrf_findings[0].severity == "critical"

    def test_supplied_pinned_ip_loopback_rejected_without_socket_creation(self):
        """F-02 Regression: Loopback pinned IP (127.0.0.1) is blocked before connection."""
        socket_spy = MagicMock()
        res = inspect_tls_certificate(
            hostname="example.com",
            pinned_ip="127.0.0.1",
            socket_factory=socket_spy
        )
        assert res.status == TLSStatus.SSRF_BLOCKED
        assert res.is_valid is False
        assert "prohibited" in res.verification_error.lower()
        socket_spy.assert_not_called()

    def test_supplied_pinned_ip_metadata_rejected_without_socket_creation(self):
        """F-02 Regression: Cloud metadata IP (169.254.169.254) is blocked before connection."""
        socket_spy = MagicMock()
        res = inspect_tls_certificate(
            hostname="example.com",
            pinned_ip="169.254.169.254",
            socket_factory=socket_spy
        )
        assert res.status == TLSStatus.SSRF_BLOCKED
        assert res.is_valid is False
        assert "prohibited" in res.verification_error.lower()
        socket_spy.assert_not_called()

    def test_supplied_pinned_ip_public_allowed_and_reaches_socket_creation(self):
        """F-02 Regression: Public pinned IP is allowed and passes through to socket creation."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.selected_alpn_protocol.return_value = None
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.__exit__.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        socket_spy = MagicMock(return_value=(MagicMock(), mock_ctx))

        res = inspect_tls_certificate(
            hostname="example.com",
            pinned_ip="93.184.215.14",
            socket_factory=socket_spy
        )
        assert res.status == TLSStatus.VALID
        assert res.is_valid is True
        # Socket factory was reached with public IP
        socket_spy.assert_called_once()
        assert socket_spy.call_args[0][2] == "93.184.215.14"

    def test_supplied_pinned_ip_unparseable_rejected(self):
        """F-02 Regression: Unparseable pinned IP string is rejected safely."""
        socket_spy = MagicMock()
        res = inspect_tls_certificate(
            hostname="example.com",
            pinned_ip="not-an-ip-address",
            socket_factory=socket_spy
        )
        assert res.status == TLSStatus.SSRF_BLOCKED
        assert "unparseable" in res.verification_error.lower()
        socket_spy.assert_not_called()


