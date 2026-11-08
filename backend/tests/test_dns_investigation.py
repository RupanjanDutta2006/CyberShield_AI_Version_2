"""CyberShield AI — Part 09: DNS & Domain Investigation Tests

Tests A, AAAA, CNAME, MX, and NS record handling, NXDOMAIN, Timeout, SERVFAIL,
Empty Answer, SSRF revalidation on resolved addresses, and serialization.
Deterministic unit tests using mocked socket functions.
"""

import socket
import pytest
from unittest.mock import patch, MagicMock

from app.services.dns.models import DNSStatus, DNSInvestigationResult
from app.services.dns.service import (
    investigate_dns,
    extract_clean_domain,
    resolve_a_and_aaaa_records,
)


class TestDNSInvestigation:
    """Test suite for Part 09 DNS Investigation."""

    def test_domain_sanitization(self):
        """Test clean domain extraction from full URLs and targets."""
        assert extract_clean_domain("https://example.com/login?token=secret") == "example.com"
        assert extract_clean_domain("http://sub.domain.org:8080/path") == "sub.domain.org"
        assert extract_clean_domain("example.com.") == "example.com"
        assert extract_clean_domain("  api.test.co.uk  ") == "api.test.co.uk"

    def test_a_and_aaaa_records_success(self):
        """Test successful A and AAAA record resolution."""
        mock_v4 = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "canon.example.com", ("93.184.215.14", 0))
        ]
        mock_v6 = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0))
        ]

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET:
                return mock_v4
            elif family == socket.AF_INET6:
                return mock_v6
            return []

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo), \
             patch("app.services.dns.service.query_dns_record_type", return_value=(["10 mail.example.com"], None, None)):
            res = investigate_dns("example.com", query_auxiliary_records=True)
            assert res.status == DNSStatus.SUCCESS
            assert res.is_destination_safe is True
            assert "93.184.215.14" in res.a_records
            assert "2606:2800:220:1:248:1893:25c8:1946" in res.aaaa_records
            assert "canon.example.com" in res.cname_records
            assert len(res.mx_records) > 0

    def test_cname_and_ns_handling(self):
        """Test CNAME resolution and NS query parsing."""
        mock_v4 = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "cdn.provider.net", ("104.16.1.1", 0))
        ]

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET:
                return mock_v4
            return []

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo), \
             patch("app.services.dns.service.query_dns_record_type", side_effect=[([], None, None), (["ns1.provider.net", "ns2.provider.net"], None, None)]):
            res = investigate_dns("blog.example.com")
            assert res.status == DNSStatus.SUCCESS
            assert "cdn.provider.net" in res.cname_records
            assert "ns1.provider.net" in res.ns_records

    def test_nxdomain_handling(self):
        """Test NXDOMAIN error classification."""
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            raise socket.gaierror(11001, "getaddrinfo failed: Name or service not known")

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            res = investigate_dns("nonexistent-domain-xyz123.com")
            assert res.status == DNSStatus.NXDOMAIN
            assert len(res.all_resolved_ips) == 0
            assert len(res.limitations) > 0
            assert res.is_destination_safe is True  # No unsafe IP reached

    def test_dns_timeout_handling(self):
        """Test DNS timeout classification."""
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            raise socket.timeout("timed out")

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            res = investigate_dns("slow-resolving-domain.org", timeout_seconds=0.5)
            assert res.status == DNSStatus.TIMEOUT
            assert "timed out" in res.notes.lower()
            assert len(res.limitations) > 0

    def test_servfail_handling(self):
        """Test DNS SERVFAIL classification."""
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            raise socket.gaierror(11002, "Temporary failure in name resolution")

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            res = investigate_dns("broken-nameserver.com")
            assert res.status == DNSStatus.SERVFAIL
            assert "servfail" in res.notes.lower()

    def test_empty_dns_answers(self):
        """Test handling of domain with empty address answers."""
        with patch("socket.getaddrinfo", return_value=[]):
            res = investigate_dns("empty-answer.com")
            assert res.status == DNSStatus.EMPTY_ANSWER
            assert len(res.all_resolved_ips) == 0

    def test_ssrf_mixed_public_and_private_answers_fails_closed(self):
        """Test that mixed public and private IPs fail closed with SSRF_BLOCKED."""
        mock_v4 = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),  # Private/Loopback!
        ]

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET:
                return mock_v4
            return []

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            res = investigate_dns("malicious-rebinding-target.com", query_auxiliary_records=False)
            assert res.status == DNSStatus.SSRF_BLOCKED
            assert res.is_destination_safe is False
            assert "prohibited" in res.blocked_reason.lower()
            # Must generate an SSRF technical finding
            ssrf_findings = [f for f in res.findings if f.check_name == "SSRF_PROHIBITED_DNS_DESTINATION"]
            assert len(ssrf_findings) == 1
            assert ssrf_findings[0].severity == "high"

    def test_dns_result_serialization_compatibility(self):
        """Test serialization to DNSFindingDetails for unified threat reports."""
        res = DNSInvestigationResult(
            domain="example.com",
            status=DNSStatus.SUCCESS,
            a_records=["93.184.215.14"],
            aaaa_records=["2606:2800:220:1:248:1893:25c8:1946"],
            all_resolved_ips=["93.184.215.14", "2606:2800:220:1:248:1893:25c8:1946"],
            mx_records=["10 mail.example.com"],
            ns_records=["ns1.example.com", "ns2.example.com"]
        )
        legacy = res.to_dns_finding_details()
        assert legacy.domain == "example.com"
        assert legacy.has_valid_dns is True
        assert legacy.a_records == ["93.184.215.14"]
        assert legacy.mx_records == ["10 mail.example.com"]

    def test_null_mx_record_rfc7505_canonical_serialization(self):
        """Batch 3 Finalization: RFC 7505 Null MX record serializes canonically as '0 .'."""
        import struct
        from app.services.dns.service import query_dns_record_type

        # Build mock DNS response with Null MX: header + question + answer (pref=0, target=\x00)
        # Header (12 bytes): tx_id=1, flags=0x8180 (std response, no error), qdcount=1, ancount=1, nscount=0, arcount=0
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        # Question: \x07example\x03com\x00, qtype=15, qclass=1
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 15, 1)
        # Answer: compression pointer \xc0\x0c -> rtype=15, rclass=1, ttl=300, rdlength=3
        # RDATA: pref=0 (2 bytes: \x00\x00), target=\x00 (root domain)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 300, 3) + struct.pack("!H", 0) + b"\x00"
        packet = header + question + answer

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__.return_value = mock_sock
            mock_sock.recvfrom.return_value = (packet, ("8.8.8.8", 53))
            mock_sock_cls.return_value = mock_sock

            records, status, err = query_dns_record_type("example.com", 15)
            assert status is None
            assert err is None
            assert records == ["0 ."]

