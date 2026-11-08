"""CyberShield AI — Part 07: IP & Hostname Security Validation (SSRF Protection) Unit Tests

Tests detection and blocking of loopback, RFC1918 private, link-local, cloud metadata,
multicast, reserved ranges, mapped IPv6, unusual IP encodings, internal hostnames,
and safe DNS resolution with fail-closed behavior on mixed or failed records.
"""

from unittest.mock import patch
import socket
import pytest

from app.services.url_investigation.ssrf_guard import (
    validate_destination_safety,
    evaluate_ip_safety,
    parse_ip_safely,
)


class TestSSRFGuard:
    """Test suite for Part 07 SSRF Guard and IP/Hostname Validation."""

    def test_public_ip_addresses_allowed(self):
        """Test legitimate public IPs pass validation."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ]
        for ip in public_ips:
            res = validate_destination_safety(ip)
            assert res.is_safe is True, f"Expected {ip} to be safe, got: {res.blocked_reason}"
            assert res.target_type == "ip"

    def test_loopback_ips_blocked(self):
        """Test loopback IPv4 and IPv6 addresses are blocked."""
        loopbacks = [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",       # IPv4-mapped IPv6 loopback
            "::ffff:7f00:1",          # Hex notation mapped loopback
            "2130706433",             # Decimal integer for 127.0.0.1
            "0177.0.0.1",             # Octal format
            "0x7f.0.0.1",             # Hex format
        ]
        for ip in loopbacks:
            res = validate_destination_safety(ip)
            assert res.is_safe is False, f"Expected {ip} to be blocked"
            assert res.is_loopback is True or "loopback" in (res.blocked_reason or "").lower()

    def test_private_rfc1918_ips_blocked(self):
        """Test private RFC 1918 IPv4 and ULA IPv6 are blocked."""
        private_ips = [
            "10.0.0.1",
            "10.254.1.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.1.254",
            "fc00::1",
            "fd12:3456:789a::1",
            "::ffff:10.0.0.1",        # IPv4-mapped private
            "::ffff:192.168.1.1",     # IPv4-mapped private
        ]
        for ip in private_ips:
            res = validate_destination_safety(ip)
            assert res.is_safe is False, f"Expected {ip} to be blocked"
            assert res.is_private is True or "private" in (res.blocked_reason or "").lower()

    def test_link_local_and_cloud_metadata_blocked(self):
        """Test link-local and cloud provider metadata addresses are blocked."""
        metadata_targets = [
            "169.254.169.254",        # AWS, GCP, Azure metadata
            "169.254.0.1",            # Oracle Cloud metadata
            "100.100.100.200",        # Alibaba metadata
            "169.254.10.20",          # Link-local
            "fe80::1",                # IPv6 link-local
            "::ffff:169.254.169.254", # Mapped metadata
        ]
        for ip in metadata_targets:
            res = validate_destination_safety(ip)
            assert res.is_safe is False, f"Expected {ip} to be blocked"
            assert res.is_link_local is True or res.is_metadata_endpoint is True

    def test_reserved_multicast_and_special_networks_blocked(self):
        """Test multicast, carrier-grade NAT, documentation, and unspecified IPs."""
        special_ips = [
            "0.0.0.0",                # Unspecified
            "::",                     # IPv6 unspecified
            "224.0.0.1",              # Multicast
            "ff02::1",                # IPv6 multicast
            "240.0.0.1",              # Reserved class E
            "100.64.0.1",             # Carrier-Grade NAT (RFC 6598)
            "192.0.2.1",              # RFC 5737 TEST-NET-1
            "198.51.100.1",           # RFC 5737 TEST-NET-2
            "203.0.113.1",            # RFC 5737 TEST-NET-3
            "2001:db8::1",            # RFC 3849 IPv6 documentation
        ]
        for ip in special_ips:
            res = validate_destination_safety(ip)
            assert res.is_safe is False, f"Expected special IP {ip} to be blocked"

    def test_internal_hostnames_and_metadata_names_blocked(self):
        """Test localhost, internal TLDs, and cloud metadata hostnames."""
        prohibited_hosts = [
            "localhost",
            "api.localhost",
            "db.local",
            "cluster.internal",
            "router.lan",
            "controller.corp",
            "auth.intranet",
            "nas.home",
            "metadata.google.internal",
            "instance-data",
            "metadata.azure.com",
        ]
        for host in prohibited_hosts:
            res = validate_destination_safety(host)
            assert res.is_safe is False, f"Expected host {host} to be blocked"

    def test_dns_resolution_safe_host(self):
        """Test safe public hostname resolution."""
        with patch("app.services.url_investigation.ssrf_guard.resolve_hostname_all_ips") as mock_dns:
            mock_dns.return_value = (["93.184.216.34"], None)
            res = validate_destination_safety("example.com", resolve_dns=True)
            assert res.is_safe is True
            assert res.resolved_ips == ["93.184.216.34"]

    def test_dns_resolution_mixed_answers_fails_closed(self):
        """Test DNS response with mixed public and private IPs fails closed."""
        with patch("app.services.url_investigation.ssrf_guard.resolve_hostname_all_ips") as mock_dns:
            # 1 public IP, 1 private RFC1918 IP (classic DNS rebinding / dual-homed target)
            mock_dns.return_value = (["93.184.216.34", "10.0.0.5"], None)
            res = validate_destination_safety("dual-homed.evil.com", resolve_dns=True)
            assert res.is_safe is False
            assert "prohibited destination" in (res.blocked_reason or "").lower()
            assert res.is_private is True

    def test_dns_resolution_failure_fails_closed(self):
        """Test DNS resolution failure fails closed (never assumed safe)."""
        with patch("app.services.url_investigation.ssrf_guard.resolve_hostname_all_ips") as mock_dns:
            mock_dns.return_value = ([], "DNS resolution failed (gaierror): Name or service not known")
            res = validate_destination_safety("nonexistent-domain-xyz.test", resolve_dns=True)
            assert res.is_safe is False
            assert "failed" in (res.blocked_reason or "").lower()

    def test_dns_resolution_timeout_fails_closed(self):
        """Test DNS resolution timeout fails closed."""
        with patch("app.services.url_investigation.ssrf_guard.resolve_hostname_all_ips") as mock_dns:
            mock_dns.return_value = ([], "DNS resolution timed out after 2.0s")
            res = validate_destination_safety("slow-dns.test", resolve_dns=True)
            assert res.is_safe is False
            assert "timed out" in (res.blocked_reason or "").lower()

