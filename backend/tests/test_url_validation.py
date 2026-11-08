"""CyberShield AI — Part 05: URL Input Validation Unit Tests

Tests strict intake validation, scheme whitelisting, authority syntax, port bounds,
embedded credential redaction, control character rejection, and length constraints.
"""

import pytest
from app.services.url_investigation.validation import validate_url_input


class TestURLInputValidation:
    """Test suite for Part 05 URL input validation."""

    def test_valid_http_and_https_urls(self):
        """Test standard well-formed HTTP and HTTPS URLs."""
        valid_samples = [
            "https://example.com",
            "http://example.com/",
            "https://sub.domain.co.uk/path/to/page?param=1&other=test#section",
            "https://secure-bank.org:8443/login",
            "http://192.0.2.1/status",
            "http://[2001:db8::1]:8080/test",
        ]
        for url in valid_samples:
            result = validate_url_input(url)
            assert result.is_valid is True, f"Expected {url} to be valid, got {result.error_message}"
            assert result.parsed_scheme in ("http", "https")
            assert result.parsed_hostname is not None
            assert result.has_credentials is False

    def test_empty_and_whitespace_input(self):
        """Test null, empty, and whitespace strings."""
        assert validate_url_input(None).is_valid is False
        assert validate_url_input("").is_valid is False
        assert validate_url_input("   \t  \n").is_valid is False
        assert validate_url_input("").error_code == "EMPTY_INPUT"

    def test_exceeds_max_length(self):
        """Test URLs exceeding maximum allowed length."""
        long_url = "https://example.com/" + ("a" * 2050)
        result = validate_url_input(long_url, max_length=2048)
        assert result.is_valid is False
        assert result.error_code == "EXCEEDS_MAX_LENGTH"

    def test_missing_scheme(self):
        """Test URLs without scheme are rejected."""
        result = validate_url_input("example.com/login")
        assert result.is_valid is False
        assert result.error_code == "MISSING_SCHEME"

    def test_unsupported_schemes(self):
        """Test dangerous and unsupported schemes."""
        prohibited = [
            "ftp://files.example.com",
            "file:///etc/passwd",
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "gopher://gopher.floodgap.com",
            "ssh://git@github.com",
            "ldap://127.0.0.1:389",
        ]
        for url in prohibited:
            result = validate_url_input(url)
            assert result.is_valid is False, f"Expected {url} to be rejected"
            assert result.error_code == "UNSUPPORTED_SCHEME"

    def test_embedded_credentials_redacted_and_disallowed(self):
        """Test embedded username/password are rejected and never leaked."""
        sensitive_urls = [
            "https://admin:SuperSecretPassword123@internal.corp/login",
            "http://victim_user@phishing.site/confirm",
            "https://user:pass123@example.com",
        ]
        for url in sensitive_urls:
            result = validate_url_input(url)
            assert result.is_valid is False
            assert result.error_code == "CREDENTIALS_DISALLOWED"
            assert result.has_credentials is True
            # Crucial security assertion: credentials must NEVER appear in error_message or sanitized_input
            assert "SuperSecretPassword123" not in (result.error_message or "")
            assert "pass123" not in (result.error_message or "")
            assert "SuperSecretPassword123" not in (result.sanitized_input or "")

    def test_malformed_ports(self):
        """Test non-numeric, zero, negative, and out-of-range ports."""
        invalid_port_urls = [
            ("http://example.com:abc/", "MALFORMED_PORT"),
            ("http://example.com:0/", "PORT_OUT_OF_RANGE"),
            ("http://example.com:65536/", "PORT_OUT_OF_RANGE"),
            ("http://example.com:99999/", "PORT_OUT_OF_RANGE"),
            ("http://example.com:-443/", "MALFORMED_PORT"),
        ]
        for url, expected_error in invalid_port_urls:
            result = validate_url_input(url)
            assert result.is_valid is False, f"Expected {url} to fail port check"
            assert result.error_code in (expected_error, "MALFORMED_PORT", "PORT_OUT_OF_RANGE")

    def test_missing_authority_and_hostname(self):
        """Test inputs missing network authority."""
        invalids = [
            "http://",
            "https:///",
            "http:///path/to/resource",
        ]
        for url in invalids:
            result = validate_url_input(url)
            assert result.is_valid is False
            assert result.error_code in ("MISSING_AUTHORITY", "MISSING_HOSTNAME")

    def test_control_characters_and_newlines(self):
        """Test injection of control characters and newlines."""
        bad_urls = [
            "http://example.com/\x00test",
            "http://example.com/\r\nSet-Cookie:malicious=1",
            "http://example.com/\x1b[31mRed",
        ]
        for url in bad_urls:
            result = validate_url_input(url)
            assert result.is_valid is False
            assert result.error_code == "ILLEGAL_CONTROL_CHARACTERS"

    def test_domain_label_boundaries(self):
        """Test domain label boundaries (hyphens, consecutive dots, length)."""
        # Consecutive dots
        assert validate_url_input("http://example..com/").is_valid is False
        # Label starting with hyphen
        assert validate_url_input("http://-example.com/").is_valid is False
        # Label ending with hyphen
        assert validate_url_input("http://example-.com/").is_valid is False
        # Label exceeding 63 chars
        long_label = "a" * 64
        assert validate_url_input(f"http://{long_label}.com/").is_valid is False

