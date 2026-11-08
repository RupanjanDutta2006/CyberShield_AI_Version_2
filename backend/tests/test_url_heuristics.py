"""CyberShield AI — Part 08: Suspicious URL Pattern Detection Unit Tests

Tests deterministic detection of bare IP hosts, deeply nested subdomains,
deceptive brand/security keywords, Cyrillic lookalike homographs, Punycode domains,
suspicious percent-encodings, open redirect parameters, non-standard ports, and URL shorteners.
"""

import pytest
from app.services.url_investigation.validation import validate_url_input
from app.services.url_investigation.normalization import normalize_url
from app.services.url_investigation.heuristics import detect_suspicious_patterns
from app.schemas.common import FindingSeverity


class TestURLHeuristics:
    """Test suite for Part 08 suspicious URL pattern detection."""

    def test_benign_url_produces_no_suspicious_findings(self):
        """Test clean, standard URL generates zero suspicious indicators."""
        url = "https://example.com/about"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        assert len(findings) == 0, f"Expected 0 findings for benign URL, got: {[f.check_name for f in findings]}"

    def test_direct_ip_hostname_detected(self):
        """Test direct IP address hostname is flagged with MEDIUM severity."""
        url = "http://198.51.100.25/status"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "SUSPICIOUS_IP_HOST" in check_names
        ip_finding = next(f for f in findings if f.check_name == "SUSPICIOUS_IP_HOST")
        assert ip_finding.severity == FindingSeverity.MEDIUM

    def test_excessive_subdomains_detected(self):
        """Test deeply nested subdomains are flagged."""
        url = "http://a.b.c.d.e.hosting-service.com/index"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "EXCESSIVE_SUBDOMAIN_DEPTH" in check_names

    def test_deceptive_security_keywords_detected(self):
        """Test authentication keywords in subdomains and path are flagged."""
        url = "http://account-verification.login.bank.com/secure-update"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "DECEPTIVE_BRAND_KEYWORDS" in check_names
        kw_finding = next(f for f in findings if f.check_name == "DECEPTIVE_BRAND_KEYWORDS")
        assert kw_finding.severity == FindingSeverity.MEDIUM
        assert "matched_keywords" in kw_finding.evidence

    def test_cyrillic_homograph_attack_detected(self):
        """Test domain containing Cyrillic lookalike letters is flagged as HIGH severity."""
        # Using Cyrillic 'а' (\u0430) inside "paypal.com"
        cyrillic_url = "https://p\u0430ypal.com/signin"
        val = validate_url_input(cyrillic_url)
        norm = normalize_url(cyrillic_url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "HOMOGRAPH_LOOKALIKE_DETECTED" in check_names
        homo_finding = next(f for f in findings if f.check_name == "HOMOGRAPH_LOOKALIKE_DETECTED")
        assert homo_finding.severity == FindingSeverity.HIGH

    def test_punycode_domain_flagged_info_or_low(self):
        """Test legitimate Punycode without Cyrillic lookalikes is flagged with LOW severity."""
        url = "https://xn--bcher-kva.example/catalog"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "PUNYCODE_DOMAIN_INDICATOR" in check_names
        puny_finding = next(f for f in findings if f.check_name == "PUNYCODE_DOMAIN_INDICATOR")
        assert puny_finding.severity == FindingSeverity.LOW

    def test_suspicious_percent_encoding_detected(self):
        """Test encoded slashes and null bytes are flagged as HIGH severity."""
        url = "http://example.com/app%2fadmin%00bypass"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "SUSPICIOUS_PERCENT_ENCODING" in check_names
        enc_finding = next(f for f in findings if f.check_name == "SUSPICIOUS_PERCENT_ENCODING")
        assert enc_finding.severity == FindingSeverity.HIGH

    def test_open_redirect_parameters_detected(self):
        """Test query parameters pointing to external URLs are flagged."""
        url = "https://trusted-site.com/auth/redirect?next=https://malicious-harvest.xyz/steal"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "SUSPICIOUS_OPEN_REDIRECT_PARAM" in check_names
        redir_finding = next(f for f in findings if f.check_name == "SUSPICIOUS_OPEN_REDIRECT_PARAM")
        assert redir_finding.severity == FindingSeverity.MEDIUM

    def test_non_standard_port_detected(self):
        """Test non-standard web ports are flagged."""
        url = "http://example.com:1337/command"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "UNUSUAL_PORT_SPECIFIED" in check_names

    def test_known_url_shortener_detected(self):
        """Test recognition of URL shortener domains."""
        url = "https://bit.ly/3xyzABC"
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "KNOWN_URL_SHORTENER" in check_names
        short_finding = next(f for f in findings if f.check_name == "KNOWN_URL_SHORTENER")
        assert short_finding.severity == FindingSeverity.INFO

    def test_excessive_url_length_detected(self):
        """Test unusually long URL paths are flagged."""
        url = "https://example.com/" + ("token-segment-" * 10)
        val = validate_url_input(url)
        norm = normalize_url(url)
        findings = detect_suspicious_patterns(val, norm)
        check_names = [f.check_name for f in findings]
        assert "EXCESSIVE_URL_LENGTH" in check_names

    def test_embedded_credentials_finding(self):
        """Test credentials in URL authority generate high-severity deceptive finding."""
        # Note: validate_url_input marks has_credentials=True
        val = validate_url_input("http://admin:secret@legit-bank.com/login")
        findings = detect_suspicious_patterns(val, normalization=None)
        check_names = [f.check_name for f in findings]
        assert "DECEPTIVE_AUTHORITY_CREDENTIALS" in check_names
        cred_finding = next(f for f in findings if f.check_name == "DECEPTIVE_AUTHORITY_CREDENTIALS")
        assert cred_finding.severity == FindingSeverity.HIGH

