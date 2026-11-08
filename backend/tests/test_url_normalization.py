"""CyberShield AI — Part 06: URL Normalization Unit Tests

Tests scheme and host casing, IDN/Punycode conversions, default port stripping,
path dot-segment resolution with consecutive-slash preservation, percent-encoding normalization,
and reliable Public Suffix List (PSL) registrable domain extraction without guessing on unknown suffixes.
"""

import pytest
from app.services.url_investigation.normalization import (
    normalize_url,
    extract_registrable_domain,
    remove_dot_segments,
    normalize_percent_encoding,
)


class TestURLNormalization:
    """Test suite for Part 06 URL normalization."""

    def test_scheme_and_hostname_lowercasing(self):
        """Test that schemes and hostnames are converted to lowercase."""
        res = normalize_url("HTTP://EXAMPLE.COM/Path/To/Resource")
        assert res.scheme == "http"
        assert res.hostname == "example.com"
        assert res.normalized_url == "http://example.com/Path/To/Resource"

    def test_default_port_stripping(self):
        """Test default ports (80 for http, 443 for https) are omitted from normalized URL."""
        res_http = normalize_url("http://example.com:80/home")
        assert res_http.port is None
        assert res_http.normalized_url == "http://example.com/home"

        res_https = normalize_url("https://example.com:443/home")
        assert res_https.port is None
        assert res_https.normalized_url == "https://example.com/home"

    def test_non_default_port_preservation(self):
        """Test non-standard ports are preserved in normalized URL."""
        res = normalize_url("http://example.com:8080/test")
        assert res.port == 8080
        assert res.normalized_url == "http://example.com:8080/test"

        res_ssl = normalize_url("https://example.com:8443/secure")
        assert res_ssl.port == 8443
        assert res_ssl.normalized_url == "https://example.com:8443/secure"

    def test_trailing_dot_hostname(self):
        """Test trailing dots on hostname are stripped."""
        res = normalize_url("https://example.com./about")
        assert res.hostname == "example.com"
        assert res.normalized_url == "https://example.com/about"

    def test_empty_path_normalized_to_slash(self):
        """Test empty path is normalized to root slash '/'."""
        res = normalize_url("https://example.com")
        assert res.path == "/"
        assert res.normalized_url == "https://example.com/"

    def test_dot_segment_resolution(self):
        """Test RFC 3986 dot-segment resolution (., ..)."""
        res = normalize_url("https://example.com/a/b/../c/./d")
        assert res.path == "/a/c/d"
        assert res.normalized_url == "https://example.com/a/c/d"

        # Trailing slash preservation
        res_trailing = normalize_url("https://example.com/a/b/../")
        assert res_trailing.path == "/a/"

    # =========================================================================
    # Issue 1 Regression Tests: Consecutive Slash Preservation
    # =========================================================================

    def test_consecutive_slashes_preserved_in_path_and_url(self):
        """Regression Test Issue 1: Consecutive slashes must NOT be collapsed in request path."""
        # 1. Test https://example.com//a///b
        res1 = normalize_url("https://example.com//a///b")
        assert res1.path == "//a///b", f"Expected path '//a///b', got '{res1.path}'"
        assert res1.normalized_url == "https://example.com//a///b"
        assert res1.original_url == "https://example.com//a///b"
        assert res1.display_path == "/a/b"

        # 2. Test https://example.com/a/b (standard single slashes preserved)
        res2 = normalize_url("https://example.com/a/b")
        assert res2.path == "/a/b"
        assert res2.normalized_url == "https://example.com/a/b"

        # 3. Test https://example.com///
        res3 = normalize_url("https://example.com///")
        assert res3.path == "///", f"Expected path '///', got '{res3.path}'"
        assert res3.normalized_url == "https://example.com///"
        assert res3.display_path == "/"

    def test_consecutive_slashes_with_query_string(self):
        """Regression Test Issue 1: Repeated slashes with query string must be preserved."""
        url = "https://example.com//api///v1//resource?filter=active&order=desc"
        res = normalize_url(url)
        assert res.path == "//api///v1//resource"
        assert res.query == "filter=active&order=desc"
        assert res.normalized_url == "https://example.com//api///v1//resource?filter=active&order=desc"
        assert res.original_url == url

    def test_consecutive_slashes_signed_url_preservation(self):
        """Regression Test Issue 1: Signed URLs (HMAC) must not have path altered."""
        signed_url = (
            "https://s3.amazonaws.com//mybucket///data.json"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abcdef1234567890"
        )
        res = normalize_url(signed_url)
        assert res.path == "//mybucket///data.json"
        assert "X-Amz-Signature=abcdef1234567890" in res.normalized_url
        assert res.normalized_url.startswith("https://s3.amazonaws.com//mybucket///data.json?")

    def test_percent_encoding_normalization(self):
        """Test unreserved percent-encoded chars decoded and reserved uppercase."""
        # %7E is '~', %41 is 'A' (unreserved -> decoded)
        res = normalize_url("https://example.com/%7Euser/%41%42%43")
        assert res.path == "/~user/ABC"

        # %2f is reserved '/' -> uppercase hex %2F preserved to prevent path confusion
        res_reserved = normalize_url("https://example.com/path%2fsub")
        assert res_reserved.path == "/path%2Fsub"

    def test_internationalized_domain_names(self):
        """Test Unicode IDN and Punycode conversion."""
        # Unicode domain
        res_unicode = normalize_url("https://münchen.de/oktoberfest")
        assert res_unicode.is_idn is True
        assert res_unicode.punycode_hostname == "xn--mnchen-3ya.de"
        assert res_unicode.unicode_hostname == "münchen.de"
        assert res_unicode.normalized_url == "https://xn--mnchen-3ya.de/oktoberfest"

        # Punycode domain
        res_puny = normalize_url("https://xn--bcher-kva.example/catalog")
        assert res_puny.is_idn is True
        assert res_puny.unicode_hostname == "bücher.example"
        assert res_puny.punycode_hostname == "xn--bcher-kva.example"

    # =========================================================================
    # Issue 2 Regression Tests: PSL Registrable Domain Detection
    # =========================================================================

    def test_psl_shared_hosting_tenant_extraction(self):
        """Regression Test Issue 2: PSL public suffixes on shared platforms extract tenant domain."""
        # GitHub Pages
        res_gh = normalize_url("https://phishing-tenant.github.io/login")
        assert res_gh.registrable_domain == "phishing-tenant.github.io"

        # Cloudflare Pages
        res_pages = normalize_url("https://my-brand.pages.dev/auth")
        assert res_pages.registrable_domain == "my-brand.pages.dev"

        # Cloudflare Workers
        res_workers = normalize_url("https://api-handler.workers.dev/v1")
        assert res_workers.registrable_domain == "api-handler.workers.dev"

        # Nested subdomain on GitHub Pages
        assert extract_registrable_domain("deep.sub.tenant.github.io") == "tenant.github.io"

        # AWS S3 and Azure Web Apps
        assert extract_registrable_domain("my-bucket.s3.amazonaws.com") == "my-bucket.s3.amazonaws.com"
        assert extract_registrable_domain("app.azurewebsites.net") == "app.azurewebsites.net"

    def test_psl_standard_and_multipart_domains(self):
        """Regression Test Issue 2: Standard gTLDs and ccTLDs."""
        assert extract_registrable_domain("example.com") == "example.com"
        assert extract_registrable_domain("sub.example.com") == "example.com"
        assert extract_registrable_domain("example.co.uk") == "example.co.uk"
        assert extract_registrable_domain("sub.example.co.uk") == "example.co.uk"
        assert extract_registrable_domain("api.service.com.au") == "service.com.au"

    def test_psl_unknown_suffix_does_not_guess(self):
        """Regression Test Issue 2: Unknown or unsupported suffix must return None, NOT guess."""
        # Do not guess last two labels when suffix is unrecognized
        assert extract_registrable_domain("unknown.invalidsuffixtest123") is None
        assert extract_registrable_domain("a.b.c.unknowntldxyz") is None

    def test_psl_bare_public_suffixes_and_ips_return_none(self):
        """Regression Test Issue 2: Bare public suffixes and IPs have no registrable domain."""
        assert extract_registrable_domain("github.io") is None
        assert extract_registrable_domain("pages.dev") is None
        assert extract_registrable_domain("co.uk") is None
        assert extract_registrable_domain("com") is None
        assert extract_registrable_domain("192.168.1.1") is None
        assert extract_registrable_domain("[::1]") is None

    def test_query_and_fragment_handling(self):
        """Test query string preservation and fragment metadata retention."""
        res = normalize_url("https://example.com/search?q=cyber+shield&category=ai#results")
        assert res.query == "q=cyber+shield&category=ai"
        assert res.fragment == "results"
        assert res.normalized_url == "https://example.com/search?q=cyber+shield&category=ai"

    def test_invalid_url_raises_value_error(self):
        """Test that invalid URLs fail with ValueError."""
        with pytest.raises(ValueError) as exc_info:
            normalize_url("ftp://not-supported.com")
        assert "Cannot normalize invalid URL" in str(exc_info.value)
