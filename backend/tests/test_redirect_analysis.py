"""CyberShield AI — Part 10: Safe Redirect Analysis Tests

Tests normal redirects, relative redirects, redirect loops, maximum redirect limits,
SSRF-blocked redirect targets, DNS rebinding prevention via IP pinning, and error handling.
"""

import pytest
from unittest.mock import patch, MagicMock
import httpx

from app.services.redirects.models import RedirectAnalysisResult
from app.services.redirects.service import trace_redirects
from app.services.redirects.transport import PinnedHTTPTransport, PinnedSyncBackend
from app.schemas.url_scan import SSRFValidationResult


class TestRedirectAnalysis:
    """Test suite for Part 10 Safe Redirect Analysis."""

    def test_single_hop_normal_redirect(self):
        """Test clean 301 redirect to target destination."""
        mock_responses = {
            "http://example.com": httpx.Response(301, headers={"Location": "https://example.com/welcome"}),
            "https://example.com/welcome": httpx.Response(200, headers={"Content-Type": "text/html"}),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: mock_responses[str(request.url)]
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("http://example.com", client_factory=fake_client_factory)
            assert result.hop_count == 2
            assert result.hops[0].status_code == 301
            assert result.hops[1].status_code == 200
            assert result.final_url == "https://example.com/welcome"
            assert result.destination_ip_safe is True
            assert result.has_circular_redirect is False
            assert result.stopped_reason == "FINAL_DESTINATION_REACHED"

    def test_relative_redirect_resolution(self):
        """Test relative Location header resolution (e.g. /login)."""
        mock_responses = {
            "https://example.com/start": httpx.Response(302, headers={"Location": "/dashboard/overview"}),
            "https://example.com/dashboard/overview": httpx.Response(200),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: mock_responses[str(request.url)]
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/start", client_factory=fake_client_factory)
            assert result.hop_count == 2
            assert result.hops[0].location_header == "/dashboard/overview"
            assert result.hops[1].url == "https://example.com/dashboard/overview"
            assert result.final_url == "https://example.com/dashboard/overview"

    def test_redirect_loop_detection(self):
        """Test circular redirect detection stops safely."""
        mock_responses = {
            "https://example.com/a": httpx.Response(302, headers={"Location": "/b"}),
            "https://example.com/b": httpx.Response(302, headers={"Location": "/a"}),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: mock_responses[str(request.url)]
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/a", client_factory=fake_client_factory)
            assert result.has_circular_redirect is True
            assert result.stopped_reason == "REDIRECT_LOOP_DETECTED"
            loop_findings = [f for f in result.findings if f.check_name == "CIRCULAR_REDIRECT_LOOP"]
            assert len(loop_findings) == 1

    def test_maximum_redirect_limit_enforced(self):
        """Test redirect traversal stops when max_redirects is exceeded."""
        def fake_client_factory(pinned_ip: str):
            # Always redirects to a new page
            mock_transport = httpx.MockTransport(
                lambda request: httpx.Response(302, headers={"Location": f"{request.url}/next"})
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/chain", max_redirects=3, client_factory=fake_client_factory)
            assert result.hop_count == 3
            assert result.stopped_reason == "MAX_REDIRECTS_EXCEEDED"
            chain_findings = [f for f in result.findings if f.check_name == "EXCESSIVE_REDIRECT_CHAIN"]
            assert len(chain_findings) == 1

    def test_unsafe_redirect_target_private_ip_blocked(self):
        """Test redirect to internal private IP address is blocked by SSRF guard."""
        mock_responses = {
            "https://example.com/auth": httpx.Response(302, headers={"Location": "http://192.168.1.1/admin"}),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: mock_responses[str(request.url)]
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        def mock_destination_safety(hostname_or_ip, port=None, resolve_dns=True, dns_timeout=2.0):
            if "192.168" in hostname_or_ip:
                return SSRFValidationResult(
                    is_safe=False,
                    hostname_or_ip=hostname_or_ip,
                    blocked_reason="Prohibited private RFC1918 address",
                    is_private=True
                )
            return SSRFValidationResult(is_safe=True, hostname_or_ip=hostname_or_ip, resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", side_effect=mock_destination_safety):
            result = trace_redirects("https://example.com/auth", client_factory=fake_client_factory)
            assert result.destination_ip_safe is False
            assert result.stopped_reason == "SSRF_BLOCKED_HOP"
            ssrf_findings = [f for f in result.findings if f.check_name == "SSRF_REDIRECT_PREVENTED"]
            assert len(ssrf_findings) == 1
            assert ssrf_findings[0].severity == "critical"

    def test_insecure_https_to_http_downgrade_detected(self):
        """Test security finding when HTTPS downgrades to plaintext HTTP."""
        mock_responses = {
            "https://example.com/secure": httpx.Response(302, headers={"Location": "http://example.com/insecure"}),
            "http://example.com/insecure": httpx.Response(200),
        }

        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: mock_responses[str(request.url)]
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/secure", client_factory=fake_client_factory)
            downgrade_findings = [f for f in result.findings if f.check_name == "INSECURE_REDIRECT_DOWNGRADE"]
            assert len(downgrade_findings) == 1
            assert downgrade_findings[0].severity == "high"

    def test_connection_timeout_handling(self):
        """Test connection timeout handled gracefully without crashing."""
        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(httpx.ConnectTimeout("Connect timeout"))
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/timeout", client_factory=fake_client_factory)
            assert result.stopped_reason == "CONNECT_TIMEOUT"
            assert len(result.limitations) > 0

    def test_connection_error_handling(self):
        """Test connection failure handled gracefully without crashing."""
        def fake_client_factory(pinned_ip: str):
            mock_transport = httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(httpx.ConnectError("Connection refused"))
            )
            return httpx.Client(transport=mock_transport, follow_redirects=False)

        safe_ssrf = SSRFValidationResult(is_safe=True, hostname_or_ip="example.com", resolved_ips=["93.184.215.14"])

        with patch("app.services.redirects.service.validate_destination_safety", return_value=safe_ssrf):
            result = trace_redirects("https://example.com/refused", client_factory=fake_client_factory)
            assert result.stopped_reason == "CONNECTION_FAILED"
            assert len(result.limitations) > 0

    def test_ip_pinning_transport_structure(self):
        """Test PinnedSyncBackend socket connection targets the pinned IP."""
        backend = PinnedSyncBackend(pinned_ip="198.51.100.5")
        assert backend.pinned_ip == "198.51.100.5"

        transport = PinnedHTTPTransport(pinned_ip="198.51.100.5")
        assert transport.pinned_ip == "198.51.100.5"
        transport.close()

    def test_f03_pinned_sync_backend_connect_tcp_passes_pinned_ip(self):
        """F-03 Regression: PinnedSyncBackend.connect_tcp must pass pinned_ip to TCP socket."""
        import httpcore
        backend = PinnedSyncBackend(pinned_ip="198.51.100.77")
        mock_stream = MagicMock(spec=httpcore.NetworkStream)

        with patch.object(httpcore.SyncBackend, "connect_tcp", return_value=mock_stream) as mock_connect:
            stream = backend.connect_tcp(
                host="target-host.example.com",
                port=443,
                timeout=3.5,
                local_address=None,
                socket_options=None
            )
            assert stream is mock_stream
            mock_connect.assert_called_once()
            call_kwargs = mock_connect.call_args.kwargs
            # Host MUST be the pinned IP, NOT the target hostname
            assert call_kwargs["host"] == "198.51.100.77"
            assert call_kwargs["port"] == 443
            assert call_kwargs["timeout"] == 3.5

    def test_f03_tls_sni_server_hostname_preserved_during_tls_negotiation(self):
        """F-03 Regression: Original hostname must remain TLS server_hostname during HTTPS handshake."""
        import httpcore
        backend = PinnedSyncBackend(pinned_ip="198.51.100.88")
        mock_raw_stream = MagicMock(spec=httpcore.NetworkStream)
        mock_tls_stream = MagicMock(spec=httpcore.NetworkStream)
        mock_raw_stream.start_tls.return_value = mock_tls_stream

        with patch.object(httpcore.SyncBackend, "connect_tcp", return_value=mock_raw_stream) as mock_connect:
            conn = httpcore.HTTPConnection(
                origin=httpcore.Origin(b"https", b"secure.target.example.org", 443),
                network_backend=backend
            )
            req = httpcore.Request(method="GET", url=httpcore.URL(b"https://secure.target.example.org/path"))
            stream = conn._connect(req)
            assert stream is mock_tls_stream

            # TCP connect targeted pinned IP
            assert mock_connect.call_args.kwargs["host"] == "198.51.100.88"
            assert mock_connect.call_args.kwargs["port"] == 443

            # TLS SNI / certificate validation preserved original hostname
            mock_raw_stream.start_tls.assert_called_once()
            assert mock_raw_stream.start_tls.call_args.kwargs["server_hostname"] == "secure.target.example.org"

    def test_f03_pinned_http_transport_preserves_http_host_header_and_target(self):
        """F-03 Regression: PinnedHTTPTransport must preserve requested HTTP Host header and target."""
        import httpcore
        transport = PinnedHTTPTransport(pinned_ip="198.51.100.99")
        mock_core_resp = MagicMock(spec=httpcore.Response)
        mock_core_resp.status = 200
        mock_core_resp.headers = [(b"content-type", b"text/plain")]
        # Use a raw iterable stream that does NOT subclass httpx.SyncByteStream
        mock_core_resp.stream = (chunk for chunk in [b"OK"])

        with patch.object(transport._pool, "handle_request", return_value=mock_core_resp) as mock_handle:
            client = httpx.Client(transport=transport)
            resp = client.get("https://requested-site.example.com/api/v1/test?param=value")
            assert resp.status_code == 200
            assert resp.text == "OK"

            mock_handle.assert_called_once()
            core_req = mock_handle.call_args[0][0]

            # Host URL and Host header remain target domain
            assert core_req.url.host == b"requested-site.example.com"
            assert core_req.url.target == b"/api/v1/test?param=value"
            lower_headers = {k.lower(): v for k, v in core_req.headers}
            assert lower_headers.get(b"host") == b"requested-site.example.com"

        transport.close()

    def test_f03_environment_proxies_cannot_redirect_connection(self, monkeypatch):
        """F-03 Regression: Environment proxies (HTTP_PROXY, ALL_PROXY) cannot intercept pinned transport."""
        import httpcore
        monkeypatch.setenv("HTTP_PROXY", "http://malicious-proxy.local:8080")
        monkeypatch.setenv("HTTPS_PROXY", "https://malicious-proxy.local:8080")
        monkeypatch.setenv("ALL_PROXY", "socks5://malicious-proxy.local:1080")
        monkeypatch.setenv("http_proxy", "http://malicious-proxy.local:8080")
        monkeypatch.setenv("https_proxy", "https://malicious-proxy.local:8080")
        monkeypatch.setenv("all_proxy", "socks5://malicious-proxy.local:1080")

        transport = PinnedHTTPTransport(pinned_ip="198.51.100.55")

        # Transport must use a direct ConnectionPool, NOT an HTTPProxy
        assert isinstance(transport._pool, httpcore.ConnectionPool)
        assert not hasattr(transport._pool, "_proxy_origin")
        assert transport._pool._network_backend.pinned_ip == "198.51.100.55"

        mock_core_resp = MagicMock(spec=httpcore.Response)
        mock_core_resp.status = 200
        mock_core_resp.headers = []
        mock_core_resp.stream = (c for c in [b"proxied_check"])

        with patch.object(transport._pool, "handle_request", return_value=mock_core_resp) as mock_handle:
            client = httpx.Client(transport=transport)
            resp = client.get("http://safe-site.example.com/status")
            assert resp.status_code == 200
            mock_handle.assert_called_once()

        transport.close()

    def test_pinned_response_stream_adapts_raw_iterable_and_closes(self):
        """Batch 3 Finalization: PinnedResponseStream wraps raw stream into httpx.SyncByteStream."""
        from app.services.redirects.transport import PinnedResponseStream

        class RawStream:
            def __init__(self):
                self.chunks = [b"part1_", b"part2"]
                self.closed = False
            def __iter__(self):
                yield from self.chunks
            def close(self):
                self.closed = True

        raw = RawStream()
        assert not isinstance(raw, httpx.SyncByteStream)

        stream_adapter = PinnedResponseStream(raw)
        assert isinstance(stream_adapter, httpx.SyncByteStream)
        assert list(stream_adapter) == [b"part1_", b"part2"]

        stream_adapter.close()
        assert raw.closed is True

    def test_pinned_http_transport_consumes_raw_httpcore_stream_without_assertion_error(self):
        """Batch 3 Finalization: httpx.Client consumes PinnedHTTPTransport response without AssertionError."""
        import httpcore
        transport = PinnedHTTPTransport(pinned_ip="93.184.215.14")

        class RawHTTPCoreStream:
            def __init__(self):
                self.chunks = [b"chunk_A_", b"chunk_B"]
                self.closed = False
            def __iter__(self):
                yield from self.chunks
            def close(self):
                self.closed = True

        raw_core_stream = RawHTTPCoreStream()
        mock_core_resp = MagicMock(spec=httpcore.Response)
        mock_core_resp.status = 200
        mock_core_resp.headers = [(b"content-type", b"text/plain")]
        mock_core_resp.stream = raw_core_stream

        with patch.object(transport._pool, "handle_request", return_value=mock_core_resp):
            client = httpx.Client(transport=transport)
            resp = client.get("https://example.com/stream-test")
            # Must succeed and consume content without AssertionError
            assert resp.status_code == 200
            assert resp.content == b"chunk_A_chunk_B"
            resp.close()
            assert raw_core_stream.closed is True

        transport.close()

    def test_pinned_http_transport_supports_ipv4_and_ipv6_destinations(self):
        """Batch 3 Finalization: PinnedHTTPTransport supports both IPv4 and IPv6 pinned addresses."""
        import httpcore
        ipv4_addr = "93.184.215.14"
        ipv6_addr = "2606:4700:8d95:72db:f264:690:ef6b:ff98"

        t_v4 = PinnedHTTPTransport(pinned_ip=ipv4_addr)
        assert t_v4.pinned_ip == ipv4_addr
        assert t_v4._pool._network_backend.pinned_ip == ipv4_addr

        t_v6 = PinnedHTTPTransport(pinned_ip=ipv6_addr)
        assert t_v6.pinned_ip == ipv6_addr
        assert t_v6._pool._network_backend.pinned_ip == ipv6_addr

        mock_core_resp = MagicMock(spec=httpcore.Response)
        mock_core_resp.status = 200
        mock_core_resp.headers = []
        mock_core_resp.stream = (c for c in [b"v6_ok"])

        with patch.object(t_v6._pool, "handle_request", return_value=mock_core_resp):
            client = httpx.Client(transport=t_v6)
            resp = client.get("https://example.com/ipv6-test")
            assert resp.status_code == 200
            assert resp.content == b"v6_ok"

        t_v4.close()
        t_v6.close()

    def test_serialization_to_legacy_redirect_finding_details(self):
        """Test serialization to RedirectFindingDetails for report compatibility."""
        res = RedirectAnalysisResult(
            initial_url="https://example.com",
            final_url="https://example.com/home",
            hop_count=1,
            has_circular_redirect=False,
            destination_ip_safe=True
        )
        legacy = res.to_redirect_finding_details()
        assert legacy.initial_url == "https://example.com"
        assert legacy.final_url == "https://example.com/home"
        assert legacy.hop_count == 1
        assert legacy.destination_ip_safe is True

