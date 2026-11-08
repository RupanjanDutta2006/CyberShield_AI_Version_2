"""CyberShield AI — Connection-Level Verified-IP Pinning Transport

Provides an HTTP transport layer that pins TCP socket connections directly to
a pre-validated IP address, completely preventing TOCTOU DNS rebinding attacks
while preserving the original HTTP Host header, TLS SNI, and certificate hostname
verification. Strictly disables environment proxies to prevent SSRF bypasses.
"""

import ssl
from typing import Optional, Iterable, Iterator
import httpcore
import httpx


class PinnedResponseStream(httpx.SyncByteStream):
    """Adapter bridging an httpcore response stream into an httpx SyncByteStream."""

    def __init__(self, httpcore_stream: Iterable[bytes]):
        self._httpcore_stream = httpcore_stream

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._httpcore_stream:
            yield chunk

    def close(self) -> None:
        if hasattr(self._httpcore_stream, "close"):
            self._httpcore_stream.close()


class PinnedSyncBackend(httpcore.SyncBackend):
    """httpcore network backend that overrides connect_tcp to use a pre-validated pinned IP."""

    def __init__(self, pinned_ip: str):
        super().__init__()
        self.pinned_ip = pinned_ip

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[httpcore.SOCKET_OPTION]] = None,
    ) -> httpcore.NetworkStream:
        """Connect TCP socket directly to pinned_ip instead of resolving host."""
        # The TCP handshake opens strictly to the pre-verified safe IP address.
        # When start_tls is subsequently called by httpcore, it passes the original
        # 'host' as server_hostname, ensuring TLS SNI and cert verification work properly.
        return super().connect_tcp(
            host=self.pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedHTTPTransport(httpx.BaseTransport):
    """httpx Transport with connection-level IP pinning and disabled environment proxies."""

    def __init__(
        self,
        pinned_ip: str,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
        retries: int = 0
    ):
        self.pinned_ip = pinned_ip
        backend = PinnedSyncBackend(pinned_ip)
        self._pool = httpcore.ConnectionPool(
            network_backend=backend,
            ssl_context=ssl_context or (ssl.create_default_context() if verify else None),
            retries=retries,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Route request through connection-level pinned pool."""
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
        )
        try:
            core_response = self._pool.handle_request(core_request)
            return httpx.Response(
                status_code=core_response.status,
                headers=core_response.headers,
                stream=PinnedResponseStream(core_response.stream),
                request=request,
            )
        except httpcore.ConnectError as err:
            raise httpx.ConnectError(str(err), request=request)
        except httpcore.ConnectTimeout as err:
            raise httpx.ConnectTimeout(str(err), request=request)
        except httpcore.ReadTimeout as err:
            raise httpx.ReadTimeout(str(err), request=request)
        except Exception as err:
            raise httpx.RequestError(str(err), request=request)

    def close(self) -> None:
        """Close connection pool."""
        self._pool.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

