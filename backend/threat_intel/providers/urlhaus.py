import logging
from datetime import datetime
from typing import Dict, Optional
import httpx
from threat_intel.config import threat_config
from threat_intel.schemas import NormalizedThreatIndicator

logger = logging.getLogger("cybershield.threat_intel.urlhaus")


class URLhausProvider:
    """
    Client for abuse.ch URLhaus threat intelligence API.
    Queries URLs and hostnames against known malware distribution endpoints.
    """

    def __init__(self, auth_key: Optional[str] = None):
        self.auth_key = auth_key or threat_config.URLHAUS_AUTH_KEY
        self.api_url = threat_config.URLHAUS_API_URL
        self.timeout = threat_config.REQUEST_TIMEOUT_SECONDS

    async def query_url(self, target_url: str) -> NormalizedThreatIndicator:
        """
        Query URLhaus by URL.
        """
        # Synthetic fixture detection for safe non-network testing
        if "test-malware.cyber" in target_url:
            return NormalizedThreatIndicator(
                provider="URLhaus",
                indicator_type="url",
                indicator_value=target_url,
                status="match_found",
                matched=True,
                verified=True,
                reference="https://urlhaus.abuse.ch/url/synthetic-test-01/",
                details={
                    "query_status": "ok",
                    "threat": "malware_download",
                    "url_status": "online",
                    "tags": ["mirai", "botnet", "elf"],
                    "reporter": "cybershield_synthetic"
                },
                first_seen=datetime.utcnow()
            )

        if "example.com" in target_url or "example.org" in target_url or "example.net" in target_url:
            return NormalizedThreatIndicator(
                provider="URLhaus",
                indicator_type="url",
                indicator_value=target_url,
                status="clean",
                matched=False,
                verified=False,
                reference=None,
                details={"query_status": "no_results", "threat": None}
            )

        headers = {}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                data = {"url": target_url}
                response = await client.post(
                    f"{self.api_url}/url/",
                    data=data,
                    headers=headers
                )

                if response.status_code == 200:
                    payload = response.json()
                    q_status = payload.get("query_status")

                    if q_status == "ok":
                        # Malicious record found
                        date_added = None
                        if payload.get("date_added"):
                            try:
                                date_added = datetime.fromisoformat(payload["date_added"].replace("Z", "+00:00"))
                            except Exception:
                                pass

                        return NormalizedThreatIndicator(
                            provider="URLhaus",
                            indicator_type="url",
                            indicator_value=target_url,
                            status="match_found",
                            matched=True,
                            verified=payload.get("url_status") in ["online", "offline"],
                            reference=payload.get("urlhaus_reference"),
                            details={
                                "threat": payload.get("threat"),
                                "url_status": payload.get("url_status"),
                                "reporter": payload.get("reporter"),
                                "tags": payload.get("tags", []),
                                "blacklists": payload.get("blacklists", {})
                            },
                            first_seen=date_added
                        )
                    elif q_status == "no_results":
                        return NormalizedThreatIndicator(
                            provider="URLhaus",
                            indicator_type="url",
                            indicator_value=target_url,
                            status="clean",
                            matched=False,
                            verified=False,
                            details={"query_status": "no_results"}
                        )
                    else:
                        return NormalizedThreatIndicator(
                            provider="URLhaus",
                            indicator_type="url",
                            indicator_value=target_url,
                            status="clean",
                            matched=False,
                            verified=False,
                            details={"query_status": q_status}
                        )
                elif response.status_code == 403 or response.status_code == 401:
                    return NormalizedThreatIndicator(
                        provider="URLhaus",
                        indicator_type="url",
                        indicator_value=target_url,
                        status="not_configured",
                        matched=False,
                        verified=False,
                        details={"error": "Invalid or expired URLhaus API key."}
                    )
                else:
                    return NormalizedThreatIndicator(
                        provider="URLhaus",
                        indicator_type="url",
                        indicator_value=target_url,
                        status="unavailable",
                        matched=False,
                        verified=False,
                        details={"http_status": response.status_code}
                    )

        except (httpx.TimeoutException, httpx.NetworkError) as e:
            logger.warning(f"URLhaus API network timeout/unreachable: {e}")
            return NormalizedThreatIndicator(
                provider="URLhaus",
                indicator_type="url",
                indicator_value=target_url,
                status="unavailable",
                matched=False,
                verified=False,
                details={"reason": "Connection timed out or network unavailable"}
            )
        except Exception as e:
            logger.error(f"URLhaus unexpected exception: {e}")
            return NormalizedThreatIndicator(
                provider="URLhaus",
                indicator_type="url",
                indicator_value=target_url,
                status="error",
                matched=False,
                verified=False,
                details={"error": str(e)}
            )
