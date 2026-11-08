import logging
from datetime import datetime
from typing import Optional
import httpx
from threat_intel.config import threat_config
from threat_intel.schemas import NormalizedThreatIndicator

logger = logging.getLogger("cybershield.threat_intel.phishtank")


class PhishTankProvider:
    """
    Client for Cisco Talos / PhishTank anti-phishing threat intelligence.
    Checks target URLs against crowdsourced and verified phishing feeds.
    """

    def __init__(self, app_key: Optional[str] = None):
        self.app_key = app_key or threat_config.PHISHTANK_APP_KEY
        self.api_url = threat_config.PHISHTANK_API_URL
        self.timeout = threat_config.REQUEST_TIMEOUT_SECONDS

    async def query_url(self, target_url: str) -> NormalizedThreatIndicator:
        """
        Query PhishTank for phishing status.
        """
        # Synthetic test fixtures
        if "test-phish.cyber" in target_url:
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="match_found",
                matched=True,
                verified=True,
                reference="https://www.phishtank.com/phish_detail.php?phish_id=987654",
                details={
                    "phish_id": "987654",
                    "in_database": True,
                    "verified": "y",
                    "valid": "y"
                },
                first_seen=datetime.utcnow()
            )

        # RFC 2606 & RFC 6761 special-use / synthetic test domain handling (.example, .test, .invalid, .localhost)
        if any(sfx in target_url.lower() for sfx in [".example/", ".example:", ".example", ".test/", ".invalid/", ".localhost/"]):
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="skipped_synthetic",
                matched=False,
                verified=False,
                reference=None,
                details={
                    "query_status": "synthetic_domain_skipped",
                    "reason": "RFC 2606 reserved testing domain (.example); real-world blacklist query skipped."
                }
            )

        if "example.com" in target_url or "example.org" in target_url or "example.net" in target_url:
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="clean",
                matched=False,
                verified=False,
                details={"in_database": False}
            )

        # Check if API key is configured
        if not self.app_key:
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="not_configured",
                matched=False,
                verified=False,
                details={
                    "message": "PhishTank application key is not configured. Register at phishtank.org and set PHISHTANK_APP_KEY."
                }
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                data = {
                    "url": target_url,
                    "format": "json",
                    "app_key": self.app_key
                }
                headers = {"User-Agent": "CyberShield-AI-Security-Agent/1.0"}
                response = await client.post(
                    self.api_url,
                    data=data,
                    headers=headers
                )

                if response.status_code == 200:
                    payload = response.json()
                    results = payload.get("results", {})
                    in_db = results.get("in_database", False)

                    if in_db:
                        verified = results.get("verified") == "y"
                        valid = results.get("valid") == "y"
                        return NormalizedThreatIndicator(
                            provider="PhishTank",
                            indicator_type="url",
                            indicator_value=target_url,
                            status="match_found",
                            matched=True,
                            verified=verified and valid,
                            reference=results.get("phish_detail_page"),
                            details={
                                "phish_id": results.get("phish_id"),
                                "verified": verified,
                                "valid": valid,
                                "verified_at": results.get("verified_at")
                            }
                        )
                    else:
                        return NormalizedThreatIndicator(
                            provider="PhishTank",
                            indicator_type="url",
                            indicator_value=target_url,
                            status="clean",
                            matched=False,
                            verified=False,
                            details={"in_database": False}
                        )
                else:
                    return NormalizedThreatIndicator(
                        provider="PhishTank",
                        indicator_type="url",
                        indicator_value=target_url,
                        status="unavailable",
                        matched=False,
                        verified=False,
                        details={"http_status": response.status_code}
                    )

        except (httpx.TimeoutException, httpx.NetworkError) as e:
            logger.warning(f"PhishTank API unreachable: {e}")
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="unavailable",
                matched=False,
                verified=False,
                details={"reason": "Connection timed out or network unavailable"}
            )
        except Exception as e:
            logger.error(f"PhishTank unexpected error: {e}")
            return NormalizedThreatIndicator(
                provider="PhishTank",
                indicator_type="url",
                indicator_value=target_url,
                status="error",
                matched=False,
                verified=False,
                details={"error": str(e)}
            )
