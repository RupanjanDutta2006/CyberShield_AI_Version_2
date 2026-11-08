"""CyberShield AI — Part 10: Safe Redirect Analysis Models

Data models and schemas for redirect chain tracing, hop inspection, and SSRF detection.
"""

from typing import List, Optional, Dict, Any, TYPE_CHECKING
from pydantic import BaseModel, Field

from app.schemas.common import TechnicalFinding, TechnicalLimitation

if TYPE_CHECKING:
    from app.schemas.url_scan import RedirectHop, RedirectFindingDetails


class RedirectHopRecord(BaseModel):
    """Detailed record of a single hop in a redirect chain."""
    hop_number: int = Field(..., description="Zero-based index of this hop")
    url: str = Field(..., description="The requested URL for this hop")
    status_code: int = Field(..., description="HTTP response status code")
    resolved_ip: Optional[str] = Field(default=None, description="Pinned IP address connected to")
    location_header: Optional[str] = Field(default=None, description="Raw Location header received")
    is_safe: bool = Field(default=True, description="Whether this hop passed SSRF validation")
    blocked_reason: Optional[str] = Field(default=None, description="Reason if blocked by SSRF or security gate")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Captured response headers")

    def to_redirect_hop(self) -> "RedirectHop":
        """Convert into backward-compatible RedirectHop schema."""
        from app.schemas.url_scan import RedirectHop
        return RedirectHop(
            hop_number=self.hop_number,
            url=self.url,
            status_code=self.status_code,
            resolved_ip=self.resolved_ip
        )


class RedirectAnalysisResult(BaseModel):
    """Complete structured result of safe redirect inspection."""
    initial_url: str = Field(..., description="Starting URL submitted for inspection")
    final_url: Optional[str] = Field(default=None, description="Final resolved destination URL")
    hop_count: int = Field(default=0, description="Total number of redirect hops taken")
    hops: List[RedirectHopRecord] = Field(default_factory=list, description="Ordered chain of redirect hops")
    has_circular_redirect: bool = Field(default=False, description="Whether a circular redirect loop was detected")
    destination_ip_safe: bool = Field(default=True, description="Whether all hops reached safe destinations")
    stopped_reason: str = Field(default="UNKNOWN", description="Reason redirect traversal stopped")
    findings: List[TechnicalFinding] = Field(default_factory=list, description="Observed security findings")
    limitations: List[TechnicalLimitation] = Field(default_factory=list, description="Documented inspection limitations")

    def to_redirect_finding_details(self) -> "RedirectFindingDetails":
        """Convert into backward-compatible RedirectFindingDetails."""
        from app.schemas.url_scan import RedirectFindingDetails
        return RedirectFindingDetails(
            initial_url=self.initial_url,
            final_url=self.final_url,
            hop_count=self.hop_count,
            hops=[hop.to_redirect_hop() for hop in self.hops],
            has_circular_redirect=self.has_circular_redirect,
            destination_ip_safe=self.destination_ip_safe
        )

