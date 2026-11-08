from typing import Any, Dict, List
from threat_intel.schemas import NormalizedThreatIndicator
from backend.schemas.scan import ProviderResultSchema


class IndicatorNormalizer:
    @staticmethod
    def to_schema(indicator: NormalizedThreatIndicator) -> ProviderResultSchema:
        return ProviderResultSchema(
            provider=indicator.provider,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.indicator_value,
            status=indicator.status,
            matched=indicator.matched,
            verified=indicator.verified,
            reference=indicator.reference,
            details=indicator.details,
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen
        )

    @classmethod
    def list_to_schema(cls, indicators: List[NormalizedThreatIndicator]) -> List[ProviderResultSchema]:
        return [cls.to_schema(ind) for ind in indicators]
