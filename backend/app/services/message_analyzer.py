"""CyberShield AI — Message Analyzer Service

Analyzes suspicious messages (Email bodies, SMS, job offers, social engineering snippets).
Employs Member 2's resilient AI engine featuring 3-tier failover
(Groq -> Gemini -> OpenAI) with offline heuristic safety net and evidence grounding.
"""

import logging
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.schemas.scan import MessageIndicator
from app.services.ai_engine import (
    AnalyzeMessageRequest,
    AnalyzeMessageResponse,
    CategoryEnum,
    IndicatorExtractor,
    MessageTypeEnum,
    RiskLevelEnum,
    ScamMessageAnalyzer,
)
from app.services.ai_engine.schemas import ExtractedIndicators

logger = logging.getLogger("cybershield.message_analyzer")


class MessageAnalyzerService:
    """
    Analyzes suspicious messages (Email bodies, SMS, job offers, social engineering snippets).
    Employs Member 2's resilient AI engine featuring 3-tier failover
    (Groq -> Gemini -> OpenAI) with offline heuristic safety net and evidence grounding.
    """

    _analyzer: Optional[ScamMessageAnalyzer] = None

    @classmethod
    def get_analyzer(cls) -> ScamMessageAnalyzer:
        if cls._analyzer is None:
            cls._analyzer = ScamMessageAnalyzer()
        return cls._analyzer

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract deduplicated URLs from message text using safe regex."""
        return IndicatorExtractor.extract_urls(text)

    @classmethod
    async def analyze_message(cls, content: str, message_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Main analysis method invoked by API routes.
        Runs full analysis with LLM failover, prompt injection defense, and grounding.
        """
        analyzer = cls.get_analyzer()
        m_type = MessageTypeEnum.OTHER
        if message_type:
            try:
                m_type = MessageTypeEnum(message_type.lower())
            except Exception:
                m_type = MessageTypeEnum.OTHER

        request = AnalyzeMessageRequest(message=content, message_type=m_type)

        try:
            m2_response, engine_name = await analyzer.analyze(request)
        except Exception as exc:
            logger.error("Analysis raised unexpected exception: %s. Using safe fallback.", str(exc))
            extracted_data = IndicatorExtractor.extract_all(content)
            m2_response, engine_name = analyzer._fallback_analysis(
                request=request,
                extracted=ExtractedIndicators(**extracted_data),
                injection_indicators=analyzer.detect_prompt_injections(content),
                fallback_reason=f"Exception recovery: {str(exc)}",
            )

        return cls._adapt_to_master_schema(m2_response, engine_name, content)

    @classmethod
    def _adapt_to_master_schema(
        cls,
        m2_resp: AnalyzeMessageResponse,
        engine_name: str,
        raw_content: str,
    ) -> Dict[str, Any]:
        """
        Maps Member 2's AnalyzeMessageResponse into the dictionary format
        required by CyberShield-AI's ScanDetailResponse and database models.
        """
        # 1. Map Risk Level & Calculate Quantitative Risk Score (0-100)
        conf = m2_resp.confidence
        risk_enum = m2_resp.risk_level

        if getattr(m2_resp, "risk_score", None) is not None:
            risk_score = m2_resp.risk_score
            if risk_score >= 88:
                risk_level = "Critical"
            elif risk_score >= 70:
                risk_level = "High"
            elif risk_score >= 40:
                risk_level = "Medium"
            else:
                risk_level = "Low"
        else:
            if risk_enum == RiskLevelEnum.HIGH_RISK:
                if conf >= 0.85 or any(k in ind.indicator.lower() for ind in m2_resp.observed_indicators for k in ["theft", "suspension", "otp", "card", "http"]):
                    risk_level = "Critical"
                    risk_score = min(98, 85 + int(conf * 13))
                else:
                    risk_level = "High"
                    risk_score = min(84, 72 + int(conf * 12))
            elif risk_enum == RiskLevelEnum.SUSPICIOUS:
                risk_level = "Medium"
                risk_score = min(69, 45 + int(conf * 24))
            elif risk_enum == RiskLevelEnum.LOW_RISK:
                risk_level = "Low"
                risk_score = max(5, int((1.0 - conf) * 20))
            else:
                risk_level = "Low"
                risk_score = 22

        # 2. Map Indicators to Master MessageIndicator list
        indicators: List[MessageIndicator] = []
        for ind in m2_resp.observed_indicators:
            name_lower = ind.indicator.lower()
            if any(k in name_lower for k in ["otp", "password", "credential", "arrest", "pin", "wire transfer", "prompt", "cvv", "unencrypted http", "card harvesting"]):
                severity = "Critical"
            elif any(k in name_lower for k in ["fee", "kyc", "urgency", "guaranteed", "suspension", "block", "aadhaar", "pan", "identity", "bank account", "investment", "deposit", "delivery", "infected", "lottery", "payout"]):
                severity = "High"
            elif any(k in name_lower for k in ["screenshot", "portal", "deadline", "cancellation", "support", "impersonation", "lure", "action"]):
                severity = "Medium"
            else:
                severity = "Medium"

            desc_text = getattr(ind, "reason", getattr(ind, "explanation", ""))
            indicators.append(
                MessageIndicator(
                    category=ind.indicator,
                    severity=severity,
                    description=f"{ind.indicator}: {desc_text}"
                )
            )

        # 3. Format grounded evidence strings with verbatim excerpts
        evidence_list = []
        for ind in m2_resp.observed_indicators:
            quote = getattr(ind, "verbatim_quote", getattr(ind, "evidence", ""))
            desc_text = getattr(ind, "reason", getattr(ind, "explanation", ""))
            if quote:
                evidence_list.append(f"Observed pattern '{ind.indicator}' matching exact excerpt: \"{quote}\"")
            else:
                evidence_list.append(f"Observed pattern '{ind.indicator}': {desc_text}")

        if m2_resp.extracted_indicators.urls:
            evidence_list.append(f"Extracted {len(m2_resp.extracted_indicators.urls)} target URL(s): {', '.join(m2_resp.extracted_indicators.urls)}")
        if m2_resp.extracted_indicators.phone_numbers:
            evidence_list.append(f"Extracted contact number(s): {', '.join(m2_resp.extracted_indicators.phone_numbers)}")
        if m2_resp.extracted_indicators.emails:
            evidence_list.append(f"Extracted contact email(s): {', '.join(m2_resp.extracted_indicators.emails)}")

        if not evidence_list:
            evidence_list = ["No overt suspicious patterns, urgent demands, or adversarial indicators detected."]

        # 4. Actionable recommendations
        recommendations = list(m2_resp.recommendations) if m2_resp.recommendations else [
            "Review sender identity and message context before proceeding.",
            "Verify any sensitive requests via official, independent channels."
        ]

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": conf,
            "category": m2_resp.category.value,
            "engine": engine_name,
            "summary": m2_resp.explanation,
            "evidence": evidence_list,
            "recommendations": recommendations,
            "message_indicators": indicators,
            "extracted_urls": m2_resp.extracted_indicators.urls,
            "extracted_indicators": m2_resp.extracted_indicators.model_dump(),
            "raw_m2_response": m2_resp.model_dump(),
        }
