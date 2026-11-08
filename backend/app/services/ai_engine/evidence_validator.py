"""Evidence verification and grounding service.

Ensures that every observed indicator quotation is strictly verifiable
against the submitted source message. Rejects ungrounded or fabricated quotes.
"""

import re
import unicodedata
from typing import List
from .schemas import ObservedIndicator


class EvidenceValidator:
    """Validates evidence quotes against raw input text to prevent hallucination."""

    @staticmethod
    def normalize_text_for_matching(text: str) -> str:
        """Normalize unicode, collapse whitespace, and lowercase for robust matching."""
        if not text:
            return ""
        normalized = unicodedata.normalize("NFKC", text)
        collapsed = re.sub(r"\s+", " ", normalized).strip().lower()
        return collapsed

    @classmethod
    def is_evidence_verifiable(cls, raw_message: str, evidence: str) -> bool:
        """Check if an evidence quote exists verbatim or whitespace-normalized in the raw message."""
        if not evidence or not raw_message:
            return False

        # Clean evidence from wrapping quotation marks if present
        cleaned_evidence = evidence.strip("\"' \t\r\n")
        if not cleaned_evidence:
            return False

        # 1. Direct exact substring match
        if cleaned_evidence in raw_message:
            return True

        # 2. Case-insensitive exact substring match
        if cleaned_evidence.lower() in raw_message.lower():
            return True

        # 3. Normalized whitespace match
        norm_raw = cls.normalize_text_for_matching(raw_message)
        norm_ev = cls.normalize_text_for_matching(cleaned_evidence)

        if norm_ev and norm_ev in norm_raw:
            return True

        # 4. Punctuation-agnostic word sequence match for multi-word quotes
        raw_words = re.findall(r"\w+", norm_raw)
        ev_words = re.findall(r"\w+", norm_ev)

        if not ev_words:
            return False

        # Check if sequence of words exists in raw words
        seq_len = len(ev_words)
        for i in range(len(raw_words) - seq_len + 1):
            if raw_words[i : i + seq_len] == ev_words:
                return True

        return False

    @classmethod
    def find_best_verbatim_quote(cls, raw_message: str, evidence: str) -> str:
        """Return the verbatim substring from raw_message matching evidence if possible."""
        cleaned_evidence = evidence.strip("\"' \t\r\n")
        if cleaned_evidence in raw_message:
            return cleaned_evidence

        # Check case-insensitive match
        idx = raw_message.lower().find(cleaned_evidence.lower())
        if idx != -1:
            return raw_message[idx : idx + len(cleaned_evidence)]

        # Fallback to normalized quote
        return cleaned_evidence

    @classmethod
    def filter_and_ground_indicators(
        cls, raw_message: str, indicators: List[ObservedIndicator]
    ) -> List[ObservedIndicator]:
        """Filter out any indicator whose evidence quotation cannot be verified in raw_message."""
        verified: List[ObservedIndicator] = []

        for item in indicators:
            if cls.is_evidence_verifiable(raw_message, item.evidence):
                # Standardize evidence quote to match original text verbatim
                verbatim_evidence = cls.find_best_verbatim_quote(raw_message, item.evidence)
                verified.append(
                    ObservedIndicator(
                        indicator=item.indicator.strip(),
                        evidence=verbatim_evidence,
                        reason=item.reason.strip(),
                    )
                )

        return verified
