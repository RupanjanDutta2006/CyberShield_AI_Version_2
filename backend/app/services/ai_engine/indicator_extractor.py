"""Deterministic indicator extraction service for URLs, domains, emails, and phone numbers.

Extracts technical indicators using regular expressions and standard URL parsing.
Strictly offline: does NOT visit or scan extracted URLs.
"""

import re
from typing import Dict, List, Set
from urllib.parse import urlparse


class IndicatorExtractor:
    """Extracts and normalizes technical indicators from unstructured text."""

    # Regex for URLs: handles http, https, ftp, hxxp (defanged), and standalone www.
    URL_PATTERN = re.compile(
        r"""(?i)\b((?:https?|hxxps?|ftp)://[^\s<>'"()]+|(?:www\.)[^\s<>'"()]+)""",
        re.VERBOSE,
    )

    # Regex for Email addresses
    EMAIL_PATTERN = re.compile(
        r"""(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"""
    )

    # Regex for phone numbers:
    # 1. Indian numbers: +91-XXXXX-XXXXX, +91 XXXXXXXXXX, 10-digit mobile starting with 6,7,8,9
    # 2. Toll-free numbers: 1800-XXX-XXXX, 1800 XXXXXX
    # 3. International standard: +1-XXX-XXX-XXXX, +XX ...
    PHONE_CANDIDATE_PATTERN = re.compile(
        r"""(?x)
        (?:
            (?:\+91[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}\b          # Indian 10-digit mobile with optional +91
            |
            1800[\s.-]?\d{3}[\s.-]?\d{3,4}\b                  # Toll-free 1800 numbers
            |
            \+\d{1,4}[\s.-]?(?:\(?\d{2,5}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{3,5}\b # International +E.164
            |
            \(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}\b               # US format (XXX) XXX-XXXX
        )
        """
    )

    # Standalone domain pattern for domain extraction (when not prefixed by http/www)
    STANDALONE_DOMAIN_PATTERN = re.compile(
        r"""(?i)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|ai|co|xyz|info|biz|top|me|in|us|uk|ca|ru|de|fr|app|dev|link|live|club|online|site|vip|pro)\b"""
    )

    # Trailing punctuation to strip from extracted URLs/emails/phones
    TRAILING_PUNCTUATION = ".,;:!?)]}\"'>"

    @classmethod
    def clean_token(cls, token: str) -> str:
        """Strip trailing sentence punctuation often attached to tokens in raw text."""
        return token.rstrip(cls.TRAILING_PUNCTUATION)

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """Extract deduplicated URLs while preserving first occurrence order."""
        matches = cls.URL_PATTERN.findall(text)
        urls: List[str] = []
        seen: Set[str] = set()

        for match in matches:
            cleaned = cls.clean_token(match)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                urls.append(cleaned)

        return urls

    @classmethod
    def extract_domains(cls, text: str, urls: List[str]) -> List[str]:
        """Extract deduplicated lowercase domains from URLs and standalone text matches."""
        domains: List[str] = []
        seen: Set[str] = set()

        def add_domain(raw_domain: str):
            if not raw_domain:
                return
            normalized = raw_domain.replace("[.]", ".").replace("(.)", ".").lower()
            if ":" in normalized:
                normalized = normalized.split(":")[0]
            normalized = normalized.strip(".-")
            if "." in normalized and len(normalized) >= 4 and normalized not in seen:
                if not re.match(r"^[\d.]+$", normalized):
                    seen.add(normalized)
                    domains.append(normalized)

        # 1. Parse domains from extracted URLs
        for url in urls:
            try:
                parse_target = url.replace("hxxp://", "http://").replace("hxxps://", "https://")
                if not parse_target.startswith(("http://", "https://", "ftp://")):
                    parse_target = "http://" + parse_target
                parsed = urlparse(parse_target)
                if parsed.hostname:
                    add_domain(parsed.hostname)
            except Exception:
                pass

        # 2. Extract standalone domains directly from text
        standalone = cls.STANDALONE_DOMAIN_PATTERN.findall(text)
        for dom in standalone:
            cleaned = cls.clean_token(dom)
            add_domain(cleaned)

        return domains

    @classmethod
    def extract_emails(cls, text: str) -> List[str]:
        """Extract deduplicated email addresses."""
        matches = cls.EMAIL_PATTERN.findall(text)
        emails: List[str] = []
        seen: Set[str] = set()

        for match in matches:
            cleaned = cls.clean_token(match)
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                emails.append(cleaned)

        return emails

    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:
        """Extract deduplicated phone numbers, filtering out currency, dates, and OTPs."""
        matches = cls.PHONE_CANDIDATE_PATTERN.findall(text)
        phones: List[str] = []
        seen: Set[str] = set()

        for match in matches:
            cleaned = cls.clean_token(match).strip()
            digits = re.sub(r"\D", "", cleaned)
            if 7 <= len(digits) <= 15:
                if cleaned not in seen:
                    seen.add(cleaned)
                    phones.append(cleaned)

        return phones

    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        """Run all extractions and return structured dictionary."""
        urls = cls.extract_urls(text)
        domains = cls.extract_domains(text, urls)
        emails = cls.extract_emails(text)
        phones = cls.extract_phone_numbers(text)

        return {
            "urls": urls,
            "domains": domains,
            "emails": emails,
            "phone_numbers": phones,
        }
