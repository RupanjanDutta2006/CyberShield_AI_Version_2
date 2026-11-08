"""CyberShield AI — Multi-Factor Threat Reputation Assessor

Evaluates threat intelligence provider results, RFC 2606 synthetic test domain rules,
and structural domain and URL heuristics to produce a calibrated, explainable,
and evidence-grounded risk assessment.
"""

import re
from typing import Any, Dict, List
from threat_intel.normalization import DANGEROUS_TLDS, RESERVED_TLDS, RESERVED_DOMAINS
from threat_intel.schemas import AggregatedReputationAssessment, NormalizedThreatIndicator


# Authoritative known legitimate domains to prevent false-positive keyword triggers
KNOWN_LEGITIMATE_DOMAINS = {
    "google.com", "microsoft.com", "wikipedia.org", "iana.org",
    "apple.com", "github.com", "amazon.com", "cloudflare.com",
    "mozilla.org", "nist.gov", "example.com"
}

# Compound phishing and social engineering domain name patterns
COMPOUND_PHISHING_PATTERNS = [
    (
        re.compile(
            r"(?i)\b(?:account[-_]?suspended|suspended[-_]?account|account[-_]?locked|account[-_]?freeze|freeze[-_]?account|restore[-_]?account|account[-_]?restore|unblock[-_]?account|security[-_]?alert|security[-_]?check|update[-_]?kyc|kyc[-_]?update|verify[-_]?identity)\b"
        ),
        "Domain name incorporates urgent account suspension, lock, or verification lure.",
        35,
    ),
    (
        re.compile(
            r"(?i)\b(?:secure[-_]?bank|bank[-_]?verify|bank[-_]?login|banking[-_]?login|secure[-_]?login|wallet[-_]?security|secure[-_]?wallet|crypto[-_]?wallet|banking[-_]?verification|customer[-_]?login|login[-_]?verification|login[-_]?verify)\b"
        ),
        "Financial/banking and authentication lure combination in domain name typical of phishing.",
        35,
    ),
    (
        re.compile(
            r"(?i)\b(?:free[-_]?prize|prize[-_]?claim|claim[-_]?reward|reward[-_]?claim|free[-_]?reward|lottery[-_]?winner|jackpot[-_]?claim|payout[-_]?claim)\b"
        ),
        "Free reward or prize claim lure in domain name characteristic of advance-fee fraud.",
        30,
    ),
    (
        re.compile(
            r"(?i)\b(?:parcel[-_]?tracking|tracking[-_]?payment|delivery[-_]?fee|redelivery[-_]?fee|shipment[-_]?tracking|payment[-_]?verification|parcel[-_]?delivery|postal[-_]?tracking)\b"
        ),
        "Package tracking and delivery payment lure in domain name characteristic of postal scams.",
        30,
    ),
]

# Sensitive URL path patterns
SENSITIVE_PATH_PATTERNS = [
    (
        re.compile(r"(?i)/(?:restore|unblock|reactivate)(?:/|$)"),
        "URL path ('{path}') specifies an account restoration call-to-action.",
        20,
    ),
    (
        re.compile(r"(?i)/(?:reward|prize|claim|payout)(?:/|$)"),
        "URL path ('{path}') specifies a prize or reward claim call-to-action.",
        20,
    ),
    (
        re.compile(r"(?i)/(?:verify|verification|auth|authenticate|validate)(?:/|$)"),
        "URL path ('{path}') directs recipient to submit verification credentials.",
        20,
    ),
    (
        re.compile(r"(?i)/(?:login|signin|admin|portal)(?:/|$)"),
        "URL path ('{path}') targets authentication or administrative portal access.",
        15,
    ),
]

# Individual deceptive keyword tokens
SUSPICIOUS_TOKENS = [
    "bank", "banking", "secure", "security", "login", "signin", "verify",
    "verification", "wallet", "account", "suspended", "prize", "reward",
    "claim", "parcel", "tracking", "payment", "customer", "support",
    "billing", "auth", "confirm", "recover", "update", "free", "kyc"
]


class ReputationAssessor:
    """
    Evaluates threat intelligence results and structural domain heuristics to produce
    a calibrated, explainable, and multi-factor risk assessment.
    """

    @classmethod
    def evaluate(
        cls,
        target_meta: Dict[str, Any],
        indicators: List[NormalizedThreatIndicator]
    ) -> AggregatedReputationAssessment:
        evidence: List[str] = []
        recommendations: List[str] = []

        confirmed_malicious = False
        unverified_malicious = False
        clean_count = 0
        unavailable_count = 0
        not_configured_count = 0
        skipped_synthetic_count = 0

        # 1. Analyze Provider Indicators
        for ind in indicators:
            if ind.matched and ind.verified:
                confirmed_malicious = True
                threat_desc = ind.details.get("threat") or "malicious indicator"
                evidence.append(
                    f"Confirmed malicious threat detected by {ind.provider}: {threat_desc} (verified match)."
                )
            elif ind.matched and not ind.verified:
                unverified_malicious = True
                evidence.append(
                    f"Suspicious unverified report flagged by {ind.provider}."
                )
            elif ind.status == "clean":
                clean_count += 1
            elif ind.status == "not_configured":
                not_configured_count += 1
            elif ind.status == "skipped_synthetic":
                skipped_synthetic_count += 1
            elif ind.status in ["unavailable", "error"]:
                unavailable_count += 1

        # 2. Structural & Heuristic Evaluation
        hostname = (target_meta.get("hostname") or "").lower()
        domain = (target_meta.get("domain") or "").lower()
        tld = (target_meta.get("tld") or "").lower()
        is_ip = target_meta.get("is_ip_literal", False)
        port = target_meta.get("port")
        scheme = (target_meta.get("scheme") or "").lower()
        path = target_meta.get("path") or "/"
        is_synthetic = bool(
            target_meta.get("is_synthetic")
            or (tld in RESERVED_TLDS)
            or (domain in RESERVED_DOMAINS)
            or any(hostname.endswith(sfx) for sfx in [".example", ".test", ".invalid", ".localhost", ".cyber"])
        )

        # Check known legitimate whitelist
        is_known_legitimate = (
            domain in KNOWN_LEGITIMATE_DOMAINS
            or any(hostname.endswith("." + d) for d in KNOWN_LEGITIMATE_DOMAINS)
        )

        heuristic_score = 0
        heuristic_flags: List[str] = []

        if is_synthetic:
            evidence.append(
                f"Synthetic / Reserved Test Domain (RFC 2606): Destination belongs to a reserved non-routable "
                f"namespace (.{tld or 'example'}). Real-world live reputation databases do not track this namespace."
            )

        if is_known_legitimate:
            # Authoritative legitimate domain: exempt from heuristic penalty
            evidence.append(
                f"Authoritative Domain Whitelist: '{domain}' belongs to verified legitimate public infrastructure."
            )
        else:
            # 2a. IP Literal Check
            if is_ip:
                heuristic_score += 25
                heuristic_flags.append("Target uses a raw IP address literal rather than a registered domain name.")

            # 2b. High-Risk TLD Check
            if tld in DANGEROUS_TLDS:
                heuristic_score += 20
                heuristic_flags.append(f"Top-Level Domain (.{tld}) is categorized as high-risk / frequently abused.")

            # 2c. Non-Standard Port Check
            if port and port not in [80, 443]:
                heuristic_score += 15
                heuristic_flags.append(f"Destination operates on non-standard web port ({port}).")

            # 2d. Compound Phishing Pattern Checks (Domain + Subdomains)
            host_to_check = hostname
            compound_matched = False
            for pat, desc, weight in COMPOUND_PHISHING_PATTERNS:
                if pat.search(host_to_check):
                    heuristic_score += weight
                    heuristic_flags.append(desc)
                    compound_matched = True

            # 2e. Co-occurring Keyword Token Check
            found_tokens = [tok for tok in SUSPICIOUS_TOKENS if tok in host_to_check]
            if len(found_tokens) >= 3:
                heuristic_score += 25
                heuristic_flags.append(
                    f"Domain name co-locates multiple phishing/lure keywords ('{', '.join(found_tokens[:4])}')."
                )
            elif len(found_tokens) >= 2 and not compound_matched:
                token_weight = min(40, len(found_tokens) * 15)
                heuristic_score += token_weight
                heuristic_flags.append(
                    f"Domain name co-locates {len(found_tokens)} distinct social engineering/phishing keywords "
                    f"('{', '.join(found_tokens[:4])}')."
                )

            # 2f. URL Path Analysis
            for p_pat, p_desc, p_weight in SENSITIVE_PATH_PATTERNS:
                if p_pat.search(path):
                    heuristic_score += p_weight
                    formatted_desc = p_desc.format(path=path)
                    heuristic_flags.append(formatted_desc)
                    break

            # 2g. Unencrypted HTTP for Sensitive Context
            if scheme == "http" and (heuristic_score > 0 or any(tok in host_to_check for tok in ["bank", "wallet", "login", "verify", "pay", "account"])):
                heuristic_score += 25
                heuristic_flags.append(
                    "Unencrypted HTTP connection utilized for sensitive authentication, banking, or account operations, exposing data to interception."
                )

        evidence.extend(heuristic_flags)

        # 3. Calibrated Risk Level Determination
        risk_score = 0
        risk_level = "Unknown"

        if confirmed_malicious:
            risk_level = "Critical"
            risk_score = max(90, min(100, 90 + (heuristic_score // 3)))
            summary = "Confirmed active malicious destination verified by threat intelligence feeds."
            recommendations.extend([
                "DO NOT visit, interact with, or enter credentials on this destination.",
                f"Immediately block the domain '{target_meta.get('domain')}' on network firewalls and DNS sinks.",
                "If credentials or payment information was entered previously, immediately trigger incident response."
            ])
        elif unverified_malicious:
            risk_level = "High"
            risk_score = max(70, min(89, 70 + (heuristic_score // 3)))
            summary = "Suspicious destination flagged in threat databases with unverified malicious signals."
            recommendations.extend([
                "Treat destination as hostile and avoid browsing.",
                "Add destination to security monitoring and quarantine incoming communications containing it."
            ])
        elif is_known_legitimate:
            risk_level = "Low"
            risk_score = 5
            summary = f"Verified legitimate public infrastructure for authoritative domain ({domain})."
            recommendations.extend([
                "Target belongs to verified legitimate organizational infrastructure.",
                "Maintain standard digital hygiene when browsing."
            ])
        elif is_synthetic:
            # Synthetic / Reserved test domain
            if heuristic_score >= 50:
                risk_level = "Critical" if heuristic_score >= 80 else "High"
                risk_score = min(95, max(70, heuristic_score + 10))
                ind_summary = ", ".join(heuristic_flags[:2]) if heuristic_flags else "phishing heuristics"
                summary = (
                    f"Synthetic / Reserved Test Domain (RFC 2606): Target exhibits high-risk deceptive lures: {ind_summary}. "
                    f"Real-world blacklist feeds do not track this namespace."
                )
                recommendations.extend([
                    "This destination is a synthetic / documentation test domain (.example); real-world reputation databases do not track it.",
                    "The domain and URL structure mirror active credential theft, banking impersonation, or advance-fee scams.",
                    "Do not enter credentials or follow links mimicking this format."
                ])
            elif heuristic_score >= 20:
                risk_level = "Medium"
                risk_score = min(65, max(45, heuristic_score + 15))
                summary = (
                    f"Synthetic / Reserved Test Domain (RFC 2606): Moderate deceptive heuristic indicators detected. "
                    f"Real-world reputation cannot be established."
                )
                recommendations.extend([
                    "Synthetic test destination displays suspicious structural patterns.",
                    "Verify target source before proceeding."
                ])
            else:
                risk_level = "Low"
                risk_score = 5
                summary = "Synthetic / Reserved Test Domain (RFC 2606): Documentation baseline sample with zero adverse indicators."
                recommendations.extend([
                    "Standard RFC 2606 reserved documentation destination (.example).",
                    "No adverse structural anomalies or phishing keywords detected."
                ])
        elif heuristic_score >= 60:
            risk_level = "High"
            risk_score = min(88, heuristic_score + 25)
            summary = "High-risk heuristic indicators detected despite no confirmed vendor blacklist match."
            recommendations.extend([
                "Exercise extreme caution; destination displays classic deceptive infrastructure patterns.",
                "Verify legitimacy of sender through independent out-of-band communication before proceeding."
            ])
        elif heuristic_score >= 20:
            risk_level = "Medium"
            risk_score = min(65, heuristic_score + 25)
            summary = "Moderate risk indicators detected. The target exhibits suspicious characteristics."
            recommendations.extend([
                "Verify whether you intended to visit this specific domain and inspect SSL certificate details.",
                "Do not authenticate or download attachments until origin is verified."
            ])
        elif clean_count > 0:
            # Clean results from at least one live provider with zero heuristic red flags
            risk_level = "Low"
            risk_score = 10
            summary = "No threat intelligence matches or structural anomalies detected."
            recommendations.extend([
                "No known threat signatures detected across checked intelligence databases.",
                "Maintain standard security hygiene: confirm identity before submitting sensitive data."
            ])
        else:
            # All providers unavailable / unconfigured and no heuristics fired
            risk_level = "Low"
            risk_score = 15
            summary = "Incomplete assessment: External threat intelligence providers were unavailable or unconfigured. No structural anomalies detected in target syntax."
            recommendations.extend([
                "Configure external API keys (URLhaus, PhishTank) to enable authoritative threat intelligence feeds.",
                "Do not assume the destination is safe merely because threat data was inaccessible."
            ])

        return AggregatedReputationAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            summary=summary,
            evidence=evidence,
            recommendations=recommendations,
            indicators=indicators
        )
