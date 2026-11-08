import re
from typing import Dict, List
from threat_intel.normalization import DANGEROUS_TLDS
from threat_intel.schemas import AggregatedReputationAssessment, NormalizedThreatIndicator


SUSPICIOUS_KEYWORD_PATTERNS = [
    r"login", r"signin", r"verify", r"secure", r"update", r"account",
    r"banking", r"wallet", r"support", r"billing", r"auth", r"confirm",
    r"recover", r"passcode", r"credential"
]


class ReputationAssessor:
    """
    Evaluates threat intelligence results and structural domain heuristics to produce
    a calibrated, explainable, and multi-factor risk assessment.
    """

    @classmethod
    def evaluate(
        cls,
        target_meta: Dict[str, any],
        indicators: List[NormalizedThreatIndicator]
    ) -> AggregatedReputationAssessment:
        evidence: List[str] = []
        recommendations: List[str] = []

        confirmed_malicious = False
        unverified_malicious = False
        clean_count = 0
        unavailable_count = 0
        not_configured_count = 0

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
            elif ind.status in ["unavailable", "error"]:
                unavailable_count += 1

        # 2. Structural & Heuristic Evaluation
        hostname = target_meta.get("hostname", "")
        tld = target_meta.get("tld", "").lower()
        is_ip = target_meta.get("is_ip_literal", False)
        port = target_meta.get("port")

        heuristic_score = 0
        heuristic_flags: List[str] = []

        if is_ip:
            heuristic_score += 25
            heuristic_flags.append("Target uses a raw IP address literal rather than a registered domain name.")

        if tld in DANGEROUS_TLDS:
            heuristic_score += 20
            heuristic_flags.append(f"Top-Level Domain (.{tld}) is categorized as high-risk / frequently abused.")

        if port and port not in [80, 443]:
            heuristic_score += 15
            heuristic_flags.append(f"Destination operates on non-standard web port ({port}).")

        # Brand / phishing keyword detection in subdomain
        subdomains = hostname.split(".")
        if len(subdomains) > 2:
            subdomain_prefix = ".".join(subdomains[:-2]).lower()
            for pattern in SUSPICIOUS_KEYWORD_PATTERNS:
                if re.search(r"\b" + pattern + r"\b", subdomain_prefix) or pattern in subdomain_prefix:
                    heuristic_score += 20
                    heuristic_flags.append(
                        f"Subdomain contains authentication/security keyword ('{pattern}') indicating possible spoofing."
                    )
                    break

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
        elif heuristic_score >= 40:
            risk_level = "High"
            risk_score = min(85, heuristic_score + 35)
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
            # No providers returned clean (all were not_configured or unavailable) and no heuristics fired
            risk_level = "Unknown"
            risk_score = 0
            summary = "Incomplete assessment: External threat intelligence providers were unavailable or unconfigured."
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
