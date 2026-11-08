"""CyberShield AI — Part 08: Suspicious URL Pattern Detection

Implements deterministic heuristic pattern analysis for URLs.
Detects structural anomalies, excessive subdomain nesting, direct IP hostnames,
deceptive brand/security keywords, Cyrillic/mixed-script homographs, Punycode indicators,
suspicious percent-encodings, open redirect parameters, non-standard ports, and URL shorteners.
Returns standardized TechnicalFinding models without relying on external APIs or AI.
"""

import re
import urllib.parse
from typing import List, Optional, Set
import idna

from app.schemas.common import TechnicalFinding, FindingSeverity
from app.schemas.url_scan import URLValidationResult, URLNormalizationResult

# Common brand and security-sensitive keywords often leveraged in phishing links
PHISHING_KEYWORDS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "security", "update", "banking", "secure", "wallet",
    "support", "confirm", "confirmation", "auth", "authenticate",
    "password", "credential", "recover", "recovery", "validation",
}

# Known public URL shortening services
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "bl.ink", "tiny.cc",
    "shorturl.at", "soo.gd", "s.id", "v.gd", "t.ly",
}

# Open redirect parameter names commonly abused in phishing and OAuth bypasses
REDIRECT_PARAMS: Set[str] = {
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_to", "next", "target", "dest", "destination", "goto",
    "r", "u", "link", "forward",
}

# Standard HTTP/HTTPS ports
STANDARD_PORTS = {80, 443, 8080, 8443}

# Cyrillic letters commonly used in Latin lookalike homograph attacks
CYRILLIC_LOOKALIKES = {
    '\u0430', '\u0435', '\u043e', '\u0440', '\u0441', '\u0443', '\u0445',
    '\u0456', '\u0458', '\u0455', '\u0410', '\u0412', '\u0415', '\u041a',
    '\u041c', '\u041d', '\u041e', '\u0420', '\u0421', '\u0422', '\u0423', '\u0425'
}


def detect_ip_hostname(hostname: str) -> Optional[TechnicalFinding]:
    """Check if the hostname is a raw IP address."""
    clean = hostname.strip().strip("[]").rstrip(".")
    # IPv4 regex or IPv6 colon
    if ":" in clean or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean):
        return TechnicalFinding(
            module="url_investigation",
            check_name="SUSPICIOUS_IP_HOST",
            severity=FindingSeverity.MEDIUM,
            title="Direct IP Address Hostname",
            description="The URL uses a raw IP address as its hostname rather than a domain name. Phishing and malicious links frequently use bare IPs to evade domain reputation filters.",
            evidence={"hostname": hostname},
            remediation="Verify the legitimate domain of the service before entering credentials or submitting sensitive information."
        )
    return None


def detect_excessive_subdomains(hostname: str) -> Optional[TechnicalFinding]:
    """Check for excessive subdomain depth."""
    clean = hostname.strip().rstrip(".")
    if ":" in clean or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean):
        return None

    labels = clean.split(".")
    # If more than 4 labels (e.g., a.b.c.example.com has 5 labels, depth 3)
    if len(labels) > 4:
        subdomains = labels[:-2]  # Exclude eTLD+1 approximation
        return TechnicalFinding(
            module="url_investigation",
            check_name="EXCESSIVE_SUBDOMAIN_DEPTH",
            severity=FindingSeverity.LOW,
            title="Excessive Subdomain Nesting",
            description=f"The domain contains {len(labels)} nested labels ({len(subdomains)} subdomains). Deeply nested subdomains are often created on dynamic DNS or free hosting services to disguise actual destinations.",
            evidence={
                "hostname": hostname,
                "label_count": len(labels),
                "subdomains": subdomains
            },
            remediation="Inspect the rightmost registrable domain to verify the actual domain owner."
        )
    return None


def detect_deceptive_keywords(hostname: str, path: str) -> Optional[TechnicalFinding]:
    """Detect security and authentication keywords in subdomains or paths."""
    clean_host = hostname.strip().rstrip(".").lower()
    clean_path = path.lower() if path else ""

    host_labels = clean_host.split(".")
    # Check subdomains (labels prior to registrable domain)
    subdomain_parts = host_labels[:-2] if len(host_labels) > 2 else []

    found_keywords = []
    # Check in subdomains
    for part in subdomain_parts:
        for kw in PHISHING_KEYWORDS:
            if kw in part and kw not in found_keywords:
                found_keywords.append(kw)

    # Check path tokens
    path_tokens = re.split(r"[/_\-\.\?&=]", clean_path)
    for token in path_tokens:
        if token in PHISHING_KEYWORDS and token not in found_keywords:
            found_keywords.append(token)

    if found_keywords:
        return TechnicalFinding(
            module="url_investigation",
            check_name="DECEPTIVE_BRAND_KEYWORDS",
            severity=FindingSeverity.MEDIUM,
            title="Security / Authentication Keyword Detected",
            description=f"The URL contains sensitive authentication or verification keywords ({', '.join(found_keywords)}) in its subdomains or path. This pattern is commonly observed in deceptive phishing lures.",
            evidence={
                "matched_keywords": found_keywords,
                "hostname": hostname,
                "path": path
            },
            remediation="Ensure you are on the official primary website before providing authentication tokens, passwords, or personal data."
        )
    return None


def detect_homograph_and_punycode(hostname: str, unicode_host: Optional[str]) -> Optional[TechnicalFinding]:
    """Detect Punycode usage and mixed-script Cyrillic homograph lookalikes."""
    clean = hostname.strip().rstrip(".").lower()

    is_puny = clean.startswith("xn--") or ".xn--" in clean
    has_cyrillic = False
    cyrillic_chars = []

    target_for_chars = unicode_host or clean
    for c in target_for_chars:
        if c in CYRILLIC_LOOKALIKES:
            has_cyrillic = True
            cyrillic_chars.append(f"{c} (U+{ord(c):04X})")

    # If mixed script Cyrillic lookalikes are detected
    if has_cyrillic:
        return TechnicalFinding(
            module="url_investigation",
            check_name="HOMOGRAPH_LOOKALIKE_DETECTED",
            severity=FindingSeverity.HIGH,
            title="Internationalized Homograph / Lookalike Attack Indicator",
            description="The domain contains Cyrillic or non-Latin lookalike characters that visually mimic Latin letters. This technique is commonly used in brand impersonation and spoofing attacks.",
            evidence={
                "hostname": hostname,
                "unicode_representation": unicode_host,
                "detected_lookalikes": cyrillic_chars
            },
            remediation="Do not trust the visual appearance of this link. It uses lookalike characters to impersonate another domain."
        )

    # If Punycode is used without Cyrillic lookalikes
    if is_puny:
        return TechnicalFinding(
            module="url_investigation",
            check_name="PUNYCODE_DOMAIN_INDICATOR",
            severity=FindingSeverity.LOW,
            title="Internationalized Punycode Domain",
            description=f"The domain uses an internationalized Punycode encoding ({clean}). While legitimate for non-Latin languages, Punycode domains should be inspected carefully for visual deception.",
            evidence={
                "punycode_hostname": clean,
                "decoded_unicode": unicode_host
            },
            remediation="Inspect the decoded Unicode representation to ensure the domain matches your intended destination."
        )

    return None


def detect_suspicious_encoding(raw_url: str) -> Optional[TechnicalFinding]:
    """Detect suspicious percent-encodings, multiple encodings, or null bytes."""
    clean = raw_url.lower()

    suspicious_items = []
    # Null byte injection
    if "%00" in clean:
        suspicious_items.append("Null byte (%00)")

    # Percent-encoded path separators
    if "%2f" in clean:
        suspicious_items.append("Percent-encoded forward slash (%2f)")
    if "%5c" in clean:
        suspicious_items.append("Percent-encoded backslash (%5c)")

    # Double encoding check (e.g. %252f, %253f)
    if "%25" in clean:
        suspicious_items.append("Double percent encoding (%25)")

    if suspicious_items:
        return TechnicalFinding(
            module="url_investigation",
            check_name="SUSPICIOUS_PERCENT_ENCODING",
            severity=FindingSeverity.HIGH,
            title="Suspicious Character Encoding / Traversal Bypass",
            description="The URL contains encoded path delimiters, null bytes, or double percent-encodings frequently used to bypass Web Application Firewalls (WAF) and path filters.",
            evidence={"suspicious_encodings": suspicious_items},
            remediation="Avoid following links containing obfuscated path delimiters or double percent-encoding."
        )
    return None


def detect_open_redirect_parameters(query_str: Optional[str]) -> Optional[TechnicalFinding]:
    """Detect query parameters that reference external URLs."""
    if not query_str:
        return None

    try:
        params = urllib.parse.parse_qs(query_str, keep_blank_values=False)
    except Exception:
        return None

    flagged_params = []
    for key, values in params.items():
        if key.lower() in REDIRECT_PARAMS:
            for val in values:
                val_lower = val.lower().strip()
                if val_lower.startswith("http:") or val_lower.startswith("https:") or val_lower.startswith("//"):
                    flagged_params.append({
                        "parameter": key,
                        "target_value": val[:64] + ("..." if len(val) > 64 else "")
                    })

    if flagged_params:
        return TechnicalFinding(
            module="url_investigation",
            check_name="SUSPICIOUS_OPEN_REDIRECT_PARAM",
            severity=FindingSeverity.MEDIUM,
            title="Potential Open Redirect Parameter",
            description="The URL contains query parameters referencing external destinations (e.g. url=, redirect=, next=). Attackers often exploit legitimate sites with open redirects to redirect victims to malicious destinations.",
            evidence={"redirect_parameters": flagged_params},
            remediation="Verify whether the site is legitimately configured or being abused as an unvalidated redirect intermediary."
        )
    return None


def detect_non_standard_port(port: Optional[int]) -> Optional[TechnicalFinding]:
    """Detect unusual or high-risk non-standard ports."""
    if port is not None and port not in STANDARD_PORTS:
        return TechnicalFinding(
            module="url_investigation",
            check_name="UNUSUAL_PORT_SPECIFIED",
            severity=FindingSeverity.LOW,
            title=f"Non-Standard Service Port ({port})",
            description=f"The URL targets a non-standard port ({port}) rather than conventional web ports (80, 443). Suspicious services and C2 infrastructure often operate on non-standard ports.",
            evidence={"port": port},
            remediation="Confirm whether the intended service is expected to run on this non-standard port."
        )
    return None


def detect_url_shortener(registrable_domain: Optional[str]) -> Optional[TechnicalFinding]:
    """Check if the domain belongs to a recognized URL shortener."""
    if registrable_domain and registrable_domain.lower() in URL_SHORTENERS:
        return TechnicalFinding(
            module="url_investigation",
            check_name="KNOWN_URL_SHORTENER",
            severity=FindingSeverity.INFO,
            title="URL Shortening Service Detected",
            description=f"The domain '{registrable_domain}' is a recognized URL shortening service. Shortened links obscure the final destination until resolved.",
            evidence={"shortener_domain": registrable_domain},
            remediation="Expand the shortened link safely before proceeding to ensure the final destination is legitimate."
        )
    return None


def detect_excessive_length(url_length: int, path_length: int) -> Optional[TechnicalFinding]:
    """Detect unusually long URLs often associated with phishing token stuffing."""
    if url_length > 120 or path_length > 80:
        return TechnicalFinding(
            module="url_investigation",
            check_name="EXCESSIVE_URL_LENGTH",
            severity=FindingSeverity.LOW,
            title="Unusually Long URL Structure",
            description=f"The URL has an unusually long structure (total length: {url_length}, path length: {path_length}). Attackers often use extensive padding to push malicious domains out of view in mobile address bars.",
            evidence={"url_length": url_length, "path_length": path_length},
            remediation="Examine the full destination domain on a desktop browser or inspect the decoded components."
        )
    return None


def detect_suspicious_patterns(
    validation: URLValidationResult,
    normalization: Optional[URLNormalizationResult] = None
) -> List[TechnicalFinding]:
    """Execute all deterministic suspicious pattern checks against validated URL data.
    
    Args:
        validation: Result from Part 05 intake validation.
        normalization: Result from Part 06 canonical normalization (if available).
        
    Returns:
        List of TechnicalFinding items for each detected heuristic indicator.
    """
    findings: List[TechnicalFinding] = []

    # 1. Embedded Credentials Indicator (from Part 05)
    if validation.has_credentials:
        findings.append(
            TechnicalFinding(
                module="url_investigation",
                check_name="DECEPTIVE_AUTHORITY_CREDENTIALS",
                severity=FindingSeverity.HIGH,
                title="Deceptive Credentials in URL Authority",
                description="The URL contains embedded user credentials (@ symbol in authority). This is a well-known deceptive technique used to spoof legitimate domains (e.g. http://paypal.com@attacker.com).",
                evidence={"sanitized_input": validation.sanitized_input},
                remediation="Do not access URLs containing credentials in the authority segment."
            )
        )

    # 2. Suspicious Percent Encoding in raw input
    encoding_finding = detect_suspicious_encoding(validation.raw_input)
    if encoding_finding:
        findings.append(encoding_finding)

    # If normalization was performed, check structural properties
    if normalization:
        # 3. IP Hostname
        ip_finding = detect_ip_hostname(normalization.hostname)
        if ip_finding:
            findings.append(ip_finding)

        # 4. Excessive Subdomain Depth
        subdomain_finding = detect_excessive_subdomains(normalization.hostname)
        if subdomain_finding:
            findings.append(subdomain_finding)

        # 5. Deceptive Keywords
        keyword_finding = detect_deceptive_keywords(normalization.hostname, normalization.path)
        if keyword_finding:
            findings.append(keyword_finding)

        # 6. Homograph / Lookalike / Punycode
        homograph_finding = detect_homograph_and_punycode(normalization.hostname, normalization.unicode_hostname)
        if homograph_finding:
            findings.append(homograph_finding)

        # 7. Non-Standard Port
        port_finding = detect_non_standard_port(normalization.port)
        if port_finding:
            findings.append(port_finding)

        # 8. Open Redirect Parameters
        redirect_finding = detect_open_redirect_parameters(normalization.query)
        if redirect_finding:
            findings.append(redirect_finding)

        # 9. Known URL Shortener
        shortener_finding = detect_url_shortener(normalization.registrable_domain)
        if shortener_finding:
            findings.append(shortener_finding)

        # 10. Excessive Length
        length_finding = detect_excessive_length(len(normalization.normalized_url), len(normalization.path))
        if length_finding:
            findings.append(length_finding)

    return findings

