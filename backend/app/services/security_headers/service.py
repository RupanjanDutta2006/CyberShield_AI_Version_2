"""CyberShield AI — Part 12: HTTP Security Headers Analysis Service

Passively evaluates HTTP response headers for defensive web security signals:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Information leakage via Server / X-Powered-By banners
"""

import re
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List, Callable
import httpx

from app.schemas.common import TechnicalFinding, TechnicalLimitation, FindingSeverity
from app.services.security_headers.models import (
    HeaderEvaluationStatus,
    SingleHeaderAnalysis,
    SecurityHeaderAnalysisResult,
)
from app.services.url_investigation.ssrf_guard import (
    validate_destination_safety,
    parse_ip_safely,
    evaluate_ip_safety,
)
from app.services.redirects.transport import PinnedHTTPTransport


def evaluate_hsts(header_val: Optional[str], is_https: bool) -> Tuple[SingleHeaderAnalysis, Optional[TechnicalFinding]]:
    """Evaluate Strict-Transport-Security header."""
    if not header_val:
        status = HeaderEvaluationStatus.MISSING
        finding = None
        if is_https:
            finding = TechnicalFinding(
                module="security_headers",
                check_name="MISSING_HSTS_HEADER",
                severity=FindingSeverity.LOW,
                title="Strict-Transport-Security Header Missing",
                description="The HTTPS endpoint does not provide an HSTS header, allowing potential SSL-stripping man-in-the-middle attacks.",
                evidence={"header": "Strict-Transport-Security", "is_https": is_https},
                remediation="Configure Strict-Transport-Security with max-age>=31536000 and includeSubDomains."
            )
        return SingleHeaderAnalysis(
            header_name="Strict-Transport-Security",
            status=status,
            is_present=False,
            explanation="Header not provided in HTTP response."
        ), finding

    val = header_val.strip()
    directives = {}
    for part in val.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip().lower()] = v.strip().strip('"')
        elif part:
            directives[part.lower()] = True

    max_age_str = directives.get("max-age")
    try:
        max_age = int(max_age_str) if max_age_str is not None else None
    except ValueError:
        max_age = None

    if max_age is None:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="MALFORMED_HSTS_HEADER",
            severity=FindingSeverity.LOW,
            title="Malformed HSTS Header",
            description=f"HSTS header '{val}' is missing a valid numeric max-age directive.",
            evidence={"raw_value": val},
            remediation="Ensure max-age directive contains a valid integer number of seconds."
        )
        return SingleHeaderAnalysis(
            header_name="Strict-Transport-Security",
            status=HeaderEvaluationStatus.MALFORMED,
            is_present=True,
            raw_value=val,
            explanation="Missing valid numeric max-age parameter.",
            details=directives
        ), finding

    # Weak if less than ~126 days (10886400 seconds)
    if max_age < 10886400:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="WEAK_HSTS_MAX_AGE",
            severity=FindingSeverity.INFO,
            title="Short HSTS max-age Duration",
            description=f"HSTS max-age ({max_age}s) is shorter than recommended industry baseline (>= 31536000s / 1 year).",
            evidence={"max_age": max_age},
            remediation="Increase max-age to at least 31536000 seconds."
        )
        return SingleHeaderAnalysis(
            header_name="Strict-Transport-Security",
            status=HeaderEvaluationStatus.WEAK,
            is_present=True,
            raw_value=val,
            explanation=f"HSTS duration ({max_age}s) is short.",
            details=directives
        ), finding

    return SingleHeaderAnalysis(
        header_name="Strict-Transport-Security",
        status=HeaderEvaluationStatus.VALID,
        is_present=True,
        raw_value=val,
        explanation="Robust HSTS configuration present.",
        details=directives
    ), None


def evaluate_csp(header_val: Optional[str]) -> Tuple[SingleHeaderAnalysis, Optional[TechnicalFinding]]:
    """Evaluate Content-Security-Policy header."""
    if not header_val:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="MISSING_CSP_HEADER",
            severity=FindingSeverity.LOW,
            title="Content-Security-Policy Header Missing",
            description="The response lacks a Content-Security-Policy header, reducing defense-in-depth against cross-site scripting (XSS) and code injection.",
            evidence={"header": "Content-Security-Policy"},
            remediation="Deploy a Content-Security-Policy restricting authorized script and object sources."
        )
        return SingleHeaderAnalysis(
            header_name="Content-Security-Policy",
            status=HeaderEvaluationStatus.MISSING,
            is_present=False,
            explanation="Header not provided in HTTP response."
        ), finding

    val = header_val.strip()
    directives: Dict[str, List[str]] = {}
    for part in val.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    # Check for weak or dangerous CSP keywords
    weak_indicators = []
    val_lower = val.lower()
    if "'unsafe-inline'" in val_lower:
        weak_indicators.append("'unsafe-inline'")
    if "'unsafe-eval'" in val_lower:
        weak_indicators.append("'unsafe-eval'")
    if "data:" in val_lower and ("script-src" in directives or "default-src" in directives):
        weak_indicators.append("data: in script sources")

    if weak_indicators:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="WEAK_CSP_CONFIGURATION",
            severity=FindingSeverity.LOW,
            title="Weak Content-Security-Policy Directives",
            description=f"CSP contains permissive keywords ({', '.join(weak_indicators)}) that weaken protection against script injection.",
            evidence={"weak_directives": weak_indicators, "raw_csp": val[:128]},
            remediation="Replace 'unsafe-inline' and 'unsafe-eval' with nonces or cryptographic hashes."
        )
        return SingleHeaderAnalysis(
            header_name="Content-Security-Policy",
            status=HeaderEvaluationStatus.WEAK,
            is_present=True,
            raw_value=val,
            explanation=f"Permissive directives detected: {', '.join(weak_indicators)}.",
            details={"directives": list(directives.keys()), "weak_indicators": weak_indicators}
        ), finding

    return SingleHeaderAnalysis(
        header_name="Content-Security-Policy",
        status=HeaderEvaluationStatus.VALID,
        is_present=True,
        raw_value=val,
        explanation="Content-Security-Policy present with restrictive source boundaries.",
        details={"directives": list(directives.keys())}
    ), None


def evaluate_x_content_type_options(header_val: Optional[str]) -> Tuple[SingleHeaderAnalysis, Optional[TechnicalFinding]]:
    """Evaluate X-Content-Type-Options header."""
    if not header_val:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="MISSING_X_CONTENT_TYPE_OPTIONS",
            severity=FindingSeverity.INFO,
            title="X-Content-Type-Options Header Missing",
            description="The X-Content-Type-Options header is absent, allowing legacy browsers to MIME-sniff responses away from the declared Content-Type.",
            evidence={"header": "X-Content-Type-Options"},
            remediation="Set 'X-Content-Type-Options: nosniff'."
        )
        return SingleHeaderAnalysis(
            header_name="X-Content-Type-Options",
            status=HeaderEvaluationStatus.MISSING,
            is_present=False,
            explanation="Header missing."
        ), finding

    val = header_val.strip().lower()
    if val == "nosniff":
        return SingleHeaderAnalysis(
            header_name="X-Content-Type-Options",
            status=HeaderEvaluationStatus.VALID,
            is_present=True,
            raw_value=header_val.strip(),
            explanation="Correctly configured to 'nosniff'."
        ), None

    finding = TechnicalFinding(
        module="security_headers",
        check_name="MALFORMED_X_CONTENT_TYPE_OPTIONS",
        severity=FindingSeverity.INFO,
        title="Non-Standard X-Content-Type-Options Value",
        description=f"Expected 'nosniff', observed '{header_val.strip()}'.",
        evidence={"observed": header_val.strip()},
        remediation="Ensure X-Content-Type-Options is set strictly to 'nosniff'."
    )
    return SingleHeaderAnalysis(
        header_name="X-Content-Type-Options",
        status=HeaderEvaluationStatus.MALFORMED,
        is_present=True,
        raw_value=header_val.strip(),
        explanation=f"Non-standard value '{header_val.strip()}'."
    ), finding


def evaluate_x_frame_options(header_val: Optional[str]) -> Tuple[SingleHeaderAnalysis, Optional[TechnicalFinding]]:
    """Evaluate X-Frame-Options header."""
    if not header_val:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="MISSING_X_FRAME_OPTIONS",
            severity=FindingSeverity.LOW,
            title="X-Frame-Options Header Missing",
            description="The response lacks an X-Frame-Options header to protect against UI redressing and clickjacking.",
            evidence={"header": "X-Frame-Options"},
            remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        )
        return SingleHeaderAnalysis(
            header_name="X-Frame-Options",
            status=HeaderEvaluationStatus.MISSING,
            is_present=False,
            explanation="Header missing."
        ), finding

    val = header_val.strip().upper()
    if val in ("DENY", "SAMEORIGIN"):
        return SingleHeaderAnalysis(
            header_name="X-Frame-Options",
            status=HeaderEvaluationStatus.VALID,
            is_present=True,
            raw_value=header_val.strip(),
            explanation=f"Valid framing protection directive '{val}'."
        ), None

    finding = TechnicalFinding(
        module="security_headers",
        check_name="WEAK_X_FRAME_OPTIONS",
        severity=FindingSeverity.INFO,
        title="Unusual or Deprecated X-Frame-Options Directive",
        description=f"Observed '{header_val.strip()}'. Directives like ALLOW-FROM are deprecated in modern browsers.",
        evidence={"observed": header_val.strip()},
        remediation="Use 'DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors'."
    )
    return SingleHeaderAnalysis(
        header_name="X-Frame-Options",
        status=HeaderEvaluationStatus.WEAK,
        is_present=True,
        raw_value=header_val.strip(),
        explanation=f"Non-standard or deprecated directive '{header_val.strip()}'."
    ), finding


def evaluate_referrer_policy(header_val: Optional[str]) -> Tuple[SingleHeaderAnalysis, Optional[TechnicalFinding]]:
    """Evaluate Referrer-Policy header."""
    if not header_val:
        return SingleHeaderAnalysis(
            header_name="Referrer-Policy",
            status=HeaderEvaluationStatus.MISSING,
            is_present=False,
            explanation="Header missing; browser defaults apply."
        ), None

    val = header_val.strip().lower()
    if "unsafe-url" in val:
        finding = TechnicalFinding(
            module="security_headers",
            check_name="INSECURE_REFERRER_POLICY",
            severity=FindingSeverity.LOW,
            title="Insecure Referrer-Policy Configured",
            description="Referrer-Policy is set to 'unsafe-url', which leaks sensitive full URL paths and query parameters to third-party referrers.",
            evidence={"policy": val},
            remediation="Use 'strict-origin-when-cross-origin' or 'no-referrer'."
        )
        return SingleHeaderAnalysis(
            header_name="Referrer-Policy",
            status=HeaderEvaluationStatus.WEAK,
            is_present=True,
            raw_value=header_val.strip(),
            explanation="Policy contains 'unsafe-url', which leaks sensitive path tokens."
        ), finding

    return SingleHeaderAnalysis(
        header_name="Referrer-Policy",
        status=HeaderEvaluationStatus.VALID,
        is_present=True,
        raw_value=header_val.strip(),
        explanation=f"Safe Referrer-Policy directive '{val}'."
    ), None


def evaluate_server_banner(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[TechnicalFinding]]:
    """Detect information disclosure in Server or X-Powered-By banners."""
    server = headers.get("server") or headers.get("Server")
    powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")

    combined_parts = []
    if server:
        combined_parts.append(f"Server: {server}")
    if powered_by:
        combined_parts.append(f"X-Powered-By: {powered_by}")

    if not combined_parts:
        return None, None

    banner_str = "; ".join(combined_parts)
    # Check if granular version digits are disclosed (e.g. Apache/2.4.41, nginx/1.18.0, PHP/7.4)
    if re.search(r"/\d+\.\d+", banner_str):
        finding = TechnicalFinding(
            module="security_headers",
            check_name="VERBOSE_SERVER_BANNER_DISCLOSED",
            severity=FindingSeverity.INFO,
            title="Verbose Server Version Disclosed",
            description=f"Response discloses specific software version banner: {banner_str}. This assists attackers in identifying version-specific CVEs.",
            evidence={"banner": banner_str},
            remediation="Suppress or sanitize server version banners in web server configuration."
        )
        return banner_str, finding

    return banner_str, None


def analyze_security_headers_from_dict(
    headers: Dict[str, str],
    url: str = "",
    status_code: int = 200
) -> SecurityHeaderAnalysisResult:
    """Analyze a dictionary of HTTP headers passively."""
    is_https = url.lower().startswith("https:")
    findings: List[TechnicalFinding] = []

    # Case-insensitive header lookup dict
    h_lower = {k.lower(): v for k, v in headers.items()}

    hsts_val = h_lower.get("strict-transport-security")
    csp_val = h_lower.get("content-security-policy")
    xcto_val = h_lower.get("x-content-type-options")
    xfo_val = h_lower.get("x-frame-options")
    rp_val = h_lower.get("referrer-policy")

    hsts_res, hsts_find = evaluate_hsts(hsts_val, is_https)
    if hsts_find:
        findings.append(hsts_find)

    csp_res, csp_find = evaluate_csp(csp_val)
    if csp_find:
        findings.append(csp_find)

    xcto_res, xcto_find = evaluate_x_content_type_options(xcto_val)
    if xcto_find:
        findings.append(xcto_find)

    xfo_res, xfo_find = evaluate_x_frame_options(xfo_val)
    if xfo_find:
        findings.append(xfo_find)

    rp_res, rp_find = evaluate_referrer_policy(rp_val)
    if rp_find:
        findings.append(rp_find)

    banner, banner_find = evaluate_server_banner(headers)
    if banner_find:
        findings.append(banner_find)

    # Collect other interesting security headers
    additional = {}
    for interesting in ("permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy"):
        if interesting in h_lower:
            additional[interesting] = h_lower[interesting]

    return SecurityHeaderAnalysisResult(
        target_url=url,
        status_code=status_code,
        is_reachable=True,
        hsts=hsts_res,
        csp=csp_res,
        x_content_type_options=xcto_res,
        x_frame_options=xfo_res,
        referrer_policy=rp_res,
        server_banner=banner,
        additional_headers=additional,
        findings=findings
    )


def fetch_and_analyze_security_headers(
    url: str,
    pinned_ip: Optional[str] = None,
    timeout: float = 3.0,
    client_factory: Optional[Callable[[str], httpx.Client]] = None
) -> SecurityHeaderAnalysisResult:
    """Fetch HTTP response headers securely using IP pinning and analyze them."""
    if pinned_ip:
        parsed_pinned = parse_ip_safely(pinned_ip)
        if parsed_pinned is None or not evaluate_ip_safety(parsed_pinned)[0]:
            dummy_h = SingleHeaderAnalysis(header_name="unavailable", status=HeaderEvaluationStatus.UNAVAILABLE)
            return SecurityHeaderAnalysisResult(
                target_url=url,
                status_code=None,
                is_reachable=False,
                hsts=dummy_h,
                csp=dummy_h,
                x_content_type_options=dummy_h,
                x_frame_options=dummy_h,
                referrer_policy=dummy_h,
                limitations=[
                    TechnicalLimitation(
                        module="security_headers",
                        reason=f"Prohibited pinned IP '{pinned_ip}' rejected by SSRF guard",
                        impact="Security headers could not be retrieved."
                    )
                ]
            )
        target_ip = str(parsed_pinned)
    else:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or url
        ssrf_res = validate_destination_safety(host, resolve_dns=True, dns_timeout=timeout)
        if not ssrf_res.is_safe or not ssrf_res.resolved_ips:
            dummy_h = SingleHeaderAnalysis(header_name="unavailable", status=HeaderEvaluationStatus.UNAVAILABLE)
            return SecurityHeaderAnalysisResult(
                target_url=url,
                status_code=None,
                is_reachable=False,
                hsts=dummy_h,
                csp=dummy_h,
                x_content_type_options=dummy_h,
                x_frame_options=dummy_h,
                referrer_policy=dummy_h,
                limitations=[
                    TechnicalLimitation(
                        module="security_headers",
                        reason=ssrf_res.blocked_reason or "Prohibited destination",
                        impact="Headers could not be retrieved."
                    )
                ]
            )
        target_ip = ssrf_res.resolved_ips[0]

    try:
        if client_factory:
            client = client_factory(target_ip)
        else:
            transport = PinnedHTTPTransport(pinned_ip=target_ip, verify=True)
            client = httpx.Client(transport=transport, follow_redirects=False, timeout=timeout, trust_env=False)

        with client:
            resp = client.get(url, headers={"User-Agent": "CyberShield-Security-Auditor/1.0", "Connection": "close"})
            headers_dict = dict(resp.headers)
            return analyze_security_headers_from_dict(headers_dict, url=url, status_code=resp.status_code)

    except Exception as exc:
        dummy_h = SingleHeaderAnalysis(header_name="unavailable", status=HeaderEvaluationStatus.UNAVAILABLE)
        return SecurityHeaderAnalysisResult(
            target_url=url,
            status_code=None,
            is_reachable=False,
            hsts=dummy_h,
            csp=dummy_h,
            x_content_type_options=dummy_h,
            x_frame_options=dummy_h,
            referrer_policy=dummy_h,
            limitations=[
                TechnicalLimitation(
                    module="security_headers",
                    reason=f"Failed to fetch headers: {str(exc)}",
                    impact="Security headers could not be examined."
                )
            ]
        )

