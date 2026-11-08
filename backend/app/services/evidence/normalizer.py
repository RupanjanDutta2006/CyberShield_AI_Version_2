"""CyberShield AI — Evidence Normalization & Standardization (Part 13)

Normalizes disparate investigation findings from URL heuristics, DNS, redirects,
TLS, HTTP security headers, threat intelligence, and AI analysis into a unified
standardized evidence model with deduplication, correlation, and provenance tracking.
"""

import re
import urllib.parse
import hashlib
from typing import Optional, List, Dict, Any, Union, Set
from datetime import datetime, timezone

from app.schemas.common import TechnicalFinding, TechnicalLimitation, FindingSeverity
from app.schemas.url_scan import URLPreFlightResult
from app.schemas.threat_intel import ThreatIntelSourceResult, ThreatIntelSummary
from app.schemas.ai_analysis import MessageAnalysisResponse
from app.schemas.evidence import (
    CheckStatus,
    EvidenceAuthority,
    StandardSeverity,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)

# Sensitive parameter names and credential key variants to redact
SENSITIVE_KEY_NAMES = {
    "token", "password", "passwd", "pwd", "secret", "key", "api_key", "apikey",
    "access_token", "refresh_token", "client_secret", "private_key", "auth",
    "authorization", "otp", "session", "session_id", "credential", "credentials",
    "pass", "pin", "code"
}

SENSITIVE_SUBSTRINGS = (
    "password", "secret", "api_key", "apikey", "access_token",
    "refresh_token", "client_secret", "private_key"
)

# Governed / curated threat intelligence providers recognized as authoritative for confirmed matches
VERIFIED_AUTHORITATIVE_TI_FEEDS = {
    "urlhaus",
    "google safe browsing",
    "openphish",
    "phishtank",
}


def _is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key or parameter name represents sensitive credential material."""
    if not isinstance(key, str):
        return False
    normalized = key.lower().strip().replace("-", "_")
    # Never treat benign usernames or generic headers as sensitive
    if normalized in ("username", "user", "user_agent", "useragent", "status", "host", "domain"):
        return False
    if normalized in SENSITIVE_KEY_NAMES:
        return True
    return any(sub in normalized for sub in SENSITIVE_SUBSTRINGS)


def redact_sensitive_url_and_params(url: str) -> str:
    """Sanitize URL query parameters and userinfo credentials.
    
    Preserves scheme, host, port, path, and non-sensitive query parameters while redacting:
    - Userinfo credentials (e.g. user:pass@host -> user:[REDACTED]@host)
    - Sensitive query parameters (e.g. ?token=secret&user=alice -> ?token=[REDACTED]&user=alice)
    """
    if not url or not isinstance(url, str):
        return url
    try:
        parsed = urllib.parse.urlsplit(url)
        clean_netloc = parsed.netloc

        # Redact userinfo credentials in netloc
        if "@" in parsed.netloc:
            userinfo, host_port = parsed.netloc.rsplit("@", 1)
            if ":" in userinfo:
                uname, _ = userinfo.split(":", 1)
                clean_userinfo = f"{uname}:[REDACTED]"
            else:
                clean_userinfo = "[REDACTED]"
            clean_netloc = f"{clean_userinfo}@{host_port}"

        # Redact sensitive query parameters
        clean_query = parsed.query
        if parsed.query:
            params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_params = []
            for k, v in params:
                if _is_sensitive_key(k):
                    sanitized_params.append((k, "[REDACTED]"))
                else:
                    sanitized_params.append((k, v))
            clean_query = urllib.parse.urlencode(sanitized_params)

        return urllib.parse.urlunsplit((parsed.scheme, clean_netloc, parsed.path, clean_query, parsed.fragment))
    except Exception:
        # Fallback regex redaction without exposing raw values
        redacted = re.sub(
            r'([?&](?:token|password|key|secret|auth|access_token|otp|client_secret|refresh_token)=)[^&#]*',
            r'\1[REDACTED]',
            url,
            flags=re.IGNORECASE
        )
        return re.sub(r'(://[^:/@\s]+:)[^@\s]+(@)', r'\1[REDACTED]\2', redacted)


def redact_sensitive_evidence(data: Any) -> Any:
    """Recursively redact sensitive keys and values across nested dicts, lists, and tuples."""
    if isinstance(data, dict):
        clean_dict: Dict[str, Any] = {}
        for k, v in data.items():
            if _is_sensitive_key(str(k)):
                clean_dict[k] = "[REDACTED]"
            else:
                clean_dict[k] = redact_sensitive_evidence(v)
        return clean_dict
    elif isinstance(data, list):
        return [redact_sensitive_evidence(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(redact_sensitive_evidence(item) for item in data)
    elif isinstance(data, set):
        return {redact_sensitive_evidence(item) for item in data}
    elif isinstance(data, str):
        if "://" in data:
            return redact_sensitive_url_and_params(data)
        return data
    return data


def redact_sensitive_dict(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Backward-compatible helper for evidence dictionaries."""
    res = redact_sensitive_evidence(data)
    return res if isinstance(res, dict) else {}


def map_severity_to_standard(sev: Union[FindingSeverity, StandardSeverity, str, None]) -> StandardSeverity:
    """Map any severity enum or string into the 4 standard severity levels."""
    if sev is None:
        return StandardSeverity.INFORMATIONAL
    s = str(sev.value if hasattr(sev, "value") else sev).lower()
    if s in ("high", "critical"):
        return StandardSeverity.HIGH
    if s == "medium":
        return StandardSeverity.MEDIUM
    if s == "low":
        return StandardSeverity.LOW
    return StandardSeverity.INFORMATIONAL


def _generate_finding_id(category: EvidenceCategory, source_module: str, title: str, target: Optional[str]) -> str:
    """Generate a deterministic, reproducible finding identifier."""
    seed = f"{category.value}|{source_module}|{title.lower().strip()}|{(target or '').lower().strip()}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"{category.value}_{source_module}_{digest}"


def _upsert_evidence_item(
    items_by_key: Dict[str, StandardizedEvidenceItem],
    new_item: StandardizedEvidenceItem
) -> None:
    """Insert or merge an evidence item preserving all original references, correlations, and timestamps."""
    fid = new_item.finding_id
    if fid in items_by_key:
        existing = items_by_key[fid]
        # Preserve and merge all unique original references
        for ref in new_item.original_references:
            if ref not in existing.original_references:
                existing.original_references.append(ref)
        # Preserve and merge all unique correlations
        for corr in new_item.correlations:
            if corr not in existing.correlations:
                existing.correlations.append(corr)
        # Merge supporting evidence dictionary keys
        if new_item.evidence:
            for k, v in new_item.evidence.items():
                if k not in existing.evidence:
                    existing.evidence[k] = v
        # Preserve upstream observation timestamp if existing is missing
        if not existing.observed_at and new_item.observed_at:
            existing.observed_at = new_item.observed_at
        # Merge conflict flags
        if new_item.is_conflicting:
            existing.is_conflicting = True
            if new_item.conflict_details:
                existing.conflict_details = (
                    f"{existing.conflict_details}; {new_item.conflict_details}"
                    if existing.conflict_details else new_item.conflict_details
                )
    else:
        items_by_key[fid] = new_item


def _resolve_coverage_states(
    completed_checks: List[str],
    failed_checks: List[str],
    unavailable_checks: List[str],
    partial_checks: List[str],
    skipped_checks: List[str],
    not_applicable_checks: List[str],
    limitations: List[str],
) -> EvidenceCoverage:
    """Resolve check identifiers across multiple state collections conservatively.

    Enforces that:
    1. An explicit failure is never masked or overridden by completed or partial status.
    2. Identifiers in multiple states are detected and resolved conservatively:
       failed > unavailable > partial > skipped > not_applicable > completed.
    3. State conflicts are documented in limitations.
    4. Each identifier appears in exactly one final coverage category (pairwise disjoint).
    5. NOT_APPLICABLE and SKIPPED checks are strictly excluded from the applicable denominator.
    6. Coverage ratio is bounded [0.0, 1.0].
    """
    raw_state_map: Dict[str, Set[str]] = {}
    for ident in completed_checks:
        raw_state_map.setdefault(ident, set()).add("completed")
    for ident in failed_checks:
        raw_state_map.setdefault(ident, set()).add("failed")
    for ident in unavailable_checks:
        raw_state_map.setdefault(ident, set()).add("unavailable")
    for ident in partial_checks:
        raw_state_map.setdefault(ident, set()).add("partial")
    for ident in skipped_checks:
        raw_state_map.setdefault(ident, set()).add("skipped")
    for ident in not_applicable_checks:
        raw_state_map.setdefault(ident, set()).add("not_applicable")

    final_completed: Set[str] = set()
    final_failed: Set[str] = set()
    final_unavailable: Set[str] = set()
    final_partial: Set[str] = set()
    final_skipped: Set[str] = set()
    final_not_applicable: Set[str] = set()

    for ident, states in raw_state_map.items():
        if len(states) == 1:
            st = next(iter(states))
            if st == "completed":
                final_completed.add(ident)
            elif st == "failed":
                final_failed.add(ident)
            elif st == "unavailable":
                final_unavailable.add(ident)
            elif st == "partial":
                final_partial.add(ident)
            elif st == "skipped":
                final_skipped.add(ident)
            elif st == "not_applicable":
                final_not_applicable.add(ident)
        else:
            # Multi-state conflict: resolve conservatively.
            # Hierarchy: failed > unavailable > partial > skipped > not_applicable > completed
            if "failed" in states:
                chosen = "failed"
                final_failed.add(ident)
            elif "unavailable" in states:
                chosen = "unavailable"
                final_unavailable.add(ident)
            elif "partial" in states:
                chosen = "partial"
                final_partial.add(ident)
            elif "skipped" in states:
                chosen = "skipped"
                final_skipped.add(ident)
            elif "not_applicable" in states:
                chosen = "not_applicable"
                final_not_applicable.add(ident)
            else:
                chosen = "completed"
                final_completed.add(ident)

            sorted_states_str = ", ".join(sorted(states))
            limitations.append(
                f"[coverage] Conflicting coverage states for '{ident}': [{sorted_states_str}]; "
                f"resolved conservatively to '{chosen}'"
            )

    # Applicable denominator: completed, partial, unavailable, and failed
    # (NOT_APPLICABLE and SKIPPED checks are strictly excluded from applicable denominator)
    applicable_checks = final_completed | final_partial | final_unavailable | final_failed
    if len(applicable_checks) > 0:
        effective_completed = len(final_completed) + (0.5 * len(final_partial))
        coverage_ratio = round(min(1.0, max(0.0, effective_completed / len(applicable_checks))), 2)
    else:
        coverage_ratio = 0.0

    return EvidenceCoverage(
        completed=sorted(final_completed),
        unavailable=sorted(final_unavailable),
        failed=sorted(final_failed),
        skipped=sorted(final_skipped),
        not_applicable=sorted(final_not_applicable),
        partial=sorted(final_partial),
        coverage_ratio=coverage_ratio,
    )


def normalize_evidence(
    target: str,
    preflight: Optional[URLPreFlightResult] = None,
    technical_investigation: Optional[Any] = None,
    threat_intel: Optional[Union[ThreatIntelSummary, List[ThreatIntelSourceResult]]] = None,
    ai_analysis: Optional[MessageAnalysisResponse] = None,
    custom_limitations: Optional[List[str]] = None,
) -> EvidenceCollection:
    """Normalize and aggregate findings from all available upstream investigation modules.
    
    Args:
        target: Target URL, domain, or message indicator under investigation.
        preflight: Batch 2 URL intake & SSRF preflight result.
        technical_investigation: Batch 3 TechnicalInvestigationResult.
        threat_intel: Threat intelligence feeds summary or source list.
        ai_analysis: Member 2 AI scam message analysis result.
        custom_limitations: Additional operational limitations to record.
        
    Returns:
        EvidenceCollection containing standardized items, coverage audit, and infrastructure correlations.
    """
    sanitized_target = redact_sensitive_url_and_params(target)
    items_by_key: Dict[str, StandardizedEvidenceItem] = {}

    completed_checks: List[str] = []
    unavailable_checks: List[str] = []
    failed_checks: List[str] = []
    skipped_checks: List[str] = []
    not_applicable_checks: List[str] = []
    partial_checks: List[str] = []

    correlated_domains: Set[str] = set()
    correlated_ips: Set[str] = set()
    limitations: List[str] = list(custom_limitations or [])

    # Extract initial target domain if valid URL
    try:
        p_init = urllib.parse.urlsplit(target)
        if p_init.hostname:
            correlated_domains.add(p_init.hostname.lower())
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 1. Normalize Preflight (Batch 2: Parts 05–08)
    # -------------------------------------------------------------------------
    if preflight is not None:
        completed_checks.append("url_preflight")

        # Provenance timestamp from preflight normalization if available
        preflight_ts = getattr(preflight.normalization, "normalized_at", None) if preflight.normalization else None

        # Domain correlations
        if preflight.normalization and preflight.normalization.hostname:
            correlated_domains.add(preflight.normalization.hostname.lower())
        if preflight.normalization and preflight.normalization.registrable_domain:
            correlated_domains.add(preflight.normalization.registrable_domain.lower())

        # SSRF safety status
        if preflight.ssrf_validation:
            completed_checks.append("ssrf_preflight")
            for ip in preflight.ssrf_validation.resolved_ips:
                correlated_ips.add(ip)
            if not preflight.ssrf_validation.is_safe:
                fid = _generate_finding_id(EvidenceCategory.URL_SYNTAX, "ssrf_guard", "SSRF Prohibited Destination", sanitized_target)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.URL_SYNTAX,
                    severity=StandardSeverity.HIGH,
                    title="SSRF Prohibited Destination Detected",
                    description=preflight.ssrf_validation.blocked_reason or "Target resolves to private, loopback, or metadata address range.",
                    evidence=redact_sensitive_dict({
                        "target": sanitized_target,
                        "resolved_ips": preflight.ssrf_validation.resolved_ips,
                        "blocked_reason": preflight.ssrf_validation.blocked_reason,
                    }),
                    source_module="ssrf_guard",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                    observed_at=preflight_ts,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=sanitized_target,
                    original_references=["part_07_ssrf_preflight"],
                ))

        # Batch 2 Heuristic pattern findings (Part 08)
        if preflight.heuristic_findings:
            completed_checks.append("url_heuristics")
            for hf in preflight.heuristic_findings:
                fid = _generate_finding_id(EvidenceCategory.HEURISTIC, hf.module or "url_heuristics", hf.title, sanitized_target)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.HEURISTIC,
                    severity=map_severity_to_standard(hf.severity),
                    title=hf.title,
                    description=hf.description,
                    evidence=redact_sensitive_dict(hf.evidence or {}),
                    source_module=hf.module or "url_heuristics",
                    source_authority=EvidenceAuthority.HEURISTIC,
                    observed_at=preflight_ts,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=sanitized_target,
                    original_references=[hf.check_name],
                ))
        else:
            completed_checks.append("url_heuristics")

    # -------------------------------------------------------------------------
    # 2. Normalize Technical Website Investigation (Batch 3: Parts 09–12)
    # -------------------------------------------------------------------------
    if technical_investigation is not None:
        # Collect limitations from Batch 3
        ti_lims = getattr(technical_investigation, "all_limitations", None) or getattr(technical_investigation, "limitations", [])
        for lim in ti_lims:
            mod_str = getattr(lim, "module", "investigation")
            reason_str = getattr(lim, "reason", getattr(lim, "description", str(lim)))
            lim_text = f"[{mod_str}] {reason_str}"
            if lim_text not in limitations:
                limitations.append(lim_text)

        # Check overall coordinator status and abort conditions
        overall_status = getattr(technical_investigation, "status", None)
        status_val = str(getattr(overall_status, "value", overall_status)).upper() if overall_status else "COMPLETED"

        all_lim_texts = [
            (getattr(lim, "reason", getattr(lim, "description", str(lim)))).lower()
            for lim in ti_lims
        ]
        joined_lims = " ".join(all_lim_texts)

        # Preflight abort condition (e.g. initial URL validation or intake SSRF guard failure)
        preflight_aborted = (
            status_val == "FAILED"
            and any(phrase in joined_lims for phrase in ("prohibited by ssrf", "rejected", "aborted", "blocked by ssrf"))
        )

        # DNS safety abort condition: DNS ran, but destination was unsafe, halting downstream inspection
        dns_res = getattr(technical_investigation, "dns", None)
        dns_ssrf_aborted = False
        if dns_res:
            dns_safe = getattr(dns_res, "is_destination_safe", True)
            dns_st = str(getattr(dns_res.status, "value", dns_res.status)).upper()
            dns_blk = getattr(dns_res, "blocked_reason", None) or ""
            if (not dns_safe) or dns_st == "SSRF_BLOCKED" or ("ssrf" in dns_blk.lower()):
                dns_ssrf_aborted = True
        elif "dns resolution blocked by ssrf" in joined_lims:
            dns_ssrf_aborted = True

        # Redirect abort condition: Redirect ran, but hop was blocked by SSRF
        redir_res = getattr(technical_investigation, "redirects", None)
        redirect_ssrf_aborted = False
        if redir_res:
            redir_safe = getattr(redir_res, "destination_ip_safe", True)
            redir_stop = str(getattr(redir_res, "stopped_reason", "")).upper()
            if (not redir_safe) or redir_stop == "SSRF_BLOCKED_HOP":
                redirect_ssrf_aborted = True
        elif "redirect traversal halted: intermediate hop blocked by ssrf" in joined_lims or "redirect chain blocked by ssrf" in joined_lims:
            redirect_ssrf_aborted = True

        # ---------------------------------------------------------------------
        # Part 09: DNS Records & Infrastructure
        # ---------------------------------------------------------------------
        if dns_res:
            dns_status_str = str(getattr(dns_res.status, "value", dns_res.status)).upper()
            dns_ts = getattr(dns_res, "timestamp", None)
            domain_name = getattr(dns_res, "domain", sanitized_target)

            if domain_name:
                correlated_domains.add(domain_name.lower())
            for a in getattr(dns_res, "a_records", []):
                correlated_ips.add(a)
            for aaaa in getattr(dns_res, "aaaa_records", []):
                correlated_ips.add(aaaa)

            # Map actual upstream DNSStatus enum values:
            # SUCCESS, EMPTY_ANSWER, NXDOMAIN, TIMEOUT, SERVFAIL, UNAVAILABLE, INVALID_DOMAIN, SSRF_BLOCKED
            if dns_status_str in ("SUCCESS", "EMPTY_ANSWER"):
                completed_checks.append("dns_investigation")
            elif dns_status_str == "NXDOMAIN":
                # NXDOMAIN is a completed observation (domain does not exist)
                completed_checks.append("dns_investigation")
                fid = _generate_finding_id(EvidenceCategory.DNS, "dns", "Non-Existent Domain (NXDOMAIN)", domain_name)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.DNS,
                    severity=StandardSeverity.MEDIUM,
                    title="Domain Does Not Exist (NXDOMAIN)",
                    description=f"Authoritative DNS query returned NXDOMAIN for {domain_name}. Domain is not registered or nameservers are inactive.",
                    evidence={"domain": domain_name, "status": dns_status_str},
                    source_module="dns",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                    observed_at=dns_ts,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=domain_name,
                    original_references=["dns_nxdomain"],
                ))
            elif dns_status_str in ("TIMEOUT", "SERVFAIL"):
                failed_checks.append("dns_investigation")
                limitations.append(f"[dns] DNS investigation encountered {dns_status_str} for {domain_name}")
            elif dns_status_str == "UNAVAILABLE":
                unavailable_checks.append("dns_investigation")
                limitations.append(f"[dns] DNS service was unavailable for {domain_name}")
            elif dns_status_str == "INVALID_DOMAIN":
                failed_checks.append("dns_investigation")
                limitations.append(f"[dns] Invalid domain syntax: {domain_name}")
            elif dns_status_str == "SSRF_BLOCKED":
                failed_checks.append("dns_investigation")
                fid = _generate_finding_id(EvidenceCategory.DNS, "dns", "DNS Resolved SSRF Prohibited IP", domain_name)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.DNS,
                    severity=StandardSeverity.HIGH,
                    title="DNS Resolved SSRF Prohibited Address",
                    description=dns_res.blocked_reason or f"DNS resolution for {domain_name} returned private, loopback, or metadata addresses.",
                    evidence=redact_sensitive_dict({
                        "domain": domain_name,
                        "all_resolved_ips": getattr(dns_res, "all_resolved_ips", []),
                        "blocked_reason": dns_res.blocked_reason
                    }),
                    source_module="dns",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                    observed_at=dns_ts,
                    check_status=CheckStatus.FAILED,
                    relevant_target=domain_name,
                    original_references=["dns_ssrf_blocked"],
                ))
                limitations.append(f"[dns] DNS resolution blocked by SSRF policy for {domain_name}")
            else:
                partial_checks.append("dns_investigation")

            # Ingest individual DNS findings
            for df in getattr(dns_res, "findings", []):
                fid = _generate_finding_id(EvidenceCategory.DNS, df.module, df.title, domain_name)
                is_auth = (
                    "rebind" in df.check_name.lower()
                    or "ssrf" in df.check_name.lower()
                    or "nxdomain" in df.check_name.lower()
                )
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.DNS,
                    severity=map_severity_to_standard(df.severity),
                    title=df.title,
                    description=df.description,
                    evidence=redact_sensitive_dict(df.evidence or {}),
                    source_module=df.module,
                    source_authority=EvidenceAuthority.AUTHORITATIVE if is_auth else EvidenceAuthority.HEURISTIC,
                    observed_at=dns_ts,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=domain_name,
                    original_references=[df.check_name],
                ))
        else:
            if preflight_aborted:
                skipped_checks.append("dns_investigation")
                limitations.append("[dns] DNS investigation skipped: preflight destination validation aborted execution")
            else:
                unavailable_checks.append("dns_investigation")
                limitations.append("[dns] DNS investigation result was missing/unavailable")

        # ---------------------------------------------------------------------
        # Part 10: Safe Redirect Analysis
        # ---------------------------------------------------------------------
        if redir_res:
            stop_reason = str(getattr(redir_res, "stopped_reason", "UNKNOWN")).upper()
            final_url = getattr(redir_res, "final_url", sanitized_target)

            for hop in getattr(redir_res, "hops", []):
                if hasattr(hop, "resolved_ip") and hop.resolved_ip:
                    correlated_ips.add(hop.resolved_ip)
                if hasattr(hop, "url") and hop.url:
                    try:
                        h_host = urllib.parse.urlsplit(hop.url).hostname
                        if h_host:
                            correlated_domains.add(h_host.lower())
                    except Exception:
                        pass

            # Map actual upstream stopped_reason values:
            # FINAL_DESTINATION_REACHED, REDIRECT_LOOP_DETECTED, MAX_REDIRECTS_EXCEEDED,
            # SSRF_BLOCKED_HOP, INVALID_REDIRECT_TARGET, TOTAL_TIMEOUT_EXCEEDED,
            # CONNECT_TIMEOUT, CONNECTION_FAILED, DNS_RESOLUTION_FAILED, REQUEST_ERROR
            if stop_reason == "FINAL_DESTINATION_REACHED":
                completed_checks.append("redirect_analysis")
            elif stop_reason == "REDIRECT_LOOP_DETECTED":
                completed_checks.append("redirect_analysis")
            elif stop_reason == "MAX_REDIRECTS_EXCEEDED":
                partial_checks.append("redirect_analysis")
                limitations.append("[redirects] Maximum redirect hops (5) exceeded before reaching final destination")
            elif stop_reason == "SSRF_BLOCKED_HOP":
                failed_checks.append("redirect_analysis")
                fid = _generate_finding_id(EvidenceCategory.REDIRECT, "redirects", "SSRF Prohibited Destination in Redirect Hop", final_url)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.REDIRECT,
                    severity=StandardSeverity.HIGH,
                    title="SSRF Prohibited Destination in Redirect Hop",
                    description="Redirect chain attempted to connect to private, loopback, or cloud metadata address.",
                    evidence=redact_sensitive_dict({
                        "stopped_reason": stop_reason,
                        "hops_count": getattr(redir_res, "hop_count", 0),
                    }),
                    source_module="redirects",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                    check_status=CheckStatus.FAILED,
                    relevant_target=redact_sensitive_url_and_params(final_url),
                    original_references=["redirect_ssrf_blocked"],
                ))
                limitations.append("[redirects] Redirect traversal halted: intermediate hop blocked by SSRF gate")
            elif stop_reason in ("TOTAL_TIMEOUT_EXCEEDED", "CONNECT_TIMEOUT", "CONNECTION_FAILED", "DNS_RESOLUTION_FAILED", "REQUEST_ERROR"):
                failed_checks.append("redirect_analysis")
                limitations.append(f"[redirects] Redirect trace halted: {stop_reason}")
            elif stop_reason == "INVALID_REDIRECT_TARGET":
                failed_checks.append("redirect_analysis")
                limitations.append("[redirects] Redirect header contained an invalid or unsupported URL target")
            else:
                partial_checks.append("redirect_analysis")

            for rf in getattr(redir_res, "findings", []):
                fid = _generate_finding_id(EvidenceCategory.REDIRECT, rf.module, rf.title, final_url)
                is_auth = "loop" in rf.check_name.lower() or "ssrf" in rf.check_name.lower()
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.REDIRECT,
                    severity=map_severity_to_standard(rf.severity),
                    title=rf.title,
                    description=rf.description,
                    evidence=redact_sensitive_dict(rf.evidence or {}),
                    source_module=rf.module,
                    source_authority=EvidenceAuthority.AUTHORITATIVE if is_auth else EvidenceAuthority.HEURISTIC,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=redact_sensitive_url_and_params(final_url),
                    original_references=[rf.check_name],
                ))
        else:
            if preflight_aborted:
                skipped_checks.append("redirect_analysis")
                limitations.append("[redirects] Redirect analysis skipped: preflight destination validation aborted execution")
            elif dns_ssrf_aborted:
                skipped_checks.append("redirect_analysis")
                limitations.append("[redirects] Redirect analysis skipped: downstream execution aborted by DNS destination safety block")
            else:
                unavailable_checks.append("redirect_analysis")
                limitations.append("[redirects] Redirect analysis was not executed or result was unavailable")

        # ---------------------------------------------------------------------
        # Part 11: TLS & SSL Certificate Analysis
        # ---------------------------------------------------------------------
        tls_res = getattr(technical_investigation, "tls", None)
        if tls_res:
            tls_status_str = str(getattr(tls_res.status, "value", tls_res.status)).upper()
            tls_host = getattr(tls_res, "hostname", sanitized_target)

            # Map actual upstream TLSStatus enum values:
            # VALID, EXPIRED, SELF_SIGNED, HOSTNAME_MISMATCH, UNTRUSTED_CHAIN,
            # HANDSHAKE_FAILED, TIMEOUT, NOT_HTTPS, SSRF_BLOCKED, UNAVAILABLE
            if tls_status_str in ("VALID", "EXPIRED", "SELF_SIGNED", "HOSTNAME_MISMATCH", "UNTRUSTED_CHAIN"):
                completed_checks.append("tls_analysis")
            elif tls_status_str == "NOT_HTTPS":
                not_applicable_checks.append("tls_analysis")
                limitations.append(f"[tls] Target {tls_host} does not use HTTPS; TLS analysis is not applicable")
            elif tls_status_str in ("TIMEOUT", "HANDSHAKE_FAILED"):
                failed_checks.append("tls_analysis")
                limitations.append(f"[tls] TLS handshake failed for {tls_host}: {getattr(tls_res, 'verification_error', tls_status_str)}")
            elif tls_status_str == "SSRF_BLOCKED":
                failed_checks.append("tls_analysis")
                fid = _generate_finding_id(EvidenceCategory.TLS, "tls_analysis", "TLS Connection Blocked by SSRF Policy", tls_host)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.TLS,
                    severity=StandardSeverity.HIGH,
                    title="TLS Connection Blocked by SSRF Policy",
                    description=f"TLS connection to {tls_host} was aborted because resolved IP violates SSRF policy.",
                    evidence={"hostname": tls_host, "status": tls_status_str},
                    source_module="tls_analysis",
                    source_authority=EvidenceAuthority.AUTHORITATIVE,
                    check_status=CheckStatus.FAILED,
                    relevant_target=tls_host,
                    original_references=["tls_ssrf_blocked"],
                ))
                limitations.append(f"[tls] TLS inspection blocked by SSRF policy for {tls_host}")
            elif tls_status_str == "UNAVAILABLE":
                unavailable_checks.append("tls_analysis")
                limitations.append(f"[tls] TLS analysis service was unavailable for {tls_host}")
            else:
                partial_checks.append("tls_analysis")

            for tf in getattr(tls_res, "findings", []):
                fid = _generate_finding_id(EvidenceCategory.TLS, tf.module, tf.title, tls_host)
                is_auth = tls_status_str in ("EXPIRED", "HOSTNAME_MISMATCH", "UNTRUSTED_CHAIN", "SELF_SIGNED")
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.TLS,
                    severity=map_severity_to_standard(tf.severity),
                    title=tf.title,
                    description=tf.description,
                    evidence=redact_sensitive_dict(tf.evidence or {}),
                    source_module=tf.module,
                    source_authority=EvidenceAuthority.AUTHORITATIVE if is_auth else EvidenceAuthority.HEURISTIC,
                    check_status=CheckStatus.COMPLETED,
                    relevant_target=tls_host,
                    original_references=[tf.check_name],
                ))
        else:
            if target.startswith("http://"):
                not_applicable_checks.append("tls_analysis")
                limitations.append("[tls] Target uses plain HTTP; TLS inspection not applicable")
            elif preflight_aborted:
                skipped_checks.append("tls_analysis")
                limitations.append("[tls] TLS inspection skipped: preflight destination validation aborted execution")
            elif dns_ssrf_aborted:
                skipped_checks.append("tls_analysis")
                limitations.append("[tls] TLS inspection skipped: downstream execution aborted by DNS destination safety block")
            elif redirect_ssrf_aborted:
                skipped_checks.append("tls_analysis")
                limitations.append("[tls] TLS inspection skipped: redirect chain targeted an unsafe or prohibited destination")
            else:
                unavailable_checks.append("tls_analysis")
                limitations.append("[tls] TLS analysis was not executed or result was unavailable")

        # ---------------------------------------------------------------------
        # Part 12: HTTP Security Headers
        # ---------------------------------------------------------------------
        sec_res = getattr(technical_investigation, "headers", None)
        if sec_res:
            is_reachable = getattr(sec_res, "is_reachable", True)
            target_endpoint = getattr(sec_res, "target_url", sanitized_target)

            if not is_reachable:
                # If endpoint was unreachable, header inspection failed
                failed_checks.append("security_headers")
                limitations.append(f"[security_headers] Endpoint {target_endpoint} was unreachable; HTTP security headers could not be inspected")
            else:
                # Inspect individual header evaluations
                header_objs = [
                    getattr(sec_res, "hsts", None),
                    getattr(sec_res, "csp", None),
                    getattr(sec_res, "x_content_type_options", None),
                    getattr(sec_res, "x_frame_options", None),
                    getattr(sec_res, "referrer_policy", None),
                ]
                evaluated_headers = [h for h in header_objs if h is not None]

                missing_objs_count = 5 - len(evaluated_headers)

                if not evaluated_headers:
                    unavailable_checks.append("security_headers")
                    limitations.append("[security_headers] No security header evaluation records were present")
                else:
                    observed_count = 0
                    unavail_count = missing_objs_count
                    unknown_count = 0

                    for h in evaluated_headers:
                        raw_status = getattr(h, "status", None)
                        if hasattr(raw_status, "value"):
                            h_st = str(raw_status.value).strip().upper()
                        elif raw_status is not None:
                            h_st = str(raw_status).strip().upper()
                        else:
                            h_st = ""
                        if "." in h_st:
                            h_st = h_st.split(".")[-1]

                        # Only VALID, WEAK, MALFORMED, and MISSING count as observed
                        if h_st in ("VALID", "WEAK", "MALFORMED", "MISSING"):
                            observed_count += 1
                        elif h_st == "UNAVAILABLE":
                            unavail_count += 1
                        else:
                            # Unknown, empty, missing-status, or unsupported values must NOT count as observed
                            unknown_count += 1
                            h_name = getattr(h, "header_name", "unknown_header")
                            limitations.append(
                                f"[security_headers] Header '{h_name}' has unrecognized or invalid evaluation status: '{raw_status}'"
                            )

                    if observed_count > 0 and unavail_count == 0 and unknown_count == 0:
                        completed_checks.append("security_headers")
                    elif observed_count > 0 and (unavail_count > 0 or unknown_count > 0):
                        partial_checks.append("security_headers")
                        limitations.append(
                            f"[security_headers] Partial header analysis: {observed_count} observed, "
                            f"{unavail_count} unavailable, {unknown_count} invalid/unknown"
                        )
                    else:
                        # All evaluations were unavailable or unknown
                        unavailable_checks.append("security_headers")
                        limitations.append("[security_headers] All HTTP security header evaluations were unavailable or invalid")

            # Ingest all findings and limitations
            for hf in getattr(sec_res, "findings", []):
                fid = _generate_finding_id(EvidenceCategory.SECURITY_HEADERS, hf.module, hf.title, sanitized_target)
                _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                    finding_id=fid,
                    category=EvidenceCategory.SECURITY_HEADERS,
                    severity=map_severity_to_standard(hf.severity),
                    title=hf.title,
                    description=hf.description,
                    evidence=redact_sensitive_dict(hf.evidence or {}),
                    source_module=hf.module,
                    source_authority=EvidenceAuthority.HEURISTIC,
                    check_status=CheckStatus.COMPLETED if is_reachable else CheckStatus.FAILED,
                    relevant_target=sanitized_target,
                    original_references=[hf.check_name],
                ))
            if getattr(sec_res, "limitations", None):
                for lim in sec_res.limitations:
                    lim_text = f"[{lim.module}] {lim.reason}" if hasattr(lim, "reason") else str(lim)
                    if lim_text not in limitations:
                        limitations.append(lim_text)
        else:
            if preflight_aborted:
                skipped_checks.append("security_headers")
                limitations.append("[security_headers] Header inspection skipped: preflight destination validation aborted execution")
            elif dns_ssrf_aborted:
                skipped_checks.append("security_headers")
                limitations.append("[security_headers] Header inspection skipped: downstream execution aborted by DNS destination safety block")
            elif redirect_ssrf_aborted:
                skipped_checks.append("security_headers")
                limitations.append("[security_headers] Header inspection skipped: redirect chain targeted an unsafe or prohibited destination")
            else:
                unavailable_checks.append("security_headers")
                limitations.append("[security_headers] Security headers analysis was not executed or result was unavailable")

    # -------------------------------------------------------------------------
    # 3. Normalize Threat Intelligence (Member 4 Integration)
    # -------------------------------------------------------------------------
    ti_sources: List[ThreatIntelSourceResult] = []
    if threat_intel is not None:
        if isinstance(threat_intel, ThreatIntelSummary):
            ti_sources = threat_intel.sources
        elif isinstance(threat_intel, list):
            ti_sources = threat_intel

    if ti_sources:
        available_count = 0
        failed_or_unavail_count = 0

        for src in ti_sources:
            src_status = (src.source_status or "available").lower().strip()
            src_name = src.source.strip()
            src_name_norm = src_name.lower()
            checked_ts = getattr(src, "checked_at", None)

            if src_status == "available":
                available_count += 1
                if src.match:
                    # Determine source authority under documented trust policy
                    is_recognized = any(known in src_name_norm for known in VERIFIED_AUTHORITATIVE_TI_FEEDS)
                    source_auth = EvidenceAuthority.AUTHORITATIVE if is_recognized else EvidenceAuthority.UNKNOWN

                    fid = _generate_finding_id(
                        EvidenceCategory.THREAT_INTEL,
                        src_name,
                        f"Identified as Malicious ({src.threat_type or 'threat'})",
                        sanitized_target
                    )
                    _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                        finding_id=fid,
                        category=EvidenceCategory.THREAT_INTEL,
                        severity=StandardSeverity.HIGH,
                        title=f"Target Listed on Threat Feed: {src_name}",
                        description=f"Threat intelligence source {src_name} flagged target as {src.threat_type or 'known malicious threat'}.",
                        evidence=redact_sensitive_dict({
                            "source": src_name,
                            "threat_type": src.threat_type,
                            "evidence": src.evidence,
                            "checked_at": checked_ts,
                        }),
                        source_module=f"threat_intel_{src_name}",
                        source_authority=source_auth,
                        observed_at=checked_ts,
                        check_status=CheckStatus.COMPLETED,
                        relevant_target=sanitized_target,
                        original_references=[f"{src_name}_match"],
                    ))
                else:
                    # Clean/no-match feed result is strictly INFORMATIONAL with HEURISTIC authority
                    fid = _generate_finding_id(
                        EvidenceCategory.THREAT_INTEL,
                        src_name,
                        f"No Threat Found in {src_name}",
                        sanitized_target
                    )
                    _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                        finding_id=fid,
                        category=EvidenceCategory.THREAT_INTEL,
                        severity=StandardSeverity.INFORMATIONAL,
                        title=f"Threat Intelligence Feed Clean: {src_name}",
                        description=f"{src_name} lookup returned no recorded malicious activity. Note: Absence of record does not guarantee safety.",
                        evidence={"source": src_name, "match": False, "checked_at": checked_ts},
                        source_module=f"threat_intel_{src_name}",
                        source_authority=EvidenceAuthority.HEURISTIC,
                        observed_at=checked_ts,
                        check_status=CheckStatus.COMPLETED,
                        relevant_target=sanitized_target,
                        original_references=[f"{src_name}_no_match"],
                    ))
            elif src_status in ("timeout", "error"):
                failed_or_unavail_count += 1
                limitations.append(f"[threat_intel] Feed {src_name} lookup failed: {src_status}")
            else:  # rate_limited, unavailable
                failed_or_unavail_count += 1
                limitations.append(f"[threat_intel] Feed {src_name} lookup unavailable: {src_status}")

            if getattr(src, "limitations", None):
                for l_item in src.limitations:
                    limitations.append(f"[threat_intel_{src_name}] {l_item}")

        # Compute accurate TI coverage breakdown
        if available_count > 0 and failed_or_unavail_count == 0:
            completed_checks.append("threat_intelligence")
        elif available_count > 0 and failed_or_unavail_count > 0:
            partial_checks.append("threat_intelligence")
        else:
            # All feeds failed or were unavailable
            any_failed = any((s.source_status or "").lower() in ("timeout", "error") for s in ti_sources)
            if any_failed:
                failed_checks.append("threat_intelligence")
            else:
                unavailable_checks.append("threat_intelligence")
    else:
        # Missing TI input is recorded as unavailable, NEVER as clean
        unavailable_checks.append("threat_intelligence")
        limitations.append("[threat_intel] No threat intelligence feeds were provided for inspection")

    # -------------------------------------------------------------------------
    # 4. Normalize AI Scam Analysis (Member 2 Integration)
    # -------------------------------------------------------------------------
    if ai_analysis is not None:
        completed_checks.append("ai_analysis")
        if ai_analysis.extracted_indicators:
            for d in ai_analysis.extracted_indicators.domains:
                correlated_domains.add(d.lower())

        ai_risk = (ai_analysis.risk_level or "low_risk").lower()
        if ai_risk == "high_risk":
            ai_sev = StandardSeverity.HIGH
        elif ai_risk in ("suspicious", "medium_risk"):
            ai_sev = StandardSeverity.MEDIUM
        else:
            ai_sev = StandardSeverity.LOW

        for ind in ai_analysis.observed_indicators:
            fid = _generate_finding_id(EvidenceCategory.AI_ANALYSIS, "ai_scam_model", ind.indicator, sanitized_target)
            _upsert_evidence_item(items_by_key, StandardizedEvidenceItem(
                finding_id=fid,
                category=EvidenceCategory.AI_ANALYSIS,
                severity=ai_sev,
                title=f"AI Scam Indicator: {ind.indicator}",
                description=ind.reason,
                evidence=redact_sensitive_dict({"quoted_evidence": ind.evidence}),
                source_module="ai_scam_model",
                source_authority=EvidenceAuthority.HEURISTIC,
                observed_at=None,
                check_status=CheckStatus.COMPLETED,
                relevant_target=sanitized_target,
                original_references=[ind.indicator],
            ))

        if ai_analysis.limitations:
            for l_item in ai_analysis.limitations:
                limitations.append(f"[ai_analysis] {l_item}")

    # -------------------------------------------------------------------------
    # 5. Deduplication, Conflict Detection & Accurate Coverage Accounting
    # -------------------------------------------------------------------------
    normalized_items: List[StandardizedEvidenceItem] = list(items_by_key.values())

    # Detect cross-feed TI conflicts
    has_authoritative_malicious = any(
        it.category == EvidenceCategory.THREAT_INTEL and it.severity == StandardSeverity.HIGH
        for it in normalized_items
    )
    has_clean_feed = any(
        it.category == EvidenceCategory.THREAT_INTEL and it.severity == StandardSeverity.INFORMATIONAL
        for it in normalized_items
    )
    if has_authoritative_malicious and has_clean_feed:
        for it in normalized_items:
            if it.category == EvidenceCategory.THREAT_INTEL:
                it.is_conflicting = True
                it.conflict_details = "Feeds report opposing findings: one feed flagged target as malicious while another had no active record."

    # Deduplicate and conservatively resolve check identifiers across states
    coverage = _resolve_coverage_states(
        completed_checks=completed_checks,
        failed_checks=failed_checks,
        unavailable_checks=unavailable_checks,
        partial_checks=partial_checks,
        skipped_checks=skipped_checks,
        not_applicable_checks=not_applicable_checks,
        limitations=limitations,
    )

    return EvidenceCollection(
        target=sanitized_target,
        collected_at=datetime.now(timezone.utc).isoformat(),
        items=normalized_items,
        coverage=coverage,
        correlated_domains=sorted(correlated_domains),
        correlated_ips=sorted(correlated_ips),
        limitations=limitations,
    )
