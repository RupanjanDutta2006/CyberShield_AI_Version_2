"""CyberShield AI — Indicator Severity & Authority Classifier (Part 14)

Assigns documented severity and evidence-authority classifications to indicators,
enforces deduplication, prevents double-counting of correlated issues, and guarantees
that heuristics and AI opinions cannot masquerade as authoritative evidence.
"""

from typing import List, Dict, Any, Optional, Tuple
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    StandardizedEvidenceItem,
)
from app.services.severity.models import (
    ClassifiedIndicator,
    IndicatorClassificationResult,
)

# Standard base weights by severity level
BASE_WEIGHTS = {
    StandardSeverity.INFORMATIONAL: 0,
    StandardSeverity.LOW: 10,
    StandardSeverity.MEDIUM: 25,
    StandardSeverity.HIGH: 50,
}

# Calibration multipliers by evidence authority level
AUTHORITY_MULTIPLIERS = {
    EvidenceAuthority.AUTHORITATIVE: 1.0,
    EvidenceAuthority.CORROBORATED: 0.85,
    EvidenceAuthority.HEURISTIC: 0.60,
    EvidenceAuthority.UNKNOWN: 0.30,
}


def derive_underlying_issue_key(item: StandardizedEvidenceItem) -> str:
    """Generate a canonical underlying issue key to prevent double counting related findings."""
    title_lower = item.title.lower().strip()

    # Common cross-module heuristic & impersonation concepts
    if "brand" in title_lower or "impersonat" in title_lower:
        return "heuristic:brand_impersonation"
    if "punycode" in title_lower or "homograph" in title_lower:
        return "heuristic:punycode_homograph"
    if "tld" in title_lower or "top-level domain" in title_lower:
        return "heuristic:suspicious_tld"
    if "raw ip" in title_lower or ("ip" in title_lower and "host" in title_lower):
        return "heuristic:ip_address_hostname"
    
    # Header findings
    if item.category == EvidenceCategory.SECURITY_HEADERS:
        if "hsts" in title_lower:
            return "header:missing_hsts"
        if "content-security-policy" in title_lower or "csp" in title_lower:
            return "header:missing_csp"
        if "x-frame-options" in title_lower:
            return "header:missing_xfo"
        if "x-content-type-options" in title_lower:
            return "header:missing_xcto"
        if "server" in title_lower or "banner" in title_lower:
            return "header:server_banner_disclosure"
        return f"header:{item.source_module}"

    # Redirect findings
    if item.category == EvidenceCategory.REDIRECT:
        if "loop" in title_lower or "circular" in title_lower:
            return "redirect:circular_loop"
        if "max redirects" in title_lower:
            return "redirect:max_hops_exceeded"
        if "ssrf" in title_lower or "unsafe destination" in title_lower:
            return "network:ssrf_prohibited"
        return f"redirect:{title_lower[:25]}"

    # TLS findings
    if item.category == EvidenceCategory.TLS:
        if "expired" in title_lower:
            return "tls:expired_certificate"
        if "hostname mismatch" in title_lower or "san mismatch" in title_lower:
            return "tls:hostname_mismatch"
        if "self-signed" in title_lower or "untrusted" in title_lower:
            return "tls:untrusted_ca"
        if "weak" in title_lower:
            return "tls:weak_cipher_algorithm"
        return f"tls:{title_lower[:25]}"

    # DNS findings
    if item.category == EvidenceCategory.DNS:
        if "nxdomain" in title_lower or "does not exist" in title_lower:
            return "dns:nxdomain"
        if "rebind" in title_lower or "private" in title_lower:
            return "network:ssrf_prohibited"
        if "null mx" in title_lower:
            return "dns:null_mx_configured"
        return f"dns:{title_lower[:25]}"

    # SSRF findings
    if "ssrf" in title_lower:
        return "network:ssrf_prohibited"

    # Threat Intelligence
    if item.category == EvidenceCategory.THREAT_INTEL:
        if item.severity == StandardSeverity.HIGH:
            return f"threat_intel:malicious_match:{item.source_module}"
        return f"threat_intel:clean_feed:{item.source_module}"

    # AI Analysis
    if item.category == EvidenceCategory.AI_ANALYSIS:
        return f"ai_analysis:{title_lower[:30]}"

    # URL Heuristics
    return f"heuristic:{item.source_module}:{title_lower[:30]}"


# Severity ordering helper
SEV_RANK = {
    StandardSeverity.INFORMATIONAL: 0,
    StandardSeverity.LOW: 1,
    StandardSeverity.MEDIUM: 2,
    StandardSeverity.HIGH: 3,
}

# Authority ordering helper
AUTHORITY_RANK = {
    EvidenceAuthority.UNKNOWN: 0,
    EvidenceAuthority.HEURISTIC: 1,
    EvidenceAuthority.CORROBORATED: 2,
    EvidenceAuthority.AUTHORITATIVE: 3,
}


def _evaluate_independent_sources(
    group: List[StandardizedEvidenceItem],
) -> Tuple[int, EvidenceAuthority, List[str]]:
    """Determine the number of demonstrably independent sources and consolidated authority.

    Rules:
    - Distinct source_module values alone do NOT prove independent corroboration.
    - Two items are coupled/dependent (cannot form separate independent sources) if:
      1. They share the same source_module, OR
      2. They share any original_references, OR
      3. They share any correlations.
    - Items lacking sufficient provenance (both original_references and correlations empty)
      cannot establish independence from other items.
    - Pure AI-analysis groups strictly remain HEURISTIC.
    - If authoritative evidence is present, authority is AUTHORITATIVE.
    - Authority is upgraded to CORROBORATED if and only if >= 2 demonstrably independent
      sources corroborate the underlying issue.
    - Otherwise, the highest existing authority among items is preserved (non-promotion).
    """
    distinct_modules = sorted(set(it.source_module for it in group))

    # 1. Authoritative check
    has_authoritative = any(it.source_authority == EvidenceAuthority.AUTHORITATIVE for it in group)

    # 2. Pure AI check
    is_all_ai = all(it.category == EvidenceCategory.AI_ANALYSIS for it in group)
    if is_all_ai:
        return 1, EvidenceAuthority.HEURISTIC, distinct_modules

    # 3. Filter items that can establish technical corroboration
    # AI interpretations do not corroborate technical findings
    eval_items = [it for it in group if it.category != EvidenceCategory.AI_ANALYSIS]
    if not eval_items:
        eval_items = group

    # Items with sufficient provenance
    prov_items = [it for it in eval_items if (it.original_references or it.correlations)]

    # If fewer than 2 items have sufficient provenance, independence cannot be proven
    if len(prov_items) < 2:
        independent_sources_count = 1
        is_corroborated = False
    else:
        # Build dependence graph among items with provenance
        m = len(prov_items)
        parent = list(range(m))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(i: int, j: int) -> None:
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_i] = root_j

        for i in range(m):
            for j in range(i + 1, m):
                it_i = prov_items[i]
                it_j = prov_items[j]
                is_dependent = False

                # Same module duplicate observations cannot be independent sources
                if it_i.source_module == it_j.source_module:
                    is_dependent = True
                # Overlapping original_references indicates shared underlying observation
                elif it_i.original_references and it_j.original_references:
                    if set(it_i.original_references) & set(it_j.original_references):
                        is_dependent = True
                # Overlapping correlations indicates coupled observation
                if not is_dependent and it_i.correlations and it_j.correlations:
                    if set(it_i.correlations) & set(it_j.correlations):
                        is_dependent = True

                if is_dependent:
                    union(i, j)

        num_components = len(set(find(i) for i in range(m)))
        if num_components >= 2:
            independent_sources_count = num_components
            is_corroborated = True
        else:
            independent_sources_count = 1
            is_corroborated = False

    # Consolidated authority resolution
    if has_authoritative:
        consolidated_authority = EvidenceAuthority.AUTHORITATIVE
    elif is_corroborated:
        consolidated_authority = EvidenceAuthority.CORROBORATED
    else:
        # Preserve highest existing authority
        highest_existing = max((it.source_authority for it in group), key=lambda a: AUTHORITY_RANK.get(a, 0))
        consolidated_authority = highest_existing

    return independent_sources_count, consolidated_authority, distinct_modules


def classify_indicators(items: List[StandardizedEvidenceItem]) -> IndicatorClassificationResult:
    """Classify, weight, and deduplicate standardized evidence items into a consistent indicator model.
    
    Enforces rules:
    - Independent sources confirming the same issue upgrade authority to CORROBORATED.
    - Multiple representations of the same issue are not counted repeatedly in weights.
    - AI-generated interpretations remain strictly HEURISTIC authority.
    - Valid TLS does not suppress malicious indicators.
    - High-severity heuristics do not become AUTHORITATIVE without external corroboration.
    - Deterministic and independent of input ordering.
    """
    grouped_items: Dict[str, List[StandardizedEvidenceItem]] = {}
    
    # 1. Group by underlying issue key
    for item in items:
        issue_key = derive_underlying_issue_key(item)
        if issue_key not in grouped_items:
            grouped_items[issue_key] = []
        grouped_items[issue_key].append(item)

    classified_list: List[ClassifiedIndicator] = []
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    authoritative_threat_count = 0
    has_auth_malicious = False
    max_severity = StandardSeverity.INFORMATIONAL

    # 2. Consolidate each group into a single ClassifiedIndicator (order-independent)
    for issue_key in sorted(grouped_items.keys()):
        group = grouped_items[issue_key]

        # Sort items deterministically within the group so primary selection is order-invariant
        group_sorted = sorted(
            group,
            key=lambda it: (
                -SEV_RANK[it.severity],
                -AUTHORITY_RANK.get(it.source_authority, 0),
                it.source_module,
                it.finding_id,
                it.title,
            )
        )
        primary = group_sorted[0]
        highest_sev = primary.severity

        # Determine independent corroboration, authority, and distinct sources
        (
            corroboration_count,
            consolidated_authority,
            distinct_sources,
        ) = _evaluate_independent_sources(group_sorted)

        base_wt = BASE_WEIGHTS[highest_sev]
        mult = AUTHORITY_MULTIPLIERS.get(consolidated_authority, 0.3)
        effective_wt = round(base_wt * mult, 2)

        # Authoritative threat classification
        has_auth_category = any(
            it.source_authority == EvidenceAuthority.AUTHORITATIVE
            and it.category in (
                EvidenceCategory.THREAT_INTEL,
                EvidenceCategory.URL_SYNTAX,
                EvidenceCategory.DNS,
                EvidenceCategory.REDIRECT,
                EvidenceCategory.TLS,
            )
            for it in group_sorted
        )
        is_auth_threat = (
            consolidated_authority == EvidenceAuthority.AUTHORITATIVE
            and highest_sev == StandardSeverity.HIGH
            and has_auth_category
        )

        if is_auth_threat:
            authoritative_threat_count += 1
            has_auth_malicious = True

        is_heuristic_only = (consolidated_authority == EvidenceAuthority.HEURISTIC)

        # Track max severity
        if SEV_RANK[highest_sev] > SEV_RANK[max_severity]:
            max_severity = highest_sev

        # Count severities
        if highest_sev == StandardSeverity.HIGH:
            high_count += 1
        elif highest_sev == StandardSeverity.MEDIUM:
            medium_count += 1
        elif highest_sev == StandardSeverity.LOW:
            low_count += 1
        else:
            info_count += 1

        if corroboration_count > 1:
            explanation = (
                f"Underlying issue '{issue_key}' assigned severity {highest_sev.value} "
                f"with authority {consolidated_authority.value} corroborated across {corroboration_count} "
                f"independent source(s) ({', '.join(distinct_sources)}) "
                f"(effective weight: {effective_wt})."
            )
        else:
            obs_str = f" ({len(distinct_sources)} observing module(s): {', '.join(distinct_sources)})" if len(distinct_sources) > 1 else ""
            explanation = (
                f"Underlying issue '{issue_key}' assigned severity {highest_sev.value} "
                f"with authority {consolidated_authority.value} across {corroboration_count} source(s)"
                f"{obs_str} (effective weight: {effective_wt})."
            )

        classified_list.append(ClassifiedIndicator(
            indicator_id=f"ind_{issue_key.replace(':', '_').replace(' ', '_')[:35]}",
            title=primary.title,
            category=primary.category,
            severity=highest_sev,
            authority=consolidated_authority,
            base_weight=base_wt,
            effective_weight=effective_wt,
            source_modules=distinct_sources,
            corroboration_count=corroboration_count,
            underlying_issue_key=issue_key,
            is_authoritative_threat=is_auth_threat,
            is_heuristic_only=is_heuristic_only,
            explanation=explanation,
        ))

    return IndicatorClassificationResult(
        classified_indicators=classified_list,
        total_indicators=len(items),
        high_severity_count=high_count,
        medium_severity_count=medium_count,
        low_severity_count=low_count,
        info_severity_count=info_count,
        authoritative_threat_count=authoritative_threat_count,
        has_authoritative_malicious_evidence=has_auth_malicious,
        max_indicator_severity=max_severity,
        deduplicated_issue_count=len(classified_list),
    )
