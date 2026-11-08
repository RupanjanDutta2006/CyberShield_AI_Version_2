# CyberShield AI — Source Code Audit: Member 1 + Member 3 Integration

**Audit Date:** 2026-11-08  
**Scope:** Member 1 (`Project/`) and Member 3 (`CyberShield-Blockchain/`)  
**Integration Baseline Location:** `D:\Adamas Hackathon\Integration_Member_1_3`  
**Auditor:** Senior Backend Architect & Security Auditor  

---

## 1. Executive Summary

This source audit examines the source deliverables from:
1. **Member 1 (Core Backend Lead)**: Located at `D:\Adamas Hackathon\Project`. Consists of a FastAPI backend application including URL investigation pipeline, SSRF protections, technical analyzers (DNS, redirects, TLS, HTTP security headers), evidence normalizer, severity classifier, deterministic risk engine, unified threat report assembler, API routing with API key authentication, and SQLite database repository.
2. **Member 3 (Blockchain & Web3 Lead)**: Located at `D:\Adamas Hackathon\CyberShield-Blockchain` (with repository root at `CyberShield-Blockchain\CyberShield-Blockchain`). Consists of the Solidity smart contract `ThreatReportRegistry.sol`, Hardhat testing/deployment infrastructure, Python Web3 client and canonical hasher (`blockchain_service.py`, `report_hash.py`), TypeScript schema and normalization (`threatReport.ts`), Next.js blockchain API route (`app/api/blockchain/route.ts`), and cross-language test suites.

Both baselines were verified independently prior to any modification:
- Member 1 test suite: **293 passed**, 0 failed, 1 warning (Starlette testclient deprecation).
- Member 3 test suites: **40 passed** (Python `test_blockchain.py`), **29 passed** (Hardhat: 22 Solidity contract + 7 cross-language hash consistency), plus 4 reported live EVM checks.

---

## 2. Actual Folder Structures

### 2.1 Member 1 Directory Structure (`Project/`)
```
Project/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── router.py         # Primary API routes (/health, /reports, /history, /reports/register, /reports/verify, etc.)
│   │   │       └── __init__.py
│   │   ├── core/
│   │   │   ├── config.py             # Settings (pydantic-settings), API keys, CORS, blockchain config
│   │   │   ├── security.py           # API key authentication (require_api_auth)
│   │   │   └── __init__.py
│   │   ├── database/
│   │   │   ├── models.py             # ThreatReportModel (SQLite persistence)
│   │   │   ├── repository.py         # CRUD repository for threat reports
│   │   │   ├── session.py            # SQLite engine and session factory
│   │   │   └── __init__.py
│   │   ├── schemas/
│   │   │   ├── ai_analysis.py        # Message analysis schemas
│   │   │   ├── blockchain.py         # ReportRegistrationRequest/Response, ReportVerificationRequest/Response
│   │   │   ├── common.py             # Enums: RiskClassification, VerificationStatus, ScanType, etc.
│   │   │   ├── evidence.py           # Evidence models and EvidenceCoverage
│   │   │   ├── report.py             # Legacy / helper report structures
│   │   │   ├── risk.py               # RiskAssessment schemas
│   │   │   ├── threat_intel.py       # Threat intelligence schemas
│   │   │   ├── threat_report.py      # UnifiedThreatReport master Pydantic schema
│   │   │   ├── url_scan.py           # URL preflight and technical investigation schemas
│   │   │   └── __init__.py
│   │   ├── services/
│   │   │   ├── ai_analysis/          # Scam message analysis service
│   │   │   ├── blockchain/
│   │   │   │   ├── canonical_hash.py # RFC 8785 canonical JSON serializer & SHA-256 hasher
│   │   │   │   ├── service.py        # Off-chain / simulated blockchain registration & verification
│   │   │   │   └── __init__.py
│   │   │   ├── dns/                  # DNS record lookup and SSRF IP validation
│   │   │   ├── evidence/             # Normalizer (FROZEN - Part 13)
│   │   │   ├── redirects/            # Safe redirect tracing and connection IP pinning
│   │   │   ├── report_generator/     # assemble_unified_threat_report builder
│   │   │   ├── risk_engine/          # Deterministic risk engine rules and evaluator
│   │   │   ├── security_headers/     # HTTP security header parser and auditor
│   │   │   ├── severity/             # Finding severity and authority classifier
│   │   │   ├── technical_investigation.py # Coordinator for DNS, Redirects, TLS, Headers
│   │   │   ├── threat_intelligence/  # Threat intel lookup (URLhaus, GSB, heuristic corpus)
│   │   │   ├── tls_analysis/         # TLS certificate and cipher inspector
│   │   │   └── url_investigation/    # URL validation, SSRF preflight, normalization
│   │   └── main.py                   # FastAPI application initialization & middleware
│   ├── tests/                        # 23 test modules (293 tests)
│   ├── .env.example
│   └── requirements.txt
├── Brain/                            # Historical audit and phase execution reports (Part 01-20)
└── README.md
```

### 2.2 Member 3 Directory Structure (`CyberShield-Blockchain/`)
```
CyberShield-Blockchain/
└── CyberShield-Blockchain/
    ├── contracts/
    │   └── ThreatReportRegistry.sol   # Solidity 0.8.24 registry with role-based access & duplicate protection
    ├── artifacts/                     # Hardhat build artifacts & compiled ABIs
    │   └── contracts/ThreatReportRegistry.sol/ThreatReportRegistry.json
    ├── scripts/
    │   └── deploy.js                  # Deployment script saving deployment.json
    ├── test/
    │   ├── ThreatReportRegistry.test.js # 22 Mocha/Chai contract tests
    │   └── hash_consistency.mjs       # 7 cross-language hash consistency tests
    ├── python/
    │   ├── report_hash.py             # Python canonical serializer & Keccak-256 hasher
    │   ├── blockchain_service.py      # Python Web3 service for registerReport/verifyReport
    │   └── test_blockchain.py        # 40 pytest tests for report validation & blockchain service
    ├── lib/
    │   └── blockchain/
    │       └── threatReport.ts        # TypeScript UnifiedThreatReport interface & Keccak-256 hasher
    ├── app/
    │   └── api/
    │       └── blockchain/
    │           └── route.ts           # Next.js App Router API route
    ├── hardhat.config.js              # Hardhat configuration (Solidity 0.8.24, local EVM)
    ├── package.json                   # NPM dependencies (hardhat, ethers, mocha, chai)
    ├── deployment.json                # Local deployment info (contract address, deployer, block)
    ├── .env.example                   # Environment variable template
    └── Documentation markdown files   # Audit and readiness documentation
```

---

## 3. Existing Implementations and Integration Points

### 3.1 Report Generation & Schema
- **Member 1**: Generates `UnifiedThreatReport` (`backend/app/schemas/threat_report.py`). Contains rich investigation details: `scan_id`, `submitted_input`, `risk`, `evidence_coverage`, `technical_findings`, `threat_intelligence`, `ai_analysis`, `recommendations`, `limitations`, `report_integrity`, `persistence_metadata`.
- **Member 3**: Expects `UnifiedThreatReport` (`lib/blockchain/threatReport.ts` and `python/report_hash.py`) with 10 required fields: `report_id`, `schema_version`, `detected_at`, `generated_at`, `severity`, `category`, `status`, `confidence_score`, `summary`, `description`, plus optional arrays `indicators`, `affected_assets`, `remediation_steps`, `mitre_techniques`, and `threat_actor`.

### 3.2 Cryptographic Hashing
- **Member 1 (`canonical_hash.py`)**: Uses RFC 8785 principles (`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`) producing a SHA-256 hash. Mutated fields `report_integrity` and `persistence_metadata` are excluded.
- **Member 3 (`report_hash.py` & `threatReport.ts`)**: Uses identical RFC 8785 sorting/separators, but computes **Keccak-256** (`Web3.keccak` / `ethers.keccak256`) and derives `reportId = keccak256(abi.encodePacked("CYBERSHIELD_REPORT_V1", reportHash))` to match the Solidity contract requirement.
- **Contract (`ThreatReportRegistry.sol`)**: Accepts `bytes32 reportHash`. In EVM semantics, `bytes32` is an arbitrary 32-byte value. It stores `reportHash` and indexes by `reportId = keccak256(abi.encodePacked(NAMESPACE, reportHash))`.

### 3.3 Blockchain Service & API Routes
- **Member 1 (`backend/app/services/blockchain/service.py`)**: Designed for Part 19. If `is_real_blockchain_configured` is false, it returns honest `simulated` status with simulated hashes.
- **Member 3 (`python/blockchain_service.py`)**: Implements real Web3.py transactions calling `contract.functions.registerReport(report_hash)`, validating `receipt.status == 1`, handling nonces, gas, private key signatures, and calling `verifyReport(report_id, report_hash)`.
- **Member 1 API Endpoints**:
  - `POST /api/v1/reports/register` (Protected with API auth)
  - `POST /api/v1/reports/verify` (Public integrity check)
- **Member 3 Next.js Route**:
  - `POST /api/blockchain` with actions `"hash"`, `"verify"`, `"register"`.

---

## 4. Identified Compatibility Issues & Resolutions

| Issue ID | Identified Issue | Severity | Resolution Strategy |
|---|---|---|---|
| **COMPAT-01** | **Report Schema Divergence**: Member 1 uses complex nested schema (`scan_id`, `risk`, `technical_findings`, etc.), while Member 3 validates 10 specific flat/top-level fields (`report_id`, `severity`, `confidence_score`, etc.). | High | Implement a dedicated schema adapter `backend/app/services/blockchain/adapter.py` that maps Member 1's `UnifiedThreatReport` deterministically to Member 3's format without losing technical evidence. |
| **COMPAT-02** | **Cryptographic Hash Algorithm Divergence**: Member 1 uses SHA-256 in existing tests; Member 3 contract and services use Keccak-256. | High | Support both: retain SHA-256 for Member 1 internal report integrity while providing Keccak-256 for EVM smart contract registration and verification. Ensure EVM registration uses Keccak-256 matching `ThreatReportRegistry.sol`. |
| **COMPAT-03** | **Blockchain Execution Mode**: Member 1 relies on simulation mode in tests; Member 3 requires a live EVM node or throws `ConnectionError`. | High | Integrate Member 3's real Web3 capabilities into `service.py` while preserving transparent fallback to `SIMULATED` mode when no live node/contract is available, preventing test suite failure. |
| **COMPAT-04** | **Artifacts and ABI Location**: Member 3 Python code used hardcoded relative paths (`parent.parent / "deployment.json"`). | Medium | Make ABI and deployment paths configurable via environment variables (`REGISTRY_ABI_PATH`, `REGISTRY_CONTRACT_ADDRESS`, etc.) with intelligent fallbacks. |
| **COMPAT-05** | **Private Key / Signer Configuration**: Environment variable precedence between `BLOCKCHAIN_PRIVATE_KEY` and `DEPLOYER_PRIVATE_KEY`. | Medium | Support both variables in order, prioritizing `BLOCKCHAIN_PRIVATE_KEY` and falling back cleanly to `DEPLOYER_PRIVATE_KEY` or unlocked local accounts. |
| **COMPAT-06** | **Next.js Integration**: Member 3 created Next.js TypeScript files (`lib/blockchain/threatReport.ts` and `app/api/blockchain/route.ts`), while Member 1 is a FastAPI Python backend. | Low | Retain the TypeScript integration files in `blockchain/lib` and `blockchain/app` for future Member 4 (frontend) integration, and verify cross-language hash parity with Python. |

---

## 5. Audit Conclusion

The two modules are complementary:
- Member 1 provides the end-to-end security analysis engine and persistent threat report generator.
- Member 3 provides the cryptographic commitment ledger, EVM contract, Web3 signing pipeline, and on-chain verification.

The integration baseline in `Integration_Member_1_3` can proceed to Phase 2 (Schema Compatibility) and Phase 3 (Hash Compatibility).

