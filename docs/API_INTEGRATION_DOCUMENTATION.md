# CyberShield AI — API Integration Documentation
**Version:** 1.0.0 (Unified 4-Member Integration)  
**Base URL:** `http://127.0.0.1:8000/api/v1`  
**OpenAPI Docs:** `http://127.0.0.1:8000/docs` (Swagger UI) & `http://127.0.0.1:8000/redoc` (ReDoc)

---

## 1. Overview & Architecture Contracts

CyberShield AI unifies the contributions of four distinct engineering domains into a coherent REST API surface:
1. **Frontend & Operations (Member 4):** Consumes `/api/v1/scans/url`, `/api/v1/scans/message`, `/api/v1/scans`, `/api/v1/scans/{scan_id}`, `/api/v1/reports/{report_id}`, `/api/v1/reports/{report_id}/verify`, `/api/v1/system/status`, and `/api/v1/stats`.
2. **AI Scam Intelligence (Member 2):** Powers social engineering detection, prompt injection defense, and conversational artifact extraction via `/api/v1/analyze-message` and `/api/v1/scans/message`.
3. **Forensic Website Investigation & Backend (Member 1):** Provides SSRF preflight, DNS inspection, redirect tracing, TLS evaluation, HTTP defensive headers, and deterministic risk scoring via `/api/v1/url/preflight`, `/api/v1/investigate/*`, and `/api/v1/reports/investigate`.
4. **Blockchain Integrity Registry (Member 3):** Offers cryptographic canonical hashing, immutable smart contract registration, and tamper detection via `/api/v1/reports/register`, `/api/v1/reports/verify`, and `/api/v1/reports/{report_id}/verify`.

---

## 2. Authentication Contract

- **Public Endpoints:** All scanning intake, report reading, health checks, stats, and verification endpoints are open for client usage.
- **Protected Endpoints:** Administrative endpoints (`/api/v1/reports`, `/api/v1/history`, `/api/v1/reports/investigate`, `/api/v1/reports/register`, `/api/v1/reports/verify`) enforce strict API key validation.
- **Accepted Headers:**
  - `X-API-Key: <api_key>`
  - `Authorization: Bearer <api_key>`
- **Default Key:** `cybershield-auth-key-2026` (configurable via `CYBERSHIELD_API_KEY` or `AUTH_SECRET_KEY`).

---

## 3. Complete Endpoint Inventory

### A. Core Frontend Scanning Endpoints (Member 4 & Unified Pipeline)

#### 1. URL Multi-Stage Investigation
- **Path:** `POST /api/v1/scans/url`
- **Frontend Consumer:** `frontend/src/components/scanner/UrlScanner.tsx`
- **Request Body:**
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response (`ScanDetailResponse`):**
  ```json
  {
    "scan_id": "9369be34-d079-450f-af58-e4b95f269ba1",
    "scan_type": "url",
    "target": "https://example.com",
    "normalized_target": "https://example.com/",
    "domain": "example.com",
    "hostname": "example.com",
    "status": "completed",
    "risk_level": "Low",
    "risk_score": 10,
    "created_at": "2026-11-08T15:00:00.000000",
    "providers_checked": [
      {
        "provider": "URLhaus",
        "indicator_type": "domain",
        "is_flagged": false,
        "threat_type": null,
        "confidence": 1.0,
        "details": {}
      },
      {
        "provider": "PhishTank",
        "indicator_type": "url",
        "is_flagged": false,
        "threat_type": null,
        "confidence": 1.0,
        "details": {}
      }
    ],
    "report": {
      "report_id": "78643196-8576-4d04-8ceb-ebad10115049",
      "summary": "Target passed initial security screening. Low risk indicators detected.",
      "evidence": [
        "Infrastructure verified across 2 independent threat intelligence feeds."
      ],
      "recommendations": [
        "Target appears safe based on current telemetry. Standard precautions apply."
      ],
      "report_hash": "62bf194380ebfe297ce1d5ae19028a38b55d9d700543e493240e94bb5fba9cf5",
      "verification_status": "locally_hashed",
      "blockchain_tx": null,
      "created_at": "2026-11-08T15:00:00.000000"
    },
    "events": [
      {
        "event_type": "ssrf_preflight",
        "description": "Passed zero-outbound SSRF preflight check.",
        "created_at": "2026-11-08T15:00:00.000000"
      },
      {
        "event_type": "technical_investigation",
        "description": "Completed Stage 3 multi-vector technical analysis (DNS, TLS, Redirects, Headers).",
        "created_at": "2026-11-08T15:00:00.000000"
      }
    ],
    "message_indicators": null,
    "analysis_engine": null
  }
  ```
- **Status Codes:** `200 OK`, `400 Bad Request` (SSRF violation or invalid URL).

---

#### 2. Message / Text Scam Analysis
- **Path:** `POST /api/v1/scans/message`
- **Frontend Consumer:** `frontend/src/components/scanner/MessageScanner.tsx`
- **Request Body:**
  ```json
  {
    "content": "URGENT: Your Chase account is suspended. Verify credentials and OTP at https://chase-login-update.com immediately."
  }
  ```
- **Response (`ScanDetailResponse`):**
  ```json
  {
    "scan_id": "f519ebad-b829-4df1-be7d-df9822a90100",
    "scan_type": "message",
    "target": "URGENT: Your Chase account is suspended...",
    "status": "completed",
    "risk_level": "Critical",
    "risk_score": 87,
    "created_at": "2026-11-08T15:01:00.000000",
    "report": {
      "report_id": "c928fa8e-9031-41c0-a8dc-37d402ba61d2",
      "summary": "High-risk credential harvesting detected.",
      "evidence": [
        "Observed pattern 'Urgent account suspension': Demands immediate verification under penalty of account closure.",
        "Extracted 1 target URL(s): https://chase-login-update.com"
      ],
      "recommendations": [
        "Do not click any links or provide credentials/OTPs.",
        "Contact your financial institution through verified official channels."
      ],
      "report_hash": "2ef7021666ffb59218d6ff841f4ba402b1f84501a3559f518e3c3b0eb68d4d80",
      "verification_status": "locally_hashed"
    },
    "message_indicators": [
      {
        "category": "OTP and credential theft",
        "severity": "Critical",
        "description": "Urgent account suspension: Coercive threat urging victim to act immediately."
      }
    ],
    "analysis_engine": "groq_llama3_70b"
  }
  ```
- **Status Codes:** `200 OK`, `422 Unprocessable Entity` (Empty content or < 5 characters).

---

#### 3. Scan History & Item Retrieval
- **Path:** `GET /api/v1/scans`
- **Frontend Consumer:** `frontend/src/components/history/ScanHistory.tsx`
- **Query Parameters:** `skip=0`, `limit=20`
- **Response (`ScanListResponse`):**
  ```json
  {
    "total": 42,
    "items": [
      {
        "scan_id": "f519ebad-b829-4df1-be7d-df9822a90100",
        "scan_type": "message",
        "target": "URGENT: Your Chase account is suspended...",
        "risk_level": "Critical",
        "risk_score": 87,
        "status": "completed",
        "created_at": "2026-11-08T15:01:00.000000"
      }
    ]
  }
  ```

- **Path:** `GET /api/v1/scans/{scan_id}`
- **Frontend Consumer:** `frontend/src/components/history/ScanDetailModal.tsx`
- **Response:** Returns full `ScanDetailResponse`.

---

#### 4. Cryptographic Report Integrity Verification
- **Path:** `POST /api/v1/reports/{report_id}/verify`
- **Frontend Consumer:** `frontend/src/components/history/ReportVerificationModal.tsx`
- **Request Body (Optional simulated tampering):**
  ```json
  {
    "simulated_tampered_summary": null
  }
  ```
- **Response (`VerifyReportResponse`):**
  ```json
  {
    "report_id": "c928fa8e-9031-41c0-a8dc-37d402ba61d2",
    "stored_hash": "2ef7021666ffb59218d6ff841f4ba402b1f84501a3559f518e3c3b0eb68d4d80",
    "recalculated_hash": "2ef7021666ffb59218d6ff841f4ba402b1f84501a3559f518e3c3b0eb68d4d80",
    "is_valid": true,
    "verification_status": "locally_hashed",
    "audit_notes": "Cryptographic SHA-256 fingerprint matches stored database record exactly.",
    "blockchain_verified": true,
    "blockchain_tx": "0xdaef93c560866320c5803ce9292232051f1e69bbec659653d31ef62816f4a43f"
  }
  ```

---

#### 5. Telemetry, System Health, and Stats
- **Path:** `GET /api/v1/system/status`
- **Response (`SystemStatusResponse`):** Checks database connectivity, AI providers, Threat Intel feeds, and Web3 RPC status.
- **Path:** `GET /api/v1/stats`
- **Response (`StatsOverviewResponse`):** Returns high-level metrics (total scans, critical threats, active providers).

---

### B. Member 1 Forensic Website Investigation Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/url/preflight` | `POST` | Public | Offline SSRF intake check, canonical URL normalization, and IP classification. |
| `/api/v1/investigate/dns` | `POST` | Public | DNS records resolution (A, AAAA, MX, TXT, NS) with anomaly detection. |
| `/api/v1/investigate/redirects` | `POST` | Public | Multi-hop safe HTTP redirect trace with per-hop SSRF validation. |
| `/api/v1/investigate/tls` | `POST` | Public | X.509 certificate hierarchy, issuer validity, SAN, and expiration audit. |
| `/api/v1/investigate/headers` | `POST` | Public | Passive evaluation of CSP, HSTS, X-Frame-Options, and Referrer-Policy. |
| `/api/v1/investigate/technical` | `POST` | Public | Coordinated execution of DNS + Redirects + TLS + Headers pipeline. |
| `/api/v1/reports/investigate` | `POST` | Required | Coordinated preflight + technical + threat intel investigation returning `UnifiedThreatReport`. |
| `/api/v1/history` | `GET` | Required | Paginated list of persisted `UnifiedThreatReport` records. |
| `/api/v1/reports` | `POST` | Required | Direct off-chain storage for pre-assembled threat reports. |
| `/api/v1/scan-url` | `POST` | Public | **501 Not Implemented Gate:** Directs callers to safe preflight or full investigation. |

---

### C. Member 2 AI Scam Analysis Endpoint

#### Flexible Multi-Contract Message Analysis
- **Path:** `POST /api/v1/analyze-message`
- **Method:** `POST`
- **Request Body (Member 1 Format):**
  ```json
  {
    "message_text": "URGENT: Your account is locked. Verify at https://secure-bank.test",
    "sender_hint": "security@alert.test"
  }
  ```
- **Request Body (Member 2 Format):**
  ```json
  {
    "message": "URGENT: Your account is locked. Verify at https://secure-bank.test",
    "message_type": "sms"
  }
  ```
- **Response:**
  Seamlessly returns structured AI scam analysis including `category`, `risk_level`, `observed_indicators`, and `recommendations` with multi-tier failover (Groq -> Gemini -> OpenAI -> Local Heuristic).

---

### D. Member 3 Blockchain Registry Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/reports/register` | `POST` | Required | Computes deterministic canonical hash and anchors `bytes32 reportId` into `ThreatReportRegistry.sol`. |
| `/api/v1/reports/verify` | `POST` | Required | Re-calculates report hash and calls smart contract `verifyReport(reportId, reportHash)` on-chain. |

---

## 4. Cross-Member Data Mapping & Integrity Guarantees

1. **Risk Score Normalization:**
   - Technical Engine: 0 to 100 integer.
   - AI Confidence: 0.0 to 1.0 float.
   - Classification mapping:
     - 0–34: `Low` / `Low Risk`
     - 35–69: `Medium` / `Suspicious`
     - 70–89: `High` / `High Risk`
     - 90–100: `Critical` / `Confirmed Malicious`
2. **Canonical Hash Algorithm:**
   All components compute deterministic SHA-256 digests over sorted JSON keys without whitespace:
   `SHA-256(json.dumps(obj, sort_keys=True, separators=(',', ':')))`
   Validated via 29/29 Hardhat cross-language tests.

