# CyberShield AI — Known Issues, Operational Caveats & Architectural Rationale

This document outlines architectural design decisions, environmental dependencies, and known edge-case behaviors across the integrated CyberShield AI application.

---

## 1. External AI Provider Keys & Fallback Engine Behavior

### Condition:
The AI Scam Analyzer module implements a 4-tier failover mechanism:
1. **Tier 1:** Groq Cloud (`llama-3.3-70b-versatile`)
2. **Tier 2:** Google Gemini (`gemini-1.5-flash`)
3. **Tier 3:** OpenAI (`gpt-4o-mini`)
4. **Tier 4:** Deterministic Local Heuristics (`offline_heuristic_engine`)

### Behavior:
If none of `GROQ_API_KEY`, `GEMINI_API_KEY`, or `OPENAI_API_KEY` are provisioned in `.env`, the system automatically and silently falls back to Tier 4 (`offline_heuristic_engine`).
- **Impact:** The application continues to function seamlessly with zero crashes and high precision regex-based indicator extraction, prompt injection defense, and grounded evidence generation.
- **Action Required for Production:** To activate deep semantic LLM reasoning, provide a valid API key in `.env`.

---

## 2. Blockchain Multi-Mode Operation (Live EVM vs Simulation)

### Condition:
The Web3 blockchain anchoring adapter in `app/services/blockchain/service.py` checks for the presence of `REGISTRY_CONTRACT_ADDRESS` and `WEB3_PROVIDER_URI`.

### Behavior:
- **When Configured:** Transactions are broadcast to the EVM node at `WEB3_PROVIDER_URI` (e.g. `http://127.0.0.1:8545` or an Ethereum Sepolia RPC), producing real transaction hashes (`blockchain_tx`), confirmed block numbers, and smart contract verification on `ThreatReportRegistry.sol`.
- **When Empty / Unreachable:** The system operates in **Simulation Mode** (`verification_status: "simulated_valid"` / `"locally_hashed"`).
- **Caveat:** When running the full backend test suite, if a local Hardhat node is not running on port 8545, tests automatically test simulation mode. If a local node is active, live EVM tests execute against contract `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

---

## 3. Threat Intelligence API Rate Limiting (URLhaus & PhishTank)

### Condition:
During high-frequency scanning or continuous integration runs, public endpoints for URLhaus and PhishTank may throttle requests or experience network latency.

### Behavior:
- The threat intelligence service implements in-memory caching (`THREAT_INTEL_CACHE_TTL=3600`) and safe exception catching.
- If a threat feed times out or returns HTTP 429/500, the scanner marks that provider's status as `unavailable` or `error` without failing the overall scan. The technical investigation (DNS, TLS, Headers, Redirects) continues unhindered.

---

## 4. Windows TLS Certificate Store (`certifi`)

### Condition:
On Windows operating systems, standard Python SSL context (`ssl.create_default_context()`) does not automatically load Windows system certificate stores, occasionally causing `UNTRUSTED_CHAIN` errors on domains using Let's Encrypt certificates.

### Resolution:
In `app/services/tls_analysis/service.py`, the SSL context is initialized with `cafile=certifi.where()`. This ensures consistent cross-platform certificate path validation across Windows, Linux, and macOS.

---

## 5. Early Security Gate: `POST /api/v1/scan-url` Gated (501)

### Rationale:
Member 1 designed `POST /api/v1/scan-url` as an early gated endpoint that deliberately raises `HTTP 501 Not Implemented` to prevent accidental raw, unmonitored outbound crawling.
- **Active Endpoints:**
  - `POST /api/v1/scans/url` — Safe, multi-stage, guarded investigation.
  - `POST /api/v1/reports/investigate` — Coordinated forensic investigation.
  - `POST /api/v1/url/preflight` — Zero-outbound offline syntax & SSRF validation.

---

## 6. Frontend Three.js 3D Bundle Size

### Condition:
During `npm run build`, Vite emits a warning:
`(!) Some chunks are larger than 500 kB after minification (dist/assets/index-BpIyep4N.js: ~1.24 MB)`.

### Rationale:
This is expected due to the inclusion of the Three.js 3D rendering pipeline and Lucide icon suite for the animated ceramic CyberShield robot (`frontend/src/components/robot`). For production CDN deployment, code-splitting via `React.lazy()` or Vite `rollupOptions.output.manualChunks` can be applied if sub-500kB chunks are required.

