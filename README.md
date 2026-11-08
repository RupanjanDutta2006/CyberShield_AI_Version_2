# CyberShield AI — Intelligent Threat Detection & Blockchain Verification Platform

CyberShield AI is an enterprise-grade cybersecurity analysis platform combining **multi-vector technical website forensics**, **multi-provider AI scam & social engineering detection**, and **decentralized blockchain report immutability**.

Developed for the **Adamas Hackathon**, this repository represents the unified production integration of all four team members' engineering deliverables into one cohesive, fully verified, and runnable platform.

---

## 🏛️ System Architecture

CyberShield AI integrates four synchronized engineering pillars:

```
                            ┌───────────────────────────────────┐
                            │    React 18 + Vite Frontend UI    │
                            │   (Three.js 3D Ceramic Robot)     │
                            └─────────────────┬─────────────────┘
                                              │ HTTP / JSON
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Unified API Gateway (v1)                              │
├────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
│ 1. Forensic URL Engine     │ 2. AI Scam Analyzer Engine  │ 3. Web3 Blockchain Adapter  │
│ - SSRF Zero-Outbound Guard │ - Groq (Llama 3.3 70B)      │ - Canonical JSON Hashing    │
│ - DNS Record Audit (RFC)   │ - Gemini 1.5 Flash          │ - ThreatReportRegistry.sol  │
│ - Safe Redirect Tracing    │ - OpenAI GPT-4o-mini        │ - On-Chain Verification     │
│ - TLS X.509 Certificate    │ - Offline Heuristic Engine  │ - Tamper Detection          │
│ - Defensive Security Hdr   │ - Prompt Injection Defense  │ - Hardhat / EVM Compatible  │
└─────────────┬──────────────┴──────────────┬──────────────┴──────────────┬──────────────┘
              │                             │                             │
              ▼                             ▼                             ▼
   Threat Intel Feeds             SQLAlchemy Persistence        EVM Smart Contract
 (URLhaus & PhishTank)           (SQLite / PostgreSQL DB)       (Local / Testnet)
```

### Team Contributions & Module Ownership

- **Member 1 (Backend & Forensics):** Preflight SSRF safety guard, DNS resolver, multi-hop redirect tracer, TLS/SSL inspection, defensive HTTP header auditor, deterministic 0–100 risk scoring engine, and `UnifiedThreatReport` schema.
- **Member 2 (AI Scam Analyzer):** 4-tier multi-provider LLM failover (Groq -> Gemini -> OpenAI -> Local Heuristics), adversarial prompt injection defense, `EvidenceValidator`, and regex artifact extractor.
- **Member 3 (Blockchain / Web3):** `ThreatReportRegistry.sol` Solidity contract, 29-case Hardhat verification suite, Web3.py adapter client, cross-language canonical hash consistency, and tamper-proof audit verification.
- **Member 4 (Frontend UI & Orchestration):** React 18 + TypeScript + Vite + Tailwind CSS dashboard with interactive Three.js 3D ceramic security robot, live threat intelligence integration, scan history, and cryptographic report verification modal.

---

## 🚀 Quick Start Guide

### ⚡ Option A: One-Click Instant Launch (Windows)

Simply double-click the included batch script in the project root:

```bash
START.bat
```
- Automatically checks Python, Node.js, and dependencies.
- Prevents duplicate server processes.
- Opens **Backend** (port 8000) and **Frontend** (port 5173) in separate titled console windows with live logs.
- Automatically launches your browser to **`http://localhost:5173`**.
- To stop all servers cleanly, double-click **`STOP.bat`**.

---

### 🛠️ Option B: Manual Installation & Startup
- **Python:** 3.11 or higher
- **Node.js:** v18 or higher (with npm)
- **Git**

---

### 1. Installation

Clone or navigate to the integrated repository:
```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration"
```

#### Set Up Environment Variables
```bash
# Copy template configuration
cp .env.example backend/.env
cp .env.example frontend/.env
```

#### Install Backend Dependencies
```bash
cd backend
python -m pip install -r requirements.txt
# Alternatively: pip install fastapi uvicorn pydantic pydantic-settings sqlalchemy web3 certifi dnspython cryptography requests pytest pytest-asyncio
```

#### Install Blockchain Dependencies
```bash
cd ../blockchain
npm install
```

#### Install Frontend Dependencies
```bash
cd ../frontend
npm install
```

---

### 2. (Optional) Run Local Blockchain Node

To activate live EVM blockchain report anchoring:

```bash
# In Terminal 1 (Start local EVM node):
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\blockchain"
npx hardhat node

# In Terminal 2 (Deploy registry contract):
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\blockchain"
npx hardhat run scripts/deploy.js --network localhost
```
*Note: If no blockchain node is running, the application gracefully operates in **Simulation Mode** without failing.*

---

### 3. Start Backend API Server

```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **API Base:** `http://127.0.0.1:8000`
- **Interactive Swagger Docs:** `http://127.0.0.1:8000/docs`
- **ReDoc Documentation:** `http://127.0.0.1:8000/redoc`

---

### 4. Start Frontend Client

```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\frontend"
npm run dev
```
- Open `http://localhost:5173` in your web browser.

---

## 🧪 Testing & Verification

The project includes exhaustive automated test suites covering all four engineering layers:

### 1. Full Backend Pytest Regression (381 Tests)
```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration"
python -m pytest backend/tests -v
```
*Expected: 381 passed in ~19 seconds.*

### 2. Blockchain Smart Contract Suite (29 Tests)
```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\blockchain"
npx hardhat test
```
*Expected: 29 passing in ~750ms.*

### 3. Live EVM Integration & Web3 Adapter
```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration"
python backend/tests/verify_live_evm.py
```
*Expected: Registration, Verification, Duplicate Rejection, and Tamper Detection all succeed.*

### 4. Frontend Production Build
```bash
cd "D:\Adamas Hackathon\CyberShield_AI_Final_Integration\frontend"
npm run build
```
*Expected: Clean compilation with 0 TypeScript/Vite errors.*

---

## 📡 API Endpoints Summary

| Endpoint | Method | Purpose |
|---|---|---|
| `POST /api/v1/scans/url` | `POST` | Comprehensive technical website investigation (DNS, TLS, Redirects, Headers, Threat Intel). |
| `POST /api/v1/scans/message` | `POST` | AI scam and social engineering analysis with prompt injection defense. |
| `GET /api/v1/scans` | `GET` | Paginated scan history with threat scoring. |
| `GET /api/v1/scans/{scan_id}` | `GET` | Detailed telemetry and evidence for a specific scan. |
| `POST /api/v1/reports/{report_id}/verify` | `POST` | Cryptographic report integrity check and on-chain verification. |
| `GET /api/v1/system/status` | `GET` | Operational status of DB, AI providers, Threat Intel, and Web3 RPC. |
| `GET /api/v1/stats` | `GET` | High-level metrics for dashboard cards. |
| `POST /api/v1/url/preflight` | `POST` | Offline SSRF validation and URL normalization. |
| `POST /api/v1/analyze-message` | `POST` | Direct Member 1 / Member 2 message analysis endpoint. |
| `POST /api/v1/reports/investigate` | `POST` | Coordinated Member 1 forensic investigation. |
| `POST /api/v1/reports/register` | `POST` | Anchor canonical report hash into `ThreatReportRegistry.sol`. |
| `POST /api/v1/reports/verify` | `POST` | On-chain verification of report hash integrity. |

For detailed request and response contracts, consult [API_INTEGRATION_DOCUMENTATION.md](API_INTEGRATION_DOCUMENTATION.md).

---

## 📂 Project Structure

```
CyberShield_AI_Final_Integration/
├── .env.example                       <- Environment configuration template
├── .gitignore                         <- Version control exclusions
├── README.md                          <- Project overview and guide
├── FINAL_INTEGRATION_REPORT.md        <- Integration and architectural audit report
├── API_INTEGRATION_DOCUMENTATION.md   <- Complete REST API specifications
├── TEST_RESULTS.md                    <- Execution logs and test evidence
├── KNOWN_ISSUES.md                    <- Technical caveats and operational notes
├── backend/                           <- FastAPI application
│   ├── app/                           <- Core services, routers, models, schemas
│   └── tests/                         <- 28 test files (381 unit and E2E tests)
├── blockchain/                        <- Hardhat project & Solidity contracts
│   ├── contracts/                     <- ThreatReportRegistry.sol
│   ├── scripts/                       <- Contract deployment scripts
│   └── test/                          <- Hardhat unit & cross-language tests
└── frontend/                          <- React 18 + Vite + Tailwind CSS application
    └── src/                           <- UI components, Three.js robot, API client
```

---

## 📄 Documentation Index
- **[Final Integration Report](FINAL_INTEGRATION_REPORT.md)** — Architectural reconciliation, cross-member merges, and source-of-truth mappings.
- **[API Integration Documentation](API_INTEGRATION_DOCUMENTATION.md)** — Complete schemas, status codes, and frontend consumers.
- **[Test Execution Results](TEST_RESULTS.md)** — Execution logs from Pytest, Hardhat, Web3, and Vite.
- **[Known Issues & Operational Notes](KNOWN_ISSUES.md)** — Fallback tiers, simulation modes, and environmental dependencies.

---

## 🛡️ License & Acknowledgments
Built with ❤️ for the **Adamas Hackathon 2026**.
Dedicated to creating a safer, scam-resistant digital ecosystem.

