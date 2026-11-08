# CyberShield AI — Core Backend

**Lead:** Member 1 — Core Backend Lead  
**Framework:** FastAPI / Python 3.11  
**Architecture:** Modular Domain-Driven Service Architecture  

---

## 1. Directory Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application factory & lifecycle
│   ├── api/
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── router.py           # API v1 routes aggregation
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py               # Pydantic & environment settings
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── common.py               # Shared base models, enums & risk labels
│   │   ├── url_scan.py             # URL scan request/response contracts
│   │   ├── ai_analysis.py          # Member 2 AI scam analysis schemas
│   │   ├── threat_intel.py         # Member 4 threat intel schemas
│   │   ├── blockchain.py           # Member 3 Web3 verification schemas
│   │   └── threat_report.py        # Master Unified Threat Report schema
│   ├── services/
│   │   ├── __init__.py
│   │   ├── url_investigation/      # URL normalization & intake
│   │   ├── dns/                    # DNS inspection service
│   │   ├── redirects/              # Safe redirect tracing (SSRF protected)
│   │   ├── tls_analysis/           # TLS certificate & trust analysis
│   │   ├── security_headers/       # Passive HTTP headers evaluation
│   │   ├── risk_engine/            # Deterministic risk aggregation engine
│   │   ├── ai_analysis/            # Member 2 integration interface
│   │   ├── threat_intelligence/    # Member 4 integration interface
│   │   └── blockchain/             # Member 3 Web3 integration interface
│   ├── database/                   # Persistence layer (Member 4)
│   └── utils/                      # Shared helper utilities
├── tests/
│   ├── __init__.py
│   ├── test_health.py              # Health check endpoint tests
│   ├── test_schemas.py             # Schema validation and contract tests
│   └── test_app.py                 # FastAPI application and OpenAPI tests
├── .env.example                    # Environment variable template
├── requirements.txt                # Reused dependencies list
└── README.md                       # Backend documentation
```

---

## 2. Setup and Startup Instructions

### Prerequisites
- Python 3.11+
- Existing packages: FastAPI, Uvicorn, Pydantic, HTTPX, Pytest, Python-dotenv.

### Environment Configuration
Copy the template configuration file:
```bash
cp backend/.env.example backend/.env
```
Edit `backend/.env` with local configuration if needed. Never commit actual secret keys.

### Running the Development Server
From the project root:
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Or with `--app-dir` explicit directory binding:
```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
Or from within the `backend` directory:
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI Swagger UI will be available at:
- `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### Running Tests
From the project root:
```bash
python -m pytest backend/tests -v
```

---

## 3. Security Guardrails

1. **SSRF Safety Gate:** All outbound URL inspection routines are prohibited from accessing private RFC 1918 ranges, link-local addresses, cloud metadata endpoints, or loopback.
2. **Safe Degradation:** Unavailable external services must report `Inconclusive` or partial findings; they must never report a clean/safe verdict.
3. **Zero Secrets in Code:** Configuration is strictly pulled from the environment via `app.core.config.Settings`.

