# SENTINEL SOC — Gobuster Detection & Gateway Verification Test Log

## STEP 1: Discovery Report

### 1. Backend Start Command and Port
- **Start Command**: `python run.py` or `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **Port**: `8000`
- **Current Status**: Running (Active on `0.0.0.0:8000`)

### 2. Gateway Start Command and Port
- **Start Command**: `python gateway_proxy.py --port 8088`
- **Port**: `8088` (default, configurable via `--port`)
- **NGINX Spec**: `backend/nginx/sentinel_gateway.conf` defines a reverse proxy listening on port `80` with subrequest `/api/gateway/evaluate`
- **Current Status**: Not running

### 3. Upstream Routing Configuration
- **In `backend/gateway_proxy.py`**:
  - `BACKEND_BASE_URL`: `http://127.0.0.1:8000`
  - Real Traffic Destination: `http://127.0.0.1:8000/demo/real{req_path}`
  - Decoy Traffic Destination: `http://127.0.0.1:8000/demo/decoy{req_path}`
- **In `backend/nginx/sentinel_gateway.conf`**:
  - `real_application`: `127.0.0.1:8001` (backup `127.0.0.1:8000`)
  - `decoy_honeypot`: `127.0.0.1:8002` (backup `127.0.0.1:8000`)
- **Explicit `REAL_UPSTREAM` and `DECOY_UPSTREAM` variables**: **MISSING** from `backend/.env` and `backend/app/config.py`.

### 4. Upstream Process Status
- Port `8000` (Backend API & Demo Apps): **Running**
- Port `8001` / `9001` (Standalone Real App): **Not Running**
- Port `8002` / `9002` (Standalone Decoy App): **Not Running**
- Port `8088` (Gateway Proxy): **Not Running**

### 5. Artifacts and Endpoints Inventory

| Artifact / Endpoint | Status | Location / Actual Implementation |
|---|---|---|
| `pathintel.py` | **MISSING** | Not found anywhere in codebase |
| `enumeration.py` | **MISSING** | Not found in codebase (Enumeration detection logic currently lives in `app/services/behaviour_risk.py`) |
| `routes.yaml` | **MISSING** | Not found in codebase (`app/config/playbooks.yaml` exists for playbooks) |
| `GET /api/enumeration` | **MISSING** | No such endpoint registered |
| `GET /api/path-stats` | **MISSING** | No such endpoint registered (Closest: `/api/gateway/stats`, `/api/function-intelligence/stats`) |
| `GET /api/access-log` | **MISSING** | No such endpoint registered (Closest: `/api/audit`, `/api/events`, `/api/gateway/sessions`) |
| `POST /api/gateway/decide` | **MISSING** | No such endpoint registered (Actual gateway evaluation endpoint is `GET /api/gateway/evaluate`) |

---
**Status**: Step 1 complete. Awaiting user guidance before proceeding to Step 2/3/4 as instructed ("For anything missing, list it and STOP to tell me instead of inventing it").

