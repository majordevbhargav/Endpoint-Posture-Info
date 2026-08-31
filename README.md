# Endpoint Posture and Compliance Platform

This is the restructured build described in `docs/Endpoint_Posture_Platform_Project_Plan.md`:
frontend and backend split into separate folders, PostgreSQL as the
database, and Phase 1 (decoupled ISE enforcement) already wired in.

## Folder structure

```
endpoint-posture-platform/
├── backend/
│   ├── app/                              Flask services + collectors
│   │   ├── posture_app.py                Ingests posture results (Postgres). No auto ISE writes.
│   │   ├── posture_ui.py                 Dashboard API + queue worker, serves frontend/public/*.html
│   │   ├── posture_db.py                 PostgreSQL data layer (same public functions as the old SQLite one)
│   │   ├── ise_transport.py              Transport interface (Section 8.3)
│   │   ├── ers_transport.py              ISE ERS REST implementation (default)
│   │   ├── pxgrid_transport.py           ISE pxGrid implementation (stub, Phase 5)
│   │   ├── ise_session_watcher.py        Polls ISE sessions, now tracks connect/disconnect
│   │   ├── application_remediation.py    Reused as-is (Section 6)
│   │   ├── endpoint_360_integration.py   Reused as-is (Section 6)
│   │   ├── endpoint_experience_dashboard.py   Reused as-is
│   │   ├── endpoint_security_indicators.py    Reused as-is
│   │   └── endpoint_hardware_health_integration.py   New module (Section 6.1, Phase 3a)
│   ├── agents/
│   │   ├── posture_agent.ps1             Reused as-is (Windows WinRM/CIM posture collection)
│   │   ├── Save-PostureCredential.ps1    Reused as-is
│   │   └── hardware_health_agent.ps1     New (Phase 3a) - local mode implemented, remote mode TODO
│   ├── db/migrations/                    Readable, ordered SQL matching posture_db.init_db()'s schema
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── public/
│   │   ├── dashboard.html                Main dashboard (unchanged from the prototype, just relocated)
│   │   └── console.html                  Simpler queue/results console (extracted from posture_ui.py)
│   └── src/                              Placeholder for a future React rewrite (css/js currently empty -
│                                          dashboard.html's inline <script>/<style> stay inline for now,
│                                          per project plan Section 9.2)
├── docs/
│   └── Endpoint_Posture_Platform_Project_Plan.md
├── docker-compose.yml                    Local Postgres + Adminer only
└── .gitignore
```

## What already changed vs. the original prototype

- **Database**: SQLite → PostgreSQL. `posture_db.py` was rewritten against
  `psycopg2` but keeps the exact same function names (`save_assessment`,
  `get_assessments`, `get_db`, etc.) so every other module works unchanged.
- **Enforcement decoupled (Phase 1)**: `posture_app.py`'s `receive_posture()`
  no longer calls ISE at all. Three new admin-triggered routes do that
  instead: `POST /api/v1/endpoints/<mac>/share-posture`, `/restrict`,
  `/clear-restriction`. `posture_ui.py` proxies these so the dashboard never
  talks to ISE directly.
- **Connection-state tracking (Phase 2)**: `ise_session_watcher.py` now calls
  `mark_connected()` / `mark_disconnected()` on every poll, fixing the "seen
  forever" recheck gap (Problem 2) and letting `/api/dashboard/summary`
  report `not_connected` separately from compliant/non-compliant counts.
- **ISE transport abstraction (Section 8.3)**: `ise_transport.py` defines the
  interface; `ers_transport.py` wraps the existing `ISEClient` logic
  unchanged; `pxgrid_transport.py` is a clearly-labeled stub for Phase 5.
- **Frontend split out**: `dashboard.html` moved as-is into `frontend/public/`;
  `console.html` was extracted from the `INDEX_HTML` string that used to live
  inside `posture_ui.py`.
- **Hardware Health module scaffolded (Phase 3a)**: new blueprint, schema,
  and a PowerShell submission agent, built on
  `endpoint_hardware_warranty_collector.py`'s collection logic.

## What was intentionally left alone

`application_remediation.py`, `endpoint_360_integration.py`,
`endpoint_experience_dashboard.py`, `endpoint_security_indicators.py`,
`posture_agent.ps1`, and `Save-PostureCredential.ps1` were copied over
unchanged, per the project plan's file inventory (Section 6) - none of them
touch SQLite directly or perform automatic enforcement, so there was nothing
in them that needed to change for this pass.

## Running it locally

1. **Start Postgres:**
   ```bash
   docker compose up -d postgres
   ```
2. **Configure environment:**
   ```bash
   cd backend
   cp .env.example .env      # fill in ISE_HOST / ISE_USER / ISE_PASS when ready
   python -m venv .venv && source .venv/bin/activate   # Linux/Mac
   pip install -r requirements.txt
   ```
3. **Initialize the schema** (also happens automatically on first run of
   either Flask app via `init_db()`):
   ```bash
   cd app
   python -c "from posture_db import init_db; init_db()"
   ```
4. **Run the two Flask services** (on the Windows console host that has
   WinRM line-of-sight to endpoints, per Section 15 question 5):
   ```bash
   python posture_app.py     # posture ingestion + ISE actions, port 8000
   python posture_ui.py      # dashboard + queue worker, port 5000
   ```
5. **Run the watcher** on the same host:
   ```bash
   python ise_session_watcher.py
   ```
6. Open `http://127.0.0.1:5000/` for the dashboard, or `/console` for the
   simpler queue/results view.

## Still open before further phases (see project plan Section 15)

Questions 1, 2, 6, and 7 gate the rest of Phase 1's UI polish (operator
attribution in the audit log, confirming the ANC policy name). Questions 10
and 11 gate finishing the Hardware Health module's warranty lookup and
score thresholds. Nothing below has been implemented speculatively - the
stubs (`pxgrid_transport.py`, the remote mode in
`hardware_health_agent.ps1`) fail loudly rather than pretending to work.
