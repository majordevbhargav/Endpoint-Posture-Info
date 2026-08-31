# Database Reference — Endpoint Posture & Compliance Platform

This document covers **only the database**: what engine it runs on, every
table that exists, what each column means, how tables relate to each
other, and how to look inside the database yourself at any time.

---

## 1. What database engine, and where does it live

- **Engine:** PostgreSQL 16
- **Where it runs:** inside a Docker container named `posture-postgres`,
  defined in `docker-compose.yml` at the project root
- **Port:** `5433` on your machine (mapped to Postgres's normal port
  `5432` inside the container — moved off `5432` because a separate,
  natively-installed Postgres was already using it on your machine)
- **Database name:** `posture`
- **Username:** `posture`
- **Password:** whatever is set in `POSTGRES_PASSWORD` in both `.env`
  files (root and `backend\.env` — they must match)
- **Where the data actually lives on disk:** inside a Docker-managed
  volume called `posture_pg_data`, not a plain file you can browse
  directly. This is why `docker compose down -v` deletes all your data —
  the `-v` flag removes that volume.

The connection details are read from `backend\.env` by `posture_db.py`
every time any part of the app starts (via `load_dotenv()`).

---

## 2. How Python talks to it

Every other file in the project (`posture_app.py`, `posture_ui.py`,
`application_remediation.py`, `endpoint_360_integration.py`,
`endpoint_hardware_health_integration.py`) goes through **one shared
module**, `posture_db.py`. Nothing else connects to Postgres directly.

```python
from posture_db import db

with db() as con:
    con.execute("SELECT * FROM endpoints WHERE mac = ?", (mac,))
```

`posture_db.py` keeps a small pool of open connections (up to
`POSTGRES_MAX_CONN`, default 10) so the app isn't opening/closing a fresh
connection on every single request.

---

## 3. What a "primary key" is, in plain terms

A **primary key** is the column (or columns) that uniquely identifies one
row in a table — no two rows can ever have the same value in that
column, and it's how other tables refer back to a specific row.

Two patterns are used across this database:

- **`SERIAL PRIMARY KEY`** — an auto-incrementing whole number (`1, 2, 3,
  ...`) that Postgres assigns automatically every time a new row is
  inserted. Used wherever a table is a growing history/log — you never
  pick this value yourself.
- **A natural key, like `mac TEXT PRIMARY KEY`** — instead of an
  auto-number, the real-world unique identifier (a device's MAC address,
  an IP address, an app name) *is* the primary key. Used where the
  real-world thing genuinely can't repeat — there's only ever one
  `endpoints` row per MAC address, for example.

---

## 4. All tables, grouped by what they're for

### Group A — Core posture (created by `posture_db.py`)

#### `endpoints`
One row per physical device ever seen. Updated in place every time a new
posture check runs (not appended — this table always reflects the
*latest known* state of a device).

| Column | Type | Notes |
|---|---|---|
| **`mac`** | TEXT | **Primary key.** The device's MAC address, uppercased. |
| `ip` | TEXT | Most recent known IP |
| `hostname` | TEXT | Computer name |
| `os`, `os_version` | TEXT | e.g. "Microsoft Windows 11 Pro" |
| `last_seen`, `first_seen` | TEXT | ISO-8601 UTC timestamps |
| `apps_count` | INTEGER | Count of installed apps as of last check |
| `manufacturer`, `model`, `serial_number` | TEXT | Hardware identity |
| `cpu_percent`, `memory_percent`, `memory_total_mb`, `memory_free_mb` | REAL | Latest resource snapshot |
| `connected` | INTEGER (0/1) | Is this device currently on an active ISE session right now? (Phase 2 fix) |
| `session_started` | TEXT | When the *current* connected session began |
| `last_disconnected` | TEXT | When it last dropped off |
| `shared_with_ise_at` | TEXT | Last time an admin clicked "Share Posture with ISE" |
| `enforcement_state` | TEXT | Last known restrict/clear-restriction result |

#### `assessments`
One row **per posture check ever run** — this is the append-only history
table. Never updated, only inserted into, so nothing is ever silently
overwritten.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** Auto-incrementing. |
| `mac` | TEXT | Which device this check was for (not a formal foreign key, but always matches an `endpoints.mac`) |
| `ip` | TEXT | IP at the time of this specific check |
| `timestamp` | TEXT | When this check ran |
| `status` | TEXT | `COMPLIANT`, `NON-COMPLIANT`, `ERROR`, `SKIPPED` |
| `detail` | TEXT | Human-readable summary |
| `submitted` | INTEGER (0/1) | Whether the agent's direct POST to `posture_app.py` succeeded |
| `submit_error` | TEXT | Error text if it didn't |
| `apps_count` | INTEGER | App count at the time of this check |

#### `check_results`
One row per **individual check** (Firewall, Open Ports, Application
Control) within one assessment. Several rows per `assessments` row.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `assessment_id` | INTEGER | **Foreign key** → `assessments.id`. `ON DELETE CASCADE`: if an assessment row is ever deleted, its checks go with it automatically. |
| `check_name` | TEXT | e.g. "Windows Firewall" |
| `status` | TEXT | `COMPLIANT` / `NON-COMPLIANT` / `ERROR` |
| `detail` | TEXT | Specifics, e.g. "Disabled: Public" |

#### `needs_attention`
Devices whose last check failed and are waiting on manual retry/skip
from the dashboard.

| Column | Type | Notes |
|---|---|---|
| **`ip`** | TEXT | **Primary key.** |
| `added_at` | TEXT | When it was flagged |

#### `endpoint_ports`
Listening TCP ports discovered on a device, one snapshot per check.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac` | TEXT | Which device |
| `port`, `process`, `pid` | INTEGER/TEXT | Port number, owning process name, process ID |
| `reachable` | INTEGER (0/1/NULL) | Did an active probe confirm this port actually responds? |
| `timestamp` | TEXT | Which check this snapshot belongs to |

#### `endpoint_processes`
Top processes by memory, one snapshot per check (old snapshot deleted and
replaced each time — this table is always "latest only," not history).

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac`, `name`, `pid` | TEXT/INTEGER | |
| `memory_mb`, `cpu_time_seconds` | REAL | |
| `timestamp` | TEXT | |

#### `endpoint_apps`
Installed application inventory, also "latest only" per device (old rows
deleted and replaced on each check, per device).

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac`, `name`, `version`, `publisher` | TEXT | |
| `timestamp` | TEXT | |

---

### Group B — Connection tracking (Phase 2)

#### `endpoint_session_log`
Append-only log of every connect/disconnect event, independent of
posture status. This is what makes "not connected" show up correctly on
the dashboard instead of a device looking compliant forever after it's
gone.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac`, `ip` | TEXT | |
| `event` | TEXT | `CONNECTED` or `DISCONNECTED` |
| `timestamp` | TEXT | |

---

### Group C — ISE admin actions (Phase 1)

#### `ise_action_audit`
Every time an admin clicks Share Posture / Restrict / Clear Restriction,
a row is written here — success or failure, always.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `timestamp` | TEXT | |
| `mac` | TEXT | |
| `action` | TEXT | `SHARE_POSTURE`, `RESTRICT`, or `CLEAR_RESTRICTION` |
| `operator` | TEXT | Who did it (currently blank — no login system yet, see project plan Section 15 Q6) |
| `result` | TEXT | `SUCCESS` or `FAILED` |
| `detail` | TEXT | Error message or confirmation text |

---

### Group D — Hardware Health module (Phase 3a)

#### `endpoint_hardware_health`
One row per hardware-health collection run.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac`, `timestamp` | TEXT | |
| `manufacturer`, `model`, `serial_number`, `bios_version` | TEXT | |
| `cpu_score`, `memory_score`, `storage_score`, `battery_score`, `overall_score` | INTEGER | 0–100 health scores |
| `hardware_event_count` | INTEGER | Windows Event Log hardware errors, last 7 days |
| `warranty_status`, `warranty_days_remaining` | TEXT/INTEGER | |
| `report_json` | TEXT | Full raw report, in case a field isn't broken out into its own column yet |

#### `endpoint_hardware_recommendations`
Proactive action items generated alongside each hardware health report.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `mac`, `timestamp` | TEXT | |
| `priority` | TEXT | `HIGH` / `MEDIUM` |
| `area` | TEXT | e.g. "Storage", "Hardware Events" |
| `action` | TEXT | Recommended action text |

---

### Group E — Endpoint 360 (experience + security), created by `endpoint_360_integration.py`

#### `endpoint_experience_history`
Wi-Fi/gateway/DNS/internet/application experience score, sampled
periodically for the console's own machine.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `timestamp`, `mac`, `ip`, `hostname`, `target` | TEXT | |
| `score` | REAL | 0–100 |
| `status`, `root_cause` | TEXT | |
| `endpoint_status`, `wifi_status`, `gateway_status`, `dns_status`, `internet_status`, `application_status` | TEXT | Per-component status |
| `gateway_latency_ms`, `gateway_loss_percent`, `wifi_signal_percent`, `dns_latency_ms`, `internet_latency_ms`, `tcp_443_latency_ms`, `https_latency_ms` | REAL | |
| `report_json` | TEXT | Full raw report |

#### `endpoint_security_history`
Lateral-movement / beaconing / suspicious-connection security score,
same sampling pattern.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `timestamp`, `ip`, `hostname` | TEXT | |
| `security_score` | REAL | |
| `risk_level`, `overall_status` | TEXT | |
| `high_findings`, `medium_findings`, `total_findings` | INTEGER | |
| `report_json` | TEXT | |

#### `endpoint_360_diagnostics` (created by `posture_ui.py`, not `posture_db.py`)
History of on-demand diagnostics run against a *selected fleet endpoint*
from the Endpoint 360 page (different from the two tables above, which
are about the console's own machine).

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `timestamp`, `ip` | TEXT | |
| `score`, `traceroute_hops` | INTEGER | |
| `status` | TEXT | |
| `endpoint_latency_ms`, `dns_latency_ms`, `application_latency_ms` | REAL | |
| `report_json` | TEXT | |

---

### Group F — Application Remediation, created by `application_remediation.py`

#### `app_classification`
Whether an application is Business Relevant / Business Irrelevant /
Review — one row per unique app name.

| Column | Type | Notes |
|---|---|---|
| **`app_key`** | TEXT | **Primary key.** Normalized (lowercased, whitespace-collapsed) app name. |
| `app_name` | TEXT | Original display name |
| `category` | TEXT | `Business Relevant` / `Business Irrelevant` / `Review` |
| `updated_at` | TEXT | |

#### `app_uninstall_selection`
Which apps are currently checked off for a bulk uninstall action.

| Column | Type | Notes |
|---|---|---|
| **`app_key`** | TEXT | **Primary key.** |
| `app_name`, `selected_at` | TEXT | |

#### `remediation_audit`
Log of every classify/select/uninstall action taken from the Remediation
page.

| Column | Type | Notes |
|---|---|---|
| **`id`** | SERIAL | **Primary key.** |
| `timestamp`, `action`, `application`, `endpoint_ip`, `endpoint_mac`, `detail` | TEXT | |

---

## 5. How the tables relate to each other

```
endpoints (1 device)
    │  mac
    ├──────────────► assessments (many checks over time)
    │                     │  id
    │                     └──────────────► check_results (many per check)
    │
    ├──────────────► endpoint_ports
    ├──────────────► endpoint_processes
    ├──────────────► endpoint_apps
    ├──────────────► endpoint_session_log
    ├──────────────► ise_action_audit
    └──────────────► endpoint_hardware_health
                              │  id
                              └────► endpoint_hardware_recommendations
```

Only `check_results.assessment_id → assessments.id` is an actual
database-enforced foreign key (with cascading delete). Every other
relationship (`mac` appearing in multiple tables) is a *logical* link the
application code relies on, not one Postgres enforces itself — this
matches how the original SQLite version was built, and keeps inserts fast
and simple, at the cost of Postgres not catching a typo'd MAC address for
you.

---

## 6. Where to look at the actual data yourself

You have three options, easiest first.

### Option 1 — Adminer (web-based GUI, no install needed)

It's already running via `docker-compose.yml`.

1. Make sure Postgres is up: `docker compose up -d`
2. Open **http://localhost:8080** in your browser
3. Log in:
   - **System:** PostgreSQL
   - **Server:** `postgres`
   - **Username:** `posture`
   - **Password:** whatever's in your `.env`
   - **Database:** `posture`
4. Click any table name on the left to browse its rows, or use the "SQL
   command" tab to run your own queries.

### Option 2 — `psql` inside the Docker container (command line)

```powershell
docker exec -it posture-postgres psql -U posture -d posture
```
Enter your password when prompted, then:

```sql
\dt                          -- list all tables
\d endpoints                 -- show a table's columns and types
SELECT * FROM endpoints;     -- see actual rows
SELECT * FROM assessments ORDER BY timestamp DESC LIMIT 10;
```
Type `\q` to exit.

### Option 3 — Any external Postgres client (DBeaver, pgAdmin, TablePlus, etc.)

Connect using:
- **Host:** `localhost`
- **Port:** `5433`
- **Database:** `posture`
- **Username:** `posture`
- **Password:** from `.env`

Any of these tools will let you browse tables, run queries, and export
data — useful once you want to look at things more seriously than
Adminer's simpler interface allows.

---

## 7. Resetting or inspecting from scratch

- **See every table that currently exists:**
  ```sql
  \dt
  ```
  (in `psql`) or check the left sidebar in Adminer.

- **Wipe everything and start over** (deletes all data permanently):
  ```powershell
  docker compose down -v
  docker compose up -d postgres
  ```
  Then re-run:
  ```powershell
  python -c "from posture_db import init_db; init_db()"
  ```
  This only recreates the Group A/B/C/D tables (the ones `posture_db.py`
  owns directly). Groups E and F get created automatically the first time
  `posture_ui.py` starts, since `register_endpoint_360()` and
  `register_remediation()` each run their own table-creation step on
  startup.
