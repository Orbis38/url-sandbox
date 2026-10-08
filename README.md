<p align="center"> <img src="UrlProbe_icon.png" width="128"></p>
<h1 align="center">UrlProbe</h1>

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Engine%20%26%20Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)

**UrlProbe** is an automated, enterprise-grade threat analysis platform and web sandbox engineered to safely investigate suspicious URLs, phishing campaigns, credential harvesting pages, and malicious redirections in an isolated containerized ecosystem.

UrlProbe spins up ephemeral browser sandboxes equipped with anti-bot evasion techniques, real-time **30 FPS interactive desktop sessions (VNC)** with support for **up to 5 concurrent sessions**, **MP4 session video recording**, **per-analysis Tor IP rotation**, deep network telemetry (DNS, TLS, HTTP waterfalls, Scapy packet inspection), and a comprehensive **REST API** with local **multimodal AI vision assessment** (Gemma / Ollama) for SOC and SOAR incident response automation.

---

## Table of Contents
1. [Key Capabilities](#key-capabilities)
2. [Required Network Ports](#required-network-ports)
3. [System Architecture](#system-architecture)
4. [Analysis Execution Lifecycle](#analysis-execution-lifecycle)
5. [Interactive VNC Architecture & Concurrency](#interactive-vnc-architecture--concurrency)
6. [Data Persistence & Retention Policy](#data-persistence--retention-policy)
7. [REST API Documentation](#rest-api-documentation)
8. [Installation & Deployment](#installation--deployment)
9. [Operational Commands](#operational-commands)
10. [Security & Production Hardening](#security--production-hardening)
11. [License](#license)

---

## Key Capabilities

- **🛡️ Isolated Disposable Sandboxes**: Every analysis runs inside an isolated, disposable container running Debian, Xvfb, and Chromium 131 with anti-bot fingerprint masking, permission prompt suppression, and viewport emulation.
- **🖥️ Multi-Session 30 FPS Interactive VNC**: Direct, real-time control of the sandboxed browser via Openbox, x11vnc, and noVNC (1280×720 at 30 FPS). Click through multi-stage phishing funnels, bypass CAPTCHAs, or trigger dynamic malware scripts. Supports **up to 5 concurrent live sessions** with dedicated port isolation. Non-interactive analyses retain a 1440×900 browser window.
- **🎥 MP4 Video Session Recording**: Optional lightweight FFmpeg recording of the interactive X11 display. Captures the entire user navigation session into standard H.264 MP4 format, viewable directly within the report via an embedded video player or downloadable for forensic auditing.
- **📸 Flexible Screenshot Controls**: Independent options for standard viewport screenshots and full-page scrolling screenshots. Completely disabled when deselected.
- **🧅 Dedicated Tor Gateway & Instant IP Rotation**: Traffic can be routed through an isolated Tor container with remote DNS resolution (SOCKS5h) and active bootstrap synchronization. Executes `SIGNAL NEWNYM` via the Tor ControlPort before every run to guarantee a fresh exit node.
- **🤖 Multimodal AI Vision Heuristics**: Extracts visual features, detects credential harvesting fields, analyzes DOM brand impersonation heuristics, and produces an AI-ready summary optimized for local LLMs (Gemma, Llama, Ollama).
- **🍪 Intelligent Cookie Consent Suppression**: Automatically identifies and dismisses intrusive GDPR/cookie consent dialogs before screenshots and threat heuristics are calculated.
- **💾 Long-Term Persistence & 60-Day Auto-Pruning**: User accounts persist indefinitely in MongoDB Docker named volumes. Analysis records, GridFS documents, logs, and artifacts are automatically purged after 60 days.
- **⚡ Programmatic REST API**: Fully authenticated endpoints (`/api/v1/analyze`, `/api/v1/tasks/<id>`, `/api/v1/tasks/<id>/summary`, `/api/v1/tasks/<id>/screenshot`, `/api/v1/tasks/<id>/video`) for turnkey integration with SOAR platforms (Cortex XSOAR, Splunk SOAR, Shuffle).

---

## Required Network Ports

The following table summarizes all network ports utilized across the UrlProbe infrastructure. Ensure these ports are open on the host or permitted within your firewall rules:

| Port / Protocol | Direction / Scope | Service / Container | Description |
| :--- | :--- | :--- | :--- |
| **`8000/tcp`** | **Host Inbound** | `website` (Gunicorn / Flask) | **Web Interface & REST API**. Serves the dashboard, report viewer, authentication, and REST API endpoints. |
| **`6080 - 6100/tcp`** | **Host Inbound** | `box` containers (Websockify / noVNC) | **Interactive VNC Port Pool**. Dynamically allocated per interactive session. Allows up to 20 concurrent VNC sessions (up to 5 parallel Celery workers) directly accessible via browser. |
| **`6379/tcp`** | **Host / Docker Bridge** | `redis` | **Task Broker & State Lock**. Celery message queue, asynchronous task results, and atomic VNC port allocation tracking. |
| **`27017/tcp`** | **Host / Docker Bridge** | `mongodb` | **Primary Data Store**. Stores user accounts, task lifecycle logs (`taskdblogs`), and GridFS chunks for HTML/JSON reports and artifacts. |
| **`9050/tcp`** | **Docker Internal** (`frontend_box`) | `proxy` (Tor Daemon) | **Tor SOCKS5 / SOCKS5h Proxy**. Provides isolated anonymized routing with remote DNS resolution for sandboxed browsers. |
| **`9051/tcp`** | **Docker Internal** (`frontend_box`) | `proxy` (Tor ControlPort) | **Tor Control Interface**. Used by the sandbox orchestrator to verify 100% bootstrap status and trigger IP rotation (`SIGNAL NEWNYM`). |
| **`5900/tcp`** | **Container Internal** (Disposable `box`) | `x11vnc` | **RFB Protocol Server**. Internal VNC server capturing the Xvfb `:99` virtual display and feeding `websockify`. |
| **`Unix Domain Socket`** | **Shared Volume** (`/output/<task>/control.sock`) | `box` & `website` | **IPC Control Socket**. Enables real-time commands (clicks, scrolls, state capture, graceful shutdown) between the web app and running sandbox. |

---

## System Architecture

UrlProbe consists of five decoupled services connected through private internal Docker networks and persistent shared storage:

```
                                  ┌───────────────────────────────┐
                                  │     SOC Analyst / Browser     │
                                  │      SOAR / SIEM Workflows    │
                                  └──────────────┬────────────────┘
                                                 │ HTTP (8000) / REST API
                                                 ▼
                                  ┌───────────────────────────────┐
                                  │       UrlProbe Website        │
                                  │   (Flask / Gunicorn / Nginx)  │
                                  └───────┬───────────────┬───────┘
                                          │               │
                     Task Dispatch (6379) │               │ Mongo Auth & Queries (27017)
                                          ▼               ▼
                             ┌─────────────────┐   ┌──────────────────────────────┐
                             │  Redis Broker   │   │        MongoDB Store         │
                             │  & Port Lock    │   │  (Users, Reports, GridFS)    │
                             └────────┬────────┘   └──────────────────────────────┘
                                      │
                         Consume Task │ (Concurrency: 5)
                                      ▼
                        ┌──────────────────────────────┐
                        │      Workers API Node        │
                        │    (Celery Orchestrator)     │
                        └──────────────┬───────────────┘
                                       │ Docker Socket (/var/run/docker.sock)
                                       │ Launches ephemeral box containers
                                       ▼
            ┌─────────────────────────────────────────────────────────────┐
            │        Disposable Sandboxes (Up to 5 Concurrent)            │
            │  ┌───────────────────────────────────────────────────────┐  │
            │  │ Sandbox Container: `url-sandbox_box_<task_id>`        │  │
            │  │  - Xvfb Virtual Framebuffer (1280x720)                │  │
            │  │  - Openbox Window Manager                             │  │
            │  │  - Chromium 131 Stealth Webdriver                     │  │
            │  │  - x11vnc (5900) -> Websockify (Host Port: 6080-6100) │  │
            │  │  - FFmpeg (X11 grab -> session.mp4)                   │  │
            │  │  - Scapy Network Sniffer                              │  │
            │  │  - IPC Socket: `control.sock`                         │  │
            │  └──────────────────────────┬────────────────────────────┘  │
            └─────────────────────────────┼───────────────────────────────┘
                                          │
                                          │ SOCKS5h (9050) & ControlPort (9051)
                                          ▼
                             ┌────────────────────────┐
                             │   Tor Proxy Gateway    │
                             │  (IP Rotation NEWNYM)  │
                             └────────────────────────┘
```

---

## Analysis Execution Lifecycle

The sequence below illustrates the end-to-end processing pipeline when an analysis request is submitted:

```
Analyst/API        Website            Celery Worker       Docker Engine       Sandbox Container     Tor Gateway
    │                 │                     │                   │                     │              │
    │── POST /analyze ─>│                     │                   │                     │              │
    │   (URL, Options)│── Enqueue Task ────>│                   │                     │              │
    │<── Task ID ─────│   (Redis)           │                   │                     │              │
    │                 │                     │── Find Free Port ─│                     │              │
    │                 │                     │   (6080-6100)     │                     │              │
    │                 │                     │── Run Container ─>│                     │              │
    │                 │                     │   (Named Box)     │── Spawn Container ─>│              │
    │                 │                     │                   │                     │── Rotate IP ─>│
    │                 │                     │                   │                     │   (NEWNYM)   │<── 250 OK
    │                 │                     │                   │                     │── Navigate ──>│
    │                 │                     │                   │                     │   (Chromium)  │
    │                 │                     │                   │                     │── Dismiss Popups
    │                 │                     │                   │                     │── Screenshots │
    │                 │                     │                   │                     │── Network Map │
    │                 │                     │                   │                     │── Signal Done │
    │                 │                     │<── Read Done Marker ────────────────────│   (Done Marker)
    │                 │                     │── Build Report ──>│ (GridFS Store)      │              │
    │── Poll Status ─>│                     │                   │                     │              │
    │<── Complete ────│                     │                   │                     │              │
    │                 │                     │                   │                     │              │
    │── View Report ─>│── Fetch GridFS ────>│                   │                     │              │
    │                 │<── Rendered HTML ───│                   │                     │              │
    │                 │                     │                   │                     │              │
    │   [If Interactive VNC Session was selected]               │                     │              │
    │── GET /status ─>│── Check Socket ──────────────────────────────────────────────>│              │
    │<── Active/Port ─│                                                               │              │
    │── Connect VNC ─────────────────────────────────────────────────────────────────>│ (Websockify) │
    │   (ws://host:608x)                                                              │ (Live Click) │
    │── Finish Session─>│── Send 'close' ─────────────────────────────────────────────>│              │
    │                 │                                                               │── Stop FFmpeg│
    │                 │                                                               │── Save State │
    │                 │                                                               │── Exit Box   │
    │<── Reload ──────│                                                               └──────────────┘
```

---

## Interactive VNC Architecture & Concurrency

UrlProbe provides an isolated, multi-tenant interactive architecture designed to allow analysts to interact directly with live pages without cross-session bleed:

```
  Analyst A (Task A) ──────> noVNC Frame ──────> Host Port 6080 ──────> Box A (Websockify: 6080)
  Analyst B (Task B) ──────> noVNC Frame ──────> Host Port 6081 ──────> Box B (Websockify: 6080)
  Analyst C (Task C) ──────> noVNC Frame ──────> Host Port 6082 ──────> Box C (Websockify: 6080)
  Analyst D (Task D) ──────> noVNC Frame ──────> Host Port 6083 ──────> Box D (Websockify: 6080)
  Analyst E (Task E) ──────> noVNC Frame ──────> Host Port 6084 ──────> Box E (Websockify: 6080)
```

### Key Technical Mechanisms:
1. **Host-Level Port Reservation (`find_free_port`)**:
   `worker.py` checks Docker bindings and the Redis set `active_vnc_ports`. Allocation is not atomic: concurrent workers can choose the same port before a container becomes visible. Session tickets prevent port knowledge from authorizing another user's session, but port collisions remain an open availability issue documented in the security assessment.
2. **Per-Analysis Session Verification**:
   When opening any report, the frontend issues an asynchronous status check to `/live_interact/<task_id>/status`:
   - If the session for that **specific task** is still active, the assigned VNC port is dynamically loaded.
   - If the task is finished (or is an archived analysis), the VNC iframe is **never mounted**, preventing historical reports from mistakenly connecting to newly allocated sessions on reused ports.
3. **Clean Session Termination (No Reconnect Loops)**:
   - When the analyst clicks **"✓ Finish Session"**, the noVNC iframe is removed immediately from the DOM to eliminate "reconnecting..." visual loops.
   - A graceful `close` action is dispatched through `/output/<task>/control.sock`.
   - The sandbox captures the final visual state, flushes the FFmpeg video trailer, removes the socket, updates `vnc_session.json` to `status: "ended"`, and terminates.
   - The report updates to show a completed session badge alongside the MP4 playback controls.

---

## Data Persistence & Retention Policy

UrlProbe separates ephemeral execution from durable storage:

```
                            ┌──────────────────────────────────────────────┐
                            │               STORAGE ENGINE                 │
                            └──────────────────────┬───────────────────────┘
                                                   │
                  ┌────────────────────────────────┴────────────────────────────────┐
                  ▼                                                                 ▼
      ┌─────────────────────────┐                                       ┌─────────────────────────┐
      │   USER ACCOUNTS ENGINE  │                                       │     ANALYSIS ENGINE     │
      ├─────────────────────────┤                                       ├─────────────────────────┤
      │ • Collection: `users`   │                                       │ • Collection: `reports` │
      │ • Retention: INDEFINITE │                                       │ • Collection: `tasklogs`│
      │ • Volume:               │                                       │ • Storage: GridFS chunks│
      │   `url-sandbox_mongodb` │                                       │ • Files: MP4, logs, img │
      │                         │                                       │ • Retention: 60 DAYS    │
      └─────────────────────────┘                                       └────────────┬────────────┘
                                                                                     │
                                                      Scheduled Cleanups (Daily / Worker Startup)
                                                                                     │
                                                                                     ▼
                                                                        [Purged after 60 days]
```

- **User Accounts (`users`)**: Persist **indefinitely** inside the named Docker volume `url-sandbox_mongodb_data` mapped to `/data/db`. Stopping, restarting, or upgrading containers preserves all analyst logins.
- **Analysis Data & Artifacts**: Retained for **60 days**. The built-in cleanup subsystem (`shared/retention.py`) automatically prunes tasks older than 60 days on worker and web startup:
  - Deletes GridFS file binaries (HTML reports, raw logs, JSON blobs).
  - Removes metadata records from `reports`, `taskfileslogs`, and `taskdblogs`.
  - Removes physical on-disk directories (`/output/<task_id>`), including `session.mp4` video recordings and PCAP captures.

---

## REST API Documentation

Sign in and open **API Keys** in the sidebar to create a named key. Copy the token when it is shown: only its hash is stored, and the full token cannot be displayed again. The screen lists your keys, creation and last-use dates, and lets you revoke them.

Provide the token in `X-API-Key` or `Authorization: Bearer <token>`. Each key acts as its creator and can access only that user's analyses. There is no default or environment-wide API key; `URL_SANDBOX_API_KEY` is no longer used. Revoked keys and keys belonging to deleted users are rejected. An explicitly supplied invalid token is rejected even when a browser session is present.

The queue, active logs, reports, screenshots, video recordings and live-session controls are scoped to the authenticated user. New tasks are assigned an owner before they enter the queue. Legacy tasks without `owner_id` remain stored but are hidden; they must be assigned to a verified owner explicitly before they can be accessed.

Interactive sessions require a random per-session WebSocket ticket supplied only by the authenticated status endpoint. Each sandbox mounts only its own task directory. Rebuild and restart the website, worker and box images together to apply these changes; sessions started by older images do not gain these protections automatically.

### 1. Submit URL for Analysis
```bash
POST /api/v1/analyze
```
**Request Body (JSON):**
```json
{
  "url": "https://malicious-portal.example/login",
  "use_proxy": true,
  "interactive": true,
  "record_vnc": true,
  "take_screenshot": true,
  "take_full_screenshot": false,
  "block_cookies": true,
  "sniffer_on": false,
  "url_timeout": 10,
  "analyzer_timeout": 60,
  "interactive_timeout": 300,
  "useragent": "Chrome"
}
```
**Response (200 OK):**
```json
{
  "status": "queued",
  "task_id": "4b68ff03-3e11-46ab-a021-998847b744d0",
  "target_url": "https://malicious-portal.example/login",
  "use_tor": true,
  "interactive": true,
  "record_vnc": true
}
```

### 2. Retrieve AI Vision & Threat Assessment
```bash
GET /api/v1/tasks/<task_id>/summary
```

For compatibility, this response includes `screenshot_base64` as a `data:image/...;base64,...` URL by default. The image is encoded when the API response is requested; it is not duplicated inside the stored summary. Clients that only need metadata can request `GET /api/v1/tasks/<task_id>/summary?include_screenshot=false`, which omits the base64 field and keeps the authenticated `screenshot_url`.
**Response (200 OK):**
```json
{
  "task_id": "4b68ff03-3e11-46ab-a021-998847b744d0",
  "status": "COMPLETED",
  "target_url": "https://malicious-portal.example/login",
  "final_url": "https://login-security-update.com/verify",
  "http_status": 200,
  "tor_routed": true,
  "exit_ip": "185.220.101.4",
  "ai_assessment": {
    "verdict": "PHISHING",
    "risk_score": 95,
    "impersonated_brand": "Microsoft 365",
    "credential_theft_detected": true,
    "form_action": "https://exfil-node.pw/post.php"
  },
  "screenshot_available": true
}
```

### 3. Fetch Captured Screenshot
```bash
GET /api/v1/tasks/<task_id>/screenshot
```
Returns the AI-sized `image/jpeg` preview, or the original `image/png` when no preview is available. The preview retains the existing JPEG size/quality settings. For original-resolution images use `GET /api/v1/tasks/<task_id>/images/normal_image` or `/images/full_image`; `/images/circular_layout` returns the network graph. All image routes require the same user/session or API-key authorization as the task. Binary responses support private ETag revalidation.

New raw JSON reports contain small image descriptors with `artifact`, `content_type` and authenticated `url` fields instead of inline hexadecimal image bytes. Existing inline reports remain readable. HTML reports load binary images through the authenticated endpoints.

### 4. Stream or Download Recorded Session Video
```bash
GET /api/v1/tasks/<task_id>/video
```
Returns streamable `video/mp4` of the recorded interactive session (when `record_vnc` was enabled).

### 5. Check Live Interactive VNC Status
```bash
GET /live_interact/<task_id>/status
```
**Response (200 OK):**
```json
{
  "task": "4b68ff03-3e11-46ab-a021-998847b744d0",
  "active": true,
  "status": "active",
  "vnc_port": 6080,
  "has_video": true,
  "video_url": "/api/v1/tasks/4b68ff03-3e11-46ab-a021-998847b744d0/video"
}
```

---

## Installation & Deployment

### System Prerequisites
- **Operating System**: Linux (Ubuntu/Debian, openSUSE, Fedora/RHEL/CentOS).
- **Docker Engine**: Docker 20.10+ & Docker Compose v2.
- **Hardware Recommendations**: 4+ CPU cores, 8 GB RAM, 20 GB free disk space (to comfortably run 5 parallel browser sandboxes).

### One-Click Installation
```bash
# Clone the repository
git clone https://github.com/Orbis38/url-sandbox.git
cd url-sandbox

# Make runner executable and launch automatic configuration
chmod +x run.sh
sudo ./run.sh auto_configure
```

The script will automatically:
1. Detect and install required package dependencies (`curl`, `jq`, `docker`, `docker-compose`).
2. Verify Docker daemon operation and socket availability.
3. Build all service images (`website`, `workers_api`, `box`, `proxy`, `mongodb`).
4. Initialize the persistent MongoDB and storage volumes.
5. Launch all background microservices.

Open your browser at **`http://127.0.0.1:8000/`** to access the web dashboard.

---

## Operational Commands

Manage your deployment using `run.sh` or standard Docker Compose commands:

```bash
# Interactive menu
sudo ./run.sh

# Run development stack
sudo docker compose -f docker-compose-dev.yml up -d

# Stop all services (safely preserves database and files)
sudo ./run.sh stop
# OR
sudo docker compose -f docker-compose-dev.yml down

# View real-time container status
sudo docker compose -f docker-compose-dev.yml ps

# Follow application logs
sudo docker compose -f docker-compose-dev.yml logs -f workers_api
```

---

## Security & Production Hardening

1. **Firewall Ingress**: In production, restrict ports `27017` (MongoDB) and `6379` (Redis) to the local Docker network. Do not expose database ports to public interfaces.
2. **Reverse Proxy & HTTPS**: Deploy an Nginx, Caddy, or Traefik reverse proxy in front of port `8000` with valid TLS certificates (Let's Encrypt).
3. **Secret Keys**: The session key is installation-specific and loaded from the private `.secrets/flask-session.key` file. Run `python3 scripts/init_session_secret.py` once before using Compose directly; `run.sh` initializes it automatically and never replaces an existing key. Back up this private file outside Git. `URL_SANDBOX_SESSION_SECRET` or `URL_SANDBOX_SESSION_SECRET_FILE` can override it. Startup fails if the key is absent/too short. MongoDB and Redis credentials still need rotation and least-privilege configuration. Create per-user API keys from the sidebar.
4. **Sandbox Network Isolation**: The disposable `box` container uses the `url-sandbox_frontend_box` bridge. Browser and Requests traffic uses Tor when `use_proxy` is enabled, but this is not an egress firewall; apply network policies to block private and metadata destinations.

See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for reproduced findings, remaining risks and test commands.

## Restart behavior and housekeeping

- MongoDB and Redis host ports bind only to `127.0.0.1`. Container-to-container connections continue to use their Docker service names. Remote administrative connections now require a secure tunnel or equivalent access control.
- The frontend never purges the broker queue. Redis uses a named data volume and AOF (`appendfsync everysec`) for queued messages. This is not an exactly-once guarantee under crashes; up to the latest second of Redis writes may be lost.
- A task must exist in MongoDB and be unstarted before the worker can claim it atomically. Started, finished, interrupted, cancelled or deleted tasks are not rerun by broker redelivery. There is no retry/recovery of interrupted browser or VNC sessions. Submit a new analysis manually if needed.
- API status can be `queued`, `running`, `completed`, `failed`, `timed_out`, `interrupted` or `cancelled`. Failed/interrupted summaries return HTTP 422; clients should handle these terminal states. The dashboard shows error badges and retained logs/reports.
- `maintenance` checks every minute. It removes only stopped project boxes (after a 30-second grace period), never running ones. An unfinished running task becomes `interrupted` after the worker's maximum execution time plus 60 seconds (currently roughly 6–7 minutes including the scan interval). Queued tasks are left intact. Hourly retention removes artifacts older than 60 days, including old flat log files; accounts and API keys are retained.
- Login allows 10 attempts per account and 30 per source address per 15-minute fixed window. A successful login resets the account counter; excessive attempts return HTTP 429 and `Retry-After`. Forwarded IP headers are not trusted. Behind a reverse proxy, configure trusted proxy handling explicitly before relying on distinct client addresses.
- API timeout ranges are integers: URL 1–60 seconds, analysis 1–120 seconds, interactive 1–900 seconds. Existing UI choices/defaults are unchanged. Invalid values return HTTP 400 before creating a job; request bodies are limited to 1 MiB.

The first session-key rotation requires users to sign in again; subsequent restarts retain valid sessions and API keys. `RUN_LIVE_HARDENING_TESTS=1 python tests/live_hardening_smoke.py` explicitly checks loopback ports, AOF, timeout validation, pending-queue/session/API-key preservation across a frontend restart and rejection of cookies signed with the old public key. It pauses only an idle worker and cancels/removes its own test task before releasing it.

See [SECURITY_REMAINING.md](SECURITY_REMAINING.md) for current residual risks and the operational effect of further fixes.

## Analysis performance

- Network events are inserted into TinyDB in a single batch. Packet capture batches its writes, flushes the final batch on graceful shutdown and disables Scapy's redundant in-memory packet storage.
- PNG/JPEG artifacts live outside TinyDB JSON and are published once per content version to GridFS. Stored reports and summaries reference those artifacts; live screenshot updates replace binaries instead of rewriting the entire HTML report.
- DNS record lookups run concurrently with a five-second per-query lifetime. Header/certificate inspection shares a streamed GET request and closes it without downloading the final page body. Browser navigation remains a separate request.
- Task listings/status use projected fields and dedicated indexes. New logs are separate owner-scoped records, leaving task documents small. Active Logs initially shows up to 200 recent lines, then retrieves bounded cursor-based deltas. The visible log buffer retains 2,000 lines; the per-task Logs page still provides the complete retained history, including legacy embedded logs.
- Queue/log polling pauses in hidden tabs, slows when idle and schedules the next request after the current one completes.

Rebuild website, worker and box together before producing new-format captures. These changes do not alter VNC compression, frame rate, session limits or the previously selected resolutions. Index creation is idempotent at startup; the task index remains non-unique to accommodate existing duplicate legacy records.

For an explicit end-to-end check against the running local stack, run `RUN_LIVE_STACK_TESTS=1 python tests/live_stack_smoke.py` from a test environment with Docker SDK, Requests, BeautifulSoup, Pillow and websocket-client installed. This creates and removes two temporary accounts, keys, analyses and a local HTTP fixture. It verifies actual Chromium screenshots (including a full page), API image/base64 compatibility, user isolation, VNC authentication and 1280×720 desktop/video, key revocation, and default Tor navigation to example.com. Docker access is required; this script is excluded from automatic pytest discovery.

---

## License

This project is licensed under the terms of the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for complete details.
