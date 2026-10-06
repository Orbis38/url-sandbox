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
- **🖥️ Multi-Session 30 FPS Interactive VNC**: Direct, real-time control of the sandboxed browser via Openbox, x11vnc, and noVNC (1440×900 at 30 FPS). Click through multi-stage phishing funnels, bypass CAPTCHAs, or trigger dynamic malware scripts. Supports **up to 5 concurrent live sessions** with dedicated port isolation.
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
            │  │  - Xvfb Virtual Framebuffer (1440x900)                │  │
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
Returns `image/jpeg` containing the rendered target viewport.

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
3. **Secret Keys**: Rotate the session-signing `backend_key`, Redis password and MongoDB credentials before analyzing untrusted links in live SOC environments. Create per-user API keys from the sidebar.
4. **Sandbox Network Isolation**: The disposable `box` container uses the `url-sandbox_frontend_box` bridge. Browser and Requests traffic uses Tor when `use_proxy` is enabled, but this is not an egress firewall; apply network policies to block private and metadata destinations.

See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for reproduced findings, remaining risks and test commands.

---

## License

This project is licensed under the terms of the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for complete details.
