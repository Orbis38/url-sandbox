# Current security status — 2026-10-08

This report describes the current code and deployed Compose stack. Findings from the original commit remain documented separately in SECURITY_ASSESSMENT.md. Confirmed application behavior is distinguished from conditional post-compromise risks; no host/renderer exploit or dependency-CVE scan has been performed.

## Five changes implemented and deployed

| Change | Evidence | Operational effect |
|---|---|---|
| Database/Redis ports restricted | Docker publishes 27017/6379 only on 127.0.0.1 | UI/API unaffected; remote DB tools require a tunnel |
| Public Flask key removed and rotated | Private installation file, fail-closed loader, old-key cookie rejected on real stack | One login after rotation; API keys unchanged; later restarts preserve sessions |
| No automatic queue purge/recovery | Frontend restart preserves an unstarted task; atomic worker claim refuses started/terminal/deleted tasks | Queued work continues; interrupted work is not relaunched |
| Login/input limits | Account/IP counters shared through MongoDB, HTTP 429/Retry-After, invalid timeouts rejected before dispatch | Normal defaults unchanged; excess attempts/custom out-of-range inputs rejected |
| Periodic housekeeping | Maintenance remains running, unit tests restrict deletion to old exited project boxes | Running sessions untouched; reports/video retained 60 days; stale running jobs marked interrupted |

Redis AOF is persisted on a named volume with a one-second fsync interval. This preserves queued messages across ordinary broker recreation; it does not guarantee zero loss during a crash. A worker message lost between acknowledgement and the initial claim can leave an unstarted metadata record queued; there is deliberately no broker reconstruction/retry. Started executions without a terminal result are reconciled after roughly 6–7 minutes. Interrupted/failed summaries return HTTP 422, which API integrations must handle.

Session key: `.secrets/flask-session.key`, private permissions, excluded from Git and Docker build context. The value is never printed. Backend and maintenance do not receive that secret. Maintenance has Docker-socket access and disables its SELinux label to access that socket on this host; it is therefore an administrative component, not a low-privilege sandbox.

## Remaining findings

### R1 — High: static MongoDB/Redis credentials and excessive DB privileges

**Files/lines:** `shared/settings.py:18–31`; `docker-compose-dev.yml:96–122` (equivalent test Compose configuration).

**Cause:** published credentials remain in source and the application uses MongoDB's root account. Loopback publication removes ordinary direct LAN exposure but does not replace authentication or least privilege.

**Scenario/impact:** a local untrusted process or an attacker reaching an internal service can authenticate, alter accounts/reports or manipulate the broker. This can bypass application ownership controls. The former externally published-port configuration was Critical; current exploitability requires local/internal reachability.

**Fix:** rotate the actual MongoDB user password and Redis credentials, move them out of source and introduce a dedicated application MongoDB user/Redis ACL. Changing MONGO_INITDB_ROOT_PASSWORD alone does not rotate an existing database user.

**Urgency/operation:** urgent, particularly on a shared host. Normal UI and API keys can be retained; coordinated credential updates/reconnects cause a short maintenance window. No data migration is necessary.

### R2 — High: SSRF and unrestricted egress

**Files/lines:** `website/web.py:354,1002`; `box/qbsandbox.py:33–46,104–128,642–654`; Compose `frontend_box` network.

**Cause:** syntactic URL validation is not an egress policy. `localhost` is accepted; DNS names, redirects and browser subresources can reach private destinations. Direct mode remains available.

**Scenario/impact:** a user or a malicious analyzed page causes requests to reachable internal services, including state-changing GET endpoints. Controlled loopback access and redirects were reproduced. Direct private-IP literal URLs were rejected; cloud metadata access has not been tested.

**Fix:** enforce outbound network rules blocking private/link-local/metadata destinations, except explicitly required DNS/Tor gateway traffic. Cover redirects and subresources, not just the initial URL.

**Urgency/operation:** urgent before analyzing untrusted public links on a sensitive network. Public web analysis should continue; analysis of legitimate private URLs needs an explicit allowlist. The internal smoke fixture must be allowed in the test environment.

### R3 — High: HTTP/plaintext VNC transport

**Files/lines:** Compose website port/command (`7–10`); `box/qbsandbox.py` websockify startup; `backend/qbreport.py` iframe URL construction.

**Cause:** main UI/API and directly published VNC endpoints have no built-in TLS. VNC tickets are strong credentials but not encryption. Session cookies are not Secure while the site runs over HTTP.

**Scenario/impact:** an observer on an accessible network can capture passwords, API/session credentials, VNC tickets or screen content.

**Fix:** HTTPS plus authenticated WSS routing through a gateway; set Secure cookies only once HTTPS is enforced. Prevent bypass through direct HTTP/VNC listeners.

**Urgency/operation:** urgent for LAN/remote use; lower exposure for strictly local access. Medium operational impact: certificates/domain and VNC iframe/gateway routing must change together. Enabling HTTPS only on the main page breaks the current direct-port VNC URLs.

### R4 — High: resource exhaustion remains possible

**Files/lines:** `backend/worker.py:144–153`; `shared/settings.py:37`; `box/qbsandbox.py:780–896`; registration/API submission in `website/web.py`.

**Cause:** timeouts are bounded, but there are no global/per-user admission quotas or Docker CPU/RAM/PID limits. `max_concurrent_vnc` is not enforced. Control-socket calls refresh the idle timer, so they can keep a session alive beyond the requested duration. Public registration allows new identities.

**Scenario/impact:** an authenticated caller queues many jobs or keeps several browsers/recordings active; a hostile page allocates heavy CPU/RAM. Host exhaustion was not attempted.

**Fix:** global admission limit, per-user quotas, absolute session lifetime and measured container resource limits. Consider controlled registration for an internal analyst tool.

**Urgency/operation:** urgent for multiuser/exposed installations. Extra requests must queue or receive 429; heavy legitimate pages may need larger caps. Normal single-session usage can remain unchanged.

### R5 — High, conditional: worker/maintenance compromise gives host-level control

**Files/lines:** Compose worker `privileged`, Docker socket and host Docker config mounts; maintenance socket and SELinux label configuration; shared code mounts; `box/qbsandbox.py:598` and box Dockerfile root execution.

**Cause:** worker and maintenance possess an unrestricted Docker socket; the worker is privileged. Shared code is mounted writable into the website/backend. Chromium runs as root with `--no-sandbox`.

**Scenario/impact:** an initial code-execution compromise in an administrative component can take over the Docker host. A compromised frontend can also alter shared executable code. No direct command injection, renderer RCE or container escape was demonstrated.

**Fix:** make shared code mounts read-only (low-impact first step); remove unnecessary host Docker configuration mounts/privileged flags where tested; separate a minimal provisioning/reaping service with restricted operations. Run browser boxes unprivileged with a working browser sandbox or use a stronger isolation boundary.

**Urgency/operation:** important defense in depth for hostile-page analysis. Read-only code mounts should not affect normal use or host-side editing. Browser UID/sandbox changes require output permissions, sniffing capabilities and VNC regression tests; larger operational impact than credential rotation.

### R6 — Medium: non-atomic VNC port allocation

**Files/lines:** `backend/worker.py:43–82,118–120`.

**Cause:** a pending Redis reservation can be cleared before its container appears; reservation result is ignored; capacity exhaustion returns 6080 anyway.

**Scenario/impact:** concurrent requests choose the same port and sessions fail. VNC tickets prevent port knowledge alone from authorizing another session. Redis-set semantics were reproduced with a double, not a distributed load test.

**Fix:** atomic owned leases or Docker-assigned ports; explicit capacity errors; also reap containers left in Created state after failed startup (current housekeeping targets Exited state).

**Urgency/operation:** prioritize with increased concurrent use. Mostly transparent; full capacity must produce a clear error or waiting state instead of a failed session.

### R7 — Medium: “no redirect” does not prevent redirect navigation

**Files/lines:** `box/qbsandbox.py:642–654`; streamed HTTP inspection follows redirects.

**Cause:** both browser branches call navigation; implicit element waits do not disable redirects.

**Scenario/impact:** a 302 is followed even with the option selected, leading to unexpected destinations. Real Chromium reproduced this behavior.

**Fix:** implement a navigation policy covering HTTP, script and meta-refresh redirects, or remove/rename the misleading switch until it is supported.

**Urgency/operation:** medium; higher if analysts rely on this as a safety boundary. Blocking redirects changes results for redirect-heavy sites and authentication flows.

### R8 — Medium: weak passwords / open registration

**Files/lines:** `website/web.py:249–269` and RegistrationForm.

**Cause:** one-character passwords are still accepted; signup is public. Login throttling reduces online guessing but does not establish strong credentials or restrict account creation.

**Scenario/impact:** weak accounts are easier to guess; new identities can bypass future per-user quotas or consume bcrypt CPU through signup.

**Fix:** stronger registration password policy, signup limiting and optional invitation/admin control. Existing users can keep their accounts, with an explicit password-update policy.

**Urgency/operation:** medium, or high on a publicly reachable deployment. Affects new registrations and possibly future password changes; invitations change onboarding.

### R9 — Low: open redirect on login

**File/line:** `website/web.py:240`.

**Cause:** unvalidated `next` is passed to redirect. **Scenario/impact:** authenticated users are redirected to an attacker URL, enabling phishing/trust abuse; automatic cookie disclosure was not demonstrated.

**Fix/operation:** allow only local validated destinations. Small, low-impact fix; external `next` targets stop working.

## Conditional supply-chain and privacy risks

- `.github/workflows/main.yml:12–22` downloads and executes a mutable remote script, then pushes changes. Upstream compromise can execute runner code; no such compromise was attempted. Pin/verify the script and reduce workflow permissions. Application flow is unchanged, CI maintenance changes.
- Unpinned Python dependencies/images make rebuild behavior less predictable. Pin versions from the tested images; this is not a claim that specific dependency CVEs are present or absent. No normal UI impact, but upgrades become explicit.
- Tor is not a complete egress/anonymity boundary: DNS enrichment uses the local resolver and the box can use direct networking. Route required enrichment appropriately if anonymity is an operational requirement; DNS record coverage may change depending on the chosen resolver.
- Missing CSRF protection on cookie-authenticated JSON APIs remains defense in depth; the previously asserted same-site cross-origin JSON exploit was discarded after real-browser preflight/no-cors tests. No direct data-driven XSS or SSTI path has been found in normal report generation.

## Recommended order

1. Rotate service credentials and reduce DB privileges; make shared code mounts read-only.
2. Enforce egress isolation and bounded global resource admission.
3. Add HTTPS/WSS together if used over a network.
4. Correct port allocation, redirect semantics and registration policy; pin the CI script/dependencies.

Priorities depend on exposure: plaintext transport is immediately urgent for remote users; resource quotas become urgent under concurrent/untrusted use. None of these follow-ups introduces automatic recovery of interrupted analyses.
