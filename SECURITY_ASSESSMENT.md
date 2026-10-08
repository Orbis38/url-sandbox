# Security assessment and verification

Date: 2026-10-06. Original assessment baseline: `c138b775fd3857a0093e44f5927317eeff572fea`.

**Historical baseline assessment. Updated 2026-10-08:** the five agreed hardening changes are now implemented and deployed. For current dispositions and operational impact, use [SECURITY_REMAINING.md](SECURITY_REMAINING.md); statements below about open findings reflect the earlier assessment unless explicitly updated.

Baseline reproductions read that commit through `git show`; they do not reset or modify the worktree. A passing **assessment** test means that the stated baseline behavior was reproduced, not that the vulnerability is fixed. Regression tests separately exercise the updated implementation.

## Implemented changes

- **API Keys** sidebar page: create named per-user keys, show the plaintext token once, list metadata and revoke keys. Tokens contain 256 random bits; MongoDB stores only SHA-256 digests and a short display prefix. Creation/revocation forms enforce CSRF and the creation response uses `Cache-Control: no-store`.
- Removed the static/default/environment-wide API credential. Invalid, revoked and deleted-owner tokens are rejected. Explicit credentials take precedence over browser cookies.
- Persisted task ownership before Celery dispatch. Queue, active logs, reports, JSON, screenshots, summaries, recordings and live controls are scoped to the authenticated owner. Foreign and unowned legacy tasks return 404. The worker no longer inserts duplicate task records.
- Canonical UUID validation blocks malformed task identifiers and the query injection in the polling route.
- Live VNC requires a random session ticket; raw x11vnc listens only on localhost. Each box mounts only its own output directory. Log artifacts and the report builder now use that directory consistently.
- Fixed a colliding `validators` import that made incorrect passwords raise an AttributeError, and preserved proper HTTP status codes in the error handler.

At the time of the initial assessment deployment had not been performed. The updated stack was subsequently rebuilt, started and tested end to end. Legacy tasks are not automatically attributed because the original data does not record a trustworthy owner.

**Updated 2026-10-08:** the public Flask signing secret has been removed and rotated to a persistent private installation key. Old-secret cookie forgery is rejected on the deployed stack. MongoDB/Redis ports now bind to localhost; their static credentials remain a residual risk.

## Verification environment and limits

- Real Flask routes, templates, CSRF, Flask-Login, bcrypt and GridFS API; MongoDB storage simulated with mongomock and Celery dispatch isolated with test doubles.
- Real loopback HTTP services and websockify/WebSocket connections.
- Real Chromium 154 headless navigation and cross-origin requests. The redirect test runs the exact original navigation branch through a small browser adapter; it does not run the complete Selenium analysis pipeline.
- Real Docker bind-mount isolation using a locally cached `python:3.11-slim`, temporary containers and a temporary volume, with container networking disabled. Temporary resources are removed by the test.
- Worker failure and port allocation tests execute original functions with Docker/Redis doubles. They demonstrate application logic, not a live distributed load test.
- No production database, cloud metadata service or corporate LAN was contacted. No host-exhaustion test, Chromium exploit, dependency-CVE scan or CI supply-chain compromise was attempted.

## Findings after verification

The baseline file/line locations below refer to the original commit. Files changed by remediation have shifted line numbers.

| ID | Severity | Verification | Current disposition |
|---|---|---|---|
| 1 | Critical | Published service credentials/ports confirmed in configuration; no live database takeover attempted | Open |
| 2 | High | Default API token accepted by original Flask endpoint | Fixed; rejected by regression tests |
| 3 | High | Forged signed cookie authenticates on updated Flask app | Open |
| 4 | High | Another user retrieves a private report and enumerates tasks | Fixed; all task routes checked |
| 5 | High | Original websockify forwards VNC protocol without credentials | Fixed for new sessions; tickets tested over real WebSockets |
| 6 | High | Original Requests path reaches a controlled loopback service | Open; direct private-IP literal scenario narrowed |
| 7 | High | Global read/write mount confirmed in original code | Per-task mount fixed and tested in Docker; root/disabled browser sandbox remain |
| 8 | High | Extreme/negative timeouts accepted; missing quotas and teardown confirmed in code | Open; host exhaustion not attempted |
| 9 | Medium | Pending Redis reservation discarded, returning same VNC port | Open |
| 10 | Low | `..` retrieves a fixed-name parent file in original Flask route | Fixed by UUID/ownership guard |
| 11 | Medium | Simulated container startup failure yields `completed` with no report | Open |
| 12 | Medium | Real Chromium follows HTTP redirect with `no_redirect` both true and false | Open |
| 13 | Medium | Retention deletes task directory but leaves flat log file | Partially fixed for new artifacts; old logs and scheduling remain |
| 14 | Medium | HTTP configuration and missing cookie Secure flag confirmed | Open; no interception attempted |
| 15 | Medium | One-character registration password accepted; no attempt limiter in application | Open; account brute-force not attempted |
| 16 | Low | External `next` causes a redirect after authentication | Open |
| 17 | Medium | `$ne` injected into original polling route retrieves a report | Fixed by UUID/ownership checks |

### 1. Public service credentials and exposed MongoDB/Redis

**Locations:** `shared/settings.py:20–24,29–33`; `docker-compose-dev.yml:73–100`; `docker-compose-test.yml:69–94`.

**Cause:** fixed credentials distributed in source, MongoDB root credentials used by the app, service ports published without loopback-only bindings. **Scenario:** a reachable service accepts the documented credentials, allowing database changes or broker manipulation. **Impact:** account/report/data compromise, deletion and queue poisoning. **Remediation:** rotate credentials, remove external port publication, use external secrets and least-privilege DB users/Redis ACLs. **Evidence boundary:** configuration is confirmed; the exploit needs service reachability and unchanged credentials. No running application database was attacked.

### 2. Default API credential

**Locations:** original `shared/settings.py:4`; `website/web.py:820–840`.

**Cause:** a public fallback secret authorizes APIs without a user. **Scenario:** submit analyses using that token. **Impact:** unauthorized analysis/API access and a starting point for SSRF/resource abuse. **Remediation implemented:** per-user high-entropy credentials with hashed storage and revocation. **Tests:** `test_baseline_default_key_accepted`, `test_default_key_and_anonymous_rejected`, key lifecycle and deleted-owner tests.

### 3. Public Flask session-signing secret

**Locations:** `shared/settings.py:18`; original `website/web.py:71–74,100–105`.

**Cause:** static signing secret in source. **Scenario:** construct a signed session containing a known user's `_user_id`; no password is required. **Impact:** impersonation, including access through the new ownership checks and key-management page. **Remediation:** replace the secret with an externally supplied random value and invalidate old sessions. **Test:** `test_known_session_secret_forges_identity_on_current_app` returns 200 for the victim's private task using a fabricated cookie. The test intentionally uses a known victim ID; it does not prove discovery of that ID.

### 4. Missing per-user authorization

**Locations:** original `website/web.py:229–243,337–353,415–440,496–531,551–563,700–813,888–1023`; `shared/logger.py:24–31`.

**Cause:** no trusted task owner and authentication-only checks. **Scenario:** register/sign in, obtain UUIDs from the global queue and read/control someone else's tasks. **Impact:** cross-user information disclosure and interference. **Remediation implemented:** owner recorded before dispatch, scoped listings, authorization guard for every task route and ownership checks on polling. Unowned legacy tasks fail closed. **Tests:** cross-user baseline reproduction plus 18 route/credential combinations, queue/log scoping, legacy denial and positive owner reads.

### 5. Unauthenticated live VNC

**Locations:** original `box/qbsandbox.py:529–550`; `backend/worker.py:104–108,123–130`.

**Cause:** passwordless x11vnc and a public websockify port with no authentication. **Scenario:** connect directly to an active port, bypassing Flask. **Impact:** desktop viewing/control and local browser navigation. **Remediation implemented:** opaque per-session ticket validated by websockify; localhost-only x11vnc; authorized status endpoint supplies the ticket. **Tests:** original forwarding accepts no credentials; updated command rejects missing, incorrect and another session's token, accepting the correct ticket. A simulated VNC banner is the downstream target; no actual desktop or command execution was exploited. TLS is still a separate open requirement.

### 6. SSRF and unrestricted destinations

**Locations:** original `website/web.py:328–350,842–869`; `box/qbsandbox.py:101–112,160–167,654–664`; `docker-compose-dev.yml:104–111`.

**Cause:** syntactic URL validation without a network destination policy; direct mode permitted. **Scenario reproduced:** `http://localhost:<test-port>/private` passes validation and the actual header-extraction function reads a private-service marker. A browser also follows a redirect to loopback. **Impact:** requests to reachable internal services, internal information disclosure and endpoint side effects. Cloud metadata access is conditional and was not tested. **Remediation:** egress enforcement, protocol/destination restrictions and checks at every redirect/DNS resolution, including browser subresources.

**Correction:** the tested validator rejects direct literals `127.0.0.1`, `192.168.1.10` and `169.254.169.254`. A claim that those exact URLs are accepted is discarded. SSRF itself remains because `localhost` is accepted and redirects reach private destinations.

### 7. Shared sandbox artifacts / reduced browser isolation

**Locations:** original `backend/worker.py:115–130`; `box-Dockerfile:13–16`; `box/qbsandbox.py:613`.

**Cause:** each box receives the entire output volume read/write; runs as root with Chromium sandbox disabled. **Scenario:** desktop access or a compromised box can read other analyses' files. **Impact:** cross-analysis disclosure/modification. **Remediation implemented:** only the task subdirectory is mounted. **Tests:** worker launch contract, two sequential jobs without settings mutation, real box log-writing/report-building, and real Docker denial of sibling-directory access. **Remaining hardening:** run unprivileged and enable browser sandboxing. No Chromium RCE or container escape was demonstrated; these are not claimed as independently exploitable RCE findings.

### 8. Unbounded analysis resources and incomplete teardown

**Locations:** original `website/web.py:327–353,842–876`; `backend/worker.py:90–130,190–211`; `box/qbsandbox.py:791–909`; `shared/settings.py:39`.

**Cause:** absent quotas, unvalidated timeout ranges, ignored VNC concurrency setting, no explicit container CPU/RAM/PID limits and no normal interactive-container removal. **Scenario:** queue many jobs or request excessively long sessions. **Impact:** potential queue/port/memory/disk exhaustion and orphaned containers. **Remediation:** bounded schema, per-user quotas/backpressure, Docker limits, absolute session deadline and external cleanup reconciler. **Test:** original endpoint queues an interactive timeout of 1,000,000,000 and a negative URL timeout. Actual host exhaustion or persistence for that duration was not attempted.

### 9. VNC allocation race

**Locations:** original `backend/worker.py:37–76,104–130`.

**Cause:** Docker inventory and Redis reservation are separate; a reservation without an already visible container is removed and `SADD`'s result is ignored. **Scenario:** worker B allocates before worker A's container appears. **Impact:** duplicate port choice and failed sessions. **Remediation:** atomic owned leases, expiry and an explicit capacity error, or Docker-assigned ports. **Test:** a Redis set double reproduces the relevant semantics; two allocations return 6080 despite the first reservation. Cross-user reconnection caused by Docker port reuse was not demonstrated. New VNC tickets additionally prevent a wrong-session connection from being authorized merely by port knowledge.

### 10. Bounded path traversal

**Locations:** original `website/web.py:708,774–783,805–813`.

**Cause:** unchecked task segment in filesystem joins. **Scenario reproduced:** `/api/v1/tasks/../video` retrieves a pre-created parent `session.mp4`. **Impact:** reads outside the task directory, restricted to expected fixed filenames and the single-segment route. **Remediation implemented:** canonical UUID and owner validation before filesystem access. **Tests:** original fixed-name parent read and updated rejection. Arbitrary reading of `/etc/passwd` through this route was not demonstrated and is not claimed.

### 11. Failure reported as completion

**Locations:** original `backend/worker.py:190–211`; `shared/logger.py:34–39`; `website/web.py:427–432,902–907,929–941`.

**Cause:** error paths still set `end`, and APIs interpret that as success/completion. **Scenario reproduced:** Docker startup raises and report generation fails; task status is still `completed`. **Impact:** automation/operators may trust incomplete analysis. **Remediation:** explicit failure/timeout/partial states and artifact-completeness indicators. **Test:** original worker function with a simulated startup failure, then actual current status API. A false benign threat classification was not demonstrated.

### 12. Ineffective no-redirect switch

**Locations:** original `box/qbsandbox.py:654–664,160–167`.

**Cause:** both branches navigate using `get`; implicit element waits do not block redirects. **Scenario reproduced:** controlled 302 to a private page with the switch both enabled and disabled. **Impact:** unexpected navigation and increased SSRF exposure. **Remediation:** implement a navigation/proxy policy covering HTTP, JavaScript and meta-refresh redirects. **Test:** exact baseline branch plus real Chromium. Only the HTTP-redirect case was executed.

### 13. Incomplete retention

**Locations:** `shared/retention.py:29–31,57–74`; original `box/run.py:78,97`; `backend/qbreport.py:141–148`.

**Cause:** cleanup removes task directories while logs were stored beside them; no periodic scheduler found and an early return skips global-log pruning. **Scenario reproduced:** a 61-day task is removed while its flat private log survives. **Impact:** sensitive artifacts exceed the promised retention and consume disk. **Remediation partially implemented:** new log artifacts reside in the task directory. Remaining work: clean legacy flat artifacts, schedule recurring cleanup and reconcile orphaned artifacts/containers. **Test:** baseline cleanup against temporary files and isolated storage.

### 14. Plaintext transport / cookie configuration

**Locations:** both Compose files `7–9`; original `website/web.py:71–74`; `box/qbsandbox.py:545–550`.

**Cause:** distributed listeners use HTTP/websockify without TLS, and the cookie Secure flag is not enabled. **Scenario:** a network observer sees cookies, API tokens or VNC tickets. **Impact:** credential/session disclosure. **Remediation:** HTTPS/WSS, Secure cookies, HSTS and prevention of direct listener bypass. **Evidence boundary:** configuration confirmed; a deployment with enforced external TLS can mitigate it. No interception test was performed.

### 15. Weak registration policy / absent attempt limiting

**Locations:** original `website/web.py:150–170,208–217,234–240`.

**Cause:** single-character passwords accepted; no application attempt limiter. **Scenario:** repeated password guesses against a weak account. **Impact:** potential account takeover and bcrypt CPU pressure. **Remediation:** stronger password requirements, per-account/source limiting, monitoring and appropriate MFA. **Test:** registration accepts a one-character password. Brute-force success and the absence of external reverse-proxy rate limiting were not established.

### 16. Open redirect

**Locations:** original `website/web.py:219–221`.

**Cause:** `next` is used without origin validation. **Scenario reproduced:** an authenticated request redirects to an external attacker URL. **Impact:** phishing/trust abuse, not automatic cookie disclosure. **Remediation:** permit only validated local relative destinations. **Test:** original Flask response has the external Location and status 302.

### 17. MongoDB query injection in task polling

**Locations:** original `website/web.py:635–643`.

**Cause:** attacker-supplied JSON object becomes the value of `task` in both MongoDB and GridFS queries. **Scenario reproduced:** `{"task":{"$ne":null}}` retrieves a private completed report. **Impact:** selector manipulation and report disclosure. **Remediation implemented:** accept only canonical UUID strings and validate task ownership. **Correction:** the first assessment understated this as a query manipulation without demonstrated retrieval; the concrete test confirms retrieval. It overlaps with the original broader missing-authorization issue.

## Discarded / unproven scenarios

- **JSON CSRF from another same-site origin: discarded for tested routes.** The initial claim that `fetch(..., mode: 'no-cors')` could send accepted `application/json` was incorrect. Real Chromium, with an authenticated SameSite=Lax cookie, blocks normal cross-origin JSON via preflight. In no-cors mode, the server rejects the request body as JSON; no task is queued. Missing CSRF checks on cookie-authenticated APIs remain a defense-in-depth concern if request parsing/CORS changes, not the previously claimed working exploit.
- **Direct data-driven XSS in normal reports: not found.** Adversarial script/image payloads are escaped by the real Jinja helpers and by actual report generation. Stored HTML altered through a compromised database is still dangerous, but requires prior storage compromise.
- **SSTI via report values: not found.** A `{{7*7}}` payload stays literal; it is a value, not template source.
- **Direct command injection / host RCE: not demonstrated.** Argument-list subprocess calls do not interpret user input as shell code. Privileged worker plus Docker socket increases post-compromise impact, but no initial code-execution primitive was established.
- **Weak crypto from MD5/SHA1 certificate fingerprints: discarded as an authentication vulnerability.** They are displayed diagnostics, not password or trust verification mechanisms.
- **Tor/control secret and mutable CI script:** source/configuration hardening concerns. No compromise of a box, control service or upstream repository was attempted; they are not counted as verified independent exploitation paths.
- **Dependency CVEs:** not assessed. Tests use installed test dependencies; no claim of a clean dependency/image inventory is made.

## Reproduction commands

Install web runtime dependencies and `tests/requirements.txt` into a disposable virtual environment. For the local HTTP tests use the Requests/urllib3 versions from `box-requirements.txt`; Docker integration additionally needs the Docker SDK from `backend-requirements.txt`. Browser integration needs Chromium on PATH.

```bash
PYTHONPATH=.:tests pytest -q tests/test_user_security.py tests/test_worker_isolation.py
RUN_SECURITY_ASSESSMENT=1 PYTHONPATH=.:tests pytest -q tests/test_assessment.py
RUN_LOCAL_SECURITY_TESTS=1 RUN_LOCAL_DOCKER_TESTS=1 RUN_SECURITY_ASSESSMENT=1 \
  PYTHONPATH=.:tests pytest -q
```

The last command requires permission to create loopback sockets and access Docker. The Docker test does not pull images and skips if `python:3.11-slim` is unavailable.

Final local execution: **55 passed, 0 failed, 0 skipped** in 7.73 seconds: 35 application/worker regression tests, 13 baseline assessment tests, 6 local network/browser tests and 1 real Docker isolation test. The pinned Flask/Werkzeug stack under Python 3.13 emits deprecation warnings; these are not suppressed in the application.
