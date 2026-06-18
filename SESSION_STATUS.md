# Caddy-Defender — Status

Primer for picking this repo up cold. Last updated **2026-06-18** at the end of the session that renamed the rate-limiter to `auto_blocklist`, fixed two latent admin-API bugs, and merged upstream.

---

## What the project is

A Caddy v2 middleware plugin (`pkg.jsn.cam/caddy-defender`) that blocks or manipulates HTTP requests based on client IP. Fork of upstream `JasonLovesDoggo/caddy-defender`.

- **`origin`** = `chunkychode/caddy-defender` (the user's fork)
- **`upstream`** = `JasonLovesDoggo/caddy-defender` (the original)

Core features:
- **IP range filtering** — predefined keys (`openai`, `aws`, `gcloud`, …) or literal CIDRs.
- **File-based blocklist** — a text file watched via fsnotify; reloads on change.
- **Auto-blocklisting** (formerly "rate_limit_config", renamed this session) — detects abuse by counting configurable status codes (e.g. 404s) per IP per window and **permanently** adds violators to the blocklist. It is detect-and-block, **not** a rate limiter — it never re-allows an IP after a window.
- **Admin API** — RESTful endpoints under `/defender/*` on Caddy's admin listener for blocklist management and auto-blocklist stats.
- **Responders** — block, custom, drop, garbage, redirect, **ratelimit** (header-only forwarder for external [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit)), tarpit.

## Layout

```
plugin.go              Defender type, Provision, Cleanup; global auto-blocklist singleton
middleware.go          ServeHTTP: client-IP resolve → IP check → responder; recorder for auto-blocklist tracking
config.go              Caddyfile/JSON unmarshal, Validate; responder type consts
admin_app.go           admin.api.defender module — /defender/blocklist, /defender/stats, /defender/auto_blocklist/*
ranges/fetchers/       Per-source CIDR fetchers + FileFetcher (fsnotify, parent-dir watch)
autoblocklist/         Tracker (fixed-window counter per IP) + Config + ResponseRecorder  (was ratelimit/)
matchers/ip/           IPChecker wrapping gaissmai/bart trie
matchers/whitelist/    Whitelist validation and lookup
responders/            block, custom, drop, garbage, redirect, ratelimit, tarpit
localtest/             Dockerized end-to-end validation harness (validate.ps1)
```

---

## This session's work (branch `feature/rate-limiter`)

Four commits on top of the previously-shipped fixes, then an upstream merge.

1. **`refactor: rename rate_limit_config feature to auto_blocklist`**
   - Pure rename, behaviour unchanged. Caddyfile/JSON key `rate_limit_config` → `auto_blocklist`; Go package `ratelimit/` → `autoblocklist/`; field `RateLimitConfig` → `AutoBlocklistConfig`; vars `globalRateLimiter*` → `globalAutoBlocklist*`; admin routes `/defender/ratelimit/*` → `/defender/auto_blocklist/*`; `examples/rate-limiting/` → `examples/auto-blocklist/`.
   - **BREAKING (no alias):** old Caddyfile/JSON keys and old admin routes are gone.

2. **`fix: repair admin API DELETE/reset endpoints (two latent bugs)`** — both pre-existing, never worked in prod:
   - Admin routes used `/*`. Caddy's admin API uses `net/http.ServeMux`, where `*` is a **literal**, not a wildcard, so `DELETE /defender/blocklist/1.2.3.4` always 404'd. Changed to trailing-slash subtree match (`/defender/blocklist/`, `/defender/auto_blocklist/reset/`).
   - `removeIPFromFile` compared the bare URL IP against CIDR file entries (`9.9.9.9` vs `9.9.9.9/32`) → never matched. Now matches bare IP against its `/32` and `/128` forms.
   - These were invisible to unit tests (which exercise the file helpers, not HTTP routing).

3. **`test: add localtest admin/blocklist validation harness`** — `localtest/validate.ps1` spins up a container and verifies every admin endpoint + blocking + auto_blocklist end-to-end. **Run:** `powershell -ExecutionPolicy Bypass -File localtest\validate.ps1` (Docker must be running; image `caddy-defender:autoblocklist-test` built locally). Result this session: **12/12**.

4. **`Merge upstream/main into feature/rate-limiter`** — caught up from 14 commits behind to **0 behind**:
   - **#139 trusted-proxy client IP** — defender now resolves the client IP via `caddyhttp.ClientIPVarKey` (respects `trusted_proxies`) instead of raw `RemoteAddr`. Relevant to prod (see below).
   - **Security bumps:** Caddy 2.11.3 → **2.11.4**, go-jose 3.0.5 (#135), bart 0.28.0; embedded AI CIDR refreshes.
   - **Restored the `ratelimit` responder** (upstream kept it; our branch had deleted it). It now coexists with `auto_blocklist` — no naming collision after the rename, so the config.go switch no longer diverges from upstream.
   - Conflict resolution: config.go took upstream's const-extraction + restored ratelimit responder while preserving our auto_blocklist parsing; go.mod/go.sum took upstream then `go mod tidy` re-added our direct dep `fsnotify` (absent upstream).

Verification: `go build`/`go test` green; localtest 12/12; `defender ratelimit {…}` Caddyfile validates; modules `admin.api.defender` + `http.handlers.defender` present; `caddy version` = v2.11.4.

---

## Corrected facts (previous SESSION_STATUS was wrong)

- **There is no `defender_admin` global option.** It is not registered anywhere in the code. `DefenderAdmin` is an `admin.api.defender` module that Caddy **auto-loads** because it lives in the `admin.api` namespace. A `defender_admin` line in the global options block makes Caddy fail to start (`unrecognized global option`). Remove it from any Caddyfile that has it.
- **Prod exposes the admin API via `CADDY_ADMIN=0.0.0.0:2019`** (set in the caddy compose service env). Port 2019 is **not** published to the host — only reachable on the `portainer_caddy` / `inside` docker networks, where n8n lives. That is how the Grafana→n8n auto-add POST to `http://caddy:2019/defender/blocklist` works. Note: anything on those networks has the full Caddy control API.

---

## Production deployment

- **Current prod image (this session's build):** `cechode/caddy-defender:auto-blocklist-v6`, pushed to Docker Hub 2026-06-18, digest `sha256:b9601b100d8f7c35686a3a709c406d8ea8e91507a969e83be3067e234a161334`. (Supersedes `feature-rate-limit-v5`.)

### Required coordinated migration (do these together in one deploy)

The rename is breaking with no alias, so the image and Caddyfile must change together:
1. compose `image:` → `cechode/caddy-defender:auto-blocklist-v6`
2. In the prod Caddyfile `(defme)` snippet, rename the block (sub-fields unchanged):
   ```caddyfile
   auto_blocklist {        # was: rate_limit_config
       enabled
       status_codes 404 403 502 401 308 301 302
       max_requests 5
       window_duration 1m
   }
   ```
   Deploying the new image with the old key → Caddy won't start. The n8n POST path (`/defender/blocklist`) and the blocklist directory mount are unaffected by the rename.

### Critical bind-mount rule (unchanged)

`os.Rename` in the atomic-write path **cannot** replace a target that is itself a Docker bind-mount (`EBUSY`). Bind-mount the **directory** containing the blocklist, not the file. Prod already does this: `/mnt/data/compdata/caddy/blocklist:/etc/caddy/blocklist` + `blocklist_file /etc/caddy/blocklist/blocklist.txt`. ✓

### #139 / trusted_proxies note

Prod sets `trusted_proxies static 192.168.0.100/24`. With #139 now merged, defender keys IP checks and auto-blocklisting on the **real** client IP (via `ClientIPVarKey`) rather than the proxy's. If a proxy sits in that range, this changes which IP gets blocklisted (for the better). Worth watching the first prod run after deploy.

---

## Build, test, release

Go is **not installed on the host.** Everything runs inside `caddy:builder` (Go + xcaddy pre-installed). On Windows/git-bash, prefix docker runs with `MSYS_NO_PATHCONV=1` so `-w /src` isn't mangled, and use a Windows volume path.

```bash
# Build + test
MSYS_NO_PATHCONV=1 docker run --rm -v "C:/_cloned/caddy-defender:/src" -w /src caddy:builder \
    sh -c "go build ./... && go test ./..."

# Production image
MSYS_NO_PATHCONV=1 docker build -t cechode/caddy-defender:<tag> .
docker push cechode/caddy-defender:<tag>

# End-to-end validation (Docker Desktop must be running)
MSYS_NO_PATHCONV=1 docker build -t caddy-defender:autoblocklist-test .
powershell -ExecutionPolicy Bypass -File localtest\validate.ps1
```

xcaddy resolves its own module graph and does **not** need a complete `go.sum`, which is why `docker build` works even when host `go build` would not.

---

## Repo state (end of session)

- Branch: `feature/rate-limiter` (name now a misnomer — feature is `auto_blocklist`; left as-is).
- Fully merged with `upstream/main` (0 behind). 49 commits ahead of upstream.
- Working tree clean.
- Pushed to `origin/feature/rate-limiter` this session.
- Docker Hub: `cechode/caddy-defender:auto-blocklist-v6` pushed.

## Known quirks / future work

In decreasing priority:
1. **Per-Defender `FileFetcher` duplication.** Each `defender {…}` block gets its own fsnotify watcher; one write fans out to N "reloading" events + N trie rebuilds. The auto-blocklist tracker already solves the equivalent via a singleton + refcount; `FileFetcher` should mirror that. Not worth it below ~30 sites.
2. **Race in `matchers/ip.IPChecker.UpdateRanges`** under concurrent updates (surfaces under `-race`, test `ConcurrentUpdates`). Pre-existing. Low contention today (one writer per blocklist file); must fix before any singleton refactor of #1.
3. **Append-only add path** could replace the read-all/rewrite-atomic add with an `O_APPEND` write + in-memory set. Discussed, not done.
4. **Branch rename.** `feature/rate-limiter` no longer describes the work; consider renaming the branch/eventually merging to `main`.
