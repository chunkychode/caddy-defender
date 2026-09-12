# Caddy-Defender — Status

Primer for picking this repo up cold. Last updated **2026-09-11** at the end of the session that merged upstream (Datadog fetcher, dep bumps), added **path-signature instant banning**, and fixed the singleton auto-add bug.

---

## What the project is

A Caddy v2 middleware plugin (`pkg.jsn.cam/caddy-defender`) that blocks or manipulates HTTP requests based on client IP. Fork of upstream `JasonLovesDoggo/caddy-defender`.

- **`origin`** = `chunkychode/caddy-defender` (the user's fork)
- **`upstream`** = `JasonLovesDoggo/caddy-defender` (the original)

Core features:
- **IP range filtering** — predefined keys (`openai`, `aws`, `gcloud`, `datadog`, …) or literal CIDRs.
- **File-based blocklist** — a text file watched via fsnotify; reloads on change.
- **Auto-blocklisting** — detects abuse and **permanently** adds violators to the blocklist. Two triggers:
  1. **Status-code counting** — N tracked status codes per IP per window.
  2. **Path signatures** (new this session) — first request whose path matches a configured signature (`.env`, `/wp-admin`, …) bans immediately, regardless of status code.
  It is detect-and-block, **not** a rate limiter — it never re-allows an IP.
- **Admin API** — `/defender/*` on Caddy's admin listener (auto-loaded, no global option needed).
- **Responders** — block, custom, drop, garbage, redirect, ratelimit (header-only), tarpit.

## Layout

```
plugin.go              Defender type, Provision, Cleanup; global auto-blocklist singleton (+ fallback blocklist file)
middleware.go          ServeHTTP: client-IP → range check → path-signature check → proxy → status-code tracking
config.go              Caddyfile/JSON unmarshal, Validate
admin_app.go           admin.api.defender — /defender/blocklist, /defender/stats, /defender/auto_blocklist/*
ranges/fetchers/       Per-source CIDR fetchers + FileFetcher (fsnotify, parent-dir watch)
autoblocklist/         Tracker (fixed-window counter per IP), Config (incl. Paths + MatchPath), ResponseRecorder
matchers/ip/           IPChecker wrapping gaissmai/bart trie
responders/            block, custom, drop, garbage, redirect, ratelimit, tarpit
localtest/             Dockerized end-to-end harness (validate.ps1) — 17 checks
```

---

## This session's work (branch `auto-blocklist`)

### 1. Merged `upstream/main` (committed: `1afa81e`)
16 commits: Datadog IP-range fetcher (#153, new `datadog` key), bart 0.28.0→0.29.0, testify 1.11.1→1.12.1, embedded CIDR refreshes. Only conflict was go.mod (our direct `fsnotify` dep, same as last time). 0 behind upstream.

### 2. Path-signature instant ban (UNCOMMITTED at time of writing)
Motivated by a prod log: a GCP box (34.176.41.51) probed `fin.himmelman.family/<vendor>/.env` 19× in 2.7s. Authentik's `forward_auth` answered every probe with a **302**, which isn't a tracked status code, so auto_blocklist never fired. Status-code counting is blind behind an auth proxy.

New `auto_blocklist` sub-option:
```caddyfile
auto_blocklist {
    enabled
    ...
    paths .env .git/ wp-login.php xmlrpc.php phpinfo /wp-admin
}
```
- Entry starting with `/` → **prefix** match; otherwise **substring**. Case-insensitive.
- Checked **before** the request is proxied. On hit: `tracker.MarkBlocked(ip)` (stats show it, prevents a duplicate write from a later 404 burst), write IP to blocklist, respond with the configured responder.
- Whitelisted IPs exempt. If `auto_add_to_blocklist` is off, logs a Warn and passes through (detect-only).
- **Validation** (`autoblocklist.Config.Validate`, called from `Defender.Validate`): rejects empty/whitespace entries and a bare `/` (would ban every visitor). Verified with `caddy validate` in the built image: bad config fails at load with a clear message.
- Code: `autoblocklist/config.go` (`Paths`, `MatchPath`), `autoblocklist/tracker.go` (`Config()`, `MatchPath`, `MarkBlocked`), `middleware.go`, `config.go` (`paths` parsing).

### 3. Singleton auto-add bug fix (UNCOMMITTED)
The tracker is process-global, but the "write to blocklist" decision used the **per-vhost** config (`m.AutoBlocklistConfig.AutoAddToBlocklist`, `m.BlocklistFile`). A vhost without an `auto_blocklist {}` block still fed the shared counter, and if the once-per-window "exceeded" transition fired on that vhost, nobody ever wrote the IP. Fixed: decision comes from `tracker.Config()`, and the file falls back to `globalAutoBlocklistFile` (first enabled instance's `blocklist_file`). Regression test: `TestDefenderServeHTTP_AutoAddUsesGlobalConfig`. Not hit in prod today (every vhost imports `defme`), but latent.

### Verification
- `go vet` + `go test ./...` green in `caddy:builder`.
- `localtest/validate.ps1` **17/17** (new step 8 covers path bans).
- Docs updated: README syntax + quick example (also removed the bogus `defender_admin` global), `examples/auto-blocklist/README.md` table.

---

## Production deployment

- **Latest pushed image:** `cechode/caddy-defender:auto-blocklist-v7` (also tagged `latest`), pushed 2026-09-11, digest `sha256:9e5dda8f9941dcca07c0c801fac96c3dcf29649b81dd672b5092ed27d60ea1e1`. Contains path signatures + singleton fix + validation. Built from the **uncommitted** working tree (see Repo state). Prod was on `auto-blocklist-v6` at session end; deploy is the user's call.

### Actual prod `(defme)` snippet (corrected 2026-09-11; previous doc was stale)
```caddyfile
defender drop {
    whitelist 192.168.100.108 173.164.175.106 173.164.175.107 173.164.175.109
    ranges openai aws
    blocklist_file /etc/caddy/blocklist/blocklist.txt
    auto_blocklist {
        enabled
        status_codes 400 401 403 404 405 406 415 505
        max_requests 5
        window_duration 1m
    }
}
```
Every vhost imports `alwaysinclude` → `defme`. `fin` and `files` sit behind authentik `forward_auth` (302 for unauthenticated), so only path signatures can catch scanners there.

### Recommended prod changes after deploying v7
1. Add `paths .env .git/ wp-login.php xmlrpc.php phpinfo /wp-admin /actuator` to `auto_blocklist`.
2. Add `gcloud` to `ranges` (34.176.0.0/16 is in the embedded list; would have stopped the observed scanner on request 1). Consider `digitalocean vultr linode oci aliyun huawei` too.
3. Do **not** add 302 to `status_codes` — an expired-session SPA user fires several 302s in a second and would be permanently banned at threshold 5.

### Critical bind-mount rule (unchanged)
Bind-mount the **directory** containing the blocklist, not the file (`os.Rename` → EBUSY otherwise). Prod does this. ✓

---

## Build, test, release

Go is **not installed on the host.** Everything runs inside `caddy:builder`. Use a named volume for the module cache or every run re-downloads ~300 modules. On Windows/git-bash prefix with `MSYS_NO_PATHCONV=1`. `gofmt -l` flags every file because of CRLF checkout — ignore. `-race` doesn't work in this image (no cgo).

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "C:/_cloned/caddy-defender:/src" -v caddy-defender-gomod:/go/pkg/mod -w /src caddy:builder \
    sh -c "go vet ./... && go test ./..."

MSYS_NO_PATHCONV=1 docker build -t caddy-defender:autoblocklist-test .
powershell -ExecutionPolicy Bypass -File localtest\validate.ps1

MSYS_NO_PATHCONV=1 docker build -t cechode/caddy-defender:<tag> . && docker push cechode/caddy-defender:<tag>
```

---

## Repo state (end of session)

- Branch: `auto-blocklist`. Merge commit `1afa81e` on top; 0 behind upstream.
- **Uncommitted:** path-signature feature + singleton fix + tests + docs + localtest (12 files). Awaiting user's go-ahead to commit.
- Not pushed. No new Docker Hub tag yet.

## Known quirks / future work

1. **Subnet escalation** — June blocklist snapshot: 2779 /32s, heavy clustering (50 each in 66.132.x, 176.65.x). After N /32s from one /24, ban the /24. Not started.
2. **Per-Defender `FileFetcher` duplication** — N vhosts = N fsnotify watchers + N trie rebuilds per write. Mirror the tracker singleton pattern. Not worth it below ~30 sites.
3. **Race in `IPChecker.UpdateRanges`** under concurrent updates (pre-existing, low contention). Fix before #2.
4. **Responder after response already written** — on a status-code threshold hit the responder runs after `next` already wrote headers (pre-existing "Option A"). Harmless with `drop`, produces a superfluous-WriteHeader warning with `block`.
