# caddy-defender (auto-blocklist fork)

Caddy v2 with the [caddy-defender](https://github.com/JasonLovesDoggo/caddy-defender) middleware built in, plus **automatic scanner blocklisting**.

- **Source:** [github.com/chunkychode/caddy-defender](https://github.com/chunkychode/caddy-defender/tree/auto-blocklist), branch `auto-blocklist`
- **Upstream:** [JasonLovesDoggo/caddy-defender](https://github.com/JasonLovesDoggo/caddy-defender), merged regularly
- **Exact commit** of any tag: `docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' cechode/caddy-defender:<tag>`

## What this fork adds

- **Auto-blocklist by status code.** An IP that produces N tracked status codes (e.g. 404) within a time window is written to the blocklist file permanently.
- **Path-signature instant ban.** The first request matching a signature (`.env`, `.git/`, `/wp-admin`, …) bans the IP before it reaches your app. Works behind auth proxies that answer every probe with a 302.
- **Admin API** on Caddy's admin listener: `/defender/blocklist`, `/defender/stats`, `/defender/auto_blocklist/stats`, `/defender/auto_blocklist/reset/<ip>`.
- One tracker is shared across all sites in the Caddy process.

Everything from upstream is included: embedded IP ranges (`openai`, `aws`, `gcloud`, `azurepubliccloud`, `datadog`, …), file-based blocklists with live reload, and the block / custom / drop / garbage / redirect / ratelimit / tarpit responders.

## Tags

- `latest`: newest release
- `auto-blocklist-vN`: pinned releases

## Example Caddyfile

```caddyfile
example.com {
    defender block {
        ranges openai aws gcloud
        whitelist 203.0.113.10
        blocklist_file /etc/caddy/blocklist/blocklist.txt
        auto_blocklist {
            enabled
            status_codes 404
            max_requests 5
            window_duration 1m
            paths .env .git/ wp-login.php xmlrpc.php phpinfo /wp-admin
        }
    }
    reverse_proxy app:8080
}
```

## docker compose

```yaml
services:
  caddy:
    image: cechode/caddy-defender:latest
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./blocklist:/etc/caddy/blocklist   # mount the DIRECTORY, not the file
      - caddy_data:/data
volumes:
  caddy_data:
```

**Mount the directory that holds the blocklist, not the file itself.** Blocklist writes use an atomic rename, which fails with `EBUSY` on a single-file bind mount.

## Unban an IP

```bash
curl -X DELETE localhost:2019/defender/blocklist/198.51.100.7
curl -X DELETE localhost:2019/defender/auto_blocklist/reset/198.51.100.7
```

Full docs: [README](https://github.com/chunkychode/caddy-defender/blob/auto-blocklist/README.md) · [auto-blocklist guide](https://github.com/chunkychode/caddy-defender/blob/auto-blocklist/examples/auto-blocklist/README.md)
