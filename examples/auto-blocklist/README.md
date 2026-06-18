# Auto-Blocklisting (Scanner Detection) Example

This example demonstrates how to use Caddy Defender's built-in scanner auto-blocklisting feature to automatically and permanently block IPs that generate excessive 404 responses.

> **Note:** This is a detect-and-block mechanism, not a rate limiter. Offending IPs are added to the persistent blocklist and are **not** automatically re-allowed after any time period. For a re-allowing rate limiter, use the `ratelimit` responder with [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit).

## Features

- **Automatic 404 Detection**: Tracks IPs generating 404 responses
- **Configurable Thresholds**: Set custom limits and time windows
- **Auto-Blocking**: IPs exceeding limits are automatically added to blocklist
- **Admin API**: Monitor and manage auto-blocklisting via REST endpoints
- **No External Dependencies**: Built directly into Caddy Defender

## How It Works

1. **Request Processing**: All requests pass through Defender
2. **Status Code Tracking**: 404 responses (and other configured codes) are tracked per IP
3. **Threshold Check**: If an IP exceeds the limit (e.g., 10 404s in 5 minutes)
4. **Automatic Blocking**: IP is immediately blocked AND added to persistent blocklist
5. **Whitelist Respect**: Whitelisted IPs are never tracked or blocked

## Configuration

### Caddyfile Syntax

```caddy
defender block {
    blocklist_file /path/to/blocklist.txt

    auto_blocklist {
        enabled
        status_codes 404 403 401
        max_requests 10
        window_duration 5m
        auto_add_to_blocklist
        cleanup_interval 10m
    }
}
```

### JSON Configuration

```json
{
    "handler": "defender",
    "raw_responder": "block",
    "blocklist_file": "/path/to/blocklist.txt",
    "auto_blocklist": {
        "enabled": true,
        "status_codes": [404, 403, 401],
        "max_requests": 10,
        "window_duration": "5m",
        "auto_add_to_blocklist": true,
        "cleanup_interval": "10m"
    }
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable auto-blocklisting |
| `status_codes` | []int | `[404]` | HTTP status codes to track |
| `max_requests` | int | `10` | Maximum requests allowed in window |
| `window_duration` | duration | `5m` | Detection window for counting requests |
| `auto_add_to_blocklist` | boolean | `true` | Auto-add violators to blocklist |
| `cleanup_interval` | duration | `10m` | How often to clean old tracking data |

## Admin API Endpoints

### View Auto-Blocklist Statistics

```bash
curl http://localhost:2019/defender/auto_blocklist/stats
```

**Response:**
```json
{
    "enabled": true,
    "status_codes": [404],
    "max_requests": 10,
    "window": "5m0s",
    "tracked_count": 2,
    "tracked_ips": {
        "192.168.1.100": {
            "ip": "192.168.1.100",
            "request_count": 8,
            "window_start": "2025-10-12T10:30:00Z",
            "time_remaining": "2m15s",
            "exceeds_threshold": false
        },
        "10.0.0.50": {
            "ip": "10.0.0.50",
            "request_count": 12,
            "window_start": "2025-10-12T10:28:00Z",
            "time_remaining": "15s",
            "exceeds_threshold": true
        }
    }
}
```

### Reset Tracking for an IP

```bash
curl -X DELETE http://localhost:2019/defender/auto_blocklist/reset/192.168.1.100
```

**Response:**
```json
{
    "reset": "192.168.1.100"
}
```

## Testing

### Test Normal Behavior

```bash
# Make 5 requests - should all succeed
for i in {1..5}; do
    curl -I http://localhost/nonexistent
done
```

### Test Auto-Blocklisting

```bash
# Make 15 404 requests - 11th request onwards should be blocked
for i in {1..15}; do
    echo "Request $i:"
    curl -I http://localhost/does-not-exist-$i
    sleep 0.5
done
```

After 10 404s, the IP will be:
1. Immediately blocked (11th request returns 403)
2. Added to blocklist file
3. Permanently blocked until manually removed

### Verify IP Was Blocked

```bash
# Check blocklist file
cat /var/lib/caddy/blocklist.txt

# Should show your IP in CIDR format:
# 127.0.0.1/32
```

## Use Cases

### 1. Scanner/Bot Detection
Attackers often probe for vulnerabilities by requesting common paths:
```
/admin
/wp-admin
/.env
/.git/config
```

These generate 404s, triggering automatic blocking.

### 2. Brute Force Protection
Track 401/403 responses to detect authentication attacks:

```caddy
auto_blocklist {
    enabled
    status_codes 401 403
    max_requests 5
    window_duration 1m
}
```

### 3. API Abuse Auto-Blocklisting
Protect API endpoints from abuse:

```caddy
auto_blocklist {
    enabled
    status_codes 429  # Track rate limit responses
    max_requests 100
    window_duration 1h
}
```

## Important Notes

1. **Requires `blocklist_file`**: Auto-blocklisting requires a blocklist file to be configured for persistent blocking
2. **Respects Whitelist**: IPs in the whitelist are never tracked or blocked
3. **Fixed Window Algorithm**: Uses efficient fixed window counting (see docs for details)
4. **Memory Efficient**: ~48KB for 1000 tracked IPs
5. **Automatic Cleanup**: Old tracking data is purged automatically

## Troubleshooting

### Auto-blocklisting not working

1. Check `enabled` is set to `true`
2. Verify `blocklist_file` is configured
3. Ensure DefenderAdmin app is loaded in global config
4. Check logs for errors

### Legitimate users getting blocked

1. Add them to the `whitelist`
2. Increase `max_requests` threshold
3. Increase `window_duration`
4. Adjust `status_codes` to be more specific

### High memory usage

1. Decrease `window_duration`
2. Decrease `cleanup_interval` for more frequent cleanup
3. Review tracked IPs via Admin API

## See Also

- [Main Documentation](../../README.md)
- [Blocklist Management](../blocklist/README.md)
- [Admin API Reference](../../docs/api.md)
