<#
  Local validation harness for caddy-defender (auto_blocklist branch).

  Verifies, end-to-end against a freshly-built image:
    1. Admin API: GET /defender/blocklist (read)
    2. Admin API: POST /defender/blocklist (add)  -> file write + watcher reload
    3. Blocking:  a listed IP is actually blocked (403)
    4. Admin API: DELETE /defender/blocklist/{ip} (remove) -> watcher reload, unblocked
    5. Auto-blocklist: exceeding the 404 threshold auto-adds the IP and blocks it
    6. Admin API: GET /defender/auto_blocklist/stats  and  DELETE .../reset/{ip}

  Usage:   powershell -ExecutionPolicy Bypass -File localtest\validate.ps1
  Requires: Docker running, image 'caddy-defender:autoblocklist-test' built.
#>

# 'Continue' so native-exe stderr (e.g. 'docker rm' on a missing container)
# doesn't abort the script under PowerShell 5.1's NativeCommandError behavior.
$ErrorActionPreference = 'Continue'
$IMAGE   = 'caddy-defender:autoblocklist-test'
$NAME    = 'defender-validate'
$SITE    = 'http://localhost:8080'
$ADMIN   = 'http://localhost:2019'
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$bl      = Join-Path $here 'blocklist'

$pass = 0; $fail = 0
function Check($label, $cond, $detail) {
  if ($cond) { Write-Host "  PASS  $label" -ForegroundColor Green; $script:pass++ }
  else       { Write-Host "  FAIL  $label  ($detail)" -ForegroundColor Red; $script:fail++ }
}
# curl.exe helpers (clearer status-code handling than Invoke-WebRequest for 403s)
function Code($url, $method='GET', $body=$null) {
  if ($body) {
    # Write the JSON body to a temp file: passing JSON inline to curl.exe on
    # Windows mangles the quotes, producing invalid JSON (HTTP 400).
    $tmp = New-TemporaryFile
    [System.IO.File]::WriteAllText($tmp, $body)
    try   { return (curl.exe -s -o NUL -w "%{http_code}" -X $method -H "Content-Type: application/json" --data "@$tmp" $url) }
    finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
  }
  return (curl.exe -s -o NUL -w "%{http_code}" -X $method $url)
}
function Body($url) { return (curl.exe -s $url) }

Write-Host "== cleanup any prior run ==" -ForegroundColor Cyan
docker rm -f $NAME *>$null
Remove-Item (Join-Path $bl 'blocklist.txt') -ErrorAction SilentlyContinue
# also clear any leftover temp files from atomic writes
Get-ChildItem $bl -Filter 'blocklist-*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "== start container ==" -ForegroundColor Cyan
# Mount the DIRECTORY (not the file) per the atomic-rename rule.
docker run -d --name $NAME -p 8080:8080 -p 2019:2019 `
  -v "${bl}:/data" `
  -v "$(Join-Path $here 'Caddyfile'):/etc/caddy/Caddyfile:ro" `
  $IMAGE | Out-Null

try {
  Write-Host "== wait for admin API ==" -ForegroundColor Cyan
  $ready = $false
  for ($i=0; $i -lt 30; $i++) {
    Start-Sleep 1
    if ((Code "$ADMIN/defender/stats") -eq '200') { $ready = $true; break }
  }
  if (-not $ready) { throw "admin API did not come up; container logs:`n$(docker logs $NAME 2>&1)" }

  Write-Host "`n== 1. baseline: request allowed, capture client IP Caddy sees ==" -ForegroundColor Cyan
  $clientIP = (Body "$SITE/").Trim()
  Check "site reachable & allowed (200)" ((Code "$SITE/") -eq '200') "got $(Code "$SITE/")"
  Write-Host "       client IP as seen by Caddy: $clientIP"
  $cidr = "$clientIP/32"

  Write-Host "`n== 2. GET blocklist (should be empty) ==" -ForegroundColor Cyan
  $b = Body "$ADMIN/defender/blocklist" | ConvertFrom-Json
  Check "GET /defender/blocklist returns total=0" ($b.total -eq 0) "total=$($b.total)"

  Write-Host "`n== 3. POST our own IP to the blocklist ==" -ForegroundColor Cyan
  $c = Code "$ADMIN/defender/blocklist" 'POST' "{`"ips`":[`"$cidr`"]}"
  Check "POST add returns 201" ($c -eq '201') "got $c"
  Start-Sleep 2  # let fsnotify reload
  $b = Body "$ADMIN/defender/blocklist" | ConvertFrom-Json
  Check "blocklist now contains $cidr" ($b.ips -contains $cidr) "ips=$($b.ips -join ',')"

  Write-Host "`n== 4. blocked: same request now 403 ==" -ForegroundColor Cyan
  Check "listed IP is blocked (403)" ((Code "$SITE/") -eq '403') "got $(Code "$SITE/")"

  Write-Host "`n== 5. DELETE the IP, expect unblocked ==" -ForegroundColor Cyan
  $c = Code "$ADMIN/defender/blocklist/$clientIP" 'DELETE'
  Check "DELETE returns 200" ($c -eq '200') "got $c"
  Start-Sleep 2
  Check "request allowed again (200)" ((Code "$SITE/") -eq '200') "got $(Code "$SITE/")"

  Write-Host "`n== 6. auto_blocklist: exceed 404 threshold (max_requests 5) ==" -ForegroundColor Cyan
  for ($i=1; $i -le 6; $i++) { Code "$SITE/missing$i" 'GET' | Out-Null }
  Start-Sleep 2
  $stats = Body "$ADMIN/defender/auto_blocklist/stats" | ConvertFrom-Json
  Check "auto_blocklist stats reachable & enabled" ($stats.enabled -eq $true) "enabled=$($stats.enabled)"
  Check "our IP tracked by auto_blocklist" ($null -ne $stats.tracked_ips.$clientIP) "tracked=$($stats.tracked_count)"
  $b = Body "$ADMIN/defender/blocklist" | ConvertFrom-Json
  Check "auto-added our IP to blocklist" ($b.ips -contains $cidr) "ips=$($b.ips -join ',')"
  Check "auto-blocked: request now 403" ((Code "$SITE/") -eq '403') "got $(Code "$SITE/")"

  Write-Host "`n== 7. auto_blocklist reset endpoint ==" -ForegroundColor Cyan
  $c = Code "$ADMIN/defender/auto_blocklist/reset/$clientIP" 'DELETE'
  Check "reset returns 200" ($c -eq '200') "got $c"
}
finally {
  Write-Host "`n== teardown ==" -ForegroundColor Cyan
  docker rm -f $NAME *>$null
}

Write-Host "`n=========== RESULT: $pass passed, $fail failed ===========" -ForegroundColor ($(if ($fail -eq 0) {'Green'} else {'Red'}))
if ($fail -gt 0) { exit 1 }
