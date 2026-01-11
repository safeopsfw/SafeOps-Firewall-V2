# Check if ports are available
# Run before starting SafeOps Engine

Write-Host "=== SafeOps Port Conflict Checker ===" -ForegroundColor Green
Write-Host ""

$ports = @{
    "5353" = "dnsproxy (DNS redirect)"
    "8080" = "mitmproxy (SOCKS5)"
    "9000" = "SafeOps API"
}

$conflicts = @()

foreach ($port in $ports.Keys) {
    $description = $ports[$port]

    # Check if port is in use
    $listener = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    $udpListener = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue

    if ($listener -or $udpListener) {
        Write-Host "[!] Port $port is IN USE" -ForegroundColor Yellow
        Write-Host "    Service: $description" -ForegroundColor Gray

        if ($listener) {
            $process = Get-Process -Id $listener[0].OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "    Used by: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Gray
            }
        }

        if ($udpListener) {
            # Port 5353 is special - mDNS can share it
            if ($port -eq "5353") {
                Write-Host "    Note: Port 5353 (mDNS) supports multiple listeners - this is OK!" -ForegroundColor Green
            } else {
                $conflicts += $port
            }
        }

        Write-Host ""
    } else {
        Write-Host "[✓] Port $port is AVAILABLE" -ForegroundColor Green
        Write-Host "    Service: $description" -ForegroundColor Gray
        Write-Host ""
    }
}

# Summary
if ($conflicts.Count -gt 0) {
    Write-Host "=== Action Required ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "The following ports have conflicts:" -ForegroundColor Red
    foreach ($port in $conflicts) {
        Write-Host "  - Port $port ($($ports[$port]))" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "1. Stop the conflicting service" -ForegroundColor Gray
    Write-Host "2. Change SafeOps port in configs/engine.yaml" -ForegroundColor Gray
    Write-Host ""
    exit 1
} else {
    Write-Host "=== All Ports Available ===" -ForegroundColor Green
    Write-Host "You can safely start SafeOps Engine" -ForegroundColor Green
    Write-Host ""
    exit 0
}
