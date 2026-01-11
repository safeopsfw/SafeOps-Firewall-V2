# ============================================================================
# Stop All SafeOps Services
# ============================================================================
# Purpose: Gracefully stop all running services
# Date: 2026-01-04
# ============================================================================

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Service Shutdown" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

$processes = @(
    "packet_engine",
    "tls_proxy",
    "captive_portal",
    "dns_server",
    "dhcp_monitor",
    "step-ca"
)

foreach ($procName in $processes) {
    Write-Host "Stopping $procName..." -ForegroundColor Yellow -NoNewline

    $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue

    if ($proc) {
        Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host " STOPPED" -ForegroundColor Green
    } else {
        Write-Host " NOT RUNNING" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "All services stopped" -ForegroundColor Green
Write-Host ""
