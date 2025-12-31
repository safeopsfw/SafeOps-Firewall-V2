# Stop All SafeOps Services
# Location: D:\SafeOpsFV2\stop_all_services.ps1

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Stopping SafeOps Services" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Kill all service processes
$services = @(
    "certificate_manager",
    "dhcp_server",
    "dns_server",
    "captive_portal",
    "tls_proxy"
)

$stopped = 0

foreach ($service in $services) {
    $process = Get-Process $service -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "[STOP] $service..." -ForegroundColor Yellow
        Stop-Process -Name $service -Force -ErrorAction SilentlyContinue
        $stopped++
    }
}

# Stop Node.js (Dashboard)
$nodeProcesses = Get-Process node -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path -like "*SafeOpsFV2*"
}

if ($nodeProcesses) {
    Write-Host "[STOP] Dashboard (Node.js)..." -ForegroundColor Yellow
    $nodeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    $stopped++
}

Write-Host ""
if ($stopped -gt 0) {
    Write-Host "Stopped $stopped service(s)" -ForegroundColor Green
} else {
    Write-Host "No services were running" -ForegroundColor Gray
}
Write-Host ""
