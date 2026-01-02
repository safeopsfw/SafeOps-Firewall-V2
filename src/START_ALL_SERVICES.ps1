# Start All Phase 1 Services with Logging

Write-Host "`n=== STARTING PHASE 1 SERVICES ===" -ForegroundColor Cyan
Write-Host "This will start DNS Server, TLS Proxy, and NIC Management`n" -ForegroundColor Yellow

# Start DNS Server
Write-Host "[1/3] Starting DNS Server on port 53..." -ForegroundColor Green
Start-Process -FilePath "D:\SafeOpsFV2\src\dns_server\bin\dns_server.exe" `
              -WorkingDirectory "D:\SafeOpsFV2\src\dns_server" `
              -WindowStyle Normal

Start-Sleep -Seconds 2

# Start TLS Proxy
Write-Host "[2/3] Starting TLS Proxy on port 50054..." -ForegroundColor Green
Start-Process -FilePath "D:\SafeOpsFV2\src\tls_proxy\bin\tls_proxy.exe" `
              -WorkingDirectory "D:\SafeOpsFV2\src\tls_proxy" `
              -WindowStyle Normal

Start-Sleep -Seconds 3

# Start NIC Management
Write-Host "[3/3] Starting NIC Management (will show UAC prompt)..." -ForegroundColor Green
Start-Process -FilePath "D:\SafeOpsFV2\src\nic_management\nic_management.exe" `
              -WorkingDirectory "D:\SafeOpsFV2\src\nic_management" `
              -Verb RunAs `
              -WindowStyle Normal

Write-Host "`n=== ALL SERVICES STARTED ===" -ForegroundColor Cyan
Write-Host "`nYou should see 3 windows:" -ForegroundColor Yellow
Write-Host "  1. DNS Server (port 53)" -ForegroundColor Gray
Write-Host "  2. TLS Proxy (port 50054) - Shows [TRAFFIC] logs" -ForegroundColor Gray
Write-Host "  3. NIC Management - Captures all packets" -ForegroundColor Gray

Write-Host "`nConnect a device to your Windows hotspot and watch traffic flow!" -ForegroundColor Green
Write-Host "Press any key to exit this script (services will keep running)..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
