# SafeOps Stable Service Launcher
# Launches each service in a separate PowerShell window for better stability

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SafeOps Stable Service Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Detect Gateway IP
Write-Host "Detecting network interface..." -ForegroundColor Cyan
$GATEWAY_IP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1).IPAddress

if (-not $GATEWAY_IP) {
    Write-Host "✗ No network interface found!" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ Using Gateway IP: $GATEWAY_IP" -ForegroundColor Green
Write-Host ""

# Setup Logs Directory
$LOG_DIR = "D:\SafeOpsFV2\logs"
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null

# Clear previous logs
Write-Host "Clearing previous logs..." -ForegroundColor Cyan
Get-ChildItem -Path $LOG_DIR -Filter "*.log" -File | Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "✓ Logs directory: $LOG_DIR (cleared)" -ForegroundColor Green
Write-Host ""

# Service 1: step-ca
Write-Host "[1/6] Starting step-ca..." -ForegroundColor Cyan
$stepCACmd = @"
Set-Location 'D:\SafeOpsFV2\certs\step-ca'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  step-ca (Port 9000)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
.\step-ca.exe ca\config\ca.json --password-file ca\secrets\password.txt 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\step-ca.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $stepCACmd -WindowStyle Normal
Start-Sleep -Seconds 3
Write-Host "  ✓ step-ca started in new window" -ForegroundColor Green

# Service 2: Certificate Manager
Write-Host "[2/6] Starting Certificate Manager..." -ForegroundColor Cyan
$certMgrCmd = @"
Set-Location 'D:\SafeOpsFV2\src\certificate_manager'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  Certificate Manager (Port 8082)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
.\certificate_manager.exe 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\certificate-manager.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $certMgrCmd -WindowStyle Normal
Start-Sleep -Seconds 3
Write-Host "  ✓ Certificate Manager started in new window" -ForegroundColor Green

# Service 3: DHCP Server
Write-Host "[3/6] Starting DHCP Server..." -ForegroundColor Cyan
$dhcpCmd = @"
Set-Location 'D:\SafeOpsFV2\src\dhcp_server'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  DHCP Server (Port 67)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
.\dhcp_server.exe 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\dhcp-server.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $dhcpCmd -WindowStyle Normal
Start-Sleep -Seconds 2
Write-Host "  ✓ DHCP Server started in new window" -ForegroundColor Green

# Service 4: DNS Server
Write-Host "[4/6] Starting DNS Server..." -ForegroundColor Cyan
$dnsCmd = @"
Set-Location 'D:\SafeOpsFV2\src\dns_server'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  DNS Server (Port 53)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
.\dns_server.exe -captive -portal-ip $GATEWAY_IP -portal-port 8080 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\dns-server.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $dnsCmd -WindowStyle Normal
Start-Sleep -Seconds 2
Write-Host "  ✓ DNS Server started in new window" -ForegroundColor Green

# Service 5: NIC Management API
Write-Host "[5/6] Starting NIC Management..." -ForegroundColor Cyan
$nicCmd = @"
Set-Location 'D:\SafeOpsFV2\src\nic_management'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  NIC Management API (Port 8081)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
.\\api\\nic_api.exe 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\nic-api.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $nicCmd -WindowStyle Normal
Start-Sleep -Seconds 2
Write-Host "  ✓ NIC Management started in new window" -ForegroundColor Green

# Service 6: Dashboard
Write-Host "[6/6] Starting Dashboard..." -ForegroundColor Cyan
$dashboardCmd = @"
Set-Location 'D:\SafeOpsFV2\src\ui\dev'
Write-Host '========================================' -ForegroundColor Green
Write-Host '  Dashboard (Port 5173)' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
powershell -ExecutionPolicy Bypass -Command "npm run dev" 2>&1 | Tee-Object -FilePath 'D:\SafeOpsFV2\logs\dashboard.log'
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $dashboardCmd -WindowStyle Normal
Start-Sleep -Seconds 3
Write-Host "  ✓ Dashboard started in new window" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  All Services Started!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Each service is running in its own window:" -ForegroundColor Cyan
Write-Host "  1. step-ca              (Port 9000)" -ForegroundColor White
Write-Host "  2. Certificate Manager  (Port 8082)" -ForegroundColor White
Write-Host "  3. DHCP Server          (Port 67)" -ForegroundColor White
Write-Host "  4. DNS Server           (Port 53)" -ForegroundColor White
Write-Host "  5. NIC Management       (Port 8081)" -ForegroundColor White
Write-Host "  6. Dashboard            (Port 5173)" -ForegroundColor White
Write-Host ""
Write-Host "Dashboard URLs:" -ForegroundColor Cyan
Write-Host "  http://localhost:5173" -ForegroundColor White
Write-Host "  http://localhost:5173/network" -ForegroundColor White
Write-Host "  http://localhost:5173/certificates" -ForegroundColor White
Write-Host ""
Write-Host "Logs: $LOG_DIR" -ForegroundColor Yellow
Write-Host ""
Write-Host "To stop all services:" -ForegroundColor Yellow
Write-Host "  Close each PowerShell window OR run: .\stop_all_services.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "Verifying services in 5 seconds..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

# Verify services are running
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$processes = Get-Process | Where-Object { $_.ProcessName -match "step-ca|certificate_manager|dhcp_server|dns_server|nic_api|node" }
if ($processes) {
    Write-Host "Running Processes:" -ForegroundColor Green
    $processes | Select-Object ProcessName, Id, @{Name = "Memory(MB)"; Expression = { [math]::Round($_.WorkingSet64 / 1MB, 2) } } | Format-Table -AutoSize
}
else {
    Write-Host "⚠ No services detected running!" -ForegroundColor Yellow
    Write-Host "Check the individual PowerShell windows for errors." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✓ Startup complete!" -ForegroundColor Green
Write-Host "Press any key to exit this launcher window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
