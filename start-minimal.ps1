# SafeOps Minimal Start - NO NETWORK CHANGES
# Only starts services WITHOUT touching network configuration

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SafeOps Minimal Start (Safe Mode)" -ForegroundColor Cyan
Write-Host "  No network configuration changes" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Log directory
$LOG_DIR = "D:\SafeOpsFV2\logs"
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
Write-Host "✓ Logs: $LOG_DIR" -ForegroundColor Green
Write-Host ""

# Step 1: Start step-ca (keep window visible so it doesn't close)
Write-Host "[1/3] Starting step-ca..." -ForegroundColor Cyan
Start-Process -FilePath "D:\SafeOpsFV2\certs\step-ca\step-ca.exe" `
    -ArgumentList "ca\config\ca.json", "--password-file", "ca\secrets\password.txt" `
    -WorkingDirectory "D:\SafeOpsFV2\certs\step-ca"

Start-Sleep -Seconds 5
$stepCARunning = Test-NetConnection -ComputerName localhost -Port 9000 -InformationLevel Quiet -WarningAction SilentlyContinue
if ($stepCARunning) {
    Write-Host "  ✓ step-ca running on port 9000" -ForegroundColor Green
} else {
    Write-Host "  ✗ step-ca FAILED to start" -ForegroundColor Red
    Write-Host "    Check the step-ca window for errors" -ForegroundColor Yellow
}

# Step 2: Start Certificate Manager
Write-Host "[2/3] Starting Certificate Manager..." -ForegroundColor Cyan
Start-Process -FilePath "D:\SafeOpsFV2\src\certificate_manager\certificate_manager.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\certificate_manager"

Start-Sleep -Seconds 3
$certMgrRunning = Test-NetConnection -ComputerName localhost -Port 8082 -InformationLevel Quiet -WarningAction SilentlyContinue
if ($certMgrRunning) {
    Write-Host "  ✓ Certificate Manager running on port 8082" -ForegroundColor Green
} else {
    Write-Host "  ✗ Certificate Manager FAILED" -ForegroundColor Red
}

# Step 3: Start Dashboard
Write-Host "[3/3] Starting Dashboard..." -ForegroundColor Cyan
Write-Host "  Opening http://localhost:3001" -ForegroundColor Gray
Start-Process "http://localhost:3001"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Core Services Started!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Services:" -ForegroundColor Cyan
Write-Host "  • step-ca:              https://localhost:9000" -ForegroundColor White
Write-Host "  • Certificate Manager:  http://localhost:8082" -ForegroundColor White
Write-Host "  • Dashboard:            http://localhost:3001" -ForegroundColor White
Write-Host ""
Write-Host "Download CA Certificate:" -ForegroundColor Cyan
Write-Host "  • https://localhost:9000/roots.pem" -ForegroundColor Yellow
Write-Host "  • http://localhost:8082/ca/root" -ForegroundColor Yellow
Write-Host ""
Write-Host "NOTE: DHCP, DNS, and NIC services NOT started (to protect your internet)" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop all services..." -ForegroundColor Gray

# Keep script running
while ($true) {
    Start-Sleep -Seconds 60
}
