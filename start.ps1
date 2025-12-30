#Requires -RunAsAdministrator
# SafeOps Launcher - Starts all services and dev UI

Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       SafeOps - Starting All Services                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

$services = @()

# Certificate Manager
Write-Host "Starting Certificate Manager..." -ForegroundColor Green
$certMgr = Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "cd /d $PSScriptRoot\src\certificate_manager && go run .\cmd\main.go" -PassThru -WindowStyle Normal
$services += $certMgr
Start-Sleep -Seconds 2

# DHCP Server
Write-Host "Starting DHCP Server..." -ForegroundColor Green
$dhcp = Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "cd /d $PSScriptRoot\src\dhcp_server && go run .\cmd\main.go" -PassThru -WindowStyle Normal
$services += $dhcp
Start-Sleep -Seconds 2

# NIC Management gRPC
Write-Host "Starting NIC Management gRPC..." -ForegroundColor Green
$nicGrpc = Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "cd /d $PSScriptRoot\src\nic_management && go run .\cmd\." -PassThru -WindowStyle Normal
$services += $nicGrpc
Start-Sleep -Seconds 1

# NIC Management API
Write-Host "Starting NIC Management API..." -ForegroundColor Green
$nicApi = Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "cd /d $PSScriptRoot\src\nic_management && go run .\api\cmd\." -PassThru -WindowStyle Normal
$services += $nicApi
Start-Sleep -Seconds 2

# Dev UI
Write-Host "Starting Dev UI..." -ForegroundColor Green
$devUi = Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "cd /d $PSScriptRoot\src\ui\dev && npm run dev" -PassThru -WindowStyle Normal
$services += $devUi
Start-Sleep -Seconds 8

# Open browser
Write-Host "`nOpening browser..." -ForegroundColor Yellow
Start-Process "http://localhost:3001/network"

Write-Host "`n╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            ✅ All Services Started                     ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nServices:" -ForegroundColor Cyan
Write-Host "  • Certificate Manager: localhost:50053 (gRPC), localhost:8093 (HTTP)"
Write-Host "  • DHCP Server: 0.0.0.0:67 (UDP), localhost:50055 (gRPC)"
Write-Host "  • NIC Management: localhost:50051 (gRPC), localhost:8081 (API)"
Write-Host "  • Dev UI: http://localhost:3001/network"

Write-Host "`nPress Ctrl+C to stop all services..." -ForegroundColor Yellow

# Wait for Ctrl+C
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host "`nStopping all services..." -ForegroundColor Red
    foreach ($service in $services) {
        Stop-Process -Id $service.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "All services stopped.`n" -ForegroundColor Green
}
