# SafeOps Phase 3A+3B Startup Script
# TLS Proxy with MITM Inspection + Packet Engine + DHCP Monitor + DNS Server
# Run as Administrator

param(
    [switch]$EnableMITM = $false,
    [switch]$Help
)

if ($Help) {
    Write-Host "SafeOps Phase 3A+3B Startup Script"
    Write-Host "=================================="
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\start-phase-3AB.ps1          # Start Phase 3A (HTTP only)"
    Write-Host "  .\start-phase-3AB.ps1 -EnableMITM # Start Phase 3B (HTTP + HTTPS MITM)"
    Write-Host ""
    Write-Host "Services Started:"
    Write-Host "  1. DHCP Monitor (port 50055)"
    Write-Host "  2. TLS Proxy"
    Write-Host "     - DNS Decision Service (port 50052)"
    Write-Host "     - Packet Processing Service (port 50051)"
    Write-Host "  3. NIC Management with Packet Engine"
    Write-Host ""
    exit 0
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Network Security Platform" -ForegroundColor Cyan
if ($EnableMITM) {
    Write-Host "  Phase 3B: TLS MITM + HTTP Inspection" -ForegroundColor Yellow
} else {
    Write-Host "  Phase 3A: HTTP Packet Interception Only" -ForegroundColor Green
}
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/3] Starting DHCP Monitor..." -ForegroundColor Green
$dhcpMonitorPath = "D:\SafeOpsFV2\src\dhcp_monitor"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$dhcpMonitorPath'; go run ."

Start-Sleep -Seconds 3

Write-Host "[2/3] Starting TLS Proxy..." -ForegroundColor Green
$tlsProxyPath = "D:\SafeOpsFV2\src\tls_proxy"
$env:TLS_PROXY_DHCP_MONITOR = "localhost:50055"
$env:TLS_PROXY_STEP_CA = "https://localhost:9000"
$env:TLS_PROXY_DNS_PORT = "50052"
$env:TLS_PROXY_PACKET_PORT = "50051"
$env:TLS_PROXY_GATEWAY_IP = "192.168.137.1"
$env:TLS_PROXY_POLICY = "ALLOW_ONCE"
$env:TLS_PROXY_CAPTIVE_URL = "https://captive.safeops.local:8444/welcome"
$env:TLS_PROXY_SHOW_ONCE = "true"

if ($EnableMITM) {
    $env:TLS_PROXY_ENABLE_MITM = "true"
    Write-Host "  MITM Inspection: ENABLED" -ForegroundColor Yellow
} else {
    $env:TLS_PROXY_ENABLE_MITM = "false"
    Write-Host "  MITM Inspection: DISABLED (Phase 3A mode)" -ForegroundColor Green
}

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$tlsProxyPath'; .\tls_proxy.exe"

Start-Sleep -Seconds 3

Write-Host "[3/3] Starting NIC Management (Go - with gRPC blocking)..." -ForegroundColor Green
Write-Host "  Note: Using Go version for HTTP redirect support" -ForegroundColor Yellow
$nicManagementPath = "D:\SafeOpsFV2\src\nic_management"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$nicManagementPath'; go run cmd/main.go"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  All Services Started Successfully!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Service Status:" -ForegroundColor Yellow
Write-Host "  DHCP Monitor:             localhost:50055" -ForegroundColor White
Write-Host "  TLS Proxy DNS Service:    localhost:50052" -ForegroundColor White
Write-Host "  TLS Proxy Packet Service: localhost:50051" -ForegroundColor White
Write-Host "  NIC Management:           Running" -ForegroundColor White
Write-Host "  Packet Engine:            Running (captures to TLS Proxy)" -ForegroundColor White
Write-Host ""

if ($EnableMITM) {
    Write-Host "MITM Configuration:" -ForegroundColor Yellow
    Write-Host "  Mode: Phase 3B - Full TLS Inspection" -ForegroundColor White
    Write-Host "  Certificate Generation: Self-signed fallback" -ForegroundColor White
    Write-Host "  Step-CA: https://localhost:9000 (optional)" -ForegroundColor White
    Write-Host "  SNI Parser: ENABLED" -ForegroundColor White
    Write-Host "  Certificate Cache: ENABLED (max 1000 certs)" -ForegroundColor White
    Write-Host "  Dual TLS Handler: ENABLED" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT:" -ForegroundColor Red
    Write-Host "  Only TRUSTED devices (with CA cert installed) will be inspected" -ForegroundColor Yellow
    Write-Host "  UNTRUSTED devices will have traffic forwarded without inspection" -ForegroundColor Yellow
} else {
    Write-Host "HTTP Inspection:" -ForegroundColor Yellow
    Write-Host "  Mode: Phase 3A - HTTP only (no TLS inspection)" -ForegroundColor White
    Write-Host "  Captive Portal Redirect: ENABLED" -ForegroundColor White
    Write-Host "  Policy: ALLOW_ONCE (show portal once)" -ForegroundColor White
}

Write-Host ""
Write-Host "Traffic Flow:" -ForegroundColor Yellow
Write-Host "  1. Packet Engine captures: HTTP/HTTPS/SSH/RDP/SMB/DNS/SMTP/IMAP/FTP" -ForegroundColor White
Write-Host "  2. HTTPS (port 443) packets sent to TLS Proxy (port 50051)" -ForegroundColor White
Write-Host "  3. Other protocols: Metadata logged, immediately forwarded" -ForegroundColor White
Write-Host "  4. TLS Proxy checks device trust (DHCP Monitor)" -ForegroundColor White
if ($EnableMITM) {
    Write-Host "  5. For TRUSTED devices: Extract SNI, generate cert, MITM" -ForegroundColor White
    Write-Host "  6. For UNTRUSTED devices: Forward without inspection" -ForegroundColor White
} else {
    Write-Host "  5. HTTP traffic: Redirect to captive portal if untrusted" -ForegroundColor White
    Write-Host "  6. HTTPS traffic: Forward without inspection (Phase 3A)" -ForegroundColor White
}

Write-Host ""
Write-Host "Press Ctrl+C in any window to stop" -ForegroundColor Cyan
Write-Host ""

# Keep script running
Read-Host "Press Enter to exit"
