# SafeOps Complete Network Suite - PowerShell Startup Script
# Starts all 4 modules: Certificate Manager, DHCP, NIC API, Threat Intel + Dev UI
# Run with: powershell -ExecutionPolicy Bypass -File start_safeops.ps1

param(
    [switch]$NoUI,        # Skip starting the Dev UI
    [switch]$NoBrowser,   # Don't open browser
    [switch]$Silent       # Minimal output
)

$ErrorActionPreference = "Continue"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check for admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] Restarting with administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Colors and formatting
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host "  ============================================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Step, [string]$Text)
    Write-Host "  [$Step] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "        $Text" -ForegroundColor Gray
}

# Clear screen
Clear-Host

Write-Header "SafeOps Network Security Suite - 4 Module Startup"
Write-Host ""
Write-Host "  Modules:" -ForegroundColor White
Write-Host "    1. Certificate Manager (CA + Captive Portal)" -ForegroundColor DarkGreen
Write-Host "    2. DHCP Server (IP Assignment)" -ForegroundColor DarkCyan
Write-Host "    3. NIC Management API (Network Control)" -ForegroundColor DarkYellow
Write-Host "    4. Threat Intelligence (Security Database)" -ForegroundColor DarkMagenta
Write-Host "    5. Dev UI (React Dashboard)" -ForegroundColor DarkRed
Write-Host ""

# Define services
$services = @(
    @{
        Name = "Certificate Manager"
        Path = "$ScriptRoot\src\certificate_manager"
        Command = "go run ./cmd/."
        Port = 8082
        Color = "Green"
        Wait = 5
    },
    @{
        Name = "DHCP Server"
        Path = "$ScriptRoot\src\dhcp_server"
        Command = "go run ./cmd/."
        Port = 67
        Color = "Cyan"
        Wait = 3
    },
    @{
        Name = "NIC Management API"
        Path = "$ScriptRoot\src\nic_management\api"
        Command = "go run cmd/main.go"
        Port = 8081
        Color = "Yellow"
        Wait = 3
    },
    @{
        Name = "Threat Intel API"
        Path = "$ScriptRoot\src\threat_intel"
        Command = "go run ./cmd/api/."
        Port = 8084
        Color = "Magenta"
        Wait = 3
    }
)

# Add UI if not skipped
if (-not $NoUI) {
    $services += @{
        Name = "Dev UI"
        Path = "$ScriptRoot\src\ui\dev"
        Command = "npm run dev"
        Port = 3001
        Color = "Red"
        Wait = 5
    }
}

# Start each service
$processes = @()
$step = 1
$total = $services.Count

foreach ($svc in $services) {
    Write-Step "$step/$total" "Starting $($svc.Name)..."
    
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/k", "title SafeOps $($svc.Name) && cd /d `"$($svc.Path)`" && $($svc.Command)" `
        -PassThru `
        -WindowStyle Normal
    
    $processes += @{ Name = $svc.Name; Process = $proc }
    
    Write-Info "Waiting $($svc.Wait)s for $($svc.Name) to initialize..."
    Start-Sleep -Seconds $svc.Wait
    $step++
}

# Open browser
if (-not $NoBrowser -and -not $NoUI) {
    Write-Host ""
    Write-Step "*" "Opening browser..."
    Start-Process "http://localhost:3001"
}

# Display status
Write-Header "All Services Started!"
Write-Host ""
Write-Host "  Service Endpoints:" -ForegroundColor White
Write-Host "    Certificate Manager:  http://localhost:8082" -ForegroundColor Green
Write-Host "    DHCP Server:          Port 67 (UDP)" -ForegroundColor Cyan
Write-Host "    NIC Management API:   http://localhost:8081/api" -ForegroundColor Yellow
Write-Host "    Threat Intel API:     http://localhost:8084/api" -ForegroundColor Magenta
if (-not $NoUI) {
    Write-Host "    Dev UI Dashboard:     http://localhost:3001" -ForegroundColor Red
}
Write-Host ""
Write-Host "  CA Certificate Distribution:" -ForegroundColor White
Write-Host "    CA Certificate:       http://192.168.137.1:8082/ca.crt" -ForegroundColor Gray
Write-Host "    Trust Guide:          http://192.168.137.1:8082/trust-guide" -ForegroundColor Gray
Write-Host "    Linux Install:        http://192.168.137.1:8082/install-ca.sh" -ForegroundColor Gray
Write-Host ""

# Wait for user input
Write-Host "  Press any key to STOP all services..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Stop all services
Write-Host ""
Write-Step "*" "Stopping all services..."

# Kill by window title
$windowTitles = @(
    "SafeOps Certificate Manager",
    "SafeOps DHCP Server",
    "SafeOps NIC API",
    "SafeOps Threat Intel",
    "SafeOps Dev UI"
)

foreach ($title in $windowTitles) {
    $procs = Get-Process | Where-Object { $_.MainWindowTitle -like "*$title*" }
    foreach ($p in $procs) {
        try { $p | Stop-Process -Force } catch { }
    }
}

# Also kill go.exe and node.exe from our directories (be careful)
# This is a fallback in case window title matching fails
taskkill /FI "WINDOWTITLE eq SafeOps*" /F 2>$null

Write-Host "  [+] All services stopped. Goodbye!" -ForegroundColor Green
Start-Sleep -Seconds 2
