# SafeOps Development Server Launcher
# Starts all SafeOps services: Backend, Frontend, Threat Intel, NIC Management, DHCP Monitor

param(
    [switch]$BackendOnly,
    [switch]$FrontendOnly,
    [switch]$ServicesOnly,
    [switch]$Minimal  # Only Backend + Frontend, no Go services
)

$ErrorActionPreference = "Continue"

Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   SafeOps Full Development Server Launcher       ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Project paths
$projectRoot = "D:\SafeOpsFV2"
$backendPath = "$projectRoot\backend"
$frontendPath = "$projectRoot\src\ui\dev"
$threatIntelPath = "$projectRoot\src\threat_intel"
$nicManagementPath = "$projectRoot\src\nic_management"
$dhcpMonitorPath = "$projectRoot\src\dhcp_monitor"

# Database password (used by Go services)
$dbPassword = "safeops123"

# Function to start Node.js Backend (port 5050)
function Start-Backend {
    Write-Host "[1/5] Backend API (Port 5050)" -ForegroundColor Cyan
    Write-Host "     Location: $backendPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host 'Backend API Server' -ForegroundColor Green; npm run dev" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start Frontend (port 3001)
function Start-Frontend {
    Write-Host "[2/5] Frontend UI (Port 3001)" -ForegroundColor Cyan
    Write-Host "     Location: $frontendPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; Write-Host 'SafeOps Frontend UI' -ForegroundColor Green; npm run dev" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start Threat Intel API (port 8080)
function Start-ThreatIntel {
    Write-Host "[3/5] Threat Intel API (Port 8080)" -ForegroundColor Cyan
    Write-Host "     Location: $threatIntelPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$threatIntelPath'; `$env:DB_PASSWORD='$dbPassword'; Write-Host 'Threat Intel API Server' -ForegroundColor Green; go run ./cmd/api/main.go" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start NIC Management (port 8081)
function Start-NICManagement {
    Write-Host "[4/5] NIC Management (Port 8081)" -ForegroundColor Cyan
    Write-Host "     Location: $nicManagementPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$nicManagementPath'; Write-Host 'NIC Management Service' -ForegroundColor Green; .\nic_management.exe" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start DHCP Monitor (ports 53, 80) - Requires Admin
function Start-DHCPMonitor {
    Write-Host "[5/6] Network Monitor (Portal:80)" -ForegroundColor Cyan
    Write-Host "     Location: $dhcpMonitorPath" -ForegroundColor Gray
    Write-Host "     NOTE: Requires Administrator for port 80" -ForegroundColor Yellow
    
    # Run as Administrator with compiled exe (DNS hijacking disabled)
    Start-Process pwsh -Verb RunAs -ArgumentList "-NoExit", "-Command", "cd '$dhcpMonitorPath'; Write-Host 'Network Monitor (Admin)' -ForegroundColor Green; .\dhcp_monitor.exe" -WindowStyle Normal
    Write-Host "     ✓ Started (Admin)" -ForegroundColor Green
}

# Function to start Step-CA Certificate Authority (port 9000)
function Start-StepCA {
    Write-Host "[6/6] Step-CA Certificate Authority (Port 9000)" -ForegroundColor Cyan
    Write-Host "     Location: D:\SafeOpsFV2\certs\step-ca" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd 'D:\SafeOpsFV2\certs\step-ca'; Write-Host 'Step-CA Certificate Authority' -ForegroundColor Green; .\step-ca.exe 'ca\config\ca.json' --password-file 'ca\secrets\password.txt'" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Main execution
Write-Host "Starting services..." -ForegroundColor Yellow
Write-Host ""

if ($BackendOnly) {
    Start-Backend
}
elseif ($FrontendOnly) {
    Start-Frontend
}
elseif ($ServicesOnly) {
    Start-ThreatIntel
    Start-Sleep -Milliseconds 500
    Start-NICManagement
    Start-Sleep -Milliseconds 500
    Start-DHCPMonitor
    Start-Sleep -Milliseconds 500
    Start-StepCA
}
elseif ($Minimal) {
    # Only Backend + Frontend
    Start-Backend
    Start-Sleep -Milliseconds 500
    Start-Frontend
}
else {
    # Start ALL services
    Start-Backend
    Start-Sleep -Milliseconds 500
    Start-Frontend
    Start-Sleep -Milliseconds 500
    Start-ThreatIntel
    Start-Sleep -Milliseconds 500
    Start-NICManagement
    Start-Sleep -Milliseconds 500
    Start-DHCPMonitor
    Start-Sleep -Milliseconds 500
    Start-StepCA
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   All SafeOps Services Started!                  ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Active Services:" -ForegroundColor Cyan
Write-Host "  🎨 Frontend UI:       http://localhost:3001" -ForegroundColor White
Write-Host "  🔧 Backend API:       http://localhost:5050" -ForegroundColor White
Write-Host "  🛡️  Threat Intel API:  http://localhost:8080" -ForegroundColor White
Write-Host "  🌐 NIC Management:    http://localhost:8081" -ForegroundColor White
Write-Host "  📡 Network Monitor:   http://localhost:80 (Portal)" -ForegroundColor White
Write-Host "  🔐 Step-CA:           https://localhost:9000" -ForegroundColor White
Write-Host ""
Write-Host "Health Checks:" -ForegroundColor Cyan
Write-Host "  Backend:       http://localhost:5050/health" -ForegroundColor Gray
Write-Host "  Threat Intel:  http://localhost:8080/api/health" -ForegroundColor Gray
Write-Host "  Network Mon.:  http://localhost:80/api/health" -ForegroundColor Gray
Write-Host "  Step-CA:       https://localhost:9000/health" -ForegroundColor Gray
Write-Host ""
Write-Host "Network Monitor:" -ForegroundColor Cyan
Write-Host "  Captive Portal: localhost:80" -ForegroundColor Gray
Write-Host "  DNS Hijack:    DISABLED (safe mode)" -ForegroundColor Gray
Write-Host ""
Write-Host "Database:" -ForegroundColor Cyan
Write-Host "  PostgreSQL:  localhost:5432" -ForegroundColor Gray
Write-Host "  Database:    threat_intel_db" -ForegroundColor Gray
Write-Host "  User:        safeops (password: $dbPassword)" -ForegroundColor Gray
Write-Host ""
Write-Host "Options:" -ForegroundColor Yellow
Write-Host "  .\start_dev_server.ps1               # Start ALL services" -ForegroundColor Gray
Write-Host "  .\start_dev_server.ps1 -Minimal      # Backend + Frontend only" -ForegroundColor Gray
Write-Host "  .\start_dev_server.ps1 -BackendOnly  # Backend only" -ForegroundColor Gray
Write-Host "  .\start_dev_server.ps1 -FrontendOnly # Frontend only" -ForegroundColor Gray
Write-Host "  .\start_dev_server.ps1 -ServicesOnly # Go services only" -ForegroundColor Gray
Write-Host ""
Write-Host "Each service runs in its own window. Close windows to stop." -ForegroundColor DarkGray
Write-Host ""
