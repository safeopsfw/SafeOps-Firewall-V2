# SafeOps Development Server Launcher
# Starts all SafeOps services: Backend, Frontend, Threat Intel, NIC Management

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

# Database password (used by Go services)
$dbPassword = "safeops123"

# Function to start Node.js Backend (port 5050)
function Start-Backend {
    Write-Host "[1/4] Backend API (Port 5050)" -ForegroundColor Cyan
    Write-Host "     Location: $backendPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host 'Backend API Server' -ForegroundColor Green; npm run dev" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start Frontend (port 3001)
function Start-Frontend {
    Write-Host "[2/4] Frontend UI (Port 3001)" -ForegroundColor Cyan
    Write-Host "     Location: $frontendPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; Write-Host 'SafeOps Frontend UI' -ForegroundColor Green; npm run dev" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start Threat Intel API (port 8080)
function Start-ThreatIntel {
    Write-Host "[3/4] Threat Intel API (Port 8080)" -ForegroundColor Cyan
    Write-Host "     Location: $threatIntelPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$threatIntelPath'; `$env:DB_PASSWORD='$dbPassword'; Write-Host 'Threat Intel API Server' -ForegroundColor Green; go run ./cmd/api/main.go" -WindowStyle Normal
    Write-Host "     ✓ Started" -ForegroundColor Green
}

# Function to start NIC Management (port 8081)
function Start-NICManagement {
    Write-Host "[4/4] NIC Management (Port 8081)" -ForegroundColor Cyan
    Write-Host "     Location: $nicManagementPath" -ForegroundColor Gray
    
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$nicManagementPath'; Write-Host 'NIC Management Service' -ForegroundColor Green; .\nic_management.exe" -WindowStyle Normal
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
Write-Host ""
Write-Host "Health Checks:" -ForegroundColor Cyan
Write-Host "  Backend:       http://localhost:5050/health" -ForegroundColor Gray
Write-Host "  Threat Intel:  http://localhost:8080/api/health" -ForegroundColor Gray
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
