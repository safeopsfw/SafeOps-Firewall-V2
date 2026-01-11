# ============================================================================
# Restart Step-CA Certificate Authority
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\restart-stepca.ps1
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-Location "D:\SafeOpsFV2\src\step-ca"

Write-Host "Restarting Step-CA..." -ForegroundColor Cyan

# Stop if running
& ".\scripts\stop-stepca.ps1"

# Wait for clean shutdown
Start-Sleep -Seconds 2

# Start
& ".\scripts\start-stepca.ps1"
