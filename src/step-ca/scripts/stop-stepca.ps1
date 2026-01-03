# ============================================================================
# Stop Step-CA Certificate Authority
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\stop-stepca.ps1
# ============================================================================

$ErrorActionPreference = 'Stop'

Write-Host "Stopping Step-CA..." -ForegroundColor Yellow

# Find Step-CA process
$process = Get-Process -Name "step-ca" -ErrorAction SilentlyContinue

if ($process) {
    Stop-Process -Name "step-ca" -Force
    Start-Sleep -Seconds 1
    
    # Verify stopped
    $check = Get-Process -Name "step-ca" -ErrorAction SilentlyContinue
    if ($check) {
        Write-Host "⚠️  Step-CA still running, force killing..." -ForegroundColor Yellow
        Stop-Process -Id $check.Id -Force
    }
    
    Write-Host "✅ Step-CA stopped" -ForegroundColor Green
}
else {
    Write-Host "⚠️  Step-CA is not running" -ForegroundColor Yellow
}
