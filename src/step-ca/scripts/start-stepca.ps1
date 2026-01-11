# ============================================================================
# Start Step-CA with Password from PostgreSQL
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\start-stepca.ps1
# Purpose: Starts Step-CA using password retrieved from database
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-Location "D:\SafeOpsFV2\src\step-ca"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Starting Step-CA Certificate Authority" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

try {
    # Check if already running
    $existing = Get-Process -Name "step-ca" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "⚠️  Step-CA is already running (PID: $($existing.Id))" -ForegroundColor Yellow
        exit 0
    }
    
    # Retrieve password from database
    Write-Host "Retrieving password from PostgreSQL..." -ForegroundColor Yellow
    $passwordFile = & ".\scripts\get-password.ps1" -OutputMode File
    
    if (-not (Test-Path $passwordFile)) {
        throw "Password file not created"
    }
    
    Write-Host "✅ Password retrieved" -ForegroundColor Green
    
    # Start Step-CA
    Write-Host "Starting Step-CA server on :9000..." -ForegroundColor Yellow
    
    # Run Step-CA (this blocks - use Start-Process for background)
    .\bin\step-ca.exe config\ca.json --password-file $passwordFile
    
}
catch {
    Write-Error "Failed to start Step-CA: $_"
    exit 1
}
finally {
    # Clean up password file
    if ($passwordFile -and (Test-Path $passwordFile)) {
        Remove-Item $passwordFile -Force -ErrorAction SilentlyContinue
        Write-Host "🧹 Cleaned up temporary password file" -ForegroundColor Gray
    }
}
