# ============================================================================
# Script: Re-initialize Step-CA with Known Password
# ============================================================================
# File: D:\SafeOpsFV2\src\step-ca\scripts\reinit-stepca.ps1
# Purpose: Re-create Step-CA keys with a known password
# ============================================================================

$ErrorActionPreference = 'Stop'

$stepCaDir = "D:\SafeOpsFV2\src\step-ca"
$password = "SafeOpsCA2026!"  # Known password for Step-CA

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Re-initializing Step-CA with Known Password" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Create password file
$passwordFile = "$stepCaDir\secrets\password.txt"
$password | Out-File -FilePath $passwordFile -Encoding ASCII -NoNewline
Write-Host "[OK] Password file created: $passwordFile" -ForegroundColor Green

# Backup existing CA files
$backupDir = "$stepCaDir\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Copy-Item "$stepCaDir\secrets\*" -Destination "$backupDir\secrets\" -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$stepCaDir\certs\*" -Destination "$backupDir\certs\" -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$stepCaDir\config\*" -Destination "$backupDir\config\" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Existing files backed up to: $backupDir" -ForegroundColor Green

# Delete old db (will be re-created)
if (Test-Path "$stepCaDir\db") {
    Remove-Item "$stepCaDir\db" -Recurse -Force
    Write-Host "[OK] Old database removed" -ForegroundColor Yellow
}

# Re-initialize Step-CA
Write-Host ""
Write-Host "Initializing Step-CA..." -ForegroundColor Yellow
Write-Host "This will create new Root CA and Intermediate CA keys."
Write-Host ""

# Remove old keys to allow fresh init
Remove-Item "$stepCaDir\secrets\*_key" -Force -ErrorAction SilentlyContinue
Remove-Item "$stepCaDir\certs\*" -Force -ErrorAction SilentlyContinue

Set-Location $stepCaDir

# Initialize Step-CA with specific configuration
& "$stepCaDir\bin\step.exe" ca init `
    --name "SafeOps Root CA" `
    --dns "localhost,safeops-ca.local,192.168.137.1,127.0.0.1" `
    --address ":9000" `
    --provisioner "safeops-admin" `
    --password-file "$passwordFile" `
    --provisioner-password-file "$passwordFile" `
    --deployment-type "standalone" `
    --ra "StepCAS" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Step CA initialization failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[OK] Step-CA initialized successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Password: $password"
Write-Host "Password file: $passwordFile"
Write-Host ""
Write-Host "To start Step-CA, run:" -ForegroundColor Cyan
Write-Host "  cd $stepCaDir"
Write-Host "  .\bin\step-ca.exe (Get-Content $env:USERPROFILE\.step\config\ca.json | ConvertFrom-Json | Select-Object -ExpandProperty root) --password-file $passwordFile"
Write-Host ""
